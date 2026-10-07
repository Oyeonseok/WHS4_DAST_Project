"""Observe existing local dashboard scans and save bounded acceptance evidence.

This utility never launches, resumes, controls, or mutates a scan.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aidast.pipeline.model_settings import load_scan_model_choices  # noqa: E402

TERMINAL = {"completed", "failed", "cancelled"}
STAGES = ("Scope", "Recon", "Attack", "Chaining", "Validation", "Report")
SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_RESPONSE_BYTES = 8_000_000


class ObservationError(RuntimeError):
    """Safe, bounded error suitable for persisted evidence."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ObservationError("dashboard redirects are refused")


class DashboardClient:
    def __init__(self, base_url: str, timeout: float = 15) -> None:
        parsed = urlsplit(base_url)
        host = parsed.hostname or ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if (parsed.scheme not in {"http", "https"} or not loopback
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise ValueError("dashboard URL must be a loopback HTTP(S) origin")
        _ = parsed.port  # Validate the port before any request.
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path: str, payload: dict | None = None, *, markdown=False):
        if not path.startswith("/api/v1/") or ".." in path:
            raise ValueError("invalid dashboard API path")
        method = "POST" if payload is not None else "GET"
        if method == "POST":
            raise ValueError("dashboard observation is read-only")
        headers = {"Accept": "text/markdown" if markdown else "application/json"}
        if payload is not None:
            headers |= {"Origin": self.base_url, "Content-Type": "application/json"}
        request = Request(self.base_url + path, headers=headers, method=method,
                          data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise ObservationError(f"HTTP {exc.code} on {method} {path}", status_code=exc.code) from None
        except (URLError, TimeoutError, OSError):
            raise ObservationError(f"dashboard transport failed on {method} {path}") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ObservationError("dashboard response exceeds the observation limit")
        try:
            return raw.decode("utf-8") if markdown else json.loads(raw)
        except (UnicodeError, ValueError):
            raise ObservationError("dashboard response has invalid encoding or JSON") from None


def load_ids(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    if raw.lstrip().startswith("["):
        values = json.loads(raw)
    else:
        values = [line.strip() for line in raw.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    if (not isinstance(values, list) or not values
            or any(not isinstance(value, str) or not SCAN_ID.fullmatch(value) for value in values)):
        raise ValueError("scan IDs must be a JSON string list or one valid ID per line")
    if len(set(values)) != len(values):
        raise ValueError("duplicate scan IDs do not count as separate runs")
    if len(values) > 20:
        raise ValueError("one observation batch supports at most 20 unique scans")
    return values


def remember_events(row: dict, events: list[dict], source: str) -> None:
    # API endpoints expose at most 500 recent entries. A saturated page cannot
    # establish complete error coverage, even if every visible entry is green.
    if len(events) >= 500:
        row["event_coverage_complete"] = False
    for event in events:
        if event.get("level") != "error":
            continue
        identifier = str(event.get("audit_id") or event.get("id") or "unknown")[:256]
        key = f"{'audit' if event.get('audit_id') else source}:{identifier}"
        row["error_events"][key] = {
            "id": identifier, "source": source,
            "stage": str(event.get("stage") or "unknown")[:40],
            "event_type": str(event.get("event_type") or event.get("message_code") or "error")[:256],
            "failure_code": str(event.get("failure_code") or "")[:80],
        }


def collect_full_ledger(row: dict, result_root: Path) -> None:
    """Read the dashboard's sanitized persisted log, including beyond API caps."""
    source = result_root.expanduser().absolute() / ".webui" / "events.db"
    if (any(path.is_symlink() for path in (source, *source.parents))
            or not source.is_file() or source.stat().st_size > 250_000_000):
        raise ObservationError("full dashboard event ledger unavailable")
    connection = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        cursor = connection.execute(
            "SELECT max(event_id) FROM web_events WHERE scan_id=?", (row["scan_id"],)
        ).fetchone()[0]
        if cursor is None or cursor < row.get("last_event_id", 0):
            raise ObservationError("full dashboard ledger does not cover the observed cursor")
        for event_id, raw in connection.execute(
            "SELECT event_id,payload_json FROM web_events "
            "WHERE scan_id=? AND event_type='log.appended' ORDER BY event_id", (row["scan_id"],)
        ):
            event = json.loads(raw)
            remember_events(row, [{**event, "id": event_id}], "logs")
        row["event_coverage_complete"] = True
        row["event_coverage_source"] = "persisted_dashboard_ledger"
    finally:
        connection.close()


def finalize(client, row: dict, *, result_root: Path,
             expected_models: dict | None) -> None:
    scan_id = row["scan_id"]
    prefix = f"/api/v1/scans/{scan_id}"
    if row["terminal_status"] not in TERMINAL:
        raise ValueError("scan must be terminal before collecting final artifacts")

    def collect(name, action, *, missing_ok=False):
        try:
            return action()
        except (ObservationError, ValueError, OSError, sqlite3.Error) as exc:
            if missing_ok and isinstance(exc, ObservationError) and exc.status_code == 404:
                return None
            row["observation_errors"].append(f"{name} unavailable")
            return None

    summary = collect("scan summary", lambda: client.request(prefix + "/summary"), missing_ok=True)
    row["summary_present"] = bool(isinstance(summary, dict)
                                  and summary.get("scan_id") == scan_id
                                  and str(summary.get("markdown") or "").strip())
    listed = collect("report list", lambda: client.request(f"/api/v1/reports?scan_id={scan_id}"))
    row["reports"] = []
    for report in (listed or {}).get("reports", []):
        report_id = str(report.get("report_id") or "")
        if not SCAN_ID.fullmatch(report_id) or report.get("scan_id") != scan_id:
            row["observation_errors"].append("report identifier or scan binding invalid")
            continue
        body = collect("report content", lambda: client.request(
            f"/api/v1/reports/{report_id}", markdown=True))
        if isinstance(body, str) and body.strip():
            row["reports"].append({"report_id": report_id,
                                   "sha256": hashlib.sha256(body.encode()).hexdigest()})
    models = collect("persisted models", lambda: load_scan_model_choices(result_root, scan_id))
    row["persisted_models"] = models.model_dump() if models is not None else None
    row["expected_models_match"] = (expected_models is None or
                                     row["persisted_models"] == expected_models)
    if not row["event_coverage_complete"]:
        collect("full dashboard event ledger", lambda: collect_full_ledger(row, result_root))


def assess(row: dict, *, required_stages=STAGES) -> dict[str, bool]:
    stages = row.get("stage_statuses", {})
    return {
        "completed": row.get("terminal_status") == "completed",
        "stages_completed": all(stages.get(stage) in {"completed", "skipped"}
                                for stage in required_stages)
                            and all(value not in {"failed", "running", "pending", "cancelled"}
                                    for value in stages.values()),
        "error_free": not row.get("error_events"),
        "event_coverage_complete": row.get("event_coverage_complete") is True,
        "observation_complete": not row.get("observation_errors"),
        "report_present": row.get("summary_present") is True or bool(row.get("reports")),
        "models_persisted": bool(row.get("persisted_models")),
        "model_selection": row.get("expected_models_match") is True,
    }


def evidence(rows: list[dict]) -> dict:
    for row in rows:
        row["checks"] = assess(row)
        row["passed"] = all(row["checks"].values())
    count_ok = 10 <= len(rows) <= 20 and len({row["scan_id"] for row in rows}) == len(rows)
    return {"schema_version": "1.0", "observed_at": datetime.now(timezone.utc).isoformat(),
            "criteria": {"minimum_runs": 10, "maximum_runs": 20},
            "run_count": len(rows), "run_count_valid": count_ok,
            "passed_runs": sum(row["passed"] for row in rows),
            "passed": count_ok and all(row["passed"] for row in rows), "scans": rows}


def write_evidence(destination: Path, document: dict) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    lines = ["# Dashboard observation evidence", "",
             f"Acceptance: {'PASS' if document['passed'] else 'FAIL'}; "
             f"{document['passed_runs']}/{document['run_count']} scans passed.", "",
             "| Scan | Terminal | Errors | Report | Failed checks |",
             "| --- | --- | --- | --- | --- |"]
    for row in document["scans"]:
        failed = ", ".join(key for key, ok in row["checks"].items() if not ok) or "none"
        lines.append(f"| {row['scan_id']} | {row.get('terminal_status') or 'pending'} | "
                     f"{len(row['error_events'])} | "
                     f"{'yes' if row.get('summary_present') or row.get('reports') else 'no'} | {failed} |")
    lines += ["", "Scan summaries count as report artifacts even when there are no finding drafts. "
              "No request bodies, report content, credentials, or free-form error messages are saved.", ""]
    for filename, body in (("dashboard-observation.json", json.dumps(document, ensure_ascii=False, indent=2) + "\n"),
                           ("dashboard-observation.md", "\n".join(lines))):
        staging = destination / (filename + ".tmp")
        staging.write_text(body, encoding="utf-8")
        staging.replace(destination / filename)


def observe(client, ids: list[str], *, result_root: Path, destination: Path,
            timeout: float, poll_seconds: float, settle_seconds: float,
            expected_models: dict | None = None) -> dict:
    rows = [{"scan_id": scan_id, "terminal_status": None, "stage_statuses": {},
             "error_events": {}, "observation_errors": [], "event_coverage_complete": True,
             "finalized": False} for scan_id in ids]
    deadline = time.monotonic() + timeout
    terminal_since: dict[str, float] = {}
    while True:
        for row in rows:
            if row["finalized"]:
                continue
            scan_id = row["scan_id"]
            try:
                snapshot = client.request(f"/api/v1/scans/{scan_id}")
                if snapshot.get("scan_id") != scan_id:
                    raise ObservationError("snapshot scan binding mismatch")
                row["terminal_status"] = snapshot.get("status")
                row["stage_statuses"] = snapshot.get("stage_statuses", {})
                row["last_event_id"] = snapshot.get("last_event_id", 0)
                remember_events(row, snapshot.get("logs", []), "logs")
                audits = client.request(f"/api/v1/scans/{scan_id}/audit")
                remember_events(row, audits.get("events", []), "audit")
                if row["terminal_status"] in TERMINAL:
                    terminal_since.setdefault(scan_id, time.monotonic())
                    if time.monotonic() - terminal_since[scan_id] >= settle_seconds:
                        finalize(client, row, result_root=result_root,
                                 expected_models=expected_models)
                        row["finalized"] = True
                else:
                    terminal_since.pop(scan_id, None)
            except (ObservationError, ValueError, TypeError, AttributeError, OSError):
                # A recovered dashboard outage is still an observed error and
                # cannot silently disappear from an error-free acceptance run.
                issue = "dashboard polling failed"
                if issue not in row["observation_errors"]:
                    row["observation_errors"].append(issue)
        expired = time.monotonic() >= deadline
        if expired:
            for row in rows:
                if not row["finalized"]:
                    row["observation_errors"].append("observation deadline reached")
        document = evidence(rows)
        write_evidence(destination, document)
        if expired or all(row["finalized"] for row in rows):
            return document
        time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-ids", required=True, type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--result-root", type=Path, default=ROOT / "result")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-models", type=Path,
                        help="JSON object with the six expected persisted model choices")
    parser.add_argument("--timeout", type=float, default=14400)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument("--settle-seconds", type=float, default=5)
    args = parser.parse_args(argv)
    try:
        if (args.timeout <= 0
                or not 0 < args.poll_seconds <= 60 or not 0 <= args.settle_seconds <= 60
                or not all(math.isfinite(value) for value in
                           (args.timeout, args.poll_seconds, args.settle_seconds))):
            raise ValueError("invalid observation limits")
        ids = load_ids(args.scan_ids)
        expected = None
        if args.expected_models:
            from aidast.pipeline.model_settings import ScanModelChoices
            expected = ScanModelChoices.model_validate_json(
                args.expected_models.read_text(encoding="utf-8")).model_dump()
        client = DashboardClient(args.base_url)
        document = observe(client, ids, result_root=args.result_root, destination=args.output,
                           timeout=args.timeout,
                           poll_seconds=args.poll_seconds, settle_seconds=args.settle_seconds,
                           expected_models=expected)
    except (ObservationError, ValueError, OSError):
        print("Observation setup failed; check local dashboard, IDs, and model settings.",
              file=sys.stderr)
        return 2
    print(f"{'PASS' if document['passed'] else 'FAIL'}: "
          f"{document['passed_runs']}/{document['run_count']} scans; evidence: {args.output}")
    return 0 if document["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
