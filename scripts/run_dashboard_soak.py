#!/usr/bin/env python3
"""Run and verify sequential scans through the dashboard HTTP API.

The state file is append-only at the scan-attempt level.  Existing successful
runs are revalidated and retained, known but unrecorded scan IDs are evaluated
before a new scan is launched, and a failed attempt stops the supervisor.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener


REQUIRED_STAGES = ("Scope", "Recon", "Attack", "Chaining", "Validation", "Report")
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
TOKEN_MARKER = re.compile(r"TOKEN_[A-Z0-9_:-]+", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TransientAPIError(RuntimeError):
    """The dashboard remained unavailable after bounded retries."""


@dataclass(frozen=True)
class SoakConfig:
    base_url: str
    baseline_id: str
    target_id: str
    total: int
    min_baseline_count: int = 81
    min_matched_count: int = 73
    min_recall: float = 0.90


class DashboardClient:
    def __init__(
        self,
        base_url: str,
        *,
        attempts: int = 5,
        retry_delay: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.attempts = attempts
        self.retry_delay = retry_delay
        self.sleep = sleep
        self.opener = build_opener(ProxyHandler({}))

    def call(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers.update({"Origin": self.base_url, "Content-Type": "application/json"})
        request = Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method="POST" if payload is not None else "GET",
        )
        last_error: Exception | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                with self.opener.open(request, timeout=25) as response:
                    raw = response.read(8_000_001)
                if len(raw) > 8_000_000:
                    raise ValueError("dashboard response exceeds 8 MB")
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError("dashboard response is not a JSON object")
                return value
            except HTTPError as exc:
                # 4xx responses are deterministic contract failures.  Retrying
                # them can accidentally repeat a rejected mutation.
                if 400 <= exc.code < 500:
                    raise
                last_error = exc
            except (URLError, TimeoutError, OSError, ValueError) as exc:
                last_error = exc
            if attempt < self.attempts:
                self.sleep(min(self.retry_delay * (2 ** (attempt - 1)), 30.0))
        raise TransientAPIError(str(last_error)[:300]) from last_error


def _errors(snapshot: dict[str, Any], audit: dict[str, Any]) -> list[dict[str, Any]]:
    found = [
        {"source": "log", "id": item.get("id"), "code": item.get("message_code")}
        for item in snapshot.get("logs") or []
        if isinstance(item, dict) and str(item.get("level", "")).lower() == "error"
    ]
    found.extend(
        {"source": "audit", "id": item.get("id") or item.get("audit_id"),
         "code": item.get("event_type") or item.get("message_code")}
        for item in audit.get("events") or []
        if isinstance(item, dict) and str(item.get("level", "")).lower() == "error"
    )
    return found


def evaluate_run(
    scan_id: str,
    snapshot: dict[str, Any],
    audit: dict[str, Any],
    wiki: dict[str, Any],
    validations: dict[str, Any],
    report_response: dict[str, Any],
    config: SoakConfig,
) -> dict[str, Any]:
    stages = snapshot.get("stage_statuses") or {}
    errors = _errors(snapshot, audit)
    comparison = wiki.get("comparison") or {}
    cases = [item for item in validations.get("cases") or [] if isinstance(item, dict)]
    completed_cases = [
        item for item in cases if str(item.get("processing_phase", "")).lower() == "completed"
    ]
    confirmed_cases = [
        item for item in completed_cases if str(item.get("current_status", "")).upper() == "CONFIRMED"
    ]
    confirmed_ids = {str(item.get("case_id")) for item in confirmed_cases if item.get("case_id")}
    reports = [item for item in report_response.get("reports") or [] if isinstance(item, dict)]
    languages_by_case: dict[str, set[str]] = {}
    contaminated_titles: list[dict[str, str]] = []
    for report in reports:
        case_id = report.get("case_id")
        language = str(report.get("language") or "").lower()
        if isinstance(case_id, str) and language:
            languages_by_case.setdefault(case_id, set()).add(language)
        title = str(report.get("title") or "")
        if TOKEN_MARKER.search(title):
            contaminated_titles.append({"report_id": str(report.get("report_id") or ""), "title": title})
    missing_report_languages = {
        case_id: sorted({"ko", "en"} - languages_by_case.get(case_id, set()))
        for case_id in sorted(confirmed_ids)
        if not {"ko", "en"}.issubset(languages_by_case.get(case_id, set()))
    }

    checks = {
        "completed": snapshot.get("status") == "completed",
        "stages_completed": all(stages.get(stage) == "completed" for stage in REQUIRED_STAGES),
        "zero_errors": not errors,
        "wiki_lint": wiki.get("configured") is True and (wiki.get("lint") or {}).get("ok") is True,
        "baseline": (
            comparison.get("baseline_id") == config.baseline_id
            and comparison.get("baseline_count") == config.min_baseline_count
        ),
        "recon_recall": (
            isinstance(comparison.get("exact_recall"), (int, float))
            and comparison["exact_recall"] >= config.min_recall
            and comparison.get("matched_count", 0) >= config.min_matched_count
        ),
        "validation_cases": bool(cases),
        "validations_completed": len(completed_cases) == len(cases),
        "confirmed_findings": bool(confirmed_ids),
        "bilingual_reports": not missing_report_languages and bool(confirmed_ids),
        "clean_report_titles": not contaminated_titles,
    }
    return {
        "scan_id": scan_id,
        "evaluated_at": utc_now(),
        "terminal_status": snapshot.get("status"),
        "stage_statuses": stages,
        "requests": snapshot.get("requests"),
        "endpoints": snapshot.get("endpoints"),
        "errors": errors,
        "validation": {
            "case_count": len(cases),
            "completed_count": len(completed_cases),
            "confirmed_count": len(confirmed_ids),
            "confirmed_case_ids": sorted(confirmed_ids),
        },
        "reports": [str(item.get("report_id")) for item in reports if item.get("report_id")],
        "report_coverage": {
            "languages_by_confirmed_case": {
                case_id: sorted(languages_by_case.get(case_id, set())) for case_id in sorted(confirmed_ids)
            },
            "missing_languages": missing_report_languages,
            "contaminated_titles": contaminated_titles,
        },
        "wiki": {
            "baseline_count": comparison.get("baseline_count"),
            "matched_count": comparison.get("matched_count"),
            "exact_recall": comparison.get("exact_recall"),
            "lint_ok": (wiki.get("lint") or {}).get("ok"),
        },
        "checks": checks,
        "passed": all(checks.values()),
    }


class SoakSupervisor:
    def __init__(
        self,
        *,
        client: DashboardClient,
        config: SoakConfig,
        ids_path: Path,
        state_path: Path,
        launch_payload: dict[str, Any],
        poll_seconds: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.config = config
        self.ids_path = ids_path
        self.state_path = state_path
        self.launch_payload = launch_payload
        self.poll_seconds = poll_seconds
        self.sleep = sleep

    def load_state(self) -> dict[str, Any]:
        if self.state_path.is_file():
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not isinstance(value.get("runs", []), list):
                raise ValueError("invalid soak state")
        else:
            value = {"runs": []}
        value.update({
            "schema_version": "2.0",
            "target_runs": self.config.total,
            "baseline_id": self.config.baseline_id,
        })
        value.setdefault("started_at", utc_now())
        value.setdefault("runs", [])
        return value

    def save(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.replace(self.state_path)

    def scan_ids(self) -> list[str]:
        if not self.ids_path.is_file():
            return []
        return list(dict.fromkeys(line.strip() for line in self.ids_path.read_text().splitlines() if line.strip()))

    def launch(self) -> str:
        response = self.client.call("/api/v1/scans", self.launch_payload)
        scan_id = response.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            raise ValueError("launch response omitted scan_id")
        self.ids_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ids_path.open("a", encoding="utf-8") as stream:
            stream.write(scan_id + "\n")
        print(f"LAUNCHED {scan_id}", flush=True)
        return scan_id

    def inspect(self, scan_id: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
        snapshot = self.client.call("/api/v1/scans/" + quote(scan_id, safe=""))
        if snapshot.get("status") not in TERMINAL_STATUSES:
            return snapshot, None
        prefix = "/api/v1/scans/" + quote(scan_id, safe="")
        audit = self.client.call(prefix + "/audit")
        wiki = self.client.call(prefix + "/recon-wiki", {
            "baseline_id": self.config.baseline_id,
            "baseline_kind": "source",
            "target_id": self.config.target_id,
        })
        validations = self.client.call(prefix + "/validations")
        reports = self.client.call("/api/v1/reports?scan_id=" + quote(scan_id, safe=""))
        return snapshot, evaluate_run(scan_id, snapshot, audit, wiki, validations, reports, self.config)

    def run(self, *, resume_after_failure: bool = False) -> int:
        state = self.load_state()
        existing = {str(row.get("scan_id")): row for row in state["runs"] if isinstance(row, dict)}
        if state.get("status") == "stopped_on_failure" and not resume_after_failure:
            print("STOPPED state contains a failed attempt; pass --resume-after-failure after fixing it", flush=True)
            return 2
        state["status"] = "running"
        state.pop("finished_at", None)
        self.save(state)

        pending = self.scan_ids()
        current: str | None = None
        last_marker: tuple[Any, ...] | None = None
        while True:
            passed_count = sum(bool(row.get("passed")) for row in existing.values())
            if passed_count >= self.config.total:
                state["runs"] = [existing[key] for key in self.scan_ids() if key in existing]
                state["status"] = "completed"
                state["finished_at"] = utc_now()
                self.save(state)
                print(f"SOAK_COMPLETED {passed_count}", flush=True)
                return 0

            if current is None:
                # Revalidate successful historical rows and evaluate any IDs the
                # prior process launched before it was interrupted.
                current = next((scan_id for scan_id in pending if scan_id not in existing), None)
                if current is None:
                    current = next((scan_id for scan_id in pending if existing[scan_id].get("passed")), None)
                    pending = [scan_id for scan_id in pending if scan_id != current]
                if current is None:
                    current = self.launch()

            snapshot, result = self.inspect(current)
            marker = (
                snapshot.get("status"), snapshot.get("stage"), snapshot.get("progress"),
                snapshot.get("requests"), snapshot.get("last_event_id"),
            )
            if marker != last_marker:
                print("STATUS", current, *marker, flush=True)
                last_marker = marker
            if result is None:
                self.sleep(self.poll_seconds)
                continue

            existing[current] = result
            ordered_ids = self.scan_ids()
            state["runs"] = [existing[key] for key in ordered_ids if key in existing]
            self.save(state)
            print("TERMINAL", json.dumps(result, ensure_ascii=False), flush=True)
            if not result["passed"]:
                state["status"] = "stopped_on_failure"
                state["failed_scan_id"] = current
                self.save(state)
                return 2
            current = None
            last_marker = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--ids", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--total", type=int, default=10)
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    parser.add_argument("--resume-after-failure", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 10 <= args.total <= 20:
        raise SystemExit("--total must be between 10 and 20")
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("launch payload must be a JSON object")
    config = SoakConfig(args.base_url, args.baseline_id, args.target_id, args.total)
    supervisor = SoakSupervisor(
        client=DashboardClient(args.base_url), config=config, ids_path=args.ids,
        state_path=args.state, launch_payload=payload, poll_seconds=args.poll_seconds,
    )
    try:
        return supervisor.run(resume_after_failure=args.resume_after_failure)
    except (HTTPError, TransientAPIError, OSError, ValueError, KeyError) as exc:
        state = supervisor.load_state()
        state["status"] = "supervisor_error"
        state["supervisor_error"] = {"type": type(exc).__name__, "message": str(exc)[:300], "at": utc_now()}
        supervisor.save(state)
        print(f"SUPERVISOR_ERROR {type(exc).__name__}: {str(exc)[:300]}", flush=True)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
