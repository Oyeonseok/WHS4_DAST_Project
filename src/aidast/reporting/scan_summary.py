"""Deterministic, offline execution reports for empty or interrupted scans.

This artifact describes persisted coverage and failures. It never turns an
unvalidated finding, incomplete case, or failed tool into a security finding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import closing
from pathlib import Path

from .runtime import ReportError, _path


def _counts(conn: sqlite3.Connection, query: str, scan_id: str) -> dict[str, int]:
    return {str(row[0] or "unknown"): row[1] for row in conn.execute(query, (scan_id,))}


def _markdown_text(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()<>|])", r"\\\1", text)


def _snapshot(database: Path, scan_id: str) -> dict:
    # The read-only URI prevents a typo from silently creating an empty DB.
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("BEGIN")
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        row = conn.execute(
            "SELECT scan_id,status,started_at,finished_at FROM scans WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
        if row is None:
            raise ReportError("scan summary requires an existing scan")
        scan = dict(row)
        inventory: dict[str, int] = {}
        for name, query in (
            ("assets", "SELECT count(*) FROM assets WHERE scan_id=?"),
            ("origins", """SELECT count(*) FROM origins o JOIN assets a
                ON a.asset_id=o.asset_id WHERE a.scan_id=?"""),
            ("endpoints", """SELECT count(*) FROM endpoints e JOIN origins o
                ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
                WHERE a.scan_id=?"""),
            ("parameters", """SELECT count(*) FROM parameters p JOIN endpoints e
                ON e.endpoint_id=p.endpoint_id JOIN origins o ON o.origin_id=e.origin_id
                JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?"""),
            ("candidate_findings", "SELECT count(*) FROM findings WHERE scan_id=?"),
        ):
            required = "findings" if name == "candidate_findings" else name
            if required in tables:
                inventory[name] = conn.execute(query, (scan_id,)).fetchone()[0]

        stages = [dict(item) for item in conn.execute(
            """SELECT stage_run_id,stage,status,started_at,finished_at,
                CASE WHEN error_message IS NULL OR error_message='' THEN 0 ELSE 1 END
                    AS error_present
                FROM stage_runs WHERE scan_id=? ORDER BY created_at,rowid""",
            (scan_id,),
        )] if "stage_runs" in tables else []

        tool_statuses = _counts(conn,
            "SELECT status,count(*) FROM pipeline_runs WHERE scan_id=? GROUP BY status",
            scan_id,
        ) if "pipeline_runs" in tables else {}
        tool_errors = [dict(item) for item in conn.execute(
            """SELECT stage,error_type,recoverable,count(*) AS count
                FROM pipeline_runs WHERE scan_id=?
                AND (status IN ('failed','error','cancelled') OR error_type IS NOT NULL)
                GROUP BY stage,error_type,recoverable ORDER BY stage,error_type,recoverable""",
            (scan_id,),
        )] if "pipeline_runs" in tables else []
        quality = {str(row[0]): str(row[1]) for row in conn.execute(
            """SELECT s.signal_type,s.value FROM surface_signals s JOIN origins o
                ON o.origin_id=s.origin_id JOIN assets a ON a.asset_id=o.asset_id
                WHERE a.scan_id=? AND s.signal_type IN
                ('recon_quality','proxy_allowed_requests','proxy_blocked_requests')
                ORDER BY s.detected_at,s.rowid""", (scan_id,)
        )} if "surface_signals" in tables else {}

        validation = {"available": "validation_cases" in tables,
                      "statuses": {}, "phases": {}, "current_confirmed": 0,
                      "confirmed_count_basis": "persisted_status_only"}
        if validation["available"]:
            validation["statuses"] = _counts(conn,
                """SELECT current_status,count(*) FROM validation_cases
                    WHERE scan_id=? GROUP BY current_status""", scan_id)
            validation["phases"] = _counts(conn,
                """SELECT processing_phase,count(*) FROM validation_cases
                    WHERE scan_id=? GROUP BY processing_phase""", scan_id)
            validation["current_confirmed"] = conn.execute(
                """SELECT count(*) FROM validation_cases WHERE scan_id=?
                    AND current_status='CONFIRMED' AND processing_phase='completed'
                    AND decision_stage_run_id=latest_stage_run_id""", (scan_id,),
            ).fetchone()[0]
        return {"scan": scan, "inventory": inventory, "stages": stages,
                "tools": {"statuses": tool_statuses, "errors": tool_errors},
                "validation": validation, "recon_quality": quality}


def _replace_artifact(path: Path, text: str) -> None:
    _path(path)
    handle, name = tempfile.mkstemp(prefix=".scan-summary-", dir=path.parent)
    staging = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def write_scan_summary(
    database: Path,
    output_root: Path,
    *,
    scan_id: str,
    report_results: Sequence[Mapping] = (),
    errors: Sequence[Mapping] = (),
) -> dict:
    """Publish a refreshable summary from one consistent DB snapshot.

    Raw exception strings, response bodies, secrets, and finding claims are
    deliberately excluded. Detailed diagnostics stay in the source database.
    Integrity and filesystem failures still raise; callers cannot interpret a
    failed artifact write as a completed report.
    """
    source = _path(database, existing=True)
    output = _path(output_root)
    snapshot = _snapshot(source, scan_id)
    report_rows = [{key: item[key] for key in ("report_id", "case_id", "status", "platform")
                    if key in item} for item in report_results]
    issue_rows = [{key: str(item[key]) for key in ("stage", "case_id", "language", "error_type")
                   if key in item and item[key] is not None} for item in errors]
    latest_stages = list({item["stage"]: item for item in snapshot["stages"]}.values())
    incomplete = (
        bool(issue_rows or snapshot["tools"]["errors"])
        or snapshot["recon_quality"].get("recon_quality") == "coverage_incomplete"
        or snapshot["scan"]["status"] in {"failed", "cancelled", "completed_with_errors"}
        or any(item["status"] in {"failed", "cancelled"} or item["error_present"]
               for item in latest_stages)
        or any(phase != "completed" and count
               for phase, count in snapshot["validation"]["phases"].items())
    )
    active = (snapshot["scan"]["status"] in {"pending", "running"}
              or any(item["status"] in {"pending", "running"}
                     for item in latest_stages))
    drafted_rows = [item for item in report_rows if item.get("status") == "drafted"]
    drafted_cases = len({
        str(item["case_id"]) for item in drafted_rows if item.get("case_id")
    })
    summary = {"schema_version": "1.0", "scan_id": scan_id,
               "execution_status": "partial" if incomplete else "in_progress" if active else "completed",
               **snapshot, "latest_stages": latest_stages,
               "reports": report_rows, "errors": issue_rows,
               "report_counts": {
                   "finding_cases": drafted_cases,
                   "localized_drafts": len(drafted_rows),
               },
               "conclusion": "Only current confirmed Validation cases can produce finding reports. "
                             "Empty or incomplete results do not establish the absence of vulnerabilities."}
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    summary["snapshot_sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "ScanSummary.json"
    markdown_path = output / "ScanSummary.md"
    if json_path.exists():
        _path(json_path, existing=True)
        try:
            previous = json.loads(json_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise ReportError("existing scan summary is invalid") from exc
        if not isinstance(previous, dict) or previous.get("scan_id") != scan_id:
            raise ReportError("existing scan summary belongs to a different scan")
    markdown = ["# 스캔 실행 보고서", "", f"- 스캔: {_markdown_text(scan_id)}",
                f"- 실행 상태: {summary['execution_status']}",
                f"- DB에 기록된 현재 확정 상태 사례: {summary['validation']['current_confirmed']}",
                f"- 생성된 취약점 보고서: {drafted_cases}",
                f"- 생성된 언어별 보고서 초안: {len(drafted_rows)}", "", "## 수집 결과", ""]
    markdown.extend(f"- {name}: {count}" for name, count in summary["inventory"].items())
    if summary["recon_quality"]:
        markdown.extend(["", "## 정찰 품질", ""])
        markdown.extend(f"- {name}: {_markdown_text(value)}"
                        for name, value in summary["recon_quality"].items())
    markdown.extend(["", "## 단계 상태", "", "| 단계 | 상태 | 오류 기록 |", "| --- | --- | --- |"])
    markdown.extend(f"| {_markdown_text(item['stage'])} | {_markdown_text(item['status'])} | "
                    f"{'있음' if item['error_present'] else '없음'} |" for item in summary["stages"])
    markdown.extend(["", "## 오류 및 미완료 작업", "",
                     f"- 도구 오류 그룹: {len(summary['tools']['errors'])}",
                     f"- 보고서 또는 실행 오류: {len(issue_rows)}"])
    for issue in issue_rows:
        markdown.append("- " + ", ".join(f"{key}: {_markdown_text(value)}" for key, value in issue.items()))
    markdown.extend(["", "현재 완료된 검증 결과만 취약점 보고서의 근거로 사용합니다. "
                     "결과가 비어 있거나 작업이 미완료된 경우 취약점이 없다고 판단할 수 없습니다.", "",
                     f"Snapshot SHA-256: {summary['snapshot_sha256']}", ""])
    _replace_artifact(markdown_path, "\n".join(markdown))
    _replace_artifact(json_path, json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    return {"summary_path": str(json_path), "summary_markdown_path": str(markdown_path), **summary}
