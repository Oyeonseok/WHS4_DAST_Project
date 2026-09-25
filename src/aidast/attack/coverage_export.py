"""Export an auditable Attack -> Validation -> Report outcome for every item."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


def _publish(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    staging = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def _report_path(report_root: Path | None, case_id: str | None) -> str | None:
    if report_root is None or case_id is None or not report_root.is_dir():
        return None
    matches = sorted(report_root.glob(f"**/{case_id}/Report.md"))
    return str(matches[0].absolute()) if matches else None


def _outcomes(
    row: sqlite3.Row, *, report_root: Path | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    attack = {
        "status": str(row["coverage_status"]),
        "reason": row["disposition_reason"],
        "attempt_count": int(row["attempt_count"]),
        "finding_id": row["finding_id"],
    }
    validation_status = row["validation_status"]
    case_id = row["case_id"]
    if row["finding_id"] is None:
        validation = {
            "status": "NOT_APPLICABLE",
            "case_id": None,
            "reason": "Attack did not produce an evidence-bound finding.",
        }
    elif validation_status is None:
        validation = {
            "status": "PENDING",
            "case_id": None,
            "reason": "The evidence-bound finding has not completed independent Validation.",
        }
    else:
        validation = {
            "status": str(validation_status),
            "case_id": case_id,
            "reason": "Persisted independent Validation decision.",
        }

    located_report = _report_path(report_root, case_id)
    if validation["status"] == "CONFIRMED":
        report = {
            "status": "DRAFTED" if located_report else "PENDING",
            "path": located_report,
            "reason": (
                "A local report draft was located."
                if located_report else
                "Validation confirmed the finding; a report draft is still required."
            ),
        }
    else:
        report = {
            "status": "WITHHELD",
            "path": None,
            "reason": "Reports require an independently CONFIRMED Validation case.",
        }
    return attack, validation, report


def export_coverage_results(
    database: Path, scan_id: str, output_dir: Path, *,
    report_root: Path | None = None,
) -> dict[str, Any]:
    """Write one result record per coverage item without inventing findings."""
    database = Path(database).expanduser().resolve(strict=True)
    output_dir = Path(output_dir).expanduser().absolute()
    report_root = (
        Path(report_root).expanduser().absolute() if report_root is not None else None
    )
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        scan = conn.execute(
            "SELECT 1 FROM scans WHERE scan_id=?", (scan_id,),
        ).fetchone()
        if scan is None:
            raise ValueError(f"unknown scan: {scan_id}")
        rows = conn.execute(
            """WITH latest_validation AS (
                   SELECT v.* FROM validation_cases v
                   JOIN (
                       SELECT finding_id, MAX(rowid) AS latest_rowid
                       FROM validation_cases
                       WHERE scan_id=? AND finding_id IS NOT NULL
                       GROUP BY finding_id
                   ) latest ON latest.latest_rowid=v.rowid
               )
               SELECT c.coverage_id,c.endpoint_id,c.annotation_id,c.vuln_class,
                      c.skill_name,c.injection_location,c.parameter_name,
                      c.required_identity_role,c.status coverage_status,
                      c.disposition_reason,c.attempt_count,c.finding_id,
                      e.method,e.normalized_path,an.rationale,
                      v.case_id,v.current_status validation_status
               FROM attack_coverage_items c
               JOIN endpoints e ON e.endpoint_id=c.endpoint_id
               JOIN endpoint_annotations an ON an.annotation_id=c.annotation_id
               LEFT JOIN latest_validation v ON v.finding_id=c.finding_id
               WHERE c.scan_id=?
               ORDER BY e.normalized_path,e.method,c.vuln_class,c.coverage_id""",
            (scan_id, scan_id),
        ).fetchall()

    records: list[dict[str, Any]] = []
    for row in rows:
        attack, validation, report = _outcomes(row, report_root=report_root)
        records.append({
            "coverage_id": row["coverage_id"],
            "endpoint_id": row["endpoint_id"],
            "annotation_id": row["annotation_id"],
            "method": row["method"],
            "path": row["normalized_path"],
            "vulnerability_class": row["vuln_class"],
            "skill_name": row["skill_name"],
            "injection_location": row["injection_location"],
            "parameter_name": row["parameter_name"],
            "required_identity_role": row["required_identity_role"],
            "source_rationale": row["rationale"],
            "attack": attack,
            "validation": validation,
            "report": report,
        })

    attack_counts = Counter(item["attack"]["status"] for item in records)
    validation_counts = Counter(item["validation"]["status"] for item in records)
    report_counts = Counter(item["report"]["status"] for item in records)
    payload = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "total": len(records),
        "attack_statuses": dict(sorted(attack_counts.items())),
        "validation_statuses": dict(sorted(validation_counts.items())),
        "report_statuses": dict(sorted(report_counts.items())),
        "items": records,
    }
    _publish(
        output_dir / "CoverageResults.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )

    lines = [
        "# Exhaustive Attack, Validation, and Report Results",
        "",
        f"- Scan: `{scan_id}`",
        f"- Coverage items: {len(records)}",
        f"- Attack: `{dict(sorted(attack_counts.items()))}`",
        f"- Validation: `{dict(sorted(validation_counts.items()))}`",
        f"- Report: `{dict(sorted(report_counts.items()))}`",
        "",
        "A source annotation is not automatically a confirmed vulnerability. Reports are",
        "withheld unless independent Validation reaches `CONFIRMED`.",
        "",
        "| Method and path | Class | Attack | Validation | Report | Coverage ID |",
        "|---|---|---|---|---|---|",
    ]
    for item in records:
        lines.append(
            "| {method} `{path}` | {vulnerability_class} | {attack} | "
            "{validation} | {report} | `{coverage_id}` |".format(
                method=item["method"], path=item["path"],
                vulnerability_class=item["vulnerability_class"],
                attack=item["attack"]["status"],
                validation=item["validation"]["status"],
                report=item["report"]["status"],
                coverage_id=item["coverage_id"],
            )
        )
    _publish(output_dir / "CoverageResults.md", "\n".join(lines) + "\n")
    return {
        "scan_id": scan_id,
        "total": len(records),
        "json": str((output_dir / "CoverageResults.json").absolute()),
        "markdown": str((output_dir / "CoverageResults.md").absolute()),
        "attack_statuses": dict(sorted(attack_counts.items())),
        "validation_statuses": dict(sorted(validation_counts.items())),
        "report_statuses": dict(sorted(report_counts.items())),
    }
