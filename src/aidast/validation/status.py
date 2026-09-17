"""Read-only shared Pipeline.db Validation status views."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .models import ValidationError, canonical_sha256


def shared_validation_status(database: Path, *, scan_id: str | None = None,
                             case_id: str | None = None) -> dict:
    if (scan_id is None) == (case_id is None):
        raise ValidationError("select exactly one scan_id or case_id")
    path = Path(database).expanduser().absolute()
    if path.is_symlink():
        raise ValidationError("Pipeline.db must be a regular file")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValidationError("Pipeline.db must be a regular file")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            if conn.execute("PRAGMA user_version").fetchone()[0] < 9:
                raise ValidationError("shared Validation status requires Pipeline.db schema v9")
            if case_id is not None:
                row = conn.execute("SELECT * FROM validation_cases WHERE case_id=?", (case_id,)).fetchone()
                if row is None:
                    raise ValidationError("unknown Validation case")
                case = _case(dict(row))
                hypotheses = conn.execute(
                    """SELECT ordinal,gap_axis,path_id,hypothesis_kind,current_score,
                    reason_json,required_preconditions_json,recommended_actions_json,
                    expected_signal_json,execution_owner,feasibility,potential_impact_json
                    FROM validation_impact_hypotheses WHERE case_id=? AND stage_run_id=?
                    ORDER BY ordinal""", (case_id, case["decision_stage_run_id"]),
                ).fetchall() if case["current_status"] == "UNDERPOWERED" else []
                case["impact_hypotheses"] = [_json_row(item) for item in hypotheses]
                return {"database": str(path), "case": case}
            rows = conn.execute(
                "SELECT * FROM validation_cases WHERE scan_id=? ORDER BY case_id", (scan_id,)
            ).fetchall()
            if not rows and conn.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone() is None:
                raise ValidationError("unknown scan")
            cases = [_case(dict(row)) for row in rows]
            owners = {name: 0 for name in ("validation", "chaining", "manual")}
            hypothesis_count = 0
            for owner, count in conn.execute(
                """SELECT h.execution_owner,count(*) FROM validation_impact_hypotheses h
                JOIN validation_cases c ON c.case_id=h.case_id
                WHERE c.scan_id=? AND h.stage_run_id=c.decision_stage_run_id
                GROUP BY h.execution_owner""", (scan_id,),
            ):
                owners[owner] = count
                hypothesis_count += count
            return {"database": str(path), "scan_id": scan_id, "case_count": len(cases),
                    "cases": cases, "impact_hypothesis_count": hypothesis_count,
                    "impact_hypotheses_by_owner": owners}
    except ValidationError:
        raise
    except (OSError, sqlite3.Error, json.JSONDecodeError):
        raise ValidationError("cannot read shared Validation status") from None


def _case(case: dict) -> dict:
    decision_json = case.pop("decision_json")
    if decision_json is not None:
        decision = json.loads(decision_json)
        if canonical_sha256(decision) != case["decision_sha256"]:
            raise ValidationError("Validation decision digest mismatch")
        case["decision"] = decision
    case["effective_status"] = (
        "DEVELOPING" if case["processing_phase"] == "developing" else case["current_status"]
    )
    return case


def _json_row(row: sqlite3.Row) -> dict:
    result = dict(row)
    for key in tuple(result):
        if key.endswith("_json"):
            result[key[:-5]] = json.loads(result.pop(key))
    result["potential_impact_is_advisory"] = True
    return result
