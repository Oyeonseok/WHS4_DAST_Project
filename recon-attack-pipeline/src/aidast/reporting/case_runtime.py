"""Report v2 persistence bound to a current shared Pipeline.db Validation case."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import closing
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any

from aidast.validation.models import canonical_json, canonical_sha256

from .models import ReportDraft, validate_draft
from .render import render_report


def _references(value: Any, *, key: str = "") -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for name, child in value.items():
            if name.endswith("evidence_ids") and isinstance(child, list):
                result.update(item for item in child if isinstance(item, str))
            else:
                result.update(_references(child, key=name))
    elif isinstance(value, list):
        for child in value:
            result.update(_references(child, key=key))
    return result


def read_verified_case(path: Path, case_id: str) -> dict[str, Any]:
    """Read one internally consistent case and evidence set in a DB snapshot."""
    from .runtime import ReportError, _path

    source = _path(path, existing=True)
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("BEGIN")
        if conn.execute("PRAGMA user_version").fetchone()[0] < 9:
            raise ReportError("shared Pipeline.db schema v9 is required")
        row = conn.execute("SELECT * FROM validation_cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise ReportError("unknown Validation case")
        case = dict(row)
        if case["current_status"] == "KNOWN":
            return {"eligibility": "known", "case_id": case_id,
                    "known_source_case_id": case["known_source_case_id"]}
        if case["current_status"] == "CONTESTED":
            return {"eligibility": "review_only", "case": case,
                    "review_bundle": json.loads(case["decision_json"])}
        if (case["current_status"] != "CONFIRMED" or case["processing_phase"] != "completed"
                or case["decision_stage_run_id"] != case["latest_stage_run_id"]):
            raise ReportError("report requires a current completed CONFIRMED Validation case")
        try:
            decision = json.loads(case["decision_json"])
        except (TypeError, json.JSONDecodeError):
            raise ReportError("Validation decision is not valid JSON") from None
        if canonical_sha256(decision) != case["decision_sha256"]:
            raise ReportError("Validation decision digest mismatch")
        cited = sorted(_references(decision))
        if not cited:
            raise ReportError("confirmed Validation decision has no evidence citations")
        placeholders = ",".join("?" for _ in cited)
        rows = conn.execute(
            f"""SELECT evidence_id,evidence_kind,details_json,content_sha256,content_length,created_at
            FROM validation_evidence WHERE case_id=? AND stage_run_id=?
            AND evidence_id IN ({placeholders}) ORDER BY evidence_id""",
            (case_id, case["decision_stage_run_id"], *cited),
        ).fetchall()
        if len(rows) != len(cited):
            raise ReportError("Validation decision cites missing or foreign evidence")
        evidence = [dict(item) for item in rows]
        for item in evidence:
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except json.JSONDecodeError:
                raise ReportError("Validation evidence details are invalid") from None
            if len(item["content_sha256"]) != 64 or item["content_length"] < 0:
                raise ReportError("Validation evidence content binding is invalid")
        return {"eligibility": "confirmed", "scan_id": case["scan_id"], "case_id": case_id,
                "target_kind": case["target_kind"], "target_id": case["finding_id"] or case["chain_id"],
                "decision_sha256": case["decision_sha256"], "decision": decision,
                "severity": case["severity"], "impact_score": case["impact_score"],
                "evidence": evidence, "allowed_evidence_ids": cited,
                "evidence_hashes": [
                    {"evidence_id": item["evidence_id"], "content_sha256": item["content_sha256"],
                     "content_length": item["content_length"]} for item in evidence
                ]}


def _context(source: dict[str, Any], platform: str) -> dict[str, Any]:
    from .runtime import PLATFORMS, ReportError, SCHEMA_VERSION, _sha

    if platform not in PLATFORMS:
        raise ReportError("platform must be hackerone, bugcrowd, or intigriti")
    skill_root = files("aidast.skills.reporting")
    skill = skill_root.joinpath("SKILL.md").read_text(encoding="utf-8")
    template = skill_root.joinpath("references", platform + ".md").read_text(encoding="utf-8")
    context = {"schema_version": SCHEMA_VERSION, "platform": platform,
               "source": {key: source[key] for key in (
                   "scan_id", "case_id", "target_kind", "target_id", "decision_sha256", "evidence_hashes",
               )},
               "validation": source, "allowed_evidence_ids": source["allowed_evidence_ids"],
               "skill": skill, "template": template, "skill_sha256": _sha(skill),
               "template_sha256": _sha(template)}
    context["context_sha256"] = canonical_sha256(context)
    return context


_SCHEMA = """
CREATE TABLE report_runs (
 report_id TEXT PRIMARY KEY, source_path TEXT NOT NULL, scan_id TEXT NOT NULL,
 case_id TEXT NOT NULL, decision_sha256 TEXT NOT NULL, context_sha256 TEXT NOT NULL,
 context_json TEXT NOT NULL CHECK(json_valid(context_json)), created_at TEXT NOT NULL
);
CREATE TABLE report_drafts (
 report_id TEXT PRIMARY KEY REFERENCES report_runs(report_id), draft_sha256 TEXT NOT NULL,
 draft_json TEXT NOT NULL CHECK(json_valid(draft_json)), markdown_sha256 TEXT NOT NULL,
 markdown TEXT NOT NULL, created_at TEXT NOT NULL
);
PRAGMA user_version=2;
"""


def _load(path: Path, *, verify_source: bool = True) -> tuple[dict, dict, dict | None, bool]:
    from .runtime import ReportError, _path, _sha

    report_db = _path(path, existing=True)
    with closing(sqlite3.connect(report_db.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        if conn.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ReportError("unsupported shared-case report database version")
        rows = conn.execute("SELECT * FROM report_runs").fetchall()
        if len(rows) != 1:
            raise ReportError("report database must contain exactly one source-bound run")
        run = dict(rows[0])
        draft_row = conn.execute("SELECT * FROM report_drafts WHERE report_id=?", (run["report_id"],)).fetchone()
    context = json.loads(run["context_json"])
    unsigned = {key: value for key, value in context.items() if key != "context_sha256"}
    if canonical_sha256(unsigned) != context.get("context_sha256") or run["context_sha256"] != context.get("context_sha256"):
        raise ReportError("stored report context hash mismatch")
    stale = False
    if verify_source:
        source_path = _path(report_db.parent / run["source_path"], existing=True)
        with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source_conn:
            current = source_conn.execute(
                "SELECT decision_sha256 FROM validation_cases WHERE case_id=?", (run["case_id"],)
            ).fetchone()
        if current is None:
            raise ReportError("prepared report source case no longer exists")
        stale = current[0] != run["decision_sha256"]
        if not stale:
            read_verified_case(source_path, run["case_id"])
    stored = dict(draft_row) if draft_row else None
    if stored:
        if _sha(stored["draft_json"]) != stored["draft_sha256"] or _sha(stored["markdown"]) != stored["markdown_sha256"]:
            raise ReportError("stored report draft hash mismatch")
        draft = validate_draft(json.loads(stored["draft_json"]), context)
        if render_report(draft) != stored["markdown"]:
            raise ReportError("stored report content does not match draft")
    return run, context, stored, stale


def prepare_case_report(pipeline_db: Path, output_dir: Path, *, platform: str, case_id: str) -> dict:
    from .runtime import ReportError, _path

    source_path = _path(pipeline_db, existing=True)
    source = read_verified_case(source_path, case_id)
    if source["eligibility"] == "known":
        return source
    if source["eligibility"] == "review_only":
        return source
    context = _context(source, platform)
    output = _path(output_dir)
    if output.is_relative_to(source_path.parent) or source_path.is_relative_to(output):
        raise ReportError("report output must be separate from the Pipeline database directory")
    output.mkdir(parents=True, exist_ok=True)
    target = output / "Report.db"
    if target.exists():
        _, previous, _, _ = _load(target)
        if previous != context:
            raise ReportError("existing report belongs to a different case, decision, or platform")
    else:
        handle, name = tempfile.mkstemp(prefix=".report-", suffix=".db", dir=output)
        os.close(handle)
        staging = Path(name)
        try:
            with closing(sqlite3.connect(staging)) as conn:
                conn.executescript(_SCHEMA)
                conn.execute("INSERT INTO report_runs VALUES (?,?,?,?,?,?,?,?)", (
                    "report_" + uuid.uuid4().hex, os.path.relpath(source_path, output), source["scan_id"],
                    case_id, source["decision_sha256"], context["context_sha256"], canonical_json(context),
                    datetime.now(timezone.utc).isoformat()))
                conn.commit()
            os.link(staging, target)
        finally:
            staging.unlink(missing_ok=True)
    from .runtime import _publish
    _publish(output / "Report.context.json", canonical_json(context) + "\n")
    _publish(output / "Report.schema.json", canonical_json(ReportDraft.model_json_schema()) + "\n")
    return case_report_status(target)


def record_case_report(report_db: Path, document: dict) -> dict:
    from .runtime import ReportError, _path, _publish, _sha

    path = _path(report_db, existing=True)
    run, context, stored, stale = _load(path)
    if stale:
        raise ReportError("current Validation decision differs from prepared report source")
    draft = validate_draft(document, context)
    encoded = canonical_json(draft.model_dump())
    markdown = render_report(draft)
    if stored and stored["draft_json"] != encoded:
        raise ReportError("report already contains a different immutable draft")
    if stored is None:
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("INSERT INTO report_drafts VALUES (?,?,?,?,?,?)", (
                run["report_id"], _sha(encoded), encoded, _sha(markdown), markdown,
                datetime.now(timezone.utc).isoformat()))
            conn.commit()
    _publish(path.parent / "Report.md", markdown)
    _publish(path.parent / "Report.json", encoded + "\n")
    return case_report_status(path)


def case_report_status(report_db: Path) -> dict:
    run, context, stored, stale = _load(report_db)
    return {"report_id": run["report_id"], "status": "prepared" if stored is None else "drafted",
            "stale": stale, "platform": context["platform"], "case_id": run["case_id"],
            "report_db": str(Path(report_db).resolve()),
            "report_path": None if stored is None else str(Path(report_db).resolve().parent / "Report.md"),
            "source": context["source"], "context_sha256": context["context_sha256"]}
