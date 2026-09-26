"""Conservatively compare a repeated Blind replay with its preceding decision."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..contracts.models import BlindAssessment, canonical_sha256


AXES = ("impact_boundary", "impact_sensitivity", "impact_actor_requirements")


def _replay_signature(conn: sqlite3.Connection, case_id: str,
                      stage_run_id: str,
                      attempt_ids: tuple[str, ...]) -> tuple[tuple[Any, ...], ...]:
    if not attempt_ids:
        return ()
    placeholders = ",".join("?" for _ in attempt_ids)
    rows = conn.execute(
        f"""SELECT a.attempt_kind,a.ordinal,a.batch_no,a.signal_type,a.outcome,
                  a.signal_observed,a.blocker_axis,e.content_sha256,e.content_length
           FROM validation_attempts a
           JOIN validation_evidence e ON e.attempt_id=a.attempt_id
             AND e.evidence_kind='observation'
           WHERE a.case_id=? AND a.stage_run_id=?
             AND a.attempt_id IN ({placeholders})
           ORDER BY a.batch_no,a.attempt_kind,a.ordinal""",
        (case_id, stage_run_id, *attempt_ids),
    ).fetchall()
    return tuple(tuple(row) for row in rows) if len(rows) == len(attempt_ids) else ()


def _without_batch_numbers(rows: tuple[tuple[Any, ...], ...]) -> tuple[tuple[Any, ...], ...]:
    return tuple(row[:2] + row[3:] for row in rows)


def bound_revalidated_assessment(
    conn: sqlite3.Connection, case: dict[str, Any], stage_run_id: str,
    assessment: BlindAssessment,
) -> tuple[BlindAssessment, dict[str, Any]]:
    """Cap optimistic drift only when the previous UNDERPOWERED replay is identical."""
    raw_axes = [getattr(assessment, name).score for name in AXES]
    audit: dict[str, Any] = {
        "raw_axes": raw_axes,
        "effective_axes": list(raw_axes),
        "prior_stage_run_id": None,
    }
    prior_stage = case.get("decision_stage_run_id")
    if (case.get("current_status") != "UNDERPOWERED" or prior_stage is None
            or prior_stage == stage_run_id or assessment.reproduced is not True):
        return assessment, audit
    prior_scope = conn.execute(
        """SELECT scope_sha256 FROM validation_eligibility_assessments
           WHERE case_id=? AND stage_run_id=? AND phase='preflight'
           ORDER BY rowid DESC LIMIT 1""",
        (case["case_id"], prior_stage),
    ).fetchone()
    if prior_scope is None or prior_scope[0] != case.get("scope_sha256"):
        return assessment, audit
    prior_row = conn.execute(
        """SELECT details_json,content_sha256 FROM validation_evidence
           WHERE case_id=? AND stage_run_id=? AND evidence_kind='blind_assessment'
           ORDER BY rowid DESC LIMIT 1""",
        (case["case_id"], prior_stage),
    ).fetchone()
    if prior_row is None:
        return assessment, audit
    prior_document = json.loads(prior_row[0])
    if (canonical_sha256(prior_document) != prior_row[1]
            or prior_document.get("blind_case_sha256") != assessment.blind_case_sha256
            or prior_document.get("reproduced") is not True):
        return assessment, audit
    current_replay = _replay_signature(
        conn, case["case_id"], stage_run_id,
        (*assessment.target_attempt_ids, *assessment.control_attempt_ids),
    )
    prior_replay = _replay_signature(
        conn, case["case_id"], prior_stage,
        (*prior_document["target_attempt_ids"], *prior_document["control_attempt_ids"]),
    )
    if (len(current_replay) < 5
            or _without_batch_numbers(current_replay)
                != _without_batch_numbers(prior_replay)):
        return assessment, audit
    prior_axes = [prior_document[name]["score"] for name in AXES]
    effective = [min(old, new) for old, new in zip(prior_axes, raw_axes, strict=True)]
    audit.update(
        effective_axes=effective,
        prior_stage_run_id=prior_stage,
        replay_signature_sha256=canonical_sha256(current_replay),
    )
    if effective == raw_axes:
        return assessment, audit
    updates = {}
    for name, score in zip(AXES, effective, strict=True):
        current_axis = getattr(assessment, name)
        if score < current_axis.score:
            updates[name] = current_axis.model_copy(update={
                "score": score,
                "reason": "Unchanged replay; impact cannot rise from Blind rescoring alone.",
            })
    return assessment.model_copy(update=updates), audit
