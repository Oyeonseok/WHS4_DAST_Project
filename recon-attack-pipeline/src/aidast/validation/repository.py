"""Transactional shared Pipeline.db storage for Validation-owned rows."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from aidast.recon.db import new_id, now

from .impact import evaluate_impact
from .models import TerminalStatus, canonical_json, canonical_sha256


class ValidationRepositoryError(ValueError):
    pass


class ConcurrentValidationUpdate(ValidationRepositoryError):
    pass


class ValidationRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _stage(self, stage_run_id: str, *, running: bool = True) -> sqlite3.Row | tuple:
        row = self.conn.execute(
            "SELECT scan_id,stage,status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
        ).fetchone()
        if row is None or row[1] != "validation" or (running and row[2] != "running"):
            raise ValidationRepositoryError("a running Validation stage is required")
        return row

    def create_case(self, *, scan_id: str, stage_run_id: str, target_kind: str,
                    target_id: str, case_id: str | None = None) -> str:
        if target_kind not in {"finding", "chain"}:
            raise ValidationRepositoryError("target kind must be finding or chain")
        identifier = case_id or new_id("vcase")
        with self.conn:
            stage = self._stage(stage_run_id)
            if stage[0] != scan_id:
                raise ValidationRepositoryError("Validation stage does not belong to scan")
            table, column = (("findings", "finding_id") if target_kind == "finding"
                             else ("finding_chains", "chain_id"))
            if self.conn.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? AND scan_id=?", (target_id, scan_id)
            ).fetchone() is None:
                raise ValidationRepositoryError("Validation target does not belong to scan")
            self.conn.execute(
                """INSERT INTO validation_cases
                (case_id,scan_id,target_kind,finding_id,chain_id,latest_stage_run_id,processing_phase)
                VALUES (?,?,?,?,?,?,'queued')""",
                (identifier, scan_id, target_kind, target_id if target_kind == "finding" else None,
                 target_id if target_kind == "chain" else None, stage_run_id),
            )
        return identifier

    def begin_revalidation(self, case_id: str, *, stage_run_id: str, expected_version: int) -> int:
        with self.conn:
            stage = self._stage(stage_run_id)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET latest_stage_run_id=?,processing_phase='queued',
                   state_version=state_version+1,updated_at=?
                   WHERE case_id=? AND scan_id=? AND state_version=?
                   AND processing_phase='completed'""",
                (stage_run_id, now(), case_id, stage[0], expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed or is not available for revalidation")
        return expected_version + 1

    def add_attempt(self, *, case_id: str, stage_run_id: str, batch_no: int,
                    attempt_kind: str, ordinal: int, signal_type: str, outcome: str,
                    observation: dict[str, Any] | None = None, finished: bool = True,
                    attempt_id: str | None = None) -> str:
        identifier = attempt_id or new_id("vattempt")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            self.conn.execute(
                """INSERT INTO validation_attempts
                (attempt_id,case_id,stage_run_id,batch_no,attempt_kind,ordinal,signal_type,outcome,
                 observation_json,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, batch_no, attempt_kind, ordinal, signal_type,
                 outcome, canonical_json(observation or {}), now() if finished else None),
            )
        return identifier

    def add_evidence(self, *, case_id: str, stage_run_id: str, evidence_kind: str,
                     details: dict[str, Any], content_sha256: str, content_length: int,
                     attempt_id: str | None = None, development_action_id: str | None = None,
                     evidence_id: str | None = None) -> str:
        identifier = evidence_id or new_id("vevidence")
        if (attempt_id is None) == (development_action_id is None) and evidence_kind not in {
            "blind_assessment", "claim_comparison",
        }:
            raise ValidationRepositoryError("execution evidence requires exactly one source")
        encoded = canonical_json(details)
        if len(encoded.encode("utf-8")) > 8192:
            raise ValidationRepositoryError("evidence details exceed 8 KiB")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            relation = attempt_id or development_action_id
            if relation is not None:
                table, column = (("validation_attempts", "attempt_id") if attempt_id else
                                 ("validation_development_actions", "action_id"))
                if self.conn.execute(
                    f"SELECT 1 FROM {table} WHERE {column}=? AND case_id=? AND stage_run_id=?",
                    (relation, case_id, stage_run_id),
                ).fetchone() is None:
                    raise ValidationRepositoryError("evidence source does not belong to case and stage")
            self.conn.execute(
                """INSERT INTO validation_evidence
                (evidence_id,case_id,stage_run_id,attempt_id,development_action_id,evidence_kind,
                 details_json,content_sha256,content_length) VALUES (?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, attempt_id, development_action_id,
                 evidence_kind, encoded, content_sha256, content_length),
            )
        return identifier

    def finalize(self, case_id: str, *, stage_run_id: str, expected_version: int,
                 status: TerminalStatus, decision: dict[str, Any], evidence_ids: Iterable[str],
                 impact: tuple[int, int, int] | None = None,
                 known_source_case_id: str | None = None, known_similarity: float | None = None) -> int:
        cited = tuple(evidence_ids)
        if len(cited) != len(set(cited)):
            raise ValidationRepositoryError("decision evidence IDs must be unique")
        with self.conn:
            case = self._assert_current_case(case_id, stage_run_id)
            if case["state_version"] != expected_version:
                raise ConcurrentValidationUpdate("case state version changed")
            count = self.conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE case_id=? AND stage_run_id=? AND evidence_id IN (%s)"
                % (",".join("?" for _ in cited) or "NULL"), (case_id, stage_run_id, *cited),
            ).fetchone()[0]
            if count != len(cited):
                raise ValidationRepositoryError("decision cites evidence outside the current case and stage")
            impact_result = evaluate_impact(*impact) if impact is not None else None
            if status in {"CONFIRMED", "UNDERPOWERED"} and impact_result is None:
                raise ValidationRepositoryError("impact is required for reproduced decisions")
            if status == "UNDERPOWERED" and not impact_result.underpowered:
                raise ValidationRepositoryError("UNDERPOWERED predicate is not satisfied")
            if status == "CONFIRMED" and impact_result.underpowered:
                raise ValidationRepositoryError("underpowered impact cannot be CONFIRMED")
            if status == "KNOWN":
                source = self.conn.execute(
                    """SELECT scan_id,current_status,processing_phase,latest_stage_run_id,decision_stage_run_id
                    FROM validation_cases WHERE case_id=?""", (known_source_case_id,),
                ).fetchone()
                if (source is None or source[0] != case["scan_id"] or source[1] != "CONFIRMED"
                        or source[2] != "completed" or source[3] != source[4]
                        or known_similarity is None or not 0 <= known_similarity <= 1):
                    raise ValidationRepositoryError("KNOWN requires a current same-scan CONFIRMED source")
            elif known_source_case_id is not None or known_similarity is not None:
                raise ValidationRepositoryError("KNOWN source fields are only valid for KNOWN")
            encoded = canonical_json(decision)
            decision_sha = canonical_sha256(decision)
            values = (impact_result.boundary, impact_result.sensitivity,
                      impact_result.actor_requirements, impact_result.score,
                      impact_result.severity) if impact_result else (None,) * 5
            previous = case["current_status"]
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='completed',current_status=?,
                decision_stage_run_id=?,known_source_case_id=?,known_similarity=?,
                impact_boundary=?,impact_sensitivity=?,impact_actor_requirements=?,impact_score=?,severity=?,
                decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?""",
                (status, stage_run_id, known_source_case_id, known_similarity, *values, encoded,
                 decision_sha, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while committing decision")
            if previous == "CONFIRMED" and status != "CONFIRMED":
                invalidation = {"reason": "known_source_no_longer_confirmed", "source_case_id": case_id}
                invalidation_json = canonical_json(invalidation)
                self.conn.execute(
                    """UPDATE validation_cases SET current_status='INCONCLUSIVE',known_source_case_id=NULL,
                    known_similarity=NULL,decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
                    WHERE known_source_case_id=? AND current_status='KNOWN'""",
                    (invalidation_json, canonical_sha256(invalidation), now(), case_id),
                )
        return expected_version + 1

    def read_case(self, case_id: str) -> dict[str, Any]:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute("SELECT * FROM validation_cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise ValidationRepositoryError("unknown Validation case")
        result = dict(row)
        if result["decision_json"] is not None:
            decision = json.loads(result["decision_json"])
            if canonical_sha256(decision) != result["decision_sha256"]:
                raise ValidationRepositoryError("Validation decision digest mismatch")
            result["decision"] = decision
        return result

    def _assert_current_case(self, case_id: str, stage_run_id: str) -> sqlite3.Row:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute(
            "SELECT * FROM validation_cases WHERE case_id=? AND latest_stage_run_id=?",
            (case_id, stage_run_id),
        ).fetchone()
        if row is None:
            raise ValidationRepositoryError("case is not assigned to the current stage")
        stage = self._stage(stage_run_id)
        if stage[0] != row["scan_id"]:
            raise ValidationRepositoryError("case and stage scan do not match")
        return row
