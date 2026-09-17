"""Transactional shared Pipeline.db storage for Validation-owned rows."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

from aidast.recon.db import new_id, now

from ..core.decision import evaluate_impact
from .evidence_policy import sanitize_metadata
from ..contracts.models import ValidationError, TerminalStatus, canonical_json, canonical_sha256


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
                    signal_observed: bool | None = None, blocker_axis: str | None = None,
                    attempt_id: str | None = None,
                    impact_hypothesis_id: str | None = None) -> str:
        identifier = attempt_id or new_id("vattempt")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            if impact_hypothesis_id is not None and self.conn.execute(
                """SELECT 1 FROM validation_impact_hypotheses
                   WHERE hypothesis_id=? AND case_id=? AND stage_run_id=?""",
                (impact_hypothesis_id, case_id, stage_run_id),
            ).fetchone() is None:
                raise ValidationRepositoryError("impact attempt cites a foreign hypothesis")
            self.conn.execute(
                """INSERT INTO validation_attempts
                (attempt_id,case_id,stage_run_id,batch_no,attempt_kind,ordinal,signal_type,outcome,
                 signal_observed,blocker_axis,observation_json,finished_at,impact_hypothesis_id)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, batch_no, attempt_kind, ordinal, signal_type,
                 outcome, signal_observed, blocker_axis,
                 canonical_json(sanitize_metadata(observation or {})), now() if finished else None,
                 impact_hypothesis_id),
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
        encoded = canonical_json(sanitize_metadata(details))
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

    def complete_attempt(self, attempt_id: str, *, outcome: str,
                         signal_observed: bool | None, blocker_axis: str | None,
                         observation: dict[str, Any]) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_attempts SET outcome=?,signal_observed=?,blocker_axis=?,
                observation_json=?,finished_at=? WHERE attempt_id=? AND finished_at IS NULL""",
                (outcome, signal_observed, blocker_axis,
                 canonical_json(sanitize_metadata(observation)), now(), attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("Validation attempt is missing or already completed")

    def stage_blind_case(self, case_id: str, *, stage_run_id: str, expected_version: int,
                         attack_skill_name: str, skill_sha256: str,
                         validation_profile_sha256: str, source_policy_sha256: str,
                         current_policy_sha256: str, blind_case_sha256: str,
                         attack_claim_sha256: str) -> int:
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='blind_replay',
                attack_skill_name=?,skill_sha256=?,validation_profile_sha256=?,
                source_policy_sha256=?,current_policy_sha256=?,blind_case_sha256=?,
                attack_claim_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?
                AND processing_phase IN ('queued','interrupted')""",
                (attack_skill_name, skill_sha256, validation_profile_sha256,
                 source_policy_sha256, current_policy_sha256, blind_case_sha256,
                 attack_claim_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while staging blind input")
        return expected_version + 1

    def resume_blind_case(self, case_id: str, *, stage_run_id: str,
                          expected_version: int, current_policy_sha256: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='blind_replay',
                current_policy_sha256=?,updated_at=? WHERE case_id=?
                AND latest_stage_run_id=? AND state_version=? AND processing_phase='queued'
                AND blind_case_sha256 IS NOT NULL AND blind_assessment_sha256 IS NULL""",
                (current_policy_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case cannot resume at blind replay")

    def resume_unblinding(self, case_id: str, *, stage_run_id: str,
                          expected_version: int, current_policy_sha256: str) -> None:
        """Resume after the immutable blind assessment has already been committed."""
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='unblinding',
                current_policy_sha256=?,updated_at=? WHERE case_id=?
                AND latest_stage_run_id=? AND state_version=? AND processing_phase='queued'
                AND blind_case_sha256 IS NOT NULL AND blind_assessment_sha256 IS NOT NULL""",
                (current_policy_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case cannot resume at unblinding")

    def freeze_blind_assessment(self, case_id: str, *, stage_run_id: str,
                                expected_version: int, assessment_sha256: str) -> int:
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='unblinding',
                blind_assessment_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?
                AND processing_phase='blind_replay' AND blind_assessment_sha256 IS NULL""",
                (assessment_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while freezing blind assessment")
        return expected_version + 1

    def set_processing_phase(self, case_id: str, *, stage_run_id: str,
                             phase: str) -> None:
        if phase not in {"blind_replay", "developing"}:
            raise ValidationRepositoryError("unsupported intermediate processing phase")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            self.conn.execute(
                "UPDATE validation_cases SET processing_phase=?,updated_at=? WHERE case_id=?",
                (phase, now(), case_id),
            )

    def add_development_action(self, *, case_id: str, stage_run_id: str, ordinal: int,
                               blocker_axis: str, action_type: str,
                               details: dict[str, Any] | None = None) -> str:
        identifier = new_id("vaction")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            self.conn.execute(
                """INSERT INTO validation_development_actions
                (action_id,case_id,stage_run_id,ordinal,blocker_axis,action_type,status,details_json)
                VALUES (?,?,?,?,?,?,'planned',?)""",
                (identifier, case_id, stage_run_id, ordinal, blocker_axis, action_type,
                 canonical_json(sanitize_metadata(details or {}))),
            )
        return identifier

    def start_development_action(self, action_id: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions
                   SET status='running',started_at=?
                   WHERE action_id=? AND status='planned'""",
                (now(), action_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError(
                    "development action is missing or already started"
                )

    def finish_development_action(self, action_id: str, *, succeeded: bool,
                                  details: dict[str, Any] | None = None) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions SET status=?,details_json=?,
                started_at=COALESCE(started_at,?),finished_at=?
                WHERE action_id=? AND status IN ('planned','running')""",
                ("succeeded" if succeeded else "failed",
                 canonical_json(sanitize_metadata(details or {})), now(), now(), action_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("development action is missing or already finished")

    def mark_development_action_outcome_unknown(
        self, action_id: str, *, details: dict[str, Any] | None = None,
    ) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions
                   SET status='outcome_unknown',details_json=?,
                       started_at=COALESCE(started_at,?),finished_at=?
                   WHERE action_id=? AND status IN ('planned','running')""",
                (
                    canonical_json(sanitize_metadata(details or {})),
                    now(), now(), action_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError(
                    "development action is missing or already finished"
                )

    def add_impact_hypothesis(self, *, case_id: str, stage_run_id: str, ordinal: int,
                              proposal: dict[str, Any], skill_sha256: str,
                              validation_profile_sha256: str) -> str:
        identifier = new_id("vhypothesis")
        required = {
            "gap_axis", "path_id", "hypothesis_kind", "current_score", "reason",
            "required_preconditions", "recommended_actions", "expected_signal",
            "supporting_evidence_ids", "execution_owner", "feasibility", "potential_impact",
        }
        if set(proposal) != required:
            raise ValidationRepositoryError("impact hypothesis fields do not match the contract")
        evidence_ids = proposal["supporting_evidence_ids"]
        if not isinstance(evidence_ids, (list, tuple)) or not evidence_ids:
            raise ValidationRepositoryError("impact hypothesis requires current-stage evidence")
        digest_input = {key: proposal[key] for key in sorted(proposal)}
        proposal_sha256 = canonical_sha256(digest_input)
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            placeholders = ",".join("?" for _ in evidence_ids)
            count = self.conn.execute(
                f"SELECT count(*) FROM validation_evidence WHERE case_id=? AND stage_run_id=? "
                f"AND evidence_id IN ({placeholders})", (case_id, stage_run_id, *evidence_ids),
            ).fetchone()[0]
            if count != len(set(evidence_ids)):
                raise ValidationRepositoryError("impact hypothesis cites foreign evidence")
            existing = self.conn.execute(
                """SELECT hypothesis_id,proposal_sha256 FROM validation_impact_hypotheses
                   WHERE case_id=? AND stage_run_id=? AND path_id=?""",
                (case_id, stage_run_id, proposal["path_id"]),
            ).fetchone()
            if existing is not None:
                if existing[1] != proposal_sha256:
                    raise ValidationRepositoryError("stored impact hypothesis changed")
                return existing[0]
            self.conn.execute(
                """INSERT INTO validation_impact_hypotheses
                (hypothesis_id,case_id,stage_run_id,ordinal,gap_axis,path_id,hypothesis_kind,
                current_score,reason_json,required_preconditions_json,recommended_actions_json,
                expected_signal_json,supporting_evidence_ids_json,execution_owner,feasibility,
                potential_impact_json,skill_sha256,validation_profile_sha256,proposal_sha256)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, ordinal, proposal["gap_axis"],
                 proposal["path_id"], proposal["hypothesis_kind"], proposal["current_score"],
                 canonical_json(sanitize_metadata(proposal["reason"])),
                 canonical_json(sanitize_metadata(proposal["required_preconditions"])),
                 canonical_json(sanitize_metadata(proposal["recommended_actions"])),
                 canonical_json(sanitize_metadata(proposal["expected_signal"])),
                 canonical_json(list(evidence_ids)), proposal["execution_owner"],
                 proposal["feasibility"], canonical_json(sanitize_metadata(proposal["potential_impact"])),
                 skill_sha256, validation_profile_sha256, proposal_sha256),
            )
        return identifier

    def read_impact_hypothesis(self, hypothesis_id: str) -> dict[str, Any]:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute(
            "SELECT * FROM validation_impact_hypotheses WHERE hypothesis_id=?",
            (hypothesis_id,),
        ).fetchone()
        if row is None:
            raise ValidationRepositoryError("unknown impact hypothesis")
        result = dict(row)
        for source, target in (
            ("plan_json", "plan"), ("observation_json", "observation"),
        ):
            if result.get(source) is not None:
                value = json.loads(result[source])
                digest = result[source.replace("_json", "_sha256")]
                if canonical_sha256(value) != digest:
                    raise ValidationRepositoryError("impact execution digest mismatch")
                result[target] = value
        return result

    def record_impact_plan(self, hypothesis_id: str, *, agent_id: str,
                           plan: dict[str, Any]) -> None:
        encoded = canonical_json(plan)
        status = "skipped" if plan.get("disposition") == "skip" else "planned"
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET agent_id=?,plan_json=?,plan_sha256=?,status=?,
                       finished_at=CASE WHEN ?='skipped' THEN ? ELSE finished_at END
                   WHERE hypothesis_id=? AND status='planned' AND plan_json IS NULL""",
                (agent_id, encoded, canonical_sha256(plan), status, status, now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("impact hypothesis is not available for planning")

    def start_impact_hypothesis(self, hypothesis_id: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses SET status='running',started_at=?
                   WHERE hypothesis_id=? AND status='planned' AND plan_json IS NOT NULL""",
                (now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("impact hypothesis is not ready to execute")

    def finish_impact_hypothesis(self, hypothesis_id: str, *,
                                 observation: dict[str, Any]) -> None:
        encoded = canonical_json(observation)
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='succeeded',observation_json=?,observation_sha256=?,finished_at=?
                   WHERE hypothesis_id=? AND status='running'""",
                (encoded, canonical_sha256(observation), now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                row = self.conn.execute(
                    """SELECT status,observation_sha256 FROM validation_impact_hypotheses
                       WHERE hypothesis_id=?""", (hypothesis_id,),
                ).fetchone()
                if row is None or row[0] != "succeeded" or row[1] != canonical_sha256(observation):
                    raise ValidationRepositoryError("impact hypothesis cannot be completed")

    def mark_impact_hypothesis_outcome_unknown(self, hypothesis_id: str) -> None:
        with self.conn:
            self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='outcome_unknown',finished_at=?
                   WHERE hypothesis_id=? AND status='running'""",
                (now(), hypothesis_id),
            )

    def fail_impact_hypothesis(self, hypothesis_id: str) -> None:
        with self.conn:
            self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='failed',finished_at=?
                   WHERE hypothesis_id=? AND status='planned'""",
                (now(), hypothesis_id),
            )

    def quarantine_running_impact_hypotheses(self, *, case_id: str,
                                             stage_run_id: str) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='outcome_unknown',finished_at=?
                   WHERE case_id=? AND stage_run_id=? AND status='running'""",
                (now(), case_id, stage_run_id),
            )
        return cursor.rowcount

    def finalize(self, case_id: str, *, stage_run_id: str, expected_version: int,
                 status: TerminalStatus, decision: dict[str, Any], evidence_ids: Iterable[str],
                 impact: tuple[int, int, int] | None = None,
                 known_source_case_id: str | None = None) -> int:
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
                        or source[2] != "completed" or source[3] != source[4]):
                    raise ValidationRepositoryError("KNOWN requires a current same-scan CONFIRMED source")
            elif known_source_case_id is not None:
                raise ValidationRepositoryError("KNOWN source fields are only valid for KNOWN")
            encoded = canonical_json(decision)
            decision_sha = canonical_sha256(decision)
            values = (impact_result.boundary, impact_result.sensitivity,
                      impact_result.actor_requirements, impact_result.score,
                      impact_result.severity) if impact_result else (None,) * 5
            previous = case["current_status"]
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='completed',current_status=?,
                decision_stage_run_id=?,known_source_case_id=?,
                impact_boundary=?,impact_sensitivity=?,impact_actor_requirements=?,impact_score=?,severity=?,
                decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?""",
                (status, stage_run_id, known_source_case_id, *values, encoded,
                 decision_sha, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while committing decision")
            if previous == "CONFIRMED" and status != "CONFIRMED":
                invalidation = {"reason": "known_source_no_longer_confirmed", "source_case_id": case_id}
                invalidation_json = canonical_json(invalidation)
                self.conn.execute(
                    """UPDATE validation_cases SET current_status='INCONCLUSIVE',known_source_case_id=NULL,
                    decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
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
