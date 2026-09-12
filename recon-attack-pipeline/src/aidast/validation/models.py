"""Strict contracts for reviewing previously captured local evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Explanation = Annotated[str, Field(min_length=1, max_length=4000)]
QUESTIONS = ("Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7")


class ValidationError(ValueError):
    """Local evidence, assessment, or persisted provenance is inconsistent."""


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_json(value: Any) -> str:
    """Encode decision inputs deterministically for persisted SHA-256 bindings."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


TerminalStatus = Literal[
    "CONFIRMED", "DISPROVEN", "OUT_OF_SCOPE", "KNOWN", "UNDERPOWERED",
    "BLOCKED", "INCONCLUSIVE", "CONTESTED",
]
ProcessingPhase = Literal[
    "queued", "blind_replay", "developing", "unblinding", "completed", "interrupted",
]
SignalType = Literal[
    "oob_callback", "response_diff", "error_signature", "timing", "dom_effect",
    "state_change", "authorization_boundary",
]
BlockerAxis = Literal[
    "identity_auth", "state_setup", "encoding_transport", "timing_concurrency",
    "environment_topology",
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ImpactAxisProposal(StrictContract):
    score: Annotated[int, Field(ge=0, le=3)]
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    reason: Explanation

    @model_validator(mode="after")
    def unique_evidence(self) -> "ImpactAxisProposal":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("duplicate impact evidence references are not allowed")
        return self


class BlindAssessment(StrictContract):
    case_id: Identifier
    blind_case_sha256: Digest
    reproduced: StrictBool | None
    signal_types: tuple[SignalType, ...] = Field(max_length=7)
    target_attempt_ids: tuple[Identifier, ...] = Field(max_length=6)
    control_attempt_ids: tuple[Identifier, ...] = Field(max_length=64)
    evidence_ids: tuple[Identifier, ...] = Field(max_length=128)
    blocker_axis: BlockerAxis | None = None
    blocker_reason: Explanation | None = None
    impact_boundary: ImpactAxisProposal
    impact_sensitivity: ImpactAxisProposal
    impact_actor_requirements: ImpactAxisProposal
    conclusion: Explanation

    @model_validator(mode="after")
    def consistent_references(self) -> "BlindAssessment":
        groups = (self.signal_types, self.target_attempt_ids, self.control_attempt_ids, self.evidence_ids)
        if any(len(items) != len(set(items)) for items in groups):
            raise ValueError("duplicate blind-assessment references are not allowed")
        if (self.blocker_axis is None) != (self.blocker_reason is None):
            raise ValueError("blocker axis and reason must be supplied together")
        return self


class ClaimComparison(StrictContract):
    case_id: Identifier
    blind_assessment_sha256: Digest
    attack_claim_sha256: Digest
    alignment: Literal["aligned", "conflicting"]
    conflict_axes: tuple[Literal["vuln_class", "boundary", "sensitivity"], ...] = Field(max_length=3)
    validation_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    attack_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    reason: Explanation

    @model_validator(mode="after")
    def conflict_contract(self) -> "ClaimComparison":
        if (self.alignment == "conflicting") != bool(self.conflict_axes):
            raise ValueError("conflict axes are required only for conflicting comparisons")
        for values in (self.conflict_axes, self.validation_evidence_ids, self.attack_evidence_ids):
            if len(values) != len(set(values)):
                raise ValueError("duplicate claim-comparison references are not allowed")
        return self


class ValidationCaseSnapshot(StrictContract):
    case_id: Identifier
    scan_id: Identifier
    target_kind: Literal["finding", "chain"]
    target_id: Identifier
    latest_stage_run_id: Identifier
    decision_stage_run_id: Identifier | None = None
    processing_phase: ProcessingPhase
    current_status: TerminalStatus | None = None
    state_version: Annotated[int, Field(ge=0)]
    decision_sha256: Digest | None = None

    @model_validator(mode="after")
    def decision_binding(self) -> "ValidationCaseSnapshot":
        if (self.current_status is None) != (self.decision_sha256 is None):
            raise ValueError("status and decision digest must be present together")
        if self.processing_phase == "completed" and (
            self.current_status is None or self.decision_stage_run_id != self.latest_stage_run_id
        ):
            raise ValueError("completed snapshots require a current decision from the latest stage")
        return self


class ValidationStageResult(StrictContract):
    stage: Literal["VALIDATION"] = "VALIDATION"
    status: Literal["completed", "failed", "skipped"]
    scan_id: Identifier
    db_path: str
    stage_run_id: Identifier
    case_ids: tuple[Identifier, ...]
    validation_agent_ids: tuple[Identifier, ...] = Field(max_length=1)
    summary: dict[str, Any]


class QuestionAnswer(Contract):
    question_id: Literal["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7"]
    passed: StrictBool | None
    reason: Explanation
    evidence_ids: tuple[Identifier, ...] = Field(max_length=64)


class PoCAssessment(Contract):
    reproduced: StrictBool | None
    reason: Explanation
    evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    request_ids: tuple[Identifier, ...] = Field(max_length=64)


class ValidationAssessment(Contract):
    schema_version: Literal[1]
    context_sha256: Digest
    finding_id: Identifier
    reviewer: Identifier
    questions: tuple[QuestionAnswer, ...] = Field(min_length=7, max_length=7)
    poc: PoCAssessment

    @model_validator(mode="after")
    def exact_questions(self) -> ValidationAssessment:
        if sorted(q.question_id for q in self.questions) != list(QUESTIONS):
            raise ValueError("exactly one answer for each of Q1 through Q7 is required")
        for ids in [q.evidence_ids for q in self.questions] + [self.poc.evidence_ids, self.poc.request_ids]:
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate evidence references are not allowed")
        return self
