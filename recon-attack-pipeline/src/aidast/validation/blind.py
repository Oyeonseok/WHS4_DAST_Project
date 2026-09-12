"""In-memory disclosure boundary between blind replay and Attack claims."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from .models import (BlindAssessment, Digest, Identifier, StrictContract,
                     canonical_sha256)


class BlindCase(StrictContract):
    case_id: Identifier
    target_kind: Literal["finding", "chain"]
    endpoint: str
    method: str
    injection_location: Literal["path", "query", "header", "cookie", "body"]
    parameter_name: str
    payload_template: dict[str, Any] | list[Any] | str | int | float | bool | None
    required_identity_roles: tuple[str, ...]
    credential_references: tuple[Identifier, ...]
    signal_types: tuple[str, ...]
    controls: dict[str, Any]
    attack_skill_name: Identifier
    attack_skill_sha256: Digest
    validation_skill_sha256: Digest
    validation_profile_sha256: Digest


class AttackClaim(StrictContract):
    target_kind: Literal["finding", "chain"]
    target_id: Identifier
    vuln_class: str
    title: str
    claimed_impact: str
    claimed_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    attack_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)


class BlindDisclosureError(ValueError):
    pass


class StagedBlindCase:
    """Keep the claim inaccessible until a valid assessment is frozen."""

    def __init__(self, blind_case: BlindCase, attack_claim: AttackClaim):
        if blind_case.target_kind != attack_claim.target_kind:
            raise BlindDisclosureError("blind case and Attack claim target kinds differ")
        self._blind_case = blind_case
        self._attack_claim = attack_claim
        self.blind_case_sha256 = canonical_sha256(blind_case.model_dump())
        self.attack_claim_sha256 = canonical_sha256(attack_claim.model_dump())
        self.blind_assessment_sha256: str | None = None

    def blind_view(self) -> dict[str, Any]:
        """Return only the allowlisted BlindCase, copied through serialization."""
        return self._blind_case.model_dump(mode="json") | {
            "blind_case_sha256": self.blind_case_sha256,
        }

    def freeze_assessment(self, assessment: BlindAssessment) -> str:
        if self.blind_assessment_sha256 is not None:
            raise BlindDisclosureError("blind assessment is already frozen")
        if assessment.case_id != self._blind_case.case_id:
            raise BlindDisclosureError("blind assessment belongs to another case")
        if assessment.blind_case_sha256 != self.blind_case_sha256:
            raise BlindDisclosureError("blind case digest mismatch")
        self.blind_assessment_sha256 = canonical_sha256(assessment.model_dump())
        return self.blind_assessment_sha256

    def reveal_claim(self, current_claim: AttackClaim) -> dict[str, Any]:
        if self.blind_assessment_sha256 is None:
            raise BlindDisclosureError("Attack claim is unavailable before assessment freeze")
        if canonical_sha256(current_claim.model_dump()) != self.attack_claim_sha256:
            raise BlindDisclosureError("Attack claim changed after staging")
        return self._attack_claim.model_dump(mode="json") | {
            "attack_claim_sha256": self.attack_claim_sha256,
            "blind_assessment_sha256": self.blind_assessment_sha256,
        }
