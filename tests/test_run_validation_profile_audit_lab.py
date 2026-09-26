"""Controlled audit assessments must obey the real Blind contract."""

from aidast.validation.contracts.models import BlindAssessment, ClaimComparison, canonical_sha256
from scripts.run_validation_profile_audit_lab import ControlledReplayAssessmentAgent


def _observation(kind, ordinal, observed):
    suffix = f"{kind}-{ordinal}"
    return {"attempt_id": suffix, "evidence_id": f"e-{suffix}",
            "attempt_kind": kind, "outcome": "observed" if observed else "not_observed",
            "signal_observed": observed}


def test_controlled_negative_assessment_keeps_citations_with_zero_axes():
    agent = ControlledReplayAssessmentAgent()
    blind = {"case_id": "case", "blind_case_sha256": "a" * 64,
             "signal_types": ["authorization_boundary"]}
    observations = [_observation("positive_control", 1, True),
                    _observation("negative_control", 1, False)] + [
        _observation("target", index, False) for index in (1, 2, 3)]
    assessment = BlindAssessment.model_validate(agent.assess(blind, observations))
    assert assessment.reproduced is False
    assert assessment.impact_boundary.score == 0
    assert assessment.impact_boundary.evidence_ids == (
        "e-target-1", "e-negative_control-1")
    claim = {"blind_assessment_sha256": canonical_sha256(assessment.model_dump(mode="json")),
             "attack_claim_sha256": "b" * 64,
             "attack_evidence_ids": ["attack-evidence"]}
    comparison = ClaimComparison.model_validate(agent.compare(
        claim, assessment.model_dump(mode="json")))
    assert comparison.alignment == "conflicting"


def test_controlled_positive_assessment_keeps_sensitivity_zero():
    agent = ControlledReplayAssessmentAgent()
    blind = {"case_id": "case", "blind_case_sha256": "a" * 64,
             "signal_types": ["error_signature"]}
    observations = [_observation("positive_control", 1, True),
                    _observation("negative_control", 1, False)] + [
        _observation("target", index, True) for index in (1, 2, 3)]
    assessment = BlindAssessment.model_validate(agent.assess(blind, observations))
    assert assessment.reproduced is True
    assert [assessment.impact_boundary.score, assessment.impact_sensitivity.score,
            assessment.impact_actor_requirements.score] == [1, 0, 2]
