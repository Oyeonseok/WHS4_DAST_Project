"""Eligibility contracts are deterministic before an LLM or replay is involved."""

from __future__ import annotations

import hashlib
import json

import pytest

from aidast.validation import (
    EligibilityAssessment,
    EligibilityRequest,
    ScopeEligibilityError,
    ScopePolicySource,
    unknown_assessment,
    validate_grounding,
)


def eligibility_request(**overrides):
    document = {
        "case_id": "case", "scope_sha256": "a" * 64, "phase": "preflight",
        "scope_markdown": "# Approved policy\nActual rule", "target_kind": "finding",
        "vuln_class": "open_redirect", "endpoint": "https://example.test/redirect",
        "method": "GET", "title": "Open redirect",
        "claimed_impact": "redirect to a controlled destination",
        "reproduction_summary": {"attempt": "bounded"},
        "evidence_refs": ("evidence",), "evidence_summaries": ({"id": "evidence"},),
    }
    return EligibilityRequest(**(document | overrides))


def eligible_assessment(**overrides):
    document = {
        "case_id": "case", "scope_sha256": "a" * 64, "phase": "preflight",
        "eligibility": "ELIGIBLE", "exclusion_kind": None,
        "matched_rule": "Approved rule", "scope_quote": "Actual rule",
        "required_impact": (), "replay_allowed": True,
        "reason": "The approved rule permits this finding.", "evidence_refs": ("evidence",),
    }
    return EligibilityAssessment(**(document | overrides))


def test_conditional_requires_impact_and_replay_permission():
    with pytest.raises(ValueError):
        EligibilityAssessment(
            case_id="case", scope_sha256="a" * 64, phase="preflight",
            eligibility="CONDITIONAL", exclusion_kind="open_redirect",
            matched_rule="Open redirect requires additional impact",
            scope_quote="Open redirects without additional security impact",
            required_impact=(), replay_allowed=True, reason="Impact is not yet shown",
            evidence_refs=(),
        )


def test_grounding_rejects_quote_not_present_in_snapshot():
    assessment = eligible_assessment(scope_quote="invented policy text")
    with pytest.raises(ScopeEligibilityError, match="scope quote is not grounded"):
        validate_grounding(assessment, "# Approved policy\nActual rule")


def test_grounding_rejects_digest_not_bound_to_snapshot():
    assessment = eligible_assessment(scope_sha256="b" * 64)
    with pytest.raises(ScopeEligibilityError, match="scope digest does not match scope snapshot"):
        validate_grounding(assessment, "# Approved policy\nActual rule")


def test_grounding_rejects_an_unknown_assessment_with_an_invented_quote():
    assessment = unknown_assessment(eligibility_request(), "The policy response was invalid.")
    assessment = assessment.model_copy(update={"scope_quote": "invented policy text"})
    with pytest.raises(ScopeEligibilityError, match="scope quote is not grounded"):
        validate_grounding(assessment, "# Approved policy\nActual rule")


def test_unknown_assessment_fails_closed_with_request_binding():
    request = eligibility_request()
    assessment = unknown_assessment(request, "The policy response was invalid.")
    assert assessment.case_id == request.case_id
    assert assessment.scope_sha256 == request.scope_sha256
    assert assessment.phase == request.phase
    assert assessment.eligibility == "UNKNOWN"
    assert assessment.replay_allowed is False
    assert assessment.scope_quote == ""


def test_scope_policy_source_hashes_exact_utf8_and_validates_approval(tmp_path):
    scope_bytes = b"# Approved policy\n"
    scope_path = tmp_path / "Scope.md"
    scope_path.write_bytes(scope_bytes)
    approval_bytes = json.dumps({
        "scope_id": "scope",
        "approved_by": "reviewer",
        "approved_at": "2026-09-18T00:00:00Z",
        "scope_json_sha256": "b" * 64,
        "scope_markdown_sha256": hashlib.sha256(scope_bytes).hexdigest(),
    }).encode("utf-8")
    (tmp_path / "Approval.json").write_bytes(approval_bytes)

    source = ScopePolicySource.from_path(scope_path)

    assert source.scope_markdown == "# Approved policy\n"
    assert source.scope_sha256 == hashlib.sha256(scope_bytes).hexdigest()
    assert source.approval_digest == hashlib.sha256(approval_bytes).hexdigest()
    assert source.source_path == str(scope_path)


def test_scope_policy_source_rejects_sidecar_digest_mismatch(tmp_path):
    scope_path = tmp_path / "Scope.md"
    scope_path.write_text("# Approved policy\n", encoding="utf-8")
    (tmp_path / "Approval.json").write_text(json.dumps({
        "scope_id": "scope",
        "approved_by": "reviewer",
        "approved_at": "2026-09-18T00:00:00Z",
        "scope_json_sha256": "b" * 64,
        "scope_markdown_sha256": "a" * 64,
    }), encoding="utf-8")

    with pytest.raises(ScopeEligibilityError, match="scope approval digest mismatch"):
        ScopePolicySource.from_path(scope_path)


def test_scope_policy_source_from_text_is_deterministic():
    source = ScopePolicySource.from_text("# Approved policy\n", "fixture.md")
    assert source.scope_sha256 == hashlib.sha256(b"# Approved policy\n").hexdigest()
    assert source.approval_digest is None
