"""Neon-derived lab policy provenance and actual request-boundary behavior."""

import hashlib
import json
import sqlite3

import pytest

from scripts import prepare_local_lab_scopes as lab
from aidast.core.request_broker import RequestBroker
from aidast.core.request_governor import GovernorError, RequestGovernor
from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.execution_rules import bind_execution_policies
from aidast.scope.identity_headers import resolve_scope_identity_headers
from aidast.scope.models import ProgramPage
from test_request_governor import Clock
from test_validation_request_broker import Response


HEADER_QUOTE = "Use a unique header with your HackerOne username (X-Bug-Bounty:HackerOne-username) in requests to help us identify your testing."
RATE_QUOTE = "Avoid excessive automated scanning; keep requests to 10 per second or lower to prevent potential service impact."


@pytest.fixture
def source(tmp_path):
    document = lab._document(lab.LAB_SCOPES["juice-shop"])
    text = HEADER_QUOTE + "\n" + RATE_QUOTE
    document.source = ProgramPage.model_validate(document.source.model_dump() | {
        "requested_url": "https://hackerone.com/neon_bbp",
        "final_url": "https://hackerone.com/neon_bbp/policy_scopes",
        "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
    })
    path = tmp_path / "NeonScope.json"
    path.write_text(document.model_dump_json())
    return path


def prepare(source, tmp_path, **changes):
    assert hasattr(lab, "prepare_neon_policy_lab"), "Neon-derived lab preparation is not implemented"
    return lab.prepare_neon_policy_lab(
        source_path=source, output_root=tmp_path / "Scope", username="researcher_1",
        approved_by="test-operator", **changes,
    )


@pytest.mark.parametrize("name", ["juice-shop", "vuln-bank"])
def test_profile_publishes_grounded_single_neon_header_and_explicit_local_caps(source, tmp_path, name):
    output = prepare(source, tmp_path)[name]
    document, _ = ScopeCoordinator(output).load_approved_scope()
    analysis = document.analysis
    ScopeCoordinator._require_grounded_analysis(document.source, analysis)
    assert [header.name for header in analysis.required_request_headers] == ["X-Bug-Bounty"]
    assert resolve_scope_identity_headers(analysis, hackerone_username="researcher_1") == {"X-Bug-Bounty": "researcher_1"}
    assert analysis.execution_rules.policy_review_version == 2
    assert analysis.execution_rules.exclusions == []
    assert not analysis.execution_rules.required_inputs
    assert not analysis.execution_rules.blocking_requirements
    quota, = analysis.execution_rules.request_limits
    assert (quota.maximum, quota.period_seconds, quota.scope) == (10, 1.0, "program")
    assert quota.source_quote == RATE_QUOTE
    assert "Local experiment" in document.source.text
    provenance = json.loads((output / "LabPolicyProvenance.json").read_text())
    assert provenance["source_content_sha256"] == json.loads(source.read_text())["source"]["content_sha256"]
    assert set(provenance["adapted_controls"]) == {"requests_per_second", "required_identity_header"}
    assert provenance["local_experiment_controls"] == {"max_requests": 500, "concurrency": 1, "timeout_seconds": 15, "max_depth": 2}


@pytest.mark.parametrize("name,port", [("juice-shop", 3001), ("vuln-bank", 5001)])
def test_target_policy_retains_loopback_boundary_and_active_grant(source, tmp_path, name, port):
    output = prepare(source, tmp_path)[name]
    assert hasattr(lab, "neon_lab_policy"), "Executable policy compilation is not implemented"
    document, markdown = ScopeCoordinator(output).load_approved_scope()
    policy = lab.neon_lab_policy(document, markdown, username="researcher_1")
    assert policy.required_identity_headers == {"X-Bug-Bounty": "researcher_1"}
    assert policy.hackerone_username is None
    assert policy.limits.requests_per_second == 10
    assert policy.limits.max_requests == 500
    assert policy.limits.concurrency == 1
    assert policy.allows_attack_url(f"http://127.0.0.1:{port}/login", method="POST")
    assert not policy.allows_attack_url(f"http://127.0.0.1:{port}/", method="DELETE")
    assert not policy.allows_url("https://console-stage.neon.build/")
    assert not policy.allows_url(f"http://127.0.0.1:{5001 if port == 3001 else 3001}/")
    saved = json.loads((output / "TargetPolicy.json").read_text())
    assert saved["policies"] == [policy.model_dump(mode="json")]
    assert policy.request_governor is None  # Per-scan binding belongs to scan launch.


@pytest.mark.parametrize("change", ["missing_rate", "bad_digest", "foreign_program"])
def test_unverified_source_is_rejected_before_publication(source, tmp_path, change):
    assert hasattr(lab, "prepare_neon_policy_lab"), "Neon source validation is not implemented"
    data = json.loads(source.read_text())
    if change == "missing_rate":
        data["source"]["text"] = HEADER_QUOTE
        data["source"]["content_sha256"] = hashlib.sha256(HEADER_QUOTE.encode()).hexdigest()
    elif change == "bad_digest":
        data["source"]["content_sha256"] = "a" * 64
    else:
        data["source"]["final_url"] = "https://hackerone.com/another_program"
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        prepare(source, tmp_path)
    assert not (tmp_path / "Scope").exists()


def test_repeat_is_byte_identical_and_different_identity_cannot_overwrite(source, tmp_path):
    baseline = tmp_path / "Scope/lab-aidast-invalid/juice-shop"
    baseline.mkdir(parents=True)
    (baseline / "existing.json").write_text("baseline")
    output = prepare(source, tmp_path)
    snapshot = {p: p.read_bytes() for folder in output.values() for p in folder.iterdir() if p.is_file()}
    prepare(source, tmp_path)
    assert all(path.read_bytes() == value for path, value in snapshot.items())
    assert (baseline / "existing.json").read_text() == "baseline"
    with pytest.raises(ValueError, match="different|mismatch"):
        lab.prepare_neon_policy_lab(source_path=source, output_root=tmp_path / "Scope",
                                    username="another_researcher", approved_by="test-operator")
    assert all(path.read_bytes() == value for path, value in snapshot.items())


def test_bound_profile_paces_requests_and_exhausts_budget_across_broker_instances(source, tmp_path):
    output = prepare(source, tmp_path)["juice-shop"]
    assert hasattr(lab, "neon_lab_policy"), "Executable policy compilation is not implemented"
    document, markdown = ScopeCoordinator(output).load_approved_scope()
    policy = lab.neon_lab_policy(document, markdown, username="researcher_1")
    bound = bind_execution_policies({"lab": policy}, document.analysis.execution_rules,
        result_root=tmp_path, program_url=str(document.source.requested_url),
        scan_id="scan_policy_test", prerequisite_evidence={})["lab"]
    clock, requests = Clock(), []

    def transport(request, timeout):
        headers = {name.lower(): value for name, value in request.header_items()}
        requests.append((clock(), headers))
        return Response()

    for index in range(500):
        broker = RequestBroker(bound, transport=transport)
        broker.governor = RequestGovernor(bound.request_governor, clock=clock, sleeper=clock.sleep)
        broker.request(policy.asset, headers={"Cookie": "owned-session", "Authorization": "Bearer owned-token", "X-Bug-Bounty": "wrong"})
        if (index + 1) % 10 == 0:
            if index < 499:
                with pytest.raises(ValueError, match="quota"):
                    broker.request(policy.asset)
            clock.sleep(1.0)  # Permit the next rolling window; do not weaken the quota.
    assert len(requests) == 500
    assert all(headers["x-bug-bounty"] == "researcher_1" and "x-hackerone" not in headers for _, headers in requests)
    assert requests[0][1]["cookie"] == "owned-session"
    assert requests[0][1]["authorization"] == "Bearer owned-token"
    assert all(right[0] - left[0] >= 0.1 - 1e-8 for left, right in zip(requests, requests[1:]))
    with pytest.raises(ValueError, match="budget"):
        broker.request(policy.asset)
    assert len(requests) == 500
    with sqlite3.connect(bound.request_governor.ledger_path) as conn:
        assert conn.execute("SELECT sum(units) FROM governor_requests").fetchone()[0] == 500


def test_profile_shared_concurrency_rejects_second_reservation(source, tmp_path):
    output = prepare(source, tmp_path)["vuln-bank"]
    assert hasattr(lab, "neon_lab_policy"), "Executable policy compilation is not implemented"
    document, markdown = ScopeCoordinator(output).load_approved_scope()
    policy = lab.neon_lab_policy(document, markdown, username="researcher_1")
    policy = bind_execution_policies({"lab": policy}, document.analysis.execution_rules,
        result_root=tmp_path, program_url=str(document.source.requested_url),
        scan_id="scan_policy_test", prerequisite_evidence={})["lab"]
    clock = Clock()
    first = RequestGovernor(policy.request_governor, clock=clock, sleeper=clock.sleep)
    second = RequestGovernor(policy.request_governor, clock=clock, sleeper=clock.sleep)
    permit = first.reserve(policy.asset)
    permit.wait()
    with pytest.raises(GovernorError, match="concurrency"):
        second.reserve(policy.asset)
    permit.complete()
    second.reserve(policy.asset).wait()


def test_cli_generates_both_profiles_without_model_calls(source, tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["prepare_local_lab_scopes", "--policy-profile", "neon-common",
        "--policy-source", str(source), "--hackerone-username", "researcher_1",
        "--output-dir", str(tmp_path / "Scope")])
    try:
        result = lab.main()
    except SystemExit as exc:
        pytest.fail(f"Neon policy CLI is not available: {exc}")
    assert result == 0
    assert len(list((tmp_path / "Scope").glob("*/*/TargetPolicy.json"))) == 2
