from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from aidast.cli import main
from aidast.core.http_safety import sanitize_headers
from aidast.core.request_broker import RequestBroker
from aidast.recon.executor import ReconExecutionError
from aidast.orchestration.scope import ScopeCoordinator
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import SourceEvidence, RequiredRequestHeader, HeaderInput
from aidast.web.launch import ApprovedScopeCatalog, ScanLaunchManager, ScanLaunchRequest
from aidast.web.projection import DashboardProjector
from aidast.web.requirements import build_scope_execution_requirements
from test_attack_request_guard import FakeOpener, fixture, guarded_request
from test_recon_workflow import FakeReconMainAgent, PROGRAM_URL


QUOTE = "Include X-Bug-Bounty:HackerOne-username in requests."


class IdentityScopeAgent(FakeReconMainAgent):
    def collect_scope(self, program_url):
        page, analysis = super().collect_scope(program_url)
        text = page.text + "\n" + QUOTE
        page = page.model_copy(update={
            "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        })
        analysis = analysis.model_copy(update={
            "required_request_headers": [RequiredRequestHeader(
                name="X-Intigriti-Username" if "Intigriti" in QUOTE else "X-Bug-Bounty",
                value_template="{intigriti_username}" if "Intigriti" in QUOTE else "{hackerone_username}",
                inputs=[HeaderInput(key="intigriti_username" if "Intigriti" in QUOTE else "hackerone_username", label="Platform username", kind="username")],
                source_quote=QUOTE,
            )],
            "operational_constraints": [*analysis.operational_constraints, QUOTE],
            "source_evidence": [*analysis.source_evidence,
                                SourceEvidence(section="Testing rules", quote=QUOTE)],
        })
        return page, analysis


def test_approved_scope_catalog_exposes_bug_bounty_requirement_and_launcher_requires_handle(tmp_path):
    directory = tmp_path / "Scope" / "bugcrowd" / "example"
    ScopeCoordinator(directory).collect(
        program_url=PROGRAM_URL, main_agent=IdentityScopeAgent(), approved_by="operator",
        review=lambda markdown_path: True,
    )
    scope = ApprovedScopeCatalog(tmp_path).list()[0]
    assert scope.identity_header == "hackerone"
    assert scope.execution_requirements.required_header.name == "X-Bug-Bounty"
    processes = []

    def process_factory(*args, **kwargs):
        processes.append(args)
        raise AssertionError("missing identity must be rejected before process launch")

    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path), process_factory=process_factory)
    with pytest.raises(ValueError, match="hackerone_username"):
        manager.launch(ScanLaunchRequest(
            scope_id=scope.scope_id, targets=["*.example.com"], authorization_confirmed=True,
        ))
    assert processes == []


def _cli(tmp_path, *, execute=False, username=None, intigriti_username=None, agent=None, header_inputs=None):
    output, errors = io.StringIO(), io.StringIO()
    captured = []

    def executor(**kwargs):
        captured.append(kwargs)
        raise ReconExecutionError("stopped at external execution boundary")

    argv = ["recon", PROGRAM_URL, "--target", "*.example.com", "--output-dir", str(tmp_path / "Scope")]
    argv += ["--execute"] if execute else ["--policy-only"]
    if username:
        argv += ["--hackerone-username", username]
    if intigriti_username:
        argv += ["--intigriti-username", intigriti_username]
    for value in header_inputs or []:
        argv += ["--header-input", value]
    with (patch("aidast.cli.CodexMainAgent", return_value=agent or IdentityScopeAgent()),
          patch("aidast.cli.ReconExecutor", side_effect=executor),
          patch("builtins.input", return_value="y"),
          redirect_stdout(output), redirect_stderr(errors)):
        result = main(argv)
    return result, errors.getvalue(), captured


def test_cli_requires_bug_bounty_identity_before_any_target_execution(tmp_path):
    result, errors, captured = _cli(tmp_path, execute=True)
    assert result == 1
    assert "X-Bug-Bounty" in errors and "--hackerone-username" in errors
    assert captured == []


def test_cli_binds_exact_scope_header_into_target_policy(tmp_path):
    result, _, _ = _cli(tmp_path, username="researcher_1")
    assert result == 0
    policy = json.loads((tmp_path / "Scope/bugcrowd/example/TargetPolicy.json").read_text())["policies"][0]
    assert policy.get("required_identity_headers") == {"X-Bug-Bounty": "researcher_1"}


def test_cli_injects_required_header_into_recon_execution(tmp_path):
    _, _, captured = _cli(tmp_path, execute=True, username="researcher_1")
    assert captured[0]["request_headers"] == {"X-Bug-Bounty": "researcher_1"}


def test_intigriti_identity_also_survives_target_policy_for_later_stages(tmp_path, monkeypatch):
    monkeypatch.setattr(__import__(__name__), "QUOTE", "Include X-Intigriti-Username:username in requests.")
    result, _, _ = _cli(tmp_path, intigriti_username="researcher_1")
    assert result == 0
    policy = json.loads((tmp_path / "Scope/bugcrowd/example/TargetPolicy.json").read_text())["policies"][0]
    assert policy.get("required_identity_headers") == {"X-Intigriti-Username": "researcher_1"}


def _policy(headers):
    return TargetPolicy(
        scope_id="scope", policy_id="policy", asset_type="URL", asset="https://example.test/",
        allowed_hosts=["example.test"],
    ).model_copy(update={"required_identity_headers": headers})


@pytest.mark.parametrize("name", ["X-Research-Identity", "Research-Contact", "X-Bug-Bounty"])
def test_recon_http_broker_applies_policy_identity_and_preserves_authentication(name):
    requests = []
    from test_attack_request_guard import FakeResponse

    def transport(request, timeout):
        requests.append(request)
        return FakeResponse(request.full_url)

    RequestBroker(_policy({name: "trusted_researcher"}), transport=transport).request(
        "https://example.test/", headers={name.lower(): "untrusted", "Cookie": "session=owned"},
    )

    assert requests[0].get_header(name.capitalize()) == "trusted_researcher"
    assert requests[0].get_header("Cookie") == "session=owned"


def test_legacy_recon_policy_does_not_remove_manually_supplied_identity():
    requests = []
    from test_attack_request_guard import FakeResponse

    def transport(request, timeout):
        requests.append(request)
        return FakeResponse(request.full_url)

    RequestBroker(_policy({}), transport=transport).request(
        "https://example.test/", headers={"X-HackerOne": "researcher_1"},
    )
    assert requests[0].get_header("X-hackerone") == "researcher_1"


@pytest.mark.parametrize("name", ["X-Research-Identity", "Research-Contact", "X-Bug-Bounty"])
def test_attack_applies_policy_identity_over_case_variant_payload(name, tmp_path):
    database, policy, payload, stage, task = fixture(tmp_path)
    document = json.loads(policy.read_text())
    document["policies"][0]["required_identity_headers"] = {name: "trusted_researcher"}
    policy.write_text(json.dumps(document))
    payload.write_text(json.dumps({
        "method": "GET", "url": "https://example.test/api/profile",
        "headers": {name.lower(): "untrusted"},
    }))
    opener = FakeOpener()
    with patch("aidast.attack.request_cli.build_opener", return_value=opener):
        guarded_request(database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload)
    assert opener.calls[0][0].get_header(name.capitalize()) == "trusted_researcher"


def test_validation_applies_required_identity_after_runtime_and_credential_headers():
    from test_validation_request_broker import ValidationRequestBrokerTests, Response
    from aidast.validation.execution.request_broker import ValidationRequestBroker

    existing = ValidationRequestBrokerTests()
    existing.setUp()
    requests = []
    try:
        policy = existing.policy.model_copy(update={
            "required_identity_headers": {"X-Bug-Bounty": "trusted_researcher"},
        })

        def transport(request, timeout):
            requests.append(request)
            return Response()

        broker = ValidationRequestBroker(
            db_path=existing.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=existing.blind, policy=policy,
            transport=transport, credential_resolver=lambda reference: {
                "X-Bug-Bounty": "credential-override", "Authorization": "Bearer owned",
            }, sleeper=lambda delay: None, clock=lambda: 100.0,
        )
        broker.request("https://test/items/7", method="GET", headers={"x-bug-bounty": "runtime-override"})
        assert requests[0].get_header("X-bug-bounty") == "trusted_researcher"
        assert requests[0].get_header("Authorization") == "Bearer owned"
    finally:
        existing.doCleanups()


def test_bug_bounty_identity_is_redacted_in_persisted_header_views():
    assert sanitize_headers({"X-Bug-Bounty": "private_handle"}) == {"X-Bug-Bounty": "[REDACTED]"}


def test_supported_policy_identity_headers_are_validated_and_preserved():
    data = _policy({}).model_dump()
    data["required_identity_headers"] = {"x-bug-bounty": "researcher_1"}
    try:
        policy = TargetPolicy.model_validate(data)
    except ValueError:
        pytest.fail("known identity header should be accepted and normalized")
    assert policy.required_identity_headers == {"x-bug-bounty": "researcher_1"}


@pytest.mark.parametrize("headers", [
    {"Authorization": "Bearer secret"}, {"Cookie": "session=secret"},
    {"X-Bug-Bounty": "bad\r\nX-Injected: yes"}, {"X-Bug-Bounty": ""},
])
def test_policy_identity_field_cannot_be_used_for_authentication_or_header_injection(headers):
    data = _policy({}).model_dump()
    data["required_identity_headers"] = headers
    with pytest.raises(ValueError):
        TargetPolicy.model_validate(data)


def test_cli_username_alias_does_not_invent_headers_when_ai_declares_none(tmp_path):
    result, _, captured = _cli(tmp_path, execute=True, username="researcher_1", agent=FakeReconMainAgent())
    assert captured[0]["request_headers"] == {}
    policy = json.loads((tmp_path / "Scope/bugcrowd/example/TargetPolicy.json").read_text())["policies"][0]
    assert policy.get("hackerone_username") is None
    assert policy.get("required_identity_headers", {}) == {}
