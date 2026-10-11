"""Transition fixtures must keep each scenario isolated and integrity-valid."""

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.validation.core.integrity import CandidateIntegrityError, CandidateIntegrityGate


def _recorded_inputs():
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    required = ("CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json")
    if not all((source / name).exists() for name in required):
        pytest.skip("pinned local observations are unavailable")
    report = json.loads((source / "LocalControlObservations.json").read_text())
    by_url = {item["url"]: item for item in report["observations"]}
    return source, report, by_url


def test_transition_lab_prepares_balanced_isolated_valid_cases(tmp_path: Path) -> None:
    from scripts.prepare_validation_transition_lab import prepare_transition_lab

    source, report, by_url = _recorded_inputs()
    output = tmp_path / "transition"
    manifest = prepare_transition_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", output,
        live_probe=lambda url: (
            by_url[url]["observed_http_status"], by_url[url]["response_body_sha256"],
            by_url[url]["response_bytes"],
        ),
        identity_probe=lambda: report["runtime_identity"],
        impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"},
            by_url[url]["response_body_sha256"],
        ),
    )
    assert {case["scenario_id"] for case in manifest["cases"]} == {
        "verified_marker", "minimal_threshold", "weak_marker", "false_marker",
        "no_action", "partial_boundary",
    }
    by_name = {case["scenario_id"]: case for case in manifest["cases"]}
    reference = by_name["verified_marker"]["baseline_evidence_sha256"]
    assert all(case["baseline_evidence_sha256"] == reference
               for case in manifest["cases"])
    assert by_name["verified_marker"]["real_axis_trial_ready"] is True
    assert by_name["weak_marker"]["real_axis_trial_ready"] is True
    for name in ("minimal_threshold", "partial_boundary"):
        assert by_name[name]["real_axis_trial_ready"] is False
        assert by_name[name]["real_axis_trial_reason"] == "shared_replay_evidence"
    assert not (output / "validation-transition-answer-key.json").exists()
    weak = manifest["proof_negative_controls"][0]
    assert weak["scenario_id"] == "weak_source_signal"
    answer = json.loads((Path(__file__).resolve().parents[1] /
                         "resources/lab/validation-transition-answer-key.json").read_text())
    assert answer["real_agent_axis_trials"] == {
        "verified_marker": "ready",
        "minimal_threshold": "awaits_distinct_official_observation",
        "weak_marker": "ready",
        "false_marker": "ready",
        "no_action": "ready",
        "partial_boundary": "awaits_distinct_official_observation",
    }
    assert answer["proof_negative_controls"]["weak_source_signal"][
        "expected_gate"] == "runtime_profile_semantics"
    with sqlite3.connect(output / weak["scenario_id"] / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        spec = conn.execute(
            "SELECT runtime_contract_json FROM finding_reproduction_specs WHERE finding_id=?",
            (weak["finding_id"],),
        ).fetchone()
        assert json.loads(spec[0])["target"]["assertions"][0]["expected"] == "users"
        with pytest.raises(CandidateIntegrityError) as error:
            CandidateIntegrityGate(conn).validate_finding(
                case_id="preflight-weak-source-signal",
                scan_id=weak["scan_id"], finding_id=weak["finding_id"],
            )
        assert error.value.check == "runtime_profile_semantics"
    for case in manifest["cases"]:
        bundle = output / case["scenario_id"]
        mapping = json.loads((bundle / "CandidateFindingMap.json").read_text())
        assert len(mapping["cases"]) == 7
        assert mapping["transition_case"]["finding_id"] == case["finding_id"]
        with sqlite3.connect(bundle / "Pipeline.db") as conn:
            conn.row_factory = sqlite3.Row
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            candidate = CandidateIntegrityGate(conn).validate_finding(
                case_id="preflight-" + case["scenario_id"],
                scan_id=case["scan_id"], finding_id=case["finding_id"],
            )
            assert candidate.staged._blind_case.runtime_contract["target"]["assertions"][0][
                "expected"] == '"password":'
            actions = candidate.impact_development_actions
            if case["scenario_id"] == "no_action":
                assert actions == ()
            elif case["scenario_id"] == "weak_marker":
                assert len(actions) == 1
                assert actions[0].precondition_observation is None
            elif case["scenario_id"] == "false_marker":
                assert len(actions[0].assertions) == 3
                assert actions[0].assertions[-1].expected == "ADMIN999"
            else:
                assert len(actions) == 1
                assert actions[0].precondition_observation is not None
    with pytest.raises(ValueError, match="already exists"):
        prepare_transition_lab(
            source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
            source / "LocalControlObservations.json", output,
            live_probe=lambda url: (0, "", 0),
            identity_probe=lambda: report["runtime_identity"],
        )
