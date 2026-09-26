"""A controlled baseline must expose real stage transitions and native GET results."""

import json
from pathlib import Path

import pytest


def test_recording_blind_agent_does_not_change_agent_validation() -> None:
    from scripts.run_validation_transition_lab import RecordingBlindAgent

    raw = {
        "impact_boundary": {"score": 1}, "impact_sensitivity": {"score": 0},
        "impact_actor_requirements": {"score": 2}, "reproduced": True,
        "evidence_ids": ["evidence"],
    }

    class Delegate:
        agent_id = "delegate"

        def assess(self, blind_case, observations, correction=None):
            return raw

    records = []
    agent = RecordingBlindAgent(Delegate(), records)
    assert agent.assess({}, ()) is raw
    assert records[0]["impact_axes"] == [1, 0, 2]


def test_real_blind_mode_keeps_scope_eligibility_fixed(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from unittest.mock import patch
    from scripts.run_validation_transition_lab import (
        FixtureEligibilityAgent, run_transition_case,
    )

    (tmp_path / "TransitionManifest.json").write_text(json.dumps({
        "cases": [{"scenario_id": "single", "finding_id": "finding",
                   "scan_id": "scan"}],
    }))
    (tmp_path / "single").mkdir()

    class Blind:
        agent_id = "blind_real_stub"

        def close(self):
            pass

    class Coordinator:
        eligibility_agent = object()
        impact_development_port = None

        def run(self, scan_id, *, finding_id):
            assert isinstance(self.eligibility_agent, FixtureEligibilityAgent)
            return SimpleNamespace(stage_run_id="stage")

    with (patch("scripts.run_validation_transition_lab.CodexBlindValidationRunner",
                return_value=Blind()),
          patch("scripts.run_validation_transition_lab.build_impact_lab_coordinator",
                return_value=(Coordinator(), {"finding_id": "finding"})),
          patch("scripts.run_validation_transition_lab._case_snapshot",
                return_value={"status": "CONFIRMED", "stage_run_id": "stage"})):
        trace = run_transition_case(tmp_path, "single", assessment_mode="real")
    assert trace["baseline"]["status"] == "CONFIRMED"


def test_real_blind_mode_rejects_unproven_distinct_start_axis(tmp_path: Path) -> None:
    from scripts.run_validation_transition_lab import run_transition_case

    (tmp_path / "TransitionManifest.json").write_text(json.dumps({
        "cases": [{"scenario_id": "partial_boundary", "finding_id": "finding",
                   "scan_id": "scan", "real_axis_trial_ready": False,
                   "real_axis_trial_reason": "shared_replay_evidence"}],
    }))
    (tmp_path / "partial_boundary").mkdir()
    with pytest.raises(ValueError, match="shared_replay_evidence"):
        run_transition_case(tmp_path, "partial_boundary", assessment_mode="real")
    assert not (tmp_path / "partial_boundary" / "TransitionTrace.json").exists()


def _recorded_inputs():
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not (source / "LocalControlObservations.json").exists():
        pytest.skip("pinned local observations are unavailable")
    report = json.loads((source / "LocalControlObservations.json").read_text())
    by_url = {item["url"]: item for item in report["observations"]}
    return source, report, by_url


def test_controlled_transition_records_underpowered_then_current_decision(tmp_path: Path) -> None:
    from scripts.prepare_validation_transition_lab import prepare_transition_lab
    from scripts.run_validation_transition_lab import run_transition_case

    source, report, by_url = _recorded_inputs()
    output = tmp_path / "transition"
    prepare_transition_lab(
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

    class Response:
        def __init__(self, url):
            self.url = url
            self.status = 404 if url.endswith("/missing") else 200
            self.headers = {"Content-Type": "application/json"}

        def geturl(self):
            return self.url

        def read(self, maximum):
            if self.status == 404:
                return b'{"error":"missing"}'
            return b'{"users":[{"username":"admin","account_number":"ADMIN001",' \
                   b'"password":"redacted"}]}'

        def close(self):
            pass

    trace = run_transition_case(
        output, "verified_marker", assessment_mode="fixture", planner_mode="fixture",
        transport=lambda request, timeout: Response(request.full_url),
        impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"},
            by_url[url]["response_body_sha256"],
        ),
    )
    assert trace["transport_mode"] == "injected"
    assert [item["impact_axes"] for item in trace["blind_assessments"]] == [
        [1, 0, 2], [1, 0, 2],
    ]
    assert trace["baseline"]["status"] == "UNDERPOWERED"
    assert trace["developed"]["status"] == "CONFIRMED"
    assert trace["planner_observations"][0]["status"] == "UNDERPOWERED"
    assert trace["planner_observations"][0]["processing_phase"] == "developing"
    assert trace["hypotheses"] == [{"status": "succeeded", "outcome": "observed"}]
    assert (output / "verified_marker" / "TransitionTrace.json").exists()
    from scripts.score_validation_transition_lab import score_transition_case
    report = score_transition_case(output, "verified_marker")
    assert report["checks"]["baseline_underpowered"] is True
    assert report["checks"]["fresh_native_get"] is True
    assert report["checks"]["developing_phase"] is True
    assert report["result"] == "PASS"
    trace_file = output / "verified_marker" / "TransitionTrace.json"
    claimed_native = {**trace, "transport_mode": "native"}
    trace_file.write_text(json.dumps(claimed_native))
    assert score_transition_case(output, "verified_marker")["result"] == "UNRESOLVED"
    trace_file.write_text(json.dumps(trace))
    already_confirmed = {**trace, "assessment_mode": "real",
                         "blind_assessments": [trace["blind_assessments"][0],
                                               {**trace["blind_assessments"][1],
                                                "impact_axes": [1, 1, 2]}]}
    trace_file.write_text(json.dumps(already_confirmed))
    assert score_transition_case(output, "verified_marker")["result"] == "UNRESOLVED"
    trace_file.write_text(json.dumps(trace))
    from scripts.score_validation_transition_lab import DEFAULT_ORACLE
    oracle = json.loads(DEFAULT_ORACLE.read_text())
    oracle["cases"]["verified_marker"]["expected_baseline_axes"] = [0, 0, 2]
    changed_oracle = tmp_path / "changed-oracle.json"
    changed_oracle.write_text(json.dumps(oracle))
    assert score_transition_case(output, "verified_marker", changed_oracle)["result"] == "UNRESOLVED"

    run_transition_case(
        output, "false_marker", assessment_mode="fixture", planner_mode="fixture",
        transport=lambda request, timeout: Response(request.full_url),
        impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"},
            by_url[url]["response_body_sha256"],
        ),
    )
    assert score_transition_case(output, "false_marker")["result"] == "PASS"
    import sqlite3
    from aidast.validation import canonical_sha256
    with sqlite3.connect(output / "false_marker" / "Pipeline.db") as conn:
        evidence_id, raw = conn.execute(
            "SELECT evidence_id,details_json FROM validation_evidence "
            "WHERE evidence_kind='impact_development_observation'"
        ).fetchone()
        changed = json.loads(raw)
        for item in changed["evaluation"]["assertions"]:
            if item["assertion_id"] == "seeded-admin-account":
                item["passed"] = False
            if item["assertion_id"] == "absent-admin-marker":
                item["passed"] = True
        conn.execute("DROP TRIGGER validation_evidence_no_update")
        conn.execute("UPDATE validation_evidence SET details_json=? WHERE evidence_id=?",
                     (json.dumps(changed), evidence_id))
        conn.commit()
    assert score_transition_case(output, "false_marker")["result"] == "UNRESOLVED"


    verified_db = output / "verified_marker" / "Pipeline.db"
    with sqlite3.connect(verified_db) as conn:
        row = conn.execute(
            "SELECT evidence_id,details_json FROM validation_evidence "
            "WHERE evidence_kind='blind_assessment_pre_impact'"
        ).fetchone()
        audit = json.loads(row[1])
        audit["prior_stage_run_id"] = "stage_forged"
        conn.execute("DROP TRIGGER validation_evidence_no_update")
        conn.execute(
            "UPDATE validation_evidence SET details_json=?,content_sha256=? "
            "WHERE evidence_id=?",
            (json.dumps(audit), canonical_sha256(audit), row[0]),
        )
        conn.commit()
    assert score_transition_case(output, "verified_marker")["result"] == "UNRESOLVED"

    class InvalidPlanner:
        agent_id = "invalid_plan_fixture"

        def plan(self, request, *, evidence):
            return {
                "path_id": request.path_id,
                "proposal_sha256": "f" * 64,
                "disposition": "execute", "preconditions_satisfied": True,
                "evidence_ids": list(request.supporting_evidence_ids),
                "reason": "Intentional invalid proposal binding for the error trace.",
            }

        def close(self):
            pass

    from unittest.mock import patch
    with patch("scripts.run_validation_transition_lab.CodexImpactDevelopmentRunner",
               lambda attack_skill_name: InvalidPlanner()):
        with pytest.raises(Exception, match="proposal binding"):
            run_transition_case(
                output, "minimal_threshold", assessment_mode="fixture", planner_mode="real",
                transport=lambda request, timeout: Response(request.full_url),
                impact_marker_probe=lambda url: (
                    {"users", "password", "seeded_admin", "seeded_admin_account"},
                    by_url[url]["response_body_sha256"],
                ),
            )
    error_trace = json.loads((output / "minimal_threshold" / "TransitionTrace.json").read_text())
    assert error_trace["execution_error"]["type"] == "ImpactDevelopmentError"
    assert error_trace["planner_plans"][0]["proposal_sha256"] == "f" * 64
    assert score_transition_case(output, "minimal_threshold")["result"] == "EXECUTION_ERROR"
    with sqlite3.connect(output / "false_marker" / "Pipeline.db") as conn:
        conn.execute("UPDATE validation_evidence SET details_json=? WHERE evidence_id=?",
                     (raw, evidence_id))
        original = json.loads(conn.execute(
            "SELECT decision_json FROM validation_cases WHERE finding_id=?",
            (trace["baseline"].get("finding_id", "lab-finding-27c1f1de26686f70"),),
        ).fetchone()[0])
        original["impact_development"][0]["observation"]["evidence_ids"] = []
        conn.execute("UPDATE validation_cases SET decision_json=?,decision_sha256=? "
                     "WHERE finding_id='lab-finding-27c1f1de26686f70'",
                     (json.dumps(original), canonical_sha256(original)))
        conn.commit()
    assert score_transition_case(output, "false_marker")["result"] == "UNRESOLVED"

def test_field_name_only_agent_score_is_bounded_before_impact_development(
    tmp_path: Path,
) -> None:
    import sqlite3
    from scripts.prepare_validation_transition_lab import prepare_transition_lab
    from scripts.run_validation_transition_lab import run_transition_case

    source, report, by_url = _recorded_inputs()
    output = tmp_path / "proof-bound-transition"
    marker_probe = lambda url: (
        {"users", "password", "seeded_admin", "seeded_admin_account"},
        by_url[url]["response_body_sha256"],
    )
    prepare_transition_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", output,
        live_probe=lambda url: (
            by_url[url]["observed_http_status"], by_url[url]["response_body_sha256"],
            by_url[url]["response_bytes"],
        ),
        identity_probe=lambda: report["runtime_identity"],
        impact_marker_probe=marker_probe,
    )
    manifest_path = output / "TransitionManifest.json"
    manifest = json.loads(manifest_path.read_text())
    selected = next(item for item in manifest["cases"]
                    if item["scenario_id"] == "verified_marker")
    selected["fixture_baseline_axes"]["sensitivity"] = 1
    manifest_path.write_text(json.dumps(manifest))

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, url):
            self.url = url
            if url.endswith("/missing"):
                self.status = 404

        def geturl(self):
            return self.url

        def read(self, maximum):
            if self.status == 404:
                return b'{"error":"missing"}'
            return (b'{"users":[{"username":"admin","account_number":"ADMIN001",'
                    b'"password":"redacted"}]}')

        def close(self):
            pass

    trace = run_transition_case(
        output, "verified_marker", assessment_mode="fixture", planner_mode="fixture",
        transport=lambda request, timeout: Response(request.full_url),
        impact_marker_probe=marker_probe,
    )
    assert trace["blind_assessments"][0]["impact_axes"] == [1, 1, 2]
    assert trace["baseline"]["status"] == "UNDERPOWERED"
    assert trace["baseline"]["impact_axes"] == [1, 0, 2]
    assert trace["planner_observations"][0]["processing_phase"] == "developing"
    assert trace["developed"]["status"] == "CONFIRMED"
    with sqlite3.connect(output / "verified_marker" / "Pipeline.db") as conn:
        audits = [json.loads(row[0]) for row in conn.execute(
            "SELECT details_json FROM validation_evidence "
            "WHERE evidence_kind='blind_assessment_pre_impact' "
            "ORDER BY created_at"
        )]
    assert audits[0]["raw_axes"] == [1, 1, 2]
    assert audits[0]["effective_axes"] == [1, 0, 2]
    assert audits[0]["profile_proof_rule"] == "source_leak_field_name_only"

    from scripts.score_validation_transition_lab import DEFAULT_ORACLE, score_transition_case
    oracle = json.loads(DEFAULT_ORACLE.read_text())
    oracle["cases"]["verified_marker"]["expected_baseline_axes"] = [0, 0, 2]
    changed_oracle = tmp_path / "different-real-scenario.json"
    changed_oracle.write_text(json.dumps(oracle))
    trace_path = output / "verified_marker" / "TransitionTrace.json"
    trace_path.write_text(json.dumps({**trace, "assessment_mode": "real"}))
    assert score_transition_case(output, "verified_marker", changed_oracle)[
        "result"] == "BASELINE_AXIS_MISMATCH"


def test_control_only_axis_citations_are_capped_before_impact_development(tmp_path: Path) -> None:
    import sqlite3
    from unittest.mock import patch
    from scripts.prepare_validation_transition_lab import prepare_transition_lab
    from scripts import run_validation_transition_lab as transition

    source, report, by_url = _recorded_inputs()
    output = tmp_path / "axis-citation-transition"
    prepare_transition_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", output,
        live_probe=lambda url: (
            by_url[url]["observed_http_status"],
            by_url[url]["response_body_sha256"],
            by_url[url]["response_bytes"],
        ),
        identity_probe=lambda: report["runtime_identity"],
        impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"},
            by_url[url]["response_body_sha256"],
        ),
    )

    class ControlOnlyAgent(transition.FixtureBlindAgent):
        def assess(self, blind_case, observations, correction=None):
            raw = super().assess(blind_case, observations, correction)
            control_id = next(item["evidence_id"] for item in observations
                              if item["attempt_kind"] == "positive_control")
            for name in ("impact_boundary", "impact_actor_requirements"):
                raw[name]["evidence_ids"] = (control_id,)
            return raw

    class Response:
        headers = {"Content-Type": "application/json"}

        def __init__(self, url):
            self.url = url
            self.status = 404 if url.endswith("/missing") else 200

        def geturl(self):
            return self.url

        def read(self, maximum):
            if self.status == 404:
                return b'{"error":"missing"}'
            return (b'{"users":[{"username":"admin","account_number":"ADMIN001",'
                    b'"password":"redacted"}]}')

        def close(self):
            pass

    with patch.object(transition, "FixtureBlindAgent", ControlOnlyAgent):
        trace = transition.run_transition_case(
            output, "no_action", assessment_mode="fixture", planner_mode="fixture",
            transport=lambda request, timeout: Response(request.full_url),
            impact_marker_probe=lambda url: (
                {"users", "password", "seeded_admin", "seeded_admin_account"},
                by_url[url]["response_body_sha256"],
            ),
        )
    assert trace["blind_assessments"][0]["impact_axes"] == [1, 0, 2]
    assert trace["baseline"]["impact_axes"] == [0, 0, 0]
    assert trace["baseline"]["status"] == "UNDERPOWERED"
    with sqlite3.connect(output / "no_action" / "Pipeline.db") as conn:
        audit = json.loads(conn.execute(
            "SELECT details_json FROM validation_evidence "
            "WHERE evidence_kind='blind_assessment_pre_impact' ORDER BY rowid LIMIT 1"
        ).fetchone()[0])
    assert audit["raw_axes"] == [1, 0, 2]
    assert audit["effective_axes"] == [0, 0, 0]
    assert set(audit["axis_grounding_rules"]) == {
        "impact_boundary_missing_observed_target",
        "impact_boundary_missing_negative_control",
        "impact_actor_requirements_missing_observed_target",
    }
