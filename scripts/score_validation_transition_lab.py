"""Score a two-stage transition scenario against an independent answer key."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path

from aidast.validation import ImpactDevelopmentRuntimeContract, canonical_sha256, evaluate_impact
from aidast.validation.contracts.impact_development import (
    impact_action_document, impact_contract_document,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORACLE = ROOT / "resources/lab/validation-transition-answer-key.json"
IMPACT_URL = "http://127.0.0.1:5001/debug/users"


def _assertions_match(action, details: dict, expectations: list[dict], *,
                      signal_observed: bool) -> bool:
    """Bind the observed pass/fail pattern to exact immutable assertions."""
    declared = {item.assertion_id: item for item in action.assertions}
    observed = details.get("evaluation", {}).get("assertions", [])
    if (len(declared) != len(expectations) or len(observed) != len(expectations)
            or set(declared) != {item.get("assertion_id") for item in expectations}
            or details.get("evaluation", {}).get("signal_observed") is not signal_observed):
        return False
    by_id = {item.get("assertion_id"): item for item in observed}
    if len(by_id) != len(observed):
        return False
    for expected in expectations:
        identifier = expected["assertion_id"]
        contract, actual = declared[identifier], by_id.get(identifier)
        if (actual is None or contract.kind != expected["kind"]
                or contract.expected != expected["expected"]
                or list(contract.path) != expected.get("path", [])
                or actual.get("kind") != expected["kind"]
                or actual.get("passed") is not expected["passed"]
                or actual.get("expected_sha256") != canonical_sha256(expected["expected"])):
            return False
        actual_value = expected.get("actual", expected["expected"])
        if actual.get("actual_sha256") != canonical_sha256(actual_value):
            return False
    return True


def _replay_signature(conn: sqlite3.Connection, case_id: str,
                      stage_run_id: str, attempt_ids: list[str]) -> tuple[tuple, ...]:
    if (not attempt_ids or any(type(item) is not str for item in attempt_ids)
            or len(attempt_ids) != len(set(attempt_ids))):
        return ()
    placeholders = ",".join("?" for _ in attempt_ids)
    rows = conn.execute(
        f"""SELECT a.attempt_kind,a.ordinal,a.batch_no,a.signal_type,a.outcome,
                  a.signal_observed,a.blocker_axis,e.content_sha256,e.content_length
           FROM validation_attempts a JOIN validation_evidence e
             ON e.attempt_id=a.attempt_id AND e.evidence_kind='observation'
           WHERE a.case_id=? AND a.stage_run_id=?
             AND a.attempt_id IN ({placeholders})
           ORDER BY a.batch_no,a.attempt_kind,a.ordinal""",
        (case_id, stage_run_id, *attempt_ids),
    ).fetchall()
    return tuple(tuple(row) for row in rows) if len(rows) == len(attempt_ids) else ()


def _assessment_attempt_ids(document: dict) -> list[str]:
    targets = document.get("target_attempt_ids")
    controls = document.get("control_attempt_ids")
    if not isinstance(targets, list) or not isinstance(controls, list):
        return []
    return targets + controls


def _stage_assessment(conn: sqlite3.Connection, case_id: str,
                      stage_run_id: str) -> dict | None:
    rows = conn.execute(
        """SELECT details_json,content_sha256 FROM validation_evidence
           WHERE case_id=? AND stage_run_id=? AND evidence_kind='blind_assessment'""",
        (case_id, stage_run_id),
    ).fetchall()
    if len(rows) != 1:
        return None
    value = json.loads(rows[0][0])
    return value if canonical_sha256(value) == rows[0][1] else None


def _without_batch_numbers(rows: tuple[tuple, ...]) -> tuple[tuple, ...]:
    return tuple(row[:2] + row[3:] for row in rows)


def _profile_proof_rule(runtime: dict) -> str | None:
    target = runtime.get("target", {}).get("assertions", [])
    content = [item for item in target
               if item.get("kind") in {"header_equals", "body_contains", "json_equals"}]
    if (len(content) == 1 and content[0].get("kind") == "body_contains"
            and content[0].get("expected") == '"password":'):
        return "source_leak_field_name_only"
    return None


def _proof_bounded_axes(axes: list[int], rule: str | None) -> list[int] | None:
    if len(axes) != 3 or any(type(value) is not int for value in axes):
        return None
    effective = list(axes)
    if rule == "source_leak_field_name_only":
        effective[1] = 0
    elif rule is not None:
        return None
    return effective


def score_transition_case(root: Path, scenario_id: str,
                          oracle_path: Path = DEFAULT_ORACLE) -> dict:
    oracle = json.loads(Path(oracle_path).read_text())
    manifest = json.loads((Path(root) / "TransitionManifest.json").read_text())
    if (oracle.get("fixture_kind") != "synthetic_validation_transition_oracle"
            or manifest.get("fixture_kind") != "synthetic_validation_transition_scenarios"
            or scenario_id not in oracle["cases"]):
        raise ValueError("transition oracle or scenario is invalid")
    selected = next((item for item in manifest["cases"]
                     if item["scenario_id"] == scenario_id), None)
    if selected is None or selected["candidate_id"] != oracle["candidate_id"]:
        raise ValueError("transition scenario does not match oracle candidate")
    expected = oracle["cases"][scenario_id]
    bundle = Path(root) / scenario_id
    trace_path = bundle / "TransitionTrace.json"
    if not trace_path.exists():
        return {"scenario_id": scenario_id, "result": "PENDING", "checks": {}}
    trace = json.loads(trace_path.read_text())
    if trace.get("execution_error"):
        error = trace["execution_error"]
        with sqlite3.connect(bundle / "Pipeline.db") as conn:
            row = conn.execute(
                "SELECT c.processing_phase,c.latest_stage_run_id,s.status "
                "FROM validation_cases c JOIN stage_runs s "
                "ON s.stage_run_id=c.latest_stage_run_id WHERE c.finding_id=?",
                (selected["finding_id"],),
            ).fetchone()
        recorded = bool(
            row and row[0] == error.get("processing_phase") == "interrupted"
            and row[1] == error.get("stage_run_id")
            and row[2] == error.get("stage_status") == "failed"
        )
        return {"scenario_id": scenario_id,
                "result": "EXECUTION_ERROR" if recorded else "UNRESOLVED",
                "error_type": error.get("type"), "error_message": error.get("message"),
                "failed_stage_run_id": error.get("stage_run_id"),
                "checks": {"failed_stage_recorded": recorded}}
    baseline = trace.get("baseline") or {}
    developed = trace.get("developed") or {}
    if not developed and baseline.get("status") != "UNDERPOWERED":
        with sqlite3.connect(bundle / "Pipeline.db") as conn:
            row = conn.execute(
                "SELECT c.current_status,c.processing_phase,s.status "
                "FROM validation_cases c JOIN stage_runs s "
                "ON s.stage_run_id=c.latest_stage_run_id WHERE c.finding_id=?",
                (selected["finding_id"],),
            ).fetchone()
        verified = bool(row and row[0] == baseline.get("status")
                        and row[1] == "completed" and row[2] == "completed")
        return {"scenario_id": scenario_id,
                "result": "BASELINE_NOT_UNDERPOWERED" if verified else "UNRESOLVED",
                "baseline_status": baseline.get("status"), "final_status": None,
                "checks": {"baseline_stage_completed": verified}}
    checks = {}
    blind_records = trace.get("blind_assessments", [])
    predevelopment = None
    preimpact_audit = None
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        runtime_row = conn.execute(
            "SELECT runtime_contract_json,runtime_contract_sha256 "
            "FROM finding_reproduction_specs WHERE finding_id=?",
            (selected["finding_id"],),
        ).fetchone()
        runtime = json.loads(runtime_row[0]) if runtime_row and runtime_row[0] else {}
        runtime_valid = bool(runtime_row and runtime_row[1] == canonical_sha256(runtime))
        profile_rule = _profile_proof_rule(runtime) if runtime_valid else None
        baseline_audit_rows = conn.execute(
            "SELECT details_json,content_sha256 FROM validation_evidence "
            "WHERE stage_run_id=? AND evidence_kind='blind_assessment_pre_impact'",
            (baseline.get("stage_run_id"),),
        ).fetchall()
        baseline_case = conn.execute(
            "SELECT case_id FROM validation_cases WHERE finding_id=?",
            (selected["finding_id"],),
        ).fetchone()
        baseline_document = (
            _stage_assessment(conn, baseline_case[0], baseline.get("stage_run_id"))
            if baseline_case else None
        )
        audit_rows = conn.execute(
            "SELECT details_json,content_sha256 FROM validation_evidence "
            "WHERE stage_run_id=? AND evidence_kind='blind_assessment_pre_impact'",
            (developed.get("stage_run_id"),),
        ).fetchall()
    baseline_audit_valid = not baseline_audit_rows and profile_rule is None
    if len(baseline_audit_rows) == 1 and baseline_document is not None and blind_records:
        try:
            document = json.loads(baseline_audit_rows[0][0])
            raw = document["raw_axes"]
            effective = document["effective_axes"]
            baseline_audit_valid = bool(
                canonical_sha256(document) == baseline_audit_rows[0][1]
                and document.get("prior_stage_run_id") is None
                and "replay_signature_sha256" not in document
                and document.get("profile_proof_rule") == profile_rule
                and raw == blind_records[0].get("impact_axes")
                and effective == _proof_bounded_axes(raw, profile_rule)
                and effective == baseline.get("impact_axes")
                and document.get("effective_assessment") == baseline_document
            )
        except (KeyError, TypeError, ValueError):
            baseline_audit_valid = False
    checks["baseline_proof_audit"] = baseline_audit_valid
    if len(audit_rows) == 1:
        try:
            document = json.loads(audit_rows[0][0])
            if canonical_sha256(document) == audit_rows[0][1]:
                preimpact_audit = document
        except (TypeError, ValueError):
            pass
    audit_valid = bool(
        preimpact_audit is not None and len(blind_records) == 2
        and preimpact_audit.get("raw_axes") == blind_records[1].get("impact_axes")
    )
    if audit_valid:
        prior_stage = preimpact_audit.get("prior_stage_run_id")
        raw_axes = preimpact_audit["raw_axes"]
        effective_axes = preimpact_audit.get("effective_axes")
        sealed = preimpact_audit.get("effective_assessment")
        if sealed is not None:
            try:
                audit_valid = bool(
                    isinstance(sealed, dict)
                    and [sealed[name]["score"] for name in (
                        "impact_boundary", "impact_sensitivity",
                        "impact_actor_requirements",
                    )] == effective_axes
                    and sealed.get("reproduced") == blind_records[1].get("reproduced")
                )
            except (KeyError, TypeError):
                audit_valid = False
    if audit_valid:
        if prior_stage is None:
            audit_valid = (effective_axes == _proof_bounded_axes(raw_axes, profile_rule)
                           and preimpact_audit.get("profile_proof_rule") == profile_rule
                           and "replay_signature_sha256" not in preimpact_audit)
        else:
            with sqlite3.connect(bundle / "Pipeline.db") as conn:
                case_row = conn.execute(
                    "SELECT case_id FROM validation_cases WHERE finding_id=?",
                    (selected["finding_id"],),
                ).fetchone()
                case_id = case_row[0] if case_row else ""
                prior_document = _stage_assessment(conn, case_id, prior_stage)
                current_document = preimpact_audit.get("effective_assessment")
                if not isinstance(current_document, dict):
                    current_document = _stage_assessment(
                        conn, case_id, developed.get("stage_run_id"),
                    )
                current_replay = _replay_signature(
                    conn, case_id, developed.get("stage_run_id"),
                    _assessment_attempt_ids(current_document or {}),
                )
                prior_replay = _replay_signature(
                    conn, case_id, prior_stage,
                    _assessment_attempt_ids(prior_document or {}),
                )
                scopes = conn.execute(
                    """SELECT stage_run_id,scope_sha256 FROM validation_eligibility_assessments
                       WHERE case_id=? AND stage_run_id IN (?,?) AND phase='preflight'""",
                    (case_id, prior_stage, developed.get("stage_run_id")),
                ).fetchall()
            prior_axes = None
            if prior_document is not None:
                try:
                    prior_axes = [prior_document[name]["score"] for name in (
                        "impact_boundary", "impact_sensitivity",
                        "impact_actor_requirements",
                    )]
                except (KeyError, TypeError):
                    pass
            scopes_by_stage = {stage: scope for stage, scope in scopes}
            expected_effective = None
            if (isinstance(raw_axes, list) and len(raw_axes) == 3
                    and isinstance(prior_axes, list) and len(prior_axes) == 3
                    and all(type(value) is int for value in (*raw_axes, *prior_axes))):
                expected_effective = _proof_bounded_axes(
                    [min(old, new) for old, new in zip(prior_axes, raw_axes)],
                    profile_rule,
                )
            audit_valid = bool(
                prior_stage == baseline.get("stage_run_id")
                and len(current_replay) >= 5
                and _without_batch_numbers(current_replay)
                    == _without_batch_numbers(prior_replay)
                and preimpact_audit.get("replay_signature_sha256")
                    == canonical_sha256(current_replay)
                and len(scopes) == 2
                and set(scopes_by_stage) == {prior_stage, developed.get("stage_run_id")}
                and len(set(scopes_by_stage.values())) == 1
                and prior_axes == baseline.get("impact_axes")
                and preimpact_audit.get("profile_proof_rule") == profile_rule
                and effective_axes == expected_effective
            )
    checks["preimpact_audit"] = audit_valid
    if len(blind_records) == 2:
        try:
            predevelopment = evaluate_impact(*preimpact_audit["effective_axes"])
        except (KeyError, TypeError, ValueError):
            pass
    checks["predevelopment_underpowered"] = bool(
        predevelopment is not None and predevelopment.underpowered
        and blind_records[1].get("reproduced") is True
        and (trace.get("assessment_mode") != "fixture" or
             blind_records[1]["impact_axes"] == expected["expected_baseline_axes"])
    )
    expected_after_development = None
    if predevelopment is not None:
        expected_after_development = [
            predevelopment.boundary,
            max(predevelopment.sensitivity, 2)
                if expected["expected_impact_outcome"] == "observed"
                else predevelopment.sensitivity,
            predevelopment.actor_requirements,
        ]
    checks["development_axis_only"] = bool(
        expected_after_development is not None
        and developed.get("impact_axes") == expected_after_development
    )
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        case = conn.execute(
            "SELECT * FROM validation_cases WHERE finding_id=?",
            (selected["finding_id"],),
        ).fetchone()
        baseline_stage = conn.execute(
            "SELECT status FROM stage_runs WHERE stage_run_id=? AND scan_id=?",
            (baseline.get("stage_run_id"), selected["scan_id"]),
        ).fetchone()
        developed_stage = conn.execute(
            "SELECT status FROM stage_runs WHERE stage_run_id=? AND scan_id=?",
            (developed.get("stage_run_id"), selected["scan_id"]),
        ).fetchone()
        blind_rows = conn.execute(
            "SELECT details_json,content_sha256 FROM validation_evidence "
            "WHERE stage_run_id=? AND evidence_kind='blind_assessment'",
            (baseline.get("stage_run_id"),),
        ).fetchall()
        baseline_impact = None
        if len(blind_rows) == 1:
            assessment = json.loads(blind_rows[0]["details_json"])
            if canonical_sha256(assessment) == blind_rows[0]["content_sha256"]:
                baseline_impact = evaluate_impact(
                    assessment["impact_boundary"]["score"],
                    assessment["impact_sensitivity"]["score"],
                    assessment["impact_actor_requirements"]["score"],
                )
        checks["baseline_underpowered"] = bool(
            baseline_stage is not None and baseline_stage["status"] == "completed"
            and baseline.get("status") == expected["expected_baseline_status"]
            and baseline_impact is not None and baseline_impact.underpowered
            and list((baseline_impact.boundary, baseline_impact.sensitivity,
                      baseline_impact.actor_requirements)) == baseline.get("impact_axes")
            and (trace.get("assessment_mode") != "fixture" or
                 baseline.get("impact_axes") == expected["expected_baseline_axes"])
        )
        checks["final_status"] = bool(
            developed_stage is not None and developed_stage["status"] == "completed"
            and case is not None and case["current_status"] == expected["expected_final_status"]
            and case["latest_stage_run_id"] == developed.get("stage_run_id")
            and developed.get("status") == case["current_status"]
            and case["processing_phase"] == "completed"
        )
        checks["fixture_axes"] = (
            trace.get("assessment_mode") != "fixture" or bool(
                case is not None and [case["impact_boundary"], case["impact_sensitivity"],
                                      case["impact_actor_requirements"]]
                == expected["fixture_final_axes"]
            )
        )
        rows = conn.execute(
            "SELECT hypothesis_id,status,observation_json FROM validation_impact_hypotheses "
            "WHERE stage_run_id=? AND case_id=? ORDER BY ordinal",
            (developed.get("stage_run_id"), case["case_id"] if case else ""),
        ).fetchall()
        checks["hypothesis"] = bool(len(rows) == 1 and
            rows[0]["status"] == expected["expected_hypothesis_status"] and
            (json.loads(rows[0]["observation_json"])["outcome"]
             if rows[0]["observation_json"] else None) == expected["expected_impact_outcome"])
        requests = conn.execute(
            "SELECT r.request_id,r.method,r.url,r.status,r.response_status FROM validation_http_requests r "
            "JOIN validation_attempts a ON a.attempt_id=r.attempt_id "
            "WHERE a.stage_run_id=? AND a.case_id=? AND a.impact_hypothesis_id IS NOT NULL",
            (developed.get("stage_run_id"), case["case_id"] if case else ""),
        ).fetchall()
        checks["fresh_native_get"] = bool(
            len(requests) == expected["expected_native_gets"] and all(
                row["method"] == "GET" and row["url"] == IMPACT_URL
                and row["status"] == "completed" and row["response_status"] == 200
                for row in requests
            )
        )
        decision = json.loads(case["decision_json"]) if case and case["decision_json"] else {}
        checks["decision_digest"] = bool(
            case is not None and decision and canonical_sha256(decision) == case["decision_sha256"]
        )
        cited = set(decision.get("evidence_ids", []))
        impact_evidence = conn.execute(
            "SELECT e.evidence_id,e.details_json,e.content_sha256 FROM validation_evidence e "
            "JOIN validation_attempts a ON a.attempt_id=e.attempt_id "
            "WHERE a.stage_run_id=? AND a.case_id=? AND a.impact_hypothesis_id IS NOT NULL "
            "AND e.evidence_kind='impact_development_observation'",
            (developed.get("stage_run_id"), case["case_id"] if case else ""),
        ).fetchall()
        impact_records = decision.get("impact_development", [])
        if expected["expected_native_gets"]:
            linked = bool(
                len(impact_evidence) == len(requests) == len(rows) == len(impact_records) == 1
                and impact_records[0].get("hypothesis_id") == rows[0]["hypothesis_id"]
                and impact_records[0].get("observation", {}).get("evidence_ids")
                    == [impact_evidence[0]["evidence_id"]]
                and impact_records[0].get("observation", {}).get("details", {}).get("request_ids")
                    == [requests[0]["request_id"]]
                and (expected["expected_impact_outcome"] != "observed" or
                     impact_evidence[0]["evidence_id"] in cited)
            )
        else:
            linked = bool(not impact_evidence and (
                len(impact_records) == 0 if scenario_id == "no_action" else
                len(impact_records) == 1 and impact_records[0].get("status") == "skipped"
            ))
        checks["impact_evidence"] = linked
        spec = conn.execute(
            "SELECT impact_development_contract_json,impact_development_contract_sha256 "
            "FROM finding_reproduction_specs WHERE finding_id=?",
            (selected["finding_id"],),
        ).fetchone()
        if expected["expected_native_gets"] and len(impact_evidence) == 1 and spec and spec[0]:
            contract = ImpactDevelopmentRuntimeContract.model_validate_json(spec[0])
            action = contract.actions[0]
            details = json.loads(impact_evidence[0]["details_json"])
            transport_mode = trace.get("transport_mode", "native")
            checks["assertion_signature"] = bool(
                transport_mode in {"native", "injected"}
                and (transport_mode == "injected" or (
                    action.precondition_observation is not None
                    and impact_evidence[0]["content_sha256"]
                        == action.precondition_observation.response_sha256
                ))
                and canonical_sha256(impact_contract_document(contract)) == spec[1]
                and details.get("contract_sha256") == canonical_sha256(impact_action_document(action))
                and details.get("contract_id") == action.contract_id
                and details.get("path_id") == action.path_id
                and details.get("request_ids") == [requests[0]["request_id"]]
                and details.get("response_status") == 200
                and re.fullmatch(r"[0-9a-f]{64}", impact_evidence[0]["content_sha256"]) is not None
                and _assertions_match(
                    action, details, oracle["assertion_expectations"][scenario_id],
                    signal_observed=expected["expected_impact_outcome"] == "observed",
                )
            )
        else:
            checks["assertion_signature"] = expected["expected_native_gets"] == 0
    observations = trace.get("planner_observations", [])
    checks["developing_phase"] = (
        not expected["require_developing_phase"] or
        any(item.get("status") == "UNDERPOWERED"
            and item.get("processing_phase") == "developing"
            for item in observations)
    )
    other_checks = {key: value for key, value in checks.items() if key != "developing_phase"}
    real_axis_mismatch = bool(
        trace.get("assessment_mode") == "real"
        and baseline.get("impact_axes") != expected["expected_baseline_axes"]
    )
    checks["real_scenario_baseline_axes"] = not real_axis_mismatch
    result = (
        "BASELINE_AXIS_MISMATCH" if real_axis_mismatch else
        "NON_CAUSAL_BASELINE" if (trace.get("assessment_mode") == "real"
                                  and predevelopment is not None
                                  and not predevelopment.underpowered) else
        "UNRESOLVED" if not all(other_checks.values()) else
        "GAP_DEVELOPING_PHASE" if not checks["developing_phase"] else "PASS"
    )
    return {"scenario_id": scenario_id, "result": result, "checks": checks,
            "baseline_status": baseline.get("status"),
            "final_status": developed.get("status"),
            "phase_trace_source": "runner_snapshot_during_planning"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("scenario_id")
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    args = parser.parse_args()
    report = score_transition_case(args.root, args.scenario_id, args.oracle)
    output = args.root / args.scenario_id / "TransitionScore.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(output), "result": report["result"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
