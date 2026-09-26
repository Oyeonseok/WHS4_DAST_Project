"""Independently score the current impact Development stage against a separate oracle."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from urllib.parse import urljoin

from aidast.validation import ImpactDevelopmentRuntimeContract, canonical_sha256
from aidast.validation.contracts.runtime_contract import render_http_request
from aidast.validation.contracts.impact_development import (
    impact_action_document, impact_contract_document,
)
from aidast.validation.execution.impact_development import VerifiedImpactPreconditions


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORACLE = ROOT / "resources/lab/validation-impact-answer-key.json"


def _decision_has_impact_proof(conn: sqlite3.Connection, case: sqlite3.Row,
                               expected: dict) -> bool:
    """Require the actual agent plan, bounded request, and cited score evidence."""
    try:
        if (case["current_status"] != "CONFIRMED"
                or case["processing_phase"] != "completed"
                or case["latest_stage_run_id"] != case["decision_stage_run_id"]
                or case["impact_sensitivity"] < expected["final_score_min"]):
            return False
        decision = json.loads(case["decision_json"])
        if canonical_sha256(decision) != case["decision_sha256"]:
            return False
        cited = set(decision["evidence_ids"])
        final_axis = decision["blind_assessment"]["impact_sensitivity"]
        if (final_axis["score"] != case["impact_sensitivity"]
                or final_axis["score"] < expected["final_score_min"]):
            return False
        spec = conn.execute(
            """SELECT impact_development_contract_json,impact_development_contract_sha256,
                      source_request_ids_json
               FROM finding_reproduction_specs WHERE finding_id=?""",
            (case["finding_id"],),
        ).fetchone()
        contract = ImpactDevelopmentRuntimeContract.model_validate_json(
            spec["impact_development_contract_json"]
        )
        if canonical_sha256(impact_contract_document(contract)) != spec["impact_development_contract_sha256"]:
            return False
        actions = [item for item in contract.actions
                   if item.path_id == expected["path_id"]]
        if len(actions) != 1:
            return False
        action = actions[0]
        rendered_url, headers, body = render_http_request(
            urljoin(expected["url"], action.endpoint_template), action.request,
        )
        if (action.contract_id != expected["contract_id"]
                or action.method != expected["method"]
                or rendered_url != expected["url"] or headers or body is not None
                or not any(assertion.kind == expected["assertion_kind"]
                           and assertion.expected == expected["assertion_expected"]
                           for assertion in action.assertions)):
            return False
        receipt = action.precondition_observation
        if (receipt is None
                or list(receipt.marker_json_path) != expected["marker_json_path"]
                or receipt.response_status != expected["response_status"]
                or receipt.marker_assertion_id != expected["marker_assertion_id"]
                or receipt.marker_source is None
                or receipt.marker_source.url != expected["marker_source_url"]
                or receipt.marker_source.file_sha256 != expected["marker_source_sha256"]
                or receipt.marker_source.line != expected["marker_source_line"]
                or not any(item.assertion_id == receipt.marker_assertion_id
                           and item.kind == expected["marker_assertion_kind"]
                           and list(item.path) == expected["marker_json_path"]
                           and item.expected == expected["marker_assertion_expected"]
                           for item in action.assertions)
                or receipt.source_request_id not in json.loads(spec["source_request_ids_json"])):
            return False
        source = conn.execute(
            """SELECT method,url,status,response_status,request_fingerprint
               FROM attack_http_requests WHERE request_id=?""",
            (receipt.source_request_id,),
        ).fetchone()
        if (source is None or source["method"] != expected["method"]
                or source["url"] != expected["url"]
                or source["status"] != "completed"
                or source["response_status"] != receipt.response_status):
            return False
        attempt = conn.execute(
            """SELECT response_signature FROM attack_attempts
               WHERE finding_id=? AND request_fingerprint=?""",
            (case["finding_id"], source["request_fingerprint"]),
        ).fetchone()
        if attempt is None or attempt["response_signature"] != receipt.response_sha256:
            return False
        hypotheses = conn.execute(
            """SELECT * FROM validation_impact_hypotheses
               WHERE case_id=? AND stage_run_id=? AND path_id=?""",
            (case["case_id"], case["decision_stage_run_id"], expected["path_id"]),
        ).fetchall()
        if len(hypotheses) != 1:
            return False
        hypothesis = hypotheses[0]
        plan = json.loads(hypothesis["plan_json"])
        observation = json.loads(hypothesis["observation_json"])
        if (hypothesis["gap_axis"] != expected["gap_axis"]
                or hypothesis["current_score"] > expected["initial_score_max"]
                or hypothesis["status"] != "succeeded"
                or plan["path_id"] != expected["path_id"]
                or plan["proposal_sha256"] != hypothesis["proposal_sha256"]
                or plan["disposition"] != "execute"
                or plan["preconditions_satisfied"] is not True
                or observation["path_id"] != expected["path_id"]
                or observation["proposal_sha256"] != hypothesis["proposal_sha256"]
                or observation["outcome"] != "observed"
                or observation["signal_observed"] is not True
                or observation["signal"] != {"kind": expected["signal_kind"]}
                or observation["details"]["contract_id"] != expected["contract_id"]):
            return False
        baseline = conn.execute(
            """SELECT attempt_kind,ordinal,outcome,signal_observed FROM validation_attempts
               WHERE case_id=? AND stage_run_id=? AND impact_hypothesis_id IS NULL""",
            (case["case_id"], case["decision_stage_run_id"]),
        ).fetchall()
        kinds = {(row["attempt_kind"], row["ordinal"]): dict(row) for row in baseline}
        if (len(baseline) != 5
                or kinds.get(("positive_control", 1), {}).get("outcome") != "observed"
                or kinds.get(("positive_control", 1), {}).get("signal_observed") != 1
                or kinds.get(("negative_control", 1), {}).get("outcome") != "not_observed"
                or kinds.get(("negative_control", 1), {}).get("signal_observed") != 0
                or any(kinds.get(("target", ordinal), {}).get("outcome") != "observed"
                       or kinds.get(("target", ordinal), {}).get("signal_observed") != 1
                       for ordinal in (1, 2, 3))):
            return False
        baseline_evidence = conn.execute(
            """SELECT e.evidence_id FROM validation_evidence e
               JOIN validation_attempts a ON a.attempt_id=e.attempt_id
               WHERE e.case_id=? AND e.stage_run_id=?
                 AND a.impact_hypothesis_id IS NULL AND e.evidence_kind='observation'""",
            (case["case_id"], case["decision_stage_run_id"]),
        ).fetchall()
        baseline_ids = {row[0] for row in baseline_evidence}
        receipt_rows = conn.execute(
            """SELECT evidence_id,details_json,content_sha256 FROM validation_evidence
               WHERE case_id=? AND stage_run_id=?
                 AND evidence_kind='impact_precondition_verification'""",
            (case["case_id"], case["decision_stage_run_id"]),
        ).fetchall()
        if len(receipt_rows) != 1:
            return False
        receipt_ids = set()
        for row in receipt_rows:
            document = json.loads(row["details_json"])
            verified = VerifiedImpactPreconditions.model_validate(document)
            details = document["details"]
            marker_source = details["marker_source"]
            expected_source_url = expected["marker_source_url"]
            if (canonical_sha256(document) != row["content_sha256"]
                    or document["path_id"] != expected["path_id"]
                    or document["contract_sha256"] != canonical_sha256(impact_action_document(action))
                    or list(verified.required_preconditions) != expected["required_preconditions"]
                    or verified.evidence_ids
                    or list(verified.source_request_ids) != [receipt.source_request_id]
                    or details["contract_id"] != expected["contract_id"]
                    or details["source_request_id"] != receipt.source_request_id
                    or details["response_sha256"] != receipt.response_sha256
                    or details["response_status"] != expected["response_status"]
                    or details["marker_json_path"] != expected["marker_json_path"]
                    or details["marker_assertion_id"] != expected["marker_assertion_id"]
                    or details["marker_assertion_expected"] != expected["marker_assertion_expected"]
                    or marker_source["url"] not in {expected_source_url,
                                                    expected_source_url.split("#", 1)[0]}
                    or marker_source["file_sha256"] != expected["marker_source_sha256"]
                    or marker_source["line"] != expected["marker_source_line"]):
                return False
            receipt_ids.add(row["evidence_id"])
        plan_ids = set(plan["evidence_ids"])
        if (not plan_ids or not plan_ids & baseline_ids
                or not plan_ids <= baseline_ids | receipt_ids
                or not receipt_ids <= plan_ids
                or not plan_ids & baseline_ids <= cited):
            return False
        attempts = conn.execute(
            """SELECT attempt_id,outcome,signal_observed,finished_at
               FROM validation_attempts WHERE case_id=? AND stage_run_id=?
                 AND impact_hypothesis_id=?""",
            (case["case_id"], case["decision_stage_run_id"], hypothesis["hypothesis_id"]),
        ).fetchall()
        if (len(attempts) != 1 or attempts[0]["outcome"] != "observed"
                or attempts[0]["signal_observed"] != 1 or attempts[0]["finished_at"] is None):
            return False
        evidence = conn.execute(
            """SELECT evidence_id,details_json FROM validation_evidence
               WHERE case_id=? AND stage_run_id=? AND attempt_id=?
                 AND evidence_kind='impact_development_observation'""",
            (case["case_id"], case["decision_stage_run_id"], attempts[0]["attempt_id"]),
        ).fetchall()
        if (len(evidence) != 1 or observation["evidence_ids"] != [evidence[0]["evidence_id"]]
                or evidence[0]["evidence_id"] not in cited
                or evidence[0]["evidence_id"] not in final_axis["evidence_ids"]):
            return False
        action_sha = canonical_sha256(impact_action_document(action))
        details = json.loads(evidence[0]["details_json"])
        marker_sha = canonical_sha256(expected["assertion_expected"])
        source_marker_sha = canonical_sha256(expected["marker_assertion_expected"])
        assertions = details["evaluation"]["assertions"]
        def observed_assertion(assertion_id: str, kind: str, digest: str) -> bool:
            return any(item["assertion_id"] == assertion_id
                       and item["kind"] == kind
                       and item["expected_sha256"] == digest
                       and item["actual_sha256"] == digest
                       and item["passed"] is True for item in assertions)
        if (observation["details"]["contract_sha256"] != action_sha
                or details["contract_id"] != expected["contract_id"]
                or details["contract_sha256"] != action_sha
                or details["path_id"] != expected["path_id"]
                or details["evaluation"]["signal_observed"] is not True
                or not observed_assertion("password-field-name", expected["assertion_kind"], marker_sha)
                or not observed_assertion(expected["marker_assertion_id"], expected["marker_assertion_kind"], source_marker_sha)):
            return False
        request_ids = observation["details"]["request_ids"]
        if len(request_ids) != 1:
            return False
        if details["request_ids"] != request_ids:
            return False
        development = decision["impact_development"]
        if (len(development) != 1
                or development[0]["hypothesis_id"] != hypothesis["hypothesis_id"]
                or development[0]["status"] != "succeeded"
                or development[0]["plan"] != plan
                or development[0]["observation"] != observation):
            return False
        requests = conn.execute(
            """SELECT * FROM validation_http_requests
               WHERE request_id=? AND case_id=? AND stage_run_id=? AND attempt_id=?""",
            (request_ids[0], case["case_id"], case["decision_stage_run_id"],
             attempts[0]["attempt_id"]),
        ).fetchall()
        return (len(requests) == 1
                and requests[0]["development_action_id"] is None
                and requests[0]["method"] == expected["method"]
                and requests[0]["url"] == expected["url"]
                and requests[0]["status"] == "completed"
                and requests[0]["response_status"] == expected["response_status"])
    except (KeyError, TypeError, ValueError, IndexError, sqlite3.Error):
        return False


def score_impact_lab(bundle: Path, oracle_path: Path = DEFAULT_ORACLE) -> dict:
    expected = json.loads(oracle_path.read_text(encoding="utf-8"))
    mapping = json.loads((bundle / "CandidateFindingMap.json").read_text(encoding="utf-8"))
    if (expected.get("fixture_kind") != "synthetic_impact_development_lab_oracle"
            or mapping.get("impact_lab", {}).get("candidate_id") != expected["candidate_id"]):
        raise ValueError("impact lab oracle or mapping mismatch")
    selected = mapping["impact_lab"]
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        cases = conn.execute(
            """SELECT * FROM validation_cases WHERE scan_id=? AND finding_id=?""",
            (selected["scan_id"], selected["finding_id"]),
        ).fetchall()
        if len(cases) > 1:
            raise ValueError("impact lab has multiple Validation cases")
        actual = cases[0]["current_status"] if cases else None
        passed = bool(cases and _decision_has_impact_proof(conn, cases[0], expected))
    return {"candidate_id": expected["candidate_id"],
            "target_validation_status": expected["target_validation_status"],
            "actual_validation_status": actual,
            "result": "PASS" if passed else "UNRESOLVED" if cases else "PENDING",
            "proof_requirement": expected["proof_requirement"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = score_impact_lab(args.bundle, args.oracle)
    output = args.output or args.bundle / "ImpactDevelopmentScore.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    print(json.dumps({"output": str(output), "result": report["result"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
