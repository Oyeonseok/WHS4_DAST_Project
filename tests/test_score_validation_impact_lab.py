"""Impact lab scoring requires the agent plan and a cited native GET result."""

import json
import sqlite3

import pytest

from aidast.validation import canonical_sha256


EXPECTED = {
    "path_id": "bounded-impact-confirmation",
    "gap_axis": "sensitivity",
    "initial_score_max": 1,
    "final_score_min": 2,
    "contract_id": "debug-users-password-field",
    "method": "GET",
    "url": "http://127.0.0.1:5001/debug/users",
    "response_status": 200,
    "assertion_kind": "body_contains",
    "assertion_expected": '"password":',
    "marker_json_path": ["users", 0, "account_number"],
    "marker_assertion_id": "seeded-admin-account",
    "marker_assertion_kind": "json_equals",
    "marker_assertion_expected": "ADMIN001",
    "marker_source_url": "https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/database.py#L255",
    "marker_source_sha256": "071e9a655508f6c6790cc01620a8a680681165defa5a141c017729e3280b793b",
    "marker_source_line": 255,
    "signal_kind": "hunt_source_leak_bounded_impact_observed",
    "required_preconditions": [
        "An exact same-origin safe-method request already captured by Attack",
        "A unique non-secret configuration or data marker for the stronger impact",
    ],
}


def _fixture() -> tuple[sqlite3.Connection, sqlite3.Row]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE validation_cases (
          case_id TEXT, finding_id TEXT, current_status TEXT, processing_phase TEXT,
          latest_stage_run_id TEXT, decision_stage_run_id TEXT, decision_json TEXT,
          decision_sha256 TEXT, impact_sensitivity INTEGER);
        CREATE TABLE validation_impact_hypotheses (
          hypothesis_id TEXT, case_id TEXT, stage_run_id TEXT, path_id TEXT,
          gap_axis TEXT, current_score INTEGER, proposal_sha256 TEXT, status TEXT,
          plan_json TEXT, observation_json TEXT);
        CREATE TABLE validation_attempts (
          attempt_id TEXT, case_id TEXT, stage_run_id TEXT, batch_no INTEGER,
          attempt_kind TEXT, ordinal INTEGER, outcome TEXT, signal_observed INTEGER,
          impact_hypothesis_id TEXT, finished_at TEXT);
        CREATE TABLE validation_http_requests (
          request_id TEXT, case_id TEXT, stage_run_id TEXT, attempt_id TEXT,
          development_action_id TEXT, method TEXT, url TEXT, status TEXT,
          response_status INTEGER);
        CREATE TABLE validation_evidence (
          evidence_id TEXT, case_id TEXT, stage_run_id TEXT, attempt_id TEXT,
          evidence_kind TEXT, content_sha256 TEXT, details_json TEXT);
        CREATE TABLE finding_reproduction_specs (
          finding_id TEXT, impact_development_contract_json TEXT,
          impact_development_contract_sha256 TEXT, source_request_ids_json TEXT);
        CREATE TABLE attack_http_requests (
          request_id TEXT, method TEXT, url TEXT, status TEXT,
          response_status INTEGER, request_fingerprint TEXT);
        CREATE TABLE attack_attempts (
          request_fingerprint TEXT, response_signature TEXT, finding_id TEXT);
    """)
    evidence_ids = [f"baseline-evidence-{index}" for index in range(5)]
    for index, kind in enumerate(("positive_control", "negative_control",
                                  "target", "target", "target")):
        ordinal = index - 1 if kind == "target" else 1
        observed = 0 if kind == "negative_control" else 1
        conn.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (f"baseline-attempt-{index}", "case", "stage", 1, kind,
                      ordinal, "observed" if observed else "not_observed",
                      observed, None, "done"))
        conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?,?)",
                     (evidence_ids[index], "case", "stage", f"baseline-attempt-{index}",
                      "observation", "a" * 64, "{}"))
    conn.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                 ("impact-attempt", "case", "stage", 2, "target", 1,
                  "observed", 1, "hypothesis", "done"))
    conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?,?)",
                 ("impact-evidence", "case", "stage", "impact-attempt",
                  "impact_development_observation", "b" * 64, "{}"))
    conn.execute("INSERT INTO validation_http_requests VALUES (?,?,?,?,?,?,?,?,?)",
                 ("impact-request", "case", "stage", "impact-attempt", None,
                  "GET", EXPECTED["url"], "completed", 200))
    proposal_sha = "c" * 64
    plan = {"path_id": EXPECTED["path_id"], "proposal_sha256": proposal_sha,
            "disposition": "execute", "preconditions_satisfied": True,
            "evidence_ids": evidence_ids}
    observation = {"path_id": EXPECTED["path_id"], "proposal_sha256": proposal_sha,
                   "outcome": "observed", "signal_observed": True,
                   "signal": {"kind": EXPECTED["signal_kind"]},
                   "evidence_ids": ["impact-evidence"],
                   "details": {"contract_id": EXPECTED["contract_id"],
                               "request_ids": ["impact-request"]}}
    conn.execute("INSERT INTO validation_impact_hypotheses VALUES (?,?,?,?,?,?,?,?,?,?)",
                 ("hypothesis", "case", "stage", EXPECTED["path_id"],
                  EXPECTED["gap_axis"], 1, proposal_sha, "succeeded",
                  json.dumps(plan), json.dumps(observation)))
    contract = {"schema_version": 1, "actions": [{
        "contract_id": EXPECTED["contract_id"], "path_id": EXPECTED["path_id"],
        "endpoint_template": "/debug/{resource}", "method": "GET",
        "request": {"path_parameters": {"resource": "users"}},
        "assertions": [{"assertion_id": "password-field-name",
                        "kind": EXPECTED["assertion_kind"],
                        "expected": EXPECTED["assertion_expected"]},
                       {"assertion_id": EXPECTED["marker_assertion_id"],
                        "kind": EXPECTED["marker_assertion_kind"],
                        "path": EXPECTED["marker_json_path"],
                        "expected": EXPECTED["marker_assertion_expected"]}],
        "credential_roles": [],
        "precondition_observation": {
            "source_request_id": "attack-source-request",
            "response_sha256": "d" * 64,
            "response_status": 200,
            "marker_json_path": EXPECTED["marker_json_path"],
            "marker_assertion_id": EXPECTED["marker_assertion_id"],
            "marker_source": {"url": EXPECTED["marker_source_url"],
                              "file_sha256": EXPECTED["marker_source_sha256"],
                              "line": EXPECTED["marker_source_line"]},
        },
    }]}
    from aidast.validation import ImpactDevelopmentRuntimeContract
    from aidast.validation.contracts.impact_development import impact_contract_document
    contract = impact_contract_document(ImpactDevelopmentRuntimeContract.model_validate(contract))
    conn.execute("INSERT INTO finding_reproduction_specs VALUES (?,?,?,?)",
                 ("finding", json.dumps(contract), canonical_sha256(contract),
                  json.dumps(["attack-source-request"])))
    conn.execute("INSERT INTO attack_http_requests VALUES (?,?,?,?,?,?)",
                 ("attack-source-request", "GET", EXPECTED["url"], "completed", 200, "f" * 64))
    conn.execute("INSERT INTO attack_attempts VALUES (?,?,?)", ("f" * 64, "d" * 64, "finding"))
    marker_digest = canonical_sha256(EXPECTED["assertion_expected"])
    admin_digest = canonical_sha256(EXPECTED["marker_assertion_expected"])
    impact_details = {"contract_id": EXPECTED["contract_id"],
                      "contract_sha256": canonical_sha256(contract["actions"][0]),
                      "path_id": EXPECTED["path_id"],
                      "request_ids": ["impact-request"],
                      "evaluation": {"signal_observed": True, "assertions": [{
                          "assertion_id": "password-field-name", "kind": "body_contains",
                          "expected_sha256": marker_digest, "actual_sha256": marker_digest,
                          "passed": True,
                      }, {
                          "assertion_id": EXPECTED["marker_assertion_id"], "kind": "json_equals",
                          "expected_sha256": admin_digest, "actual_sha256": admin_digest,
                          "passed": True,
                      }]}}
    observation["details"]["contract_sha256"] = impact_details["contract_sha256"]
    conn.execute("UPDATE validation_impact_hypotheses SET observation_json=?",
                 (json.dumps(observation),))
    conn.execute("UPDATE validation_evidence SET details_json=? WHERE evidence_id='impact-evidence'",
                 (json.dumps(impact_details),))
    decision = {"evidence_ids": [*evidence_ids, "impact-evidence"],
                "blind_assessment": {"impact_sensitivity": {
                    "score": 2, "evidence_ids": ["impact-evidence"]}},
                "impact_development": [{"hypothesis_id": "hypothesis",
                                        "status": "succeeded", "plan": plan,
                                        "observation": observation}]}
    conn.execute("INSERT INTO validation_cases VALUES (?,?,?,?,?,?,?,?,?)",
                 ("case", "finding", "CONFIRMED", "completed", "stage", "stage",
                  json.dumps(decision), canonical_sha256(decision), 2))
    _add_verified_precondition_to_plan(conn)
    return conn, conn.execute("SELECT * FROM validation_cases").fetchone()


def test_impact_score_accepts_cited_agent_execution() -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, case = _fixture()
    assert _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()


def _add_verified_precondition_to_plan(conn: sqlite3.Connection) -> None:
    contract = json.loads(conn.execute(
        "SELECT impact_development_contract_json FROM finding_reproduction_specs"
    ).fetchone()[0])
    action = contract["actions"][0]
    source = action["precondition_observation"]
    receipt = {
        "path_id": EXPECTED["path_id"],
        "contract_sha256": canonical_sha256(action),
        "required_preconditions": EXPECTED["required_preconditions"],
        "evidence_ids": [],
        "source_request_ids": [source["source_request_id"]],
        "details": {
            "contract_id": EXPECTED["contract_id"],
            "response_sha256": source["response_sha256"],
            "response_status": source["response_status"],
            "source_request_id": source["source_request_id"],
            "marker_json_path": source["marker_json_path"],
            "marker_assertion_id": source["marker_assertion_id"],
            "marker_source": {
                **source["marker_source"],
                "url": source["marker_source"]["url"].split("#", 1)[0],
            },
            "marker_assertion_expected": EXPECTED["marker_assertion_expected"],
        },
    }
    conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?,?)",
                 ("precondition-evidence", "case", "stage", None,
                  "impact_precondition_verification", canonical_sha256(receipt),
                  json.dumps(receipt)))
    hypothesis = conn.execute("SELECT plan_json FROM validation_impact_hypotheses").fetchone()
    plan = json.loads(hypothesis[0])
    plan["evidence_ids"].append("precondition-evidence")
    conn.execute("UPDATE validation_impact_hypotheses SET plan_json=?",
                 (json.dumps(plan),))
    decision = json.loads(conn.execute(
        "SELECT decision_json FROM validation_cases"
    ).fetchone()[0])
    decision["impact_development"][0]["plan"] = plan
    conn.execute("UPDATE validation_cases SET decision_json=?,decision_sha256=?",
                 (json.dumps(decision), canonical_sha256(decision)))


def test_impact_score_accepts_verified_precondition_receipt_in_agent_plan() -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, case = _fixture()
    assert _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()


def test_impact_score_rejects_tampered_precondition_receipt() -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, _ = _fixture()
    receipt = json.loads(conn.execute(
        "SELECT details_json FROM validation_evidence WHERE evidence_id='precondition-evidence'"
    ).fetchone()[0])
    receipt["details"]["marker_source"]["file_sha256"] = "0" * 64
    conn.execute("UPDATE validation_evidence SET details_json=?,content_sha256=? "
                 "WHERE evidence_id='precondition-evidence'",
                 (json.dumps(receipt), canonical_sha256(receipt)))
    case = conn.execute("SELECT * FROM validation_cases").fetchone()
    assert not _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()


def test_impact_score_rejects_unrelated_precondition_terms() -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, _ = _fixture()
    receipt = json.loads(conn.execute(
        "SELECT details_json FROM validation_evidence WHERE evidence_id='precondition-evidence'"
    ).fetchone()[0])
    receipt["required_preconditions"] = ["An unrelated prerequisite"]
    conn.execute("UPDATE validation_evidence SET details_json=?,content_sha256=? "
                 "WHERE evidence_id='precondition-evidence'",
                 (json.dumps(receipt), canonical_sha256(receipt)))
    case = conn.execute("SELECT * FROM validation_cases").fetchone()
    assert not _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()


def test_impact_score_requires_precondition_receipt_citation() -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, _ = _fixture()
    plan = json.loads(conn.execute(
        "SELECT plan_json FROM validation_impact_hypotheses"
    ).fetchone()[0])
    plan["evidence_ids"].remove("precondition-evidence")
    conn.execute("UPDATE validation_impact_hypotheses SET plan_json=?",
                 (json.dumps(plan),))
    decision = json.loads(conn.execute(
        "SELECT decision_json FROM validation_cases"
    ).fetchone()[0])
    decision["impact_development"][0]["plan"] = plan
    conn.execute("UPDATE validation_cases SET decision_json=?,decision_sha256=?",
                 (json.dumps(decision), canonical_sha256(decision)))
    case = conn.execute("SELECT * FROM validation_cases").fetchone()
    assert not _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()


@pytest.mark.parametrize("mutation", [
    "UPDATE validation_impact_hypotheses SET current_score=2",
    "UPDATE validation_impact_hypotheses SET status='skipped'",
    "UPDATE validation_impact_hypotheses SET plan_json='{}'",
    "UPDATE validation_impact_hypotheses SET observation_json='{}'",
    "DELETE FROM validation_http_requests",
    "UPDATE validation_http_requests SET status='failed'",
    "UPDATE validation_http_requests SET response_status=404",
    "DELETE FROM validation_evidence WHERE evidence_id='impact-evidence'",
    "UPDATE validation_attempts SET outcome='not_observed' WHERE attempt_id='impact-attempt'",
    "UPDATE validation_evidence SET details_json='{}' WHERE evidence_id='impact-evidence'",
    "UPDATE validation_attempts SET outcome='blocked' WHERE attempt_id='baseline-attempt-0'",
    "DELETE FROM attack_http_requests",
    "UPDATE attack_attempts SET response_signature='e' || substr(response_signature,2)",
])
def test_impact_score_rejects_incomplete_development(mutation: str) -> None:
    from scripts.score_validation_impact_lab import _decision_has_impact_proof
    conn, case = _fixture()
    conn.execute(mutation)
    assert not _decision_has_impact_proof(conn, case, EXPECTED)
    conn.close()
