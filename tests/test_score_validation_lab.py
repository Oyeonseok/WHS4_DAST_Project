"""Status scoring must distinguish a wrong verdict from missing proof."""

from pathlib import Path
import json
import shutil
import sqlite3

import pytest

from aidast.validation import canonical_sha256
from scripts.score_validation_lab import _decision_has_proof, classify_status, score_validation_lab
from scripts.validation_lab_negative_proof import LabNegativeProof


def _fresh_pipeline(source: Path) -> Path:
    bundle = source / "validation-lab"
    baseline = bundle / "Pipeline.before-validation.db"
    candidate = baseline if baseline.exists() else bundle / "Pipeline.db"
    if not candidate.exists():
        pytest.skip("isolated local Validation lab fixture is not installed")
    with sqlite3.connect(candidate) as conn:
        if conn.execute("SELECT COUNT(*) FROM validation_cases").fetchone()[0]:
            pytest.skip("the local fixture has already been executed")
    return candidate


@pytest.mark.parametrize(("target", "actual", "result"), [
    ("CONFIRMED", "CONFIRMED", "PASS"),
    ("DISPROVEN", "DISPROVEN", "PASS"),
    ("CONFIRMED", "DISPROVEN", "WRONG_VERDICT"),
    ("DISPROVEN", "CONFIRMED", "WRONG_VERDICT"),
    ("DISPROVEN", "INCONCLUSIVE", "UNRESOLVED"),
    ("CONFIRMED", "UNDERPOWERED", "UNRESOLVED"),
    ("CONFIRMED", "KNOWN", "UNRESOLVED"),
    ("DISPROVEN", None, "PENDING"),
])
def test_classify_status(target: str, actual: str | None, result: str) -> None:
    assert classify_status(target, actual) == result


def test_fresh_fixture_reports_pending_and_deferred_without_guessing(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    pipeline = _fresh_pipeline(source)

    report = score_validation_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "validation-lab/CandidateFindingMap.json",
        pipeline,
    )

    assert report["summary"] == {"PENDING": 7, "NEEDS_PREREQUISITES": 3}
    assert len(report["cases"]) == 10
    assert all(item["result"] in {"PENDING", "NEEDS_PREREQUISITES"}
               for item in report["cases"])


def test_matching_status_without_attempt_evidence_is_not_pass(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "result/test-runs/validation-candidates"
    source_pipeline = _fresh_pipeline(source)
    pipeline = tmp_path / "Pipeline.db"
    shutil.copyfile(source_pipeline, pipeline)
    item = json.loads((source / "validation-lab/CandidateFindingMap.json").read_text())["cases"][0]
    scan_id, finding_id = item["scan_id"], item["finding_id"]
    with sqlite3.connect(pipeline) as conn:
        stage_run_id = conn.execute(
            "SELECT stage_run_id FROM stage_runs WHERE scan_id=? LIMIT 1", (scan_id,)
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO validation_cases
               (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,
                decision_stage_run_id,processing_phase,current_status,decision_json,decision_sha256)
               VALUES (?,?,?,?,?,?,'completed','DISPROVEN','{}',?)""",
            ("fabricated-case", scan_id, "finding", finding_id,
             stage_run_id, stage_run_id, "0" * 64),
        )
    report = score_validation_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "validation-lab/CandidateFindingMap.json", pipeline,
    )
    fabricated = next(row for row in report["cases"] if row.get("finding_id") == finding_id)
    assert fabricated["result"] == "UNSUPPORTED_DECISION"


@pytest.mark.parametrize("status", ["DISPROVEN", "CONFIRMED"])
def test_proof_audit_requires_controls_targets_and_cited_evidence(status: str) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE validation_attempts (
          attempt_id TEXT, case_id TEXT, stage_run_id TEXT, batch_no INTEGER,
          attempt_kind TEXT, ordinal INTEGER, outcome TEXT, signal_observed INTEGER,
          observation_json TEXT, finished_at TEXT);
        CREATE TABLE validation_evidence (
          evidence_id TEXT, case_id TEXT, stage_run_id TEXT, attempt_id TEXT,
          evidence_kind TEXT, content_sha256 TEXT);
        CREATE TABLE audit_case (
          case_id TEXT, decision_stage_run_id TEXT, current_status TEXT,
          decision_json TEXT, decision_sha256 TEXT, impact_boundary INTEGER,
          impact_sensitivity INTEGER, impact_actor_requirements INTEGER);
    """)
    kinds = [("positive_control", 1, 1), ("negative_control", 1, 0)]
    kinds += [("target", ordinal, int(status == "CONFIRMED")) for ordinal in (1, 2, 3)]
    for index, (kind, ordinal, observed) in enumerate(kinds):
        attempt_id = f"attempt-{index}"
        runtime = {"policy_allowed": True,
                   "explicit_non_exploit": status == "DISPROVEN" and kind == "target"}
        conn.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (attempt_id, "case", "stage", 1, kind, ordinal,
                      "observed" if observed else "not_observed", observed,
                      json.dumps({"validation_runtime": runtime}), "done"))
        conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?)",
                     (f"evidence-{index}", "case", "stage", attempt_id,
                      "observation", "c" * 64))
    decision = {"evidence_ids": [f"evidence-{index}" for index in range(5)]}
    conn.execute("INSERT INTO audit_case VALUES (?,?,?,?,?,?,?,?)",
                 ("case", "stage", status, json.dumps(decision),
                  canonical_sha256(decision), 1, 1, 1))
    case = conn.execute("SELECT * FROM audit_case").fetchone()
    if status == "DISPROVEN":
        assert not _decision_has_proof(conn, case)
        conn.close()
        return
    assert _decision_has_proof(conn, case)
    conn.execute("UPDATE validation_attempts SET outcome='blocked' WHERE attempt_id='attempt-2'")
    assert not _decision_has_proof(conn, case)
    conn.execute("UPDATE validation_attempts SET outcome='observed' WHERE attempt_id='attempt-2'")
    if status == "DISPROVEN":
        conn.execute("""UPDATE validation_attempts SET observation_json=?
                        WHERE attempt_id='attempt-4'""", (json.dumps({
            "validation_runtime": {"policy_allowed": True,
                                   "explicit_non_exploit": False}
        }),))
        assert not _decision_has_proof(conn, case)
        conn.execute("""UPDATE validation_attempts SET observation_json=?
                        WHERE attempt_id='attempt-4'""", (json.dumps({
            "validation_runtime": {"policy_allowed": True,
                                   "explicit_non_exploit": True}
        }),))
        for index, explicit in ((5, True), (6, False)):
            conn.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (f"attempt-{index}", "case", "stage", 1, "target", index - 1,
                          "not_observed", 0, json.dumps({"validation_runtime": {
                              "policy_allowed": True, "explicit_non_exploit": explicit,
                          }}), "done"))
            conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?)",
                         (f"evidence-{index}", "case", "stage", f"attempt-{index}",
                          "observation", "c" * 64))
            decision["evidence_ids"].append(f"evidence-{index}")
        conn.execute("UPDATE audit_case SET decision_json=?,decision_sha256=?",
                     (json.dumps(decision), canonical_sha256(decision)))
        case = conn.execute("SELECT * FROM audit_case").fetchone()
        assert not _decision_has_proof(conn, case)
        conn.execute("DELETE FROM validation_attempts WHERE attempt_id IN ('attempt-5','attempt-6')")
        conn.execute("DELETE FROM validation_evidence WHERE evidence_id IN ('evidence-5','evidence-6')")
        decision["evidence_ids"] = decision["evidence_ids"][:5]
        conn.execute("UPDATE audit_case SET decision_json=?,decision_sha256=?",
                     (json.dumps(decision), canonical_sha256(decision)))
        case = conn.execute("SELECT * FROM audit_case").fetchone()
    conn.execute("DELETE FROM validation_evidence WHERE evidence_id='evidence-0'")
    assert not _decision_has_proof(conn, case)
    conn.close()


def test_disproven_audit_binds_every_target_to_pinned_source_and_inert_control() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE validation_attempts (
          attempt_id TEXT, case_id TEXT, stage_run_id TEXT, batch_no INTEGER,
          attempt_kind TEXT, ordinal INTEGER, outcome TEXT, signal_observed INTEGER,
          observation_json TEXT, finished_at TEXT);
        CREATE TABLE validation_evidence (
          evidence_id TEXT, case_id TEXT, stage_run_id TEXT, attempt_id TEXT,
          evidence_kind TEXT, content_sha256 TEXT);
    """)
    proof = LabNegativeProof(
        candidate_id="candidate", scan_id="scan", endpoint="http://test/api/Users",
        attack_skill_name="hunt-auth-bypass", runtime_sha256="a" * 64,
        target_url="http://test/api/Users", expected_status=401,
        proof_kind="auth_denial", source_sha256="b" * 64,
        source_line=382, source_anchor="app.get('/api/Users', security.isAuthorized())",
    )
    metadata = {
        "candidate_id": proof.candidate_id, "proof_kind": proof.proof_kind,
        "source_sha256": proof.source_sha256, "source_line": proof.source_line,
        "source_anchor": proof.source_anchor,
        "negative_control_digest": "c" * 64,
    }
    attempts = [("positive_control", 1, True), ("negative_control", 1, False)]
    attempts += [("target", ordinal, False) for ordinal in (1, 2, 3)]
    for index, (kind, ordinal, observed) in enumerate(attempts):
        observation = {
            "response_status": 401, "response_url": proof.target_url,
            "validation_runtime": {"policy_allowed": True,
                                   "explicit_non_exploit": kind == "target"},
        }
        if kind == "target":
            observation["bounded_negative_proof"] = dict(metadata)
        conn.execute("INSERT INTO validation_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (f"attempt-{index}", "case", "stage", 1, kind, ordinal,
                      "observed" if observed else "not_observed", int(observed),
                      json.dumps(observation), "done"))
        conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?,?)",
                     (f"evidence-{index}", "case", "stage", f"attempt-{index}",
                      "observation", "c" * 64))
    decision = {"evidence_ids": [f"evidence-{index}" for index in range(5)]}
    case = {"case_id": "case", "decision_stage_run_id": "stage",
            "current_status": "DISPROVEN", "decision_json": json.dumps(decision),
            "decision_sha256": canonical_sha256(decision)}
    assert _decision_has_proof(conn, case, expected_negative_proof=proof)
    assert not _decision_has_proof(conn, case)

    last = json.loads(conn.execute(
        "SELECT observation_json FROM validation_attempts WHERE attempt_id='attempt-4'"
    ).fetchone()[0])
    last["bounded_negative_proof"]["source_line"] = 999
    conn.execute("UPDATE validation_attempts SET observation_json=? WHERE attempt_id='attempt-4'",
                 (json.dumps(last),))
    assert not _decision_has_proof(conn, case, expected_negative_proof=proof)
    last["bounded_negative_proof"]["source_line"] = proof.source_line
    conn.execute("UPDATE validation_attempts SET observation_json=? WHERE attempt_id='attempt-4'",
                 (json.dumps(last),))
    conn.execute("UPDATE validation_attempts SET outcome='blocked' WHERE attempt_id='attempt-4'")
    assert not _decision_has_proof(conn, case, expected_negative_proof=proof)
    conn.close()
