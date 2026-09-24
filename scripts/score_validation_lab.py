"""Compare persisted shared Validation decisions with the separate lab oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

from aidast.validation import canonical_sha256, evaluate_impact
try:
    from scripts.validation_lab_negative_proof import (
        LabNegativeProof, load_lab_negative_proofs,
    )
except ModuleNotFoundError:  # Direct `python scripts/score_validation_lab.py`.
    from validation_lab_negative_proof import (
        LabNegativeProof, load_lab_negative_proofs,
    )


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / "result/test-runs/validation-candidates"


def classify_status(target: str, actual: str | None) -> str:
    if target not in {"CONFIRMED", "DISPROVEN"}:
        raise ValueError(f"unsupported oracle status: {target}")
    if actual is None:
        return "PENDING"
    if actual == target:
        return "PASS"
    if actual in {"CONFIRMED", "DISPROVEN"}:
        return "WRONG_VERDICT"
    return "UNRESOLVED"


def _decision_has_proof(conn: sqlite3.Connection, case: sqlite3.Row, *,
                        expected_negative_proof: LabNegativeProof | None = None) -> bool:
    """Independently require the control batch and cited attempt evidence."""
    try:
        decision = json.loads(case["decision_json"])
        if canonical_sha256(decision) != case["decision_sha256"]:
            return False
        cited = set(decision["evidence_ids"])
    except (TypeError, ValueError, KeyError):
        return False
    attempts = conn.execute(
        """SELECT attempt_id,batch_no,attempt_kind,ordinal,outcome,signal_observed,
                  observation_json,finished_at FROM validation_attempts
           WHERE case_id=? AND stage_run_id=? ORDER BY batch_no DESC,attempt_kind,ordinal""",
        (case["case_id"], case["decision_stage_run_id"]),
    ).fetchall()
    for batch_no in sorted({row["batch_no"] for row in attempts}, reverse=True):
        batch = {(row["attempt_kind"], row["ordinal"]): row
                 for row in attempts if row["batch_no"] == batch_no}
        target_ordinals = sorted(ordinal for kind, ordinal in batch if kind == "target")
        if target_ordinals not in ([1, 2, 3], [1, 2, 3, 4, 5]):
            continue
        required = {("positive_control", 1), ("negative_control", 1)} | {
            ("target", ordinal) for ordinal in target_ordinals
        }
        if not required <= batch.keys():
            continue
        try:
            evidence_digests = {}
            for key in required:
                row = batch[key]
                if row["finished_at"] is None or row["outcome"] == "outcome_unknown":
                    return False
                runtime = json.loads(row["observation_json"]).get("validation_runtime", {})
                if runtime.get("policy_allowed") is not True:
                    return False
                evidence = conn.execute(
                    """SELECT evidence_id,content_sha256 FROM validation_evidence
                       WHERE case_id=? AND stage_run_id=? AND attempt_id=?
                         AND evidence_kind='observation'""",
                    (case["case_id"], case["decision_stage_run_id"], row["attempt_id"]),
                ).fetchall()
                matching = [(evidence_id, digest) for evidence_id, digest in evidence
                            if evidence_id in cited]
                if len(matching) != 1:
                    return False
                evidence_digests[key] = matching[0][1]
            if batch[("positive_control", 1)]["signal_observed"] != 1:
                return False
            if batch[("negative_control", 1)]["signal_observed"] != 0:
                return False
            targets = [batch[("target", ordinal)] for ordinal in target_ordinals]
            if case["current_status"] == "DISPROVEN":
                if expected_negative_proof is None:
                    return False
                negative_observation = json.loads(
                    batch[("negative_control", 1)]["observation_json"]
                )
                negative_hash = evidence_digests[("negative_control", 1)]
                if (not isinstance(negative_hash, str)
                        or re.fullmatch(r"[0-9a-f]{64}", negative_hash) is None
                        or negative_observation.get("response_status") != expected_negative_proof.expected_status):
                    return False
                expected_metadata = {
                    "candidate_id": expected_negative_proof.candidate_id,
                    "proof_kind": expected_negative_proof.proof_kind,
                    "source_sha256": expected_negative_proof.source_sha256,
                    "source_line": expected_negative_proof.source_line,
                    "source_anchor": expected_negative_proof.source_anchor,
                    "negative_control_digest": negative_hash,
                }
                return all(
                    target["outcome"] == "not_observed"
                    and target["signal_observed"] == 0
                    and (observation := json.loads(target["observation_json"]))
                    .get("validation_runtime", {}).get("explicit_non_exploit") is True
                    and observation.get("response_status") == expected_negative_proof.expected_status
                    and observation.get("response_url") == expected_negative_proof.target_url
                    and evidence_digests[("target", target["ordinal"])] == negative_hash
                    and observation.get("bounded_negative_proof") == expected_metadata
                    for target in targets
                )
            if case["current_status"] == "CONFIRMED":
                impact = evaluate_impact(
                    case["impact_boundary"], case["impact_sensitivity"],
                    case["impact_actor_requirements"],
                )
                return (len(targets) == 3
                        and all(target["outcome"] == "observed"
                                and target["signal_observed"] == 1 for target in targets)
                        and not impact.underpowered)
        except (TypeError, ValueError, KeyError):
            return False
    return False


def score_validation_lab(inventory: Path, answers: Path, mapping_path: Path,
                         pipeline: Path) -> dict:
    """Score only current completed decisions; leave missing proof unresolved."""
    with sqlite3.connect(answers) as answer_db:
        digest_row = answer_db.execute(
            "SELECT value FROM answer_metadata WHERE key='inventory_sha256'"
        ).fetchone()
        if digest_row is None or digest_row[0] != hashlib.sha256(inventory.read_bytes()).hexdigest():
            raise ValueError("answer key does not match candidate inventory")
        answer_db.row_factory = sqlite3.Row
        oracle = {row["candidate_id"]: dict(row) for row in answer_db.execute(
            "SELECT * FROM answer_key"
        )}
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if mapping.get("fixture_kind") != "synthetic_attack_claims_for_validation_only":
        raise ValueError("candidate mapping is not the isolated Validation fixture")
    mapped = mapping["cases"]
    proof_by_candidate: dict[str, LabNegativeProof] | None = None
    by_id = {item["candidate_id"]: item for item in mapped}
    if (len(by_id) != len(mapped) or any(candidate_id not in oracle for candidate_id in by_id)
            or {candidate_id for candidate_id, row in oracle.items()
                if row["readiness"] == "GET_REPLAY_READY"} != set(by_id)):
        raise ValueError("candidate mapping differs from the ready answer-key subset")
    rows = []
    with sqlite3.connect(pipeline) as conn:
        conn.row_factory = sqlite3.Row
        for candidate_id, answer in sorted(oracle.items()):
            item = by_id.get(candidate_id)
            if item is None:
                rows.append({
                    "candidate_id": candidate_id,
                    "target_validation_status": answer["target_validation_status"],
                    "actual_validation_status": None,
                    "result": "NEEDS_PREREQUISITES",
                    "proof_requirement": answer["proof_requirement"],
                })
                continue
            stored = conn.execute(
                """SELECT case_id,current_status,processing_phase,latest_stage_run_id,
                          decision_stage_run_id,decision_json,decision_sha256,
                          impact_boundary,impact_sensitivity,impact_actor_requirements
                   FROM validation_cases
                   WHERE scan_id=? AND finding_id=?""",
                (item["scan_id"], item["finding_id"]),
            ).fetchall()
            if len(stored) > 1:
                raise ValueError(f"multiple Validation cases for {candidate_id}")
            actual = None
            result = "PENDING"
            if stored:
                case = stored[0]
                if (case["processing_phase"] == "completed"
                        and case["latest_stage_run_id"] == case["decision_stage_run_id"]):
                    actual = case["current_status"]
            result = classify_status(answer["target_validation_status"], actual)
            if result == "PASS":
                if actual == "DISPROVEN" and proof_by_candidate is None:
                    try:
                        observations_path = inventory.parent / "LocalControlObservations.json"
                        recorded_identity = json.loads(
                            observations_path.read_text(encoding="utf-8")
                        )["runtime_identity"]
                        proof_by_candidate = {
                            proof.candidate_id: proof
                            for proof in load_lab_negative_proofs(
                                inventory_path=inventory, mapping_path=mapping_path,
                                pipeline_path=pipeline, observations_path=observations_path,
                                identity_probe=lambda: recorded_identity,
                            ).values()
                        }
                    except (OSError, ValueError, KeyError, sqlite3.Error):
                        proof_by_candidate = {}
                if not _decision_has_proof(
                    conn, stored[0],
                    expected_negative_proof=(proof_by_candidate or {}).get(candidate_id),
                ):
                    result = "UNSUPPORTED_DECISION"
            rows.append({
                "candidate_id": candidate_id,
                "scan_id": item["scan_id"], "finding_id": item["finding_id"],
                "target_validation_status": answer["target_validation_status"],
                "actual_validation_status": actual,
                "result": result,
                "proof_requirement": answer["proof_requirement"],
            })
    return {"fixture_kind": mapping["fixture_kind"],
            "summary": dict(Counter(row["result"] for row in rows)), "cases": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-db", type=Path, default=DEFAULT_ROOT / "CandidateInventory.db")
    parser.add_argument("--answer-db", type=Path, default=DEFAULT_ROOT / "CandidateAnswerKey.db")
    parser.add_argument("--mapping", type=Path,
                        default=DEFAULT_ROOT / "validation-lab/CandidateFindingMap.json")
    parser.add_argument("--pipeline", type=Path, default=DEFAULT_ROOT / "validation-lab/Pipeline.db")
    parser.add_argument("--output", type=Path,
                        default=DEFAULT_ROOT / "validation-lab/ValidationScore.json")
    args = parser.parse_args()
    report = score_validation_lab(args.candidate_db, args.answer_db, args.mapping, args.pipeline)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "summary": report["summary"]}))


if __name__ == "__main__":
    main()
