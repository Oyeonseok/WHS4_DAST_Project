"""Read-only Validation evidence calibration against distinct official and synthetic oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from aidast.validation.contracts.models import BlindAssessment, canonical_sha256
from aidast.validation.core.decision import evaluate_impact
from aidast.validation.core.profile_evidence import PROFILE_EVIDENCE_RULES
from aidast.validation.core.profile_evidence import RULE_VERSION
try:
    from scripts.score_validation_lab import classify_status, score_validation_lab
except ModuleNotFoundError:  # Direct execution from scripts/.
    from score_validation_lab import classify_status, score_validation_lab


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OFFICIAL = ROOT / "resources/lab/validation-answer-key.json"
DEFAULT_TRANSITION = ROOT / "resources/lab/validation-transition-answer-key.json"
DEFAULT_BUNDLE = ROOT / "result/test-runs/validation-candidates/validation-lab"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _valid_fact_bindings(document: dict[str, Any]) -> bool:
    targets = document.get("target_attempt_ids")
    controls = document.get("control_attempt_ids")
    target_evidence = document.get("observed_target_evidence_ids")
    negative_evidence = document.get("inert_negative_evidence_ids")
    facts = document.get("facts")
    if any(not isinstance(value, list) or any(not isinstance(item, str) or not item
                                               for item in value)
           for value in (targets, controls, target_evidence, negative_evidence)):
        return False
    if not isinstance(facts, list) or len(facts) > 8:
        return False
    if any(len(value) != len(set(value)) for value in
           (targets, controls, target_evidence, negative_evidence)):
        return False
    if document.get("replay_status") != "complete" and facts:
        return False
    def same_ids(left: object, right: list[str]) -> bool:
        return (isinstance(left, list) and len(left) == len(right)
                and all(isinstance(item, str) for item in left)
                and set(left) == set(right))

    for fact in facts:
        if (not isinstance(fact, dict)
                or fact.get("kind") not in {
                    "assertion_differential", "json_value_differential",
                    "nonce_callback_differential",
                }
                or fact.get("profile_id") != document.get("profile_id")
                or fact.get("runtime_kind") != document.get("runtime_kind")
                or fact.get("provenance") != "contract_bound_adapter_summary"
                or not same_ids(fact.get("target_attempt_ids"), targets)
                or not same_ids(fact.get("target_evidence_ids"), target_evidence)
                or fact.get("negative_attempt_id") not in controls
                or fact.get("negative_evidence_id") not in negative_evidence):
            return False
        if fact["kind"] in {"assertion_differential", "json_value_differential"}:
            if any(not isinstance(fact.get(key), str)
                   or SHA256.fullmatch(fact[key]) is None
                   for key in ("assertion_id_sha256", "assertion_predicate_sha256",
                               "expected_sha256")) or not isinstance(fact.get("assertion_kind"), str):
                return False
            if (fact["kind"] == "json_value_differential"
                    and (document.get("runtime_kind") not in {"http", "multipart"}
                         or fact.get("assertion_kind") != "json_path_nonempty_string"
                         or fact.get("value_shape") != "nonempty_string"
                         or not isinstance(fact.get("json_path_sha256"), str)
                         or SHA256.fullmatch(fact["json_path_sha256"]) is None)):
                return False
        elif (document.get("runtime_kind") != "oob"
              or not isinstance(fact.get("protocols"), list)
              or not fact["protocols"]):
            return False
    return True


def _load_official(path: Path) -> list[dict[str, Any]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(rows, list) or not rows
            or any(not isinstance(row, dict)
                   or not isinstance(row.get("candidate_id"), str)
                   or row.get("target_validation_status") not in {"CONFIRMED", "DISPROVEN"}
                   or not isinstance(row.get("readiness"), str)
                   for row in rows)):
        raise ValueError("official Validation oracle is invalid")
    if len({row["candidate_id"] for row in rows}) != len(rows):
        raise ValueError("official Validation oracle has duplicate candidates")
    return rows


def _load_transition(path: Path, official_ids: set[str]) -> dict[str, Any]:
    oracle = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(oracle, dict)
            or oracle.get("fixture_kind") != "synthetic_validation_transition_oracle"
            or oracle.get("candidate_id") not in official_ids
            or not isinstance(oracle.get("cases"), dict)):
        raise ValueError("synthetic transition oracle is invalid or unbound")
    for scenario_id, row in oracle["cases"].items():
        if not isinstance(scenario_id, str) or not isinstance(row, dict):
            raise ValueError("synthetic transition scenario is invalid")
        for phase in ("baseline", "final"):
            axes_key = "expected_baseline_axes" if phase == "baseline" else "fixture_final_axes"
            status_key = "expected_baseline_status" if phase == "baseline" else "expected_final_status"
            axes, status = row.get(axes_key), row.get(status_key)
            if (not isinstance(axes, list) or len(axes) != 3
                    or any(type(score) is not int or not 0 <= score <= 3 for score in axes)
                    or status not in {"UNDERPOWERED", "CONFIRMED"}):
                raise ValueError(f"synthetic transition axes are invalid: {scenario_id}")
            predicted = "UNDERPOWERED" if evaluate_impact(*axes).underpowered else "CONFIRMED"
            if predicted != status:
                raise ValueError(f"synthetic transition {scenario_id} contradicts impact rubric")
    return oracle


def _load_axis_labels(path: Path | None, ready_ids: set[str]) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict)
            or document.get("oracle_kind") != "provided_profile_axis_labels"
            or not isinstance(document.get("cases"), list)):
        raise ValueError("provided axis oracle is invalid")
    labels: dict[str, dict[str, Any]] = {}
    for row in document["cases"]:
        if (not isinstance(row, dict)
                or row.get("candidate_id") not in ready_ids
                or not isinstance(row.get("profile_id"), str)
                or row["profile_id"] not in PROFILE_EVIDENCE_RULES
                or not isinstance(row.get("expected_axes"), list)
                or len(row["expected_axes"]) != 3
                or any(type(score) is not int or not 0 <= score <= 3
                       for score in row["expected_axes"])
                or not isinstance(row.get("source_refs"), list)
                or not row["source_refs"]
                or any(not isinstance(ref, str) or not ref.strip()
                       for ref in row["source_refs"])):
            raise ValueError("provided axis label is invalid")
        if row["candidate_id"] in labels:
            raise ValueError("duplicate provided axis label")
        labels[row["candidate_id"]] = row
    return labels


def _axes(value: object) -> list[int] | None:
    return (value if isinstance(value, list) and len(value) == 3
            and all(type(score) is int and 0 <= score <= 3 for score in value)
            else None)


def _audit_status(
    conn: sqlite3.Connection, case: sqlite3.Row, profile_id: str,
) -> tuple[str, int, list[int] | None, list[int] | None]:
    rows = conn.execute(
        """SELECT stage_run_id,details_json,content_sha256 FROM validation_evidence
           WHERE case_id=? AND evidence_kind='blind_profile_evidence_audit'""",
        (case["case_id"],),
    ).fetchall()
    if not rows:
        return "MISSING", 0, None, None
    current = [row for row in rows if row["stage_run_id"] == case["decision_stage_run_id"]]
    if len(current) != 1:
        return "INVALID_BINDING", 0, None, None
    row = current[0]
    try:
        document = json.loads(row["details_json"])
        if (not isinstance(document, dict)
                or canonical_sha256(document) != row["content_sha256"]
                or document.get("mode") != "audit"
                or document.get("rule_version") != RULE_VERSION
                or document.get("case_id") != case["case_id"]
                or document.get("stage_run_id") != case["decision_stage_run_id"]
                or document.get("profile_id") != profile_id
                or document.get("runtime_kind") != PROFILE_EVIDENCE_RULES[profile_id].runtime_kind
                or document.get("profile_sha256") != case["validation_profile_sha256"]
                or document.get("assessment_sha256") != case["blind_assessment_sha256"]
                or not isinstance(document.get("replay_status"), str)
                or not _valid_fact_bindings(document)):
            return "INVALID_BINDING", 0, None, None
        raw_axes = _axes(document.get("raw_axes"))
        effective_axes = _axes(document.get("effective_axes"))
        if ("raw_axes" in document and raw_axes is None
                or "effective_axes" in document and effective_axes is None):
            return "INVALID_BINDING", 0, None, None
        frozen_rows = conn.execute(
            """SELECT details_json,content_sha256 FROM validation_evidence
               WHERE case_id=? AND stage_run_id=? AND evidence_kind='blind_assessment'""",
            (case["case_id"], case["decision_stage_run_id"]),
        ).fetchall()
        if len(frozen_rows) != 1 or effective_axes is None:
            return "INVALID_BINDING", 0, None, None
        frozen = BlindAssessment.model_validate_json(frozen_rows[0]["details_json"])
        frozen_axes = [frozen.impact_boundary.score, frozen.impact_sensitivity.score,
                       frozen.impact_actor_requirements.score]
        if (frozen.case_id != case["case_id"]
                or canonical_sha256(frozen.model_dump(mode="json"))
                   != frozen_rows[0]["content_sha256"]
                or frozen_rows[0]["content_sha256"] != case["blind_assessment_sha256"]
                or frozen_axes != effective_axes):
            return "INVALID_BINDING", 0, None, None
        return "VALID_BINDING", len(document["facts"]), raw_axes, effective_axes
    except (TypeError, ValueError, KeyError):
        return "INVALID_BINDING", 0, None, None


def calibrate_profile_evidence(
    official_key: Path, transition_key: Path, mapping_path: Path,
    pipeline_path: Path, *, axis_labels: Path | None = None,
    candidate_inventory: Path | None = None, answer_db: Path | None = None,
) -> dict[str, Any]:
    """Measure oracle and audit coverage; never alter production scores or answer keys."""
    official = _load_official(official_key)
    official_by_id = {row["candidate_id"]: row for row in official}
    if (candidate_inventory is None) != (answer_db is None):
        raise ValueError("candidate inventory and answer DB must be supplied together")
    independent_score = (score_validation_lab(
        candidate_inventory, answer_db, mapping_path, pipeline_path,
    ) if candidate_inventory is not None and answer_db is not None else None)
    transition = _load_transition(transition_key, set(official_by_id))
    ready_ids = {row["candidate_id"] for row in official
                 if row["readiness"] == "GET_REPLAY_READY"}
    provided_axes = _load_axis_labels(axis_labels, ready_ids)
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if (not isinstance(mapping, dict)
            or mapping.get("fixture_kind") != "synthetic_attack_claims_for_validation_only"
            or not isinstance(mapping.get("cases"), list)):
        raise ValueError("Validation candidate mapping is invalid")
    mapped = {row["candidate_id"]: row for row in mapping["cases"]}
    if (len(mapped) != len(mapping["cases"])
            or set(mapped) != {row["candidate_id"] for row in official
                                  if row["readiness"] == "GET_REPLAY_READY"}):
        raise ValueError("Validation mapping differs from ready official candidates")
    profiles = {
        name: {"official_status_labels": 0, "synthetic_axis_trials": 0,
               "independent_axis_labels": 0, "provided_axis_labels": 0,
               "axis_label_provenance": "none", "enforcement_mode": "audit",
               "enforcement_reason": "independent profile-specific B/S/A labels are unavailable"}
        for name in sorted(PROFILE_EVIDENCE_RULES)
    }
    cases = []
    valid_audits = 0
    matches = 0
    with sqlite3.connect(pipeline_path) as conn:
        conn.row_factory = sqlite3.Row
        for answer in official:
            candidate_id = answer["candidate_id"]
            item = mapped.get(candidate_id)
            if item is None:
                cases.append({"candidate_id": candidate_id,
                              "profile_id": None,
                              "expected_status": answer["target_validation_status"],
                              "actual_status": None,
                              "status_comparison": "NEEDS_PREREQUISITES",
                              "audit_status": "NOT_RUN", "fact_count": 0,
                              "audit_reported_raw_axes": None, "actual_effective_axes": None,
                              "axis_comparison": "NEEDS_PREREQUISITES"})
                continue
            spec = conn.execute(
                "SELECT attack_skill_name FROM finding_reproduction_specs WHERE finding_id=?",
                (item["finding_id"],),
            ).fetchall()
            if len(spec) != 1 or spec[0][0] not in profiles:
                raise ValueError(f"mapped candidate has no packaged profile: {candidate_id}")
            profile_id = spec[0][0]
            label = provided_axes.get(candidate_id)
            if label is not None:
                if label["profile_id"] != profile_id:
                    raise ValueError(f"provided axis label profile differs: {candidate_id}")
                profiles[profile_id]["provided_axis_labels"] += 1
            profiles[profile_id]["official_status_labels"] += 1
            stored = conn.execute(
                """SELECT case_id,current_status,processing_phase,latest_stage_run_id,
                          decision_stage_run_id,blind_assessment_sha256,
                          validation_profile_sha256 FROM validation_cases
                   WHERE scan_id=? AND finding_id=?""",
                (item["scan_id"], item["finding_id"]),
            ).fetchall()
            if len(stored) > 1:
                raise ValueError(f"multiple Validation cases for {candidate_id}")
            case = stored[0] if stored else None
            completed = bool(case and case["processing_phase"] == "completed"
                             and case["latest_stage_run_id"] == case["decision_stage_run_id"])
            actual = case["current_status"] if completed else None
            classified = classify_status(answer["target_validation_status"], actual)
            comparison = "STATUS_MATCH" if classified == "PASS" else classified
            matches += comparison == "STATUS_MATCH"
            audit_status, fact_count, raw_axes, effective_axes = (
                _audit_status(conn, case, profile_id) if completed
                else ("NOT_RUN", 0, None, None)
            )
            axis_comparison = (
                "NO_AXIS_LABEL" if label is None else
                "PENDING_AUDIT" if effective_axes is None else
                "PROVIDED_AXIS_MATCH" if effective_axes == label["expected_axes"] else
                "PROVIDED_AXIS_MISMATCH"
            )
            valid_audits += audit_status == "VALID_BINDING"
            cases.append({"candidate_id": candidate_id, "profile_id": profile_id,
                          "expected_status": answer["target_validation_status"],
                          "actual_status": actual, "status_comparison": comparison,
                          "audit_status": audit_status, "fact_count": fact_count,
                          "audit_reported_raw_axes": raw_axes,
                          "actual_effective_axes": effective_axes,
                          "axis_comparison": axis_comparison})
    transition_candidate = mapped.get(transition["candidate_id"])
    if not transition_candidate:
        raise ValueError("synthetic axis oracle has no mapped candidate")
    source_profile = next(
        (row["profile_id"] for row in cases
         if row["candidate_id"] == transition["candidate_id"]), None,
    )
    if source_profile != "hunt-source-leak":
        raise ValueError("synthetic transition axes are not bound to hunt-source-leak")
    score_by_id = ({row["candidate_id"]: row for row in independent_score["cases"]}
                   if independent_score is not None else {})
    if (independent_score is not None
            and (len(score_by_id) != len(independent_score["cases"])
                 or set(score_by_id) != set(official_by_id))):
        raise ValueError("independent scorer candidate set differs from official oracle")
    for row in cases:
        scored = score_by_id.get(row["candidate_id"])
        if scored is None:
            row["independent_score_result"] = "NOT_RUN"
            continue
        if (scored["target_validation_status"] != row["expected_status"]
                or scored.get("actual_validation_status") != row["actual_status"]):
            raise ValueError("independent scorer result differs from current case binding")
        row["independent_score_result"] = scored["result"]
    profiles[source_profile]["synthetic_axis_trials"] = len(transition["cases"])
    profiles[source_profile]["axis_label_provenance"] = "synthetic_transition_fixture"
    axis_trials = [{
        "scenario_id": scenario_id,
        "profile_id": source_profile,
        "expected_baseline_axes": row["expected_baseline_axes"],
        "expected_baseline_status": row["expected_baseline_status"],
        "fixture_final_axes": row["fixture_final_axes"],
        "expected_final_status": row["expected_final_status"],
        "real_agent_trial_state": transition.get("real_agent_axis_trials", {}).get(scenario_id),
        "observed_agent_axis_comparison": "NOT_AVAILABLE",
        "label_provenance": "synthetic_transition_fixture",
        "rubric_consistent": True,
    } for scenario_id, row in sorted(transition["cases"].items())]
    return {
        "schema_version": 4,
        "mode": "read_only_calibration",
        "status_comparison_scope": "stored_current_status_only_no_decision_proof_check",
        "audit_validation_scope": "hash_schema_internal_citations_and_frozen_assessment_binding",
        "synthetic_axis_scope": "fixture_rubric_consistency_only_no_agent_axis_comparison",
        "decision_proof_scope": ("source_pinned_lab_scorer" if independent_score is not None
                                 else "not_checked"),
        "axis_label_scope": "provided_labels_unverified_for_production_enforcement",
        "official_key_sha256": hashlib.sha256(official_key.read_bytes()).hexdigest(),
        "transition_key_sha256": hashlib.sha256(transition_key.read_bytes()).hexdigest(),
        "provided_axis_key_sha256": (
            hashlib.sha256(axis_labels.read_bytes()).hexdigest()
            if axis_labels is not None else None),
        "summary": {
            "official_status_labels": len(official),
            "ready_official_candidates": len(mapped),
            "stored_status_matches": matches,
            "evidence_backed_status_matches": sum(
                row["independent_score_result"] == "PASS" for row in cases),
            "synthetic_axis_trials": len(axis_trials),
            "rubric_consistent_trials": len(axis_trials),
            "current_audits_binding_valid": valid_audits,
            "independent_axis_labels": 0,
            "provided_axis_labels": len(provided_axes),
            "provided_axis_matches": sum(
                row["axis_comparison"] == "PROVIDED_AXIS_MATCH" for row in cases),
            "profiles": len(profiles),
            "profiles_ready_for_axis_enforcement": sum(
                profile["enforcement_mode"] == "enforce"
                for profile in profiles.values()),
        },
        "profiles": profiles,
        "cases": cases,
        "axis_trials": axis_trials,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official-key", type=Path, default=DEFAULT_OFFICIAL)
    parser.add_argument("--transition-key", type=Path, default=DEFAULT_TRANSITION)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_BUNDLE / "CandidateFindingMap.json")
    parser.add_argument("--pipeline", type=Path, default=DEFAULT_BUNDLE / "Pipeline.db")
    parser.add_argument("--axis-labels", type=Path,
                        help="Provided B/S/A labels for advisory comparison only; synthetic key is rejected")
    parser.add_argument("--candidate-db", type=Path,
                        help="CandidateInventory.db for independent final-decision proof scoring")
    parser.add_argument("--answer-db", type=Path,
                        help="CandidateAnswerKey.db bound to --candidate-db")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = calibrate_profile_evidence(
        args.official_key, args.transition_key, args.mapping, args.pipeline,
        axis_labels=args.axis_labels,
        candidate_inventory=args.candidate_db, answer_db=args.answer_db,
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
