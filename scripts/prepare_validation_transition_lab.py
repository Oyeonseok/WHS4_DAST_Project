"""Prepare isolated, balanced Impact Development transition scenarios.

All Attack claims remain explicitly synthetic. Network observations come from
the pinned local GET lab; this script only varies immutable Development
contracts and fixture baseline axes. The independent oracle stays in resources.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable

from aidast.validation import ImpactDevelopmentRuntimeContract, canonical_sha256
from aidast.validation.contracts.impact_development import impact_contract_document
from aidast.validation.core.integrity import CandidateIntegrityError, CandidateIntegrityGate

try:
    from scripts.prepare_validation_lab import (
        DEFAULT_ROOT, DEFAULT_SCOPE_ROOT, IMPACT_CANDIDATE, fetch_status_and_digest,
        prepare_validation_lab, probe_impact_markers, verify_runtime_identity,
    )
except ModuleNotFoundError:  # Direct CLI invocation.
    from prepare_validation_lab import (
        DEFAULT_ROOT, DEFAULT_SCOPE_ROOT, IMPACT_CANDIDATE, fetch_status_and_digest,
        prepare_validation_lab, probe_impact_markers, verify_runtime_identity,
    )


SCENARIOS = (
    ("verified_marker", (1, 0, 2)),
    ("minimal_threshold", (1, 0, 0)),
    ("weak_marker", (1, 0, 2)),
    ("false_marker", (1, 0, 2)),
    ("no_action", (1, 0, 2)),
    ("partial_boundary", (0, 0, 2)),
)


def _baseline_evidence_sha256(candidate) -> str:
    """Identify the replay facts visible before any Impact action runs."""
    blind = candidate.staged._blind_case.model_dump(mode="json")
    for key in ("case_id", "development_capabilities",
                "impact_development_capabilities"):
        blind.pop(key, None)
    return canonical_sha256({
        "blind_replay": blind,
        "attack_source_requests": list(candidate.source_requests),
    })


def _vary_contract(database: Path, finding_id: str, scenario_id: str) -> None:
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT impact_development_contract_json FROM finding_reproduction_specs "
            "WHERE finding_id=?", (finding_id,),
        ).fetchone()
        if row is None or row[0] is None:
            raise ValueError("transition seed has no bound impact contract")
        contract = json.loads(row[0])
        action = contract["actions"][0]
        if scenario_id == "weak_marker":
            action.pop("precondition_observation")
            action["assertions"] = [item for item in action["assertions"]
                                    if item["assertion_id"] == "password-field-name"]
        elif scenario_id == "false_marker":
            action["assertions"].append({
                "assertion_id": "absent-admin-marker", "kind": "json_equals",
                "path": ["users", 0, "account_number"], "expected": "ADMIN999",
            })
        elif scenario_id == "no_action":
            contract = None
        elif scenario_id not in {"verified_marker", "minimal_threshold", "partial_boundary"}:
            raise ValueError(f"unknown transition scenario: {scenario_id}")
        if contract is not None:
            contract = impact_contract_document(
                ImpactDevelopmentRuntimeContract.model_validate(contract)
            )
        trigger = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='finding_reproduction_specs_no_update'"
        ).fetchone()
        if trigger is None:
            raise ValueError("transition seed lost immutable-spec trigger")
        with conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                "UPDATE finding_reproduction_specs SET impact_development_contract_json=?, "
                "impact_development_contract_sha256=? WHERE finding_id=?",
                (json.dumps(contract, sort_keys=True) if contract is not None else None,
                 canonical_sha256(contract) if contract is not None else None,
                 finding_id),
            )
            conn.execute(trigger[0])


def _stage_weak_source_signal(database: Path, finding_id: str) -> None:
    """Keep the former generic marker as an integrity-negative control."""
    with sqlite3.connect(database) as conn:
        row = conn.execute(
            "SELECT runtime_contract_json FROM finding_reproduction_specs "
            "WHERE finding_id=?", (finding_id,),
        ).fetchone()
        if row is None or row[0] is None:
            raise ValueError("transition seed has no bound replay contract")
        runtime = json.loads(row[0])
        for kind in ("target", "negative_control"):
            runtime[kind]["assertions"][0]["expected"] = "users"
        trigger = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='finding_reproduction_specs_no_update'"
        ).fetchone()
        if trigger is None:
            raise ValueError("transition seed lost immutable-spec trigger")
        with conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                "UPDATE finding_reproduction_specs SET runtime_contract_json=?, "
                "runtime_contract_sha256=? WHERE finding_id=?",
                (json.dumps(runtime, sort_keys=True), canonical_sha256(runtime), finding_id),
            )
            conn.execute(trigger[0])


def prepare_transition_lab(
    inventory: Path, answers: Path, observations: Path, output: Path, *,
    scope_root: Path = DEFAULT_SCOPE_ROOT,
    live_probe: Callable[[str], tuple[int, str, int]] = fetch_status_and_digest,
    identity_probe: Callable[[], dict] = verify_runtime_identity,
    impact_marker_probe: Callable[[str], tuple[set[str], str]] = probe_impact_markers,
) -> dict:
    """Stage one live-checked seed, then clone and validate every scenario DB."""
    output = Path(output)
    if output.exists():
        raise ValueError(f"transition output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="validation-transition-", dir=output.parent) as directory:
        staging = Path(directory)
        seed = staging / "seed"
        mapping = prepare_validation_lab(
            inventory, answers, observations, seed, scope_root=scope_root,
            live_probe=live_probe, identity_probe=identity_probe,
            impact_probe=True, impact_marker_probe=impact_marker_probe,
        )
        selected = mapping["impact_lab"]
        if selected["candidate_id"] != IMPACT_CANDIDATE:
            raise ValueError("transition seed selected an unexpected candidate")
        cases = []
        for scenario_id, baseline in SCENARIOS:
            bundle = staging / scenario_id
            shutil.copytree(seed, bundle)
            _vary_contract(bundle / "Pipeline.db", selected["finding_id"], scenario_id)
            variant_mapping = json.loads((bundle / "CandidateFindingMap.json").read_text())
            variant_mapping["transition_case"] = {
                "scenario_id": scenario_id, **selected,
            }
            (bundle / "CandidateFindingMap.json").write_text(
                json.dumps(variant_mapping, ensure_ascii=False, indent=2) + "\n"
            )
            with sqlite3.connect(bundle / "Pipeline.db") as conn:
                conn.row_factory = sqlite3.Row
                candidate = CandidateIntegrityGate(conn).validate_finding(
                    case_id="preflight-" + scenario_id,
                    scan_id=selected["scan_id"], finding_id=selected["finding_id"],
                )
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError(f"transition scenario DB failed integrity: {scenario_id}")
            evidence_sha256 = _baseline_evidence_sha256(candidate)
            cases.append({
                "scenario_id": scenario_id, **selected,
                "baseline_evidence_sha256": evidence_sha256,
                "fixture_baseline_axes": {
                    "boundary": baseline[0], "sensitivity": baseline[1],
                    "actor_requirements": baseline[2],
                },
            })
        reference = next(case for case in cases
                         if case["scenario_id"] == "verified_marker")
        for case in cases:
            shared_replay_conflict = (
                case["fixture_baseline_axes"] != reference["fixture_baseline_axes"]
                and case["baseline_evidence_sha256"]
                    == reference["baseline_evidence_sha256"]
            )
            case["real_axis_trial_ready"] = not shared_replay_conflict
            case["real_axis_trial_reason"] = (
                "shared_replay_evidence" if shared_replay_conflict else None
            )
        weak_name = "weak_source_signal"
        weak_bundle = staging / weak_name
        shutil.copytree(seed, weak_bundle)
        _stage_weak_source_signal(weak_bundle / "Pipeline.db", selected["finding_id"])
        with sqlite3.connect(weak_bundle / "Pipeline.db") as conn:
            conn.row_factory = sqlite3.Row
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("weak-signal control DB failed integrity")
            try:
                CandidateIntegrityGate(conn).validate_finding(
                    case_id="preflight-weak-source-signal",
                    scan_id=selected["scan_id"], finding_id=selected["finding_id"],
                )
            except CandidateIntegrityError as exc:
                if exc.check != "runtime_profile_semantics":
                    raise
            else:
                raise ValueError("weak-signal control passed the proof gate")
        shutil.rmtree(seed)
        manifest = {
            "fixture_kind": "synthetic_validation_transition_scenarios",
            "cases": cases,
            "proof_negative_controls": [{"scenario_id": weak_name, **selected}],
        }
        (staging / "TransitionManifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        )
        os.replace(staging, output)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-db", type=Path, default=DEFAULT_ROOT / "CandidateInventory.db")
    parser.add_argument("--answer-db", type=Path, default=DEFAULT_ROOT / "CandidateAnswerKey.db")
    parser.add_argument("--observations", type=Path, default=DEFAULT_ROOT / "LocalControlObservations.json")
    parser.add_argument("--scope-root", type=Path, default=DEFAULT_SCOPE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_ROOT / "validation-transition-lab")
    args = parser.parse_args()
    result = prepare_transition_lab(
        args.candidate_db, args.answer_db, args.observations, args.output,
        scope_root=args.scope_root,
    )
    print(json.dumps({"output": str(args.output), "scenario_count": len(result["cases"])},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
