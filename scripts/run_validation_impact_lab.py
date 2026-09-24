"""Run one isolated weak-impact case with real Validation agents and native GET Development."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aidast.validation import NativePrerequisiteResolver, ValidationCoordinator
from aidast.validation.core.policy import TargetPolicyProvider
from aidast.validation.execution.http_adapter import HttpReproductionPort
from aidast.validation.execution.native_impact import NativeImpactDevelopmentPort

try:
    from scripts.prepare_validation_lab import IMPACT_CANDIDATE
except ModuleNotFoundError:  # Direct `python scripts/run_validation_impact_lab.py`.
    from prepare_validation_lab import IMPACT_CANDIDATE


def build_impact_lab_coordinator(bundle: Path, *, agent=None,
                                 impact_agent_factory=None, transport=None
                                 ) -> tuple[ValidationCoordinator, dict]:
    """Select only the opt-in impact fixture and attach the native request ledger."""
    mapping = json.loads((bundle / "CandidateFindingMap.json").read_text(encoding="utf-8"))
    selected = mapping.get("impact_lab")
    if (not isinstance(selected, dict) or selected.get("candidate_id") != IMPACT_CANDIDATE
            or not any(all(item.get(key) == value for key, value in selected.items())
                       for item in mapping.get("cases", []))):
        raise ValueError("bundle is not an isolated impact lab")
    policy_provider = TargetPolicyProvider(bundle / "TargetPolicy.json")
    coordinator = ValidationCoordinator(
        db_path=bundle / "Pipeline.db", agent=agent,
        reproduction=HttpReproductionPort(transport=transport),
        policy_provider=policy_provider,
        prerequisite_resolver=NativePrerequisiteResolver(
            transport=transport, policy_provider=policy_provider,
        ),
        impact_development_port=NativeImpactDevelopmentPort(
            transport=transport, policy_provider=policy_provider,
        ),
        impact_agent_factory=impact_agent_factory,
    )
    return coordinator, selected


def run_impact_lab(bundle: Path) -> dict:
    coordinator, selected = build_impact_lab_coordinator(bundle)
    result = coordinator.run(selected["scan_id"], finding_id=selected["finding_id"])
    return {"candidate_id": selected["candidate_id"],
            "finding_id": selected["finding_id"],
            "stage_run_id": result.stage_run_id,
            "statuses": result.summary["statuses"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_impact_lab(args.bundle), ensure_ascii=False))


if __name__ == "__main__":
    main()
