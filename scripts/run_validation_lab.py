"""Run the isolated local GET Validation lab with pinned negative evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aidast.validation import NativePrerequisiteResolver, ValidationCoordinator
from aidast.validation.core.policy import TargetPolicyProvider

try:
    from scripts.validation_lab_negative_proof import (
        LabNegativeProofHttpPort, load_lab_negative_proofs,
    )
except ModuleNotFoundError:  # Direct `python scripts/run_validation_lab.py`.
    from validation_lab_negative_proof import (
        LabNegativeProofHttpPort, load_lab_negative_proofs,
    )


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = ROOT / "result/test-runs/validation-candidates"


def run_lab(*, bundle: Path, candidate_root: Path = DEFAULT_CANDIDATES,
            finding_id: str | None = None) -> list[dict]:
    """Validate exact staged cases; the separate answer key is never loaded."""
    mapping_path = bundle / "CandidateFindingMap.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    proofs = load_lab_negative_proofs(
        inventory_path=candidate_root / "CandidateInventory.db",
        mapping_path=mapping_path, pipeline_path=bundle / "Pipeline.db",
        observations_path=candidate_root / "LocalControlObservations.json",
    )
    port = LabNegativeProofHttpPort(proofs)
    coordinator = ValidationCoordinator(
        db_path=bundle / "Pipeline.db", agent=None, reproduction=port,
        policy_provider=TargetPolicyProvider(bundle / "TargetPolicy.json"),
        prerequisite_resolver=NativePrerequisiteResolver(),
    )
    selected = [case for case in mapping["cases"]
                if finding_id is None or case["finding_id"] == finding_id]
    if not selected:
        raise ValueError("finding is not in the isolated Validation lab mapping")
    results = []
    for case in selected:
        result = coordinator.run(case["scan_id"], finding_id=case["finding_id"])
        results.append({"candidate_id": case["candidate_id"],
                        "finding_id": case["finding_id"],
                        "stage_run_id": result.stage_run_id,
                        "statuses": result.summary["statuses"]})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--finding-id")
    args = parser.parse_args()
    results = run_lab(bundle=args.bundle, candidate_root=args.candidate_root,
                      finding_id=args.finding_id)
    print(json.dumps({"results": results}, ensure_ascii=False))


if __name__ == "__main__":
    main()
