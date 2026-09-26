"""Run controlled, read-only replays to measure audit persistence only.

This agent derives reproduced from actual target observations and fixes impact
axes for instrumentation. Its verdicts are not measurements of Blind Agent
accuracy and must not be counted as an official Agent evaluation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aidast.validation import ClaimComparison
from aidast.validation.contracts.eligibility import EligibilityAssessment

try:
    from scripts.run_validation_lab import DEFAULT_CANDIDATES, run_lab
except ModuleNotFoundError:
    from run_validation_lab import DEFAULT_CANDIDATES, run_lab


class ControlledEligibilityAgent:
    agent_id = "profile_audit_controlled_eligibility"

    def assess(self, request, correction=None):
        return EligibilityAssessment(
            case_id=request.case_id, scope_sha256=request.scope_sha256,
            phase=request.phase, eligibility="ELIGIBLE",
            matched_rule="Pinned local lab scope", scope_quote=request.scope_markdown,
            required_impact=(), replay_allowed=True,
            reason="The selected read-only GET is covered by the pinned local lab scope.",
            evidence_refs=request.evidence_refs,
        )


class ControlledReplayAssessmentAgent:
    agent_id = "profile_audit_controlled_blind"

    def assess(self, blind_case, observations, correction=None):
        targets = tuple(item for item in observations if item["attempt_kind"] == "target")
        positives = tuple(item for item in observations
                          if item["attempt_kind"] == "positive_control")
        negatives = tuple(item for item in observations
                          if item["attempt_kind"] == "negative_control")
        if (len(targets) != 3 or len(positives) != 1 or len(negatives) != 1
                or positives[0]["signal_observed"] is not True
                or negatives[0]["signal_observed"] is not False
                or not (all(item["signal_observed"] is True for item in targets)
                        or all(item["signal_observed"] is False for item in targets))):
            raise ValueError("controlled audit requires a complete and consistent replay")
        reproduced = all(item["signal_observed"] is True for item in targets)
        evidence = tuple(item["evidence_id"] for item in observations)
        target_evidence = targets[0]["evidence_id"]
        negative_evidence = negatives[0]["evidence_id"]

        def axis(score, citations):
            return {"score": score, "evidence_ids": citations,
                    "reason": "Controlled read-only replay assessment for audit instrumentation."}

        return {
            "case_id": blind_case["case_id"],
            "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": reproduced,
            "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": tuple(item["attempt_id"] for item in targets),
            "control_attempt_ids": (positives[0]["attempt_id"], negatives[0]["attempt_id"]),
            "evidence_ids": evidence, "blocker_axis": None, "blocker_reason": None,
            "impact_boundary": axis(1 if reproduced else 0,
                                    (target_evidence, negative_evidence)),
            "impact_sensitivity": axis(0, (target_evidence,)),
            "impact_actor_requirements": axis(2 if reproduced else 0,
                                              (target_evidence,)),
            "conclusion": "Controlled assessment of the completed local GET replay.",
        }

    def compare(self, claim, assessment, correction=None):
        reproduced = assessment["reproduced"]
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"],
            alignment="aligned" if reproduced else "conflicting",
            conflict_axes=() if reproduced else ("vuln_class",),
            validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="Controlled comparison of the observed target signal to the synthetic claim.",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--finding-id")
    args = parser.parse_args()
    results = run_lab(
        bundle=args.bundle, candidate_root=args.candidate_root,
        finding_id=args.finding_id, agent=ControlledReplayAssessmentAgent(),
        eligibility_agent=ControlledEligibilityAgent(),
    )
    print(json.dumps({"mode": "controlled_audit_instrumentation",
                      "results": results}, ensure_ascii=False))


if __name__ == "__main__":
    main()
