"""Packaged Validation profile coverage and strictness."""

import json
import unittest
from importlib.resources import files
from unittest.mock import Mock

from pydantic import ValidationError as PydanticValidationError

from aidast.attack.catalog import load_catalog
from aidast.validation import (ImpactGapAnalyzer, SkillProfileResolver,
                               ValidationProfile, evaluate_impact,
                               CodexBlindValidationRunner, BlindAssessment,
                               ClaimComparison)


class ValidationProfileTests(unittest.TestCase):
    def test_every_packaged_hunt_skill_has_exactly_one_bound_profile(self):
        expected = tuple(entry.skill_id for entry in load_catalog() if entry.skill_id != "chain")
        self.assertEqual(SkillProfileResolver().validate_coverage(), expected)
        profile_root = files("aidast.skills.validation").joinpath("profiles")
        actual = tuple(sorted(item.name.removesuffix(".json") for item in profile_root.iterdir()
                              if item.name.endswith(".json")))
        self.assertEqual(actual, tuple(sorted(expected)))

    def test_profile_rejects_unknown_fields_and_timing_without_baseline(self):
        document = {
            "schema_version": 1, "attack_skill_name": "hunt-test",
            "signal_types": ["timing"], "target_expected_signal": {},
            "control_positive": {"payload_template": {}, "expected_signal": {},
                                 "signal_type": "timing"},
            "control_negative": {"payload_template": {}, "expected_signal": {}},
            "impact_rules": {}, "allowed_development_actions": [],
            "impact_expansion_paths": [], "unexpected": True,
        }
        with self.assertRaises(PydanticValidationError):
            ValidationProfile.model_validate_json(json.dumps(document))

    def test_impact_gap_uses_only_profile_paths_and_current_evidence(self):
        profile = SkillProfileResolver().resolve("hunt-idor").profile
        proposals = ImpactGapAnalyzer().analyze(
            profile=profile, impact=evaluate_impact(0, 1, 2),
            evidence_ids=("current_evidence",),
        )
        self.assertEqual([item["path_id"] for item in proposals], ["cross-role-object-access"])
        self.assertEqual(proposals[0]["supporting_evidence_ids"], ["current_evidence"])
        self.assertEqual(proposals[0]["execution_owner"], "validation")

    def test_codex_runner_keeps_claim_out_of_blind_pass(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}
        assessment = BlindAssessment(
            case_id="case", blind_case_sha256="a" * 64, reproduced=True,
            signal_types=("response_diff",), target_attempt_ids=("target",),
            control_attempt_ids=("control",), evidence_ids=("evidence",),
            impact_boundary=axis, impact_sensitivity=axis,
            impact_actor_requirements=axis, conclusion="Observed consistently.",
        )
        comparison = ClaimComparison(
            case_id="case", blind_assessment_sha256="b" * 64,
            attack_claim_sha256="c" * 64, alignment="aligned", conflict_axes=(),
            validation_evidence_ids=("evidence",), attack_evidence_ids=("attack",),
            reason="Claims align.",
        )
        agent = Mock()
        agent._run_structured.side_effect = [assessment, comparison]
        runner = CodexBlindValidationRunner(agent)
        blind = {
            "case_id": "case", "attack_skill_name": "hunt-idor",
            "attack_skill_sha256": resolved.attack_skill_sha256,
            "validation_skill_sha256": resolved.validation_skill_sha256,
            "validation_profile_sha256": resolved.profile_sha256,
        }
        self.assertIs(runner.assess(blind, ()), assessment)
        first_prompt = agent._run_structured.call_args_list[0].kwargs["prompt"]
        self.assertNotIn("claimed_impact", first_prompt)
        self.assertIs(runner.compare(
            {"claimed_impact": "cross-user read"}, assessment.model_dump(mode="json")
        ), comparison)
        self.assertIn("claimed_impact", agent._run_structured.call_args_list[1].kwargs["prompt"])


if __name__ == "__main__":
    unittest.main()
