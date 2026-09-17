"""Non-executing impact-gap proposals constrained to a verified profile."""

from __future__ import annotations

from typing import Iterable

from .impact import ImpactResult
from .profiles import ValidationProfile


class ImpactGapAnalyzer:
    def analyze(self, *, profile: ValidationProfile, impact: ImpactResult,
                evidence_ids: Iterable[str]) -> tuple[dict, ...]:
        evidence = tuple(dict.fromkeys(evidence_ids))
        if not evidence:
            return ()
        scores = {
            "boundary": impact.boundary,
            "sensitivity": impact.sensitivity,
            "actor_requirements": impact.actor_requirements,
        }
        proposals = []
        for path in profile.impact_expansion_paths:
            current = scores[path.gap_axis]
            if current > 0:
                continue
            proposals.append({
                "gap_axis": path.gap_axis,
                "path_id": path.path_id,
                "hypothesis_kind": path.hypothesis_kind,
                "current_score": current,
                "reason": {"text": f"Current {path.gap_axis} score is {current}.",
                           "evidence_ids": list(evidence)},
                "required_preconditions": list(path.required_preconditions),
                "recommended_actions": list(path.recommended_actions),
                "expected_signal": path.expected_signal,
                "supporting_evidence_ids": list(evidence),
                "execution_owner": path.execution_owner,
                "feasibility": path.feasibility,
                "potential_impact": path.potential_impact,
            })
            if len(proposals) == 3:
                break
        return tuple(proposals)
