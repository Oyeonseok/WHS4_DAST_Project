"""Deterministic priority-ordered Validation status decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .impact import ImpactResult


@dataclass(frozen=True)
class DecisionInput:
    integrity_ok: bool = True
    known: bool = False
    policy_allowed: bool = True
    positive_control_passed: bool = True
    negative_control_clear: bool = True
    explicit_non_exploit_evidence: bool = False
    topology_or_unknown_cause: bool = False
    resolvable_blocker: bool = False
    development_used: bool = False
    target_observations: tuple[bool, ...] = ()
    semantic_conflict: bool = False
    attack_has_positive_evidence: bool = False
    impact: ImpactResult | None = None


DecisionStatus = Literal[
    "CONFIRMED", "DISPROVEN", "OUT_OF_SCOPE", "KNOWN", "UNDERPOWERED",
    "BLOCKED", "INCONCLUSIVE", "CONTESTED", "DEVELOPING",
]


class DecisionEngine:
    """Apply design §8.8; DEVELOPING is an effective, nonterminal status."""

    def decide(self, value: DecisionInput) -> DecisionStatus:
        if not value.integrity_ok:
            return "INCONCLUSIVE"
        if value.known:
            return "KNOWN"
        if not value.policy_allowed:
            return "OUT_OF_SCOPE"
        if not value.positive_control_passed or not value.negative_control_clear:
            return "INCONCLUSIVE"
        if value.explicit_non_exploit_evidence:
            return "DISPROVEN"
        if value.topology_or_unknown_cause:
            return "INCONCLUSIVE"
        if value.resolvable_blocker:
            return "BLOCKED" if value.development_used else "DEVELOPING"
        observations = value.target_observations
        if len(observations) not in {3, 5}:
            return "INCONCLUSIVE"
        if len(observations) == 5 or not all(observations):
            return "INCONCLUSIVE"
        if value.semantic_conflict and value.attack_has_positive_evidence:
            return "CONTESTED"
        if value.impact is None:
            return "INCONCLUSIVE"
        if value.impact.underpowered:
            return "UNDERPOWERED"
        return "CONFIRMED"
