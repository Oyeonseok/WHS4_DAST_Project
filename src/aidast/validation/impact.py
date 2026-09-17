"""Deterministic validation impact scoring independent of program rewards."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ImpactResult:
    boundary: int
    sensitivity: int
    actor_requirements: int
    score: int
    severity: str
    underpowered: bool


def evaluate_impact(boundary: int, sensitivity: int, actor_requirements: int) -> ImpactResult:
    values = (boundary, sensitivity, actor_requirements)
    if any(type(value) is not int or not 0 <= value <= 3 for value in values):
        raise ValueError("impact axes must be integers from zero through three")
    score = sum(values)
    severity = "INFO" if score <= 2 else "LOW" if score <= 4 else "MEDIUM" if score <= 6 else "HIGH" if score <= 8 else "CRITICAL"
    return ImpactResult(boundary, sensitivity, actor_requirements, score, severity,
                        boundary == 0 or sensitivity == 0 or score < 3)
