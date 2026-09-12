"""Deterministic payload normalization and same-scan KNOWN matching."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from .models import canonical_json, canonical_sha256

MATCHER_VERSION = 1
NORMALIZER_VERSION = 1
KNOWN_THRESHOLD = 0.85
_SLOT = re.compile(r"(?:<slot:(?:[^:<>]+:)?([^<>:]+)>|\{\{[^{}:]+:([^{}:]+)\}\})")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(key)): _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        value = unicodedata.normalize("NFC", value)
        return _SLOT.sub(lambda match: f"<slot:{match.group(1) or match.group(2)}>", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError("payload template must contain only JSON values")


def canonical_payload(payload: Any) -> str:
    """Return a versioned, stable JSON representation of a payload template."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("payload template must be valid JSON") from exc
    return canonical_json(_normalize(payload))


def payload_structure_sha256(payload: Any) -> str:
    return canonical_sha256(_normalize(json.loads(payload) if isinstance(payload, str) else payload))


def levenshtein_codepoint_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        for column, right_char in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[column] + 1,
                               previous[column - 1] + (left_char != right_char)))
        previous = current
    return previous[-1]


def normalized_similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return 1.0 - levenshtein_codepoint_distance(left, right) / max(len(left), len(right))


@dataclass(frozen=True)
class KnownCandidate:
    case_id: str
    vuln_class: str
    endpoint_template: str
    parameter_name: str
    payload_template: Any
    current_status: str = "CONFIRMED"


@dataclass(frozen=True)
class KnownMatch:
    source_case_id: str
    similarity: float
    matcher_version: int = MATCHER_VERSION
    normalizer_version: int = NORMALIZER_VERSION


class KnownMatcher:
    def __init__(self, threshold: float = KNOWN_THRESHOLD):
        if not 0 <= threshold <= 1:
            raise ValueError("KNOWN threshold must be between zero and one")
        self.threshold = threshold

    def match(self, *, vuln_class: str, endpoint_template: str, parameter_name: str,
              payload_template: Any, candidates: Iterable[KnownCandidate]) -> KnownMatch | None:
        target = canonical_payload(payload_template)
        matches = []
        for candidate in candidates:
            if candidate.current_status != "CONFIRMED" or (
                candidate.vuln_class, candidate.endpoint_template, candidate.parameter_name
            ) != (vuln_class, endpoint_template, parameter_name):
                continue
            similarity = normalized_similarity(target, canonical_payload(candidate.payload_template))
            if similarity >= self.threshold:
                matches.append((similarity, candidate.case_id))
        if not matches:
            return None
        similarity, case_id = sorted(matches, key=lambda item: (-item[0], item[1]))[0]
        return KnownMatch(source_case_id=case_id, similarity=similarity)
