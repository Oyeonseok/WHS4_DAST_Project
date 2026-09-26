"""Extract bounded replay facts by joining adapter summaries to staged contracts.

These receipts prove what a native adapter reported under an execution contract.
They do not independently establish ownership, a victim session, persistence,
callback source identity, or other profile-specific security semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from ..contracts.models import BlindAssessment, canonical_sha256
from ..contracts.runtime_contract import validate_runtime_contract


MAX_FACTS = 8


@dataclass(frozen=True)
class ExtractedFacts:
    facts: tuple[dict[str, Any], ...]
    omitted_count: int = 0


def _channel(runtime: Any) -> str:
    return getattr(runtime, "runtime_kind", "http")


def _assertions(attempt: Any, channel: str) -> tuple[Any, ...]:
    if channel == "concurrent":
        return attempt.aggregate_assertions
    return attempt.assertions


def _summary(details: object, channel: str) -> list[dict[str, Any]]:
    if not isinstance(details, dict):
        return []
    if channel == "concurrent":
        aggregate = details.get("aggregate")
        rows = aggregate.get("a") if isinstance(aggregate, dict) else None
    elif channel in {"http", "browser"}:
        evaluation = details.get("evaluation")
        rows = evaluation.get("assertions") if isinstance(evaluation, dict) else None
    else:
        rows = details.get("assertions")
    return rows if isinstance(rows, list) and all(isinstance(row, dict) for row in rows) else []


def _fingerprint(assertion: Any) -> str:
    # A control only separates the same predicate. The label is allowed to differ,
    # but paths, selectors, headers, frame indices and other inputs are not.
    return canonical_sha256(assertion.model_dump(mode="json", exclude={"assertion_id"}))


def _has_ledger_ids(item: dict[str, Any], channel: str) -> bool:
    details = item.get("details")
    if not isinstance(details, dict):
        return False
    key = "request_ids" if channel in {"http", "browser", "oob"} else "operation_ids"
    ids = details.get(key)
    return (isinstance(ids, list) and bool(ids)
            and all(isinstance(identifier, str) and bool(identifier) for identifier in ids)
            and len(ids) == len(set(ids)))


def _matched_summary(
    assertion: Any, attempt: Any, details: object, channel: str,
) -> dict[str, Any] | None:
    rows = _summary(details, channel)
    assertions = _assertions(attempt, channel)
    if channel == "concurrent":
        digest = canonical_sha256({"kind": assertion.kind, "expected": assertion.expected})
        matches = [row for row in rows if row.get("h") == digest and type(row.get("p")) is bool]
        return matches[0] if len(matches) == 1 else None
    if channel in {"grpc", "websocket"}:
        indices = [index for index, candidate in enumerate(assertions)
                   if _fingerprint(candidate) == _fingerprint(assertion)]
        if len(indices) != 1 or indices[0] >= len(rows):
            return None
        row = rows[indices[0]]
    else:
        identifier_key = "assertion_id_sha256" if channel == "multipart" else "assertion_id"
        identifier = (canonical_sha256(assertion.assertion_id)
                      if channel == "multipart" else assertion.assertion_id)
        matches = [row for row in rows if row.get(identifier_key) == identifier]
        if len(matches) != 1:
            return None
        row = matches[0]
    if (row.get("kind") != assertion.kind
            or row.get("expected_sha256") != canonical_sha256(assertion.expected)
            or type(row.get("passed")) is not bool):
        return None
    if (row["passed"] is True
            and not assertion.kind.startswith("duration_")
            and row.get("actual_sha256") != canonical_sha256(assertion.expected)):
        return None
    return row


def _assertion_facts(
    profile_id: str, runtime: Any, channel: str,
    targets: list[dict[str, Any]], negative: dict[str, Any],
) -> list[dict[str, Any]]:
    target_contract = runtime.for_attempt("target")
    negative_contract = runtime.for_attempt("negative_control")
    results: list[dict[str, Any]] = []
    for assertion in _assertions(target_contract, channel):
        candidates = [item for item in _assertions(negative_contract, channel)
                      if _fingerprint(item) == _fingerprint(assertion)]
        if len(candidates) != 1:
            continue
        negative_result = _matched_summary(
            candidates[0], negative_contract, negative.get("details"), channel,
        )
        if negative_result is None or (
            negative_result.get("p") if channel == "concurrent"
            else negative_result.get("passed")
        ) is not False:
            continue
        if not all(
            (row := _matched_summary(assertion, target_contract, item.get("details"), channel))
            is not None and (row.get("p") if channel == "concurrent" else row.get("passed")) is True
            for item in targets
        ):
            continue
        results.append({
            "kind": "assertion_differential",
            "profile_id": profile_id,
            "runtime_kind": channel,
            "assertion_kind": assertion.kind,
            "assertion_id_sha256": canonical_sha256(assertion.assertion_id),
            "assertion_predicate_sha256": _fingerprint(assertion),
            "expected_sha256": canonical_sha256(assertion.expected),
            "target_attempt_ids": [item["attempt_id"] for item in targets],
            "target_evidence_ids": [item["evidence_id"] for item in targets],
            "negative_attempt_id": negative["attempt_id"],
            "negative_evidence_id": negative["evidence_id"],
            "provenance": "contract_bound_adapter_summary",
        })
    return results


def _oob_facts(
    profile_id: str, runtime: Any,
    targets: list[dict[str, Any]], negative: dict[str, Any],
) -> list[dict[str, Any]]:
    target_contract = runtime.for_attempt("target")
    negative_contract = runtime.for_attempt("negative_control")

    def valid(item: dict[str, Any], contract: Any, *, observed: bool) -> bool:
        details = item.get("details")
        if not isinstance(details, dict):
            return False
        nonce = hashlib.sha256(item["attempt_id"].encode("utf-8")).hexdigest()[:16]
        token = contract.token_template.replace("{nonce}", nonce)
        count = details.get("matched_callback_count")
        protocols = details.get("matched_protocols")
        if (details.get("token_sha256") != canonical_sha256(token)
                or type(count) is not int or count < 0
                or not isinstance(protocols, list)
                or not all(isinstance(protocol, str) and protocol in contract.protocols
                           for protocol in protocols)):
            return False
        return (count >= contract.minimum_callbacks and bool(protocols)) if observed else count == 0 and not protocols

    if not all(valid(item, target_contract, observed=True) for item in targets):
        return []
    if not valid(negative, negative_contract, observed=False):
        return []
    return [{
        "kind": "nonce_callback_differential",
        "profile_id": profile_id,
        "runtime_kind": "oob",
        "target_attempt_ids": [item["attempt_id"] for item in targets],
        "target_evidence_ids": [item["evidence_id"] for item in targets],
        "negative_attempt_id": negative["attempt_id"],
        "negative_evidence_id": negative["evidence_id"],
        "protocols": sorted({protocol for item in targets
                             for protocol in item["details"]["matched_protocols"]}),
        "provenance": "contract_bound_adapter_summary",
    }]


def extract_replay_facts(
    profile_id: str, runtime_contract: Any, assessment: BlindAssessment,
    observations: Iterable[dict[str, Any]], *, replay_status: str,
) -> ExtractedFacts:
    """Return only differential, contract-bound structural facts for this Blind replay."""
    if replay_status != "complete":
        return ExtractedFacts(())
    runtime = (validate_runtime_contract(runtime_contract)
               if isinstance(runtime_contract, dict) else runtime_contract)
    channel = _channel(runtime)
    if channel == "chain":
        return ExtractedFacts(())
    replay = tuple(observations)
    target_ids = set(assessment.target_attempt_ids)
    control_ids = set(assessment.control_attempt_ids)
    targets = [item for item in replay if item.get("attempt_kind") == "target"
               and item.get("attempt_id") in target_ids]
    positives = [item for item in replay if item.get("attempt_kind") == "positive_control"
                 and item.get("attempt_id") in control_ids]
    negatives = [item for item in replay if item.get("attempt_kind") == "negative_control"
                 and item.get("attempt_id") in control_ids]
    if (len(target_ids) not in {3, 5} or len(targets) != len(target_ids)
            or len(positives) != 1 or len(negatives) != 1
            or not all(_has_ledger_ids(item, channel)
                       for item in (*targets, *positives, *negatives))
            or any(item.get("outcome") != "observed" or item.get("signal_observed") is not True
                   for item in (*targets, *positives))
            or negatives[0].get("outcome") != "not_observed"
            or negatives[0].get("signal_observed") is not False):
        return ExtractedFacts(())
    targets.sort(key=lambda item: assessment.target_attempt_ids.index(item["attempt_id"]))
    facts = (_oob_facts(profile_id, runtime, targets, negatives[0])
             if channel == "oob" else
             _assertion_facts(profile_id, runtime, channel, targets, negatives[0]))
    return ExtractedFacts(tuple(facts[:MAX_FACTS]), max(0, len(facts) - MAX_FACTS))
