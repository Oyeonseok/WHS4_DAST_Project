"""Run one isolated weak-impact case with real Validation agents and native GET Development."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Callable

from aidast.validation import NativePrerequisiteResolver, ValidationCoordinator, canonical_sha256
from aidast.validation.contracts.impact_development import impact_action_document
from aidast.validation.core.policy import TargetPolicyProvider
from aidast.validation.execution.http_adapter import HttpReproductionPort
from aidast.validation.execution.native_impact import NativeImpactDevelopmentPort

try:
    from scripts.prepare_validation_lab import (
        BASES, IMPACT_CANDIDATE, ROOT, SEED_SOURCE_SHA256, probe_impact_markers,
    )
except ModuleNotFoundError:  # Direct `python scripts/run_validation_impact_lab.py`.
    from prepare_validation_lab import (
        BASES, IMPACT_CANDIDATE, ROOT, SEED_SOURCE_SHA256, probe_impact_markers,
    )


def verify_impact_lab_preconditions(candidate, request, *,
                                    probe: Callable[[str], tuple[set[str], str]] = probe_impact_markers
                                    ) -> dict:
    """Publish a marker receipt only after rechecking its pinned source and live JSON."""
    url = BASES["vuln-bank"] + "/debug/users"
    source_url = ("https://github.com/Commando-X/vuln-bank/blob/"
                  "5e5ea5425fcf309373a0655dd111ecfb45037cbf/database.py#L255")
    source_file = ROOT / "result/lab/vuln-bank/database.py"
    if (not source_file.is_file()
            or hashlib.sha256(source_file.read_bytes()).hexdigest() != SEED_SOURCE_SHA256):
        raise ValueError("impact precondition seed source changed")
    actions = [action for action in candidate.impact_development_actions
               if action.contract_id == "debug-users-password-field"]
    if (request.path_id != "bounded-impact-confirmation"
            or tuple(request.required_preconditions) != (
                "An exact same-origin safe-method request already captured by Attack",
                "A unique non-secret configuration or data marker for the stronger impact",
            )):
        raise ValueError("impact precondition request changed")
    if len(actions) != 1:
        raise ValueError("impact precondition action missing")
    action = actions[0]
    receipt = action.precondition_observation
    marker = next((item for item in action.assertions
                   if item.assertion_id == "seeded-admin-account"), None)
    if (receipt is None or receipt.marker_source is None
            or receipt.marker_source.url != source_url
            or receipt.marker_source.file_sha256 != SEED_SOURCE_SHA256
            or receipt.marker_source.line != 255
            or list(receipt.marker_json_path) != ["users", 0, "account_number"]
            or receipt.marker_assertion_id != "seeded-admin-account"
            or receipt.response_status != 200
            or marker is None or marker.kind != "json_equals"
            or list(marker.path) != ["users", 0, "account_number"]
            or marker.expected != "ADMIN001"
            or action.method != "GET"
            or not any(item["request_id"] == receipt.source_request_id
                       and item["method"] == "GET" and item["url"] == url
                       and item["response_status"] == 200
                       and item["authorization_source"] == "scope_safe_method"
                       for item in candidate.source_requests)):
        raise ValueError("impact precondition receipt is not bound to pinned source")
    names, body_sha = probe(url)
    if (not {"users", "password", "seeded_admin", "seeded_admin_account"} <= names
            or body_sha != receipt.response_sha256):
        raise ValueError("impact precondition live marker or digest changed")
    return {
        "path_id": request.path_id,
        "contract_sha256": canonical_sha256(impact_action_document(action)),
        "required_preconditions": list(request.required_preconditions),
        "source_request_ids": [receipt.source_request_id],
        "evidence_ids": [],
        "details": {"contract_id": action.contract_id,
                    **receipt.model_dump(mode="json"),
                    "marker_assertion_expected": "ADMIN001"},
    }


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
        impact_precondition_verifier=verify_impact_lab_preconditions,
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
