"""Versioned, profile-specific semantic evidence requirements for Blind review.

This registry is currently evaluated in audit mode. Runtime observations establish
replay citations, but do not manufacture identity, ownership, state, or execution
facts that the native adapters have not independently verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
from typing import Any, Iterable

from ..contracts.models import BlindAssessment, canonical_json, canonical_sha256
from ..persistence.evidence_policy import sanitize_metadata
from .evidence_facts import extract_replay_facts
from .profiles import SkillProfileResolver, ValidationProfile


RULE_VERSION = "profile-evidence-v1"


@dataclass(frozen=True)
class ProfileEvidenceRule:
    profile_id: str
    family: str
    runtime_kind: str
    signal_type: str
    target_signal_kind: str
    target_fact: str
    boundary_fact: str
    sensitivity_fact: str
    actor_fact: str
    manual_review: bool = False


# Columns: profile | family | target effect | boundary | sensitivity | actor.
# A fact name is a requirement, never a claim that a replay adapter verified it.
_RULE_ROWS = """
hunt-api-misconfig|DIFF|unauthorized_api_effect|api_policy_and_caller|protected_api_data_or_function|api_caller_role
hunt-aspnet|DIFF|aspnet_protected_diagnostic|diagnostic_access_policy|protected_diagnostic_content|diagnostic_caller_role
hunt-ato|AUTH|victim_account_control_changed|victim_and_attacker_identity|account_control_after_recheck|account_takeover_prerequisites
hunt-auth-bypass|AUTH|protected_action_without_auth|required_vs_actual_auth_state|protected_action_completion|successful_session_state
hunt-brute-force|TIME|rate_limit_boundary_crossed|limit_policy_and_final_access|protected_action_after_guesses|attempt_count_and_time_window
hunt-business-logic|STATE|forbidden_business_transition|business_rule_and_owner|persistent_transition_recheck|successful_role_and_workflow
hunt-cache-poison|TIME|poisoned_response_independent_reader|cache_reader_boundary|independent_cache_hit_content|poison_and_read_request_sequence
hunt-captcha-bypass|AUTH|protected_action_without_challenge|challenge_policy_and_result|protected_action_recheck|challenge_and_session_state
hunt-cicd|DIFF|cicd_protected_effect|project_policy_and_caller|pipeline_secret_or_action|pipeline_caller_role
hunt-clickjacking|BROWSER|framed_sensitive_action_activated|frame_origin_and_victim|sensitive_action_recheck|victim_interaction_and_session
hunt-cloud-misconfig|DIFF|cloud_resource_outside_policy|cloud_policy_and_principal|cloud_resource_or_control_effect|cloud_caller_principal
hunt-cors|AUTH|cross_origin_credentialed_read|reader_origin_and_resource_policy|browser_read_protected_response|credential_mode_and_reader_session
hunt-csrf|AUTH|cross_origin_state_change|request_origin_and_victim|persistent_victim_state_change|victim_session_and_interaction
hunt-deserialization|ERR|deserialization_error_or_control_effect|input_to_execution_boundary|execution_or_state_marker|deserialization_input_and_role
hunt-dispatch|DIFF|unintended_handler_selected|actual_vs_intended_handler|protected_handler_effect|dispatch_input_and_caller
hunt-dom|BROWSER|controlled_source_reaches_sink|source_to_sink_flow|security_relevant_sink_effect|source_delivery_and_browser_context
hunt-exceptional-conditions|DIFF|exceptional_input_security_effect|declared_protected_boundary|stable_security_effect|exceptional_input_prerequisites
hunt-file-upload|STATE|upload_forbidden_processing_state|artifact_owner_and_policy|upload_recheck_or_execution_marker|uploader_role_and_followup
hunt-fintech-graphql|ERR|financial_graphql_protected_effect|field_owner_and_role_policy|protected_field_or_mutation_recheck|graphql_caller_role
hunt-forgot-password|AUTH|account_change_without_proof|account_owner_and_proof_policy|account_state_after_recheck|actual_user_proof_and_session
hunt-graphql|ERR|graphql_field_or_operation_violation|field_policy_and_caller|protected_value_or_mutation_recheck|graphql_operation_and_role
hunt-grpc|ERR|grpc_protected_result_or_error|method_policy_and_metadata_role|protobuf_value_or_completed_effect|grpc_caller_metadata
hunt-host-header|DIFF|host_controls_security_destination|host_to_output_binding|security_url_or_handler_consumption|host_input_and_consumer
hunt-html-injection|BROWSER|marker_parsed_in_html_node|injection_origin_and_sink|html_node_or_attribute_context|delivery_and_browser_context
hunt-http-smuggling|TIME|paired_request_desynchronization|upstream_downstream_boundary|independent_followup_response_effect|paired_request_order_and_timing
hunt-idor|AUTH|cross_owner_object_access|caller_owner_object_binding|protected_object_read_or_change|successful_caller_role
hunt-jwt-crypto|AUTH|invalid_token_protected_action|token_policy_and_actual_principal|protected_action_with_invalid_token|token_hash_and_session_state
hunt-k8s|DIFF|k8s_protected_resource_effect|service_account_namespace_policy|secret_or_cluster_action|k8s_caller_principal
hunt-laravel|DIFF|laravel_protected_diagnostic|diagnostic_route_policy|protected_laravel_content|laravel_caller_role
hunt-ldap|ERR|ldap_error_or_result_change|directory_policy_and_caller|unauthorized_result_scope|ldap_input_and_role
hunt-lfi|ERR|controlled_local_file_marker|file_path_policy_and_caller|declared_test_file_contents|path_input_and_role
hunt-llm-ai|DIFF|model_crosses_declared_trust_boundary|prompt_trust_level_and_tool_policy|model_tool_or_data_access_trace|model_input_and_tool_permissions
hunt-mfa-bypass|AUTH|protected_action_before_mfa|mfa_policy_and_session|protected_action_recheck|mfa_completion_state
hunt-misc|DIFF|declared_security_effect|declared_protected_target|specific_protected_effect|declared_effect_prerequisites
hunt-nextjs|DIFF|nextjs_protected_server_effect|server_route_policy|server_data_or_protected_route|nextjs_caller_role
hunt-nodejs|DIFF|nodejs_protected_runtime_effect|runtime_route_policy|protected_function_or_execution|nodejs_caller_role
hunt-nosqli|ERR|nosql_error_or_result_change|store_policy_and_caller|unauthorized_result_scope|nosql_input_and_role
hunt-ntlm-info|OOB|ntlm_auth_event_at_callback|actual_auth_source_principal|ntlm_auth_protocol_event|caller_role_and_callback_setup
hunt-oauth|AUTH|oauth_binding_violation_accepted|oauth_policy_and_bound_account|protected_identity_or_action|oauth_code_state_pkce_prerequisites
hunt-open-redirect|DIFF|external_navigation_destination|allowed_destination_policy|location_or_final_url|redirect_input_and_interaction
hunt-race-condition|TIME|concurrency_forbidden_final_state|concurrent_actor_resource_policy|final_state_recheck|member_order_and_concurrency
hunt-rag-vector|DIFF|foreign_corpus_marker_returned|corpus_owner_and_caller|protected_document_retrieval|retrieval_identity_and_query
hunt-rce|ERR|isolated_command_execution_marker|input_to_command_boundary|unique_execution_nonce_effect|command_input_and_role
hunt-saml|AUTH|invalid_assertion_establishes_identity|assertion_policy_and_subject|established_protected_role|assertion_signature_conditions
hunt-session|AUTH|forbidden_old_session_reuse|session_boundary_event_and_principal|protected_action_with_old_session|old_new_session_hashes
hunt-shadow-api|DIFF|shadow_api_protected_effect|server_api_policy_and_caller|protected_data_or_action|shadow_api_caller_role
hunt-sharepoint|DIFF|sharepoint_protected_effect|site_item_owner_and_role|protected_item_or_action_recheck|sharepoint_caller_role
hunt-source-leak|ERR|source_map_or_secret_marker|source_access_policy_and_caller|protected_content_not_field_name|source_request_auth_state
hunt-spa-api|DIFF|backend_protected_api_effect|backend_policy_and_role|protected_backend_object_or_action|backend_caller_role
hunt-springboot|DIFF|springboot_protected_diagnostic|actuator_route_policy|protected_diagnostic_data_or_function|actuator_caller_role
hunt-sqli|ERR|sql_error_or_result_change|database_policy_and_caller|unauthorized_result_or_mutation|sql_input_and_role
hunt-ssrf|OOB|server_request_at_callback|actual_server_source_principal|callback_protocol_and_internal_effect|caller_role_and_callback_setup
hunt-ssti|ERR|template_expression_evaluated|template_input_to_engine_boundary|evaluation_nonce_output|template_input_and_role
hunt-subdomain|DIFF|dangling_service_host_control|dns_service_ownership_policy|service_claim_and_host_control|claim_prerequisites
hunt-tls-network|DIFF|protocol_transport_policy_weakness|tls_policy_and_peer|handshake_or_certificate_violation|client_protocol_conditions
hunt-websocket|STATE|websocket_forbidden_effect|session_role_and_target_owner|cross_role_read_or_state_recheck|websocket_session_and_frames
hunt-xss|BROWSER|marker_executes_in_target_origin|origin_and_victim_context|script_execution_nonce|delivery_interaction_and_auth
hunt-xxe|OOB|entity_resolution_callback_or_file|parser_input_to_server_boundary|entity_nonce_or_file_marker|xml_input_and_parser_setup
"""

_FAMILY_CHANNELS = {
    "AUTH": ("http", "authorization_boundary"),
    "ERR": ("http", "error_signature"),
    "DIFF": ("http", "response_diff"),
    "TIME": ("http", "timing"),
    "STATE": ("http", "state_change"),
    "BROWSER": ("browser", "dom_effect"),
    "OOB": ("oob", "oob_callback"),
}
_CHANNEL_OVERRIDES = {
    "hunt-file-upload": ("multipart", "state_change"),
    "hunt-grpc": ("grpc", "error_signature"),
    "hunt-race-condition": ("concurrent", "timing"),
    "hunt-websocket": ("websocket", "state_change"),
}
_MANUAL_REVIEW = frozenset({
    "hunt-exceptional-conditions", "hunt-llm-ai", "hunt-misc",
    "hunt-subdomain", "hunt-tls-network",
})


def _build_rules() -> dict[str, ProfileEvidenceRule]:
    rules: dict[str, ProfileEvidenceRule] = {}
    for line in _RULE_ROWS.strip().splitlines():
        name, family, target, boundary, sensitivity, actor = line.split("|")
        if name in rules:
            raise ValueError(f"duplicate profile evidence rule: {name}")
        runtime, signal = _CHANNEL_OVERRIDES.get(name, _FAMILY_CHANNELS[family])
        rules[name] = ProfileEvidenceRule(
            profile_id=name, family=family, runtime_kind=runtime,
            signal_type=signal, target_signal_kind=f"{name}_verified",
            target_fact=target, boundary_fact=boundary,
            sensitivity_fact=sensitivity, actor_fact=actor,
            manual_review=name in _MANUAL_REVIEW,
        )
    return rules


PROFILE_EVIDENCE_RULES = _build_rules()


def fit_profile_audit(audit: dict[str, Any]) -> dict[str, Any]:
    """Keep mandatory audit bindings while trimming optional receipts to 8 KiB."""
    document = deepcopy(audit)
    optional_lists = ("request_ids", "operation_ids", "reported_assertion_ids", "facts")
    while True:
        cleaned = sanitize_metadata(document, max_bytes=65_536)
        if len(canonical_json(cleaned).encode("utf-8")) <= 8192:
            return cleaned
        for key in optional_lists:
            if document.get(key):
                document[key].pop()
                if key == "facts":
                    document["facts_omitted_count"] += 1
                else:
                    document["provenance_truncated"] = True
                break
        else:
            raise ValueError("profile audit mandatory fields exceed evidence budget")


def validate_rule_coverage(resolver: SkillProfileResolver | None = None) -> tuple[str, ...]:
    """Fail when packaged contracts and semantic evidence rules diverge."""
    resolver = resolver or SkillProfileResolver()
    names = resolver.validate_coverage()
    if set(names) != set(PROFILE_EVIDENCE_RULES):
        raise ValueError("profile evidence rules do not cover the packaged catalog")
    if len({rule.target_fact for rule in PROFILE_EVIDENCE_RULES.values()}) != len(names):
        raise ValueError("profile evidence target facts must be unique")
    for name in names:
        profile = resolver.resolve(name).profile
        rule = PROFILE_EVIDENCE_RULES[name]
        if (rule.target_signal_kind != profile.target_expected_signal.kind
                or rule.runtime_kind != profile.runtime_kinds[0]
                or rule.signal_type != profile.signal_types[0]):
            raise ValueError(f"profile evidence channel differs from contract: {name}")
    return names


def evaluate_profile_evidence(
    profile: ValidationProfile, profile_sha256: str,
    assessment: BlindAssessment, observations: Iterable[dict[str, Any]],
    *, raw_axes: list[int] | None = None, runtime_contract: Any | None = None,
) -> dict[str, Any]:
    """Audit replay citations without treating unverified semantic facts as proof."""
    rule = PROFILE_EVIDENCE_RULES[profile.attack_skill_name]
    if (rule.target_signal_kind != profile.target_expected_signal.kind
            or rule.runtime_kind != profile.runtime_kinds[0]
            or rule.signal_type != profile.signal_types[0]):
        raise ValueError("profile evidence rule does not match the bound contract")
    replay = tuple(observations)
    target_attempt_ids = set(assessment.target_attempt_ids)
    control_attempt_ids = set(assessment.control_attempt_ids)
    target_replay = [item for item in replay
                     if item["attempt_kind"] == "target"
                     and item["attempt_id"] in target_attempt_ids]
    positive_replay = [item for item in replay
                       if item["attempt_kind"] == "positive_control"
                       and item["attempt_id"] in control_attempt_ids]
    negative_replay = [item for item in replay
                       if item["attempt_kind"] == "negative_control"
                       and item["attempt_id"] in control_attempt_ids]
    if (len(target_attempt_ids) not in {3, 5}
            or len(target_replay) != len(target_attempt_ids)
            or any(item["outcome"] != "observed" or item["signal_observed"] is not True
                   for item in target_replay)):
        replay_status = "target_inconsistent"
    elif (len(positive_replay) != 1
          or positive_replay[0]["outcome"] != "observed"
          or positive_replay[0]["signal_observed"] is not True):
        replay_status = "positive_control_failed"
    elif (len(negative_replay) != 1
          or negative_replay[0]["outcome"] != "not_observed"
          or negative_replay[0]["signal_observed"] is not False):
        replay_status = "negative_control_failed"
    else:
        replay_status = "complete"
    request_ids: set[str] = set()
    operation_ids: set[str] = set()
    assertion_ids: set[str] = set()
    for item in replay:
        details = item.get("details", {})
        if not isinstance(details, dict):
            continue
        for key, destination in (("request_ids", request_ids), ("operation_ids", operation_ids)):
            values = details.get(key, [])
            if isinstance(values, list):
                destination.update(value for value in values if isinstance(value, str))
        evaluation = details.get("evaluation", details)
        if isinstance(evaluation, dict) and isinstance(evaluation.get("assertions"), list):
            assertion_ids.update(
                result["assertion_id"] for result in evaluation["assertions"]
                if isinstance(result, dict) and isinstance(result.get("assertion_id"), str)
            )
    targets = {item["evidence_id"] for item in replay
               if item["attempt_kind"] == "target" and item["outcome"] == "observed"
               and item["signal_observed"] is True}
    negatives = {item["evidence_id"] for item in replay
                 if item["attempt_kind"] == "negative_control"
                 and item["outcome"] == "not_observed"
                 and item["signal_observed"] is False}
    extracted = (extract_replay_facts(
        rule.profile_id, runtime_contract, assessment, replay,
        replay_status=replay_status,
    ) if runtime_contract is not None else None)
    axes: dict[str, dict[str, Any]] = {}
    for axis_name, fact in (
        ("impact_boundary", rule.boundary_fact),
        ("impact_sensitivity", rule.sensitivity_fact),
        ("impact_actor_requirements", rule.actor_fact),
    ):
        axis = getattr(assessment, axis_name)
        citations = set(axis.evidence_ids)
        missing_citations = []
        if axis.score > 0 and not citations.intersection(targets):
            missing_citations.append("observed_target")
        if axis.score > 0 and axis_name == "impact_boundary" and not citations.intersection(negatives):
            missing_citations.append("inert_negative_control")
        status = ("not_claimed" if axis.score == 0 else
                  "replay_not_grounded" if replay_status != "complete" else
                  "missing_replay_citation" if missing_citations else
                  "needs_verified_fact")
        axes[axis_name] = {
            "score": axis.score,
            "status": status,
            "required_fact": fact,
            "missing_facts": [fact] if axis.score > 0 else [],
            "missing_citations": missing_citations,
            "cited_evidence_ids": sorted(citations.intersection(targets | negatives)),
        }
    return {
        "rule_version": RULE_VERSION,
        "mode": "audit",
        "profile_id": rule.profile_id,
        "profile_sha256": profile_sha256,
        "family": rule.family,
        "runtime_kind": rule.runtime_kind,
        "signal_type": rule.signal_type,
        "target_signal_kind": rule.target_signal_kind,
        "target_fact": rule.target_fact,
        "replay_status": replay_status,
        "target_signal_status": ("observed_semantics_unverified"
                                 if replay_status == "complete" else replay_status),
        "manual_review": rule.manual_review,
        "case_id": assessment.case_id,
        "blind_case_sha256": assessment.blind_case_sha256,
        "assessment_sha256": canonical_sha256(assessment.model_dump(mode="json")),
        "raw_axes": raw_axes or [assessment.impact_boundary.score,
                                  assessment.impact_sensitivity.score,
                                  assessment.impact_actor_requirements.score],
        "effective_axes": [assessment.impact_boundary.score,
                           assessment.impact_sensitivity.score,
                           assessment.impact_actor_requirements.score],
        "target_attempt_ids": sorted(item["attempt_id"] for item in replay
                                     if item["attempt_kind"] == "target"),
        "control_attempt_ids": sorted(item["attempt_id"] for item in replay
                                      if item["attempt_kind"] in {"positive_control", "negative_control"}),
        "observed_target_evidence_ids": sorted(targets),
        "inert_negative_evidence_ids": sorted(negatives),
        "request_ids": sorted(request_ids)[:16],
        "operation_ids": sorted(operation_ids)[:16],
        "reported_assertion_ids": sorted(assertion_ids)[:16],
        "provenance_truncated": any(len(values) > 16 for values in
                                    (request_ids, operation_ids, assertion_ids)),
        "facts": list(extracted.facts) if extracted is not None else [],
        "facts_omitted_count": extracted.omitted_count if extracted is not None else 0,
        "axes": axes,
    }
