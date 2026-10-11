"""Profile-aware minimum proof rules for target-supplied runtime contracts."""

from __future__ import annotations

from typing import Any, Iterable

from .browser_contract import BrowserRuntimeContract
from .models import BlindAssessment
from .multipart_contract import MultipartRuntimeContract
from .oob_contract import OobRuntimeContract
from .websocket_contract import WebSocketRuntimeContract
from .grpc_contract import GrpcRuntimeContract
from .concurrent_contract import ConcurrentRuntimeContract
from ..core.profiles import ValidationProfile
from .runtime_contract import HttpRuntimeContract


class RuntimeSemanticError(ValueError):
    """A valid runtime schema cannot prove the profile's declared signal."""


_HTTP_CONTENT_ASSERTIONS = frozenset({
    "header_equals", "body_contains", "json_equals", "json_path_nonempty_string",
})
_HTTP_DURATION_ASSERTIONS = frozenset({
    "duration_at_least_ms", "duration_at_most_ms",
})
_PROFILE_HTTP_PROOF_ASSERTIONS = {
    "hunt-source-leak_verified": frozenset({
        ("body_contains", '"password":'),
        ("body_contains", '"sourcesContent":'),
        ("body_contains", '"openapi":'),
        ("body_contains", '"swagger":'),
        ("body_contains", "DB_PASSWORD="),
        ("body_contains", "API_KEY="),
        ("body_contains", "ref: refs/heads/"),
    }),
}


def bound_profile_proof_assessment(
    profile: ValidationProfile,
    runtime: HttpRuntimeContract | dict[str, Any] | None,
    assessment: BlindAssessment,
) -> tuple[BlindAssessment, str | None]:
    """Keep a credential field name from being scored as disclosed data."""
    if profile.target_expected_signal.kind != "hunt-source-leak_verified":
        return assessment, None
    if isinstance(runtime, dict):
        if runtime.get("runtime_kind", "http") != "http":
            return assessment, None
        runtime = HttpRuntimeContract.model_validate(runtime)
    if not isinstance(runtime, HttpRuntimeContract):
        return assessment, None
    content = [
        item for item in runtime.target.assertions
        if item.kind in _HTTP_CONTENT_ASSERTIONS
    ]
    if not any(item.kind == "body_contains" and item.expected == '"password":'
               for item in content):
        return assessment, None
    rule = "source_leak_field_name_only"
    if assessment.impact_sensitivity.score == 0:
        return assessment, rule
    sensitivity = assessment.impact_sensitivity.model_copy(update={
        "score": 0,
        "reason": "Only a credential field name was established; no sensitive value was observed before Impact Development.",
    })
    return assessment.model_copy(update={"impact_sensitivity": sensitivity}), rule


def bound_source_leak_axis_citations(
    profile: ValidationProfile,
    assessment: BlindAssessment,
    observations: Iterable[dict[str, Any]],
) -> tuple[BlindAssessment, tuple[str, ...]]:
    """Require direct replay citations before crediting source-leak Blind axes."""
    if profile.target_expected_signal.kind != "hunt-source-leak_verified":
        return assessment, ()
    replay = tuple(observations)
    observed_targets = {
        item["evidence_id"] for item in replay
        if item["attempt_kind"] == "target"
        and item["outcome"] == "observed"
        and item["signal_observed"] is True
    }
    updates: dict[str, Any] = {}
    rules: list[str] = []
    for name in ("impact_boundary", "impact_sensitivity", "impact_actor_requirements"):
        axis = getattr(assessment, name)
        if axis.score == 0:
            continue
        missing = []
        if not observed_targets.intersection(axis.evidence_ids):
            missing.append(f"{name}_missing_observed_target")
        if missing:
            rules.extend(missing)
            updates[name] = axis.model_copy(update={
                "score": 0,
                "reason": "The cited replay evidence does not support this positive impact axis.",
            })
    if not updates:
        return assessment, ()
    return assessment.model_copy(update=updates), tuple(rules)


def validate_runtime_semantics(
    runtime: HttpRuntimeContract | BrowserRuntimeContract | OobRuntimeContract | MultipartRuntimeContract | WebSocketRuntimeContract | GrpcRuntimeContract | ConcurrentRuntimeContract,
    profile: ValidationProfile,
) -> None:
    """Require a bounded target assertion that can establish the profile signal."""
    if isinstance(runtime, HttpRuntimeContract):
        kinds = {item.kind for item in runtime.target.assertions}
        if "timing" in profile.signal_types:
            if not kinds & _HTTP_DURATION_ASSERTIONS:
                raise RuntimeSemanticError("timing profiles require a target duration assertion")
        elif not kinds & _HTTP_CONTENT_ASSERTIONS:
            raise RuntimeSemanticError("HTTP target proof requires a header, body, or JSON assertion")
        required = _PROFILE_HTTP_PROOF_ASSERTIONS.get(profile.target_expected_signal.kind)
        if required is not None and not any(
            (item.kind, item.expected) in required for item in runtime.target.assertions
        ):
            raise RuntimeSemanticError(
                "HTTP source-leak proof requires a declared source, map, or credential marker"
            )
        return

    if isinstance(runtime, BrowserRuntimeContract):
        kinds = {item.kind for item in runtime.target.assertions}
        if profile.attack_skill_name == "hunt-xss" and "console_contains" not in kinds:
            raise RuntimeSemanticError(
                "XSS target proof requires an execution marker in browser console observations"
            )
        return

    if isinstance(runtime, MultipartRuntimeContract):
        kinds = {item.kind for item in runtime.target.assertions}
        if "timing" in profile.signal_types:
            if not kinds & _HTTP_DURATION_ASSERTIONS:
                raise RuntimeSemanticError("multipart timing profiles require a target duration assertion")
        elif not kinds & _HTTP_CONTENT_ASSERTIONS:
            raise RuntimeSemanticError("multipart target proof requires a header, body, or JSON assertion")
        return

    if isinstance(runtime, WebSocketRuntimeContract):
        return

    if isinstance(runtime, GrpcRuntimeContract):
        if not any(item.kind != "grpc_status_equals" for item in runtime.target.assertions):
            raise RuntimeSemanticError("gRPC target proof requires a message, trailer, error, or timing assertion")
        return

    if isinstance(runtime, ConcurrentRuntimeContract):
        if "timing" in profile.signal_types and not (
            {item.kind for item in runtime.target.member_assertions} & _HTTP_DURATION_ASSERTIONS
            or runtime.target.start_skew_at_most_ms is not None
        ):
            raise RuntimeSemanticError(
                "concurrent timing profiles require a duration or start skew assertion"
            )
        if "state_change" in profile.signal_types and not (
            any(item.kind in {"success_count_equals", "success_count_at_least"}
                for item in runtime.target.aggregate_assertions)
            or runtime.target.final_verification is not None
        ):
            raise RuntimeSemanticError(
                "concurrent state-change profiles require aggregate success or final-state assertion"
            )
        return

    if isinstance(runtime, OobRuntimeContract):
        return

    raise RuntimeSemanticError("unsupported runtime contract for a Validation profile")
