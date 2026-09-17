"""Profile-aware minimum proof rules for target-supplied runtime contracts."""

from __future__ import annotations

from typing import Any, Iterable

from .browser_contract import BrowserRuntimeContract
from .models import canonical_json, canonical_sha256
from .oob_contract import OobRuntimeContract
from ..core.profiles import ValidationProfile
from .runtime_contract import HttpRuntimeContract


class RuntimeSemanticError(ValueError):
    """A valid runtime schema cannot prove the profile's declared signal."""


_HTTP_CONTENT_ASSERTIONS = frozenset({"header_equals", "body_contains", "json_equals"})
_HTTP_DURATION_ASSERTIONS = frozenset({
    "duration_at_least_ms", "duration_at_most_ms",
})


def _different(left: object, right: object, message: str) -> None:
    if canonical_sha256(left) == canonical_sha256(right):
        raise RuntimeSemanticError(message)


def _proof_assertions(
    assertions: Iterable[Any], kinds: frozenset[str],
) -> tuple[str, ...]:
    return tuple(sorted(
        canonical_json(item.model_dump(mode="json", exclude={"assertion_id"}))
        for item in assertions if item.kind in kinds
    ))


def _same_proof_assertions(
    target: Iterable[Any], negative: Iterable[Any], kinds: frozenset[str], message: str,
) -> None:
    if _proof_assertions(target, kinds) != _proof_assertions(negative, kinds):
        raise RuntimeSemanticError(message)


def validate_runtime_semantics(
    runtime: HttpRuntimeContract | BrowserRuntimeContract | OobRuntimeContract,
    profile: ValidationProfile,
) -> None:
    """Reject controls or assertions that cannot establish the profile signal."""

    if isinstance(runtime, HttpRuntimeContract):
        _different(
            runtime.target.request.model_dump(mode="json"),
            runtime.negative_control.request.model_dump(mode="json"),
            "HTTP target and inert negative control requests must differ",
        )
        assertion_kinds = {item.kind for item in runtime.target.assertions}
        if "timing" in profile.signal_types:
            if not assertion_kinds & _HTTP_DURATION_ASSERTIONS:
                raise RuntimeSemanticError(
                    "timing profiles require a target duration assertion"
                )
            proof_kinds = _HTTP_DURATION_ASSERTIONS
        elif not assertion_kinds & _HTTP_CONTENT_ASSERTIONS:
            raise RuntimeSemanticError(
                "HTTP target proof requires a header, body, or JSON assertion"
            )
        else:
            proof_kinds = _HTTP_CONTENT_ASSERTIONS
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            proof_kinds,
            "HTTP negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, BrowserRuntimeContract):
        _different(
            runtime.target.navigation.model_dump(mode="json"),
            runtime.negative_control.navigation.model_dump(mode="json"),
            "browser target and inert negative control navigations must differ",
        )
        assertion_kinds = {item.kind for item in runtime.target.assertions}
        if profile.attack_skill_name == "hunt-xss" and "console_contains" not in assertion_kinds:
            raise RuntimeSemanticError(
                "XSS target proof requires an execution marker in browser console observations"
            )
        proof_kinds = (
            frozenset({"console_contains"})
            if profile.attack_skill_name == "hunt-xss"
            else frozenset(assertion_kinds)
        )
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            proof_kinds,
            "browser negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, OobRuntimeContract):
        _different(
            runtime.target.trigger.model_dump(mode="json"),
            runtime.negative_control.trigger.model_dump(mode="json"),
            "OOB target and inert negative control triggers must differ",
        )
        target_criteria = (
            runtime.target.token_template, runtime.target.protocols,
            runtime.target.minimum_callbacks,
        )
        negative_criteria = (
            runtime.negative_control.token_template, runtime.negative_control.protocols,
            runtime.negative_control.minimum_callbacks,
        )
        if target_criteria != negative_criteria:
            raise RuntimeSemanticError(
                "OOB negative control must use the same callback proof criteria"
            )
        return

    raise RuntimeSemanticError("unsupported runtime contract for a Validation profile")
