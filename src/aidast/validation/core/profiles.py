"""Machine-readable Validation profiles bound to packaged Hunt Skills."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any, Literal

from pydantic import Field, model_validator

from aidast.attack.catalog import load_catalog

from ..contracts.models import Digest, Identifier, SignalType, StrictContract, canonical_json


class ValidationProfileError(ValueError):
    pass


RuntimeKind = Literal["http", "browser", "oob"]


class ProfileSignalCriterion(StrictContract):
    kind: Identifier
    criterion: str = Field(min_length=21, max_length=2_000)


class ProfileTargetSignal(ProfileSignalCriterion):
    requires_fresh_target_and_control_evidence: Literal[True]


class ProfileControl(StrictContract):
    payload_template: dict[str, Any] | list[Any] | str | int | float | bool | None
    expected_signal: ProfileSignalCriterion
    signal_type: SignalType | None = None


class ProfileImpactRules(StrictContract):
    boundary: str = Field(min_length=21, max_length=2_000)
    sensitivity: str = Field(min_length=21, max_length=2_000)
    actor_requirements: str = Field(min_length=21, max_length=2_000)


class DevelopmentAction(StrictContract):
    action_type: Identifier
    blocker_axis: Literal[
        "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
    ]


class ImpactExpansionPath(StrictContract):
    path_id: Identifier
    gap_axis: Literal["boundary", "sensitivity", "actor_requirements"]
    hypothesis_kind: Identifier
    required_preconditions: tuple[str, ...]
    expected_signal: dict[str, Any]
    recommended_actions: tuple[str, ...]
    execution_owner: Literal["validation", "chaining", "manual"]
    feasibility: Literal["low", "medium", "high"] = "medium"
    potential_impact: dict[str, Any] = Field(default_factory=dict)


class ValidationProfile(StrictContract):
    schema_version: Literal[1]
    attack_skill_name: Identifier
    signal_types: tuple[SignalType, ...] = Field(min_length=1, max_length=7)
    runtime_kinds: tuple[RuntimeKind, ...] = Field(min_length=1, max_length=3)
    target_expected_signal: ProfileTargetSignal
    control_positive: ProfileControl
    control_negative: ProfileControl
    baseline_samples: int | None = Field(default=None, ge=3, le=20)
    impact_rules: ProfileImpactRules
    allowed_development_actions: tuple[DevelopmentAction, ...] = Field(max_length=2)
    impact_expansion_paths: tuple[ImpactExpansionPath, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_profile(self) -> "ValidationProfile":
        if len(self.signal_types) != len(set(self.signal_types)):
            raise ValueError("profile signal types must be unique")
        if len(self.runtime_kinds) != len(set(self.runtime_kinds)):
            raise ValueError("profile runtime kinds must be unique")
        expected_runtime_kinds = set()
        for signal_type in self.signal_types:
            if signal_type == "dom_effect":
                expected_runtime_kinds.add("browser")
            elif signal_type == "oob_callback":
                expected_runtime_kinds.add("oob")
            else:
                expected_runtime_kinds.add("http")
        if set(self.runtime_kinds) != expected_runtime_kinds:
            raise ValueError("profile runtime kinds must match its signal types")
        if "timing" in self.signal_types and self.baseline_samples is None:
            raise ValueError("timing profiles require baseline_samples")
        if self.control_positive.signal_type not in {None, *self.signal_types}:
            raise ValueError("positive control signal must be allowed by the profile")
        primary_signal = self.signal_types[0]
        if self.control_positive.signal_type != primary_signal:
            raise ValueError("positive control must exercise the primary signal channel")
        if self.control_positive.expected_signal.kind != f"{primary_signal}_channel_operational":
            raise ValueError("positive control kind must identify the primary signal channel")
        if self.control_negative.expected_signal.kind != f"no_{primary_signal}_target_effect":
            raise ValueError("negative control kind must exclude the primary target effect")
        action_keys = [(item.action_type, item.blocker_axis) for item in self.allowed_development_actions]
        if len(action_keys) != len(set(action_keys)):
            raise ValueError("development actions must be unique")
        path_ids = [item.path_id for item in self.impact_expansion_paths]
        if len(path_ids) != len(set(path_ids)):
            raise ValueError("impact expansion path IDs must be unique")
        return self


class ResolvedValidationProfile(StrictContract):
    profile: ValidationProfile
    profile_sha256: Digest
    attack_skill_sha256: Digest
    validation_skill_sha256: Digest
    attack_skill_text: str
    validation_skill_text: str


class SkillProfileResolver:
    """Load a profile only when both packaged Skill digests still match."""

    def resolve(self, attack_skill_name: str) -> ResolvedValidationProfile:
        entries = {entry.skill_id: entry for entry in load_catalog() if entry.skill_id != "chain"}
        entry = entries.get(attack_skill_name)
        if entry is None:
            raise ValidationProfileError("Attack Skill is not a packaged Hunt Skill")
        root = files("aidast.skills")
        try:
            attack_text = root.joinpath("attack", entry.source_path).read_text(encoding="utf-8")
            validation_text = root.joinpath("validation", "BASE_SKILL.md").read_text(encoding="utf-8")
            profile_text = root.joinpath(
                "validation", "profiles", f"{attack_skill_name}.json"
            ).read_text(encoding="utf-8")
            raw = json.loads(profile_text)
            profile = ValidationProfile.model_validate_json(profile_text)
        except (OSError, ValueError, TypeError) as exc:
            raise ValidationProfileError("Validation profile is missing or invalid") from exc
        attack_digest = hashlib.sha256(attack_text.encode("utf-8")).hexdigest()
        if attack_digest != entry.source_sha256:
            raise ValidationProfileError("packaged Attack Skill digest mismatch")
        if profile.attack_skill_name != attack_skill_name:
            raise ValidationProfileError("Validation profile is bound to another Attack Skill")
        return ResolvedValidationProfile(
            profile=profile,
            profile_sha256=hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest(),
            attack_skill_sha256=attack_digest,
            validation_skill_sha256=hashlib.sha256(validation_text.encode("utf-8")).hexdigest(),
            attack_skill_text=attack_text,
            validation_skill_text=validation_text,
        )

    def validate_coverage(self) -> tuple[str, ...]:
        names = tuple(entry.skill_id for entry in load_catalog() if entry.skill_id != "chain")
        for name in names:
            self.resolve(name)
        return names
