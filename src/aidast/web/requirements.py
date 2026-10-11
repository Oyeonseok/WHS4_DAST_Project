"""AI-declared operational header requirements exposed to the local scan form."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from aidast.recon.profiles import EXECUTION_PROFILES, ProfileCaps, ProfileId, grounded_scope_request_rate, profile_request_rate
from aidast.scope.execution_rules import execution_interpretation_complete
from aidast.scope.models import ScopeAnalysis, RequiredRequestHeader, HeaderInput, ScopeExecutionRules, PolicyInput, PolicyConfirmation, BlockingRequirement

IdentityHeader = Literal['hackerone', 'intigriti']

class ExecutionProfileRequirement(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    id: ProfileId
    limits: ProfileCaps

class RequiredHeader(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    name: str
    input_field: str

class ScopeExecutionRequirements(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    execution_requirements_status: Literal['ready', 'pending']
    execution_rules: ScopeExecutionRules | None = None
    policy_inputs: tuple[PolicyInput, ...] = ()
    policy_confirmations: tuple[PolicyConfirmation, ...] = ()
    policy_blockers: tuple[BlockingRequirement, ...] = ()
    header_requirements_status: Literal['ready', 'pending']
    required_headers: tuple[RequiredRequestHeader, ...]
    header_inputs: tuple[HeaderInput, ...]
    scope_max_requests_per_second: float | None = Field(default=None, gt=0)
    required_header: RequiredHeader | None
    operational_constraints: tuple[str, ...]
    profiles: tuple[ExecutionProfileRequirement, ...]


def build_scope_execution_requirements(analysis: ScopeAnalysis, *, identity_header: IdentityHeader | None = None) -> ScopeExecutionRequirements:
    analysis = ScopeAnalysis.model_validate(analysis.model_dump())
    scope_rate = grounded_scope_request_rate(analysis)
    headers = tuple(analysis.required_request_headers or [])
    inputs = {item.key: item for spec in headers for item in spec.inputs}
    first = next((spec for spec in headers if spec.inputs), None)
    rules = analysis.execution_rules
    ready = execution_interpretation_complete(analysis)
    profiles = []
    for profile_id, limits in EXECUTION_PROFILES.items():
        data = limits.model_dump()
        data['requests_per_second'] = profile_request_rate(profile_id, scope_rate)
        for option in rules.option_limits if rules else []:
            if option.field in data:
                data[option.field] = min(data[option.field], option.value)
        profiles.append(ExecutionProfileRequirement(id=profile_id, limits=ProfileCaps.model_validate(data)))
    return ScopeExecutionRequirements(
        execution_requirements_status='ready' if ready else 'pending',
        execution_rules=rules,
        policy_inputs=tuple(rules.required_inputs) if rules else (),
        policy_confirmations=tuple(rules.required_confirmations) if rules else (),
        policy_blockers=tuple(rules.blocking_requirements) if rules else (),
        header_requirements_status='ready' if ready else 'pending',
        required_headers=headers, header_inputs=tuple(inputs.values()),
        scope_max_requests_per_second=scope_rate,
        required_header=RequiredHeader(name=first.name, input_field=first.inputs[0].key) if first else None,
        operational_constraints=tuple(analysis.operational_constraints),
        profiles=tuple(profiles),
    )
