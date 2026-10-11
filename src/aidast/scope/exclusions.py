"""Frozen contracts for grounded exclusions and offline resource classifications.

Evidence byte provenance and citation associations are verified by the producing
resolver; these models validate bounded structure, never infer semantic truth.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aidast.core.exclusion_guard import (
    _headers,
    _url,
    validate_exclusion_expression,
    validate_exclusion_policy,
    validate_exclusion_predicate,
    validate_scope_exclusion,
)


Identifier = Annotated[str, Field(pattern=r'^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$')]
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Text = Annotated[str, Field(min_length=1, max_length=4096)]
Classification = Literal['match', 'nonmatch', 'unknown']


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class ExclusionPredicate(FrozenModel):
    key: Identifier
    field: Literal['host', 'path', 'method', 'query', 'json_body', 'form_body', 'semantic', 'unsupported']
    operator: Literal['equals', 'prefix', 'present']
    name: str | None = Field(default=None, max_length=512)
    value: str | None = Field(default=None, max_length=4096)

    @model_validator(mode='after')
    def validate_contract(self):
        validate_exclusion_predicate(self.model_dump())
        return self


class ExclusionExpression(FrozenModel):
    operator: Literal['predicate', 'all', 'any', 'not']
    predicate: ExclusionPredicate | None = None
    children: list[ExclusionExpression] = Field(default_factory=list, max_length=128)

    @model_validator(mode='after')
    def validate_contract(self):
        validate_exclusion_expression(self.model_dump())
        return self


class ScopeExclusion(FrozenModel):
    key: Identifier
    label: str = Field(min_length=1, max_length=160)
    source_quote: str = Field(min_length=1, max_length=16000)
    target_assets: list[Text] = Field(default_factory=list, max_length=512)
    condition: ExclusionExpression

    @model_validator(mode='after')
    def validate_contract(self):
        validate_scope_exclusion(self.model_dump())
        return self


class ResourceCandidate(FrozenModel):
    candidate_id: Identifier
    request_key: Digest
    url: str = Field(min_length=1, max_length=16384)
    method: str = Field(min_length=1, max_length=32)
    public_headers: dict[str, str] = Field(default_factory=dict, max_length=256)
    body_sha256: Digest
    body_preview: str | None = Field(default=None, max_length=8192)
    evidence_ids: list[Identifier] = Field(default_factory=list, max_length=64)

    @model_validator(mode='after')
    def validate_request_descriptor(self):
        from aidast.core.exclusion_guard import _method
        _url(self.url)
        if _method(self.method) != self.method:
            raise ValueError('candidate method must be canonical uppercase')
        _headers(self.public_headers)
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError('duplicate evidence IDs')
        return self


class ResourceEvidence(FrozenModel):
    evidence_id: Identifier
    candidate_ids: list[Identifier] = Field(min_length=1, max_length=256)
    source_url: str = Field(min_length=1, max_length=16384)
    kind: Literal['html', 'javascript', 'api', 'captured_response']
    content_sha256: Digest
    excerpt: str = Field(min_length=1, max_length=16000)
    captured_at: float | None = Field(default=None, gt=0, allow_inf_nan=False, strict=True)

    @model_validator(mode='after')
    def validate_association(self):
        _url(self.source_url)
        if len(set(self.candidate_ids)) != len(self.candidate_ids):
            raise ValueError('duplicate candidate IDs')
        return self


class ResourceCitation(FrozenModel):
    evidence_id: Identifier
    quote: str = Field(min_length=1, max_length=16000)

    @field_validator('quote')
    @classmethod
    def nonempty_quote(cls, value):
        if not value.strip():
            raise ValueError('citation quote cannot be blank')
        return value


class ResourceDecision(FrozenModel):
    candidate_id: Identifier
    rule_key: Identifier
    predicate_key: Identifier
    classification: Classification
    reason: str = Field(min_length=1, max_length=2048)
    citations: list[ResourceCitation] = Field(default_factory=list, max_length=64)

    @model_validator(mode='after')
    def require_affirmative_evidence(self):
        if not self.reason.strip():
            raise ValueError('classification needs a reason')
        if self.classification != 'unknown' and not self.citations:
            raise ValueError('match/nonmatch require affirmative evidence citations')
        return self


class ResourceClassification(FrozenModel):
    decisions: list[ResourceDecision] = Field(max_length=16384)

    @model_validator(mode='after')
    def unique_decisions(self):
        keys = [(d.candidate_id, d.rule_key, d.predicate_key) for d in self.decisions]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate resource classification decisions')
        return self


class SemanticBinding(FrozenModel):
    request_key: Digest
    rule_key: Identifier
    predicate_key: Identifier
    classification: Classification
    evidence_ids: list[Identifier] = Field(default_factory=list, max_length=64)


class CompiledExclusionPolicy(FrozenModel):
    schema_version: Literal['1'] = '1'
    scope_digest: Digest
    rule_digest: Digest
    evidence_digest: Digest
    target_asset: Text
    rules: list[ScopeExclusion] = Field(max_length=128)
    semantic_bindings: list[SemanticBinding] = Field(default_factory=list, max_length=16384)
    expires_at: float | None = Field(default=None, gt=0, allow_inf_nan=False, strict=True)

    @model_validator(mode='after')
    def validate_contract(self):
        validate_exclusion_policy(self.model_dump(mode='json'))
        return self
