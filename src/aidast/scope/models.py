"""Structured contracts for scope collection and approval."""

from __future__ import annotations

import hashlib
import re
from string import Formatter
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urldefrag, urlsplit

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from aidast.scope.exclusions import ScopeExclusion


def _reject_blank(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must not be blank")
    return value


NonEmptyText = Annotated[
    str, BeforeValidator(_reject_blank), Field(min_length=1)
]
Sha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
MAX_EXTRACTED_BLOCKERS = 64
MAX_EXTRACTED_ADVISORIES = 64
MAX_POLICY_REFERENCE_EDGES = 112


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetType(StrEnum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    WILDCARD = "WILDCARD"
    CIDR = "CIDR"
    IP_ADDRESS = "IP_ADDRESS"
    API = "API"
    MOBILE_APP = "MOBILE_APP"
    SOURCE_CODE = "SOURCE_CODE"
    OTHER = "OTHER"


class CaptureStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"


class CaptureReason(StrEnum):
    NONE = "NONE"
    JAVASCRIPT_RENDER_INCOMPLETE = "JAVASCRIPT_RENDER_INCOMPLETE"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    BOT_CHALLENGE = "BOT_CHALLENGE"
    ACCESS_DENIED = "ACCESS_DENIED"
    CONTENT_INCOMPLETE = "CONTENT_INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class ScopeNavigationDecision(StrictModel):
    """One bounded choice among controls already observed on the program page."""

    action: Literal["capture", "open"]
    candidate_id: int | None

    @model_validator(mode="after")
    def check_candidate(self) -> ScopeNavigationDecision:
        if (self.action == "open") != (self.candidate_id is not None):
            raise ValueError("open requires a candidate_id; capture requires null")
        if self.candidate_id is not None and self.candidate_id < 0:
            raise ValueError("candidate_id must be non-negative")
        return self


class ScopeAsset(StrictModel):
    asset_type: AssetType
    asset: NonEmptyText
    description: str
    eligibility: str
    maximum_severity: str


class SourceEvidence(StrictModel):
    section: NonEmptyText
    quote: NonEmptyText


class HeaderInput(StrictModel):
    key: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    label: NonEmptyText = Field(max_length=160)
    kind: Literal["text", "username", "email"]


class RequiredRequestHeader(StrictModel):
    name: str
    value_template: NonEmptyText = Field(max_length=1024)
    inputs: list[HeaderInput] = Field(max_length=16)
    source_quote: NonEmptyText = Field(max_length=16000)

    @model_validator(mode="after")
    def validate_specification(self) -> RequiredRequestHeader:
        from aidast.core.http_safety import validate_identity_header_name, validate_identity_header_value
        validate_identity_header_name(self.name)
        source_tokens = re.findall(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", self.source_quote)
        if self.name.casefold() not in {token.casefold() for token in source_tokens}:
            raise ValueError("required header name must appear as an exact HTTP token in its source quote")
        validate_identity_header_value(self.value_template)
        declared = {item.key for item in self.inputs}
        if len(declared) != len(self.inputs):
            raise ValueError("duplicate header input keys")
        syntax_remainder = re.sub(r"\{\{|\}\}|\{[A-Za-z_][A-Za-z0-9_]*\}", "", self.value_template)
        if "{" in syntax_remainder or "}" in syntax_remainder:
            raise ValueError("templates permit only simple {key} fields and escaped braces")
        fields = set()
        for _, field, format_spec, conversion in Formatter().parse(self.value_template):
            if field is not None:
                if field not in declared or format_spec or conversion is not None:
                    raise ValueError("templates permit only declared simple input fields")
                fields.add(field)
        if fields != declared:
            raise ValueError("all declared header inputs must be used in the template")
        return self


class ScopeHeaderRequirements(StrictModel):
    required_request_headers: list[RequiredRequestHeader] = Field(max_length=32)


class RequestLimit(StrictModel):
    maximum: int = Field(strict=True, gt=0, le=100_000_000)
    period_seconds: float | None = Field(default=None, gt=0, le=315360000, allow_inf_nan=False, strict=True)
    scope: Literal['scan', 'program', 'target']
    source_quote: NonEmptyText = Field(max_length=16000)


class OptionLimit(StrictModel):
    field: Literal['concurrency', 'timeout_seconds', 'max_depth', 'max_requests', 'max_scan_seconds',
                   'playwright_interaction', 'form_submission', 'katana_headless', 'ffuf_enabled',
                   'ffuf_recursion', 'mitm_capture_bodies']
    value: int | float | bool
    source_quote: NonEmptyText = Field(max_length=16000)

    @field_validator('value', mode='before')
    @classmethod
    def strict_value(cls, value):
        if type(value) not in (int, float, bool):
            raise ValueError('option limit must be a numeric or boolean value')
        return value

    @model_validator(mode='after')
    def validate_value(self):
        bounds = {'concurrency': (1,20), 'timeout_seconds': (1,120), 'max_depth': (0,10),
                  'max_requests': (1,100000), 'max_scan_seconds': (1,86400)}
        if self.field in bounds:
            low, high = bounds[self.field]
            if type(self.value) not in (int, float) or not low <= self.value <= high:
                raise ValueError('invalid numeric option limit')
            if self.field != 'max_scan_seconds' and int(self.value) != self.value:
                raise ValueError('option limit requires an integer')
        elif type(self.value) is not bool:
            raise ValueError('tool option restriction requires a boolean')
        return self


class QuotedValues(StrictModel):
    values: list[NonEmptyText] = Field(min_length=1, max_length=512)
    source_quote: NonEmptyText = Field(max_length=16000)

    @field_validator('values')
    @classmethod
    def unique_values(cls, value):
        if len(set(value)) != len(value):
            raise ValueError('duplicate permission values')
        return value


class PolicyInput(HeaderInput):
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=64)
    target_assets: list[NonEmptyText] = Field(default_factory=list, max_length=512)
    source_quote: NonEmptyText = Field(max_length=16000)

    @model_validator(mode='after')
    def validate_domains(self):
        if self.allowed_email_domains and self.kind != 'email':
            raise ValueError('email domains require an email input')
        if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', d)
               for d in self.allowed_email_domains):
            raise ValueError('invalid email domain')
        return self


class PolicyConfirmation(StrictModel):
    key: str = Field(pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
    label: NonEmptyText = Field(max_length=160)
    target_assets: list[NonEmptyText] = Field(default_factory=list, max_length=512)
    source_quote: NonEmptyText = Field(max_length=16000)


class BlockingRequirement(StrictModel):
    target_assets: list[NonEmptyText] = Field(default_factory=list, max_length=512)
    label: NonEmptyText = Field(max_length=160)
    source_quote: NonEmptyText = Field(max_length=16000)
    reason: NonEmptyText = Field(max_length=2048)


class PolicyAdvisory(BlockingRequirement):
    guidance: NonEmptyText = Field(max_length=2048)


class ScopeExecutionRules(StrictModel):
    policy_review_version: Literal[1, 2, 3] = 1
    advisories: list[PolicyAdvisory] = Field(
        default_factory=list, max_length=MAX_EXTRACTED_ADVISORIES + MAX_POLICY_REFERENCE_EDGES)
    exclusions: list[ScopeExclusion] | None = Field(default=None, max_length=128)
    request_limits: list[RequestLimit] = Field(default_factory=list, max_length=64)
    option_limits: list[OptionLimit] = Field(default_factory=list, max_length=32)
    allowed_methods: QuotedValues | None = None
    allowed_target_assets: QuotedValues | None = None
    required_inputs: list[PolicyInput] = Field(default_factory=list, max_length=64)
    required_confirmations: list[PolicyConfirmation] = Field(default_factory=list, max_length=64)
    # Retain historical blocker capacity so immutable legacy documents still load.
    blocking_requirements: list[BlockingRequirement] = Field(
        default_factory=list, max_length=MAX_EXTRACTED_BLOCKERS + MAX_POLICY_REFERENCE_EDGES)

    def quoted_requirements(self):
        return [*self.request_limits, *self.option_limits, *self.required_inputs,
                *self.required_confirmations, *self.blocking_requirements, *self.advisories,
                *([self.allowed_methods] if self.allowed_methods else []),
                *([self.allowed_target_assets] if self.allowed_target_assets else []),
                *(self.exclusions or [])]

    @model_validator(mode='after')
    def validate_duplicates(self):
        for values, attribute in [(self.option_limits, 'field'), (self.required_inputs, 'key'),
                                  (self.required_confirmations, 'key'), (self.exclusions or [], 'key')]:
            keys = [getattr(v, attribute) for v in values]
            if len(keys) != len(set(keys)):
                raise ValueError('duplicate execution rule declarations')
        if self.allowed_methods and not set(self.allowed_methods.values) <= {'GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'}:
            raise ValueError('unsupported allowed method')
        return self


class ScopeExecutionInterpretation(StrictModel):
    required_request_headers: list[RequiredRequestHeader] = Field(max_length=32)
    execution_rules: ScopeExecutionRules


class ScopeAnalysis(StrictModel):
    execution_rules: ScopeExecutionRules | None = None
    required_request_headers: list[RequiredRequestHeader] | None = Field(default=None, max_length=32)
    program_name: NonEmptyText
    program_description: str
    in_scope_assets: list[ScopeAsset]
    out_of_scope_assets: list[ScopeAsset]
    allowed_activities: list[str]
    prohibited_activities: list[str]
    submission_requirements: list[str]
    operational_constraints: list[str]
    safe_harbor: str
    ambiguities: list[str]
    source_evidence: Annotated[list[SourceEvidence], Field(min_length=1)]

    @field_validator(
        "allowed_activities",
        "prohibited_activities",
        "submission_requirements",
        "operational_constraints",
        "ambiguities",
    )
    @classmethod
    def reject_blank_list_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("list items must not be blank")
        return values

    @model_validator(mode="after")
    def require_scope_or_explanation(self) -> ScopeAnalysis:
        if not self.in_scope_assets and not self.ambiguities:
            raise ValueError("missing in-scope assets must be explained in ambiguities")
        if self.required_request_headers is not None:
            names = set()
            inputs = {}
            for header in self.required_request_headers:
                if header.name.casefold() in names:
                    raise ValueError("duplicate required header names")
                names.add(header.name.casefold())
                if not any(header.source_quote in item.quote for item in self.source_evidence):
                    raise ValueError("required header source quote must be grounded in source evidence")
                for item in header.inputs:
                    if item.key in inputs and inputs[item.key] != item:
                        raise ValueError("conflicting shared header input declarations")
                    inputs[item.key] = item
        if self.execution_rules is not None:
            header_inputs = {i.key: i for h in self.required_request_headers or [] for i in h.inputs}
            for item in self.execution_rules.required_inputs:
                if item.key in header_inputs:
                    other = header_inputs[item.key]
                    if item.kind != other.kind or item.label != other.label:
                        raise ValueError('conflicting shared header and policy input declarations')
            assets = {item.asset for item in self.in_scope_assets}
            for item in self.execution_rules.quoted_requirements():
                if not any(item.source_quote in evidence.quote for evidence in self.source_evidence):
                    raise ValueError('execution rule source quote must be grounded in source evidence')
                if not set(getattr(item, 'target_assets', [])) <= assets:
                    raise ValueError('execution requirement target must be an exact approved asset')
            allowed = self.execution_rules.allowed_target_assets
            if allowed is not None and not set(allowed.values) <= assets:
                raise ValueError('allowed targets must be exact approved assets')
        return self


class ObservedPolicyLink(StrictModel):
    """A browser/HTML-observed link, never a model-invented destination."""
    candidate_id: int = Field(strict=True, ge=0)
    url: NonEmptyText = Field(max_length=4096)
    label: str = Field(max_length=512)
    source_url: NonEmptyText = Field(max_length=4096)


class PrimaryPolicyView(StrictModel):
    """One bounded primary DOM capture; its text cannot add primary authority."""
    url: NonEmptyText = Field(max_length=4096)
    text: NonEmptyText = Field(max_length=120000)
    observed_links: list[ObservedPolicyLink] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def validate_observations(self):
        ids = [link.candidate_id for link in self.observed_links]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate primary view candidate IDs")
        if any(link.source_url != self.url for link in self.observed_links):
            raise ValueError("observed link source must match its primary view URL")
        return self


def _validate_primary_views(views, observed_links, text, final_url):
    if views and observed_links:
        raise ValueError("primary views and legacy flat observations cannot be combined")
    host = (urlsplit(str(final_url)).hostname or "").lower().removeprefix("www.")
    for view in views:
        if view.text not in text:
            raise ValueError("primary view text must occur verbatim in original capture")
        parts = urlsplit(view.url)
        if (parts.scheme != "https" or parts.username is not None or parts.password is not None
                or (parts.hostname or "").lower().removeprefix("www.") != host):
            raise ValueError("primary view URL must belong to the captured program host")


PolicyApplicability = Literal["testing", "reporting", "disclosure", "mixed", "unknown"]


class PolicyReferenceChoice(StrictModel):
    candidate_id: int = Field(strict=True, ge=0)
    source_quote: NonEmptyText = Field(max_length=16000)
    applicability: PolicyApplicability
    relationship: Literal["required", "supporting", "uncertain"] = "uncertain"


class PolicyReferenceSelection(StrictModel):
    selections: list[PolicyReferenceChoice] = Field(max_length=8)


class PolicyReferenceCapture(StrictModel):
    candidate_id: int = Field(strict=True, ge=0)
    primary_view_index: int | None = Field(default=None, strict=True, ge=0, le=5)
    parent_url: NonEmptyText = Field(max_length=4096)
    source_quote: NonEmptyText = Field(max_length=16000)
    applicability: PolicyApplicability
    relationship: Literal["required", "supporting", "uncertain"] = "uncertain"
    depth: int = Field(ge=1, le=3)
    requested_url: NonEmptyText = Field(max_length=4096)
    final_url: str | None = Field(default=None, max_length=4096)
    captured_at: AwareDatetime
    status: Literal["captured", "unresolved"]
    text: str = Field(default="", max_length=120000)
    content_sha256: Sha256Digest | None = None
    error: str | None = Field(default=None, max_length=512)
    observed_links: list[ObservedPolicyLink] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def validate_capture(self):
        if self.status == "captured":
            if not self.text.strip() or not self.final_url or self.error:
                raise ValueError("captured reference requires readable text and final URL")
            if self.content_sha256 != hashlib.sha256(self.text.encode("utf-8")).hexdigest():
                raise ValueError("reference content digest does not match text")
        elif self.text or self.content_sha256 or not self.error:
            raise ValueError("unresolved reference requires error without captured text")
        return self


class ScopeCollectionResult(StrictModel):
    observed_links: list[ObservedPolicyLink] = Field(default_factory=list, max_length=128)
    primary_views: list[PrimaryPolicyView] = Field(default_factory=list, max_length=6)
    final_url: NonEmptyText
    title: str
    capture_status: CaptureStatus
    capture_reason: CaptureReason
    captured_text: NonEmptyText
    analysis: ScopeAnalysis

    @model_validator(mode="after")
    def validate_capture_completeness(self) -> ScopeCollectionResult:
        _validate_primary_views(self.primary_views, self.observed_links, self.captured_text, self.final_url)
        if self.capture_status is CaptureStatus.COMPLETE:
            if self.capture_reason is not CaptureReason.NONE:
                raise ValueError("complete capture must use reason NONE")
            if not self.analysis.program_description.strip():
                raise ValueError("complete capture requires a program description")
            if not self.analysis.in_scope_assets:
                raise ValueError("complete capture requires explicit in-scope assets")
            if not (
                self.analysis.out_of_scope_assets
                or self.analysis.prohibited_activities
                or self.analysis.operational_constraints
            ):
                raise ValueError(
                    "complete capture requires rules, exclusions, or constraints"
                )
        elif self.capture_reason is CaptureReason.NONE:
            raise ValueError("incomplete capture requires a non-NONE reason")
        return self


class ProgramPage(StrictModel):
    observed_links: list[ObservedPolicyLink] = Field(default_factory=list, max_length=128)
    primary_views: list[PrimaryPolicyView] = Field(default_factory=list, max_length=6)
    policy_references: list[PolicyReferenceCapture] = Field(default_factory=list, max_length=MAX_POLICY_REFERENCE_EDGES)
    requested_url: HttpUrl
    final_url: HttpUrl
    title: str
    captured_at: AwareDatetime
    capture_status: CaptureStatus
    capture_reason: CaptureReason
    content_sha256: Sha256Digest
    text: NonEmptyText

    @property
    def evidence_text(self) -> str:
        """Original capture plus attributed reference bodies; never asset authority."""
        parts = [self.text]
        included = set()
        for reference in self.policy_references:
            identity = (urldefrag(reference.final_url or "")[0], reference.content_sha256)
            if reference.status == "captured" and identity not in included:
                included.add(identity)
                parts.append(f"=== REFERENCED POLICY: {reference.final_url} ===\n{reference.text}")
        return "\n\n".join(parts)

    @model_validator(mode="after")
    def verify_content_digest(self) -> ProgramPage:
        _validate_primary_views(self.primary_views, self.observed_links, self.text, self.final_url)
        for reference in self.policy_references:
            index = reference.primary_view_index
            if self.primary_views and reference.depth == 1 and index is None:
                raise ValueError("primary reference requires its primary view index")
            if index is None:
                continue  # Legacy flat captures and nested reference parents.
            if reference.depth != 1 or index >= len(self.primary_views):
                raise ValueError("reference has an invalid primary view index")
            view = self.primary_views[index]
            if (reference.parent_url != view.url or reference.source_quote not in view.text
                    or not any(link.candidate_id == reference.candidate_id
                               and link.url == reference.requested_url for link in view.observed_links)):
                raise ValueError("reference must be grounded in its own primary view")
        actual = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.content_sha256 != actual:
            raise ValueError("content_sha256 does not match text")
        if (
            self.capture_status is CaptureStatus.COMPLETE
            and self.capture_reason is not CaptureReason.NONE
        ):
            raise ValueError("complete capture must use reason NONE")
        if (
            self.capture_status is not CaptureStatus.COMPLETE
            and self.capture_reason is CaptureReason.NONE
        ):
            raise ValueError("incomplete capture requires a non-NONE reason")
        return self


class ScopeDocument(StrictModel):
    schema_version: str = "1.0"
    scope_id: NonEmptyText
    created_at: AwareDatetime
    source: ProgramPage
    analysis: ScopeAnalysis


class ScopeManifest(StrictModel):
    schema_version: str = "1.0"
    scope_id: NonEmptyText
    generated_at: AwareDatetime
    scope_json_sha256: Sha256Digest
    scope_markdown_sha256: Sha256Digest


class ScopeApproval(StrictModel):
    scope_id: NonEmptyText
    approved_by: NonEmptyText
    approved_at: AwareDatetime
    scope_json_sha256: Sha256Digest
    scope_markdown_sha256: Sha256Digest
