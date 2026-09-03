"""Validated runtime model for recon-policy-compiler output."""

from __future__ import annotations

import ipaddress
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


INTERNAL_EXECUTION_HEADER = "X-AIDAST-Execution"


class PolicyError(RuntimeError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyStatus(StrEnum):
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"


class ProgramPermission(StrEnum):
    ALLOWED = "allowed"
    CONDITIONAL = "conditional"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


class ExecutionDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


class TrafficClass(StrEnum):
    TARGET_HTTP = "target_http"
    PROVIDER_HTTP = "provider_http"
    RAW_NETWORK = "raw_network"
    LOCAL_ONLY = "local_only"
    MIXED = "mixed"


class ProxyMode(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"


class ProxyCoverage(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"
    UNKNOWN = "unknown"


class AssetType(StrEnum):
    URL = "url"
    HOST = "host"
    WILDCARD_HOST = "wildcard_host"
    CIDR = "cidr"
    IP = "ip"
    OTHER = "other"


class PolicySource(StrictModel):
    scope_md_path: str = Field(min_length=1)


class AllowTargetRule(StrictModel):
    asset_type: AssetType
    value: str = Field(min_length=1)
    schemes: list[str]
    ports: list[int]
    path_prefixes: list[str]
    source_section: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_network_fields(self) -> "AllowTargetRule":
        if self.asset_type is AssetType.OTHER:
            raise ValueError("other assets cannot be executable allow rules")
        if any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("ports must be between 1 and 65535")
        if any(not prefix.startswith("/") for prefix in self.path_prefixes):
            raise ValueError("path prefixes must start with '/'")
        return self


class DenyTargetRule(StrictModel):
    asset_type: AssetType
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    source_section: str = Field(min_length=1)


class TargetRules(StrictModel):
    allow: list[AllowTargetRule]
    deny: list[DenyTargetRule]


class RequiredHeader(StrictModel):
    name: str = Field(min_length=1)
    value: str | None
    value_source: Literal["runtime_input", "fixed_from_scope"]
    required: bool


class GlobalControls(StrictModel):
    proxy_required_for_http: bool
    maximum_requests_per_second: int | None = Field(default=None, ge=1)
    maximum_concurrency: int | None = Field(default=None, ge=1)
    maximum_duration_seconds: int | None = Field(default=None, ge=1)
    follow_off_scope_redirects: bool
    revalidate_each_redirect: bool
    required_headers: list[RequiredHeader]


class ToolProxy(StrictModel):
    mode: ProxyMode
    coverage: ProxyCoverage


class ToolControls(StrictModel):
    maximum_requests_per_second: int | None = Field(default=None, ge=1)
    maximum_concurrency: int | None = Field(default=None, ge=1)
    maximum_duration_seconds: int | None = Field(default=None, ge=1)
    required_arguments: list[str]
    forbidden_arguments: list[str]


class Evidence(StrictModel):
    source_section: str = Field(min_length=1)
    rule: str = Field(min_length=1)


class ToolPolicy(StrictModel):
    program_permission: ProgramPermission
    execution_decision: ExecutionDecision
    traffic_class: TrafficClass
    proxy: ToolProxy
    enforced_controls: ToolControls
    conditions: list[str]
    evidence: list[Evidence]
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_allow_decision(self) -> "ToolPolicy":
        if self.execution_decision is ExecutionDecision.ALLOW and not self.evidence:
            raise ValueError("allow decisions require evidence")
        if (
            self.execution_decision is ExecutionDecision.ALLOW
            and self.program_permission
            not in {ProgramPermission.ALLOWED, ProgramPermission.CONDITIONAL}
        ):
            raise ValueError("prohibited or unknown tools cannot be executable")
        return self


class RuntimeInput(StrictModel):
    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    required_by: list[str]


class ReviewItem(StrictModel):
    id: str = Field(min_length=1)
    severity: Literal["blocking", "warning"]
    question: str = Field(min_length=1)
    affected_tools: list[str]


class ReconPolicy(StrictModel):
    schema_version: Literal["1.0"]
    source: PolicySource
    policy_status: PolicyStatus
    default_execution_decision: ExecutionDecision
    target_rules: TargetRules
    global_controls: GlobalControls
    tools: dict[str, ToolPolicy]
    runtime_inputs: list[RuntimeInput]
    review_items: list[ReviewItem]

    @model_validator(mode="after")
    def validate_fail_closed_defaults(self) -> "ReconPolicy":
        if self.default_execution_decision is not ExecutionDecision.BLOCK:
            raise ValueError("default_execution_decision must be block")
        unknown_references = {
            tool_id
            for item in [*self.runtime_inputs, *self.review_items]
            for tool_id in (
                item.required_by if isinstance(item, RuntimeInput) else item.affected_tools
            )
            if tool_id not in self.tools
        }
        if unknown_references:
            raise ValueError(
                "policy references unknown tools: " + ", ".join(sorted(unknown_references))
            )
        return self

    def require_executable_tool(self, tool_id: str) -> ToolPolicy:
        if self.policy_status is PolicyStatus.BLOCKED:
            raise PolicyError("policy status is blocked")
        tool = self.tools.get(tool_id)
        if tool is None:
            raise PolicyError(f"policy does not contain tool: {tool_id}")
        if tool.execution_decision is not ExecutionDecision.ALLOW:
            raise PolicyError(
                f"tool is not executable: {tool_id} ({tool.execution_decision.value})"
            )
        if any(
            item.severity == "blocking" and tool_id in item.affected_tools
            for item in self.review_items
        ):
            raise PolicyError(f"tool has a blocking review item: {tool_id}")
        return tool


def load_policy(path: Path) -> ReconPolicy:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return ReconPolicy.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyError(f"invalid recon policy {path}: {exc}") from exc


def _normalized_host(value: str) -> str:
    host = value.rstrip(".").casefold()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme.casefold())


def _port(parsed) -> int | None:
    return parsed.port or _default_port(parsed.scheme)


def _path_matches(path: str, prefix: str) -> bool:
    path = path or "/"
    if prefix == "/":
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


class ScopeGuard:
    """Deterministically applies deny-first target rules to HTTP requests."""

    def __init__(self, policy: ReconPolicy):
        self.policy = policy

    def evaluate_url(self, url: str) -> tuple[bool, str]:
        try:
            parsed = urlsplit(url)
            request_port = _port(parsed)
        except ValueError:
            return False, "malformed URL"
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not parsed.hostname
            or request_port is None
        ):
            return False, "unsupported or incomplete URL"

        for rule in self.policy.target_rules.deny:
            if self._matches_deny(parsed, rule):
                return False, f"matched deny rule: {rule.reason}"

        for rule in self.policy.target_rules.allow:
            if self._matches_allow(parsed, rule):
                return True, f"matched allow rule from {rule.source_section}"

        return False, "no allow rule matched"

    def _matches_allow(self, parsed, rule: AllowTargetRule) -> bool:
        if rule.schemes and parsed.scheme.casefold() not in {
            scheme.casefold() for scheme in rule.schemes
        }:
            return False
        request_port = _port(parsed)
        if rule.ports and request_port not in rule.ports:
            return False
        if rule.path_prefixes and not any(
            _path_matches(parsed.path or "/", prefix) for prefix in rule.path_prefixes
        ):
            return False
        return self._matches_asset(parsed, rule.asset_type, rule.value)

    def _matches_deny(self, parsed, rule: DenyTargetRule) -> bool:
        return self._matches_asset(parsed, rule.asset_type, rule.value)

    def _matches_asset(self, parsed, asset_type: AssetType, value: str) -> bool:
        request_host = _normalized_host(parsed.hostname or "")

        if asset_type is AssetType.URL:
            target = urlsplit(value)
            if not target.hostname or parsed.scheme.casefold() != target.scheme.casefold():
                return False
            try:
                target_port = _port(target)
                request_port = _port(parsed)
            except ValueError:
                return False
            target_path = target.path or "/"
            return (
                request_host == _normalized_host(target.hostname)
                and request_port == target_port
                and _path_matches(parsed.path or "/", target_path)
            )

        if asset_type is AssetType.HOST:
            return request_host == _normalized_host(value)

        if asset_type is AssetType.WILDCARD_HOST:
            suffix = _normalized_host(value.removeprefix("*."))
            return request_host.endswith("." + suffix) and request_host != suffix

        if asset_type is AssetType.IP:
            try:
                return ipaddress.ip_address(request_host) == ipaddress.ip_address(value)
            except ValueError:
                return False

        if asset_type is AssetType.CIDR:
            try:
                return ipaddress.ip_address(request_host) in ipaddress.ip_network(
                    value, strict=False
                )
            except ValueError:
                return False

        return False
