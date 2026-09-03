"""Compile a normalized recon policy into a deterministic execution plan."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from aidast.recon.policy import (
    AllowTargetRule,
    AssetType,
    ExecutionDecision,
    PolicyError,
    ProxyCoverage,
    ProxyMode,
    ReconPolicy,
    ScopeGuard,
    TrafficClass,
)


@dataclass(frozen=True)
class SkippedPlanItem:
    item_id: str
    reason: str


@dataclass(frozen=True)
class PolicyExecutionPlan:
    targets: tuple[str, ...]
    tool_ids: tuple[str, ...]
    skipped_targets: tuple[SkippedPlanItem, ...]
    skipped_tools: tuple[SkippedPlanItem, ...]


def build_execution_plan(
    policy: ReconPolicy,
    *,
    supported_tool_ids: set[str],
    requested_targets: list[str] | None = None,
    requested_tool_ids: list[str] | None = None,
) -> PolicyExecutionPlan:
    """Select executable adapters and concrete targets without broadening scope."""
    targets, skipped_targets = _select_targets(policy, requested_targets)
    tools, skipped_tools = _select_tools(
        policy, supported_tool_ids, requested_tool_ids
    )
    if not targets:
        raise PolicyError("policy produced no concrete HTTP(S) targets")
    if not tools:
        raise PolicyError("policy produced no executable registered tools")
    return PolicyExecutionPlan(
        targets=tuple(targets),
        tool_ids=tuple(tools),
        skipped_targets=tuple(skipped_targets),
        skipped_tools=tuple(skipped_tools),
    )


def _select_targets(
    policy: ReconPolicy, requested_targets: list[str] | None
) -> tuple[list[str], list[SkippedPlanItem]]:
    guard = ScopeGuard(policy)
    if requested_targets:
        targets = []
        for target in requested_targets:
            allowed, reason = guard.evaluate_url(target)
            if not allowed:
                raise PolicyError(f"target is outside policy: {target} ({reason})")
            targets.append(target)
        return _deduplicate(targets), []

    targets: list[str] = []
    skipped: list[SkippedPlanItem] = []
    for index, rule in enumerate(policy.target_rules.allow):
        item_id = f"allow[{index}] {rule.asset_type.value}:{rule.value}"
        candidates = _concrete_urls(rule)
        if not candidates:
            skipped.append(
                SkippedPlanItem(
                    item_id=item_id,
                    reason=(
                        "requires concrete discovery input; wildcard/CIDR/other rules "
                        "are never expanded automatically"
                    ),
                )
            )
            continue
        matched = False
        for candidate in candidates:
            allowed, _ = guard.evaluate_url(candidate)
            if allowed:
                targets.append(candidate)
                matched = True
        if not matched:
            skipped.append(
                SkippedPlanItem(
                    item_id=item_id,
                    reason="no generated URL survived the complete deny-first policy",
                )
            )
    return _deduplicate(targets), skipped


def _select_tools(
    policy: ReconPolicy,
    supported_tool_ids: set[str],
    requested_tool_ids: list[str] | None,
) -> tuple[list[str], list[SkippedPlanItem]]:
    if requested_tool_ids and len(requested_tool_ids) != len(set(requested_tool_ids)):
        raise PolicyError("duplicate tool IDs are not allowed")
    candidates = requested_tool_ids or list(policy.tools)
    selected: list[str] = []
    skipped: list[SkippedPlanItem] = []
    for tool_id in candidates:
        tool = policy.tools.get(tool_id)
        if tool is None:
            if requested_tool_ids:
                raise PolicyError(f"policy does not contain tool: {tool_id}")
            continue
        reason = _tool_skip_reason(policy, tool_id, supported_tool_ids)
        if reason is None:
            selected.append(tool_id)
        elif requested_tool_ids:
            raise PolicyError(f"requested tool cannot execute: {tool_id} ({reason})")
        else:
            skipped.append(SkippedPlanItem(item_id=tool_id, reason=reason))
    return selected, skipped


def _tool_skip_reason(
    policy: ReconPolicy, tool_id: str, supported_tool_ids: set[str]
) -> str | None:
    tool = policy.tools[tool_id]
    if tool.execution_decision is not ExecutionDecision.ALLOW:
        return f"execution_decision is {tool.execution_decision.value}"
    if any(
        item.severity == "blocking" and tool_id in item.affected_tools
        for item in policy.review_items
    ):
        return "a blocking review item affects the tool"
    if tool_id not in supported_tool_ids:
        return "no registered safe adapter"
    if tool.traffic_class is not TrafficClass.TARGET_HTTP:
        return f"traffic class {tool.traffic_class.value} is not target_http"
    if tool.proxy.mode is ProxyMode.UNSUPPORTED:
        return "the tool does not support the required proxy"
    if tool.proxy.coverage is not ProxyCoverage.FULL:
        return f"proxy coverage is {tool.proxy.coverage.value}, not full"
    return None


def _concrete_urls(rule: AllowTargetRule) -> list[str]:
    if rule.asset_type is AssetType.URL:
        parsed = urlsplit(rule.value)
        if not parsed.scheme or not parsed.hostname:
            return []
        paths = _deduplicate([parsed.path or "/", *rule.path_prefixes])
        return [
            urlunsplit((parsed.scheme, parsed.netloc, path, "", "")) for path in paths
        ]

    if rule.asset_type not in {AssetType.HOST, AssetType.IP}:
        return []
    if rule.asset_type is AssetType.IP:
        try:
            address = ipaddress.ip_address(rule.value)
        except ValueError:
            return []
        host = f"[{address}]" if address.version == 6 else str(address)
    else:
        host = rule.value.rstrip(".")

    urls: list[str] = []
    for scheme in rule.schemes:
        default_port = 443 if scheme.casefold() == "https" else 80
        ports = rule.ports or [default_port]
        for port in ports:
            authority = host if port == default_port else f"{host}:{port}"
            for path in rule.path_prefixes or ["/"]:
                urls.append(urlunsplit((scheme, authority, path, "", "")))
    return urls


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
