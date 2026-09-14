"""Dependency-free header hygiene, also loaded by the standalone proxy addon."""

from __future__ import annotations

from collections.abc import Mapping
import re


BROWSER_TOKEN_HEADER = "x-aidast-browser-token"
BROWSER_MODE_HEADER = "x-aidast-browser-mode"
BROWSER_SUPPORT_MODES = {"same-origin", "passive"}


def is_sensitive_header(name: str) -> bool:
    normalized = name.lower().replace("_", "-")
    return (
        normalized in {"authorization", "proxy-authorization", "cookie", "set-cookie"}
        or any(part in normalized for part in ("token", "secret", "api-key", "apikey"))
    )


def sanitize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Retain useful header names without persisting credential values."""
    return {
        str(name): "[REDACTED]" if is_sensitive_header(str(name)) else str(value)
        for name, value in (headers or {}).items()
    }


def validate_scope_rules(rules: object) -> dict:
    """Reject incomplete proxy boundaries rather than inventing missing limits."""
    if not isinstance(rules, dict):
        raise ValueError("scope rules must be an object")
    for key in ("allowed_hosts", "allowed_schemes", "allowed_ports",
                "allowed_path_prefixes", "allowed_methods"):
        values = rules.get(key)
        if not isinstance(values, list) or not values:
            raise ValueError(f"scope rules require a nonempty {key}")
    if any(not isinstance(host, str) or not host or "://" in host or "/" in host
           for host in rules["allowed_hosts"]):
        raise ValueError("invalid allowed hosts")
    excluded_hosts = rules.get("excluded_hosts", [])
    if not isinstance(excluded_hosts, list) or any(
        not isinstance(host, str) or not _valid_host_pattern(host)
        for host in excluded_hosts
    ):
        raise ValueError("invalid excluded hosts")
    if any(scheme not in {"http", "https"} for scheme in rules["allowed_schemes"]):
        raise ValueError("invalid allowed schemes")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in rules["allowed_ports"]):
        raise ValueError("invalid allowed ports")
    if any(method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
           for method in rules["allowed_methods"]):
        raise ValueError("invalid allowed methods")
    excluded = rules.get("excluded_path_prefixes", [])
    if not isinstance(excluded, list) or any(
        not isinstance(path, str) or not path.startswith("/")
        for path in rules["allowed_path_prefixes"] + excluded
    ):
        raise ValueError("invalid path prefixes")
    for key in ("include_subdomains", "enforcement_required", "mitm_capture_bodies"):
        if key in rules and type(rules[key]) is not bool:
            raise ValueError(f"invalid {key}")
    browser_token = rules.get("browser_context_token")
    if browser_token is not None and (
        not isinstance(browser_token, str) or len(browser_token) < 16
    ):
        raise ValueError("invalid browser context token")
    maximum = rules.get("max_requests")
    if type(maximum) is not int or maximum < 1:
        raise ValueError("scope rules require a positive max_requests")
    return rules


def _valid_host_pattern(host: str) -> bool:
    value = host.lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return bool(
        value
        and "://" not in value
        and "/" not in value
        and "*" not in value
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value)
    )
