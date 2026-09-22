"""Dependency-free header hygiene, also loaded by the standalone proxy addon."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlsplit


BROWSER_TOKEN_HEADER = "x-aidast-browser-token"
BROWSER_MODE_HEADER = "x-aidast-browser-mode"
BROWSER_SUPPORT_MODES = {"same-origin", "passive"}
AUTH_CAPABILITY_HEADER = "X-AIDAST-Auth-Capability"
AUTH_CAPABILITY_VERSION = 1


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _request_binding(method: str, url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("request capability requires an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("request capability does not allow URL credentials")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = (
        f"{method.upper()}\n{parsed.scheme.lower()}\n"
        f"{parsed.hostname.lower().rstrip('.')}\n{port}\n"
        f"{parsed.path or '/'}\n{parsed.query}"
    )
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def issue_request_capability(
    signing_key: str,
    *,
    method: str,
    url: str,
    ttl_seconds: int = 20,
    now: int | None = None,
) -> str:
    """Issue one short-lived capability bound to an exact POST target."""
    if len(signing_key) < 32:
        raise ValueError("request capability requires a strong signing key")
    if method.upper() != "POST":
        raise ValueError("manual authentication capability may allow POST only")
    if not 1 <= ttl_seconds <= 60:
        raise ValueError("request capability TTL must be between 1 and 60 seconds")
    issued_at = int(time.time() if now is None else now)
    payload = {
        "v": AUTH_CAPABILITY_VERSION,
        "m": method.upper(),
        "t": _request_binding(method, url),
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
        "n": secrets.token_urlsafe(18),
    }
    encoded = _base64url_encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = hmac.new(
        signing_key.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded}.{_base64url_encode(signature)}"


def validate_request_capability(
    token: str,
    signing_key: str,
    *,
    method: str,
    url: str,
    max_ttl_seconds: int,
    used_nonces: set[str],
    now: int | None = None,
) -> bool:
    """Validate and consume a request-bound capability."""
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _base64url_encode(
            hmac.new(
                signing_key.encode("utf-8"),
                encoded.encode("ascii"),
                hashlib.sha256,
            ).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False
        payload = json.loads(_base64url_decode(encoded).decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "v",
            "m",
            "t",
            "iat",
            "exp",
            "n",
        }:
            return False
        current = int(time.time() if now is None else now)
        issued_at = payload["iat"]
        expires_at = payload["exp"]
        nonce = payload["n"]
        valid = (
            payload["v"] == AUTH_CAPABILITY_VERSION
            and payload["m"] == method.upper() == "POST"
            and payload["t"] == _request_binding(method, url)
            and type(issued_at) is int
            and type(expires_at) is int
            and 0 < expires_at - issued_at <= max_ttl_seconds
            and issued_at <= current <= expires_at
            and isinstance(nonce, str)
            and len(nonce) >= 16
            and nonce not in used_nonces
        )
        if valid:
            used_nonces.add(nonce)
        return valid
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        return False


def is_sensitive_header(name: str) -> bool:
    normalized = name.lower().replace("_", "-")
    return (
        normalized in {
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-intigriti-username", "x-hackerone",
        }
        or any(
            part in normalized
            for part in ("token", "secret", "api-key", "apikey", "capability")
        )
    )


def validate_platform_username(value: str, platform: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", candidate) is None:
        raise ValueError(
            f"must be a 1-64 character {platform} handle using letters, digits, ., _, or -"
        )
    return candidate


def validate_hackerone_username(value: str) -> str:
    return validate_platform_username(value, "HackerOne")


def merge_hackerone_identity(
    headers: Mapping[str, str] | None,
    username: str | None,
) -> dict[str, str]:
    merged = {
        str(name): str(value)
        for name, value in (headers or {}).items()
        if str(name).casefold() != "x-hackerone"
    }
    if username is not None:
        merged["X-HackerOne"] = validate_hackerone_username(username)
    return merged


def sanitize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Retain useful header names without persisting credential values."""
    result: dict[str, str] = {}
    for name, value in (headers or {}).items():
        header_name = str(name)
        header_value = str(value)
        if is_sensitive_header(header_name):
            header_value = "[REDACTED]"
        elif header_name.lower().replace("_", "-") == "user-agent":
            header_value = re.sub(
                r"<intigriti:[^>]*>", "<intigriti:[REDACTED]>", header_value,
                flags=re.IGNORECASE,
            )
        result[header_name] = header_value
    return result


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
