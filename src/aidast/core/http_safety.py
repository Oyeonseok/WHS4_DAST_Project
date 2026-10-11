"""Dependency-free header hygiene, also loaded by the standalone proxy addon."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
from ipaddress import ip_address
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

# Policy requirements may name any safe HTTP token. This deny list protects
# credentials, request routing/framing, and internal transport capabilities.
PROTECTED_IDENTITY_HEADERS = frozenset({
    "host", "cookie", "set-cookie", "authorization", "proxy-authorization",
    "connection", "keep-alive", "proxy-connection", "transfer-encoding",
    "content-length", "te", "trailer", "upgrade", "expect", "proxy-authenticate",
    "www-authenticate", "forwarded", "x-forwarded-host", "x-forwarded-for",
    "x-forwarded-proto", "via",
    "api-key", "x-api-key", "apikey", "x-apikey", "authentication",
    "x-auth", "x-auth-token", "access-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token",
})


def validate_identity_header_name(name: str) -> str:
    if (not isinstance(name, str) or len(name) > 128
            or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None):
        raise ValueError("identity header name must be a valid HTTP token")
    normalized = name.casefold().replace("_", "-")
    if normalized in PROTECTED_IDENTITY_HEADERS or normalized.startswith("x-aidast-"):
        raise ValueError("protected credential, routing or internal identity header")
    return name


def validate_identity_header_value(value: str) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("identity header value must be nonblank, bounded and free of controls")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("identity header value must be HTTP Latin-1 encodable") from exc
    return value


def scope_uses_loopback_host(hosts: object) -> bool:
    """Keep browser rendering traffic local when a scope contains loopback."""
    if not isinstance(hosts, (list, tuple, set, frozenset)):
        return False
    for raw_host in hosts:
        if not isinstance(raw_host, str):
            continue
        host = raw_host.lower().rstrip(".")
        if host == "localhost" or host.endswith(".localhost"):
            return True
        try:
            if ip_address(host).is_loopback:
                return True
        except ValueError:
            pass
    return False


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
            "x-intigriti-username", "x-hackerone", "x-bug-bounty",
        }
        or any(
            part in normalized
            for part in ("token", "secret", "api-key", "apikey", "capability")
        )
    )


def browser_has_authentication(
    headers: Mapping[str, str] | None, *,
    identity_headers: Mapping[str, str] | None = None,
) -> bool:
    """Distinguish browser credentials from required researcher ID headers."""
    controlled = {str(name).casefold() for name in (identity_headers or {})}
    for name, value in (headers or {}).items():
        normalized = str(name).casefold().replace("_", "-")
        if normalized in controlled or normalized.startswith("x-aidast-"):
            continue
        if str(value).strip() and (
            normalized in {"authorization", "proxy-authorization", "cookie"}
            or is_sensitive_header(normalized)
        ):
            return True
    return False


def validate_platform_username(value: str, platform: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", candidate) is None:
        raise ValueError(
            f"must be a 1-64 character {platform} handle using letters, digits, ., _, or -"
        )
    return candidate


def validate_hackerone_username(value: str) -> str:
    return validate_platform_username(value, "HackerOne")


def validate_identity_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Validate a generic trusted identification map without interpreting policy."""
    if not isinstance(headers, Mapping) or len(headers) > 32:
        raise ValueError("required identity headers must be a bounded object")
    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for name, value in headers.items():
        name = validate_identity_header_name(name)
        if name.casefold() in seen:
            raise ValueError("duplicate researcher identity header names")
        seen.add(name.casefold())
        normalized[name] = validate_identity_header_value(value)
    return normalized


def merge_hackerone_identity(
    headers: Mapping[str, str] | None,
    username: str | None,
    *,
    required_identity_headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    required = validate_identity_headers({} if required_identity_headers is None else required_identity_headers)
    controlled = {"x-hackerone", *(name.casefold() for name in required)}
    merged = {
        str(name): str(value)
        for name, value in (headers or {}).items()
        if str(name).casefold() not in controlled
    }
    # Preserve legacy policies, but use the exact Scope names for new policies.
    if username is not None and not required:
        merged["X-HackerOne"] = validate_hackerone_username(username)
    merged.update(required)
    return merged


def sanitize_headers(headers: Mapping[str, str] | None, *, identity_headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """Retain useful header names without persisting credential values."""
    result: dict[str, str] = {}
    for name, value in (headers or {}).items():
        header_name = str(name)
        header_value = str(value)
        if is_sensitive_header(header_name) or header_name.casefold() in {name.casefold() for name in (identity_headers or {})}:
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
    if "required_identity_headers" in rules:
        validate_identity_headers(rules["required_identity_headers"])
    if rules.get("hackerone_username") is not None:
        validate_hackerone_username(rules["hackerone_username"])
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


def exclusion_snapshot(policy):
    """Extract a guard without letting malformed present values become legacy."""
    value = policy.get('request_exclusions') if isinstance(policy, Mapping) else getattr(policy, 'request_exclusions', None)
    return value.model_dump(mode='json') if hasattr(value, 'model_dump') else value


def has_request_exclusions(policy):
    """Whether unmanaged capabilities must hold, including malformed guards."""
    value = exclusion_snapshot(policy)
    if value is None:
        return False
    from pathlib import Path
    import runpy
    try:
        guard = runpy.run_path(str(Path(__file__).with_name('exclusion_guard.py')))
        value = guard['validate_exclusion_policy'](value)
        return any(guard['exclusion_applicability'](r, value['target_asset']) != 'disjoint'
                   for r in value['rules'])
    except (ValueError, TypeError, KeyError):
        return True


def require_request_admission(policy, *, url, method, headers=None, body=None,
                              body_available=True, identity_available=True,
                              context=None, now=None, error_class=ValueError):
    """Full physical admission; false exclusions still require baseline checks."""
    if hasattr(policy, 'check_request_exclusions'):
        result = policy.check_request_exclusions(url, method=method, headers=headers,
            body=body, body_available=body_available, identity_available=identity_available,
            context=context, now=now)
    else:
        from pathlib import Path
        import runpy
        guard = runpy.run_path(str(Path(__file__).with_name('exclusion_guard.py')))
        value = exclusion_snapshot(policy)
        if value is not None and (not isinstance(value, dict) or value.get('target_asset') != policy.get('asset')):
            raise error_class('exclusion hold: policy target mismatch')
        result = guard['evaluate_exclusions'](value, url=url, method=method, headers=headers,
            body=body, body_available=body_available, identity_available=identity_available,
            context=context, now=now)
    if result['decision'] != 'continue':
        raise error_class('exclusion ' + result['decision'] + ': ' + ', '.join(result['rule_keys']) + ' (' + result['reason'] + ')')
    return result
