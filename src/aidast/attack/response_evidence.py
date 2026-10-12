"""Project captured HTTP responses into bounded, value-free planning evidence.

Recon keeps response bodies locally so deterministic parsers can recover public
route declarations.  The Attack planner must not receive those bodies, cookie
values, credentials, personal data, CSP nonces, or other response values.  This
module exposes only structural JSON types and narrowly classified HTTP security
controls.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from aidast.recon.annotations import safe_url


MAX_BODY_BYTES = 262_144
MAX_PROFILES = 8
_FIELD_NAME = re.compile(r"[A-Za-z_$][\w$.-]{0,127}\Z")
_TOKEN_SHAPED = re.compile(r"[A-Za-z0-9_+./=-]{40,}\Z")
_DIRECTIVE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def _object(raw: object) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _headers(raw: object) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in _object(raw).items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        normalized = name.casefold().replace("_", "-")[:128]
        if normalized and normalized not in result:
            result[normalized] = value[:131_072]
    return result


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return (
            parsed.scheme.casefold(), parsed.hostname.casefold().rstrip("."),
            parsed.port or (443 if parsed.scheme.casefold() == "https" else 80),
        )
    except ValueError:
        return None


def _cors_origin_class(value: str, *, request_origin: str, request_url: str) -> str:
    candidate = value.strip()
    if candidate == "*":
        return "wildcard"
    if candidate.casefold() == "null":
        return "null"
    candidate_origin = _origin(candidate)
    if candidate_origin is None:
        return "invalid"
    if request_origin and candidate_origin == _origin(request_origin):
        return "request_origin"
    if candidate_origin == _origin(request_url):
        return "same_origin"
    return "other_origin"


def _directive_names(value: str) -> list[str]:
    names = []
    for section in value.split(";")[:128]:
        name = section.strip().split(None, 1)[0].casefold() if section.strip() else ""
        if _DIRECTIVE.fullmatch(name) and name not in names:
            names.append(name)
    return names[:64]


def _token_names(value: str) -> list[str]:
    names = []
    for section in value.split(",")[:64]:
        name = section.strip().split("=", 1)[0].strip().casefold()
        if _DIRECTIVE.fullmatch(name) and name not in names:
            names.append(name)
    return names[:32]


def _security_facts(
    response_headers: Mapping[str, str], *, request_headers: Mapping[str, str],
    request_url: str,
) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    csp = response_headers.get("content-security-policy")
    report_only = response_headers.get("content-security-policy-report-only")
    if csp or report_only:
        facts["content_security_policy"] = {
            "enforced": bool(csp),
            "report_only": bool(report_only),
            "directive_names": sorted(set(
                _directive_names(csp or "") + _directive_names(report_only or "")
            )),
        }
    hsts = response_headers.get("strict-transport-security")
    if hsts:
        facts["strict_transport_security"] = {
            "present": True,
            "directive_names": _token_names(hsts.replace(";", ",")),
        }
    xcto = response_headers.get("x-content-type-options", "").strip().casefold()
    if xcto:
        facts["x_content_type_options"] = "nosniff" if xcto == "nosniff" else "other"
    xfo = response_headers.get("x-frame-options", "").strip().casefold()
    if xfo:
        facts["x_frame_options"] = (
            xfo if xfo in {"deny", "sameorigin"} else
            "allow-from" if xfo.startswith("allow-from") else "other"
        )
    allow_origin = response_headers.get("access-control-allow-origin")
    allow_credentials = response_headers.get("access-control-allow-credentials")
    vary = response_headers.get("vary", "")
    if allow_origin is not None or allow_credentials is not None or "origin" in {
        item.strip().casefold() for item in vary.split(",")
    }:
        request_origin = next(
            (value for name, value in request_headers.items() if name == "origin"), "",
        )
        cors: dict[str, Any] = {
            "vary_origin": "origin" in {
                item.strip().casefold() for item in vary.split(",")
            },
        }
        if allow_origin is not None:
            cors["allow_origin_class"] = _cors_origin_class(
                allow_origin, request_origin=request_origin, request_url=request_url,
            )
        if allow_credentials is not None:
            normalized = allow_credentials.strip().casefold()
            cors["allow_credentials"] = (
                normalized == "true" if normalized in {"true", "false"} else "other"
            )
        facts["cors"] = cors
    challenge = response_headers.get("www-authenticate", "")
    if challenge and challenge != "[REDACTED]":
        schemes = []
        for section in challenge.split(",")[:16]:
            match = re.match(r"\s*([A-Za-z][A-Za-z0-9_-]{0,31})\b", section)
            if match and match[1].casefold() not in schemes:
                schemes.append(match[1].casefold())
        if schemes:
            facts["authentication_challenge_schemes"] = schemes
    cache_control = response_headers.get("cache-control")
    if cache_control:
        facts["cache_control_directives"] = _token_names(cache_control)
    location = response_headers.get("location")
    if location:
        sanitized = safe_url(location)
        if sanitized:
            facts["redirect_location"] = sanitized
    return facts


def _safe_field_name(value: object) -> str | None:
    if not isinstance(value, str) or not _FIELD_NAME.fullmatch(value):
        return None
    if _TOKEN_SHAPED.fullmatch(value) or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f-]{27,}", value, flags=re.IGNORECASE,
    ):
        return None
    return value


def _json_shape(value: Any, *, depth: int = 0) -> Any:
    if depth >= 4:
        return "nested"
    if isinstance(value, dict):
        fields: dict[str, Any] = {}
        omitted = 0
        for raw_name, child in list(value.items())[:128]:
            name = _safe_field_name(raw_name)
            if name is None:
                omitted += 1
                continue
            fields[name] = _json_shape(child, depth=depth + 1)
            if len(fields) >= 64:
                break
        result: dict[str, Any] = {"type": "object", "fields": fields}
        if omitted or len(value) > len(fields):
            result["additional_fields_present"] = True
        return result
    if isinstance(value, list):
        return {
            "type": "array",
            "item": _json_shape(value[0], depth=depth + 1) if value else "unknown",
        }
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _body_facts(raw: object, media_type: str) -> dict[str, Any]:
    if not isinstance(raw, (str, bytes)):
        return {}
    encoded = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    facts: dict[str, Any] = {"byte_length": len(encoded)}
    if len(encoded) > MAX_BODY_BYTES:
        facts["structure_truncated"] = True
        return facts
    text = encoded.decode("utf-8", errors="replace")
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            facts["json_shape"] = _json_shape(json.loads(text))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            facts["parse_status"] = "invalid_json"
    elif media_type in {"text/html", "application/xhtml+xml"}:
        # Detailed form/action parsing is handled by passive Recon
        # reconciliation.  These counts only tell the planner what kind of
        # document was captured and never copy attributes or text.
        facts["document_structure"] = {
            "form_count": min(200, len(re.findall(r"(?i)<form(?:\s|>)", text))),
            "script_count": min(2000, len(re.findall(r"(?i)<script(?:\s|>)", text))),
            "password_field_present": bool(re.search(
                r"(?is)<input\b[^>]*\btype\s*=\s*['\"]?password\b", text,
            )),
        }
    return facts


def structural_response_evidence(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return unique response profiles containing no captured scalar values."""
    profiles: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        status = row.get("response_status")
        media_type = str(row.get("content_type") or "").split(";", 1)[0].strip().casefold()
        response_headers = _headers(row.get("response_headers"))
        request_headers = _headers(row.get("request_headers"))
        if not media_type:
            media_type = response_headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        profile: dict[str, Any] = {}
        if type(status) is int and 100 <= status <= 599:
            profile["status"] = status
        if media_type and re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
            profile["media_type"] = media_type
        security = _security_facts(
            response_headers, request_headers=request_headers,
            request_url=str(row.get("url") or ""),
        )
        if security:
            profile["security_controls"] = security
        body = _body_facts(row.get("response_body"), media_type)
        if body:
            profile["body"] = body
        if not profile:
            continue
        fingerprint = json.dumps(profile, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        profiles.append(profile)
        if len(profiles) >= MAX_PROFILES:
            break
    return profiles
