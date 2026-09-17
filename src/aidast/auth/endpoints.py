"""Secret-free authentication endpoint provenance."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from urllib.parse import urlsplit


class AuthenticationEndpointError(ValueError):
    """Authentication endpoint metadata is malformed or outside its boundary."""


_BUNDLE_FIELDS = frozenset({"method", "origin", "path", "source", "observed_at"})
_METHOD = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$")


def normalize_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise AuthenticationEndpointError("invalid authentication endpoint origin") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AuthenticationEndpointError("invalid authentication endpoint origin")
    default_port = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname.lower().rstrip(".")
    if not host:
        raise AuthenticationEndpointError("invalid authentication endpoint origin")
    host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise AuthenticationEndpointError("invalid authentication endpoint path")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or parsed.path != value:
        raise AuthenticationEndpointError("authentication endpoint path must not contain URL metadata")
    if "\\" in value or any(ord(character) < 0x20 for character in value):
        raise AuthenticationEndpointError("invalid authentication endpoint path")
    return value


@dataclass(frozen=True, slots=True)
class AuthenticationEndpoint:
    method: str
    origin: str
    path: str
    source: str = "auth_bootstrap"
    observed_at: str | None = None

    def __post_init__(self) -> None:
        method = self.method.upper() if isinstance(self.method, str) else ""
        if not _METHOD.fullmatch(method):
            raise AuthenticationEndpointError("invalid authentication endpoint method")
        if self.source != "auth_bootstrap":
            raise AuthenticationEndpointError("invalid authentication endpoint source")
        if self.observed_at is not None and (
            not isinstance(self.observed_at, str) or not self.observed_at or len(self.observed_at) > 64
        ):
            raise AuthenticationEndpointError("invalid authentication endpoint timestamp")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "origin", normalize_origin(self.origin))
        object.__setattr__(self, "path", _path(self.path))

    @classmethod
    def from_request(
        cls,
        method: str,
        url: str,
        *,
        target_origin: str,
        allowed_bootstrap_origins: frozenset[str] = frozenset(),
        observed_at: str | None = None,
    ) -> AuthenticationEndpoint | None:
        try:
            parsed = urlsplit(url)
            candidate_origin = normalize_origin(url)
            allowed = {normalize_origin(target_origin)}
            allowed.update(normalize_origin(item) for item in allowed_bootstrap_origins)
            if candidate_origin not in allowed:
                return None
            return cls(
                method=method,
                origin=candidate_origin,
                path=parsed.path or "/",
                observed_at=observed_at,
            )
        except AuthenticationEndpointError:
            return None

    def to_bundle_dict(self) -> dict[str, str]:
        result = {
            "method": self.method,
            "origin": self.origin,
            "path": self.path,
            "source": self.source,
        }
        if self.observed_at is not None:
            result["observed_at"] = self.observed_at
        return result


def parse_authentication_endpoints(
    raw: object,
    *,
    target_origin: str,
    allowed_bootstrap_origins: frozenset[str] = frozenset(),
) -> tuple[AuthenticationEndpoint, ...]:
    if not isinstance(raw, list):
        raise AuthenticationEndpointError("authentication_endpoints must be a list")
    allowed = {normalize_origin(target_origin)}
    allowed.update(normalize_origin(item) for item in allowed_bootstrap_origins)
    unique: dict[tuple[str, str, str], AuthenticationEndpoint] = {}
    for item in raw:
        if not isinstance(item, Mapping) or set(item) - _BUNDLE_FIELDS:
            raise AuthenticationEndpointError("invalid authentication endpoint fields")
        try:
            endpoint = AuthenticationEndpoint(
                method=item["method"],
                origin=item["origin"],
                path=item["path"],
                source=item["source"],
                observed_at=item.get("observed_at"),
            )
        except (KeyError, TypeError) as exc:
            raise AuthenticationEndpointError("incomplete authentication endpoint metadata") from exc
        if endpoint.origin not in allowed:
            raise AuthenticationEndpointError("authentication endpoint origin is outside its boundary")
        unique.setdefault((endpoint.method, endpoint.origin, endpoint.path), endpoint)
    return tuple(unique.values())


def serialize_authentication_endpoints(
    items: Iterable[AuthenticationEndpoint],
) -> list[dict[str, str]]:
    return [item.to_bundle_dict() for item in items]
