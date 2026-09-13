"""Resolve opaque Pipeline.db credential references at HTTP dispatch time."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PipelineCredentialResolver:
    """Resolve `env://NAME` values containing a JSON object of HTTP headers."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path).expanduser().resolve()

    def unsupported_reason(self, reference: str) -> str | None:
        try:
            uri = self._reference_uri(reference)
            environment_name = self._environment_name(uri)
            self._headers(environment_name)
        except (OSError, sqlite3.Error, ValueError):
            return "credential_reference_unavailable"
        return None

    def __call__(self, reference: str) -> dict[str, str]:
        uri = self._reference_uri(reference)
        return self._headers(self._environment_name(uri))

    def _reference_uri(self, reference: str) -> str:
        uri = self.db_path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            row = conn.execute(
                "SELECT reference_uri FROM credential_references "
                "WHERE credential_reference_id=?",
                (reference,),
            ).fetchone()
        if row is None:
            raise ValueError("unknown credential reference")
        return row[0]

    @staticmethod
    def _environment_name(uri: str) -> str:
        parsed = urlsplit(uri)
        if (
            parsed.scheme != "env" or not parsed.netloc or parsed.path
            or parsed.query or parsed.fragment or parsed.username is not None
            or parsed.password is not None or _ENV_NAME.fullmatch(parsed.netloc) is None
        ):
            raise ValueError("unsupported credential reference backend")
        return parsed.netloc

    @staticmethod
    def _headers(environment_name: str) -> dict[str, str]:
        raw = os.environ.get(environment_name)
        if raw is None:
            raise ValueError("credential environment variable is unavailable")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("credential environment variable must contain JSON") from exc
        if (
            not isinstance(value, dict) or not 1 <= len(value) <= 32
            or any(
                not isinstance(name, str) or _HEADER_NAME.fullmatch(name) is None
                or not isinstance(header, str) or len(header) > 16_384
                or "\r" in header or "\n" in header
                for name, header in value.items()
            )
        ):
            raise ValueError("credential header map is invalid")
        return dict(value)
