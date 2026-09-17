"""Target and identity bindings for Chromium storage state."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit


class SessionBindingError(ValueError):
    pass


class SessionBindings:
    """Resolve only explicitly configured target and identity session files."""

    def __init__(self, document: dict[str, dict[str, str]]) -> None:
        self._items = {
            (str(target).casefold().rstrip("."), str(identity)): Path(path).expanduser()
            for target, identities in document.items()
            for identity, path in identities.items()
        }

    @classmethod
    def from_json(cls, path: str | Path) -> "SessionBindings":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or any(
            not isinstance(identities, dict) for identities in raw.values()
        ):
            raise SessionBindingError("session bindings must be an object")
        return cls(raw)

    def resolve(self, target: str, identity: str) -> Path:
        host = urlsplit(target).hostname or target
        path = self._items.get((host.casefold().rstrip("."), identity))
        if path is None:
            raise SessionBindingError(f"no session is configured for {host}/{identity}")
        if not path.is_file() or path.is_symlink():
            raise SessionBindingError("configured session file is unavailable")
        return path.resolve(strict=True)
