"""Temporary, opt-in Recon diagnostics with a credential-safe schema."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aidast.recon.annotations import safe_text, safe_url


_BLOCKED_KEYS = frozenset({
    "authorization", "body", "cookie", "cookies", "headers", "password",
    "request_body", "response_body", "secret", "session_file", "token",
})


def diagnostic_endpoint(item: object) -> dict[str, Any]:
    """Keep route metadata only; never persist request secrets or bodies."""
    if not isinstance(item, dict):
        return {}
    result: dict[str, Any] = {}
    for key in ("method", "path", "normalized_path", "source", "content_type"):
        value = item.get(key)
        if isinstance(value, str):
            result[key] = safe_text(value)[:1000]
    for key in ("response_status", "content_length", "word_count", "line_count"):
        value = item.get(key)
        if type(value) is int:
            result[key] = value
    for key in ("is_excluded", "browser_supporting_request"):
        value = item.get(key)
        if type(value) is bool:
            result[key] = value
    for key in ("url", "parent_url", "redirect_url", "fuzz_root"):
        value = item.get(key)
        if isinstance(value, str):
            result[key] = safe_url(value)
    sources = item.get("sources") or item.get("source_tools")
    if isinstance(sources, (list, tuple, set)):
        result["sources"] = sorted({safe_text(str(value))[:200] for value in sources})
    return result


def _clean(value: object, *, key: str = "", depth: int = 0) -> Any:
    if depth > 6 or key.casefold() in _BLOCKED_KEYS:
        return "[REDACTED]"
    if value is None or type(value) in {bool, int, float}:
        return value
    if isinstance(value, str):
        return safe_url(value) if key.endswith("url") else safe_text(value)[:4000]
    if isinstance(value, dict):
        return {str(name)[:100]: _clean(item, key=str(name), depth=depth + 1)
                for name, item in list(value.items())[:200]}
    if isinstance(value, (list, tuple, set)):
        return [_clean(item, key=key, depth=depth + 1) for item in list(value)[:500]]
    return safe_text(str(value))[:1000]


class ReconDiagnostics:
    """Append bounded JSONL events to one scan-local diagnostic file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **details: object) -> None:
        document = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": safe_text(event)[:200],
            "details": _clean(details),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n")
