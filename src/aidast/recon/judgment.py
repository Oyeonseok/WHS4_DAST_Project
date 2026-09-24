"""Normalize/Merge/Rule Engine judgment.

The design docs assign this to an LLM call. For the MVP it's plain
rule-based Python so the pipeline runs end to end without any LLM
dependency.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, unquote, urlsplit

# Katana-style path fingerprinting for values that are unambiguously dynamic.
# The original path is retained on the endpoint record; this pattern only
# controls the deduplication key used by the normalized surface.
PARAM_PATTERN = re.compile(
    r"/\d{10}(?:\d{3})?(?=/|$)"
    r"|/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)"
    r"|/[0-9a-fA-F]{32}(?=/|$)"
    r"|/[0-9a-fA-F]{40}(?=/|$)"
    r"|/[0-9a-fA-F]{64}(?=/|$)"
    r"|/[0-9a-fA-F]{24}(?=/|$)"
    r"|/[0-9a-fA-F]{8,}(?=/|$)"
    r"|/\d+(?=/|$)"
    r"|/(?:19|20)\d{2}[-_]\d{1,2}[-_]\d{1,2}(?=/|$)"
    r"|/(?:19|20)\d{2}\d{2}\d{2}(?=/|$)"
)

_UNRESERVED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
)


def normalize_path(raw_path: str) -> str:
    """Create a conservative Katana-style deduplication fingerprint.

    Numeric, UUID, date, and long-hex path values become ``:id``. Query
    parameters are intentionally not parsed here: they are persisted in the
    parameters table for Attack/IDOR use, while the endpoint surface remains
    URL-level and compact.
    """
    raw = str(raw_path or "")
    # A route beginning with ``//`` is a malformed-but-common crawler path,
    # not a network-path URL; urlsplit would otherwise treat its first segment
    # as the hostname and silently drop it.
    path = (urlsplit(raw).path if not raw.startswith("//") else raw.split("?", 1)[0]) or "/"
    # Decode only unreserved escapes. Reserved delimiters must remain encoded
    # because decoding them can change route semantics.
    path = re.sub(
        r"%([0-9A-Fa-f]{2})",
        lambda m: chr(int(m.group(1), 16)) if chr(int(m.group(1), 16)) in _UNRESERVED else m.group(0).upper(),
        path,
    )
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    normalized = PARAM_PATTERN.sub("/:id", path)
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized or "/"


def query_signature(raw_url: str) -> str:
    """Return a stable query *shape* without persisting values.

    Values are intentionally discarded, while repeated keys retain a count;
    this is the Katana-style distinction between ``?id=1`` and ``?q=x``.
    """
    try:
        query = urlsplit(str(raw_url or "")).query
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    counts: dict[str, int] = defaultdict(int)
    for name, _ in pairs:
        name = unquote(name).strip()
        if name:
            counts[name] += 1
    return "&".join(
        f"{name}{'[]' if count > 1 else ''}"
        for name, count in sorted(counts.items(), key=lambda item: item[0].lower())
    )


def adaptive_path_fingerprints(
    raw_endpoints: list[dict], threshold: int = 5, *, per_method: bool = False,
) -> dict[str | tuple[str, str], str]:
    """Learn variable segments; internal callers keep methods separate."""
    rows: dict[tuple[str, int, tuple[str, ...]], set[str]] = defaultdict(set)
    for item in raw_endpoints:
        path = str(item.get("path") or "").split("?", 1)[0]
        segments = tuple(part for part in path.split("/") if part)
        for index, value in enumerate(segments):
            if index == 0:
                # Sibling pages such as /blog and /register have no stable
                # parent route that identifies them as variable values.
                continue
            key = (str(item.get("method", "GET")).upper(), index, segments[:index] + segments[index + 1:])
            rows[key].add(value)
    learned: dict[str | tuple[str, str], str] = {}
    for item in raw_endpoints:
        raw = str(item.get("path") or "")
        path, _, query = raw.partition("?")
        segments = [part for part in path.split("/") if part]
        for index, value in enumerate(segments):
            if segments[0].lower() in {"api", "rest"}:
                # API resource and action names can have many siblings at
                # any depth. That alone does not prove a segment is an ID.
                # Explicit numeric/UUID IDs are still normalized below.
                continue
            key = (str(item.get("method", "GET")).upper(), index, tuple(segments[:index] + segments[index + 1:]))
            if len(rows[key]) >= threshold and not _looks_static_segment(value):
                segments[index] = ":param"
        key = (str(item.get("method", "GET")).upper(), raw) if per_method else raw
        learned[key] = (
            "/" + "/".join(segments) + (("?" + query) if query else "")
        )
    return learned


def _looks_static_segment(value: str) -> bool:
    return value.lower() in {"api", "v1", "v2", "v3", "users", "user", "items", "products", "search", "login", "admin"}


def is_static_asset(path: str) -> bool:
    try:
        candidate = urlsplit(str(path or "")).path
    except ValueError:
        candidate = str(path or "").split("?", 1)[0]
    return candidate.lower().endswith(STATIC_EXTENSIONS)


def is_probable_redirect_loop_path(path: str) -> bool:
    """Return true for crawler paths produced by a redirect loop.

    This is intentionally target-agnostic: a segment (or short block) must
    repeat at least three times before a candidate is suppressed. Raw proxy
    observations remain stored for diagnostics; this only filters the
    normalized endpoint surface.
    """
    try:
        decoded = path
        for _ in range(2):
            decoded = unquote(decoded)
        segments = [part for part in decoded.split("/") if part]
    except (TypeError, ValueError):
        return False
    if len(segments) < 3:
        return False
    run = 1
    for previous, current in zip(segments, segments[1:]):
        run = run + 1 if previous == current else 1
        if run >= 3:
            return True
    # Also catch alternating loops such as /a/b/a/b/a/b.
    for block_size in (1, 2, 3):
        if len(segments) < block_size * 3:
            continue
        tail = segments[-block_size * 3 :]
        if tail[:block_size] == tail[block_size : 2 * block_size] == tail[2 * block_size :]:
            return True
    return False


def merge_and_normalize(raw_endpoints: list[dict]) -> list[dict]:
    """Merges raw findings from every tool into deduplicated endpoints.

    Static assets are kept but flagged `is_excluded` rather than dropped, so
    the exclusion decision stays auditable.
    """
    merged: dict[tuple[str, str], dict] = {}
    learned = adaptive_path_fingerprints(raw_endpoints, per_method=True)
    for item in raw_endpoints:
        if is_probable_redirect_loop_path(item.get("path", "")):
            continue
        norm_path = normalize_path(learned.get((item["method"].upper(), item["path"]), item["path"]))
        key = (item["method"], norm_path)
        excluded = is_static_asset(item["path"])
        if key not in merged:
            merged[key] = {
                "method": item["method"],
                "path": item["path"],
                "normalized_path": norm_path,
                "content_type": item.get("content_type"),
                "query_signature": query_signature(item.get("url") or item.get("path")),
                "source_tools": {item["source"]},
                "is_excluded": excluded,
                "exclude_reason": "static_asset" if excluded else None,
            }
        else:
            merged[key]["source_tools"].add(item["source"])
    return list(merged.values())
