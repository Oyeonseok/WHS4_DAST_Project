"""Normalize/Merge/Rule Engine judgment.

The design docs assign this to an LLM call. For the MVP it's plain
rule-based Python so the pipeline runs end to end without any LLM
dependency.
"""

from __future__ import annotations

import re

PARAM_PATTERN = re.compile(r"/\d+(?=/|$)|/[0-9a-fA-F]{8,}(?=/|$)")

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
)


def normalize_path(raw_path: str) -> str:
    """`/api/users/123` -> `/api/users/:id` (rule-based, MVP)."""
    return PARAM_PATTERN.sub("/:id", raw_path) or "/"


def is_static_asset(path: str) -> bool:
    return path.lower().endswith(STATIC_EXTENSIONS)


def merge_and_normalize(raw_endpoints: list[dict]) -> list[dict]:
    """Merges raw findings from every tool into deduplicated endpoints.

    Static assets are kept but flagged `is_excluded` rather than dropped, so
    the exclusion decision stays auditable.
    """
    merged: dict[tuple[str, str], dict] = {}
    for item in raw_endpoints:
        norm_path = normalize_path(item["path"])
        key = (item["method"], norm_path)
        excluded = is_static_asset(item["path"])
        if key not in merged:
            merged[key] = {
                "method": item["method"],
                "path": item["path"],
                "normalized_path": norm_path,
                "content_type": item.get("content_type"),
                "source_tools": {item["source"]},
                "is_excluded": excluded,
                "exclude_reason": "static_asset" if excluded else None,
            }
        else:
            merged[key]["source_tools"].add(item["source"])
    return list(merged.values())
