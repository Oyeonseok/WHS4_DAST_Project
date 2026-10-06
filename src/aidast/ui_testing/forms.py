"""Synthetic inputs for approved ordinary UI exploration."""

from __future__ import annotations

import re


def synthetic_value(field: dict, scan_id: str) -> str | None:
    """Choose a bounded value from host metadata, never untrusted page content."""
    if not isinstance(field, dict) or field.get('sensitive'):
        return None
    kind = str(field.get('type', '')).lower()
    if kind in {'password', 'file', 'hidden', 'email', 'tel', 'number', 'date'}:
        return None
    role = field.get('role')
    if role == 'search' and kind in {'search', 'text'}:
        return 'test'
    if role == 'project_name' and kind in {'text', 'textarea'}:
        suffix = re.sub(r'[^a-zA-Z0-9]', '', scan_id)[:20]
        return 'AI-Dast-' + (suffix or 'scan')
    return None
