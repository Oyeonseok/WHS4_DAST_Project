"""Render validation reports with the shared Markdown formatter."""

from __future__ import annotations

from ._render import _cited as _cited, _plain as _plain, render_markdown
from .legacy_models import CitedText as CitedText, ReportDraft


def render_report(draft: ReportDraft) -> str:
    return render_markdown(draft, source=f"Validation: `{draft.validation_id}`")
