"""Common Markdown formatting for current and legacy local reports."""

from __future__ import annotations

import html
import re

from .legacy_models import CitedText as LegacyCitedText
from .legacy_models import ReportDraft as LegacyReportDraft
from .models import CitedText as CaseCitedText
from .models import ReportDraft as CaseReportDraft

CitedText = CaseCitedText | LegacyCitedText
ReportDraft = CaseReportDraft | LegacyReportDraft


def _plain(value: str) -> str:
    # Captured content is text, never an HTML element, image or clickable URL.
    value = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)


def _cited(value: CitedText) -> str:
    return _plain(value.text) + "\n\nEvidence: " + ", ".join(f"`{item}`" for item in value.evidence_ids)


def render_markdown(draft: ReportDraft, *, source: str, legacy_generic: bool = False) -> str:
    blocks = [f"# {_plain(draft.title.text)}", "Local draft — not submitted.",
              f"Platform: {draft.platform}\n\n{source}",
              "Title evidence: " + ", ".join(f"`{item}`" for item in draft.title.evidence_ids)]

    ptes = draft.platform == "generic" and not legacy_generic
    if ptes:
        blocks.append("Format: PTES-style technical finding")

    def section(heading: str, content: CitedText | str | None, level: int = 2) -> None:
        if content is not None:
            blocks.extend([f"{'#' * level} {heading}", _cited(content) if isinstance(content, CitedText) else content])

    if ptes:
        blocks.extend(["## Executive Summary", _cited(draft.summary), "## Technical Report", "### Assessment Scope"])

    level = 4 if ptes else 2
    section("Target" if draft.platform == "bugcrowd" else "Asset", draft.asset, level)
    if ptes:
        blocks.append("### Vulnerability Assessment")
    section("Vulnerability Type" if draft.platform == "intigriti" else "Weakness", draft.weakness, level)
    section("VRT Category", draft.vrt_category)
    section("Technical Severity" if draft.platform == "bugcrowd" else "Severity", draft.severity, level)
    section("CVSS Vector", draft.cvss_vector, level)
    if not ptes:
        section("Summary" if draft.platform in {"hackerone", "generic"} else "Description", draft.summary)
    else:
        blocks.append("### Exploitation and Confirmation")
    if draft.prerequisites:
        section("Prerequisites", "\n\n".join(_cited(item) for item in draft.prerequisites), level)
    section("Steps to Reproduce", "\n\n".join(
        f"{number}. " + _cited(item).replace("\n", "\n   ")
        for number, item in enumerate(draft.steps_to_reproduce, 1)), level)
    section("Expected Behavior", draft.expected_behavior, level)
    section("Actual Behavior", draft.actual_behavior, level)
    if ptes:
        blocks.append("### Demonstrated Impact")
    section("Demonstrated Impact" if draft.platform == "bugcrowd" else "Impact", draft.impact, level)
    if ptes:
        blocks.append("### Remediation Recommendations")
    section("Recommended Solution" if draft.platform == "intigriti" else "Recommended Fix",
            None if draft.remediation is None else _plain(draft.remediation), level)
    if draft.attachment_evidence_ids:
        section("Supporting Materials" if draft.platform == "hackerone" else "Attachments",
                "Evidence references only; files are not uploaded.\n\n" + "\n".join(
                    f"- `{item}`" for item in draft.attachment_evidence_ids))
    blocks.extend(["## Source Binding", f"Context SHA-256: `{draft.source_context_sha256}`"])
    return "\n\n".join(blocks) + "\n"
