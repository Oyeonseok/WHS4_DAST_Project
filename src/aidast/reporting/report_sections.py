"""Reader-facing context shared by local drafts and submission Markdown."""

from __future__ import annotations

import re

from .presentation import _plain


_PLATFORM_NAMES = {
    "hackerone": "HackerOne", "bugcrowd": "Bugcrowd",
    "intigriti": "Intigriti", "generic": "Generic",
}
_MARKER = re.compile(r"\[(?:(?:EMAIL|TOKEN|PATH)_\d+|REDACTED)\]")


def enrich_report(markdown: str, *, platform: str, steps: str, prerequisites: str,
                  expected: str, observed: str, masked_text: str,
                  language: str = "en", platform_shown: bool = False) -> str:
    """Show the actual reproduction sequence and visible redaction markers."""
    ko = language == "ko"
    name = _PLATFORM_NAMES[platform]
    platform_line = ("대상 플랫폼: " if ko else "Target platform: ") + name
    if not platform_shown:
        lines = markdown.split("\n", 1)
        markdown = lines[0] + "\n\n" + platform_line + ("\n" + lines[1] if len(lines) > 1 else "\n")

    step_lines = []
    for line in steps.splitlines():
        match = re.match(r"^(\d+)\.\s+(.*)$", line)
        step_lines.append(f"{match[1]}. {_plain(match[2])}" if match else _plain(line))
    sections = ["## " + ("PoC 재현 과정" if ko else "PoC reproduction process")]
    if prerequisites:
        sections.append(("재현 조건: " if ko else "Prerequisites: ") + _plain(prerequisites))
    sections.append("\n".join(step_lines))
    sections.append(("기대 결과: " if ko else "Expected: ") + _plain(expected))
    sections.append(("관측 결과: " if ko else "Observed: ") + _plain(observed))
    markers = sorted(set(_MARKER.findall(masked_text)), key=lambda value: (
        value.split("_", 1)[0], int(value.rsplit("_", 1)[1][:-1]) if "_" in value else 0))
    sections.append("## " + ("마스킹 표시" if ko else "Masking applied"))
    if markers:
        sections.append(("민감값 대신 표시된 표식: " if ko else "Markers replacing sensitive values: ")
                        + ", ".join(f"`{marker}`" for marker in markers[:16]))
    else:
        sections.append("포함된 내용에는 표시할 마스킹 표식이 없습니다."
                        if ko else "No redaction markers appear in the included content.")
    return markdown.rstrip() + "\n\n" + "\n\n".join(sections) + "\n"
