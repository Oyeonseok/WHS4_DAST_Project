"""Parse upstream benchmark claims without treating them as findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path


_SECTION = re.compile(r"^#{2,6}\s+Implemented Vulnerabilities\s*$", re.I)
_HEADING = re.compile(r"^(?P<level>#{2,6})\s+(?P<title>.+?)\s*$")
_CATEGORY = re.compile(r"^\s*\d+\.\s+\*\*(?P<title>.+?)\*\*\s*$")
_ITEM = re.compile(r"^\s{2,}[-*]\s+(?P<title>.+?)\s*$")


@dataclass(frozen=True, slots=True)
class BenchmarkCatalogItem:
    ordinal: int
    category: str
    title: str
    source_path: str
    source_line: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BenchmarkCatalog:
    source_path: str
    source_sha256: str
    items: tuple[BenchmarkCatalogItem, ...]


def parse_implemented_vulnerabilities(source_root: Path) -> BenchmarkCatalog | None:
    """Return README claims in source order; return ``None`` if no catalog exists.

    These are upstream declarations, not confirmed vulnerabilities. Keeping the
    declarations in Recon.db gives later stages a stable denominator without
    manufacturing an Attack finding or conflating duplicate design flaws.
    """
    root = Path(source_root).expanduser().resolve(strict=True)
    readme = root / "README.md"
    if not readme.is_file():
        return None
    raw = readme.read_bytes()
    lines = raw.decode("utf-8").splitlines()
    in_section = False
    section_level = 0
    category: str | None = None
    items: list[BenchmarkCatalogItem] = []
    for line_number, line in enumerate(lines, start=1):
        if not in_section:
            match = _SECTION.match(line)
            if match:
                in_section = True
                section_level = len(line) - len(line.lstrip("#"))
            continue
        heading = _HEADING.match(line)
        if heading and len(heading.group("level")) <= section_level:
            break
        category_match = _CATEGORY.match(line)
        if category_match:
            category = category_match.group("title").strip()
            continue
        item_match = _ITEM.match(line)
        if item_match and category:
            title = re.sub(r"\s+", " ", item_match.group("title")).strip()
            items.append(BenchmarkCatalogItem(
                ordinal=len(items) + 1,
                category=category,
                title=title,
                source_path="README.md",
                source_line=line_number,
            ))
    if not items:
        return None
    return BenchmarkCatalog(
        source_path="README.md",
        source_sha256=hashlib.sha256(raw).hexdigest(),
        items=tuple(items),
    )
