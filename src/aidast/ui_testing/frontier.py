"""Bounded, policy-agnostic state for ordinary UI exploration."""

from __future__ import annotations

import hashlib
import json
from collections import deque

from aidast.recon.tools.page_identity import canonical_visit_key


def screen_key(url: str, candidates: list[dict]) -> str:
    """Identify visible action state without retaining page text or DOM values."""
    keys = sorted({key for item in candidates[:80]
                   if isinstance(item, dict)
                   if isinstance(key := item.get('key'), str) and 0 < len(key) <= 256})
    payload = json.dumps([canonical_visit_key(url), keys],
                         ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class ExplorerFrontier:
    """Remember attempted actions and bounded GET page visits across one pass."""

    def __init__(self, *, max_pages: int) -> None:
        if type(max_pages) is not int or not 0 <= max_pages <= 100:
            raise ValueError('max_pages must be between 0 and 100')
        self.max_pages = max_pages
        self._pages: deque[str] = deque()
        self._page_keys: set[str] = set()
        self.attempted: set[tuple[str, str]] = set()
        self.retired_screens: set[str] = set()

    @property
    def queued_count(self) -> int:
        return len(self._pages)

    def add_page(self, url: str) -> bool:
        if not isinstance(url, str) or not url:
            return False
        try:
            key = canonical_visit_key(url)
        except ValueError:
            return False
        if key in self._page_keys or len(self._page_keys) >= self.max_pages:
            return False
        self._page_keys.add(key)
        self._pages.append(url)
        return True

    def next_page(self) -> str | None:
        return self._pages.popleft() if self._pages else None

    def untried(self, screen: str, candidates: list[dict]) -> list[dict]:
        if screen in self.retired_screens:
            return []
        offered: list[dict] = []
        seen: set[str] = set()
        for item in candidates:
            if not isinstance(item, dict):
                continue
            key = item.get('key')
            if (not isinstance(key, str) or not 0 < len(key) <= 256
                    or key in seen or (screen, key) in self.attempted):
                continue
            seen.add(key)
            offered.append(item)
        return offered

    def mark_attempted(self, screen: str, candidate_key: str) -> None:
        self.attempted.add((screen, candidate_key))

    def retire_screen(self, screen: str) -> None:
        self.retired_screens.add(screen)
