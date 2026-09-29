"""Read non-secret request defaults from the verified Recon copy in Pipeline.db."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def recon_user_agent(db_path: Path, *, scan_id: str, url: str) -> str | None:
    """Prefer a successful browser navigation on this scan's exact origin.

    HTTP transactions already survive materialization. Only their User-Agent
    is inherited; observed credentials and other headers are never replayed.
    Transactions without either an origin or endpoint link can be attributed
    only in a single-scan DB.
    """
    destination = _origin(url)
    if destination is None:
        return None
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        origins = conn.execute(
            """SELECT o.base_url FROM origins o JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=?""", (scan_id,),
        )
        if not any(_origin(row[0]) == destination for row in origins):
            return None
        single_scan = conn.execute("SELECT scan_id FROM scans").fetchall() == [(scan_id,)]
        transactions = conn.execute(
            """SELECT h.url,h.request_headers,o.base_url FROM http_transactions h
               LEFT JOIN endpoints e ON e.endpoint_id=h.endpoint_id
               LEFT JOIN origins o ON o.origin_id=coalesce(h.origin_id,e.origin_id)
               LEFT JOIN assets a ON a.asset_id=o.asset_id
               LEFT JOIN origins eo ON eo.origin_id=e.origin_id
               LEFT JOIN assets ea ON ea.asset_id=eo.asset_id
               WHERE h.response_status BETWEEN 200 AND 399
                 AND ((a.scan_id=? AND (h.endpoint_id IS NULL OR ea.scan_id=?))
                      OR (h.origin_id IS NULL AND h.endpoint_id IS NULL AND ?))
               ORDER BY (h.response_status BETWEEN 200 AND 299) DESC,
                        h.captured_at DESC,h.rowid DESC""",
            (scan_id, scan_id, single_scan),
        )
        selected = None
        priority = -1
        for recorded_url, raw_headers, recorded_origin in transactions:
            if _origin(recorded_url) != destination:
                continue
            if recorded_origin is not None and _origin(recorded_origin) != destination:
                continue
            try:
                headers = json.loads(raw_headers or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(headers, dict):
                continue
            headers = {name.casefold(): value for name, value in headers.items()}
            user_agent = headers.get("user-agent")
            if (not isinstance(user_agent, str) or not user_agent.strip()
                    or len(user_agent) > 4096 or "[REDACTED]" in user_agent
                    or any(ord(char) < 32 or ord(char) == 127 for char in user_agent)):
                continue
            try:
                user_agent.encode("latin-1")
            except UnicodeEncodeError:
                continue
            candidate_priority = (
                2 if headers.get("sec-fetch-mode") == "navigate"
                else 1 if "sec-fetch-mode" in headers or "sec-ch-ua" in headers
                else 0
            )
            if candidate_priority > priority:
                selected, priority = user_agent, candidate_priority
                if priority == 2:
                    break
        return selected
