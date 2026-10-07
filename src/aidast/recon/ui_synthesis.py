"""Bounded client-route synthesis with explicit synthetic provenance."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from html.parser import HTMLParser
from itertools import islice
from urllib.parse import urlsplit

from aidast.recon.judgment import normalize_path

from .tools.passive_declarations import MAX_DECLARATIONS, _candidate, _unique


_SAFE_PATH = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?){0,31}\Z")
_STATIC_SUFFIX = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf)$", re.I,
)


class _NavigationParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.routes: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(key).casefold(): value for key, value in attrs}
        for attribute in ("href", "routerlink", "data-route", "data-href"):
            value = values.get(attribute)
            if isinstance(value, str) and len(self.routes) < MAX_DECLARATIONS:
                self.routes.append((value, self.get_starttag_text() or tag))


def _role_hint(snippet: str) -> str:
    folded = snippet.casefold()
    if any(word in folded for word in ("admin", "administrator", "superuser")):
        return "administrator"
    if any(word in folded for word in (
        "canactivate", "authguard", "authenticated", "requiresauth", "loggedin",
        "permission", "roles:", "role:",
    )):
        return "authenticated"
    return "unknown"


def _synthetic_row(
    reference: str, *, document_url: str, base_url: str, target_policy,
    source_text: str, required_role_hint: str,
) -> dict | None:
    row = _candidate(
        reference, "GET", document_url=document_url, base_url=base_url,
        target_policy=target_policy, kind="synthetic_ui_candidate",
        source="client_ui_synthesis",
    )
    if row is None:
        return None
    path = urlsplit(str(row["url"])).path or "/"
    if not _SAFE_PATH.fullmatch(path) or _STATIC_SUFFIX.search(path):
        return None
    row["evidence"].update({
        "synthesis_kind": "navigation",
        "required_role_hint": required_role_hint,
        "source_document_sha256": hashlib.sha256(source_text.encode()).hexdigest(),
        "verification_reason": "synthetic_ui_route_unrequested",
    })
    return row


def synthesize_client_ui_routes(
    text: str, *, media_type: str, document_url: str, base_url: str,
    target_policy=None, limit: int = 100,
) -> list[dict]:
    """Extract literal UI routes without evaluating code or making requests."""
    cap = max(0, min(100, int(limit)))
    if cap == 0 or not isinstance(text, str) or len(text.encode()) > 2 * 1024 * 1024:
        return []
    candidates: list[dict | None] = []
    media = media_type.split(";", 1)[0].strip().casefold()
    if media in {"text/html", "application/xhtml+xml"}:
        parser = _NavigationParser()
        try:
            parser.feed(text)
        except (AssertionError, ValueError):
            pass
        for reference, snippet in parser.routes:
            candidates.append(_synthetic_row(
                reference, document_url=document_url, base_url=base_url,
                target_policy=target_policy, source_text=text,
                required_role_hint=_role_hint(snippet),
            ))
    if media in {"application/javascript", "text/javascript", "application/x-javascript"}:
        patterns = (
            re.compile(r"\bpath\s*:\s*(['\"])(?P<path>/[^'\"\r\n]{0,1023})\1"),
            re.compile(r"\b(?:routerLink|href)\s*[:,]\s*(['\"])(?P<path>/[^'\"\r\n]{0,1023})\1"),
            re.compile(r"\.navigate(?:ByUrl)?\s*\(\s*(?:\[\s*)?(['\"])(?P<path>/[^'\"\r\n]{0,1023})\1"),
        )
        seen_spans: set[tuple[int, int]] = set()
        for pattern in patterns:
            for match in islice(pattern.finditer(text), cap * 4):
                if match.span("path") in seen_spans:
                    continue
                seen_spans.add(match.span("path"))
                object_start = text.rfind("{", max(0, match.start() - 240), match.start())
                object_end = text.find("}", match.end(), min(len(text), match.end() + 240))
                snippet = (
                    text[object_start:object_end + 1]
                    if object_start >= 0 and object_end >= 0
                    else text[max(0, match.start() - 100):min(len(text), match.end() + 100)]
                )
                candidates.append(_synthetic_row(
                    match["path"], document_url=document_url, base_url=base_url,
                    target_policy=target_policy, source_text=text,
                    required_role_hint=_role_hint(snippet),
                ))
    return _unique(candidates, cap)


def persist_synthetic_ui_candidate(
    conn: sqlite3.Connection, *, scan_id: str, origin_id: str,
    method: str, path: str, source_url: str, evidence: dict,
) -> str:
    source_hash = str(evidence.get("source_document_sha256") or "")
    if not re.fullmatch(r"[a-f0-9]{64}", source_hash):
        source_hash = hashlib.sha256(source_url.encode()).hexdigest()
    normalized = normalize_path(path)
    identity = "\x00".join((origin_id, method, normalized, "navigation", source_hash))
    candidate_id = "synthetic_ui_" + hashlib.sha256(identity.encode()).hexdigest()[:32]
    safe_evidence = {
        "synthesis_kind": "navigation",
        "verification_reason": "synthetic_ui_route_unrequested",
    }
    conn.execute(
        """INSERT OR IGNORE INTO synthetic_ui_candidates
           (candidate_id,scan_id,origin_id,method,normalized_path,candidate_kind,
            required_role_hint,source_url,source_sha256,evidence_json)
           VALUES (?,?,?,?,?,'navigation',?,?,?,?)""",
        (
            candidate_id, scan_id, origin_id, method, normalized,
            str(evidence.get("required_role_hint") or "unknown")[:80],
            source_url[:2048], source_hash,
            json.dumps(safe_evidence, sort_keys=True, separators=(",", ":")),
        ),
    )
    return candidate_id


def reconcile_synthetic_ui_candidates(
    conn: sqlite3.Connection, *, origin_id: str,
) -> int:
    """Promote only candidates backed by a captured target HTTP response."""
    cursor = conn.execute(
        """UPDATE synthetic_ui_candidates AS candidate
           SET state='verified',promoted_endpoint_id=(
                 SELECT e.endpoint_id FROM endpoints e
                 WHERE e.origin_id=candidate.origin_id AND e.method=candidate.method
                   AND e.normalized_path=candidate.normalized_path LIMIT 1
               ),verified_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
           WHERE candidate.origin_id=? AND candidate.state='synthetic'
             AND EXISTS (
               SELECT 1 FROM endpoints e JOIN http_transactions tx
                 ON tx.endpoint_id=e.endpoint_id
               WHERE e.origin_id=candidate.origin_id AND e.method=candidate.method
                 AND e.normalized_path=candidate.normalized_path
                 AND tx.response_status BETWEEN 100 AND 599
             )""",
        (origin_id,),
    )
    return cursor.rowcount
