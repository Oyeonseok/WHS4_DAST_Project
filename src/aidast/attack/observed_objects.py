"""Promote bounded object identifiers observed by black-box Recon.

The Attack stage often needs an object that the authenticated browser already
opened (for example, its own basket) plus a public reference object (for
example, a catalog item).  Recon deliberately removes example values from the
parameter table, so recover only short numeric path identifiers from durable
browser/HTTP observations.  No response body, credential, source tree, or
benchmark inventory is consulted here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from urllib.parse import unquote, urlsplit


_PLACEHOLDER = re.compile(r"^(?::([A-Za-z_$][\w$.-]*)|\{([A-Za-z_$][\w$.-]*)\})$")
_SAFE_IDENTIFIER = re.compile(r"^[1-9][0-9]{0,11}$")

# A session-selected shopping container is the only path observation that can
# establish ownership by itself. Visiting a numeric address, card, complaint,
# order, profile, or wallet URL while authenticated proves visibility, not
# ownership, so those resources remain reference-only until the scanner creates
# an object or observes an owned-parent relation.
_OWNED_RESOURCE_MARKERS = frozenset({
    "basket", "baskets", "cart", "carts",
})


def _path_bindings(template: str, observed_url: str) -> list[tuple[str, str, str]]:
    """Return ``(resource, parameter, value)`` for exact numeric path slots."""
    observed_path = unquote(urlsplit(observed_url).path or "/")
    template_parts = [part for part in unquote(template).split("/") if part]
    observed_parts = [part for part in observed_path.split("/") if part]
    if len(template_parts) != len(observed_parts):
        return []
    bindings = []
    for index, (expected, actual) in enumerate(zip(template_parts, observed_parts)):
        match = _PLACEHOLDER.fullmatch(expected)
        if match is None:
            if expected != actual:
                return []
            continue
        if not _SAFE_IDENTIFIER.fullmatch(actual):
            return []
        parameter = match.group(1) or match.group(2)
        resource = template_parts[index - 1].casefold() if index else "object"
        bindings.append((resource, parameter, actual))
    return bindings


def _insert_fact(
    conn: sqlite3.Connection, *, scan_id: str, fact_type: str, fact_key: str,
    fact_value: dict, endpoint_id: str,
) -> int:
    digest = hashlib.sha256(
        json.dumps([scan_id, fact_type, fact_key, fact_value], sort_keys=True).encode()
    ).hexdigest()[:32]
    cursor = conn.execute(
        """INSERT OR IGNORE INTO attack_facts
           (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,source_endpoint_id)
           VALUES (?,?,?,?,?,1.0,?)""",
        (
            "fact_" + digest, scan_id, fact_type, fact_key,
            json.dumps(fact_value, ensure_ascii=False, sort_keys=True), endpoint_id,
        ),
    )
    return int(cursor.rowcount == 1)


def seed_observed_object_facts(conn: sqlite3.Connection, scan_id: str) -> int:
    """Persist value-minimal object facts from this scan's own observations.

    Authenticated UI requests may establish ownership only when their discovery
    context is bound to an authenticated session and a credential reference.
    Independently successful public GET item requests establish existence, not
    ownership, and are exposed to later batches only as context.
    """
    inserted = 0
    owned_parents: dict[tuple[str, str], str] = {}
    owned_rows = conn.execute(
        """SELECT DISTINCT e.endpoint_id,e.normalized_path,eo.observed_url,
                          cr.label
           FROM endpoint_observations eo
           JOIN endpoints e ON e.endpoint_id=eo.endpoint_id
           JOIN discovery_contexts dc ON dc.context_id=eo.context_id
           JOIN sessions s ON s.session_id=dc.session_id
           JOIN credential_references cr
             ON cr.session_id=s.session_id AND cr.scan_id=?
           WHERE e.method='GET' AND s.auth_state='authenticated'
             AND eo.source_tool IN ('playwright','playwright_interaction','auth_bootstrap')
             AND eo.observed_url IS NOT NULL
           ORDER BY e.endpoint_id,eo.observed_url""",
        (scan_id,),
    ).fetchall()
    for row in owned_rows:
        for resource, parameter, value in _path_bindings(
            str(row["normalized_path"]), str(row["observed_url"]),
        ):
            if resource not in _OWNED_RESOURCE_MARKERS:
                continue
            owned_parents[(resource.rstrip("s"), value)] = str(row["label"])
            inserted += _insert_fact(
                conn, scan_id=scan_id, fact_type="owned_test_object",
                fact_key=f"observed.{resource}.{parameter}", endpoint_id=str(row["endpoint_id"]),
                fact_value={
                    "resource": resource, "parameter_name": parameter,
                    "value": value, "credential_label": str(row["label"]),
                    "evidence": "authenticated_browser_path",
                },
            )

    public_rows = conn.execute(
        """SELECT DISTINCT e.endpoint_id,e.normalized_path,h.url
           FROM http_transactions h
           JOIN endpoints e ON e.endpoint_id=h.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? AND e.method='GET'
             AND h.response_status BETWEEN 200 AND 299 AND h.url IS NOT NULL
           ORDER BY e.endpoint_id,h.url""",
        (scan_id,),
    ).fetchall()
    for row in public_rows:
        for resource, parameter, value in _path_bindings(
            str(row["normalized_path"]), str(row["url"]),
        ):
            inserted += _insert_fact(
                conn, scan_id=scan_id, fact_type="observed_reference_object",
                fact_key=f"observed.{resource}.{parameter}.{value}",
                endpoint_id=str(row["endpoint_id"]),
                fact_value={
                    "resource": resource, "parameter_name": parameter,
                    "value": value, "evidence": "successful_blackbox_get",
                },
            )

    # Successful collection reads can supply a distinct reference identifier
    # for a read-only authorization differential. Keep only numeric identifier
    # fields; names, emails, tokens, and every other response value remain in
    # the Recon evidence store.
    collection_rows = conn.execute(
        """SELECT e.endpoint_id,e.normalized_path,h.response_body
           FROM http_transactions h
           JOIN endpoints e ON e.endpoint_id=h.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? AND e.method='GET'
             AND h.response_status BETWEEN 200 AND 299
             AND h.response_body IS NOT NULL
           ORDER BY h.rowid LIMIT 256""",
        (scan_id,),
    ).fetchall()
    reference_values: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in collection_rows:
        raw = row["response_body"]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 512_000:
            continue
        try:
            body = json.loads(raw)
        except (ValueError, TypeError, RecursionError):
            continue
        if isinstance(body, dict):
            for wrapper in ("data", "items", "results", "rows"):
                if wrapper in body:
                    body = body[wrapper]
                    break
        if isinstance(body, dict):
            items = [body]
        elif isinstance(body, list):
            items = body[:32]
        else:
            continue
        resource = next(
            (part.casefold() for part in reversed(str(row["normalized_path"]).split("/"))
             if part and _PLACEHOLDER.fullmatch(part) is None),
            "object",
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            identifiers = {
                name: str(value)
                for name, value in item.items()
                if isinstance(name, str)
                and (name.casefold() == "id" or name.casefold().endswith("id"))
                and isinstance(value, int) and not isinstance(value, bool)
                and _SAFE_IDENTIFIER.fullmatch(str(value))
            }
            child_id = identifiers.get("id")
            if child_id:
                for parent_name, parent_value in identifiers.items():
                    if parent_name == "id":
                        continue
                    parent_resource = parent_name[:-2].casefold().rstrip("s")
                    credential_label = owned_parents.get((parent_resource, parent_value))
                    if credential_label is None:
                        continue
                    inserted += _insert_fact(
                        conn, scan_id=scan_id, fact_type="owned_test_object",
                        fact_key=f"observed.{resource}.id.{child_id}",
                        endpoint_id=str(row["endpoint_id"]),
                        fact_value={
                            "resource": resource, "parameter_name": "id",
                            "value": child_id, "identifiers": identifiers,
                            "credential_label": credential_label,
                            "evidence": "owned_parent_collection_relation",
                        },
                    )
                    break
            for name, value in item.items():
                if not isinstance(name, str) or not (
                    name.casefold() == "id" or name.casefold().endswith("id")
                ):
                    continue
                text = str(value) if isinstance(value, int) and not isinstance(value, bool) else ""
                if not _SAFE_IDENTIFIER.fullmatch(text):
                    continue
                reference_key = (resource, name.casefold())
                if text in reference_values[reference_key]:
                    continue
                if len(reference_values[reference_key]) >= 8:
                    continue
                reference_values[reference_key].add(text)
                inserted += _insert_fact(
                    conn, scan_id=scan_id, fact_type="observed_reference_object",
                    fact_key=f"observed.{resource}.{name}.{text}",
                    endpoint_id=str(row["endpoint_id"]),
                    fact_value={
                        "resource": resource, "parameter_name": name,
                        "value": text,
                        "evidence": "successful_blackbox_collection",
                    },
                )
    return inserted
