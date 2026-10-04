"""Deterministic endpoint-by-vulnerability Attack coverage ledger."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from urllib.parse import parse_qsl
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.lifecycle import create_task
from aidast.recon.db import new_id, now
from aidast.validation.contracts.models import ValidationError
from aidast.validation.execution.credentials import PipelineCredentialResolver
from aidast.validation.persistence.evidence_policy import sanitize_metadata
from aidast.attack.surface import ATTACK_ELIGIBLE_ENDPOINT_SQL
from aidast.attack.observed_objects import seed_observed_object_facts


VULNERABILITY_SKILLS: dict[str, str] = {
    "api_misconfig": "hunt-api-misconfig",
    "auth_bypass": "hunt-auth-bypass",
    "brute_force": "hunt-brute-force",
    "business_logic": "hunt-business-logic",
    "cors": "hunt-cors",
    "csrf": "hunt-csrf",
    "file_upload": "hunt-file-upload",
    "idor": "hunt-idor",
    "graphql": "hunt-graphql",
    "jwt_crypto": "hunt-jwt-crypto",
    "lfi": "hunt-lfi",
    "llm_ai": "hunt-llm-ai",
    "race_condition": "hunt-race-condition",
    "session": "hunt-session",
    "open_redirect": "hunt-open-redirect",
    "host_header": "hunt-host-header",
    "websocket": "hunt-websocket",
    "grpc": "hunt-grpc",
    "oauth": "hunt-oauth",
    "spa_api": "hunt-spa-api",
    "source_artifacts": "hunt-source-leak",
    "cloud_misconfig": "hunt-cloud-misconfig",
    # The source importer uses source_leak for response-side information
    # disclosure, debug output, and detailed errors. hunt-source-leak is limited
    # to build/source artifacts, so the broader misc workflow is the correct
    # execution contract for these imported signals.
    "source_leak": "hunt-misc",
    "sqli": "hunt-sqli",
    "ssrf": "hunt-ssrf",
    "xss": "hunt-xss",
}

def hypothesis_skill_catalog() -> dict[str, str]:
    """Include every installed vulnerability Skill without a global type cap."""
    from aidast.attack.skill_selector import available_attack_skill_names
    available = set(available_attack_skill_names()) - {'hunt-dispatch'}
    catalog = {name: skill for name, skill in VULNERABILITY_SKILLS.items() if skill in available}
    for skill in sorted(available):
        name = skill.removeprefix('hunt-').replace('-', '_')
        if skill not in catalog.values():
            catalog.setdefault(name, skill)
    return catalog


RETRYABLE_STATUSES = frozenset({"pending", "error_retryable"})
TERMINAL_STATUSES = frozenset({
    "tested_negative", "candidate", "confirmed", "blocked_auth",
    "policy_excluded", "unsupported", "error_terminal",
})

_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({
        "running", "blocked_auth", "policy_excluded", "unsupported",
    }),
    "error_retryable": frozenset({"running", "blocked_auth", "error_terminal"}),
    "running": frozenset({
        "tested_negative", "candidate", "blocked_auth", "policy_excluded",
        "unsupported", "error_retryable", "error_terminal",
    }),
    "candidate": frozenset({"confirmed", "pending"}),
    # Validation is authoritative and may revalidate a previously confirmed
    # case after the target or its evidence changes.
    "confirmed": frozenset({"candidate"}),
    "blocked_auth": frozenset({"pending", "unsupported"}),
}


@dataclass(frozen=True)
class CoverageManifestResult:
    scan_id: str
    total: int
    inserted: int
    existing: int
    by_vulnerability: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageStatus:
    scan_id: str
    total: int
    by_status: dict[str, int]
    by_vulnerability: dict[str, dict[str, int]]
    disposition_coverage: float
    executable_coverage: float
    validation_coverage: float
    unfinished: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _open_database(path: Path) -> sqlite3.Connection:
    database = Path(path).expanduser().resolve(strict=True)
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    migrate_live_pipeline_schema(conn)
    return conn


def resolve_abandoned_attack_leads(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Close unpromoted leads owned by terminal failed/cancelled stages.

    An interrupted native agent can persist a lead and then disappear before
    writing either a Finding or an explicit resolution.  Its task can no
    longer be resumed because stage/task leases are immutable.  Preserve the
    attempt and its HTTP evidence, but close the non-terminal interpretation as
    inconclusive so a fresh coverage task can replay the hypothesis.
    """
    cursor = conn.execute(
        """UPDATE attack_attempts
           SET outcome='inconclusive',
               resolution_reason='owning Attack stage ended before the lead was promoted; coverage retry must obtain fresh evidence',
               resolved_at=CURRENT_TIMESTAMP
           WHERE scan_id=? AND outcome='lead' AND finding_id IS NULL
             AND resolved_at IS NULL AND task_id IN (
               SELECT t.task_id FROM attack_tasks t
               JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
               WHERE t.scan_id=? AND s.status IN ('failed','cancelled')
             )""",
        (scan_id, scan_id),
    )
    return cursor.rowcount


def _select_parameter(
    vuln_class: str, parameters: Iterable[sqlite3.Row]
) -> tuple[str, str]:
    candidates = list(parameters)
    if not candidates:
        return "endpoint", ""
    hints = {
        "sqli": ("search", "query", "filter", "sort", "where", "id", "number", "username"),
        "idor": ("id", "identifier", "account", "user", "card", "loan", "transaction"),
        "ssrf": ("url", "uri", "host", "callback", "webhook"),
        "xss": ("message", "description", "name", "query", "search", "comment"),
        "file_upload": ("file", "upload", "image", "avatar", "picture"),
        "lfi": ("file", "path", "folder", "template", "name"),
        "auth_bypass": ("role", "admin", "user", "token", "username", "password"),
        "jwt_crypto": ("token", "jwt", "authorization"),
        # Rate-limit annotations on recovery endpoints must exercise the
        # verifier secret, not an unrelated replacement value. Keeping these
        # hints here also makes OTP/code endpoints deterministic when Recon
        # exposes several body fields.
        "brute_force": ("pin", "otp", "code", "token", "password", "username"),
        "race_condition": ("id", "loan", "payment", "transfer", "amount"),
    }.get(vuln_class, ())

    def score(row: sqlite3.Row) -> tuple[int, int, str, str]:
        text = " ".join(str(row[key] or "").casefold() for key in (
            "name", "location", "role", "data_type",
        ))
        name = str(row["name"] or "").casefold()
        hint_score = max((
            (len(hints) - index) * 10
            + (100 if name == hint or name.endswith(f"_{hint}") else 0)
            for index, hint in enumerate(hints) if hint in text
        ), default=0)
        identifier_score = 5 if row["is_identifier"] else 0
        location_score = {"path": 4, "query": 3, "json": 2, "form": 1}.get(
            str(row["location"]), 0,
        )
        return (-hint_score - identifier_score, -location_score,
                str(row["location"]), str(row["name"]))

    selected = sorted(candidates, key=score)[0]
    return str(selected["location"]), str(selected["name"])


def _parameter_candidates(
    conn: sqlite3.Connection, endpoint_id: str, vuln_class: str,
) -> list[dict[str, Any]]:
    """Expose every Recon parameter while retaining one deterministic preference.

    A coverage task is a vulnerability hypothesis for an endpoint, not a promise
    that the first lexically selected field is the sink.  The previous single
    field projection hid useful DB evidence from the Attack Agent and caused
    false ``unsupported`` dispositions.  Values remain absent: this is schema
    metadata only.
    """
    rows = conn.execute(
        """SELECT name,location,role,data_type,is_identifier
           FROM parameters WHERE endpoint_id=? ORDER BY location,name""",
        (endpoint_id,),
    ).fetchall()
    preferred_location, preferred_name = _select_parameter(vuln_class, rows)
    return [
        {
            "name": str(row["name"]),
            "location": str(row["location"]),
            "role": str(row["role"] or "unknown"),
            "data_type": str(row["data_type"] or "string"),
            "is_identifier": bool(row["is_identifier"]),
            "preferred": (
                str(row["location"]) == preferred_location
                and str(row["name"]) == preferred_name
            ),
        }
        for row in rows
    ]


def _source_context(
    conn: sqlite3.Connection, endpoint_id: str, annotation_id: str,
) -> dict[str, Any]:
    """Return bounded, untrusted Recon evidence for one coverage task."""
    annotation = conn.execute(
        """SELECT category,tag,rationale FROM endpoint_annotations
           WHERE annotation_id=?""",
        (annotation_id,),
    ).fetchone()
    active = dict(annotation) if annotation is not None else None
    if active and active['category'] == 'attack_hypothesis':
        metadata = json.loads(active['rationale'])
        active['rationale'] = str(metadata.get('rationale', ''))[:2000]
        active['hypothesis_only'] = True
        active['grounding_annotation_ids'] = metadata.get('grounding_annotation_ids', [])
    elif active:
        active['rationale'] = str(active['rationale'])[:2000]
    related = conn.execute(
        """SELECT an.category,an.tag,an.rationale
           FROM endpoint_annotations an
           JOIN endpoint_observations eo ON eo.observation_id=an.observation_id
           WHERE eo.endpoint_id=? AND an.annotation_id<>? AND an.category<>'attack_hypothesis'
           ORDER BY an.category,an.tag LIMIT 32""",
        (endpoint_id, annotation_id),
    ).fetchall()
    declarations: list[dict[str, Any]] = []
    declaration_seen: set[str] = set()
    for row in conn.execute(
        """SELECT source_tool,evidence_json FROM endpoint_observations
           WHERE endpoint_id=? AND discovery_kind='api_spec_declaration'
           ORDER BY observation_id LIMIT 16""",
        (endpoint_id,),
    ):
        try:
            evidence = json.loads(row["evidence_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(evidence, dict):
            continue
        declaration: dict[str, Any] = {"source_tool": str(row["source_tool"])[:128]}
        for key, limit in (("operation_summary", 1000), ("operation_description", 2000)):
            value = evidence.get(key)
            if isinstance(value, str) and value.strip():
                declaration[key] = value[:limit]
        tags = evidence.get("operation_tags")
        if isinstance(tags, list):
            declaration["operation_tags"] = [
                item[:100] for item in tags[:20] if isinstance(item, str)
            ]
        if len(declaration) == 1:
            continue
        try:
            declaration = sanitize_metadata(declaration, max_bytes=4096)
        except ValidationError:
            continue
        fingerprint = json.dumps(
            declaration, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        if fingerprint in declaration_seen:
            continue
        declaration_seen.add(fingerprint)
        declarations.append(declaration)
        if len(declarations) >= 4:
            break
    return {
        "active_annotation": active,
        "related_annotations": [
            {
                "category": str(row["category"]),
                "tag": str(row["tag"]),
                "rationale": str(row["rationale"])[:1000],
            }
            for row in related
        ],
        # Public API prose is untrusted prioritization context.  It can suggest
        # a concrete differential, but never counts as vulnerability evidence.
        "public_api_declarations": declarations,
        "request_shapes": _request_shapes(conn, endpoint_id),
    }


def _value_shape(value: Any, *, depth: int = 0) -> Any:
    """Describe captured input structure without copying any captured value."""
    if depth >= 3:
        return "nested"
    if isinstance(value, dict):
        return {
            str(key)[:128]: _value_shape(child, depth=depth + 1)
            for key, child in list(value.items())[:64]
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "item": _value_shape(value[0], depth=depth + 1) if value else "unknown",
        }
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _request_shapes(conn: sqlite3.Connection, endpoint_id: str) -> list[dict[str, Any]]:
    """Project bounded JSON/form field shapes from black-box Recon evidence.

    Captured values, headers, receipts, and full bodies are intentionally never
    returned.  Attack receives enough structure to build a legitimate request
    while credentials and personal data remain confined to Recon.db.  If no
    browser transaction supplied a body, names lexically declared by a public
    client bundle or form remain usable as a value-free request schema.
    """
    rows = conn.execute(
        """SELECT method,substr(request_headers,1,131072) request_headers,
                  substr(request_body,1,131072) request_body
           FROM http_transactions
           WHERE endpoint_id=? AND request_body IS NOT NULL
           ORDER BY captured_at DESC,http_transaction_id DESC LIMIT 16""",
        (endpoint_id,),
    ).fetchall()
    shapes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        raw = row["request_body"]
        if isinstance(raw, bytes):
            raw = raw[:131072].decode("utf-8", errors="replace")
        text = str(raw)[:131072]
        try:
            # http_transactions.content_type describes the response. A JSON
            # response does not establish that the request was encoded as JSON.
            headers = json.loads(row["request_headers"] or "{}")
            if not isinstance(headers, dict):
                continue
            media_types = {
                value.split(";", 1)[0].strip().lower()
                for name, value in headers.items()
                if isinstance(name, str) and name.casefold() == "content-type"
                and isinstance(value, str)
            }
            if len(media_types) > 1 or any(
                not isinstance(value, str)
                for name, value in headers.items()
                if name.casefold() == "content-type"
            ):
                continue
            content_type = next(iter(media_types), "")
            if content_type == "application/json" or (
                content_type.startswith("application/") and content_type.endswith("+json")
            ) or (
                not content_type and text.lstrip().startswith(("{", "["))
            ):
                fields = _value_shape(json.loads(text))
                encoding = "json"
            elif content_type == "application/x-www-form-urlencoded" and all(
                "=" in part for part in text.split("&")
            ):
                fields = {
                    str(key)[:128]: "string"
                    for key, _ in parse_qsl(text, keep_blank_values=True)[:64]
                }
                encoding = "form"
            else:
                continue
        except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
            continue
        method = str(row["method"] or "").upper()
        fingerprint = json.dumps(
            [method, encoding, fields], sort_keys=True, separators=(",", ":"),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        shapes.append({
            "method": method,
            "encoding": encoding,
            "fields": fields,
        })
        if len(shapes) >= 4:
            break
    # Captured traffic is stronger evidence than a static declaration. Do not
    # mix a possibly stale declared method with an observed request body.
    if shapes:
        return shapes
    try:
        declared = conn.execute(
            """SELECT e.method,p.location,p.name,p.data_type
               FROM endpoints e JOIN parameters p ON p.endpoint_id=e.endpoint_id
               WHERE e.endpoint_id=? AND p.location IN ('json','form')
               ORDER BY p.location,p.name LIMIT 128""",
            (endpoint_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        # Small callers and legacy read-only fixtures may contain only the
        # traffic table. The migrated production schema always has both.
        declared = []
    grouped: dict[tuple[str, str], dict[str, str]] = {}
    for row in declared:
        method = str(row["method"] or "").upper()
        encoding = str(row["location"])
        data_type = str(row["data_type"] or "string")
        if data_type == "integer":
            data_type = "number"
        if data_type not in {"string", "number", "boolean", "array", "object"}:
            data_type = "string"
        fields = grouped.setdefault((method, encoding), {})
        if len(fields) < 64:
            fields[str(row["name"])[:128]] = data_type
    for (method, encoding), fields in grouped.items():
        fingerprint = json.dumps(
            [method, encoding, fields], sort_keys=True, separators=(",", ":"),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        shapes.append({"method": method, "encoding": encoding, "fields": fields})
        if len(shapes) >= 4:
            break
    if shapes:
        return shapes

    # A public collection response is also black-box schema evidence.  Reuse
    # field names and primitive/container types only when the write route has
    # the same origin and collection path (or a single terminal item
    # placeholder). Values never leave Recon.db.  This covers generic SPA API
    # clients that pass an opaque object variable to post/put/patch, so the
    # client bundle proves the route while the observed GET proves its shape.
    try:
        endpoint = conn.execute(
            "SELECT origin_id,method,normalized_path FROM endpoints WHERE endpoint_id=?",
            (endpoint_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return shapes
    if endpoint is None or str(endpoint["method"]).upper() not in {"POST", "PUT", "PATCH"}:
        return shapes
    normalized_path = str(endpoint["normalized_path"] or "/")
    collection_path = re.sub(r"/\{[A-Za-z_$][\w$.-]*\}/?$", "", normalized_path) or "/"
    try:
        response_rows = conn.execute(
            """SELECT h.response_body
               FROM http_transactions h
               JOIN endpoints observed ON observed.endpoint_id=h.endpoint_id
               WHERE observed.origin_id=? AND observed.method='GET'
                 AND observed.normalized_path IN (?,?)
                 AND h.response_status BETWEEN 200 AND 299
                 AND h.response_body IS NOT NULL
               ORDER BY h.captured_at DESC LIMIT 8""",
            (endpoint["origin_id"], normalized_path, collection_path),
        ).fetchall()
    except sqlite3.OperationalError:
        return shapes

    def response_object(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        for wrapper in ("data", "items", "results", "rows"):
            if wrapper not in value:
                continue
            wrapped = value.get(wrapper)
            if isinstance(wrapped, dict):
                return wrapped
            if isinstance(wrapped, list):
                return next((item for item in wrapped if isinstance(item, dict)), None)
            # A named collection envelope containing a scalar/null does not
            # describe request fields. Do not reinterpret status/error wrapper
            # keys as a body schema.
            return None
        return value

    fields: dict[str, str] = {}
    for row in response_rows:
        raw = row[0]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str) or len(raw) > 200_000:
            continue
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            continue
        item = response_object(value)
        if item is None:
            continue
        for name, field_value in item.items():
            if (not isinstance(name, str) or not name or len(name) > 128
                    or name in {"createdAt", "updatedAt", "deletedAt"}):
                continue
            field_type = (
                "object" if isinstance(field_value, dict)
                else "array" if isinstance(field_value, list)
                else "boolean" if isinstance(field_value, bool)
                else "number" if isinstance(field_value, (int, float))
                else "string"
            )
            fields.setdefault(name, field_type)
            if len(fields) >= 64:
                break
        if fields:
            break
    if fields:
        shapes.append({
            "method": str(endpoint["method"]).upper(),
            "encoding": "json",
            "fields": dict(sorted(fields.items())),
            "evidence": "observed_collection_response_schema",
        })
    return shapes


def _source_assisted_scan(conn: sqlite3.Connection, scan_id: str) -> bool:
    """Return whether this scan explicitly opted into source-assisted execution."""
    row = conn.execute(
        "SELECT scope_type FROM scans WHERE scan_id=?", (scan_id,),
    ).fetchone()
    return row is not None and str(row[0]) == "source_import"


def _backfill_public_api_operation_metadata(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Link operation prose from a captured public OpenAPI document.

    Some Recon producers persisted the full public specification response but
    only a route marker on each declaration observation.  Recover bounded
    summary/description/tag fields from that already captured black-box
    artifact; never read source code or a benchmark answer database.
    """
    documents: list[dict[str, Any]] = []
    for row in conn.execute(
        """SELECT h.response_body FROM http_transactions h
           JOIN endpoints e ON e.endpoint_id=h.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? AND h.response_status BETWEEN 200 AND 299
             AND length(h.response_body) BETWEEN 2 AND 2000000
             AND (lower(h.url) LIKE '%openapi%.json%'
                  OR lower(h.url) LIKE '%swagger%.json%')
           ORDER BY h.captured_at,h.http_transaction_id LIMIT 8""",
        (scan_id,),
    ):
        raw = row[0]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            document = json.loads(raw)
        except (TypeError, ValueError, RecursionError):
            continue
        if isinstance(document, dict) and isinstance(document.get("paths"), dict):
            documents.append(document)
    if not documents:
        return 0
    updated = 0
    endpoints = conn.execute(
        """SELECT e.endpoint_id,e.method,e.normalized_path
           FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?""",
        (scan_id,),
    ).fetchall()
    for endpoint in endpoints:
        operation = None
        for document in documents:
            path_item = document["paths"].get(str(endpoint["normalized_path"]))
            if isinstance(path_item, dict):
                candidate = path_item.get(str(endpoint["method"]).casefold())
                if isinstance(candidate, dict):
                    operation = candidate
                    break
        if operation is None:
            continue
        addition: dict[str, Any] = {}
        for key, limit in (("summary", 1000), ("description", 2000)):
            value = operation.get(key)
            if isinstance(value, str) and value.strip():
                addition[f"operation_{key}"] = value[:limit]
        tags = operation.get("tags")
        if isinstance(tags, list):
            addition["operation_tags"] = [
                item[:100] for item in tags[:20] if isinstance(item, str)
            ]
        if not addition:
            continue
        try:
            addition = sanitize_metadata(addition, max_bytes=4096)
        except ValidationError:
            continue
        for observation in conn.execute(
            """SELECT observation_id,evidence_json FROM endpoint_observations
               WHERE endpoint_id=? AND discovery_kind='api_spec_declaration'""",
            (endpoint["endpoint_id"],),
        ).fetchall():
            try:
                evidence = json.loads(observation["evidence_json"] or "{}")
            except (TypeError, ValueError):
                evidence = {}
            if not isinstance(evidence, dict) or all(
                evidence.get(key) == value for key, value in addition.items()
            ):
                continue
            evidence.update(addition)
            conn.execute(
                "UPDATE endpoint_observations SET evidence_json=? WHERE observation_id=?",
                (
                    json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                    observation["observation_id"],
                ),
            )
            updated += 1
    return updated


def ensure_coverage_manifest(database: Path, scan_id: str) -> CoverageManifestResult:
    """Create durable coverage from runtime hypotheses or an explicit source import."""
    with closing(_open_database(database)) as conn, conn:
        scan = conn.execute(
            "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,),
        ).fetchone()
        if scan is None or scan["status"] != "completed" or not scan["finished_at"]:
            raise ValueError("coverage planning requires a completed Recon scan")
        _backfill_public_api_operation_metadata(conn, scan_id)
        # Preserve the minimum object identifiers already demonstrated by this
        # scan's authenticated UI and successful GET traffic. This closes the
        # Recon-to-Attack handoff without importing a source/benchmark answer.
        seed_observed_object_facts(conn, scan_id)
        annotation_categories = (
            ("source_vulnerability", "benchmark_catalog_vulnerability", "attack_hypothesis")
            if _source_assisted_scan(conn, scan_id)
            else ("attack_hypothesis",)
        )
        placeholders = ",".join("?" for _ in annotation_categories)
        rows = conn.execute(
            f"""SELECT an.annotation_id,an.tag,an.category,an.rationale,e.endpoint_id,e.method,
                      e.normalized_path,COALESCE(e.auth_required,0) auth_required
               FROM endpoint_annotations an
               JOIN endpoint_observations eo ON eo.observation_id=an.observation_id
               JOIN annotation_runs ar ON ar.annotation_run_id=an.annotation_run_id
               JOIN endpoints e ON e.endpoint_id=eo.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND ar.scan_id=? AND ar.status='completed'
                 AND an.category IN ({placeholders})
                 AND {ATTACK_ELIGIBLE_ENDPOINT_SQL}
               ORDER BY e.endpoint_id,an.tag,an.annotation_id""",
            (scan_id, scan_id, *annotation_categories),
        ).fetchall()
        planning_skills = hypothesis_skill_catalog()
        inserted = 0
        counts: Counter[str] = Counter()
        for row in rows:
            vuln_class = str(row["tag"]).casefold()
            skill_name = VULNERABILITY_SKILLS.get(vuln_class, "hunt-misc")
            parameter_candidates = _parameter_candidates(
                conn, str(row["endpoint_id"]), vuln_class,
            )
            preferred = next(
                (item for item in parameter_candidates if item["preferred"]), None,
            )
            location = str(preferred["location"]) if preferred else "endpoint"
            parameter = str(preferred["name"]) if preferred else ""
            identity = "authenticated" if row["auth_required"] else "unauthenticated"
            if row['category'] == 'attack_hypothesis':
                metadata = json.loads(row['rationale'])
                if (metadata.get('scan_id') != scan_id or metadata.get('endpoint_id') != row['endpoint_id']
                        or metadata.get('vuln_class') != vuln_class or metadata.get('hypothesis_only') is not True
                        or vuln_class not in planning_skills):
                    raise ValueError('Invalid endpoint hypothesis binding')
                skill_name = planning_skills[vuln_class]
                location, parameter = metadata['injection_location'], metadata['parameter_name']
                identity = metadata['required_identity_role']
                if identity not in {'authenticated', 'unauthenticated'} or ((location, parameter) != ('endpoint', '')
                        and (location, parameter) not in {(item['location'], item['name']) for item in parameter_candidates}):
                    raise ValueError('Invalid endpoint hypothesis parameter or identity')
            key_fields = {
                "scan_id": scan_id,
                "endpoint_id": row["endpoint_id"],
                "annotation_id": row["annotation_id"],
                "vuln_class": vuln_class,
                "injection_location": location,
                "parameter_name": parameter,
                "required_identity_role": identity,
            }
            coverage_key = _canonical_digest(key_fields)
            cursor = conn.execute(
                """INSERT OR IGNORE INTO attack_coverage_items
                   (coverage_id,coverage_key,scan_id,endpoint_id,annotation_id,
                    vuln_class,skill_name,injection_location,parameter_name,
                    required_identity_role,status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'pending')""",
                (
                    "coverage_" + coverage_key[:32], coverage_key, scan_id,
                    row["endpoint_id"], row["annotation_id"], vuln_class,
                    skill_name, location, parameter, identity,
                ),
            )
            inserted += cursor.rowcount
            counts[vuln_class] += 1
        requeue_unreplayable_candidates(conn, scan_id)
        _adopt_existing_findings(conn, scan_id)
        reclassify_misclassified_auth_blockers(conn, scan_id)
        requeue_credential_blocked_coverage(conn, scan_id)
        requeue_new_disposable_identity_coverage(conn, scan_id)
        requeue_owned_object_coverage(conn, scan_id)
        requeue_safe_session_binding_coverage(conn, scan_id)
        requeue_auth_gated_negative_coverage(conn, scan_id)
        requeue_redacted_login_differential_coverage(conn, scan_id)
        refresh_confirmed_coverage(conn, scan_id)
        total = conn.execute(
            "SELECT count(*) FROM attack_coverage_items WHERE scan_id=?", (scan_id,),
        ).fetchone()[0]
        return CoverageManifestResult(
            scan_id=scan_id, total=total, inserted=inserted,
            existing=total - inserted, by_vulnerability=dict(sorted(counts.items())),
        )


def _credential_references(
    conn: sqlite3.Connection, scan_id: str, required_role: str, *,
    available_only: bool = False, origin_url: str | None = None,
) -> list[dict[str, str]]:
    if required_role == "unauthenticated":
        return []
    rows = conn.execute(
        """SELECT c.credential_reference_id,c.label,c.identity_role,o.base_url
           FROM credential_references c
           LEFT JOIN sessions s ON s.session_id=c.session_id
           LEFT JOIN origins o ON o.origin_id=s.origin_id
           WHERE c.scan_id=?
           ORDER BY c.identity_role,c.label,c.credential_reference_id""",
        (scan_id,),
    ).fetchall()
    compatible = []
    resolver = None
    if available_only:
        database_path = Path(str(conn.execute("PRAGMA database_list").fetchone()[2]))
        resolver = PipelineCredentialResolver(
            database_path, browser_sessions=origin_url is not None,
        )
    for row in rows:
        role = str(row["identity_role"])
        if required_role not in {"authenticated", "unknown"} and role not in {
            required_role, "authenticated",
        }:
            continue
        if origin_url is not None and row["base_url"] is not None:
            source, destination = urlsplit(str(row["base_url"])), urlsplit(origin_url)
            source_origin = (source.scheme, source.hostname,
                             source.port or (443 if source.scheme == "https" else 80))
            destination_origin = (destination.scheme, destination.hostname,
                                  destination.port or (443 if destination.scheme == "https" else 80))
            if source_origin != destination_origin:
                continue
        item = {
            "credential_reference_id": str(row["credential_reference_id"]),
            "label": str(row["label"]),
            "identity_role": role,
        }
        if resolver is not None and resolver.unsupported_reason(
            item["credential_reference_id"], destination_url=origin_url,
        ) is not None:
            continue
        compatible.append(item)
    return compatible


def _credential_role(vuln_class: str, required_role: str) -> str:
    # Recon cannot reliably infer authentication requirements for passive API
    # declarations and unexecuted mutations.  Give every Attack task the
    # available same-origin opaque session references as optional controls.
    # This does not change ``required_identity_role`` or authorize a request:
    # unauthenticated baselines remain unauthenticated, while the broker still
    # checks every exact request.  It lets a task bind a supplied synthetic
    # account when the live endpoint turns out to require login instead of
    # incorrectly reporting that no safe owned identity exists.
    return "authenticated"


def _execution_identity_role(
    *, method: str, normalized_path: str, planned_role: str,
    credential_references: list[dict[str, str]],
    test_fixtures: list[dict[str, Any]],
) -> str:
    """Bind a passive anonymous declaration to a safe disposable identity.

    API specifications often omit authentication metadata.  For a narrow
    reversible local mutation, an anonymous task that has a same-origin
    scanner-created account should execute as authenticated instead of being
    skipped after the live endpoint returns 401.  The original planned role is
    retained separately on the task for auditability.
    """
    if (
        planned_role != "unauthenticated"
        or method not in {"POST", "PUT", "PATCH"}
        or normalized_path.rstrip("/") not in {
            "/upload_profile_picture", "/upload_profile_picture_url",
            "/api/ai/chat",
        }
    ):
        return planned_role
    synthetic_labels = {
        item.get("label") for item in credential_references
        if item.get("identity_role") == "identity_synthetic"
    }
    if not synthetic_labels:
        return planned_role
    for fixture in test_fixtures:
        value = fixture.get("fact_value")
        if (
            fixture.get("fact_type") == "owned_test_object"
            and isinstance(value, dict)
            and value.get("credential_label") in synthetic_labels
            and value.get("resource") == "account"
            and value.get("disposable") is True
            and value.get("cleanup_allowed") is True
        ):
            return "authenticated"
    return planned_role


def _task_fixtures(
    conn: sqlite3.Connection, scan_id: str, *, parameter_name: str,
) -> list[dict[str, Any]]:
    """Return bounded, non-secret fixture facts relevant to one coverage task."""
    fact_types = (
        ("owned_test_object", "benchmark_fixture")
        if _source_assisted_scan(conn, scan_id)
        else ("owned_test_object",)
    )
    placeholders = ",".join("?" for _ in fact_types)
    rows = conn.execute(
        f"""SELECT fact_type,fact_key,fact_value,confidence
           FROM attack_facts
           WHERE scan_id=? AND fact_type IN ({placeholders})
           ORDER BY CASE WHEN fact_key LIKE ? THEN 0 ELSE 1 END,
                    fact_type,fact_key LIMIT 32""",
        (scan_id, *fact_types,
         f"%.{parameter_name}" if parameter_name else "!never-match!"),
    ).fetchall()
    fixtures = []
    credential_labels = {
        str(row[0]) for row in conn.execute(
            "SELECT label FROM credential_references WHERE scan_id=?", (scan_id,),
        )
    }
    for row in rows:
        value = _safe_fact_value(row["fact_value"])
        # Preserve only an existing opaque reference label, never credential
        # material supplied by a fixture under a similarly named field.
        try:
            raw = row["fact_value"]
            original = (
                json.loads(raw)
                if isinstance(raw, str) and len(raw.encode("utf-8")) <= 8192
                else None
            )
        except (json.JSONDecodeError, TypeError, RecursionError):
            original = None
        if isinstance(original, dict) and isinstance(value, dict):
            label = original.get("credential_label")
            if isinstance(label, str) and len(label.encode("utf-8")) <= 256 and label in credential_labels:
                value["credential_label"] = label
            value.pop("principal", None)
        fixtures.append({
            "fact_type": str(row["fact_type"]),
            "fact_key": str(row["fact_key"]),
            "fact_value": value,
            "confidence": float(row["confidence"]),
        })
    return fixtures


def _safe_fact_value(raw: Any) -> Any:
    """Sanitize fact contents as well as their outer classification.

    A shareable fact type/key does not guarantee that nested fields or free
    text are free of credentials. Reject oversized input without echoing it.
    """
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > 8192:
            return {"omitted": "fact exceeds metadata budget"}
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            pass
    try:
        return sanitize_metadata(raw, max_bytes=2000)
    except ValidationError:
        return {"omitted": "fact exceeds safe metadata format or budget"}


_SHAREABLE_FACT_TYPES = frozenset({
    "api_documentation", "attack_observation", "attack_response_behavior",
    "auth_behavior", "bounded_probe_result", "captcha_challenge_behavior",
    "cors_behavior", "endpoint_behavior", "endpoint_runtime", "error_behavior",
    "error_disclosure", "graphql_metadata", "http_observation",
    "observed_behavior", "parameter_behavior", "response_behavior",
    "test_state", "unauthenticated_api_behavior", "observed_reference_object",
})


def _task_context_facts(
    conn: sqlite3.Connection, scan_id: str, *, endpoint_id: str,
    parameter_name: str, normalized_path: str = "",
) -> list[dict[str, Any]]:
    """Carry prior black-box observations into later bounded Attack batches.

    Attack agents already persist reusable facts, but exhaustive coverage runs
    use a fresh native agent for every batch.  Supplying a small, provenance-
    bound subset prevents the next batch from losing the application model
    learned by earlier requests.  Object fixtures remain separate because an
    observed identifier is not proof that the scanner owns that object.
    """
    resource_parts = [
        part.casefold() for part in normalized_path.split("/")
        if len(part) >= 3 and not part.startswith(":") and "{" not in part
    ]
    resource_pattern = f"%{resource_parts[-1]}%" if resource_parts else "!never-match!"
    rows = conn.execute(
        """SELECT fact_type,fact_key,fact_value,confidence,source_endpoint_id
           FROM attack_facts
           WHERE scan_id=? AND fact_type IN ({})
           ORDER BY CASE WHEN source_endpoint_id=? THEN 0 ELSE 1 END,
                    CASE WHEN fact_key LIKE ? THEN 0 ELSE 1 END,
                    CASE WHEN lower(fact_key) LIKE ? THEN 0 ELSE 1 END,
                    confidence DESC,created_at,fact_id LIMIT 48""".format(
            ",".join("?" for _ in _SHAREABLE_FACT_TYPES)
        ),
        (
            scan_id, *sorted(_SHAREABLE_FACT_TYPES), endpoint_id,
            f"%{parameter_name}%" if parameter_name else "!never-match!",
            resource_pattern,
        ),
    ).fetchall()
    facts = []
    for row in rows:
        key = str(row["fact_key"])
        normalized_key = key.casefold().replace("-", "_")
        if any(part in normalized_key for part in (
            "password", "passwd", "secret", "token", "cookie",
            "authorization", "api_key", "apikey", "private_key",
        )):
            continue
        value = _safe_fact_value(row["fact_value"])
        facts.append({
            "fact_type": str(row["fact_type"]),
            "fact_key": key,
            "fact_value": value,
            "confidence": float(row["confidence"]),
            "source_endpoint_id": row["source_endpoint_id"],
        })
    return facts


def requeue_credential_blocked_coverage(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Reopen auth-blocked items only when the DB now has enough opaque refs."""
    rows = conn.execute(
        """SELECT c.*,o.base_url AS origin_url FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           WHERE c.scan_id=? AND c.status='blocked_auth'""",
        (scan_id,),
    ).fetchall()
    reopened = 0
    for row in rows:
        references = _credential_references(
            conn, scan_id,
            _credential_role(
                str(row["vuln_class"]), str(row["required_identity_role"]),
            ),
            available_only=True, origin_url=str(row["origin_url"]),
        )
        required = 2 if row["vuln_class"] == "idor" else 1
        if len(references) < required:
            continue
        transition_coverage(
            conn, row["coverage_id"], "pending",
            f"{len(references)} compatible opaque credential references are now available",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
        reopened += 1
    return reopened


def requeue_safe_session_binding_coverage(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Reopen safe local mutations skipped before optional sessions were routed.

    Older task payloads could have an empty credential list when Recon marked a
    declared endpoint unauthenticated.  Only reopen the small reversible set
    that can use a scanner-created disposable identity.  The old empty payload
    check prevents a model that still declines a fully bound task from causing
    an endless retry loop.
    """
    rows = conn.execute(
        """SELECT c.*,e.normalized_path,o.base_url AS origin_url,t.payload_json
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.scan_id=? AND c.status IN ('policy_excluded','unsupported')""",
        (scan_id,),
    ).fetchall()
    safe_paths = {
        "/upload_profile_picture", "/upload_profile_picture_url",
        "/api/ai/chat",
    }
    markers = (
        "no synthetic account binding", "lacks a bound synthetic account",
        "no credential reference",
    )
    reopened = 0
    for row in rows:
        if str(row["normalized_path"]).rstrip("/") not in safe_paths:
            continue
        reason = str(row["disposition_reason"] or "").casefold()
        if not any(marker in reason for marker in markers):
            continue
        try:
            old_payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        if old_payload.get("credential_references"):
            continue
        references = _credential_references(
            conn, scan_id, "authenticated", available_only=True,
            origin_url=str(row["origin_url"]),
        )
        if not any(ref["identity_role"] == "identity_synthetic" for ref in references):
            continue
        _event(
            conn, row, "pending",
            "scanner-created same-origin session is now routed to this safe task",
        )
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,attempt_count=0,
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (
                "scanner-created same-origin session is now routed to this safe task",
                now(), row["coverage_id"],
            ),
        )
        reopened += 1
    return reopened


def requeue_new_disposable_identity_coverage(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Reopen a skipped task after its exact disposable identity is added.

    A task may correctly decline an identity-specific login before the scanner
    owns an account of that type.  Once a same-origin opaque credential and a
    non-secret owned-object fact exist, the old result is no longer a policy
    conclusion.  The prior payload guard makes the migration one-shot if the
    fully bound task is still inapplicable.
    """
    rows = conn.execute(
        """SELECT c.*,o.base_url AS origin_url,t.payload_json
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.scan_id=? AND c.status IN ('policy_excluded','unsupported')""",
        (scan_id,),
    ).fetchall()
    reopened = 0
    for row in rows:
        reason = " ".join(str(row["disposition_reason"] or "").casefold().split())
        if "no scanner-created synthetic merchant" not in reason:
            continue
        try:
            old_payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        old_roles = {
            str(item.get("identity_role"))
            for item in old_payload.get("credential_references", [])
            if isinstance(item, dict)
        }
        if "merchant_synthetic" in old_roles:
            continue
        references = _credential_references(
            conn, scan_id, "authenticated", available_only=True,
            origin_url=str(row["origin_url"]),
        )
        labels = {
            item["label"] for item in references
            if item["identity_role"] == "merchant_synthetic"
        }
        if not labels:
            continue
        has_owned_merchant = False
        for fact in conn.execute(
            """SELECT fact_value FROM attack_facts
               WHERE scan_id=? AND fact_type='owned_test_object'""",
            (scan_id,),
        ):
            try:
                value = json.loads(fact[0])
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                isinstance(value, dict)
                and value.get("credential_label") in labels
                and value.get("resource") == "merchant"
                and value.get("disposable") is True
                and value.get("cleanup_allowed") is True
            ):
                has_owned_merchant = True
                break
        if not has_owned_merchant:
            continue
        _event(
            conn, row, "pending",
            "scanner-created merchant identity now satisfies the skipped prerequisite",
        )
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,attempt_count=0,
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (
                "scanner-created merchant identity now satisfies the skipped prerequisite",
                now(), row["coverage_id"],
            ),
        )
        reopened += 1
    return reopened


def requeue_auth_gated_negative_coverage(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Reopen legacy anonymous conclusions that stopped at an auth gate.

    Older Attack payloads did not carry an optional authenticated control for
    hypotheses planned as unauthenticated. A 401/403 response could therefore
    become a durable negative or unsupported result even though the selected
    input was never exercised behind the gate. Reopen only those legacy tasks,
    and only after a usable same-origin opaque session exists. New payloads
    carry ``optional_control_identity_roles``, making this migration one-shot.
    """
    rows = conn.execute(
        """SELECT c.*,e.method,o.base_url AS origin_url,t.payload_json
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.scan_id=? AND c.required_identity_role='unauthenticated'
             AND c.status IN ('tested_negative','unsupported')""",
        (scan_id,),
    ).fetchall()
    reopened = 0
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        optional = payload.get("optional_control_identity_roles")
        if isinstance(optional, list) and "authenticated" in optional:
            continue
        requests = conn.execute(
            """SELECT response_status,result_json
               FROM attack_http_requests
               WHERE scan_id=? AND task_id=? AND endpoint_reference_id=?
                 AND method=? AND status='completed'
                 AND response_status IS NOT NULL""",
            (
                scan_id, row["last_task_id"], row["endpoint_id"],
                row["method"],
            ),
        ).fetchall()
        if not requests or any(
            int(request["response_status"]) not in {401, 403}
            for request in requests
        ):
            continue
        authenticated_request = False
        for request in requests:
            try:
                result = json.loads(request["result_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                result = {}
            if isinstance(result, dict) and result.get("credential_reference_id"):
                authenticated_request = True
                break
        if authenticated_request:
            continue
        references = _credential_references(
            conn, scan_id, "authenticated", available_only=True,
            origin_url=str(row["origin_url"]),
        )
        if not references:
            continue
        reason = (
            "usable same-origin session is now available for the authenticated "
            "control omitted by the legacy task"
        )
        _event(conn, row, "pending", reason)
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,attempt_count=0,
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (reason, now(), row["coverage_id"]),
        )
        reopened += 1
    return reopened


def requeue_redacted_login_differential_coverage(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Retry legacy login SQLi evidence with the secret-shape assertion.

    Older request helpers exposed no safe predicate for a nonempty returned
    credential.  A model could observe a repeatable 2xx/401 boolean pair but
    close it as inconclusive because Validation could not assert the redacted
    token.  Reopen only that exact shape and only when the old task did not
    already use ``json_path_nonempty_string``.
    """
    rows = conn.execute(
        """SELECT c.*,e.normalized_path,t.payload_json
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.scan_id=? AND c.status='unsupported'
             AND c.vuln_class='sqli'
             AND lower(e.normalized_path) LIKE '%login%'""",
        (scan_id,),
    ).fetchall()
    reopened = 0
    for row in rows:
        reason = " ".join(str(row["disposition_reason"] or "").casefold().split())
        if not (
            "broker redacted" in reason
            or "credential marker" in reason
            or "non-status login success assertion" in reason
        ):
            continue
        request_rows = conn.execute(
            """SELECT result_json FROM attack_http_requests
               WHERE scan_id=? AND task_id=? AND status='completed'""",
            (scan_id, row["last_task_id"]),
        ).fetchall()
        used_shape_assertion = False
        for request in request_rows:
            try:
                result = json.loads(request[0] or "{}")
            except json.JSONDecodeError:
                continue
            assertions = result.get("assertions", [])
            if any(
                isinstance(item, dict)
                and item.get("kind") == "json_path_nonempty_string"
                for item in assertions
            ):
                used_shape_assertion = True
                break
        if used_shape_assertion:
            continue
        statuses = {
            int(attempt[0]) for attempt in conn.execute(
                """SELECT response_status FROM attack_attempts
                   WHERE scan_id=? AND task_id=? AND response_status IS NOT NULL""",
                (scan_id, row["last_task_id"]),
            )
        }
        if not any(200 <= status < 300 for status in statuses) or not statuses & {401, 403}:
            continue
        _event(
            conn, row, "pending",
            "secret-shape assertions can now validate the redacted login differential",
        )
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,attempt_count=0,
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (
                "secret-shape assertions can now validate the redacted login differential",
                now(), row["coverage_id"],
            ),
        )
        reopened += 1
    return reopened


def requeue_owned_object_coverage(conn: sqlite3.Connection, scan_id: str) -> int:
    """Retry object-bound checks after disposable child fixtures are created.

    The previous task payload guard makes this migration one-shot. If a task
    still cannot run after receiving the exact owned object, its disposition
    remains final instead of looping forever.
    """
    facts_by_resource: dict[str, set[str]] = defaultdict(set)
    for raw_value, in conn.execute(
        """SELECT fact_value FROM attack_facts
           WHERE scan_id=? AND fact_type='owned_test_object'""",
        (scan_id,),
    ):
        try:
            value = json.loads(raw_value)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("disposable") is not True:
            continue
        resource = value.get("resource")
        label = value.get("credential_label")
        object_id = value.get("object_id")
        if (
            isinstance(resource, str) and resource
            and isinstance(label, str) and label
            and isinstance(object_id, (str, int))
        ):
            facts_by_resource[str(resource)].add(str(label))

    rows = conn.execute(
        """SELECT c.*,t.payload_json FROM attack_coverage_items c
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.scan_id=? AND c.status IN ('unsupported','policy_excluded')""",
        (scan_id,),
    ).fetchall()
    reopened = 0
    for row in rows:
        reason = " ".join(str(row["disposition_reason"] or "").casefold().split())
        resource = None
        if "address" in reason and any(marker in reason for marker in (
            "no owned", "no supplied", "no observed", "no captured", "has no observed",
        )):
            resource = "address"
        elif any(marker in reason for marker in ("basketitems", "basket item")) and any(
            marker in reason for marker in (
                "no owned", "no supplied", "no captured", "lacks a task-created",
            )
        ):
            resource = "basket_item"
        if resource is None:
            continue
        required = 2 if str(row["vuln_class"]) == "idor" else 1
        if len(facts_by_resource.get(resource, set())) < required:
            continue
        try:
            old_payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        old_resources = {
            value.get("resource")
            for fixture in old_payload.get("test_fixtures", [])
            if isinstance(fixture, dict)
            and isinstance((value := fixture.get("fact_value")), dict)
        }
        if resource in old_resources:
            continue
        reason_text = f"scanner-owned disposable {resource} fixtures are now available"
        _event(conn, row, "pending", reason_text)
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,attempt_count=0,
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (reason_text, now(), row["coverage_id"]),
        )
        reopened += 1
    return reopened


def requeue_unreplayable_candidates(conn: sqlite3.Connection, scan_id: str) -> int:
    """Do not let a finding without an immutable runtime contract count as done."""
    rows = conn.execute(
        """SELECT c.* FROM attack_coverage_items c
           JOIN finding_reproduction_specs r ON r.finding_id=c.finding_id
           WHERE c.scan_id=? AND c.status='candidate'
             AND r.runtime_contract_json IS NULL""",
        (scan_id,),
    ).fetchall()
    for row in rows:
        transition_coverage(
            conn, row["coverage_id"], "pending",
            "existing finding has no immutable runtime contract for independent Validation",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
    return len(rows)


def _authentication_blocker(reason: str) -> bool:
    lowered = " ".join(reason.casefold().split())
    return any(phrase in lowered for phrase in (
        "missing authentication identity",
        "missing authenticated identity",
        "missing credential",
        "credential reference is unavailable",
        "credential references are unavailable",
        "authentication identity is unavailable",
        "authentication required but",
        "no second identity",
        "no owner-bound",
        "opaque credential references cannot be modified",
    ))


def reclassify_misclassified_auth_blockers(
    conn: sqlite3.Connection, scan_id: str,
) -> int:
    """Repair legacy substring classification such as `unauthenticated`."""
    rows = conn.execute(
        """SELECT * FROM attack_coverage_items
           WHERE scan_id=? AND status='blocked_auth'""",
        (scan_id,),
    ).fetchall()
    repaired = 0
    for row in rows:
        reason = str(row["disposition_reason"] or "")
        if _authentication_blocker(reason):
            continue
        transition_coverage(
            conn, row["coverage_id"], "unsupported",
            "non-authentication blocker: " + reason,
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
        repaired += 1
    return repaired


def _event(
    conn: sqlite3.Connection, row: sqlite3.Row, next_status: str, reason: str,
    *, stage_run_id: str | None = None, task_id: str | None = None,
) -> None:
    conn.execute(
        """INSERT INTO attack_coverage_events
           (event_id,coverage_id,scan_id,stage_run_id,task_id,previous_status,
            next_status,reason) VALUES (?,?,?,?,?,?,?,?)""",
        (
            new_id("coverage_event"), row["coverage_id"], row["scan_id"],
            stage_run_id, task_id, row["status"], next_status, reason,
        ),
    )


def transition_coverage(
    conn: sqlite3.Connection, coverage_id: str, next_status: str, reason: str,
    *, stage_run_id: str | None = None, task_id: str | None = None,
    finding_id: str | None = None,
) -> None:
    row = conn.execute(
        "SELECT * FROM attack_coverage_items WHERE coverage_id=?", (coverage_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown coverage item: {coverage_id}")
    if next_status not in _TRANSITIONS.get(str(row["status"]), frozenset()):
        raise ValueError(f"invalid coverage transition: {row['status']} -> {next_status}")
    if not reason.strip():
        raise ValueError("coverage transition requires a reason")
    _event(
        conn, row, next_status, reason,
        stage_run_id=stage_run_id, task_id=task_id,
    )
    conn.execute(
        """UPDATE attack_coverage_items
           SET status=?,disposition_reason=?,last_stage_run_id=COALESCE(?,last_stage_run_id),
               last_task_id=COALESCE(?,last_task_id),finding_id=COALESCE(?,finding_id),
               updated_at=? WHERE coverage_id=?""",
        (
            next_status, reason, stage_run_id, task_id, finding_id,
            now(), coverage_id,
        ),
    )


def _selected_http_evidence(
    conn: sqlite3.Connection, coverage: sqlite3.Row, attempt: sqlite3.Row,
    stage_run_id: str, task_id: str, *, exact: bool, request_ids: list[str] | None = None,
) -> bool:
    query = "SELECT r.request_id FROM attack_http_requests r WHERE r.scan_id=? AND r.stage_run_id=? AND r.task_id=? AND r.request_fingerprint=? AND r.status='completed' AND r.response_status IS NOT NULL"
    params: tuple = (coverage['scan_id'], stage_run_id, task_id, attempt['request_fingerprint'])
    if exact:
        if attempt['endpoint_id'] != coverage['endpoint_id']:
            return False
        method = conn.execute('SELECT method FROM endpoints WHERE endpoint_id=?', (coverage['endpoint_id'],)).fetchone()[0]
        expected_identity = str(coverage['required_identity_role'])
        optional_identity_roles: set[str] = set()
        task = conn.execute(
            "SELECT payload_json FROM attack_tasks WHERE task_id=?", (task_id,),
        ).fetchone()
        if task is not None:
            try:
                payload = json.loads(task[0] or "{}")
            except json.JSONDecodeError:
                payload = {}
            if payload.get("planned_identity_role") == expected_identity:
                rebound = payload.get("required_identity_role")
                if rebound in {"authenticated", "unauthenticated"}:
                    expected_identity = rebound
            optional = payload.get("optional_control_identity_roles")
            if isinstance(optional, list):
                optional_identity_roles = {
                    str(role) for role in optional if isinstance(role, str)
                }
        allow_anonymous = expected_identity == "unauthenticated"
        allow_authenticated = (
            expected_identity == "authenticated"
            or "authenticated" in optional_identity_roles
        )
        query += """ AND r.endpoint_reference_id=? AND r.method=? AND (
            (? AND json_extract(r.result_json,'$.credential_reference_id') IS NULL)
            OR (? AND json_extract(r.result_json,'$.credential_reference_id') IN (
                SELECT credential_reference_id FROM credential_references WHERE scan_id=?)))"""
        params += (
            coverage['endpoint_id'], method, allow_anonymous,
            allow_authenticated, coverage['scan_id'],
        )
    for request in conn.execute(query, params):
        if request_ids is None or request[0] in request_ids:
            return True
    return False


def _hypothesis_finding_evidence(
    conn: sqlite3.Connection, coverage: sqlite3.Row, finding_id: str,
    stage_run_id: str, task_id: str,
) -> bool:
    spec = conn.execute('SELECT endpoint_id,injection_location,parameter_name,runtime_contract_json,source_attempt_ids_json,source_request_ids_json FROM finding_reproduction_specs WHERE finding_id=?', (finding_id,)).fetchone()
    location = 'body' if coverage['injection_location'] in {'json', 'form'} else coverage['injection_location']
    if (not spec or spec['endpoint_id'] != coverage['endpoint_id'] or not spec['runtime_contract_json']
            or (location != 'endpoint' and (spec['injection_location'], spec['parameter_name']) != (location, coverage['parameter_name']))):
        return False
    source_attempt_ids = json.loads(spec['source_attempt_ids_json'])
    source_request_ids = json.loads(spec['source_request_ids_json'])
    for attempt in conn.execute("SELECT attempt_id,endpoint_id,request_fingerprint FROM attack_attempts WHERE scan_id=? AND task_id=? AND finding_id=? AND outcome='confirmed'", (coverage['scan_id'], task_id, finding_id)):
        if attempt['attempt_id'] in source_attempt_ids and _selected_http_evidence(conn, coverage, attempt, stage_run_id, task_id, exact=True, request_ids=source_request_ids):
            return True
    return False


def _adopt_existing_findings(conn: sqlite3.Connection, scan_id: str) -> int:
    """Bind prior evidence to the exact DB coverage item without re-probing."""
    rows = conn.execute(
        """SELECT DISTINCT c.*,a.finding_id matched_finding_id,a.task_id matched_task_id,t.stage_run_id matched_stage_run_id,an.category
           FROM attack_coverage_items c
           JOIN attack_attempts a
             ON a.scan_id=c.scan_id AND a.endpoint_id=c.endpoint_id
            AND a.skill_name=c.skill_name AND a.outcome='confirmed'
            AND a.finding_id IS NOT NULL
           JOIN findings f ON f.finding_id=a.finding_id AND f.scan_id=a.scan_id
           JOIN finding_reproduction_specs r ON r.finding_id=f.finding_id
            AND r.runtime_contract_json IS NOT NULL
           JOIN endpoint_annotations an ON an.annotation_id=c.annotation_id
           LEFT JOIN attack_tasks t ON t.task_id=a.task_id AND t.scan_id=c.scan_id
           WHERE c.scan_id=? AND c.status='pending'
             AND (an.category<>'attack_hypothesis' OR (
                 json_extract(t.payload_json,'$.coverage_id')=c.coverage_id
                 AND (c.injection_location='endpoint' OR (r.parameter_name=c.parameter_name
                    AND r.injection_location=CASE c.injection_location WHEN 'json' THEN 'body' WHEN 'form' THEN 'body' ELSE c.injection_location END))))
           ORDER BY c.coverage_id,a.finding_id""",
        (scan_id,),
    ).fetchall()
    adopted = set()
    for row in rows:
        if row['coverage_id'] in adopted or (row['category'] == 'attack_hypothesis' and not _hypothesis_finding_evidence(conn, row, row['matched_finding_id'], row['matched_stage_run_id'], row['matched_task_id'])):
            continue
        adopted.add(row['coverage_id'])
        transition_coverage(
            conn, row["coverage_id"], "running",
            "adopting existing evidence-bound Attack finding",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
        )
        transition_coverage(
            conn, row["coverage_id"], "candidate",
            "existing evidence-bound Attack finding matches endpoint and skill",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["matched_finding_id"],
        )
    return len(adopted)


def claim_coverage_batch(
    conn: sqlite3.Connection, *, scan_id: str, stage_run_id: str,
    batch_size: int, max_attempts: int = 3,
) -> list[dict[str, Any]]:
    if not 1 <= batch_size <= 50:
        raise ValueError("coverage batch size must be between 1 and 50")
    _block_unavailable_authenticated_coverage(
        conn, scan_id=scan_id, stage_run_id=stage_run_id,
    )
    # A failed mixed batch does not identify which hypothesis triggered the
    # failure.  Replay retryable work one item at a time so a refusal or
    # transport failure can be attributed to exactly one black-box test and
    # unrelated coverage can continue.  Fresh pending work keeps the normal
    # throughput and vulnerability-class fairness below.
    has_retryable = bool(conn.execute(
        """SELECT 1 FROM attack_coverage_items
           WHERE scan_id=? AND status='error_retryable' AND attempt_count < ?
           LIMIT 1""",
        (scan_id, max_attempts),
    ).fetchone())
    effective_batch_size = 1 if has_retryable else batch_size
    rows = conn.execute(
        """WITH ranked AS (
               SELECT c.*,e.method,e.normalized_path,o.base_url AS origin_url,
                      EXISTS (
                          SELECT 1 FROM endpoint_observations api
                          WHERE api.endpoint_id=c.endpoint_id
                            AND api.discovery_kind='api_spec_declaration'
                            AND json_valid(api.evidence_json)
                            AND CASE c.vuln_class
                              WHEN 'sqli' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%sql%inject%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%vulnerable to injection%'
                              WHEN 'nosqli' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%nosql%inject%'
                              WHEN 'idor' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%idor%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%bola%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%object%authoriz%'
                              WHEN 'auth_bypass' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%auth%bypass%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%without%auth%'
                              WHEN 'ssrf' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%ssrf%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%server%side%request%forg%'
                              WHEN 'xss' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%xss%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%cross%site%script%'
                              WHEN 'csrf' THEN
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%csrf%'
                                OR lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),'')) LIKE '%cross%site%request%forg%'
                              ELSE
                                lower(COALESCE(json_extract(api.evidence_json,'$.operation_description'),''))
                                  LIKE '%' || replace(c.vuln_class,'_',' ') || '%'
                            END
                      ) AS public_security_signal,
                      CASE WHEN c.vuln_class IN
                           ('sqli','nosqli','auth_bypass','session','brute_force')
                           AND e.method IN ('POST','PUT','PATCH')
                           AND (
                             lower(e.normalized_path) LIKE '%/login%'
                             OR lower(e.normalized_path) LIKE '%/signin%'
                             OR lower(e.normalized_path) LIKE '%/session%'
                           ) THEN 1 ELSE 0 END AS login_security_signal,
                      ROW_NUMBER() OVER (
                          PARTITION BY c.status,c.vuln_class
                          ORDER BY e.normalized_path,c.coverage_id
                      ) AS class_rank,
                      (SELECT COUNT(*) FROM attack_coverage_items prior
                       WHERE prior.scan_id=c.scan_id
                         AND prior.vuln_class=c.vuln_class
                         AND prior.status NOT IN
                           ('pending','error_retryable','running')) AS class_completed
               FROM attack_coverage_items c
               JOIN endpoints e ON e.endpoint_id=c.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               WHERE c.scan_id=? AND c.status IN ('pending','error_retryable')
                 AND c.attempt_count < ?
           )
           SELECT * FROM ranked
           ORDER BY CASE status WHEN 'error_retryable' THEN 0 ELSE 1 END,
                    CASE WHEN public_security_signal=1 OR login_security_signal=1
                         THEN 0 ELSE 1 END,
                    CASE
                      WHEN (public_security_signal=1 OR login_security_signal=1)
                           AND method='GET' THEN 0
                      WHEN public_security_signal=1 OR login_security_signal=1 THEN 1
                      ELSE 2
                    END,
                    class_completed + class_rank,
                    CASE vuln_class
                        WHEN 'brute_force' THEN 90
                        WHEN 'race_condition' THEN 91
                        ELSE 10
                    END,
                    vuln_class,normalized_path,coverage_id
           LIMIT ?""",
        (scan_id, max_attempts, effective_batch_size),
    ).fetchall()
    claimed: list[dict[str, Any]] = []
    for row in rows:
        credential_references = _credential_references(
            conn, scan_id,
            _credential_role(
                str(row["vuln_class"]), str(row["required_identity_role"]),
            ),
            origin_url=str(row["origin_url"]),
        )
        test_fixtures = _task_fixtures(
            conn, scan_id, parameter_name=str(row["parameter_name"]),
        )
        planned_identity_role = str(row["required_identity_role"])
        execution_identity_role = _execution_identity_role(
            method=str(row["method"]),
            normalized_path=str(row["normalized_path"]),
            planned_role=planned_identity_role,
            credential_references=credential_references,
            test_fixtures=test_fixtures,
        )
        if execution_identity_role != planned_identity_role:
            credential_references = [
                item for item in credential_references
                if item["identity_role"] == "identity_synthetic"
            ]
        optional_control_identity_roles = (
            ["authenticated"]
            if planned_identity_role == "unauthenticated" and credential_references
            else []
        )
        context_facts = _task_context_facts(
            conn, scan_id, endpoint_id=str(row["endpoint_id"]),
            parameter_name=str(row["parameter_name"]),
            normalized_path=str(row["normalized_path"]),
        )
        parameter_candidates = _parameter_candidates(
            conn, str(row["endpoint_id"]), str(row["vuln_class"]),
        )
        source_context = _source_context(
            conn, str(row["endpoint_id"]), str(row["annotation_id"]),
        )
        if source_context.get('active_annotation', {}).get('category') == 'attack_hypothesis':
            parameter_candidates = [item for item in parameter_candidates
                if (item['location'], item['name']) == (row['injection_location'], row['parameter_name'])]
        task_id = create_task(
            conn, stage_run_id=stage_run_id, skill_name=row["skill_name"],
            endpoint_id=row["endpoint_id"],
            payload={
                "coverage_id": row["coverage_id"],
                "vuln_class": row["vuln_class"],
                "method": row["method"],
                "normalized_path": row["normalized_path"],
                "injection_location": row["injection_location"],
                "parameter_name": row["parameter_name"],
                "parameter_candidates": parameter_candidates,
                "required_identity_role": execution_identity_role,
                "planned_identity_role": planned_identity_role,
                "optional_control_identity_roles": optional_control_identity_roles,
                "credential_references": credential_references,
                "test_fixtures": test_fixtures,
                "context_facts": context_facts,
                "source_context": source_context,
            },
        )
        transition_coverage(
            conn, row["coverage_id"], "running", "scheduled in exhaustive batch",
            stage_run_id=stage_run_id, task_id=task_id,
        )
        conn.execute(
            """UPDATE attack_coverage_items SET attempt_count=attempt_count+1,
               last_stage_run_id=?,last_task_id=?,updated_at=? WHERE coverage_id=?""",
            (stage_run_id, task_id, now(), row["coverage_id"]),
        )
        claimed.append({
            "task_id": task_id,
            "skill_name": row["skill_name"],
            "endpoint_id": row["endpoint_id"],
            "coverage_id": row["coverage_id"],
            "vuln_class": row["vuln_class"],
            "method": row["method"],
            "normalized_path": row["normalized_path"],
            "injection_location": row["injection_location"],
            "parameter_name": row["parameter_name"],
            "parameter_candidates": parameter_candidates,
            "required_identity_role": execution_identity_role,
            "planned_identity_role": planned_identity_role,
            "optional_control_identity_roles": optional_control_identity_roles,
            "credential_references": credential_references,
            "test_fixtures": test_fixtures,
            "context_facts": context_facts,
            "source_context": source_context,
        })
    return claimed


def _block_unavailable_authenticated_coverage(
    conn: sqlite3.Connection, *, scan_id: str, stage_run_id: str,
) -> int:
    """Finish explicit authenticated prerequisites before native dispatch.

    This gate intentionally reads only the durable coverage prerequisite.  It
    does not infer authentication from the vulnerability class, route name, or
    agent prompt, so anonymous hypotheses remain executable.  A blocked item
    can be reopened by ``requeue_credential_blocked_coverage`` after a usable
    same-origin opaque credential reference is registered.
    """
    rows = conn.execute(
        """SELECT c.*,o.base_url AS origin_url
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           WHERE c.scan_id=? AND c.status IN ('pending','error_retryable')
             AND c.required_identity_role='authenticated'
           ORDER BY c.coverage_id""",
        (scan_id,),
    ).fetchall()
    blocked = 0
    for row in rows:
        references = _credential_references(
            conn, scan_id, "authenticated", available_only=True,
            origin_url=str(row["origin_url"]),
        )
        if references:
            continue
        transition_coverage(
            conn, str(row["coverage_id"]), "blocked_auth",
            "[auth] authenticated identity prerequisite has no usable "
            "same-origin credential reference",
            stage_run_id=stage_run_id,
        )
        blocked += 1
    return blocked


def requeue_coverage(
    database: Path, scan_id: str, statuses: Iterable[str], *, reason: str,
) -> int:
    """Explicitly reopen selected terminal dispositions after planner changes.

    Existing requests, attempts, findings, and events are preserved.  This is
    intentionally opt-in so a normal resume never erases a prior conclusion.
    """
    selected = {str(status).strip() for status in statuses if str(status).strip()}
    allowed = TERMINAL_STATUSES - {"confirmed", "candidate"}
    if not selected or not selected <= allowed:
        raise ValueError(
            "requeue statuses must be selected non-candidate terminal statuses"
        )
    if not reason.strip():
        raise ValueError("coverage requeue requires a reason")
    with closing(_open_database(database)) as conn, conn:
        placeholders = ",".join("?" for _ in selected)
        rows = conn.execute(
            f"""SELECT * FROM attack_coverage_items
                WHERE scan_id=? AND status IN ({placeholders})""",
            (scan_id, *sorted(selected)),
        ).fetchall()
        for row in rows:
            _event(conn, row, "pending", reason)
            conn.execute(
                """UPDATE attack_coverage_items
                   SET status='pending',disposition_reason=?,attempt_count=0,
                       last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
                   WHERE coverage_id=?""",
                (reason, now(), row["coverage_id"]),
            )
        return len(rows)


def reconcile_coverage_batch(
    conn: sqlite3.Connection, *, stage_run_id: str, retry_limit: int = 3,
) -> None:
    rows = conn.execute(
        """SELECT c.*,t.status task_status,t.error_message,an.category,e.method
           FROM attack_coverage_items c
           JOIN endpoint_annotations an ON an.annotation_id=c.annotation_id
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN attack_tasks t ON t.task_id=c.last_task_id
           WHERE c.last_stage_run_id=? AND c.status='running'""",
        (stage_run_id,),
    ).fetchall()
    for row in rows:
        attempts = conn.execute(
            """SELECT attempt_id,outcome,finding_id,request_fingerprint,endpoint_id,resolution_reason FROM attack_attempts
               WHERE scan_id=? AND task_id=? ORDER BY created_at,attempt_id""",
            (row["scan_id"], row["last_task_id"]),
        ).fetchall()
        finding_ids = sorted({str(item["finding_id"]) for item in attempts if item["finding_id"]})
        task_status = str(row["task_status"])
        if row['category'] == 'attack_hypothesis':
            finding_ids = [finding_id for finding_id in finding_ids
                if _hypothesis_finding_evidence(conn, row, finding_id, stage_run_id, row['last_task_id'])]
        selected_attempts = [
            item for item in attempts
            if _selected_http_evidence(
                conn, row, item, stage_run_id, row['last_task_id'],
                exact=row['category'] == 'attack_hypothesis',
            )
        ]
        # Redirect and canonicalization probes remain audit evidence, but an
        # off-target attempt must neither poison nor prove the selected
        # endpoint hypothesis. Reconcile only exact, completed HTTP evidence.
        outcomes = {str(item["outcome"] or "") for item in selected_attempts}
        negative_http_evidence = bool(selected_attempts)
        if finding_ids:
            transition_coverage(
                conn, row["coverage_id"], "candidate",
                "Attack produced an evidence-bound finding",
                stage_run_id=stage_run_id, task_id=row["last_task_id"],
                finding_id=finding_ids[0],
            )
        elif task_status == "completed" and negative_http_evidence and outcomes <= {
            "negative", "rejected",
        }:
            transition_coverage(
                conn, row["coverage_id"], "tested_negative",
                "Attack completed with terminal negative evidence",
                stage_run_id=stage_run_id, task_id=row["last_task_id"],
            )
        elif task_status == "completed" and negative_http_evidence and outcomes and outcomes <= {
            "negative", "rejected", "inconclusive",
        }:
            # A completed task with policy-bound HTTP evidence and an explicit
            # inconclusive disposition has reached a durable bounded result.
            # Replaying the same hypothesis cannot turn missing context into
            # evidence and can trigger target rate limits.  Keep it visible as
            # unsupported rather than retrying until an error_terminal state.
            reason = next(
                (str(item["resolution_reason"]) for item in reversed(attempts)
                 if item["resolution_reason"]),
                "Attack completed with bounded evidence that remained inconclusive",
            )
            transition_coverage(
                conn, row["coverage_id"], "unsupported", reason,
                stage_run_id=stage_run_id, task_id=row["last_task_id"],
            )
        elif task_status == "skipped":
            reason = str(row["error_message"] or "Attack marked the item inapplicable")
            lowered = reason.casefold()
            status = (
                "unsupported" if lowered.startswith(("[budget]", "[evidence]"))
                else "blocked_auth" if lowered.startswith("[auth]") or _authentication_blocker(reason)
                else "policy_excluded" if any(token in lowered for token in ("policy", "scope", "prohibited"))
                else "unsupported"
            )
            transition_coverage(
                conn, row["coverage_id"], status, reason,
                stage_run_id=stage_run_id, task_id=row["last_task_id"],
            )
        else:
            terminal = row["attempt_count"] >= retry_limit
            transition_coverage(
                conn, row["coverage_id"],
                "error_terminal" if terminal else "error_retryable",
                (
                    "retry limit reached without terminal evidence"
                    if terminal else "batch ended without terminal coverage evidence"
                ),
                stage_run_id=stage_run_id, task_id=row["last_task_id"],
            )


def fail_running_coverage(
    conn: sqlite3.Connection, *, stage_run_id: str, reason: str, retry_limit: int = 3,
) -> None:
    rows = conn.execute(
        """SELECT * FROM attack_coverage_items
           WHERE last_stage_run_id=? AND status='running'""", (stage_run_id,),
    ).fetchall()
    for row in rows:
        transition_coverage(
            conn, row["coverage_id"],
            "error_terminal" if row["attempt_count"] >= retry_limit else "error_retryable",
            reason, stage_run_id=stage_run_id, task_id=row["last_task_id"],
        )


def requeue_interrupted_coverage(
    conn: sqlite3.Connection, *, stage_run_id: str, reason: str,
) -> int:
    """Return operator-interrupted coverage to the normal pending queue.

    Cancellation is not an Attack failure and should not force each untouched
    item through the one-at-a-time retry isolation path on the next run.
    Request and attempt ledgers remain unchanged; only the scheduler lease and
    the claim attempt consumed by the interrupted batch are released.
    """
    rows = conn.execute(
        """SELECT * FROM attack_coverage_items
           WHERE last_stage_run_id=? AND status='error_retryable'""",
        (stage_run_id,),
    ).fetchall()
    for row in rows:
        _event(conn, row, "pending", reason)
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='pending',disposition_reason=?,
                   attempt_count=MAX(0,attempt_count-1),
                   last_stage_run_id=NULL,last_task_id=NULL,updated_at=?
               WHERE coverage_id=?""",
            (reason, now(), row["coverage_id"]),
        )
    return len(rows)


def refresh_confirmed_coverage(conn: sqlite3.Connection, scan_id: str) -> int:
    regressed = conn.execute(
        """SELECT c.*,v.current_status FROM attack_coverage_items c
           JOIN validation_cases v ON v.finding_id=c.finding_id AND v.scan_id=c.scan_id
           WHERE c.scan_id=? AND c.status='confirmed'
             AND v.processing_phase='completed' AND v.current_status<>'CONFIRMED'""",
        (scan_id,),
    ).fetchall()
    for row in regressed:
        transition_coverage(
            conn, row["coverage_id"], "candidate",
            f"latest independent Validation status is {row['current_status']}",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
    rows = conn.execute(
        """SELECT c.* FROM attack_coverage_items c
           JOIN validation_cases v ON v.finding_id=c.finding_id AND v.scan_id=c.scan_id
           WHERE c.scan_id=? AND c.status='candidate'
             AND v.processing_phase='completed' AND v.current_status='CONFIRMED'""",
        (scan_id,),
    ).fetchall()
    for row in rows:
        transition_coverage(
            conn, row["coverage_id"], "confirmed",
            "independent Validation case confirmed the finding",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
    return len(rows) + len(regressed)


def refresh_catalog_assessments(conn: sqlite3.Connection, scan_id: str) -> int:
    """Project the linked runtime coverage result onto each benchmark claim."""
    table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='benchmark_catalog_mappings'"
    ).fetchone()
    if table is None:
        return 0
    rows = conn.execute(
        """SELECT b.catalog_item_id,b.assessment_status,c.status
           FROM benchmark_catalog_items b
           JOIN benchmark_catalog_mappings m
             ON m.catalog_item_id=b.catalog_item_id
           LEFT JOIN attack_coverage_items c
             ON c.annotation_id=m.annotation_id AND c.scan_id=b.scan_id
           WHERE b.scan_id=?""",
        (scan_id,),
    ).fetchall()
    changed = 0
    for row in rows:
        coverage_state = str(row["status"] or "pending")
        if coverage_state == "confirmed":
            assessment = "confirmed"
        elif coverage_state == "tested_negative":
            assessment = "not_reproduced"
        elif coverage_state in {
            "blocked_auth", "policy_excluded", "unsupported", "error_terminal",
        }:
            assessment = "unsupported"
        else:
            assessment = "mapped_runtime"
        if assessment != row["assessment_status"]:
            conn.execute(
                """UPDATE benchmark_catalog_items SET assessment_status=?
                   WHERE catalog_item_id=?""",
                (assessment, row["catalog_item_id"]),
            )
            changed += 1
    return changed


def coverage_status(database: Path, scan_id: str) -> CoverageStatus:
    with closing(_open_database(database)) as conn, conn:
        refresh_confirmed_coverage(conn, scan_id)
        refresh_catalog_assessments(conn, scan_id)
        rows = conn.execute(
            """SELECT status,vuln_class,count(*) count
               FROM attack_coverage_items WHERE scan_id=?
               GROUP BY status,vuln_class ORDER BY vuln_class,status""",
            (scan_id,),
        ).fetchall()
        by_status: Counter[str] = Counter()
        by_vulnerability: dict[str, dict[str, int]] = {}
        for row in rows:
            by_status[row["status"]] += row["count"]
            by_vulnerability.setdefault(row["vuln_class"], {})[row["status"]] = row["count"]
        total = sum(by_status.values())
        terminal = sum(by_status[name] for name in TERMINAL_STATUSES)
        blocked = sum(by_status[name] for name in (
            "blocked_auth", "policy_excluded", "unsupported", "error_terminal",
        ))
        executed = sum(by_status[name] for name in (
            "tested_negative", "candidate", "confirmed",
        ))
        executable_denominator = total - blocked
        candidates = by_status["candidate"] + by_status["confirmed"]
        confirmed = by_status["confirmed"]
        return CoverageStatus(
            scan_id=scan_id,
            total=total,
            by_status=dict(sorted(by_status.items())),
            by_vulnerability={
                key: dict(sorted(value.items()))
                for key, value in sorted(by_vulnerability.items())
            },
            disposition_coverage=(terminal / total if total else 1.0),
            executable_coverage=(executed / executable_denominator if executable_denominator else 1.0),
            validation_coverage=(confirmed / candidates if candidates else 1.0),
            unfinished=total - terminal,
        )
