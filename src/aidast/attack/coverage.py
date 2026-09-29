"""Deterministic endpoint-by-vulnerability Attack coverage ledger."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.lifecycle import create_task
from aidast.recon.db import new_id, now
from aidast.validation.execution.credentials import PipelineCredentialResolver


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
    "pending": frozenset({"running", "policy_excluded", "unsupported"}),
    "error_retryable": frozenset({"running", "error_terminal"}),
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
    }


def ensure_coverage_manifest(database: Path, scan_id: str) -> CoverageManifestResult:
    """Create one durable item for every source vulnerability annotation."""
    with closing(_open_database(database)) as conn, conn:
        scan = conn.execute(
            "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,),
        ).fetchone()
        if scan is None or scan["status"] != "completed" or not scan["finished_at"]:
            raise ValueError("coverage planning requires a completed Recon scan")
        rows = conn.execute(
            """SELECT an.annotation_id,an.tag,an.category,an.rationale,e.endpoint_id,e.method,
                      e.normalized_path,COALESCE(e.auth_required,0) auth_required
               FROM endpoint_annotations an
               JOIN endpoint_observations eo ON eo.observation_id=an.observation_id
               JOIN annotation_runs ar ON ar.annotation_run_id=an.annotation_run_id
               JOIN endpoints e ON e.endpoint_id=eo.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND ar.scan_id=? AND ar.status='completed'
                 AND an.category IN (
                     'source_vulnerability','benchmark_catalog_vulnerability','attack_hypothesis'
                 )
                 AND COALESCE(e.is_excluded,0)=0
               ORDER BY e.endpoint_id,an.tag,an.annotation_id""",
            (scan_id, scan_id),
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
    # IDOR is inherently a cross-identity differential even when the source
    # route itself was annotated as unauthenticated.
    # JWT mutation needs a real, opaque benchmark token as its baseline. The
    # source route may itself be public (for example /login), but testing token
    # verification without any issued token only creates a false auth blocker.
    return (
        "authenticated"
        if vuln_class in {"idor", "jwt_crypto"}
        else required_role
    )


def _task_fixtures(
    conn: sqlite3.Connection, scan_id: str, *, parameter_name: str,
) -> list[dict[str, Any]]:
    """Return bounded, non-secret fixture facts relevant to one coverage task."""
    rows = conn.execute(
        """SELECT fact_type,fact_key,fact_value,confidence
           FROM attack_facts
           WHERE scan_id=? AND fact_type IN ('owned_test_object','benchmark_fixture')
           ORDER BY CASE WHEN fact_key LIKE ? THEN 0 ELSE 1 END,
                    fact_type,fact_key LIMIT 32""",
        (scan_id, f"%.{parameter_name}" if parameter_name else "!never-match!"),
    ).fetchall()
    fixtures = []
    for row in rows:
        value: Any = row["fact_value"]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[:1000]
        fixtures.append({
            "fact_type": str(row["fact_type"]),
            "fact_key": str(row["fact_key"]),
            "fact_value": value,
            "confidence": float(row["confidence"]),
        })
    return fixtures


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
        query += """ AND r.endpoint_reference_id=? AND r.method=? AND (
            (?='unauthenticated' AND json_extract(r.result_json,'$.credential_reference_id') IS NULL)
            OR (?='authenticated' AND json_extract(r.result_json,'$.credential_reference_id') IN (
                SELECT credential_reference_id FROM credential_references WHERE scan_id=?)))"""
        params += (coverage['endpoint_id'], method, coverage['required_identity_role'], coverage['required_identity_role'], coverage['scan_id'])
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
    rows = conn.execute(
        """SELECT c.*,e.method,e.normalized_path,o.base_url AS origin_url
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           WHERE c.scan_id=? AND c.status IN ('pending','error_retryable')
             AND c.attempt_count < ?
           ORDER BY CASE c.status WHEN 'error_retryable' THEN 0 ELSE 1 END,
                    CASE c.vuln_class
                        WHEN 'brute_force' THEN 90
                        WHEN 'race_condition' THEN 91
                        ELSE 10
                    END,
                    c.vuln_class,e.normalized_path,c.coverage_id
           LIMIT ?""",
        (scan_id, max_attempts, batch_size),
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
                "required_identity_role": row["required_identity_role"],
                "credential_references": credential_references,
                "test_fixtures": test_fixtures,
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
            "required_identity_role": row["required_identity_role"],
            "credential_references": credential_references,
            "test_fixtures": test_fixtures,
            "source_context": source_context,
        })
    return claimed


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
            """SELECT attempt_id,outcome,finding_id,request_fingerprint,endpoint_id FROM attack_attempts
               WHERE scan_id=? AND task_id=? ORDER BY created_at,attempt_id""",
            (row["scan_id"], row["last_task_id"]),
        ).fetchall()
        finding_ids = sorted({str(item["finding_id"]) for item in attempts if item["finding_id"]})
        outcomes = {str(item["outcome"] or "") for item in attempts}
        task_status = str(row["task_status"])
        if row['category'] == 'attack_hypothesis':
            finding_ids = [finding_id for finding_id in finding_ids
                if _hypothesis_finding_evidence(conn, row, finding_id, stage_run_id, row['last_task_id'])]
        negative_http_evidence = bool(attempts) and all(_selected_http_evidence(conn, row, item, stage_run_id, row['last_task_id'], exact=row['category'] == 'attack_hypothesis') for item in attempts)
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
