"""Build provenance-aware source reference databases for Recon Wiki."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from aidast.recon import db


_ROUTE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (/[^?# ]*)$")
_PARAMETER = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")


class ReferenceDatabaseError(ValueError):
    """A source route manifest cannot be materialized safely."""


@dataclass(frozen=True, slots=True)
class ReferenceDatabase:
    database: Path
    scan_id: str
    reference_id: str
    route_count: int
    method_counts: dict[str, int]
    manifest_sha256: str
    created: bool


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_manifest(path: Path) -> tuple[dict[str, object], list[tuple[str, str]], str]:
    manifest_path = path.expanduser().resolve(strict=True)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceDatabaseError(f"invalid route manifest: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise ReferenceDatabaseError("unsupported route manifest schema")
    required = ("reference_id", "target", "version", "source_commit", "routes")
    if any(not payload.get(key) for key in required):
        raise ReferenceDatabaseError("route manifest is missing required provenance")
    raw_routes = payload["routes"]
    if not isinstance(raw_routes, list):
        raise ReferenceDatabaseError("route manifest routes must be a list")
    routes: list[tuple[str, str]] = []
    for raw in raw_routes:
        match = _ROUTE.fullmatch(str(raw))
        if match is None:
            raise ReferenceDatabaseError(f"invalid route declaration: {raw!r}")
        routes.append((match.group(1), match.group(2)))
    if not routes or len(routes) != len(set(routes)):
        raise ReferenceDatabaseError("route manifest must contain unique method/path pairs")
    counts = dict(sorted(Counter(method for method, _ in routes).items()))
    if payload.get("route_count") != len(routes) or payload.get("method_counts") != counts:
        raise ReferenceDatabaseError("route manifest counts do not match its inventory")
    return payload, routes, _canonical_sha256(payload)


def _existing_reference(database: Path, manifest_sha256: str) -> ReferenceDatabase | None:
    if not database.is_file():
        return None
    try:
        with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as conn:
            row = conn.execute(
                "SELECT reference_id,scan_id,route_count,method_counts_json,manifest_sha256 "
                "FROM recon_reference_metadata LIMIT 1"
            ).fetchone()
            endpoint_count = int(conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0])
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.Error as exc:
        raise ReferenceDatabaseError(
            "destination already exists and is not a compatible Recon reference database"
        ) from exc
    if row is None or row[4] != manifest_sha256 or row[2] != endpoint_count or integrity != "ok":
        raise ReferenceDatabaseError("existing Recon reference does not match the manifest")
    return ReferenceDatabase(
        database=database,
        scan_id=str(row[1]),
        reference_id=str(row[0]),
        route_count=int(row[2]),
        method_counts=json.loads(row[3]),
        manifest_sha256=str(row[4]),
        created=False,
    )


def build_reference_database(
    manifest: Path, database: Path, *, target_url: str,
) -> ReferenceDatabase:
    """Materialize source-declared routes without claiming runtime observation."""
    payload, routes, manifest_sha256 = _load_manifest(manifest)
    destination = database.expanduser().resolve()
    existing = _existing_reference(destination, manifest_sha256)
    if existing is not None:
        return existing

    parsed = urlsplit(target_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ReferenceDatabaseError("target URL must be an absolute credential-free HTTP(S) URL")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    base_url = f"{parsed.scheme}://{parsed.hostname}"
    if port != default_port:
        base_url += f":{port}"

    reference_id = str(payload["reference_id"])
    stable = re.sub(r"[^a-zA-Z0-9]+", "_", reference_id).strip("_").lower()
    scan_id = f"scan_source_{stable}"
    method_counts = dict(sorted(Counter(method for method, _ in routes).items()))
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    conn = db.init_db(temporary)
    try:
        db.insert_scan(
            conn, scan_id=scan_id, scope_type="source_reference", scope_value=base_url,
        )
        asset_id = db.insert_asset(
            conn, scan_id=scan_id, identifier=base_url, asset_type="URL",
        )
        origin_id = db.upsert_origin(
            conn, asset_id=asset_id, scheme=parsed.scheme, host=parsed.hostname,
            port=port, base_url=base_url, spa_detected=True,
            framework_signature="OWASP Juice Shop / Express",
            main_crawler_mode="official_source_manifest",
        )
        context_id = f"context_source_{stable}"
        conn.execute(
            """INSERT INTO discovery_contexts
               (context_id,origin_id,action_type,action_target,auth_state,context_summary,
                started_at,ended_at) VALUES (?,?,?,?,?,?,?,?)""",
            (
                context_id, origin_id, "source_import", reference_id, "unknown",
                "Official source route declaration; no HTTP response is asserted.",
                db.now(), db.now(),
            ),
        )
        source_evidence = {
            "reference_id": reference_id,
            "target": payload["target"],
            "version": payload["version"],
            "source_commit": payload["source_commit"],
            "source_urls": payload.get("source_urls", []),
            "source_files": payload.get("source_files", {}),
            "image_digest": payload.get("image_digest"),
            "route_basis": payload.get("route_basis"),
            "manifest_sha256": manifest_sha256,
            "runtime_observed": False,
        }
        for ordinal, (method, path) in enumerate(routes, start=1):
            endpoint_id = db.upsert_endpoint(
                conn, origin_id=origin_id, method=method, path=path,
                normalized_path=path, source_tool="official_source_manifest",
                verification_status="observed",
            )
            for name in _PARAMETER.findall(path):
                db.upsert_parameter(
                    conn, endpoint_id=endpoint_id, name=name, location="path",
                    data_type="string", role="identifier" if name == "id" else "unknown",
                    is_identifier=name == "id",
                )
            conn.execute(
                """INSERT INTO endpoint_observations
                   (observation_id,endpoint_id,context_id,source_tool,discovery_kind,
                    observed_url,association_method,observed_at,evidence_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    f"observation_source_{ordinal:04d}", endpoint_id, context_id,
                    "official_source_manifest", "source_route", base_url + path,
                    "source_declaration", db.now(),
                    json.dumps(source_evidence, ensure_ascii=False, sort_keys=True),
                ),
            )
        conn.executescript(
            """CREATE TABLE recon_reference_metadata (
                 reference_id TEXT PRIMARY KEY,
                 scan_id TEXT NOT NULL,
                 target_name TEXT NOT NULL,
                 version TEXT NOT NULL,
                 source_commit TEXT NOT NULL,
                 image_digest TEXT,
                 route_count INTEGER NOT NULL,
                 method_counts_json TEXT NOT NULL,
                 manifest_sha256 TEXT NOT NULL,
                 manifest_path TEXT NOT NULL,
                 created_at TEXT NOT NULL
               );"""
        )
        conn.execute(
            "INSERT INTO recon_reference_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                reference_id, scan_id, payload["target"], payload["version"],
                payload["source_commit"], payload.get("image_digest"), len(routes),
                json.dumps(method_counts, sort_keys=True), manifest_sha256,
                str(manifest.expanduser().resolve()), db.now(),
            ),
        )
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=? WHERE scan_id=?",
            (db.now(), scan_id),
        )
        conn.commit()
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise ReferenceDatabaseError("generated Recon reference has foreign-key violations")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ReferenceDatabaseError("generated Recon reference failed integrity check")
    except Exception:
        conn.close()
        temporary.unlink(missing_ok=True)
        raise
    else:
        conn.close()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary.replace(destination)
    return ReferenceDatabase(
        database=destination,
        scan_id=scan_id,
        reference_id=reference_id,
        route_count=len(routes),
        method_counts=method_counts,
        manifest_sha256=manifest_sha256,
        created=True,
    )
