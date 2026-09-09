"""Read-only, scan-bound evidence metadata; no credentials or HTTP bodies."""

from __future__ import annotations

import sqlite3
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aidast.recon.annotations import TAXONOMY, safe_url


@dataclass(frozen=True)
class ObservationSummary:
    observation_id: str
    source_tool: str
    discovery_kind: str
    observed_url: str
    auth_state: str
    metadata: tuple[tuple[str, str | int], ...] = ()


@dataclass(frozen=True)
class EndpointEvidence:
    endpoint_id: str
    method: str
    path: str
    observation_ids: tuple[str, ...] = ()
    # (annotation ID, observation ID, category, tag)
    annotations: tuple[tuple[str, str, str, str], ...] = ()
    observation_summaries: tuple[ObservationSummary, ...] = ()


@dataclass(frozen=True)
class EvidenceSnapshot:
    scan_id: str
    status: str
    finished_at: str | None
    endpoints: tuple[EndpointEvidence, ...]


class EvidenceReader(Protocol):
    def read(self, db_path: Path, scan_id: str) -> EvidenceSnapshot: ...


class SQLiteEvidenceReader:
    """Read an existing database without initialization, migration, or writes."""

    def read(self, db_path: Path, scan_id: str) -> EvidenceSnapshot:
        # The caller verifies a finalized standalone snapshot. Immutable mode
        # also prevents SQLite from creating WAL/shared-memory helper files.
        conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            scan = conn.execute(
                "SELECT scan_id, status, finished_at FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if scan is None:
                raise ValueError("handoff scan does not exist in the database")
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            rows = conn.execute(
                """SELECT e.endpoint_id, e.method, e.normalized_path
                FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
                JOIN assets a ON a.asset_id=o.asset_id
                WHERE a.scan_id=? AND COALESCE(e.is_excluded,0)=0
                ORDER BY e.endpoint_id""", (scan_id,),
            ).fetchall()
            endpoints = []
            for endpoint_id, method, path in rows:
                observations = ()
                annotations = ()
                if "endpoint_observations" in tables:
                    observations = tuple(r[0] for r in conn.execute(
                        "SELECT observation_id FROM endpoint_observations WHERE endpoint_id=? ORDER BY observation_id",
                        (endpoint_id,),
                    ))
                    summaries = []
                    for record in conn.execute(
                        """SELECT ob.observation_id,ob.source_tool,ob.discovery_kind,
                        COALESCE(ob.observed_url,''),COALESCE(dc.auth_state,'unknown'),
                        COALESCE(ob.evidence_json,'{}')
                        FROM endpoint_observations ob
                        LEFT JOIN discovery_contexts dc ON dc.context_id=ob.context_id
                        WHERE ob.endpoint_id=? ORDER BY ob.observation_id""", (endpoint_id,),
                    ):
                        try:
                            raw_metadata = json.loads(record[5])
                        except (TypeError, ValueError):
                            raw_metadata = {}
                        allowed = {}
                        if isinstance(raw_metadata, dict):
                            for key in ("response_status", "content_length", "word_count", "line_count",
                                        "content_type", "html_tag", "html_attribute"):
                                value = raw_metadata.get(key)
                                if isinstance(value, (str, int)) and not isinstance(value, bool):
                                    allowed[key] = value if isinstance(value, int) else value[:200]
                        summaries.append(ObservationSummary(
                            str(record[0]), str(record[1])[:128], str(record[2])[:128],
                            safe_url(str(record[3])), str(record[4])[:64],
                            tuple(sorted(allowed.items())),
                        ))
                    observation_summaries = tuple(summaries)
                else:
                    observation_summaries = ()
                if {"endpoint_observations", "endpoint_annotations", "annotation_runs"} <= tables:
                    candidates = conn.execute(
                        """SELECT an.annotation_id, an.observation_id, an.category, an.tag
                        FROM endpoint_annotations an
                        JOIN endpoint_observations ob ON ob.observation_id=an.observation_id
                        JOIN annotation_runs ar ON ar.annotation_run_id=an.annotation_run_id
                        WHERE ob.endpoint_id=? AND ar.scan_id=? AND ar.status='completed'
                        ORDER BY an.annotation_id""", (endpoint_id, scan_id),
                    )
                    annotations = tuple(tuple(r) for r in candidates if r[3] in TAXONOMY.get(r[2], set()))
                normalized_method = str(method or "UNKNOWN").upper()
                if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}:
                    normalized_method = "UNKNOWN"
                endpoints.append(EndpointEvidence(
                    endpoint_id, normalized_method, safe_url(str(path or "")), observations, annotations,
                    observation_summaries,
                ))
            return EvidenceSnapshot(str(scan[0]), str(scan[1]), scan[2], tuple(endpoints))
        finally:
            conn.close()
