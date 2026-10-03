"""Evaluation-only source candidates, without synthetic Attack/Pipeline rows.

Exact route/input mappings and verdicts are operator-reviewed evidence. Neither
a challenge name nor its category supplies an exact coverage key or a verdict.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from aidast.attack.wiki import (
    KEY_FIELDS, AttackWikiError, _hash, _ingest_inventory, _load, _origin, _path, coverage_key,
)


SOURCE_FIELDS = (
    "candidate_id", "project", "external_id", "title", "vuln_class", "source_url",
    "source_path", "source_line", "source_sha256", "source_version", "claim_basis",
    "readiness", "availability", "evaluation_status",
)
SOURCE_STATUSES = frozenset({"UNASSESSED", "OUT_OF_TEST_SCOPE", "MANUAL_ONLY"})
VERDICTS = frozenset({"UNASSESSED", "VULNERABLE", "NOT_VULNERABLE"})


def ingest_candidate_baseline(
    root: Path, candidates: list[dict[str, Any]], *, project: str,
    observed_source_id: str, source_version: str, source_sha256: str,
    mapping_manifest: dict[str, Any] | None = None, label: str | None = None,
) -> dict[str, Any]:
    """Archive candidates only after a terminal runtime snapshot exists.

The manifest is version/hash-bound and contains reviewed exact coordinates;
missing entries stay unmapped and unassessed. Nothing is written to a scan DB.
    """
    sources = {item["source_id"]: item for item in _load(Path(root).expanduser().resolve())}
    observed = sources.get(observed_source_id)
    if observed is None or observed["kind"] != "runtime":
        raise AttackWikiError("candidate baseline requires an archived terminal runtime observation")
    run = observed["inventory"]
    if run["scan"]["status"] not in {"completed", "failed", "cancelled"}:
        raise AttackWikiError("candidate baseline requires a terminal runtime observation")
    if not run["origins"]:
        raise AttackWikiError("candidate baseline observation has no deployment origin")
    if not candidates:
        raise AttackWikiError("source candidate inventory is empty")
    if not project or not source_version or not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise AttackWikiError("source candidate baseline requires project/version/SHA256 provenance")

    source_rows: dict[str, dict[str, Any]] = {}
    for row in candidates:
        if not isinstance(row, dict) or any(field not in row for field in SOURCE_FIELDS):
            raise AttackWikiError("source candidate is missing provenance fields")
        if (row["project"] != project or row["source_version"] != source_version
                or row["source_sha256"] != source_sha256):
            raise AttackWikiError("source candidate project/version/hash does not match baseline")
        if row["evaluation_status"] not in SOURCE_STATUSES:
            raise AttackWikiError("candidate source status must remain unadjudicated")
        candidate_id = row["candidate_id"]
        if not isinstance(candidate_id, str) or not candidate_id or candidate_id in source_rows:
            raise AttackWikiError("invalid or duplicate source candidate ID")
        # Descriptions, probes and answer keys are intentionally not copied.
        source_rows[candidate_id] = {field: row[field] for field in SOURCE_FIELDS}
        source_rows[candidate_id].update({"mapping_status": "unmapped", "coordinate_count": 0,
                                          "adjudication_status": "UNASSESSED",
                                          "adjudication_evidence_ref": None})

    manifest = mapping_manifest if mapping_manifest is not None else {
        "schema_version": 1, "project": project, "source_version": source_version,
        "source_sha256": source_sha256, "entries": [],
    }
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or manifest.get("project") != project
            or manifest.get("source_version") != source_version
            or manifest.get("source_sha256") != source_sha256
            or not isinstance(manifest.get("entries"), list)):
        raise AttackWikiError("mapping manifest does not match source candidate provenance")
    seen: set[str] = set()
    items = []
    for entry in manifest["entries"]:
        if not isinstance(entry, dict):
            raise AttackWikiError("invalid reviewed mapping entry")
        candidate_id = entry.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id not in source_rows or candidate_id in seen:
            raise AttackWikiError("reviewed mapping references an unknown or duplicate candidate")
        seen.add(candidate_id)
        coordinates = entry.get("coordinates", [])
        verdict = entry.get("adjudication_status", "UNASSESSED")
        verdict_ref = entry.get("adjudication_evidence_ref")
        mapping_ref = entry.get("mapping_evidence_ref")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise AttackWikiError("invalid reviewed candidate adjudication")
        if verdict != "UNASSESSED" and (not isinstance(verdict_ref, str) or not verdict_ref.strip()):
            raise AttackWikiError("adjudication requires an explicit evidence reference")
        if not isinstance(coordinates, list):
            raise AttackWikiError("reviewed coordinates must be a list")
        if coordinates and (not isinstance(mapping_ref, str) or not mapping_ref.strip()):
            raise AttackWikiError("coordinate mapping requires an explicit evidence reference")
        row = source_rows[candidate_id]
        row.update({"adjudication_status": verdict, "adjudication_evidence_ref": verdict_ref,
                    "mapping_evidence_ref": mapping_ref,
                    "mapping_status": "reviewed_exact" if coordinates else "unmapped"})
        keys = set()
        for coordinate in coordinates:
            if (not isinstance(coordinate, dict) or set(coordinate) != set(KEY_FIELDS)
                    or any(not isinstance(coordinate[field], str) for field in KEY_FIELDS)
                    or any(not coordinate[field].strip() for field in KEY_FIELDS if field != "parameter_name")):
                raise AttackWikiError("mapping requires every exact coverage key field")
            coordinate = dict(coordinate)
            if _origin(coordinate["origin"]) != coordinate["origin"] or coordinate["origin"] not in run["origins"]:
                raise AttackWikiError("mapping origin does not match the observed deployment")
            if coordinate["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                raise AttackWikiError("mapping requires an explicit HTTP method")
            if (not coordinate["path"].startswith("/") or "?" in coordinate["path"]
                    or "#" in coordinate["path"] or "*" in coordinate["path"]):
                raise AttackWikiError("mapping requires an exact path template without query values")
            coordinate["path"] = _path(coordinate["path"])
            key = coverage_key(coordinate)
            if key in keys:
                raise AttackWikiError("duplicate exact coordinate in reviewed mapping")
            keys.add(key)
            items.append({**coordinate, "candidate_id": candidate_id,
                          "status": "source_candidate", "tested": False, "candidate": False,
                          "confirmed": False, "validation": None,
                          "baseline_eligible": row["evaluation_status"] == "UNASSESSED",
                          "adjudication_status": verdict, "adjudication_evidence_ref": verdict_ref})
        row["coordinate_count"] = len(keys)

    source_candidates = sorted(source_rows.values(), key=lambda item: item["candidate_id"])
    inventory = {
        "inventory_type": "source_candidate_baseline", "execution_mode": "evaluation_only",
        "evaluation_only": True, "bound_observed_source_id": observed_source_id,
        "provenance": {"project": project, "source_version": source_version,
                       "source_sha256": source_sha256, "mapping_manifest_sha256": _hash(manifest)},
        "scan": {"scan_id": "source-candidates-" + _hash(source_candidates)[:24],
                 "scope_type": "candidate_baseline", "scope_value": project,
                 "status": "not_executed", "started_at": None, "finished_at": None},
        "stages": [], "origins": run["origins"],
        "source_candidates": source_candidates,
        "items": sorted(items, key=lambda item: (item["candidate_id"], coverage_key(item))),
    }
    return _ingest_inventory(root, inventory, kind="source", label=label or f"{project} {source_version} candidates",
                             target_id=observed["target_id"])
