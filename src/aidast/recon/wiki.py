"""Persistent, provenance-aware Recon knowledge base.

The layout follows the LLM Wiki pattern: immutable machine-readable source
snapshots live under ``raw`` and a compact Markdown wiki is rebuilt from those
snapshots for humans and agents.  Coverage comparisons are method-aware and
never promote baseline/source knowledge to runtime observations.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReconWikiError(RuntimeError):
    """The Recon Wiki could not be read or updated safely."""


@dataclass(frozen=True, slots=True)
class WikiSource:
    source_id: str
    kind: str
    label: str
    target: str
    endpoint_count: int
    raw_path: Path
    page_path: Path
    created: bool


@dataclass(frozen=True, slots=True)
class CoverageComparison:
    comparison_id: str
    baseline_count: int
    observed_count: int
    matched_count: int
    exact_recall: float
    path_recall: float
    confirmed_count: int
    declared_candidate_count: int
    inferred_candidate_count: int
    confirmed_matched_count: int
    declared_candidate_matched_count: int
    inferred_candidate_matched_count: int
    missing: tuple[tuple[str, str], ...]
    report_path: Path


_KINDS = {"runtime", "source", "benchmark"}
_SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-.").lower()
    return slug[:80] or "unknown"


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def init_wiki(root: Path) -> Path:
    root = root.expanduser().resolve()
    for relative in (
        "raw", "wiki/sources", "wiki/targets", "wiki/comparisons",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)

    schema = root / "schema.md"
    if not schema.exists():
        schema.write_text(
            """# Recon Wiki schema

This directory separates evidence by provenance.

- `raw/*.json` contains immutable snapshots derived from a Recon database.
- `wiki/sources/*.md` summarizes one snapshot without changing its kind.
- `wiki/targets/*.md` catalogs all snapshots for a target.
- `wiki/comparisons/*.md` measures runtime recall against a named baseline.
- `wiki/log.md` is append-only.

Kinds have strict meaning: `runtime` was observed by live Recon, `source` was
read from operator-supplied source, and `benchmark` is evaluation-only. Source
and benchmark routes must never be reported as runtime discoveries.

The coverage key is `(HTTP method, normalized path)`. A path-only score is
secondary because it hides missing POST, PUT, PATCH, and DELETE behavior.
""",
            encoding="utf-8",
        )
    index = root / "wiki/index.md"
    if not index.exists():
        index.write_text("# Recon Wiki\n\nNo sources ingested yet.\n", encoding="utf-8")
    log = root / "wiki/log.md"
    if not log.exists():
        log.write_text("# Recon Wiki log\n", encoding="utf-8")
    return root


def _database_inventory(database: Path) -> dict[str, Any]:
    database = database.expanduser().resolve()
    if not database.is_file():
        raise ReconWikiError(f"Recon database does not exist: {database}")
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            required = {"scans", "assets", "origins", "endpoints"}
            if not required.issubset(tables):
                missing = ", ".join(sorted(required - tables))
                raise ReconWikiError(f"not a Recon database; missing tables: {missing}")
            scans = [dict(row) for row in connection.execute(
                "SELECT scan_id, scope_type, scope_value, status, started_at, finished_at "
                "FROM scans ORDER BY started_at, scan_id"
            )]
            endpoint_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(endpoints)")
            }
            def endpoint_value(name: str, fallback: str) -> str:
                return f"e.{name}" if name in endpoint_columns else fallback
            rows = list(connection.execute(
                f"""SELECT e.endpoint_id, e.method, e.normalized_path, e.path,
                          {endpoint_value('verification_status', "'observed'")} AS verification_status,
                          {endpoint_value('is_excluded', '0')} AS is_excluded,
                          {endpoint_value('exclude_reason', 'NULL')} AS exclude_reason,
                          {endpoint_value('auth_required', 'NULL')} AS auth_required,
                          {endpoint_value('source_tools', "''")} AS source_tools,
                          o.base_url
                   FROM endpoints e
                   JOIN origins o ON o.origin_id=e.origin_id
                   JOIN assets a ON a.asset_id=o.asset_id
                   JOIN scans s ON s.scan_id=a.scan_id
                   ORDER BY upper(e.method), e.normalized_path, o.base_url"""
            ))
            candidate_evidence: dict[str, list[dict[str, str]]] = {}
            observation_columns = ({row[1] for row in connection.execute(
                "PRAGMA table_info(endpoint_observations)")}
                if "endpoint_observations" in tables else set())
            if {"endpoint_id", "source_tool", "discovery_kind", "evidence_json"}.issubset(
                    observation_columns):
                for evidence_row in connection.execute(
                    """SELECT endpoint_id, discovery_kind, evidence_json
                       FROM endpoint_observations
                       WHERE source_tool='passive_route_inference'
                       ORDER BY observed_at, observation_id"""
                ):
                    try:
                        evidence = json.loads(evidence_row[2] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    rule, inferred_from = (
                        evidence.get("derivation_rule"), evidence.get("inferred_from"))
                    if not isinstance(rule, str) or not isinstance(inferred_from, str):
                        continue
                    item = {"kind": str(evidence_row[1]), "rule": rule,
                            "inferred_from": inferred_from}
                    values = candidate_evidence.setdefault(str(evidence_row[0]), [])
                    if item not in values and len(values) < 10:
                        values.append(item)
            endpoints = []
            for row in rows:
                endpoint = {
                    "method": (row["method"] or "GET").upper(),
                    "normalized_path": row["normalized_path"] or row["path"] or "/",
                    "path": row["path"] or row["normalized_path"] or "/",
                    "verification_status": row["verification_status"],
                    "is_excluded": bool(row["is_excluded"]),
                    "exclude_reason": row["exclude_reason"],
                    "auth_required": (
                        None if row["auth_required"] is None else bool(row["auth_required"])
                    ),
                    "source_tools": row["source_tools"] or "",
                    "base_url": row["base_url"],
                }
                if candidate_evidence.get(str(row["endpoint_id"])):
                    endpoint["candidate_evidence"] = candidate_evidence[str(row["endpoint_id"])]
                endpoints.append(endpoint)
    except sqlite3.Error as exc:
        raise ReconWikiError(f"cannot read Recon database {database}: {exc}") from exc

    targets = sorted({item["base_url"] for item in endpoints if item["base_url"]})
    target = targets[0] if len(targets) == 1 else ", ".join(targets)
    if not target and scans:
        target = str(scans[-1].get("scope_value") or "unknown")
    return {"scans": scans, "target": target or "unknown", "endpoints": endpoints}


def ingest_database(
    root: Path,
    database: Path,
    *,
    kind: str,
    label: str | None = None,
    target_id: str | None = None,
) -> WikiSource:
    if kind not in _KINDS:
        raise ReconWikiError(f"unsupported source kind: {kind}")
    root = init_wiki(root)
    database = database.expanduser().resolve()
    database_hash = _sha256(database)
    inventory = _database_inventory(database)
    label = label or database.parent.name or database.stem
    logical_target = target_id or inventory["target"]
    identity = {
        "database_sha256": database_hash, "kind": kind, "label": label,
        "target_id": logical_target,
    }
    source_id = f"{kind}-{_canonical_hash(identity)[:16]}"
    raw_path = root / "raw" / f"{source_id}.json"
    created = not raw_path.exists()
    if created:
        endpoints = inventory["endpoints"]
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "source_id": source_id,
            "kind": kind,
            "label": label,
            "target": inventory["target"],
            "target_id": logical_target,
            "captured_at": _now(),
            "database_path": str(database),
            "database_sha256": database_hash,
            "scan_records": inventory["scans"],
            "endpoints": endpoints,
            "inventory_sha256": _canonical_hash(endpoints),
        }
        raw_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        with (root / "wiki/log.md").open("a", encoding="utf-8") as stream:
            stream.write(
                f"\n- {_now()} — ingested `{source_id}` as `{kind}` from `{database}`.\n"
            )
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    _write_source_page(root, payload)
    _rebuild_catalog(root)
    return WikiSource(
        source_id=source_id,
        kind=kind,
        label=str(payload["label"]),
        target=str(payload.get("target_id") or payload["target"]),
        endpoint_count=len(payload["endpoints"]),
        raw_path=raw_path,
        page_path=root / "wiki/sources" / f"{source_id}.md",
        created=created,
    )


def _load_sources(root: Path) -> list[dict[str, Any]]:
    sources = []
    for path in sorted((root / "raw").glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReconWikiError(f"invalid raw source {path}: {exc}") from exc
        value["_raw_path"] = path
        sources.append(value)
    return sources


def _route_keys(payload: dict[str, Any], *, include_excluded: bool) -> set[tuple[str, str]]:
    def coverage_path(value: object) -> str:
        path = str(value)
        path = re.sub(r"\{[^/{}]+\}|<[^/<>]+>|:id(?=/|$)", ":id", path)
        return path
    return {
        (str(item["method"]).upper(), coverage_path(item["normalized_path"]))
        for item in payload["endpoints"]
        # Passive form/JavaScript/OpenAPI declarations are part of Recon's
        # route inventory even though they have not been requested. Keep them
        # in discovery recall while continuing to exclude static assets and
        # other non-service records by default.
        if (include_excluded or not item.get("is_excluded")
            or item.get("exclude_reason") == "unverified_candidate")
    }


def _route_evidence_classes(payload: dict[str, Any], *, include_excluded: bool) -> dict[
        tuple[str, str], str]:
    """Classify each coverage key by its strongest runtime evidence."""
    strength = {"inferred": 0, "declared": 1, "confirmed": 2}
    result: dict[tuple[str, str], str] = {}
    for item in payload["endpoints"]:
        if not (include_excluded or not item.get("is_excluded")
                or item.get("exclude_reason") == "unverified_candidate"):
            continue
        path = re.sub(r"\{[^/{}]+\}|<[^/<>]+>|:id(?=/|$)", ":id",
                      str(item["normalized_path"]))
        key = str(item["method"]).upper(), path
        tools = {value.strip() for value in str(item.get("source_tools") or "").split(",")}
        if item.get("verification_status") != "candidate":
            category = "confirmed"
        elif tools - {"passive_route_inference", ""}:
            category = "declared"
        else:
            category = "inferred"
        if strength[category] > strength.get(result.get(key, "inferred"), -1):
            result[key] = category
        elif key not in result:
            result[key] = category
    return result


def _write_source_page(root: Path, payload: dict[str, Any]) -> None:
    keys = sorted(_route_keys(payload, include_excluded=True))
    methods: dict[str, int] = {}
    for method, _ in keys:
        methods[method] = methods.get(method, 0) + 1
    method_text = ", ".join(f"{key} {value}" for key, value in sorted(methods.items()))
    lines = [
        f"# {_md(payload['label'])}", "",
        f"- Source ID: `{payload['source_id']}`",
        f"- Provenance: `{payload['kind']}`",
        f"- Logical target: `{_md(payload.get('target_id') or payload['target'])}`",
        f"- Target: `{_md(payload['target'])}`",
        f"- Database SHA-256: `{payload['database_sha256']}`",
        f"- Unique method/path routes: **{len(keys)}** ({method_text or 'none'})",
        "", "## Route inventory", "", "| Method | Normalized path |", "|---|---|",
    ]
    lines.extend(f"| {_md(method)} | `{_md(path)}` |" for method, path in keys)
    (root / "wiki/sources" / f"{payload['source_id']}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8",
    )


def _rebuild_catalog(root: Path) -> None:
    sources = _load_sources(root)
    index = [
        "# Recon Wiki", "",
        "Runtime, source, and benchmark evidence remain separate. Coverage uses method + path.",
        "", "| Source | Kind | Target | Routes |", "|---|---|---|---:|",
    ]
    by_target: dict[str, list[dict[str, Any]]] = {}
    for source in sources:
        count = len(_route_keys(source, include_excluded=True))
        index.append(
            f"| [{_md(source['label'])}](sources/{source['source_id']}.md) "
            f"| `{source['kind']}` | {_md(source['target'])} | {count} |"
        )
        by_target.setdefault(str(source.get("target_id") or source["target"]), []).append(source)
    (root / "wiki/index.md").write_text("\n".join(index) + "\n", encoding="utf-8")

    for target, target_sources in by_target.items():
        lines = [f"# {_md(target)}", "", "| Source | Kind | Routes |", "|---|---|---:|"]
        for source in target_sources:
            count = len(_route_keys(source, include_excluded=True))
            lines.append(
                f"| [{_md(source['label'])}](../sources/{source['source_id']}.md) "
                f"| `{source['kind']}` | {count} |"
            )
        (root / "wiki/targets" / f"{_slug(target)}.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8",
        )


def compare_databases(
    root: Path,
    *,
    observed_database: Path,
    baseline_database: Path,
    baseline_kind: str = "source",
    target_id: str | None = None,
    include_excluded: bool = False,
) -> CoverageComparison:
    observed = ingest_database(
        root, observed_database, kind="runtime", label="runtime observed",
        target_id=target_id,
    )
    if baseline_kind not in {"source", "benchmark"}:
        raise ReconWikiError("coverage baseline kind must be source or benchmark")
    baseline = ingest_database(
        root, baseline_database, kind=baseline_kind, label="coverage baseline",
        target_id=target_id,
    )
    observed_payload = json.loads(observed.raw_path.read_text(encoding="utf-8"))
    baseline_payload = json.loads(baseline.raw_path.read_text(encoding="utf-8"))
    observed_target = observed_payload.get("target_id") or observed_payload["target"]
    baseline_target = baseline_payload.get("target_id") or baseline_payload["target"]
    if observed_target != baseline_target:
        raise ReconWikiError(
            "coverage sources describe different targets: "
            f"{observed_target} != {baseline_target}; pass an explicit target ID "
            "only when both databases represent the same deployment"
        )
    observed_keys = _route_keys(observed_payload, include_excluded=include_excluded)
    baseline_keys = _route_keys(baseline_payload, include_excluded=include_excluded)
    if not baseline_keys:
        raise ReconWikiError("coverage baseline has no comparable endpoints")
    matched = observed_keys & baseline_keys
    evidence_classes = _route_evidence_classes(
        observed_payload, include_excluded=include_excluded)
    evidence_counts = {
        category: sum(value == category for value in evidence_classes.values())
        for category in ("confirmed", "declared", "inferred")
    }
    matched_evidence_counts = {
        category: sum(key in matched and value == category
                      for key, value in evidence_classes.items())
        for category in ("confirmed", "declared", "inferred")
    }
    missing = tuple(sorted(baseline_keys - observed_keys))
    exact_recall = len(matched) / len(baseline_keys) if baseline_keys else 1.0
    observed_paths = {path for _, path in observed_keys}
    baseline_paths = {path for _, path in baseline_keys}
    path_recall = (
        len(observed_paths & baseline_paths) / len(baseline_paths) if baseline_paths else 1.0
    )
    comparison_id = (
        f"{observed.source_id}--{baseline.source_id}--"
        f"{'all' if include_excluded else 'service'}"
    )
    report_path = root.expanduser().resolve() / "wiki/comparisons" / f"{comparison_id}.md"
    per_method: dict[str, tuple[int, int]] = {}
    for method in sorted({method for method, _ in baseline_keys}):
        expected = {key for key in baseline_keys if key[0] == method}
        per_method[method] = (len(expected & observed_keys), len(expected))
    lines = [
        "# Recon coverage comparison", "",
        f"- Observed: [`{observed.source_id}`](../sources/{observed.source_id}.md)",
        f"- Baseline: [`{baseline.source_id}`](../sources/{baseline.source_id}.md)",
        f"- Exact method/path recall: **{len(matched)}/{len(baseline_keys)} "
        f"({exact_recall:.2%})**",
        f"- Path-only recall: **{path_recall:.2%}**",
        "- Passive declared candidates included: **yes**",
        f"- Confirmed runtime routes: **{evidence_counts['confirmed']}** "
        f"(baseline matches: {matched_evidence_counts['confirmed']})",
        f"- Directly declared candidates: **{evidence_counts['declared']}** "
        f"(baseline matches: {matched_evidence_counts['declared']})",
        f"- Convention-inferred candidates: **{evidence_counts['inferred']}** "
        f"(baseline matches: {matched_evidence_counts['inferred']})",
        f"- Excluded endpoints included: **{'yes' if include_excluded else 'no'}**",
        "", "## Recall by method", "", "| Method | Matched | Baseline | Recall |", "|---|---:|---:|---:|",
    ]
    for method, (method_matched, method_total) in per_method.items():
        lines.append(
            f"| {method} | {method_matched} | {method_total} | "
            f"{method_matched / method_total:.2%} |"
        )
    lines.extend(["", "## Missing method/path routes", "", "| Method | Path |", "|---|---|"])
    lines.extend(f"| {method} | `{_md(path)}` |" for method, path in missing)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with (root.expanduser().resolve() / "wiki/log.md").open("a", encoding="utf-8") as stream:
        stream.write(
            f"\n- {_now()} — compared `{observed.source_id}` with `{baseline.source_id}`: "
            f"{len(matched)}/{len(baseline_keys)} ({exact_recall:.2%}).\n"
        )
    return CoverageComparison(
        comparison_id=comparison_id,
        baseline_count=len(baseline_keys),
        observed_count=len(observed_keys),
        matched_count=len(matched),
        exact_recall=exact_recall,
        path_recall=path_recall,
        confirmed_count=evidence_counts["confirmed"],
        declared_candidate_count=evidence_counts["declared"],
        inferred_candidate_count=evidence_counts["inferred"],
        confirmed_matched_count=matched_evidence_counts["confirmed"],
        declared_candidate_matched_count=matched_evidence_counts["declared"],
        inferred_candidate_matched_count=matched_evidence_counts["inferred"],
        missing=missing,
        report_path=report_path,
    )


def lint_wiki(root: Path) -> tuple[str, ...]:
    root = root.expanduser().resolve()
    if not (root / "schema.md").is_file():
        return ("missing schema.md; run recon-wiki init",)
    issues: list[str] = []
    try:
        sources = _load_sources(root)
    except ReconWikiError as exc:
        return (str(exc),)
    seen: set[str] = set()
    for source in sources:
        source_id = str(source.get("source_id", ""))
        if not source_id or source_id in seen:
            issues.append(f"duplicate or missing source_id: {source_id or '<empty>'}")
        seen.add(source_id)
        if source.get("kind") not in _KINDS:
            issues.append(f"{source_id}: invalid provenance kind")
        if source.get("inventory_sha256") != _canonical_hash(source.get("endpoints", [])):
            issues.append(f"{source_id}: immutable endpoint inventory was modified")
        database = Path(str(source.get("database_path", "")))
        if database.is_file() and source.get("database_sha256") != _sha256(database):
            issues.append(f"{source_id}: source database changed after ingestion")
        if not (root / "wiki/sources" / f"{source_id}.md").is_file():
            issues.append(f"{source_id}: missing source Markdown page")
    return tuple(issues)
