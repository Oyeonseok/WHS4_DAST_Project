"""Persistent Attack evaluation evidence, intentionally outside the execution path.

Snapshots contain coverage coordinates and evidence identifiers only. They do
not contain payloads, credentials, request bodies, or replay instructions.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aidast.attack.coverage_export import _publish
from aidast.recon.db import new_id


class AttackWikiError(RuntimeError):
    """Invalid provenance, incomplete execution, or damaged evaluation evidence."""


KINDS = frozenset({"runtime", "source", "benchmark"})
KEY_FIELDS = ("origin", "method", "path", "vuln_class", "injection_location",
              "parameter_name", "required_identity_role")
TESTED_STATUSES = frozenset({"tested_negative", "candidate", "confirmed"})


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _origin(value: str) -> str:
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and (parts.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
        host += f":{port}"
    return urlunsplit((parts.scheme.lower(), host, "", "", ""))


def _path(value: str) -> str:
    return re.sub(r"\{[^/{}]+\}|<[^/<>]+>|:[A-Za-z_][A-Za-z0-9_]*(?=/|$)",
                  ":id", value.split("?", 1)[0].split("#", 1)[0])


def coverage_key(item: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(item[field]) for field in KEY_FIELDS)


_TARGET_STOP_WORDS = frozenset({
    "aidast", "invalid", "lab", "local", "scope", "comprehensive",
    "http", "https", "scan", "target",
})


def _target_tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", value.casefold())
        if len(token) >= 3 and token not in _TARGET_STOP_WORDS
    }


def prioritize_runtime_history(
    attack_wiki_root: Path, database: Path, *, scan_id: str, target_hint: str,
) -> int:
    """Seed scheduler-only hints from older independent black-box findings.

    Source and benchmark snapshots are ignored. Runtime payloads, request IDs,
    response data, and prior verdicts are not copied into the task context.
    The resulting facts can only affect which already-planned coverage item is
    claimed first; the current run must produce its own evidence and finding.
    """
    root = Path(attack_wiki_root).expanduser().resolve()
    database = Path(database).expanduser().resolve(strict=True)
    hint_tokens = _target_tokens(target_hint)
    if len(hint_tokens) < 2 or not root.is_dir():
        return 0

    historical: dict[tuple[str, ...], int] = {}
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        scan = conn.execute(
            "SELECT started_at FROM scans WHERE scan_id=?", (scan_id,),
        ).fetchone()
        if scan is None:
            raise AttackWikiError("unknown scan for runtime-history priority")
        current_started = str(scan["started_at"] or "")
        current_origins = {
            (urlsplit(str(row[0])).scheme.casefold(),
             (urlsplit(str(row[0])).hostname or "").casefold())
            for row in conn.execute(
                """SELECT DISTINCT o.base_url FROM origins o
                   JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?""",
                (scan_id,),
            )
        }

    for wiki in sorted(path for path in root.iterdir() if path.is_dir()):
        if len(hint_tokens & _target_tokens(wiki.name)) < 2:
            continue
        try:
            sources = _load(wiki)
        except AttackWikiError:
            continue
        for source in sources:
            inventory = source.get("inventory", {})
            historical_scan = inventory.get("scan", {})
            if (
                source.get("kind") != "runtime"
                or inventory.get("execution_mode") != "black_box"
                or str(historical_scan.get("scan_id")) == scan_id
                or not current_started
                or str(historical_scan.get("started_at") or "") >= current_started
            ):
                continue
            for item in inventory.get("items", []):
                if not isinstance(item, dict) or not item.get("tested") or not item.get("candidate"):
                    continue
                parsed = urlsplit(str(item.get("origin") or ""))
                if (parsed.scheme.casefold(), (parsed.hostname or "").casefold()) not in current_origins:
                    continue
                try:
                    key = (
                        str(item["method"]).upper(), _path(str(item["path"])),
                        str(item["vuln_class"]), str(item["injection_location"]),
                        str(item["parameter_name"]), str(item["required_identity_role"]),
                    )
                except KeyError:
                    continue
                historical[key] = historical.get(key, 0) + 1
    if not historical:
        return 0

    inserted = 0
    with sqlite3.connect(database) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT c.coverage_id,c.vuln_class,c.injection_location,
                      c.parameter_name,c.required_identity_role,
                      e.method,e.normalized_path
               FROM attack_coverage_items c
               JOIN endpoints e ON e.endpoint_id=c.endpoint_id
               WHERE c.scan_id=? AND c.status NOT IN ('candidate','confirmed','running')""",
            (scan_id,),
        ).fetchall()
        for row in rows:
            key = (
                str(row["method"]).upper(), _path(str(row["normalized_path"])),
                str(row["vuln_class"]), str(row["injection_location"]),
                str(row["parameter_name"]), str(row["required_identity_role"]),
            )
            count = historical.get(key)
            if not count:
                continue
            cursor = conn.execute(
                """INSERT OR IGNORE INTO attack_facts
                   (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
                   VALUES (?,?,'historical_runtime_priority',?,?,1.0)""",
                (
                    new_id("fact"), scan_id, str(row["coverage_id"]),
                    json.dumps({
                        "historical_black_box_candidate": True,
                        "matching_snapshot_count": count,
                    }, sort_keys=True),
                ),
            )
            inserted += cursor.rowcount
    return inserted


def init_wiki(root: Path) -> Path:
    root = Path(root).expanduser().resolve()
    for relative in ("raw", "wiki/sources", "wiki/targets", "wiki/comparisons"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative, text in {
        "schema.md": "# Attack Wiki schema\n\n"
        "Source and benchmark knowledge is evaluation-only and never becomes Attack planner input. "
        "Older independent black-box runtime candidates may supply coordinate-only scheduler priority; "
        "they never supply payloads, response claims, credentials, or findings.\n\n"
        "`raw` holds immutable sanitized evidence inventories; `wiki` holds derived pages, "
        "a target catalog, comparisons and an append-only log.\n\n"
        "Kinds: runtime is post-run evidence, source is an operator baseline, benchmark "
        "supplies evaluation claims with separately adjudicated verdicts. Source-assisted runs are labeled separately.\n\n"
        "Exact key: origin, method, normalized path, vulnerability class, input location, "
        "parameter name, identity role. Actual testing needs completed same-task HTTP "
        "evidence; confirmation needs completed independent Validation.\n",
        "wiki/index.md": "# Attack Wiki\n\nNo evidence snapshots yet.\n",
        "wiki/log.md": "# Attack Wiki log\n",
    }.items():
        if not (root / relative).exists():
            _publish(root / relative, text)
    return root


def database_snapshot(database: Path, *, kind: str, scan_id: str | None = None) -> dict[str, Any]:
    """Read one consistent SQLite transaction, including committed WAL rows."""
    if kind not in KINDS:
        raise AttackWikiError(f"unsupported evidence kind: {kind}")
    database = Path(database).expanduser().resolve()
    if not database.is_file():
        raise AttackWikiError("Attack/Pipeline database does not exist")
    try:
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"scans", "assets", "origins", "endpoints", "attack_coverage_items"}
            if not required.issubset(tables):
                raise AttackWikiError("not an Attack/Pipeline coverage database")
            scans = conn.execute("SELECT scan_id,scope_type,scope_value,status,started_at,finished_at "
                                 "FROM scans ORDER BY started_at,scan_id").fetchall()
            if scan_id is None:
                if len(scans) != 1:
                    raise AttackWikiError("specify scan_id for a database containing multiple scans")
                scan_id = str(scans[0]["scan_id"])
            scan = next((dict(row) for row in scans if row["scan_id"] == scan_id), None)
            if scan is None:
                raise AttackWikiError(f"unknown scan: {scan_id}")
            stages = [dict(row) for row in conn.execute(
                "SELECT stage_run_id,stage,status,started_at,finished_at FROM stage_runs WHERE scan_id=? "
                "ORDER BY rowid", (scan_id,))] if "stage_runs" in tables else []
            if kind == "runtime":
                attack_stages = [row for row in stages if row["stage"].lower() == "attack"]
                if (scan["status"] not in {"completed", "failed", "cancelled"}
                        or not attack_stages
                        or any(row["status"] in {"pending", "running"} for row in stages)):
                    raise AttackWikiError("runtime evidence requires a terminal post-run Attack stage")
                if "attack_http_requests" in tables and conn.execute(
                    "SELECT 1 FROM attack_http_requests WHERE scan_id=? "
                    "AND (status IN ('reserved','running') OR (status='outcome_unknown' AND finished_at IS NULL)) LIMIT 1",
                    (scan_id,)).fetchone():
                    raise AttackWikiError("runtime evidence still has active HTTP requests")
            rows = conn.execute("""SELECT c.*,e.method,e.normalized_path,e.source_tools,o.base_url
                FROM attack_coverage_items c JOIN endpoints e ON e.endpoint_id=c.endpoint_id
                JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
                WHERE c.scan_id=? AND a.scan_id=c.scan_id ORDER BY c.coverage_id""", (scan_id,)).fetchall()
            items = []
            for row in rows:
                origin, path = _origin(row["base_url"]), _path(row["normalized_path"])
                requests = []
                if kind == "runtime" and "attack_http_requests" in tables and row["last_task_id"]:
                    for request in conn.execute("""SELECT request_id,method,url,endpoint_reference_id FROM attack_http_requests
                        WHERE scan_id=? AND task_id=? AND stage_run_id=? AND status='completed'
                        AND response_status IS NOT NULL AND finished_at IS NOT NULL ORDER BY request_id""",
                        (scan_id, row["last_task_id"], row["last_stage_run_id"])):
                        if (request["method"].upper() == row["method"].upper()
                                and _origin(request["url"]) == origin
                                and (request["endpoint_reference_id"] == row["endpoint_id"]
                                     or _path(urlsplit(request["url"]).path) == path)):
                            requests.append(str(request["request_id"]))
                validation = None
                if kind == "runtime" and "validation_cases" in tables and row["finding_id"]:
                    decision = conn.execute("SELECT case_id,current_status,processing_phase FROM validation_cases "
                        "WHERE scan_id=? AND finding_id=? ORDER BY rowid DESC LIMIT 1",
                        (scan_id, row["finding_id"])).fetchone()
                    if decision:
                        validation = dict(decision)
                tested = row["status"] in TESTED_STATUSES and bool(requests)
                items.append({
                    "origin": origin, "method": row["method"].upper(), "path": path,
                    "vuln_class": row["vuln_class"], "injection_location": row["injection_location"],
                    "parameter_name": row["parameter_name"], "required_identity_role": row["required_identity_role"],
                    "coverage_id": row["coverage_id"], "endpoint_id": row["endpoint_id"],
                    "annotation_id": row["annotation_id"], "status": row["status"],
                    "finding_id": row["finding_id"], "task_id": row["last_task_id"],
                    "stage_run_id": row["last_stage_run_id"], "request_ids": requests,
                    "source_policy_sha256": row["source_policy_sha256"], "validation": validation,
                    "tested": tested, "candidate": tested and bool(row["finding_id"]) and row["status"] in {"candidate", "confirmed"},
                    "confirmed": tested and bool(validation) and validation["current_status"] == "CONFIRMED"
                                 and validation["processing_phase"] == "completed",
                })
            source_assisted = scan["scope_type"] == "source_import" or any(
                "source_import" in str(row["source_tools"] or "") for row in rows)
            if {"endpoint_annotations", "annotation_runs"} <= tables:
                # A catalog imported after a run is evaluation-only. Mark a
                # runtime source-assisted only when its executed coverage was
                # actually created from a source/catalog annotation.
                source_assisted = source_assisted or bool(conn.execute("""SELECT 1
                    FROM attack_coverage_items c
                    JOIN endpoint_annotations an ON an.annotation_id=c.annotation_id
                    JOIN annotation_runs ar ON ar.annotation_run_id=an.annotation_run_id
                    WHERE c.scan_id=? AND ar.scan_id=c.scan_id AND an.category IN
                        ('vulnerability','source_vulnerability','benchmark_catalog_vulnerability') LIMIT 1""",
                    (scan_id,)).fetchone())
            origins = sorted({item["origin"] for item in items})
            return {"scan": scan, "stages": stages, "items": items, "origins": origins,
                    "execution_mode": "source_assisted" if source_assisted else "black_box"}
    except (sqlite3.Error, ValueError) as exc:
        raise AttackWikiError(f"cannot read Attack coverage database: {exc}") from exc


def _load(root: Path) -> list[dict[str, Any]]:
    values = []
    for path in sorted((root / "raw").glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(value, dict) or value.get("kind") not in KINDS
                    or value.get("inventory_sha256") != _hash(value.get("inventory"))):
                raise AttackWikiError(f"invalid snapshot integrity: {path.name}")
            identity = {name: value[name] for name in ("kind", "label", "target_id", "inventory_sha256")}
            expected = f"{value['kind']}-{_hash(identity)[:24]}"
            if value.get("source_id") != expected or path.stem != expected:
                raise AttackWikiError(f"invalid snapshot identity: {path.name}")
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AttackWikiError(f"invalid snapshot: {path.name}") from exc
        values.append(value)
    return values


def _summary(items: list[dict[str, Any]]) -> dict[str, int]:
    return {"hypothesis_count": len({coverage_key(item) for item in items}),
            **{name + "_count": len({coverage_key(item) for item in items if item[name]})
               for name in ("tested", "candidate", "confirmed")}}


def candidate_summary(inventory: dict[str, Any]) -> dict[str, int]:
    """Keep candidate, mapping and adjudication denominators separate."""
    candidates = inventory.get("source_candidates", [])
    def count(field: str, value: str) -> int:
        return len({item["candidate_id"] for item in candidates if item[field] == value})

    return {
        "source_candidate_count": len({item["candidate_id"] for item in candidates}),
        "mapped_candidate_count": count("mapping_status", "reviewed_exact"),
        "unmapped_candidate_count": count("mapping_status", "unmapped"),
        "unassessed_candidate_count": count("adjudication_status", "UNASSESSED"),
        "adjudicated_positive_candidate_count": count("adjudication_status", "VULNERABLE"),
        "adjudicated_negative_candidate_count": count("adjudication_status", "NOT_VULNERABLE"),
        "out_of_scope_candidate_count": count("evaluation_status", "OUT_OF_TEST_SCOPE"),
        "manual_only_candidate_count": count("evaluation_status", "MANUAL_ONLY"),
    }


def _catalog(root: Path, sources: list[dict[str, Any]]) -> None:
    index = ["# Attack Wiki", "", "Evaluation only. Every claim links to its captured evidence.", ""]
    for target in sorted({item["target_id"] for item in sources}):
        target_sources = [item for item in sources if item["target_id"] == target]
        name = _hash(target)[:24]
        index.append(f"- [{_text(target)}](targets/{name}.md) — {len(target_sources)} snapshots")
        lines = [f"# {_text(target)}", "", "Historical evidence is not a claim about the current deployment.", "",
                 "| Snapshot | Kind | Execution mode | Planned | Tested | Candidates | Independent confirmations |",
                 "|---|---|---|---:|---:|---:|---:|"]
        for source in target_sources:
            stats = _summary(source["inventory"]["items"])
            lines.append(f"| [{_text(source['label'])}](../sources/{source['source_id']}.md) | {source['kind']} | "
                f"{source['inventory']['execution_mode']} | {stats['hypothesis_count']} | {stats['tested_count']} | "
                f"{stats['candidate_count']} | {stats['confirmed_count']} |")
        for source in target_sources:
            if "source_candidates" in source["inventory"]:
                lines += ["", f"Source candidate inventory `{source['source_id']}`: "
                          f"`{candidate_summary(source['inventory'])}`."]
        runtime = [item for item in target_sources if item["kind"] == "runtime"]
        historical = _summary([item for source in runtime for item in source["inventory"]["items"]])
        lines += ["", f"Historical union (deduplicated coordinates): `{historical}`.", "",
                  "Outcome history (contradictions are retained, never overwritten):", ""]
        history: dict[tuple[str, ...], list[str]] = {}
        for source in runtime:
            for item in source["inventory"]["items"]:
                history.setdefault(coverage_key(item), []).append(
                    f"[{source['source_id']}](../sources/{source['source_id']}.md): {item['status']} / "
                    f"Validation {item['validation']['current_status'] if item['validation'] else 'not completed'}")
        for key, evidence in sorted(history.items()):
            lines.append(f"- `{_text(' '.join(key))}` — " + "; ".join(evidence))
        _publish(root / "wiki/targets" / f"{name}.md", "\n".join(lines) + "\n")
    _publish(root / "wiki/index.md", "\n".join(index) + "\n")


def ingest_database(root: Path, database: Path, *, kind: str, label: str | None = None,
                    target_id: str | None = None, scan_id: str | None = None) -> dict[str, Any]:
    inventory = database_snapshot(database, kind=kind, scan_id=scan_id)
    return _ingest_inventory(root, inventory, kind=kind, label=label, target_id=target_id,
                             database_path=str(Path(database).expanduser().resolve()))


def _ingest_inventory(root: Path, inventory: dict[str, Any], *, kind: str,
                      label: str | None = None, target_id: str | None = None,
                      database_path: str | None = None) -> dict[str, Any]:
    root = init_wiki(root)
    label = label or str(inventory["scan"]["scan_id"])
    target_id = target_id or ", ".join(inventory["origins"]) or str(inventory["scan"]["scope_value"])
    identity = {"kind": kind, "label": label, "target_id": target_id, "inventory_sha256": _hash(inventory)}
    source_id = f"{kind}-{_hash(identity)[:24]}"
    raw_path = root / "raw" / f"{source_id}.json"
    created = not raw_path.exists()
    if created:
        payload = {"schema_version": 1, **identity, "source_id": source_id,
                   "captured_at": _now(), "database_path": database_path,
                   "inventory": inventory}
        # Exclusive creation keeps repeated ingestion from replacing raw evidence.
        with raw_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        with (root / "wiki/log.md").open("a", encoding="utf-8") as stream:
            stream.write(f"\n- {_now()} ingest `{source_id}` ({kind}).\n")
    sources = _load(root)
    source = next(value for value in sources if value["source_id"] == source_id)
    stats = _summary(source["inventory"]["items"])
    lines = [f"# {_text(label)}", "", f"- Provenance: `{kind}`", f"- Target: `{_text(target_id)}`",
             f"- Execution mode: `{inventory['execution_mode']}`", f"- Scan: `{inventory['scan']['scan_id']}`",
             f"- Inventory SHA256: `{source['inventory_sha256']}`", f"- Coverage: `{stats}`", "",
             f"[Immutable evidence](../../raw/{source_id}.json)", "",
             "A planned hypothesis is not an actual test; an Attack candidate is not an independent confirmation."]
    candidate_stats = candidate_summary(inventory) if "source_candidates" in inventory else {}
    if candidate_stats:
        lines += ["", f"Source candidates: `{candidate_stats}`.", "",
                  "Unmapped candidates have no coverage key. Unassessed candidates are not positive findings.", "",
                  "| Source candidate | Mapping | Source scope | Adjudication |",
                  "|---|---|---|---|"]
        lines += [f"| [{_text(item['candidate_id'])}]({item['source_url']}) | {item['mapping_status']} | "
                  f"{item['evaluation_status']} | {item['adjudication_status']} |"
                  for item in inventory["source_candidates"]]
    _publish(root / "wiki/sources" / f"{source_id}.md", "\n".join(lines) + "\n")
    _catalog(root, sources)
    return {"source_id": source_id, "kind": kind, "target_id": target_id, "created": created,
            "execution_mode": inventory["execution_mode"], **stats,
            **candidate_stats,
            "raw_path": str(raw_path), "page_path": str(root / "wiki/sources" / f"{source_id}.md")}


def compare_sources(root: Path, *, observed_source_id: str, baseline_source_ids: list[str]) -> dict[str, Any]:
    """Compare a finished run against explicit immutable baselines or a prior-run union."""
    root = Path(root).expanduser().resolve()
    sources = {value["source_id"]: value for value in _load(root)}
    if not baseline_source_ids or observed_source_id in baseline_source_ids:
        raise AttackWikiError("select at least one separate baseline snapshot")
    try:
        observed = sources[observed_source_id]
        baselines = [sources[name] for name in sorted(set(baseline_source_ids))]
    except KeyError as exc:
        raise AttackWikiError("comparison snapshot is unavailable") from exc
    if observed["kind"] != "runtime":
        raise AttackWikiError("observed evidence must be runtime")
    if any(source["target_id"] != observed["target_id"] for source in baselines):
        raise AttackWikiError("comparison targets do not match")
    if any(source["inventory"]["origins"] != observed["inventory"]["origins"] for source in baselines):
        raise AttackWikiError("comparison origins do not match; separate deployment aliases explicitly")
    if any(source["inventory"]["scan"]["scan_id"] == observed["inventory"]["scan"]["scan_id"]
           for source in baselines):
        raise AttackWikiError("a run cannot be its own evaluation baseline")
    if any(source["kind"] == "runtime" and
           str(source["inventory"]["scan"]["started_at"]) >= str(observed["inventory"]["scan"]["started_at"])
           for source in baselines):
        raise AttackWikiError("historical runtime baselines must precede the observed run")
    baseline_keys = {coverage_key(item) for source in baselines for item in source["inventory"]["items"]
                     if (source["kind"] != "runtime" or item["tested"])
                     and item.get("baseline_eligible", True)}
    has_candidates = any("source_candidates" in source["inventory"] for source in baselines)
    if not baseline_keys and not has_candidates:
        raise AttackWikiError("baseline contains no eligible coverage coordinates")
    positive_keys = {coverage_key(item) for source in baselines for item in source["inventory"]["items"]
                     if item.get("baseline_eligible", True) and (
                         item["confirmed"] if source["kind"] == "runtime" else
                         item.get("adjudication_status") == "VULNERABLE"
                         and bool(item.get("adjudication_evidence_ref")))}
    negative_keys = {coverage_key(item) for source in baselines for item in source["inventory"]["items"]
                     if source["kind"] != "runtime" and item.get("baseline_eligible", True)
                     and item.get("adjudication_status") == "NOT_VULNERABLE"
                     and bool(item.get("adjudication_evidence_ref"))}
    conflicting_keys = positive_keys & negative_keys
    positive_keys -= conflicting_keys
    observed_items = observed["inventory"]["items"]
    result: dict[str, Any] = {"observed_source_id": observed_source_id,
        "baseline_source_ids": [source["source_id"] for source in baselines], "target_id": observed["target_id"],
        "execution_mode": observed["inventory"]["execution_mode"], "baseline_count": len(baseline_keys),
        "baseline_positive_count": len(positive_keys),
        "baseline_adjudication_conflict_count": len(conflicting_keys),
        "observed_count": len({coverage_key(item) for item in observed_items}),
        "semantics": "Post-run evaluation only. Historical testing is not a current vulnerability claim."}
    if has_candidates:
        candidates = [{**item, "source_id": source["source_id"]} for source in baselines
                      for item in source["inventory"].get("source_candidates", [])]
        result.update(candidate_summary({"source_candidates": candidates}))
        result["source_candidate_histories"] = [
            {key: item[key] for key in ("candidate_id", "source_id", "mapping_status", "adjudication_status")}
            for item in candidates]
        result["unmapped_source_candidates"] = [
            {key: item[key] for key in ("candidate_id", "source_id", "source_url", "evaluation_status", "adjudication_status")}
            for item in candidates if item["mapping_status"] == "unmapped"]
    for name in ("planned", "tested", "candidate", "confirmed"):
        keys = {coverage_key(item) for item in observed_items if name == "planned" or item[name]}
        denominator = positive_keys if name in {"candidate", "confirmed"} else baseline_keys
        matched = denominator & keys
        result[name + "_matched_count"] = len(matched)
        result[name + "_recall"] = len(matched) / len(denominator) if denominator else None
    tested_keys = {coverage_key(item) for item in observed_items if item["tested"]}
    result["missing"] = [dict(zip(KEY_FIELDS, key)) for key in sorted(baseline_keys - tested_keys)]
    # Keep the full claim denominator authoritative: a post-run blocker does
    # not establish that a benchmark claim was ineligible before execution.
    # In particular unsupported also includes exhausted budgets/time limits.
    observed_statuses: dict[tuple[str, ...], set[str]] = {}
    for item in observed_items:
        observed_statuses.setdefault(coverage_key(item), set()).add(item["status"])
    missing_by_disposition: dict[str, list[dict[str, str]]] = {}
    for key in sorted(baseline_keys - tested_keys):
        statuses = observed_statuses.get(key, set())
        disposition = (next(iter(statuses)) if len(statuses) == 1 else
                       "not_planned" if not statuses else "mixed")
        missing_by_disposition.setdefault(disposition, []).append(dict(zip(KEY_FIELDS, key)))
    result["missing_by_disposition"] = missing_by_disposition
    result["missing_disposition_counts"] = {
        name: len(items) for name, items in missing_by_disposition.items()}
    result["denominator_semantics"] = (
        "Coverage recall uses supplied mapped baseline claims (or historically tested coordinates). "
        "Unmapped source candidates have no coverage coordinate and are reported separately. "
        "Positive recall requires explicit evidence-backed adjudication or independent historical confirmation; "
        "source/benchmark provenance alone is not a positive verdict. "
        "Policy, authentication and unsupported dispositions remain visible in the "
        "denominator. Post-run dispositions are not verified eligibility labels; "
        "unsupported may include exhausted budgets. This is coverage recall, "
        "not measured vulnerability detection recall.")
    classes = sorted({key[3] for key in baseline_keys})
    result["by_vulnerability"] = {name: {"baseline": len({key for key in baseline_keys if key[3] == name}),
        "tested": len({key for key in baseline_keys & tested_keys if key[3] == name})} for name in classes}
    result["comparison_id"] = "comparison-" + _hash(result)[:24]
    report_path = root / "wiki/comparisons" / f"{result['comparison_id']}.md"
    lines = ["# Attack coverage recall", "", result["semantics"], "",
        f"- Observed: [{observed_source_id}](../sources/{observed_source_id}.md)",
        *[f"- Baseline: [{source['source_id']}](../sources/{source['source_id']}.md) ({source['kind']})" for source in baselines],
        f"- Execution mode: `{result['execution_mode']}`", f"- Coverage denominator: {result['baseline_count']}",
        f"- Positive finding denominator: {result['baseline_positive_count']}", "",
        result["denominator_semantics"], "",
        f"- Missing test dispositions: `{result['missing_disposition_counts']}`", "",
        "| Evidence level | Matched | Recall |", "|---|---:|---:|",
        *[f"| {name} | {result[name + '_matched_count']} | " +
          (f"{result[name + '_recall']:.2%}" if result[name + '_recall'] is not None else "N/A") + " |"
          for name in ("planned", "tested", "candidate", "confirmed")], "", "Missing actual tests:", "",
        *[f"- `{_text(' '.join(coverage_key(item)))}`" for item in result["missing"]]]
    if has_candidates:
        lines += ["", f"- Source candidate inventory: `{candidate_summary({'source_candidates': candidates})}`",
                  "", "Unmapped source candidates (excluded from coverage and positive denominators):", "",
                  *[f"- [{_text(item['candidate_id'])}]({item['source_url']}) — "
                    f"{item['evaluation_status']} / {item['adjudication_status']}"
                    for item in result["unmapped_source_candidates"]]]
    _publish(report_path, "\n".join(lines) + "\n")
    _publish(report_path.with_suffix(".json"), json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    result["report_path"] = str(report_path)
    return result


def lint_wiki(root: Path) -> tuple[str, ...]:
    root = Path(root).expanduser().resolve()
    if not (root / "schema.md").is_file():
        return ("missing schema.md",)
    try:
        sources = _load(root)
    except AttackWikiError as exc:
        return (str(exc),)
    issues = []
    for source in sources:
        if not (root / "wiki/sources" / f"{source['source_id']}.md").is_file():
            issues.append(f"missing source page: {source['source_id']}")
    return tuple(issues)
