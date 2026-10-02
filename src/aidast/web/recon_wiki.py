"""Dashboard adapter for the local Recon Wiki.

Only Recon databases below the configured result root are addressable.  The
browser receives stable opaque IDs instead of filesystem paths.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from aidast.recon.wiki import compare_databases, ingest_database, lint_wiki


class ReconWikiDashboardError(RuntimeError):
    pass


class ReconWikiCatalog:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()

    def _inside_root(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.result_root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    def _inspect(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file() or not self._inside_root(path):
            return None
        try:
            relative = path.resolve().relative_to(self.result_root).as_posix()
            with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
                connection.row_factory = sqlite3.Row
                tables = self._tables(connection)
                if not {"scans", "endpoints"}.issubset(tables):
                    return None
                scan = connection.execute(
                    "SELECT scan_id,scope_value,status,started_at FROM scans "
                    "ORDER BY started_at DESC,scan_id DESC LIMIT 1"
                ).fetchone()
                if scan is None:
                    return None
                endpoint_count = int(connection.execute(
                    "SELECT COUNT(*) FROM endpoints"
                ).fetchone()[0])
                method_counts = {
                    str(row[0] or "GET").upper(): int(row[1])
                    for row in connection.execute(
                        "SELECT upper(coalesce(method,'GET')),COUNT(*) FROM endpoints GROUP BY 1"
                    )
                }
                target = str(scan["scope_value"] or "unknown")
                if {"origins", "assets"}.issubset(tables):
                    origin_columns = {
                        str(row[1]) for row in connection.execute("PRAGMA table_info(origins)")
                    }
                    if "base_url" in origin_columns:
                        targets = [
                            str(row[0]) for row in connection.execute(
                                "SELECT DISTINCT base_url FROM origins WHERE base_url IS NOT NULL "
                                "AND trim(base_url)<>'' ORDER BY base_url"
                            )
                        ]
                        if targets:
                            target = ", ".join(targets)
                kind = "runtime"
                display_label = f"{scan['scan_id']} · {target}"
                if "recon_reference_metadata" in tables:
                    reference = connection.execute(
                        "SELECT target_name,version FROM recon_reference_metadata LIMIT 1"
                    ).fetchone()
                    if reference is not None:
                        kind = "source"
                        display_label = (
                            f"{reference['target_name']} v{reference['version']} source routes · "
                            f"{target}"
                        )
                if "benchmark_catalog_items" in tables and connection.execute(
                    "SELECT COUNT(*) FROM benchmark_catalog_items"
                ).fetchone()[0]:
                    kind = "benchmark"
                elif "endpoint_observations" in tables:
                    observation_columns = {
                        str(row[1]) for row in connection.execute(
                            "PRAGMA table_info(endpoint_observations)"
                        )
                    }
                    if "discovery_kind" in observation_columns:
                        kinds = {
                            str(row[0]) for row in connection.execute(
                                "SELECT DISTINCT discovery_kind FROM endpoint_observations "
                                "WHERE discovery_kind IS NOT NULL"
                            )
                        }
                        if kinds and kinds <= {"source_route"}:
                            kind = "source"
                if kind == "runtime":
                    endpoint_columns = {
                        str(row[1]) for row in connection.execute("PRAGMA table_info(endpoints)")
                    }
                    if "source_tools" in endpoint_columns and connection.execute(
                        "SELECT 1 FROM endpoints WHERE source_tools LIKE '%flask_source_import%' LIMIT 1"
                    ).fetchone():
                        kind = "source"
        except (OSError, sqlite3.Error, ValueError):
            return None
        database_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:24]
        return {
            "database_id": database_id,
            "scan_id": str(scan["scan_id"]),
            "status": str(scan["status"] or "unknown"),
            "started_at": str(scan["started_at"] or ""),
            "kind": kind,
            "target": target,
            "endpoint_count": endpoint_count,
            "method_counts": method_counts,
            "label": display_label,
            "_path": path.resolve(),
        }

    def entries(self) -> list[dict[str, Any]]:
        entries = []
        for path in sorted(self.result_root.rglob("Recon.db")):
            if "ReconWiki" in path.parts:
                continue
            entry = self._inspect(path)
            if entry is not None:
                entries.append(entry)
        entries.sort(key=lambda item: (item["started_at"], item["scan_id"]), reverse=True)
        return entries

    def public_entries(self) -> list[dict[str, Any]]:
        return [
            {key: value for key, value in item.items() if not key.startswith("_")}
            for item in self.entries()
        ]

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-.").lower()
        return slug[:100] or "unknown"

    def _state_path(self, wiki_root: Path) -> Path:
        return wiki_root / "dashboard.json"

    def _read_state(self, wiki_root: Path) -> dict[str, Any]:
        path = self._state_path(wiki_root)
        if not path.is_file():
            return {"version": 1, "scans": {}}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "scans": {}}
        return value if isinstance(value, dict) and isinstance(value.get("scans"), dict) else {
            "version": 1, "scans": {},
        }

    def status(self, scan_id: str, *, program_id: str | None = None) -> dict[str, Any]:
        roots = []
        if program_id:
            roots.append(self.result_root / "ReconWiki" / self._slug(program_id))
        roots.extend(sorted((self.result_root / "ReconWiki").glob("*")))
        seen: set[Path] = set()
        for root in roots:
            root = root.resolve()
            if root in seen or not self._inside_root(root):
                continue
            seen.add(root)
            item = self._read_state(root).get("scans", {}).get(scan_id)
            if isinstance(item, dict):
                return {"configured": True, **item}
        return {"configured": False, "scan_id": scan_id}

    def accumulate(
        self,
        scan_id: str,
        *,
        program_id: str,
        baseline_id: str | None,
        baseline_kind: str,
        target_id: str,
    ) -> dict[str, Any]:
        entries = self.entries()
        runtime_matches = [
            item for item in entries
            if item["scan_id"] == scan_id and item["kind"] == "runtime"
        ]
        if not runtime_matches:
            raise ReconWikiDashboardError(f"runtime Recon.db not found for {scan_id}")
        runtime = runtime_matches[0]
        logical_target = target_id.strip() or program_id
        wiki_root = self.result_root / "ReconWiki" / self._slug(program_id)
        source = ingest_database(
            wiki_root, runtime["_path"], kind="runtime", label=scan_id,
            target_id=logical_target,
        )
        comparison_payload = None
        if baseline_id:
            baseline = next((item for item in entries if item["database_id"] == baseline_id), None)
            if baseline is None:
                raise ReconWikiDashboardError("selected baseline Recon.db is unavailable")
            if baseline_kind not in {"source", "benchmark"} or baseline["kind"] != baseline_kind:
                raise ReconWikiDashboardError("selected baseline provenance does not match")
            comparison = compare_databases(
                wiki_root,
                observed_database=runtime["_path"],
                baseline_database=baseline["_path"],
                baseline_kind=baseline_kind,
                target_id=logical_target,
            )
            comparison_payload = asdict(comparison)
            comparison_payload["report_path"] = str(
                comparison.report_path.relative_to(self.result_root)
            )
            comparison_payload["missing"] = len(comparison.missing)
            comparison_payload["report_markdown"] = comparison.report_path.read_text(
                encoding="utf-8"
            )
            comparison_payload["baseline_id"] = baseline_id
            comparison_payload["baseline_label"] = baseline["label"]
            comparison_payload["baseline_kind"] = baseline_kind
        issues = lint_wiki(wiki_root)
        payload = {
            "scan_id": scan_id,
            "program_id": program_id,
            "target_id": logical_target,
            "source_id": source.source_id,
            "endpoint_count": source.endpoint_count,
            "wiki_index": str((wiki_root / "wiki/index.md").relative_to(self.result_root)),
            "comparison": comparison_payload,
            "lint": {"ok": not issues, "issues": list(issues)},
        }
        state = self._read_state(wiki_root)
        state.setdefault("scans", {})[scan_id] = payload
        state_path = self._state_path(wiki_root)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(state_path)
        return {"configured": True, **payload}
