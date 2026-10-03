"""Post-run dashboard adapter for sanitized Attack coverage evidence."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from aidast.attack.coverage_export import _publish
from aidast.attack.wiki import AttackWikiError, compare_sources, database_snapshot, ingest_database, lint_wiki
from aidast.web.recon_wiki import ReconWikiCatalog


class AttackWikiCatalog(ReconWikiCatalog):
    def entries(self) -> list[dict[str, Any]]:
        entries = []
        for name in ("Pipeline.db", "Attack.db"):
            for path in sorted(self.result_root.rglob(name)):
                if not self._inside_root(path) or "AttackWiki" in path.parts:
                    continue
                try:
                    inventory = database_snapshot(path, kind="source")
                    if not inventory["items"]:
                        continue
                    kind = "source" if inventory["execution_mode"] == "source_assisted" else "runtime"
                    relative = path.resolve().relative_to(self.result_root).as_posix()
                    location = Path(relative).parent.as_posix()
                    route_keys = frozenset(
                        (str(item["method"]), str(item["path"]))
                        for item in inventory["items"]
                    )
                    entries.append({"database_id": hashlib.sha256(relative.encode()).hexdigest()[:24],
                        "scan_id": inventory["scan"]["scan_id"], "kind": kind,
                        "label": f"{inventory['scan']['scan_id']} · {location} · {path.name}",
                        "target": ", ".join(inventory["origins"]),
                        "started_at": inventory["scan"]["started_at"] or "",
                        "hypothesis_count": len(inventory["items"]),
                        "execution_mode": inventory["execution_mode"], "_path": path.resolve(),
                        "_route_keys": route_keys})
                except (AttackWikiError, OSError, sqlite3.Error, ValueError):
                    continue
        return sorted(entries, key=lambda item: (item["started_at"], item["scan_id"]), reverse=True)

    def status(self, scan_id: str, *, program_id: str | None = None) -> dict[str, Any]:
        roots = []
        if program_id:
            roots.append(self.result_root / "AttackWiki" / self._slug(program_id))
        roots.extend(sorted((self.result_root / "AttackWiki").glob("*")))
        for root in dict.fromkeys(roots):
            if not self._inside_root(root):
                continue
            value = self._read_state(root).get("scans", {}).get(scan_id)
            if isinstance(value, dict):
                return {"configured": True, **value}
        return {"configured": False, "scan_id": scan_id}

    def accumulate(self, scan_id: str, *, program_id: str, baseline_id: str | None = None,
                   baseline_kind: str = "runtime", target_id: str = "") -> dict[str, Any]:
        entries = self.entries()
        runtime = next((item for item in entries if item["scan_id"] == scan_id), None)
        if runtime is None:
            raise AttackWikiError("Attack/Pipeline coverage database is unavailable for this scan")
        wiki_root = self.result_root / "AttackWiki" / self._slug(program_id)
        if not self._inside_root(wiki_root):
            raise AttackWikiError("Attack Wiki directory is outside the result root")
        logical_target = target_id.strip() or program_id
        source = ingest_database(wiki_root, runtime["_path"], kind="runtime", label=scan_id,
                                 target_id=logical_target, scan_id=scan_id)
        comparison = None
        if baseline_id:
            baseline = next((item for item in entries if item["database_id"] == baseline_id), None)
            if baseline is None:
                raise AttackWikiError("selected baseline is unavailable")
            if baseline_kind not in {"runtime", "source", "benchmark"}:
                raise AttackWikiError("unsupported baseline provenance")
            if baseline_kind == "runtime" and baseline["kind"] != "runtime":
                raise AttackWikiError("source-assisted evidence cannot be a black-box runtime baseline")
            if baseline_kind == "source" and baseline["kind"] != "source":
                raise AttackWikiError("selected baseline source provenance does not match")
            if not runtime["_route_keys"] & baseline["_route_keys"]:
                raise AttackWikiError(
                    "selected baseline route inventory does not overlap this scan; "
                    "choose a baseline for the same application"
                )
            baseline_source = ingest_database(wiki_root, baseline["_path"], kind=baseline_kind,
                label=baseline["scan_id"], target_id=logical_target, scan_id=baseline["scan_id"])
            comparison = compare_sources(wiki_root, observed_source_id=source["source_id"],
                                         baseline_source_ids=[baseline_source["source_id"]])
            report_path = Path(comparison["report_path"])
            comparison.update({"report_path": report_path.relative_to(self.result_root).as_posix(),
                "report_markdown": report_path.read_text(encoding="utf-8"), "missing": len(comparison["missing"]),
                "baseline_id": baseline_id, "baseline_label": baseline["label"], "baseline_kind": baseline_kind})
        issues = lint_wiki(wiki_root)
        payload = {"scan_id": scan_id, "program_id": program_id, "target_id": logical_target,
            **{key: source[key] for key in ("source_id", "hypothesis_count", "tested_count", "candidate_count", "confirmed_count", "execution_mode")},
            "wiki_index": (wiki_root / "wiki/index.md").relative_to(self.result_root).as_posix(),
            "comparison": comparison, "lint": {"ok": not issues, "issues": list(issues)}}
        state = self._read_state(wiki_root)
        state.setdefault("scans", {})[scan_id] = payload
        _publish(self._state_path(wiki_root), json.dumps(state, ensure_ascii=False, indent=2) + "\n")
        return {"configured": True, **payload}
