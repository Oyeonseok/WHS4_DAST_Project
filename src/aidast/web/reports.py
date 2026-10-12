"""Read-only projection of integrity-bound local report drafts."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


_REPORT_ID = re.compile(r"^report_[0-9a-f]{32}$")
_SCAN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class ReportNotFoundError(LookupError):
    pass


class ReportCatalog:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()

    def list(self, *, scan_id: str | None = None) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        root = self.result_root / "ReportRun"
        if not root.is_dir():
            return reports
        for database in root.rglob("Report.db"):
            item = self._read(database)
            if item is None or (scan_id is not None and item["scan_id"] != scan_id):
                continue
            reports.append({key: value for key, value in item.items() if key != "markdown"})
        return sorted(reports, key=lambda item: item["created_at"], reverse=True)[:500]

    def get(self, report_id: str) -> dict[str, Any]:
        if not _REPORT_ID.fullmatch(report_id):
            raise ReportNotFoundError("invalid report identifier")
        root = self.result_root / "ReportRun"
        if root.is_dir():
            for database in root.rglob("Report.db"):
                item = self._read(database)
                if item is not None and item["report_id"] == report_id:
                    return item
        raise ReportNotFoundError("report draft not found")

    def scan_summary(self, scan_id: str) -> dict[str, Any]:
        """Read one deterministic execution summary without trusting paths from it."""
        if not _SCAN_ID.fullmatch(scan_id):
            raise ReportNotFoundError("invalid scan identifier")
        root = self.result_root / "ReportRun"
        if not root.is_dir():
            raise ReportNotFoundError("scan summary not found")
        for document in root.rglob("ScanSummary.json"):
            try:
                if any(path.is_symlink() for path in (document, *document.parents)):
                    continue
                resolved = document.resolve(strict=True)
                resolved.relative_to(root.resolve(strict=True))
                if not resolved.is_file() or resolved.stat().st_size > 2_000_000:
                    continue
                payload = json.loads(resolved.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or payload.get("scan_id") != scan_id:
                    continue
                markdown_path = resolved.with_name("ScanSummary.md")
                if markdown_path.is_symlink() or not markdown_path.is_file():
                    continue
                markdown = markdown_path.read_text(encoding="utf-8")
                if len(markdown.encode("utf-8")) > 2_000_000:
                    continue
                return {**payload, "markdown": markdown}
            except (OSError, UnicodeError, ValueError, TypeError):
                continue
        raise ReportNotFoundError("scan summary not found")

    def database(self, report_id: str) -> Path:
        """Resolve an internal report path and constrain its source to this root."""
        from aidast.reporting.runtime import ReportError

        if not _REPORT_ID.fullmatch(report_id):
            raise ReportNotFoundError("invalid report identifier")
        root = self.result_root / "ReportRun"
        if root.is_dir():
            for database in root.rglob("Report.db"):
                item = self._read(database)
                if item is None or item['report_id'] != report_id:
                    continue
                resolved = database.resolve(strict=True)
                if any(path.is_symlink() for path in (database, *database.parents)):
                    raise ReportError("report source cannot be verified")
                try:
                    with closing(sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True)) as conn:
                        rows = conn.execute('SELECT source_path FROM report_runs').fetchall()
                    if len(rows) != 1 or not isinstance(rows[0][0], str):
                        raise ValueError
                    source = resolved.parent / rows[0][0]
                    if any(path.is_symlink() for path in (source, *source.parents)):
                        raise ValueError
                    source.resolve(strict=True).relative_to(self.result_root)
                    if not source.is_file():
                        raise ValueError
                except (OSError, sqlite3.Error, TypeError, ValueError):
                    raise ReportError("report source cannot be verified") from None
                return resolved
        raise ReportNotFoundError("report draft not found")

    def _read(self, database: Path) -> dict[str, Any] | None:
        try:
            if any(path.is_symlink() for path in (database, *database.parents)):
                return None
            resolved = database.resolve(strict=True)
            resolved.relative_to(self.result_root)
            if not resolved.is_file() or resolved.stat().st_size > 50_000_000:
                return None
            with closing(
                sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, timeout=2)
            ) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                run = conn.execute("SELECT * FROM report_runs").fetchall()
                if len(run) != 1:
                    return None
                run = run[0]
                required = {"report_id", "context_json", "created_at", "source_path"}
                if not required.issubset(run.keys()) or not isinstance(run["report_id"], str):
                    return None
                if not _REPORT_ID.fullmatch(run["report_id"]):
                    return None
                draft = conn.execute(
                    "SELECT markdown,markdown_sha256,created_at FROM report_drafts WHERE report_id=?",
                    (run["report_id"],),
                ).fetchall()
                if len(draft) != 1:
                    return None
                draft = draft[0]
            markdown = draft["markdown"]
            if not isinstance(markdown, str):
                return None
            if len(markdown.encode("utf-8")) > 2_000_000:
                return None
            if hashlib.sha256(markdown.encode("utf-8")).hexdigest() != draft["markdown_sha256"]:
                return None
            context = json.loads(run["context_json"])
            if not isinstance(context, dict):
                return None
            from aidast.reporting.runtime import PLATFORMS
            platform = context.get("platform")
            if platform not in PLATFORMS:
                return None
            from aidast.reporting.presentation import report_language
            from aidast.reporting.submission import sanitize_preview
            language = report_language(resolved, platform=platform)

            source_path = run['source_path']
            if not isinstance(source_path, str):
                return None
            markdown = sanitize_preview(markdown, paths=(str(resolved), str(resolved.parent), source_path,
                                                       str((resolved.parent / source_path).resolve())))
            title = next(
                (line.lstrip("# ").strip() for line in markdown.splitlines() if line.startswith("#")),
                "Local report draft",
            )[:200]
            # Older report drafts bind a validation record through context.source
            # rather than storing the shared case/scan columns on report_runs.
            source = context.get("source")
            source = source if isinstance(source, dict) else {}
            scan_id = run["scan_id"] if "scan_id" in run.keys() else source.get("scan_id")
            case_id = run["case_id"] if "case_id" in run.keys() else ""
            if not isinstance(scan_id, str) or not isinstance(case_id, str):
                return None
            return {
                "report_id": run["report_id"],
                "scan_id": scan_id[:128],
                "case_id": case_id[:256],
                "platform": platform,
                "language": language,
                "title": title,
                "created_at": str(draft["created_at"] or run["created_at"]),
                "markdown": markdown,
            }
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError):
            return None
