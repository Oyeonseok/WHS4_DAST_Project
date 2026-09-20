"""Asynchronous, explicitly reviewed Scope collection for the local dashboard."""

from __future__ import annotations

import re
import shutil
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aidast.agents.main import CodexMainAgent
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.scope.models import ScopeDocument
from aidast.scope.paths import identify_program
from aidast.scope.reader import PlaywrightProgramPageReader, RuntimeBrowserProgramPageReader

from .programs import ProgramRegistry


_JOB_ID = re.compile(r"^scopejob_[0-9a-f]{32}$")
_ACTIVE = {"collecting", "awaiting_browser"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ScopeCollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_mode: Literal["headless", "runtime-browser"] = "headless"
    identity: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def require_runtime_identity(self) -> "ScopeCollectionRequest":
        if self.login_mode == "runtime-browser" and not (self.identity or "").strip():
            raise ValueError("runtime-browser collection requires an identity label")
        return self


class ScopeDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["yes", "no"]
    approved_by: str | None = Field(default=None, max_length=160)
    confirmation: bool = False

    @model_validator(mode="after")
    def validate_yes(self) -> "ScopeDecisionRequest":
        if self.decision == "yes":
            if not (self.approved_by or "").strip():
                raise ValueError("Yes requires the reviewer name")
            if not self.confirmation:
                raise ValueError("Yes requires explicit confirmation")
        return self


class ScopeWorkflowManager:
    def __init__(
        self,
        result_root: Path,
        registry: ProgramRegistry,
        *,
        agent_factory: Callable[[], Any] | None = None,
        public_reader_factory: Callable[[], Any] | None = None,
        runtime_reader_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.registry = registry
        self.database = self.result_root / ".webui" / "scope_jobs.db"
        self.draft_root = self.result_root / ".webui" / "scope-drafts"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.draft_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._browser_events: dict[str, threading.Event] = {}
        self._agent_factory = agent_factory or (lambda: CodexMainAgent(timeout_seconds=300))
        self._public_reader_factory = public_reader_factory
        self._runtime_reader_factory = runtime_reader_factory
        with closing(sqlite3.connect(self.database)) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scope_jobs (
                  job_id TEXT PRIMARY KEY NOT NULL,
                  program_key TEXT UNIQUE NOT NULL,
                  status TEXT NOT NULL,
                  login_mode TEXT NOT NULL,
                  draft_path TEXT,
                  error TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scope_job_events (
                  job_id TEXT NOT NULL,
                  event_id INTEGER NOT NULL,
                  occurred_at TEXT NOT NULL,
                  level TEXT NOT NULL,
                  message TEXT NOT NULL,
                  PRIMARY KEY(job_id,event_id)
                );
                """
            )
            interrupted = conn.execute(
                "SELECT job_id FROM scope_jobs WHERE status IN ('collecting','awaiting_browser')"
            ).fetchall()
            for (job_id,) in interrupted:
                conn.execute(
                    "UPDATE scope_jobs SET status='failed',error=?,updated_at=? WHERE job_id=?",
                    ("dashboard restarted before collection finished", _now(), job_id),
                )
                self._append_event(conn, job_id, "error", "Scope collection was interrupted by a dashboard restart.")
            conn.commit()

    def statuses(self) -> dict[str, dict[str, Any]]:
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM scope_jobs").fetchall()
        return {
            f"registered-{str(row['program_key'])[:12]}": self._public_job(row)
            for row in rows
        }

    def start(self, program_id: str, request: ScopeCollectionRequest) -> dict[str, Any]:
        program = self.registry.get(program_id)
        output_dir = identify_program(str(program["program_url"])).under(
            self.result_root / "Scope"
        ).resolve(strict=False)
        if output_dir.exists():
            ScopeCoordinator(output_dir).verify_approval()
            return self._record_terminal(program, "approved", "A verified approved Scope already exists.")

        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.row_factory = sqlite3.Row
            previous = conn.execute(
                "SELECT * FROM scope_jobs WHERE program_key=?", (program["program_key"],)
            ).fetchone()
            if previous is not None and previous["status"] in _ACTIVE:
                raise ValueError("Scope collection is already running")
            if previous is not None and previous["status"] == "review_required":
                raise ValueError("a Scope draft is already waiting for review")
            if previous is not None and previous["draft_path"]:
                self._discard_path(Path(previous["draft_path"]))
            job_id = f"scopejob_{uuid4().hex}"
            now = _now()
            conn.execute(
                """INSERT INTO scope_jobs
                (job_id,program_key,status,login_mode,draft_path,error,created_at,updated_at)
                VALUES (?,?, 'collecting', ?,NULL,NULL,?,?)
                ON CONFLICT(program_key) DO UPDATE SET
                job_id=excluded.job_id,status='collecting',login_mode=excluded.login_mode,
                draft_path=NULL,error=NULL,created_at=excluded.created_at,updated_at=excluded.updated_at""",
                (job_id, program["program_key"], request.login_mode, now, now),
            )
            self._append_event(conn, job_id, "info", "Scope collection started.")
        thread = threading.Thread(
            target=self._collect,
            args=(job_id, program, request, output_dir),
            name=f"aidast-{job_id}",
            daemon=True,
        )
        thread.start()
        return self.get_job(program_id)

    def browser_ready(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        if job["status"] != "awaiting_browser":
            raise ValueError("this Scope job is not waiting for browser confirmation")
        event = self._browser_events.get(str(job["job_id"]))
        if event is None:
            raise ValueError("browser confirmation is no longer available")
        event.set()
        self._update(str(job["job_id"]), status="collecting", level="info", message="Browser login confirmation received; capturing the exact program page.")
        return self.get_job(program_id)

    def get_job(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        return self._public_job(job)

    def draft(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        if job["status"] != "review_required" or not job["draft_path"]:
            raise ValueError("no Scope draft is waiting for review")
        draft = self._validated_draft_path(Path(job["draft_path"]))
        document = ScopeDocument.model_validate_json(
            (draft / "Scope.json").read_text(encoding="utf-8")
        )
        analysis = document.analysis
        return {
            "scope_id": document.scope_id,
            "created_at": document.created_at.isoformat(),
            "source_url": str(document.source.final_url),
            "program_name": analysis.program_name,
            "program_description": analysis.program_description,
            "in_scope_assets": [item.model_dump(mode="json") for item in analysis.in_scope_assets],
            "out_of_scope_assets": [item.model_dump(mode="json") for item in analysis.out_of_scope_assets],
            "allowed_activities": analysis.allowed_activities,
            "prohibited_activities": analysis.prohibited_activities,
            "submission_requirements": analysis.submission_requirements,
            "operational_constraints": analysis.operational_constraints,
            "safe_harbor": analysis.safe_harbor,
            "ambiguities": analysis.ambiguities,
            "source_evidence": [item.model_dump(mode="json") for item in analysis.source_evidence],
        }

    def decide(self, program_id: str, request: ScopeDecisionRequest) -> dict[str, Any]:
        job, program = self._job_and_program(program_id)
        if job["status"] != "review_required" or not job["draft_path"]:
            raise ValueError("no Scope draft is waiting for a Yes/No decision")
        draft = self._validated_draft_path(Path(job["draft_path"]))
        if request.decision == "no":
            self._discard_path(draft)
            self._update(str(job["job_id"]), status="rejected", draft_path=None, level="warning", message="Scope draft rejected by the operator; no approval artifact was created.")
            return self.get_job(program_id)

        output_dir = identify_program(str(program["program_url"])).under(
            self.result_root / "Scope"
        ).resolve(strict=False)
        ScopeCoordinator(output_dir).approve_draft(
            draft, approved_by=(request.approved_by or "").strip()
        )
        self._update(str(job["job_id"]), status="approved", draft_path=None, level="success", message="Scope draft approved and integrity-bound artifacts published.")
        return self.get_job(program_id)

    def events_after(self, program_id: str, after: int) -> list[dict[str, Any]]:
        job, _program = self._job_and_program(program_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scope_job_events WHERE job_id=? AND event_id>? ORDER BY event_id LIMIT 500",
                (job["job_id"], after),
            ).fetchall()
        return [dict(row) for row in rows]

    def _collect(
        self,
        job_id: str,
        program: dict[str, Any],
        request: ScopeCollectionRequest,
        output_dir: Path,
    ) -> None:
        url = str(program["program_url"])
        try:
            agent = self._agent_factory()
            primary_reader = None
            fallback_reader = PlaywrightProgramPageReader(timeout_seconds=45)
            if request.login_mode == "headless" and self._public_reader_factory:
                primary_reader = self._public_reader_factory()
                fallback_reader = None
            elif request.login_mode == "runtime-browser":
                ready = threading.Event()
                self._browser_events[job_id] = ready

                def wait_for_operator(_prompt: str) -> str:
                    self._update(job_id, status="awaiting_browser", level="warning", message="Browser opened. Complete login/MFA, return to the exact Scope view, then confirm in the dashboard.")
                    if not ready.wait(timeout=900):
                        raise CoordinatorError("browser confirmation timed out")
                    return ""

                reader_factory = self._runtime_reader_factory or RuntimeBrowserProgramPageReader
                primary_reader = reader_factory(
                    identity=(request.identity or "").strip(),
                    timeout_seconds=45,
                    input_fn=wait_for_operator,
                    output_fn=lambda message: self._update(
                        job_id,
                        level="info",
                        message=str(message).replace(url, "[program URL]")[:500],
                    ),
                )
                fallback_reader = None
            document, draft = ScopeCoordinator(output_dir).collect_draft(
                url,
                main_agent=agent,
                primary_reader=primary_reader,
                fallback_reader=fallback_reader,
                draft_root=self.draft_root,
            )
            self._update(
                job_id,
                status="review_required",
                draft_path=str(draft),
                level="success",
                message=(
                    "Scope draft ready for explicit Yes/No review: "
                    f"{len(document.analysis.in_scope_assets)} in-scope and "
                    f"{len(document.analysis.out_of_scope_assets)} out-of-scope assets."
                ),
            )
        except Exception as exc:
            message = str(exc).replace(url, "[program URL]")[:500] or exc.__class__.__name__
            self._update(job_id, status="failed", error=message, level="error", message=f"Scope collection failed: {message}")
        finally:
            self._browser_events.pop(job_id, None)

    def _job_and_program(self, program_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        program = self.registry.get(program_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            job = conn.execute(
                "SELECT * FROM scope_jobs WHERE program_key=?", (program["program_key"],)
            ).fetchone()
        if job is None:
            raise KeyError("Scope job not found")
        return job, program

    def _record_terminal(self, program: dict[str, Any], status: str, message: str) -> dict[str, Any]:
        job_id = f"scopejob_{uuid4().hex}"
        now = _now()
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute(
                """INSERT INTO scope_jobs VALUES (?,?,?,'headless',NULL,NULL,?,?)
                ON CONFLICT(program_key) DO UPDATE SET job_id=excluded.job_id,status=excluded.status,
                login_mode=excluded.login_mode,draft_path=NULL,error=NULL,
                created_at=excluded.created_at,updated_at=excluded.updated_at""",
                (job_id, program["program_key"], status, now, now),
            )
            self._append_event(conn, job_id, "success", message)
        return self._public_job(self._job_and_program(f"registered-{str(program['program_key'])[:12]}")[0])

    def _update(
        self,
        job_id: str,
        *,
        status: str | None = None,
        draft_path: str | None | object = ...,
        error: str | None | object = ...,
        level: str | None = None,
        message: str | None = None,
    ) -> None:
        if not _JOB_ID.fullmatch(job_id):
            return
        assignments = ["updated_at=?"]
        values: list[Any] = [_now()]
        if status is not None:
            assignments.append("status=?")
            values.append(status)
        if draft_path is not ...:
            assignments.append("draft_path=?")
            values.append(draft_path)
        if error is not ...:
            assignments.append("error=?")
            values.append(error)
        values.append(job_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute(
                f"UPDATE scope_jobs SET {','.join(assignments)} WHERE job_id=?",
                values,
            )
            if message and level:
                self._append_event(conn, job_id, level, message[:500])

    @staticmethod
    def _append_event(
        conn: sqlite3.Connection, job_id: str, level: str, message: str
    ) -> None:
        event_id = int(
            conn.execute(
                "SELECT COALESCE(max(event_id),0)+1 FROM scope_job_events WHERE job_id=?",
                (job_id,),
            ).fetchone()[0]
        )
        conn.execute(
            "INSERT INTO scope_job_events VALUES (?,?,?,?,?)",
            (job_id, event_id, _now(), level, message[:500]),
        )

    @staticmethod
    def _public_job(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scope_status": str(row["status"]),
            "scope_job_id": str(row["job_id"]),
            "scope_error": str(row["error"]) if row["error"] else None,
            "scope_updated_at": str(row["updated_at"]),
        }

    def _validated_draft_path(self, path: Path) -> Path:
        resolved = path.resolve(strict=True)
        resolved.relative_to(self.draft_root)
        if resolved.is_symlink():
            raise CoordinatorError("Scope draft must not be a symbolic link")
        return resolved

    def _discard_path(self, path: Path) -> None:
        try:
            safe = self._validated_draft_path(path)
        except (OSError, ValueError, CoordinatorError):
            return
        shutil.rmtree(safe)
