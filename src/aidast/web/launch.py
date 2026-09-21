"""Constrained local scan launcher for the Web dashboard.

The browser never supplies a program URL or command.  It selects exact assets
from a fully verified approved Scope and this module builds a fixed argv list.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.policy import validate_start_url_for_target
from aidast.recon.profiles import EXECUTION_PROFILES, ProfileId
from aidast.scope.models import AssetType
from aidast.scope.paths import ScopePathError, resolve_scope_directory

from .projection import DashboardProjector, ScanNotFoundError
from .requirements import (
    IdentityHeader,
    ScopeExecutionRequirements,
    build_scope_execution_requirements,
)


EXECUTABLE_TYPES = {
    AssetType.URL,
    AssetType.API,
    AssetType.DOMAIN,
    AssetType.WILDCARD,
    AssetType.IP_ADDRESS,
}
_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ScanLaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_id: str = Field(min_length=1, max_length=160)
    targets: list[str] = Field(min_length=1, max_length=64)
    profile: ProfileId = "safe-recon"
    max_requests: int = Field(default=500, ge=1, le=2000)
    max_rps: float | None = Field(default=None, gt=0, le=50)
    max_concurrency: int | None = Field(default=None, ge=1, le=20)
    timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    max_depth: int | None = Field(default=None, ge=0, le=10)
    login_mode: str = "none"
    start_url: str | None = Field(default=None, max_length=2048)
    hackerone_username: str | None = None
    intigriti_username: str | None = None
    authorization_confirmed: bool = False

    @field_validator("targets")
    @classmethod
    def bounded_targets(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 2048 for value in values):
            raise ValueError("targets must be non-empty and at most 2048 characters")
        return values

    @field_validator("login_mode")
    @classmethod
    def valid_login_mode(cls, value: str) -> str:
        if value not in {"none", "runtime-browser"}:
            raise ValueError("unsupported login mode")
        return value

    @field_validator("hackerone_username", "intigriti_username")
    @classmethod
    def valid_handle(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not _HANDLE.fullmatch(candidate):
            raise ValueError("invalid platform handle")
        return candidate

    @field_validator("start_url")
    @classmethod
    def clean_start_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        return candidate

    @model_validator(mode="after")
    def confirmed_and_consistent(self) -> "ScanLaunchRequest":
        if not self.authorization_confirmed:
            raise ValueError("authorization confirmation is required")
        if len(set(self.targets)) != len(self.targets):
            raise ValueError("duplicate targets are not allowed")
        if self.hackerone_username and self.intigriti_username:
            raise ValueError("platform handles cannot be combined")
        if self.max_requests > EXECUTION_PROFILES[self.profile].max_requests:
            raise ValueError("request budget exceeds the selected profile")
        profile = EXECUTION_PROFILES[self.profile]
        if self.max_rps is not None and self.max_rps > profile.requests_per_second:
            raise ValueError("request rate exceeds the selected profile")
        if (
            self.max_concurrency is not None
            and self.max_concurrency > profile.concurrency
        ):
            raise ValueError("concurrency exceeds the selected profile")
        if (
            self.timeout_seconds is not None
            and self.timeout_seconds > profile.timeout_seconds
        ):
            raise ValueError("timeout exceeds the selected profile")
        if self.max_depth is not None and self.max_depth > profile.max_depth:
            raise ValueError("depth exceeds the selected profile")
        if self.start_url and len(self.targets) != 1:
            raise ValueError("a specific start URL requires exactly one target")
        return self


class ProgramResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_url: str = Field(min_length=8, max_length=2048)

    @field_validator("program_url")
    @classmethod
    def valid_program_url(cls, value: str) -> str:
        candidate = value.strip()
        # The shared resolver enforces HTTPS and platform/path structure.
        resolve_scope_directory(candidate)
        return candidate


@dataclass(frozen=True)
class ApprovedScope:
    scope_id: str
    program_id: str
    program_name: str
    platform: str
    program_url: str
    targets: tuple[dict[str, str], ...]
    identity_header: str | None
    approved_by: str
    execution_requirements: ScopeExecutionRequirements
    directory: Path | None = None

    def public(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "program_id": self.program_id,
            "program_name": self.program_name,
            "platform": self.platform,
            "targets": list(self.targets),
            "identity_header": self.identity_header,
            "approved_by": self.approved_by,
            "execution_requirements": self.execution_requirements.model_dump(
                mode="json"
            ),
        }


class ApprovedScopeCatalog:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()

    def list(self) -> list[ApprovedScope]:
        root = self.result_root / "Scope"
        scopes: list[ApprovedScope] = []
        if not root.is_dir():
            return scopes
        for scope_json in root.glob("*/*/Scope.json"):
            directory = scope_json.parent
            try:
                document, markdown = ScopeCoordinator(directory).load_approved_scope()
                approval = ScopeCoordinator(directory).verify_approval()
                platform, slug = directory.relative_to(root).parts[:2]
                targets = tuple(
                    {
                        "asset_type": asset.asset_type.value,
                        "asset": asset.asset,
                        "description": asset.description[:240],
                        "maximum_severity": asset.maximum_severity[:40],
                    }
                    for asset in document.analysis.in_scope_assets
                    if asset.asset_type in EXECUTABLE_TYPES
                )
                if not targets:
                    continue
                identity: IdentityHeader | None = (
                    "hackerone"
                    if "X-HackerOne" in markdown
                    else "intigriti"
                    if "X-Intigriti-Username" in markdown
                    else None
                )
                platform_prefix = {
                    "hackerone": "h1",
                    "yeswehack": "ywh",
                }.get(platform, platform)
                program_id = f"{platform_prefix}-{slug.replace('_', '-')}"
                scopes.append(
                    ApprovedScope(
                        scope_id=document.scope_id,
                        program_id=program_id,
                        program_name=document.analysis.program_name[:160],
                        platform=platform,
                        program_url=str(document.source.requested_url),
                        targets=targets,
                        identity_header=identity,
                        approved_by=approval.approved_by[:160],
                        execution_requirements=build_scope_execution_requirements(
                            document.analysis,
                            identity_header=identity,
                        ),
                        directory=directory.resolve(),
                    )
                )
            except (CoordinatorError, OSError, ValueError):
                continue
        return sorted(scopes, key=lambda item: (item.platform, item.program_name))

    def get(self, scope_id: str) -> ApprovedScope:
        for scope in self.list():
            if scope.scope_id == scope_id:
                return scope
        raise ValueError("approved scope not found or integrity verification failed")

    def resolve(self, program_url: str) -> ApprovedScope:
        try:
            expected = resolve_scope_directory(
                program_url, self.result_root / "Scope"
            ).resolve()
        except ScopePathError as exc:
            raise ValueError(str(exc)) from exc
        for scope in self.list():
            if scope.directory == expected:
                return scope
        raise ValueError(
            "this program has no verified approved Scope; collect and approve it first"
        )


@dataclass
class LaunchJob:
    scan_id: str
    scope: ApprovedScope
    status: str
    started_at: str
    max_requests: int
    process: Any | None = None
    finished_at: str | None = None


ProcessFactory = Callable[..., Any]


class ScanLaunchManager:
    def __init__(
        self,
        result_root: Path,
        projector: DashboardProjector,
        *,
        process_factory: ProcessFactory = subprocess.Popen,
        project_root: Path | None = None,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.projector = projector
        self.catalog = ApprovedScopeCatalog(self.result_root)
        self.process_factory = process_factory
        candidate = (project_root or Path.cwd()).expanduser().resolve()
        self.project_root = candidate
        self._jobs: dict[str, LaunchJob] = {}
        self._lock = threading.RLock()

    def list_scopes(self) -> list[dict[str, Any]]:
        return [scope.public() for scope in self.catalog.list()]

    def exists(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._jobs

    def launch(self, request: ScanLaunchRequest) -> dict[str, Any]:
        scope = self.catalog.get(request.scope_id)
        allowed = {item["asset"] for item in scope.targets}
        if any(target not in allowed for target in request.targets):
            raise ValueError("one or more targets are not in the approved Scope")
        if request.start_url:
            selected = next(
                item for item in scope.targets if item["asset"] == request.targets[0]
            )
            try:
                validate_start_url_for_target(
                    request.start_url,
                    asset_type=AssetType(selected["asset_type"]),
                    asset=selected["asset"],
                )
            except ValueError as exc:
                raise ValueError(f"start URL is outside the selected approved target: {exc}") from exc
        scope_max_rps = (
            scope.execution_requirements.scope_max_requests_per_second
        )
        if (
            request.max_rps is not None
            and scope_max_rps is not None
            and request.max_rps > scope_max_rps
        ):
            raise ValueError("request rate exceeds the approved Scope")
        if scope.identity_header == "hackerone" and not request.hackerone_username:
            raise ValueError("this Scope requires a HackerOne username")
        if scope.identity_header == "intigriti" and not request.intigriti_username:
            raise ValueError("this Scope requires an Intigriti username")

        scan_id = f"scan_{uuid4().hex}"
        argv: list[str] = [
            sys.executable,
            "-m",
            "aidast",
            "run",
            scope.program_url,
            "--scan-id",
            scan_id,
        ]
        for target in request.targets:
            argv.extend(("--target", target))
        if request.start_url:
            argv.extend(("--start-url", request.start_url))
        argv.extend(
            (
                "--profile",
                request.profile,
                "--max-requests",
                str(request.max_requests),
                "--login-mode",
                request.login_mode,
                "--output-dir",
                str(self.result_root / "Scope"),
                "--run-root",
                str(self.result_root / "Runs"),
                "--attack-output-root",
                str(self.result_root / "AttackRuns"),
            )
        )
        if request.max_rps is not None:
            argv.extend(("--max-rps", str(request.max_rps)))
        if request.max_depth is not None:
            argv.extend(("--max-depth", str(request.max_depth)))
        if request.max_concurrency is not None:
            argv.extend(("--max-concurrency", str(request.max_concurrency)))
        if request.timeout_seconds is not None:
            argv.extend(("--timeout-seconds", str(request.timeout_seconds)))
        if request.hackerone_username:
            argv.extend(("--hackerone-username", request.hackerone_username))
        if request.intigriti_username:
            argv.extend(("--intigriti-username", request.intigriti_username))

        started = _now()
        job = LaunchJob(scan_id, scope, "pending", started, request.max_requests)
        with self._lock:
            self._jobs[scan_id] = job
        self._log(scan_id, "launch.accepted", "Scope", "Scan request accepted after approval verification.")
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        source_root = self.project_root / "src"
        if source_root.is_dir():
            prior = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (os.pathsep + prior if prior else "")
        try:
            process = self.process_factory(
                argv,
                cwd=self.project_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except OSError as exc:
            job.status = "failed"
            job.finished_at = _now()
            self._log(scan_id, "launch.failed", "Scope", "Scan process could not be started.", "error")
            raise ValueError("scan process could not be started") from exc
        job.process = process
        job.status = "running"
        self._log(scan_id, "launch.started", "Recon", "AI DAST pipeline process started.")
        threading.Thread(target=self._monitor, args=(job,), daemon=True).start()
        return {"scan_id": scan_id, "status": "running", "started_at": started}

    def _monitor(self, job: LaunchJob) -> None:
        code = int(job.process.wait())
        with self._lock:
            job.finished_at = _now()
            job.status = "completed" if code == 0 else "failed"
        message = "AI DAST pipeline completed." if code == 0 else "AI DAST pipeline exited with an error."
        level = "success" if code == 0 else "error"
        self._log(job.scan_id, "launch.finished", "Report" if code == 0 else "Recon", message, level)

    def _log(self, scan_id: str, key: str, stage: str, message: str, level: str = "info") -> None:
        self.projector.record_event(
            scan_id,
            source_key=key,
            event_type="log.appended",
            payload={"stage": stage, "level": level, "message": message},
        )

    def snapshot(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None:
            raise ScanNotFoundError(f"unknown scan: {scan_id}")
        events = self.projector.stored_events_after(scan_id, 0)
        logs = [
            {
                "id": event["event_id"],
                "time": event["occurred_at"],
                **event["payload"],
            }
            for event in events
            if event["type"] == "log.appended"
        ]
        return {
            "version": 1,
            "scan_id": scan_id,
            "status": job.status,
            "stage": "Recon" if job.status != "pending" else "Scope",
            "progress": 0,
            "requests": 0,
            "budget": job.max_requests,
            "endpoints": 0,
            "findings": [],
            "scope_approved": True,
            "scope_id": job.scope.scope_id,
            "program_id": job.scope.program_id,
            "program_name": job.scope.program_name,
            "last_event_id": self.projector.cursor(scan_id),
            "logs": logs,
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [
            {
                "scan_id": job.scan_id,
                "status": job.status,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
            }
            for job in sorted(jobs, key=lambda item: item.started_at, reverse=True)
        ]
