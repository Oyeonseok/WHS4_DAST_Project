"""Constrained local scan launcher for the Web dashboard.

The browser never supplies a program URL or command.  It selects exact assets
from a fully verified approved Scope and this module builds a fixed argv list.
"""

from __future__ import annotations

import re
import os
import time
import json
import signal
import sqlite3
import subprocess
import sys
import threading
import tempfile
from contextlib import contextmanager
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aidast.core.posix_processes import signal_session
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.policy import validate_start_url_for_target
from aidast.recon.profiles import EXECUTION_PROFILES, ProfileId, profile_request_rate
from aidast.pipeline.resume import inspect_resume
from aidast.pipeline.model_settings import (
    ScanModelChoices, scan_model_settings_path, write_scan_model_choices,
)
from aidast.pipeline.lifecycle import finish_stage_run
from aidast.scope.models import AssetType
from aidast.scope.exclusion_preparation import prepare_exclusions, normalize_start_urls
from aidast.scope.exclusion_binding import ExclusionBindingResolver
from aidast.scope.execution_rules import execution_interpretation_complete, requires_policy_advisory_review
from aidast.scope.identity_headers import ScopeHeaderResolver, resolve_scope_identity_headers
from aidast.scope.execution_rules import ScopeExecutionResolver, validate_policy_prerequisites, validate_shared_policy_values
from aidast.scope.paths import ScopePathError, resolve_scope_directory, identify_program, scope_archive_directories

from .projection import DashboardProjector, ScanNotFoundError
from .process_identity import process_args, process_cwd, process_stat
from .process_control import control_process
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


def _windows_host() -> bool:
    return os.name == "nt"


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
    ffuf_max_time_seconds: int = Field(default=150, ge=0, le=86400)
    tag_batch_size: int = Field(default=25, ge=1, le=200)
    recon_model: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    attack_model: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    validation_model: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    report_model: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    login_mode: str = "none"
    start_url: str | None = Field(default=None, max_length=2048)
    policy_values: dict[str, str] = Field(default_factory=dict, max_length=64)
    policy_confirmations: list[str] = Field(default_factory=list, max_length=64)
    identity_values: dict[str, str] = Field(default_factory=dict, max_length=512)
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

    @field_validator("recon_model", "attack_model", "validation_model", "report_model")
    @classmethod
    def valid_model_name(cls, value: str | None) -> str | None:
        if value is not None and "://" in value:
            raise ValueError("model must be an identifier, not a URL")
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

    @field_validator("identity_values", "policy_values")
    @classmethod
    def bounded_identity_values(cls, values):
        if len(values) > 512 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key)
                                  or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value)
                                  for key, value in values.items()):
            raise ValueError("invalid header input values")
        return values

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
        if self.max_requests > EXECUTION_PROFILES[self.profile].max_requests:
            raise ValueError("request budget exceeds the selected profile")
        profile = EXECUTION_PROFILES[self.profile]
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


class ExclusionPreparationRequest(ScanLaunchRequest):
    refresh: bool = False


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
    def __init__(self, result_root: Path, *, header_resolver: ScopeHeaderResolver | None = None, execution_resolver: ScopeExecutionResolver | None = None) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.header_resolver = execution_resolver or header_resolver or ScopeExecutionResolver(self.result_root / ".execution-requirements")

    def list(self) -> list[ApprovedScope]:
        root = self.result_root / "Scope"
        scopes: list[ApprovedScope] = []
        if not root.is_dir():
            return scopes
        for directory in scope_archive_directories(root):
            try:
                document, markdown = ScopeCoordinator(directory).load_approved_scope()
                approval = ScopeCoordinator(directory).verify_approval()
                platform, slug = directory.relative_to(root).parts[:2]
                identity = identify_program(str(document.source.requested_url))
                if (identity.platform, identity.program) != (platform, slug):
                    continue
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
                cached_analysis = self.header_resolver.cached(document)
                requirements = build_scope_execution_requirements(
                    cached_analysis or document.analysis, identity_header=None,
                )
                if cached_analysis is None and requires_policy_advisory_review(document):
                    # Keep legacy controls visible while read-only listing waits
                    # for explicit preparation of the separate reviewed cache.
                    requirements = requirements.model_copy(update={
                        "execution_requirements_status": "pending",
                        "header_requirements_status": "pending",
                    })
                identity: IdentityHeader | None = (
                    "hackerone" if requirements.required_header
                    and requirements.required_header.input_field == "hackerone_username"
                    else "intigriti" if requirements.required_header
                    and requirements.required_header.input_field == "intigriti_username" else None
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
                        execution_requirements=requirements,
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

    def resolve_header_requirements(self, scope_id: str) -> ApprovedScope:
        scope = self.get(scope_id)
        if scope.directory is None:
            raise ValueError("approved scope not found")
        document, _ = ScopeCoordinator(scope.directory).load_approved_scope()
        self.header_resolver.resolve(document)
        return self.get(scope_id)

    resolve_execution_requirements = resolve_header_requirements

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
    targets: tuple[str, ...]
    process: Any | None = None
    finished_at: str | None = None
    stop_requested: bool = False
    process_log: Path | None = None


ProcessFactory = Callable[..., Any]


class ScanLaunchManager:
    def __init__(
        self,
        result_root: Path,
        projector: DashboardProjector,
        *,
        process_factory: ProcessFactory = subprocess.Popen,
        project_root: Path | None = None,
        header_resolver: ScopeHeaderResolver | None = None,
        execution_resolver: ScopeExecutionResolver | None = None,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.projector = projector
        self.catalog = ApprovedScopeCatalog(self.result_root, header_resolver=header_resolver, execution_resolver=execution_resolver)
        self.exclusion_resolver = ExclusionBindingResolver(self.result_root / ".exclusion-bindings")
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

    def _prepare_launch(self, request: ScanLaunchRequest, *, refresh: bool = False):
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
        if scope.directory is None:
            raise ValueError("approved scope not found")
        document, _ = ScopeCoordinator(scope.directory).load_approved_scope()
        analysis = self.catalog.header_resolver.resolve(document)
        if not execution_interpretation_complete(analysis):
            raise ValueError("Scope execution requirements need AI interpretation before launch")
        # Every cap and prerequisite comes from the same complete v3 analysis.
        scope = replace(scope, execution_requirements=build_scope_execution_requirements(analysis))
        scope_max_rps = scope.execution_requirements.scope_max_requests_per_second
        allowed_rps = profile_request_rate(request.profile, scope_max_rps)
        if request.max_rps is not None and request.max_rps > allowed_rps:
            raise ValueError("request rate exceeds the approved Scope or profile fallback")
        headers = resolve_scope_identity_headers(analysis, identity_values=request.identity_values,
                                       hackerone_username=request.hackerone_username,
                                       intigriti_username=request.intigriti_username)

        shared_values = dict(request.identity_values)
        if request.hackerone_username is not None:
            shared_values['hackerone_username'] = request.hackerone_username
        if request.intigriti_username is not None:
            shared_values['intigriti_username'] = request.intigriti_username
        validate_shared_policy_values(analysis, shared_values, request.policy_values)
        validate_policy_prerequisites(analysis.execution_rules, request.targets,
                                      request.policy_values, request.policy_confirmations)
        effective = next(item.limits for item in scope.execution_requirements.profiles if item.id == request.profile)
        overrides = {'max_requests': request.max_requests, 'concurrency': request.max_concurrency,
                     'timeout_seconds': request.timeout_seconds, 'max_depth': request.max_depth}
        for field, value in overrides.items():
            if value is not None and value > getattr(effective, field):
                raise ValueError(f'{field} exceeds the approved policy cap')
        targets = [target for target in document.analysis.in_scope_assets if target.asset in request.targets]
        starts = normalize_start_urls({(targets[0].asset_type.value,targets[0].asset):request.start_url} if request.start_url else {})
        preparation = prepare_exclusions(document=document, analysis=analysis, targets=targets,
            result_root=self.result_root, start_urls=starts, headers=headers,
            login_mode=request.login_mode, resolver=self.exclusion_resolver, refresh=refresh)
        return scope, preparation

    def prepare_resources(self, request: ExclusionPreparationRequest) -> dict[str, Any]:
        _scope, preparation = self._prepare_launch(request, refresh=request.refresh)
        return preparation.public()

    def launch(self, request: ScanLaunchRequest) -> dict[str, Any]:
        scope, preparation = self._prepare_launch(request)
        preparation.require_ready()
        scan_id = f"scan_{uuid4().hex}"
        models = ScanModelChoices.resolve(
            recon_model=request.recon_model, attack_model=request.attack_model,
            validation_model=request.validation_model, report_model=request.report_model,
        )
        write_scan_model_choices(scan_model_settings_path(self.result_root, scan_id),
                                 scan_id=scan_id, models=models)
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
        if request.recon_model is not None:
            argv.extend(("--recon-model", request.recon_model))
        if request.attack_model is not None:
            argv.extend(("--attack-model", request.attack_model))
        if request.validation_model is not None:
            argv.extend(("--validation-model", request.validation_model))
        if request.report_model is not None:
            argv.extend(("--report-model", request.report_model))
        argv.extend(
            (
                "--profile",
                request.profile,
                "--max-requests",
                str(request.max_requests),
                "--tag-batch-size",
                str(request.tag_batch_size),
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
        if scope.directory is not None and scope.directory.parent.name == "revisions":
            argv.extend(("--scope-revision", scope.directory.name))
        if request.max_rps is not None:
            argv.extend(("--max-rps", str(request.max_rps)))
        wordlist = self.project_root / "resources" / "wordlists" / "common.txt"
        if wordlist.is_file():
            argv.extend(("--ffuf-wordlist", str(wordlist)))
        argv.extend(("--ffuf-max-time-seconds", str(request.ffuf_max_time_seconds)))
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

        for key, value in request.identity_values.items():
            argv.extend(("--header-input", f"{key}={value}"))
        for key, value in request.policy_values.items():
            argv.extend(('--policy-input', f'{key}={value}'))
        for key in request.policy_confirmations:
            argv.extend(('--confirm-policy', key))
        started = _now()
        job = LaunchJob(
            scan_id, scope, "pending", started, request.max_requests,
            tuple(request.targets),
        )
        with self._lock:
            self._jobs[scan_id] = job
        self._log(scan_id, "launch.accepted", "Scope", "Scan request accepted after approval verification.", message_code="pipeline.accepted")
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        env["AIDAST_DASHBOARD_MANUAL_LOGIN"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        source_root = self.project_root / "src"
        if source_root.is_dir():
            prior = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (os.pathsep + prior if prior else "")
        try:
            with self._process_output(job) as output:
                process = self.process_factory(
                    argv,
                    cwd=self.project_root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    start_new_session=not _windows_host(),
                    **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                       if _windows_host() else {}),
                )
        except OSError as exc:
            job.status = "failed"
            job.finished_at = _now()
            self._log(scan_id, "launch.failed", "Scope", "Scan process could not be started.", "error", message_code="pipeline.start_failed")
            raise ValueError("scan process could not be started") from exc
        job.process = process
        try:
            self._record_process(scan_id, process)
        except (OSError, ValueError) as exc:
            process.terminate()
            job.status = "failed"
            job.finished_at = _now()
            self._log(scan_id, "launch.failed", "Scope", "Scan process could not be managed.",
                      "error", message_code="pipeline.start_failed")
            raise ValueError("scan process could not be managed") from exc
        job.status = "running"
        self._log(scan_id, "launch.started", "Recon", "AI DAST pipeline process started.",
                  message_code="pipeline.started", message_params=self._process_result(job))
        threading.Thread(target=self._monitor, args=(job,), daemon=True).start()
        return {
            "scan_id": scan_id, "status": "running", "started_at": started,
            "targets": list(job.targets),
        }

    def resume(self, scan_id: str) -> dict[str, Any]:
        plan = inspect_resume(self.result_root, scan_id)
        scope = self.catalog.get(plan.scope_id)
        attempt_id = uuid4().hex
        started = _now()
        job = LaunchJob(scan_id, scope, "running", started, 0, plan.targets)
        argv = [
            sys.executable, "-m", "aidast", "resume", scan_id,
            "--result-root", str(self.result_root),
        ]
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        env["AIDAST_DASHBOARD_MANUAL_LOGIN"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        source_root = self.project_root / "src"
        if source_root.is_dir():
            prior = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (os.pathsep + prior if prior else "")
        with self._lock:
            existing = self._jobs.get(scan_id)
            if existing is not None and existing.status in {"pending", "running", "paused"}:
                raise ValueError("this scan already has an active process")
            try:
                with self._process_output(job) as output:
                    job.process = self.process_factory(
                        argv, cwd=self.project_root, env=env,
                        stdin=subprocess.DEVNULL, stdout=output,
                        stderr=subprocess.STDOUT, shell=False,
                        start_new_session=not _windows_host(),
                        **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                           if _windows_host() else {}),
                    )
            except OSError as exc:
                raise ValueError("scan resume process could not be started") from exc
            try:
                self._record_process(scan_id, job.process)
            except (OSError, ValueError) as exc:
                job.process.terminate()
                raise ValueError("scan resume process could not be managed") from exc
            self._jobs[scan_id] = job
        self._log(
            scan_id, f"resume:{attempt_id}:started", plan.stage.title(),
            "Scan resumed from the last unfinished stage.",
            message_code="pipeline.resumed",
            message_params=self._process_result(job),
        )
        threading.Thread(
            target=self._monitor_resume, args=(job, attempt_id, plan.stage), daemon=True,
        ).start()
        return {
            "scan_id": scan_id, "status": "running", "stage": plan.stage.title(),
            "started_at": started, "targets": list(plan.targets),
        }

    @contextmanager
    def _process_output(self, job: LaunchJob):
        """Keep each attempt's diagnostics private and independent of the UI."""
        directory = self.result_root / ".webui" / "process-logs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="process-", suffix=".log",
            dir=directory, delete=False,
        ) as output:
            job.process_log = Path(output.name)
            yield output

    def _process_result(self, job: LaunchJob, code: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if code is not None:
            result["exit_code"] = code
        process_log = getattr(job, "process_log", None)
        if process_log is not None:
            result["diagnostic_log"] = str(process_log.relative_to(self.result_root))
        return result

    def _process_marker(self, scan_id: str) -> Path:
        self.projector.validate_scan_id(scan_id)
        return self.result_root / ".webui" / "processes" / f"{scan_id}.json"

    @staticmethod
    def _process_stat(pid: int) -> tuple[str, str]:
        return process_stat(pid)

    def _record_process(self, scan_id: str, process: Any) -> None:
        if (os.name != "posix" and not _windows_host()) or not isinstance(process, subprocess.Popen):
            return
        pid = process.pid
        if not _windows_host() and os.getpgid(pid) != pid:
            raise ValueError("scan process was not started in an isolated session")
        _state, started = self._process_stat(pid)
        self._write_process_marker(scan_id, {"pid": pid, "started": started})

    def _write_process_marker(self, scan_id: str, identity: dict[str, Any]) -> None:
        marker = self._process_marker(scan_id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        temporary = marker.with_name(f".{marker.name}.{uuid4().hex}.tmp")
        temporary.write_text(json.dumps(identity), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(marker)

    def _forget_process(self, scan_id: str) -> None:
        self._process_marker(scan_id).unlink(missing_ok=True)

    def _isolated_scan_pid(self, scan_id: str) -> int | None:
        """Recover only the exact process recorded by this dashboard."""
        if os.name != "posix" and not _windows_host():
            return None
        try:
            marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        pid = marker.get("pid") if isinstance(marker, dict) else None
        started = marker.get("started") if isinstance(marker, dict) else None
        if type(pid) is not int or pid < 2 or not isinstance(started, str):
            return None
        try:
            state, actual_start = self._process_stat(pid)
            if actual_start != started or state == "Z":
                return None
            if not _windows_host() and os.getpgid(pid) != pid:
                return None
            if process_cwd(pid) != self.project_root:
                return None
            args = process_args(pid)
            if args[1:3] != ["-m", "aidast"]:
                return None
            if args[3:4] == ["run"]:
                index = args.index("--scan-id")
                return pid if args[index + 1:index + 2] == [scan_id] else None
            if args[3:4] == ["resume"]:
                return pid if args[4:5] == [scan_id] else None
        except (OSError, IndexError, ValueError):
            return None
        return None

    def _signal_pid(self, scan_id: str, signum: int) -> int:
        pid = self._isolated_scan_pid(scan_id)
        if pid is None:
            raise ValueError("this scan has no isolated active process managed by this dashboard")
        signal_session(pid, signum)
        return pid

    def _control_scan(self, scan_id: str, action: str) -> int:
        pid = self._isolated_scan_pid(scan_id)
        if pid is None:
            raise ValueError("this scan has no isolated active process managed by this dashboard")
        marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        if marker.get("pid") != pid or not isinstance(marker.get("started"), str):
            raise ValueError("scan process identity changed")
        control_process(pid, marker["started"], action)
        return pid

    def _set_scan_pause_status(self, scan_id: str, *, expected: str, status: str) -> None:
        database = self.projector.locate_database(scan_id)
        with sqlite3.connect(database) as conn:
            with conn:
                changed = conn.execute(
                    "UPDATE scans SET status=? WHERE scan_id=? AND status=?",
                    (status, scan_id, expected),
                ).rowcount
                if changed != 1:
                    raise ValueError(f"scan is not {expected}")

    def _persisted_scan_status(self, scan_id: str) -> str:
        database = self.projector.locate_database(scan_id)
        with sqlite3.connect(database) as conn:
            row = conn.execute("SELECT status FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            raise ValueError("scan has no persisted status")
        return str(row[0])

    def _remember_pause_status(self, scan_id: str, pid: int, status: str) -> None:
        """Retain the raw Recon state when a later Pipeline stage is paused."""
        try:
            marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        except FileNotFoundError:
            # Older in-memory process adapters have no durable marker.
            # Their existing Recon-only pause contract restores running.
            if status == "running":
                return
            raise ValueError("scan has no persisted process identity")
        if not isinstance(marker, dict) or marker.get("pid") != pid or self._isolated_scan_pid(scan_id) != pid:
            raise ValueError("scan process identity changed")
        marker["pause_resume_status"] = status
        self._write_process_marker(scan_id, marker)

    def _pause_resume_status(self, scan_id: str) -> str:
        try:
            marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return "running"
        if not isinstance(marker, dict):
            raise ValueError("invalid scan process identity")
        status = marker.get("pause_resume_status", "running")
        if not isinstance(status, str) or not re.fullmatch(r"[a-z_]{1,32}", status) or status == "paused":
            raise ValueError("invalid scan pause status")
        return status

    def pause(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        if os.name != "posix" and not _windows_host():
            raise ValueError("scan pause is unavailable on this host")
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None and job.stop_requested:
                raise ValueError("scan cancellation is already in progress")
            state = self.projector.snapshot(scan_id)
            if state["status"] != "running":
                raise ValueError("scan is not running")
            previous_status = self._persisted_scan_status(scan_id)
            if previous_status == "paused":
                raise ValueError("scan is not running")
            if not re.fullmatch(r"[a-z_]{1,32}", previous_status):
                raise ValueError("invalid scan pause status")
            pid = (self._control_scan(scan_id, "pause") if _windows_host()
                   else self._signal_pid(scan_id, signal.SIGSTOP))
            try:
                self._remember_pause_status(scan_id, pid, previous_status)
                self._set_scan_pause_status(scan_id, expected=previous_status, status="paused")
            except (OSError, sqlite3.Error, ValueError):
                if _windows_host():
                    self._control_scan(scan_id, "resume")
                else:
                    self._signal_pid(scan_id, signal.SIGCONT)
                raise
            if job is not None:
                job.status = "paused"
            self._log(scan_id, "pause.finished", state["stage"], "Scan paused by operator.",
                      "warning", message_code="pipeline.paused")
        return {"scan_id": scan_id, "status": "paused"}

    def continue_scan(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        if os.name != "posix" and not _windows_host():
            raise ValueError("scan pause is unavailable on this host")
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None and job.stop_requested:
                raise ValueError("scan cancellation is already in progress")
            state = self.projector.snapshot(scan_id)
            if state["status"] != "paused":
                raise ValueError("scan is not paused")
            if self._isolated_scan_pid(scan_id) is None:
                raise ValueError("this scan has no isolated active process managed by this dashboard")
            resumed_status = self._pause_resume_status(scan_id)
            # Restore completed Recon before waking a later stage: its input
            # contract must never observe paused/running Recon after resume.
            self._set_scan_pause_status(scan_id, expected="paused", status=resumed_status)
            try:
                if _windows_host():
                    self._control_scan(scan_id, "resume")
                else:
                    self._signal_pid(scan_id, signal.SIGCONT)
            except (OSError, sqlite3.Error, ValueError):
                self._set_scan_pause_status(scan_id, expected=resumed_status, status="paused")
                raise
            if job is not None:
                job.status = "running"
            self._log(scan_id, "pause.resumed", state["stage"], "Paused scan continued.",
                      message_code="pipeline.continued")
        return {"scan_id": scan_id, "status": "running"}

    def cancel(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None or job.process is None:
                state = self.projector.snapshot(scan_id)
                status = state["status"]
                if status not in {"running", "paused"}:
                    raise ValueError("scan is not active")
                pid = self._isolated_scan_pid(scan_id)
                if pid is None:
                    raise ValueError("this scan has no isolated active process managed by this dashboard")
                if status == "paused":
                    if _windows_host():
                        self._control_scan(scan_id, "resume")
                if _windows_host():
                    self._control_scan(scan_id, "terminate")
                else:
                    try:
                        signal_session(pid, signal.SIGTERM)
                    except PermissionError:
                        # The PID identity was verified above. If macOS denies
                        # one descendant process-group signal, terminate the
                        # owned worker directly so cancellation can still
                        # close its transports and persist a terminal state.
                        os.kill(pid, signal.SIGTERM)
                threading.Thread(target=self._finish_adopted_cancel,
                                 args=(scan_id, pid, state["stage"]), daemon=True).start()
                self._log(scan_id, "cancel.requested", state["stage"], "Scan cancellation requested.",
                          "warning", message_code="pipeline.cancel_requested")
                return {"scan_id": scan_id, "status": "cancelling"}
            if job.status not in {"running", "paused"}:
                raise ValueError("this scan has no active process managed by this dashboard")
            if job.stop_requested:
                return {"scan_id": scan_id, "status": "cancelling"}
            if hasattr(job.process, "poll") and job.process.poll() is not None:
                raise ValueError("scan process has already exited")
            job.stop_requested = True
            try:
                if job.status == "paused" and isinstance(job.process, subprocess.Popen):
                    if _windows_host():
                        self._control_scan(scan_id, "resume")
                if _windows_host() and isinstance(job.process, subprocess.Popen):
                    self._control_scan(scan_id, "terminate")
                else:
                    self._terminate_process(job.process)
            except (OSError, subprocess.SubprocessError) as exc:
                job.stop_requested = False
                raise ValueError("scan process could not be stopped") from exc
            self._log(scan_id, "cancel.requested", "Recon", "Scan cancellation requested.",
                      "warning", message_code="pipeline.cancel_requested")
        return {"scan_id": scan_id, "status": "cancelling"}

    def stop(self, scan_id: str) -> dict[str, str]:
        """Compatibility alias for older dashboard clients."""
        result = self.cancel(scan_id)
        return {**result, "status": "stopping"}

    def _finish_adopted_cancel(self, scan_id: str, pid: int, stage: str = "Recon") -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self._isolated_scan_pid(scan_id) == pid:
            time.sleep(0.1)
        if self._isolated_scan_pid(scan_id) == pid:
            try:
                if _windows_host():
                    self._control_scan(scan_id, "kill")
                else:
                    signal_session(pid, signal.SIGKILL)
            except (OSError, ValueError):
                pass
        try:
            self._persist_stop(scan_id)
        except (OSError, sqlite3.Error, ValueError):
            self._log(scan_id, "cancel.persist_failed", stage,
                      "Scan process ended, but its persisted status could not be updated.",
                      "error", message_code="pipeline.cancel_persist_failed")
            return
        self._forget_process(scan_id)
        self._log(scan_id, "cancel.finished", stage, "Scan cancelled by operator.",
                  "warning", message_code="pipeline.cancelled")

    @staticmethod
    def _terminate_process(process: Any) -> None:
        if isinstance(process, subprocess.Popen) and os.name == "posix":
            try:
                signal_session(process.pid, signal.SIGTERM)
            except PermissionError:
                process.terminate()
            def force_stop() -> None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if process.poll() is None:
                        try:
                            signal_session(process.pid, signal.SIGKILL)
                        except PermissionError:
                            process.kill()
            threading.Thread(target=force_stop, daemon=True).start()
        else:
            process.terminate()

    def _persist_stop(self, scan_id: str) -> None:
        try:
            database = self.projector.locate_database(scan_id)
        except ScanNotFoundError:
            return
        with sqlite3.connect(database) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for stage_run_id, stage in conn.execute(
                "SELECT stage_run_id,stage FROM stage_runs WHERE scan_id=? AND status='running' ORDER BY rowid",
                (scan_id,),
            ).fetchall():
                if stage in {"attack", "chaining"} and "attack_http_requests" in tables:
                    conn.execute(
                        """UPDATE attack_http_requests SET status='outcome_unknown',
                           finished_at=CAST(strftime('%s','now') AS REAL),
                           error_message=COALESCE(error_message,'Scan stopped by operator')
                           WHERE stage_run_id=? AND status IN ('reserved','running')""",
                        (stage_run_id,),
                    )
                if stage == "chaining" and {"chain_candidates", "chain_executions"}.issubset(tables):
                    conn.execute(
                        """UPDATE chain_candidates SET status='inconclusive',
                           resolution_reason=COALESCE(resolution_reason,'Scan stopped by operator'),
                           resolved_at=CURRENT_TIMESTAMP
                           WHERE candidate_id IN (SELECT candidate_id FROM chain_executions
                           WHERE stage_run_id=? AND status='running') AND status='testing'""",
                        (stage_run_id,),
                    )
                    conn.execute(
                        """UPDATE chain_executions SET status='outcome_unknown',
                           reason=COALESCE(reason,'Scan stopped by operator'),
                           finished_at=CURRENT_TIMESTAMP
                           WHERE stage_run_id=? AND status='running'""",
                        (stage_run_id,),
                    )
                finish_stage_run(conn, stage_run_id, status="cancelled",
                                 error_message="Stopped by dashboard operator")
            with conn:
                conn.execute(
                    "UPDATE scans SET status='cancelled',finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                    (scan_id,),
                )

    def _monitor_resume(self, job: LaunchJob, attempt_id: str, stage: str) -> None:
        code = int(job.process.wait())
        self._forget_process(job.scan_id)
        if job.stop_requested:
            self._finish_stopped_job(job, stage.title())
            return
        with self._lock:
            job.finished_at = _now()
            job.status = "completed" if code == 0 else "failed"
        self._accumulate_runtime_wiki(job)
        self._log(
            job.scan_id, f"resume:{attempt_id}:finished", stage.title(),
            "Resumed scan completed." if code == 0 else "Resumed scan exited with an error.",
            "success" if code == 0 else "error",
            message_code="pipeline.resume_completed" if code == 0 else "pipeline.resume_failed",
            message_params=self._process_result(job, code),
        )

    def _monitor(self, job: LaunchJob) -> None:
        code = int(job.process.wait())
        self._forget_process(job.scan_id)
        if getattr(job, "stop_requested", False):
            self._finish_stopped_job(job, "Recon")
            return
        with self._lock:
            job.finished_at = _now()
            job.status = "completed" if code == 0 else "failed"
        self._accumulate_runtime_wiki(job)
        try:
            stage = self.projector.snapshot(job.scan_id)["stage"]
        except ScanNotFoundError:
            stage = "Validation" if code == 0 else "Recon"
        message = (
            f"AI DAST pipeline completed through {stage}." if code == 0
            else "AI DAST pipeline exited with an error."
        )
        level = "success" if code == 0 else "error"
        self._log(job.scan_id, "launch.finished", stage, message, level,
                  message_code="pipeline.completed" if code == 0 else "pipeline.failed",
                  message_params=self._process_result(job, code))

    def _finish_stopped_job(self, job: LaunchJob, stage: str) -> None:
        with self._lock:
            try:
                self._persist_stop(job.scan_id)
            except (OSError, sqlite3.Error, ValueError):
                self._log(job.scan_id, "cancel.persist_failed", stage,
                          "Scan process ended, but its persisted status could not be updated.",
                          "error", message_code="pipeline.cancel_persist_failed")
            job.finished_at = _now()
            job.status = "cancelled"
            self._accumulate_runtime_wiki(job)
            self._log(job.scan_id, "cancel.finished", stage, "Scan cancelled by operator.",
                      "warning", message_code="pipeline.cancelled")

    def _accumulate_runtime_wiki(self, job: LaunchJob) -> None:
        """Archive each stable Recon.db without feeding it back into execution."""
        program_id = getattr(getattr(job, "scope", None), "program_id", None)
        if not isinstance(program_id, str) or not program_id:
            return
        try:
            from .recon_wiki import ReconWikiCatalog
            ReconWikiCatalog(self.result_root).accumulate(
                job.scan_id,
                program_id=program_id,
                baseline_id=None,
                baseline_kind="source",
                target_id=program_id,
            )
        except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
            self._log(
                job.scan_id, "recon-wiki:auto:failed", "Recon",
                "Recon Wiki automatic accumulation failed.", "warning",
                message_code="recon_wiki.auto_failed",
                message_params={"error_type": type(exc).__name__},
            )
        else:
            self._log(
                job.scan_id, "recon-wiki:auto:completed", "Recon",
                "Recon.db was accumulated in the Recon Wiki.", "success",
                message_code="recon_wiki.auto_completed",
            )

    def _log(self, scan_id: str, key: str, stage: str, message: str, level: str = "info", *, message_code: str, message_params: dict[str, Any] | None = None) -> None:
        self.projector.record_event(
            scan_id,
            source_key=key,
            event_type="log.appended",
            payload={"stage": stage, "level": level, "message": message,
                     "message_code": message_code, "message_params": message_params or {}},
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
        progress = next(
            (
                event["payload"]["message_params"]["progress"]
                for event in reversed(events)
                if event["type"] == "log.appended"
                and event["payload"].get("message_code") == "agent.work"
                and event["payload"].get("stage") == "Recon"
                and type(event["payload"].get("message_params", {}).get("progress")) is int
            ),
            0,
        )
        return {
            "version": 1,
            "scan_id": scan_id,
            "status": job.status,
            "stage": "Recon" if job.status != "pending" else "Scope",
            "progress": progress if job.status == "running" else 0,
            "activity": "Preparing Recon" if job.status == "running" else None,
            "requests": 0,
            "budget": job.max_requests,
            "per_target_budget": job.max_requests,
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
                "targets": list(job.targets),
            }
            for job in sorted(jobs, key=lambda item: item.started_at, reverse=True)
        ]
