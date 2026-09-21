from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import re
import shutil
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol, Sequence
from uuid import uuid4

from aidast.agents.main import (
    CodexMainAgent,
    CodexLegacyReportWriter,
    CodexReportWriter,
    CodexValidationReviewer,
    MainAgentError,
)
from aidast.auth.codex import CodexAuth, CodexAuthError
from aidast.auth.browser import BrowserLoginError, collect_target_sessions
from aidast.core.http_safety import validate_hackerone_username
from aidast.attack.runtime import ReviewPreparationError, prepare_review
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.orchestration.chaining import (
    ChainingCoordinator,
    ChainingCoordinatorError,
)
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.executor import ReconExecutionError, ReconExecutor
from aidast.recon.agent import OfflineReconReview
from aidast.recon.models import ReconPlanTarget, ReconStep
from aidast.recon.policy import TargetPolicy, validate_policy_for_target
from aidast.recon.profiles import EXECUTION_PROFILES
from aidast.recon.surface import export_surface
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.paths import RESULT_ROOT
from aidast.reporting import (
    CaseReportAgent,
    CaseReportError,
    ReportAgent,
    ReportError,
    case_report_status,
    report_status,
)
from aidast.scope.paths import ScopePathError, resolve_scope_directory
from aidast.scope.reader import (
    PlaywrightProgramPageReader,
    ProgramPageError,
    RuntimeBrowserProgramPageReader,
)
from aidast.scope.models import AssetType, ScopeAsset, ScopeDocument
from aidast.updater import UpdateError, update_aidast
from aidast.validation import (
    ValidationAgent,
    ValidationCoordinatorError,
    ValidationError,
    shared_validation_status,
    validation_status,
)


EXECUTION_PROFILE_CHOICES = (*EXECUTION_PROFILES, "focused-recon")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aidast")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("login", help="sign in to Codex")
    commands.add_parser(
        "update",
        help="update AI DAST without removing the current installation",
    )
    tag = commands.add_parser("tag", help="tag unannotated Recon observations")
    tag.add_argument("database", type=Path)
    tag.add_argument("--scan-id")
    tag.add_argument("--batch-size", type=_positive_int, default=200)
    tag.add_argument("--codex-timeout", type=int, default=300)

    scope = commands.add_parser("scope", help="collect or inspect program scope")
    scope.add_argument(
        "subject",
        help="bug bounty program URL, or 'status'",
    )
    scope.add_argument(
        "program_url",
        nargs="?",
        help="program URL for the status operation",
    )
    _add_workflow_options(scope)
    scope.add_argument(
        "--login-mode",
        dest="scope_login_mode",
        choices=("native", "runtime-browser"),
        default="native",
        help=(
            "native uses the isolated Codex browser; runtime-browser opens an "
            "operator-controlled persistent browser for program-platform login"
        ),
    )
    scope.add_argument(
        "--identity",
        dest="scope_identity",
        default="primary",
        help="account label for the isolated program-platform browser session",
    )

    recon = commands.add_parser(
        "recon",
        help="collect or reuse approved Scope, then create Recon Plan and Tasks",
    )
    recon.add_argument("program_url", help="bug bounty program URL")
    _add_workflow_options(recon)
    execution = recon.add_mutually_exclusive_group()
    execution.add_argument(
        "--execute", action="store_true",
        help="compile per-target policy and execute the Recon Tasks",
    )
    execution.add_argument(
        "--policy-only", action="store_true",
        help="compile and preview per-target policy without running any recon tool",
    )
    selection = recon.add_mutually_exclusive_group()
    selection.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="CANONICAL_ASSET",
        help="approved canonical Scope asset to include; repeat for multiple targets",
    )
    selection.add_argument(
        "--all-targets",
        action="store_true",
        help="include every executable web target in the approved Scope",
    )
    recon.add_argument(
        "--start-url",
        help=(
            "operator-authorized URL that narrows one selected canonical target"
        ),
    )
    recon.add_argument(
        "--profile",
        choices=EXECUTION_PROFILE_CHOICES,
        default=None,
        help="optional execution cap profile; omitted by default to preserve Scope policy",
    )
    recon.add_argument(
        "--max-rps",
        type=_positive_float,
        help="lower request-rate ceiling applied to every generated target policy",
    )
    recon.add_argument(
        "--max-requests",
        type=_positive_int,
        help="lower total-request ceiling applied to every generated target policy",
    )
    recon.add_argument("--max-depth", type=_bounded_depth)
    recon.add_argument("--max-concurrency", type=_positive_int)
    recon.add_argument("--timeout-seconds", type=_positive_int)
    recon.add_argument(
        "--intigriti-username",
        type=_intigriti_username,
        help=(
            "Intigriti handle injected into X-Intigriti-Username and the "
            "required User-Agent suffix for every Recon HTTP request"
        ),
    )
    recon.add_argument(
        "--hackerone-username",
        type=_hackerone_username,
        help="HackerOne handle injected into X-HackerOne for approved target requests",
    )
    recon.add_argument("--auth-host", action="append", default=[], help="host allowed only during manual login bootstrap")
    recon.add_argument("--auth-path", action="append", default=[], help="path prefix allowed on --auth-host during login bootstrap")
    recon.add_argument("--db-path", type=Path, default=RESULT_ROOT / "Recon.db")
    recon.add_argument("--surface-path", type=Path, default=RESULT_ROOT / "Surface.json")
    recon.add_argument("--ffuf-wordlist")
    recon.add_argument(
        "--diagnostic-logs", action="store_true",
        help="write temporary endpoint-discovery diagnostics under result/logs",
    )
    recon.add_argument(
        "--tag-after", action="store_true",
        help="run the deferred observation-tagging worker after Recon completes",
    )
    recon.add_argument(
        "--tag-batch-size", type=_positive_int, default=200,
        help="maximum observations per deferred tagging request (default: 200)",
    )
    recon.add_argument(
        "--asset-discovery-batch-size", type=_positive_int, default=25,
        help=(
            "maximum wildcard-discovered hosts scheduled per wildcard in one run; "
            "remaining approved candidates stay in Recon.db for the next run"
        ),
    )
    _add_session_options(recon)

    run = commands.add_parser(
        "run",
        help="run AI Recon and tagging, then Attack, Chaining and Validation",
    )
    run.add_argument("program_url", help="bug bounty program URL")
    run.add_argument(
        "--scan-id",
        type=_scan_identifier,
        help=argparse.SUPPRESS,
    )
    _add_workflow_options(run)
    run_selection = run.add_mutually_exclusive_group(required=True)
    run_selection.add_argument(
        "--target", action="append", default=[], metavar="CANONICAL_ASSET",
        help="approved canonical Scope asset to include; repeat for multiple targets",
    )
    run_selection.add_argument(
        "--all-targets", action="store_true",
        help="include every executable web target in the approved Scope",
    )
    run.add_argument("--start-url")
    run.add_argument(
        "--profile", choices=EXECUTION_PROFILE_CHOICES, default=None
    )
    run.add_argument("--max-rps", type=_positive_float)
    run.add_argument("--max-requests", type=_positive_int)
    run.add_argument("--max-depth", type=_bounded_depth)
    run.add_argument("--max-concurrency", type=_positive_int)
    run.add_argument("--timeout-seconds", type=_positive_int)
    run.add_argument(
        "--intigriti-username",
        type=_intigriti_username,
        help=(
            "Intigriti handle injected into X-Intigriti-Username and the "
            "required User-Agent suffix for every Recon HTTP request"
        ),
    )
    run.add_argument(
        "--hackerone-username",
        type=_hackerone_username,
        help="HackerOne handle injected into X-HackerOne for approved target requests",
    )
    run.add_argument("--auth-host", action="append", default=[])
    run.add_argument("--auth-path", action="append", default=[])
    run.add_argument("--ffuf-wordlist")
    run.add_argument(
        "--diagnostic-logs", action="store_true",
        help="write temporary endpoint-discovery diagnostics under result/logs",
    )
    run.add_argument(
        "--asset-discovery-batch-size", type=_positive_int, default=25,
        help="maximum wildcard-discovered hosts scheduled per wildcard in one run",
    )
    run.add_argument(
        "--tag-after", action="store_true",
        help="run the deferred observation-tagging worker after Recon completes",
    )
    run.add_argument(
        "--tag-batch-size", type=_positive_int, default=200,
        help="maximum observations per deferred tagging request (default: 200)",
    )
    _add_session_options(run)
    run.add_argument(
        "--run-root", type=Path, default=RESULT_ROOT / "Runs",
        help="root for immutable Recon handoff artifacts (default: result/Runs)",
    )
    run.add_argument(
        "--attack-output-root", type=Path, default=RESULT_ROOT / "AttackRuns",
        help="root for merged Pipeline.db runs (default: result/AttackRuns)",
    )

    attack = commands.add_parser(
        "attack", help="prepare and inspect offline Attack runs"
    )
    attack_commands = attack.add_subparsers(dest="attack_command", required=True)
    for operation in ("review", "plan"):
        command = attack_commands.add_parser(
            operation,
            help=("prepare the legacy offline review queue" if operation == "review"
                  else "verify handoff and persist an offline review plan"),
        )
        command.add_argument("handoff", type=Path)
        command.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "AttackRun")
    for operation in ("status", "approve", "revoke", "execute"):
        command = attack_commands.add_parser(
            operation,
            help=("requires a trusted injected workflow" if operation in {"approve", "execute"}
                  else f"{operation} a persisted Attack run"),
        )
        command.add_argument("database", type=Path, help="materialized Attack database")
        command.add_argument("--run-id", help="select a run when the database contains several")
        if operation == "approve":
            command.add_argument("--by", dest="approved_by", required=True)
            command.add_argument("--authorization", type=Path, required=True,
                                 help="authorization document for the trusted verifier")
        elif operation == "revoke":
            command.add_argument(
                "--reason", required=True,
                help="record local revocation; trusted execution must check the run generation",
            )
        elif operation == "execute":
            command.add_argument("--authorization", type=Path, required=True,
                                 help="authorization document for the trusted verifier")

    validation = commands.add_parser(
        "validate", aliases=["validation"],
        help="run shared Validation or inspect persisted legacy Validation.db",
    )
    validation_commands = validation.add_subparsers(
        dest="validation_command", required=True
    )
    validation_run = validation_commands.add_parser(
        "run", help="run shared Validation or an explicit legacy selector"
    )
    validation_run.add_argument(
        "database",
        type=Path,
        help="Pipeline.db for shared Validation or legacy thin Attack.db",
    )
    validation_run.add_argument(
        "--output-dir", type=Path, default=RESULT_ROOT / "ValidationRun"
    )
    validation_run.add_argument("--run-id")
    validation_run.add_argument("--finding-id")
    validation_run.add_argument("--scan-id")
    validation_run.add_argument("--chain-id")
    validation_run.add_argument(
        "--policy",
        type=Path,
        help="current TargetPolicy.json for shared Validation",
    )
    validation_resume = validation_commands.add_parser(
        "resume", help="resume one failed shared Validation stage"
    )
    validation_resume.add_argument("database", type=Path)
    validation_resume.add_argument("--stage-run-id", required=True)
    validation_resume.add_argument("--policy", type=Path)
    validation_status_parser = validation_commands.add_parser(
        "status", help="inspect shared Pipeline.db or legacy Validation.db"
    )
    validation_status_parser.add_argument("database", type=Path)
    validation_status_parser.add_argument("--scan-id")
    validation_status_parser.add_argument("--case-id")

    report = commands.add_parser(
        "report", help="draft from a confirmed Validation case or legacy database"
    )
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_run = report_commands.add_parser(
        "run", help="create a local report draft; never submit it"
    )
    report_run.add_argument(
        "database",
        type=Path,
        help="Pipeline.db for case reports or legacy Validation.db",
    )
    report_run.add_argument(
        "--platform", required=True,
        choices=("hackerone", "intigriti", "bugcrowd"),
    )
    report_run.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "ReportRun")
    report_source = report_run.add_mutually_exclusive_group()
    report_source.add_argument("--validation-id")
    report_source.add_argument("--case-id")
    report_status_parser = report_commands.add_parser(
        "status", help="verify and inspect a Report.db"
    )
    report_status_parser.add_argument("database", type=Path)

    dashboard = commands.add_parser(
        "dashboard", help="serve the local operator WebUI and live scan events"
    )
    dashboard.add_argument(
        "--host", default="127.0.0.1",
        help="loopback address to bind (default: 127.0.0.1)",
    )
    dashboard.add_argument("--port", type=_positive_int, default=8000)
    dashboard.add_argument(
        "--result-root", type=Path, default=RESULT_ROOT,
        help=(
            "AI DAST result root (default: AIDAST_RESULT_ROOT, otherwise the "
            "cloned project's result directory)"
        ),
    )
    dashboard.add_argument(
        "--ui-dir", type=Path,
        help="optional built WebUI dist directory to serve at /",
    )
    return parser


def _default_login_mode() -> None:
    """No override means normal login-capability detection and session reuse."""
    return None


def _add_session_options(command):
    command.add_argument("--identity", default="primary", help="account label for isolated target sessions")
    command.add_argument("--session-bundle", type=Path, help="reuse a Session.json for exactly one target/account")
    command.add_argument(
        "--login-mode",
        choices=("none", "system-browser", "runtime-browser"),
        default=_default_login_mode(),
        help=(
            "omit this option for normal login detection and one session per site; "
            "none never opens a login prompt; "
            "runtime-browser opens Phase 1 Chromium for an explicit login and "
            "reuses that profile; system-browser is a compatibility option"
        ),
    )
    command.add_argument(
        "--auto-wildcard-start", action="store_true",
        help="choose a matching approved domain as a wildcard start URL when unambiguous",
    )


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _intigriti_username(value: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", candidate) is None:
        raise argparse.ArgumentTypeError(
            "must be a 1-64 character Intigriti handle using letters, digits, ., _, or -"
        )
    return candidate


def _hackerone_username(value: str) -> str:
    try:
        return validate_hackerone_username(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _scan_identifier(value: str) -> str:
    if re.fullmatch(r"scan_[0-9a-f]{32}", value) is None:
        raise argparse.ArgumentTypeError("must match scan_[0-9a-f]{32}")
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _bounded_depth(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer from 0 to 10") from exc
    if not 0 <= parsed <= 10:
        raise argparse.ArgumentTypeError("must be between 0 and 10")
    return parsed


def _add_workflow_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--output-dir",
        type=Path,
        default=RESULT_ROOT / "Scope",
        help=(
            "root directory for program scope artifacts "
            f"(default: {RESULT_ROOT / 'Scope'})"
        ),
    )
    command.add_argument(
        "--by",
        dest="approved_by",
        help="reviewer name recorded when the interactive draft is approved",
    )
    command.add_argument(
        "--page-timeout",
        type=float,
        default=45.0,
        help="maximum fallback page rendering time in seconds",
    )
    command.add_argument(
        "--codex-timeout",
        type=int,
        default=300,
        help="maximum Codex interpretation time in seconds",
    )


def _review_scope_draft(scope_path: Path) -> bool:
    try:
        document = ScopeDocument.model_validate_json(
            (scope_path.parent / "Scope.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        document = None

    print("Scope 추출 및 정책 해석이 완료되었습니다.")
    if document is not None:
        print(f"- 프로그램: {document.analysis.program_name}")
        print(f"- In-scope 자산: {len(document.analysis.in_scope_assets)}개")
        print(f"- Out-of-scope 자산: {len(document.analysis.out_of_scope_assets)}개")
        print(f"- 운영 제약사항: {len(document.analysis.operational_constraints)}개")
    print(f"Temporary Scope draft: {scope_path}")
    print("원본 프로그램 페이지와 임시 Scope.md를 대조해 검토하세요.")
    while True:
        try:
            answer = input("이 Scope를 승인하고 저장할까요? [y/N]: ").strip().casefold()
        except EOFError:
            print("입력이 없어 임시 Scope를 폐기합니다.")
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False
        print("y 또는 n으로 입력하세요.")


def main(
    argv: Sequence[str] | None = None,
    *,
    attack_workflow: AttackWorkflow | None = None,
    validation_reviewer: object | None = None,
    validation_coordinator: object | None = None,
    report_writer: object | None = None,
) -> int:
    parser = _parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Keep the original `attack HANDOFF [--output-dir DIR]` invocation.
    if (len(arguments) > 1 and arguments[0] == "attack"
            and arguments[1] not in {
                "review", "plan", "status", "approve", "revoke", "execute", "-h", "--help",
            }):
        arguments.insert(1, "review")
    args = parser.parse_args(arguments)

    try:
        if args.command == "login":
            return _run_login()
        if args.command == "update":
            print(update_aidast().message)
            return 0
        if args.command == "tag":
            return _run_tag(args)
        if args.command == "scope":
            return _run_scope(args, parser)
        if args.command == "recon":
            return _run_recon(args)
        if args.command == "run":
            args.execute = True
            args.policy_only = False
            args.tag_after = True
            args.db_path = RESULT_ROOT / "Recon.db"
            args.surface_path = RESULT_ROOT / "Surface.json"
            return _run_recon(
                args,
                prepare_attack=True,
                validation_coordinator=validation_coordinator,
            )
        if args.command == "attack":
            return _run_attack(args, workflow=attack_workflow)
        if args.command in {"validate", "validation"}:
            return _run_validation(
                args,
                reviewer=validation_reviewer,
                coordinator=validation_coordinator,
            )
        if args.command == "report":
            return _run_report(args, writer=report_writer)
        if args.command == "dashboard":
            return _run_dashboard(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        CoordinatorError,
        CodexAuthError,
        BrowserLoginError,
        MainAgentError,
        ProgramPageError,
        ReconCoordinatorError,
        ReconExecutionError,
        ReviewPreparationError,
        AttackCoordinatorError,
        ChainingCoordinatorError,
        CaseReportError,
        ReportError,
        ScopePathError,
        UpdateError,
        ValidationError,
        ValidationCoordinatorError,
        FileNotFoundError,
    ) as exc:
        print(f"aidast: {exc}", file=sys.stderr)
        return 1


def _run_login() -> int:
    CodexAuth().login()
    print("Codex login verified. AI DAST is ready.")
    return 0


def _run_dashboard(args: argparse.Namespace) -> int:
    """Serve the loopback-only operator UI and read-only run projections."""
    import ipaddress

    import uvicorn

    from aidast.web import create_app

    host = str(args.host).strip()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise MainAgentError(
            "dashboard has no remote authentication yet; bind only to localhost or a loopback IP"
        )
    application = create_app(
        result_root=args.result_root,
        ui_dir=args.ui_dir,
    )
    uvicorn.run(application, host=host, port=args.port, log_level="info")
    return 0


def _run_tag(args: argparse.Namespace) -> int:
    from aidast.recon import db as dbmod
    from aidast.recon.annotations import tag_pending_observations
    conn = dbmod.init_db(args.database)
    scan_id = args.scan_id
    if not scan_id:
        row = conn.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1").fetchone()
        if row is None:
            raise MainAgentError("no scan found in Recon database")
        scan_id = row[0]
    def _progress(batch_no, batch_count, processed, failed):
        print(f"Tagging batch {batch_no}/{batch_count}: "
              f"processed={processed}, failed={failed}", flush=True)

    done, failed = tag_pending_observations(
        conn, scan_id=scan_id,
        agent=CodexMainAgent(timeout_seconds=args.codex_timeout),
        batch_size=args.batch_size,
        progress=_progress,
    )
    print(f"Tagging complete: {done} observations processed, {failed} failed")
    return 0


def _run_scope(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.subject == "status":
        if not args.program_url:
            parser.error("`aidast scope status` requires a program URL")
        program_url = args.program_url
    else:
        if args.program_url:
            parser.error("scope collection accepts exactly one program URL")
        program_url = args.subject

    program_dir = resolve_scope_directory(program_url, args.output_dir)
    coordinator = ScopeCoordinator(program_dir)

    if args.subject == "status":
        if args.approved_by:
            parser.error("--by is only valid when collecting a new Scope")
        if args.scope_login_mode != "native" or args.scope_identity != "primary":
            parser.error("--login-mode and --identity are only valid when collecting")
        approval = coordinator.verify_approval()
        print(
            f"Scope approval valid: {approval.scope_id} "
            f"(approved by {approval.approved_by})"
        )
        return 0

    document = _collect_scope(
        program_url=program_url,
        args=args,
        coordinator=coordinator,
        main_agent=CodexMainAgent(timeout_seconds=args.codex_timeout),
    )
    if document is None:
        print("Scope draft rejected and discarded.")
        return 1
    print(
        f"Approved Scope saved for {document.analysis.program_name}: "
        f"{program_dir / 'Scope.md'}"
    )
    return 0


def _run_recon(
    args: argparse.Namespace,
    *,
    prepare_attack: bool = False,
    validation_coordinator: object | None = None,
) -> int:
    recon_failures = 0
    auth_hosts = getattr(args, "auth_host", [])
    auth_paths = getattr(args, "auth_path", [])
    if bool(auth_hosts) != bool(auth_paths):
        raise ReconCoordinatorError("--auth-host and --auth-path must be supplied together")
    if any(not host or "/" in host or ":" in host for host in auth_hosts):
        raise ReconCoordinatorError("--auth-host accepts host names only")
    if any(not path.startswith("/") for path in auth_paths):
        raise ReconCoordinatorError("--auth-path values must start with '/'")
    if args.execute and not (args.target or args.all_targets):
        raise ReconCoordinatorError(
            "--execute requires an explicit --target (repeatable) or --all-targets"
        )

    program_url = args.program_url
    program_dir = resolve_scope_directory(program_url, args.output_dir)
    scope_coordinator = ScopeCoordinator(program_dir)
    main_agent = CodexMainAgent(timeout_seconds=args.codex_timeout)

    if program_dir.exists():
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"Reusing approved Scope: {program_dir / 'Scope.md'}")
    else:
        scope_document = _collect_scope(
            program_url=program_url,
            args=args,
            coordinator=scope_coordinator,
            main_agent=main_agent,
        )
        if scope_document is None:
            print("Scope draft rejected and discarded. Recon was not planned.")
            return 1
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"Approved Scope saved: {program_dir / 'Scope.md'}")

    intigriti_username = getattr(args, "intigriti_username", None)
    hackerone_username = getattr(args, "hackerone_username", None)
    if intigriti_username and hackerone_username:
        raise ReconCoordinatorError(
            "--intigriti-username and --hackerone-username cannot be combined"
        )
    if (
        args.execute
        and "X-Intigriti-Username" in scope_markdown
        and not intigriti_username
    ):
        raise ReconCoordinatorError(
            "approved Scope requires X-Intigriti-Username; "
            "supply --intigriti-username"
        )
    if args.execute and "X-HackerOne" in scope_markdown and not hackerone_username:
        raise ReconCoordinatorError(
            "approved Scope requires X-HackerOne; supply --hackerone-username"
        )
    request_headers = (
        {
            "X-Intigriti-Username": intigriti_username,
            "User-Agent": f"aidast-recon/0.1 <intigriti:{intigriti_username}>",
        }
        if intigriti_username
        else {"X-HackerOne": hackerone_username}
        if hackerone_username
        else {}
    )

    selected_targets = _select_recon_targets(
        scope_document,
        requested_targets=args.target,
        all_targets=args.all_targets,
    )
    start_urls = _validate_start_url_selection(
        selected_targets,
        start_url=args.start_url,
        scope_document=scope_document,
        auto_wildcard_start=args.auto_wildcard_start,
    )
    # Wildcard targets first perform asset discovery. Binding their policy to
    # a single login URL would disable the approved wildcard expansion.
    start_urls = {
        key: value for key, value in start_urls.items()
        if key[0] != AssetType.WILDCARD.value
    }
    if args.target:
        print("Selected canonical Scope targets:")
        for target in selected_targets:
            print(f"- {target.asset_type.value}: {target.asset}")

    scan_id = (
        getattr(args, "scan_id", None) or f"scan_{uuid4().hex}"
        if args.execute
        else None
    )
    if prepare_attack and scan_id is not None:
        if (args.run_root / scan_id).exists() or (args.attack_output_root / scan_id).exists():
            raise ReconCoordinatorError(f"scan output already exists: {scan_id}")
    target_sessions = None
    if args.execute and (
        args.session_bundle is not None or args.login_mode == "system-browser"
    ):
        if args.session_bundle is not None:
            print("지정된 타깃 세션 번들을 검증합니다.")
        else:
            print(
                "운영체제 브라우저에서 로그인합니다. 로그인 중에는 "
                "프록시와 Scope 검사를 적용하지 않습니다."
            )
        target_sessions = collect_target_sessions(
            selected_targets, scope_id=scope_document.scope_id, run_id=scan_id,
            identity=args.identity, start_urls=start_urls, session_bundle=args.session_bundle,
            root=RESULT_ROOT / ".aidast_sessions",
        )
    elif args.execute and args.login_mode == "runtime-browser":
        print(
            "로그인 모드가 활성화되었습니다. Endpoint Discovery에서 "
            "타깃별 Chromium 로그인 세션을 수집합니다."
        )
    elif args.execute and args.login_mode is None:
        print(
            "자동 로그인 기능 판별 모드입니다. 먼저 비로그인으로 접속하고 로그인 "
            "폼·버튼·링크가 확인될 때만 Chromium 로그인 창을 엽니다."
        )
    elif args.execute:
        print(
            "비로그인 Recon 모드입니다. 브라우저 로그인 창을 열지 않습니다. "
            "인증 탐색이 필요하면 --login-mode runtime-browser 또는 "
            "--session-bundle을 사용하세요."
        )

    plan = main_agent.create_recon_plan(
        scope_id=scope_document.scope_id,
        scope_markdown=scope_markdown,
        allowed_targets=selected_targets,
    )
    if args.all_targets:
        # --all-targets is an operator choice. Do not let the planning model
        # omit targets or reduce exact web targets to probe-only tasks.
        proposed = {
            (item.asset_type, item.asset): item for item in plan.targets
        }
        complete_plan_targets = []
        for target in selected_targets:
            identity = (target.asset_type, target.asset)
            if target.asset_type not in {
                AssetType.URL, AssetType.API, AssetType.DOMAIN,
                AssetType.WILDCARD, AssetType.IP_ADDRESS,
            }:
                continue
            model_target = proposed.get(identity)
            steps = (
                [ReconStep.ASSET_DISCOVERY]
                if target.asset_type is AssetType.WILDCARD
                else [
                    ReconStep.DNS_RESOLUTION,
                    ReconStep.HTTP_PROBE,
                    ReconStep.ORIGIN_DISCOVERY,
                    ReconStep.ENDPOINT_DISCOVERY,
                ]
            )
            complete_plan_targets.append(ReconPlanTarget(
                asset_type=target.asset_type,
                asset=target.asset,
                steps=steps,
                constraints=(
                    list(model_target.constraints)
                    if model_target is not None
                    else list(plan.global_constraints)
                ),
            ))
        if complete_plan_targets:
            plan = plan.model_copy(update={"targets": complete_plan_targets})
    tasks = ReconCoordinator().create_tasks(
        plan=plan,
        scope=scope_document,
        prioritize_asset_discovery=args.all_targets,
    )
    print(
        f"Recon Plan created: {plan.plan_id} "
        f"({len(plan.targets)} targets, {len(tasks)} tasks)"
    )
    for task in tasks:
        print(f"- {task.task_type.value}: {task.target.asset}")
    if args.execute or args.policy_only:
        print("Main Agent가 승인된 Scope에서 타깃별 실행 정책을 생성합니다.")
        policies = main_agent.create_target_policies(
            scope_id=scope_document.scope_id,
            scope_markdown=scope_markdown,
            plan=plan,
            execution_start_urls=start_urls,
        )
        policies = _apply_scope_host_exclusions(
            policies,
            getattr(scope_document.analysis, "out_of_scope_assets", []),
            scope_markdown=scope_markdown,
        )
        policies = _apply_policy_caps(
            policies,
            profile=args.profile,
            max_rps=args.max_rps,
            max_requests=args.max_requests,
            max_depth=args.max_depth,
            max_concurrency=args.max_concurrency,
            timeout_seconds=args.timeout_seconds,
        )
        if hackerone_username:
            policies = {
                key: policy.model_copy(update={
                    "hackerone_username": hackerone_username,
                })
                for key, policy in policies.items()
            }
        policy_path = program_dir / "TargetPolicy.json"
        policy_path.write_text(
            json.dumps(
                {"schema_version": "1.0", "scope_id": scope_document.scope_id,
                 "policies": [policy.model_dump(mode="json") for policy in policies.values()]},
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
        print(f"TargetPolicy 생성 및 Python 검증 완료: {policy_path}")
        _print_policy_preview(policies)
        if args.policy_only:
            print("Policy-only 모드: 네트워크 Recon 도구는 실행하지 않았습니다.")
            return 0
        _require_start_urls_allowed(policies, start_urls)
        if prepare_attack:
            run_dir = (args.run_root / scan_id).resolve()
            run_dir.mkdir(parents=True, exist_ok=False)
            db_path = run_dir / "Recon.db"
            surface_path = run_dir / "Surface.json"
        else:
            run_dir = None
            db_path = args.db_path
            surface_path = args.surface_path
        executor = ReconExecutor(
            scan_id=scan_id,
            scope_type="approved_scope",
            scope_value=scope_document.scope_id,
            db_path=db_path,
            ffuf_wordlist=args.ffuf_wordlist,
            target_policies=policies,
            require_policy_enforcement=True,
            execution_start_urls=start_urls,
            annotation_agent=main_agent,
            target_sessions=target_sessions,
            request_headers=request_headers,
            auth_bootstrap=(
                {"hosts": args.auth_host, "paths": args.auth_path}
                if args.auth_host or args.auth_path else None
            ),
            interactive_login=args.login_mode == "runtime-browser",
            automatic_login=args.login_mode is None,
            diagnostic_path=(
                RESULT_ROOT / "logs" / scan_id / "recon.jsonl"
                if args.diagnostic_logs else None
            ),
            prioritize_discovered_assets_first=args.all_targets,
            asset_discovery_batch_size=args.asset_discovery_batch_size,
            candidate_db_path=program_dir / "AssetDiscovery.db",
        )
        if args.diagnostic_logs:
            print(
                "Recon 진단 로그: "
                f"{RESULT_ROOT / 'logs' / scan_id / 'recon.jsonl'}"
            )
        stage_run_id = start_stage_run(
            executor.conn, scan_id=scan_id, stage="recon"
        )
        recon_failures = 0
        try:
            recon_failures = executor.run(tasks)
            if getattr(args, "tag_after", False):
                from aidast.recon.annotations import tag_pending_observations
                print("Recon 완료: 저장된 관측 태깅을 시작합니다.")
                _, failed_tags = tag_pending_observations(
                    executor.conn,
                    scan_id=scan_id,
                    agent=main_agent,
                    batch_size=args.tag_batch_size,
                    progress=lambda n, total, done, failed: print(
                        f"Tagging batch {n}/{total}: processed={done}, failed={failed}",
                        flush=True,
                    ),
                )
                _require_complete_recon_annotations(failed_tags)
            recon_review = OfflineReconReview(
                planner=main_agent,
                conn=executor.conn,
                scope_id=scope_document.scope_id,
                scan_id=scan_id,
                approved_assets=selected_targets,
                target_policies=policies,
            ).review()
            review_path = (
                (run_dir / "ReconReview.json") if run_dir is not None
                else args.surface_path.with_name("ReconReview.json")
            )
            review_path.parent.mkdir(parents=True, exist_ok=True)
            review_path.write_text(
                recon_review.model_dump_json(indent=2), encoding="utf-8"
            )
            executor.conn.execute(
                "UPDATE scans SET status=?, finished_at=CURRENT_TIMESTAMP "
                "WHERE scan_id=?",
                ("completed_with_errors" if recon_failures else "completed", scan_id),
            )
            executor.conn.commit()
            export_surface(
                executor.conn, scan_id=scan_id, output_path=surface_path
            )
            finish_stage_run(executor.conn, stage_run_id, status="completed")
        # KeyboardInterrupt/SystemExit must also finalize the durable scan and
        # stage records; they are re-raised after cleanup below.
        except BaseException as exc:
            executor.conn.execute(
                "UPDATE scans SET status='failed', finished_at=CURRENT_TIMESTAMP "
                "WHERE scan_id=?",
                (scan_id,),
            )
            executor.conn.commit()
            try:
                finish_stage_run(
                    executor.conn, stage_run_id, status="failed",
                    error_message=str(exc),
                )
            finally:
                getattr(executor, "close", executor.conn.close)()
            raise
        print(f"Recon Surface saved: {surface_path}")
        try:
            if prepare_attack and run_dir is not None and not recon_failures:
                handoff_path = _write_recon_handoff(
                    executor=executor,
                    run_dir=run_dir,
                    program_dir=program_dir,
                    policy_path=policy_path,
                    surface_path=surface_path,
                    review_path=review_path,
                    stage_run_id=stage_run_id,
                )
                attack_output = args.attack_output_root / scan_id
                legacy_plan = _plan_attack(
                    handoff_path,
                    attack_output / "legacy",
                )
                pipeline_path = attack_output / "Pipeline.db"
                materialize_pipeline(handoff_path, pipeline_path)
                attack_result = AttackCoordinator(
                    agent=main_agent,
                    db_path=pipeline_path,
                    scope_path=run_dir / "Scope.md",
                    policy_path=run_dir / "TargetPolicy.json",
                ).run(scan_id)
                chaining_result = ChainingCoordinator(
                    agent=main_agent,
                    db_path=pipeline_path,
                    scope_path=run_dir / "Scope.md",
                    policy_path=run_dir / "TargetPolicy.json",
                ).run(scan_id)
                from aidast.validation import build_native_validation_coordinator

                coordinator = validation_coordinator
                if coordinator is None:
                    coordinator = build_native_validation_coordinator(
                        db_path=pipeline_path,
                        policy_path=run_dir / "TargetPolicy.json",
                    )
                validation_result = coordinator.run(scan_id)
                print(f"Recon handoff saved: {handoff_path}")
                print(
                    f"Legacy Attack plan saved: {legacy_plan['database']} "
                    f"({legacy_plan['task_count']} tasks)"
                )
                print(
                    f"Native Attack completed: {len(attack_result.finding_ids)} findings; "
                    f"Chaining {chaining_result.status.lower()}; "
                    f"Validation {len(validation_result.case_ids)} cases; "
                    f"shared DB: {pipeline_path}"
                )
        finally:
            getattr(executor, "close", executor.conn.close)()
    return 2 if recon_failures else 0


def _require_complete_recon_annotations(failed_tags: int) -> None:
    if failed_tags:
        raise ReconExecutionError(
            f"{failed_tags} Recon observations could not be tagged; "
            "Attack was not started"
        )


def _write_recon_handoff(
    *, executor: ReconExecutor, run_dir: Path, program_dir: Path,
    policy_path: Path, surface_path: Path, review_path: Path, stage_run_id: str,
) -> Path:
    copied = {
        "Scope.md": program_dir / "Scope.md",
        "Scope.json": program_dir / "Scope.json",
        "Approval.json": program_dir / "Approval.json",
        "TargetPolicy.json": policy_path,
    }
    for name, source in copied.items():
        shutil.copy2(source, run_dir / name)
    artifacts = [
        hash_artifact(run_dir / "Recon.db", root=run_dir, role="database",
                      media_type="application/vnd.sqlite3"),
        hash_artifact(surface_path, root=run_dir, role="surface",
                      media_type="application/json"),
        hash_artifact(review_path, root=run_dir, role="recon-review",
                      media_type="application/json"),
    ]
    for name, role, media_type in (
        ("Scope.md", "scope-markdown", "text/markdown"),
        ("Scope.json", "scope", "application/json"),
        ("Approval.json", "scope-approval", "application/json"),
        ("TargetPolicy.json", "target-policy", "application/json"),
    ):
        artifacts.append(
            hash_artifact(run_dir / name, root=run_dir, role=role,
                          media_type=media_type)
        )
    counts = {
        table: executor.conn.execute(
            f"SELECT COUNT(*) FROM {table} "
            "WHERE " + (
                "scan_id=?" if table == "assets" else
                "origin_id IN (SELECT o.origin_id FROM origins o JOIN assets a "
                "ON a.asset_id=o.asset_id WHERE a.scan_id=?)"
            ),
            (executor.scan_id,),
        ).fetchone()[0]
        for table in ("assets", "endpoints")
    }
    manifest = HandoffManifest(
        scan_id=executor.scan_id,
        stage_run_id=stage_run_id,
        producer_stage="recon",
        consumer_stage="review",
        db_path="Recon.db",
        artifacts=artifacts,
        counts=counts,
        metadata={"scope_id": executor.conn.execute(
            "SELECT scope_value FROM scans WHERE scan_id=?", (executor.scan_id,)
        ).fetchone()[0]},
    )
    handoff_path = run_dir / "Handoff.json"
    handoff_path.write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    return handoff_path


class AttackWorkflow(Protocol):
    """Trusted application boundary; command-line input never installs one.

    An embedding application must verify authorization and bind execution to
    its safe agent/broker. Supplying a name or a JSON file is not authorization.
    """

    def approve(
        self, database: Path, *, run_id: str | None,
        approved_by: str, authorization: Path,
    ) -> dict[str, Any]: ...

    def execute(
        self, database: Path, *, run_id: str | None, authorization: Path,
    ) -> dict[str, Any]: ...

    def revoke(
        self, database: Path, *, run_id: str | None, reason: str,
    ) -> dict[str, Any]:
        """Revoke store and broker ledger grants consistently before returning."""
        ...


def _run_attack(
    args: argparse.Namespace, *, workflow: AttackWorkflow | None = None,
) -> int:
    operation = args.attack_command
    if operation == "review":
        review = prepare_review(args.handoff, args.output_dir)
        print(
            f"Attack Agent offline review prepared: {review.queue_path} "
            f"({len(review.tasks)} tasks)"
        )
        return 0
    try:
        if operation in {"approve", "execute"}:
            if workflow is None:
                raise ReviewPreparationError(
                    f"attack {operation} requires a trusted injected Attack workflow; "
                    "the default CLI cannot authorize or execute requests"
                )
            options = {"run_id": args.run_id, "authorization": args.authorization}
            if operation == "approve":
                options["approved_by"] = args.approved_by
            result = getattr(workflow, operation)(args.database, **options)
        elif operation == "plan":
            result = _plan_attack(args.handoff, args.output_dir)
        elif operation == "revoke" and workflow is not None:
            result = workflow.revoke(args.database, run_id=args.run_id, reason=args.reason)
        else:
            from aidast.attack.store import AttackStore

            with AttackStore.open(args.database, run_id=args.run_id) as store:
                if operation == "revoke":
                    store.revoke_run(reason=args.reason)
                result = store.get_run()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        raise ReviewPreparationError(str(exc)) from exc


def _run_validation(
    args: argparse.Namespace,
    *,
    reviewer: object | None = None,
    coordinator: object | None = None,
) -> int:
    if args.validation_command == "status" and (args.scan_id or args.case_id):
        result = shared_validation_status(
            args.database,
            scan_id=args.scan_id,
            case_id=args.case_id,
        )
    elif args.validation_command == "status":
        result = validation_status(args.database)
    elif args.validation_command == "resume":
        from aidast.validation import build_native_validation_coordinator

        if coordinator is None:
            coordinator = build_native_validation_coordinator(
                db_path=args.database,
                policy_path=args.policy or args.database.parent / "TargetPolicy.json",
            )
        resumed = coordinator.resume(args.stage_run_id)
        result = (
            resumed.model_dump(mode="json")
            if hasattr(resumed, "model_dump")
            else resumed
        )
    elif args.scan_id:
        from aidast.validation import build_native_validation_coordinator

        if coordinator is None:
            coordinator = build_native_validation_coordinator(
                db_path=args.database,
                policy_path=args.policy or args.database.parent / "TargetPolicy.json",
            )
        shared_result = coordinator.run(
            args.scan_id,
            finding_id=args.finding_id,
            chain_id=args.chain_id,
        )
        result = (
            shared_result.model_dump(mode="json")
            if hasattr(shared_result, "model_dump")
            else shared_result
        )
    else:
        raw = ValidationAgent(reviewer or CodexValidationReviewer()).run(
            args.database,
            args.output_dir,
            run_id=args.run_id,
            finding_id=args.finding_id,
        )
        result = {
            "database": raw["database"],
            "validation_run_id": raw["validation_run_id"],
            "run_id": raw["run_id"],
            "scan_id": raw["scan_id"],
            "status": raw["status"],
            "decision_count": raw["decision_count"],
            "decisions": [
                {
                    "validation_id": item["validation_id"],
                    "finding_id": item["finding_id"],
                    "status": item["status"],
                }
                for item in raw["decisions"]
            ],
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


def _run_report(args: argparse.Namespace, *, writer: object | None = None) -> int:
    if args.report_command == "status":
        with sqlite3.connect(args.database) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        result = (
            case_report_status(args.database)
            if version == 2
            else report_status(args.database)
        )
    elif args.case_id:
        result = CaseReportAgent(writer or CodexReportWriter()).run(
            args.database,
            args.output_dir,
            platform=args.platform,
            case_id=args.case_id,
        )
    else:
        result = ReportAgent(writer or CodexLegacyReportWriter()).run(
            args.database,
            args.output_dir,
            platform=args.platform,
            validation_id=args.validation_id,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


def _plan_attack(handoff: Path, output_dir: Path) -> dict[str, Any]:
    from aidast.attack.authorization import canonical_digest
    from aidast.attack.catalog import load_catalog
    from aidast.attack.store import materialize_attack_database

    catalog_digest = canonical_digest([asdict(entry) for entry in load_catalog()])
    with materialize_attack_database(
        handoff, output_dir, catalog_digest=catalog_digest,
    ) as store:
        review = prepare_review(handoff, output_dir / "review")
        write = store.save_plan(
            review.to_dict(portable=True), revision=1,
            tasks=[asdict(task) for task in review.tasks],
        )
        if write.error:
            raise ReviewPreparationError(f"could not persist Attack plan: {write.error}")
        return {
            "run_id": store.run_id,
            "scan_id": store.scan_id,
            "database": str(store.path),
            "mode": "offline",
            "task_count": len(review.tasks),
            "queue_path": str(review.queue_path),
        }


def _validate_start_url_selection(
    selected_targets: Sequence[ScopeAsset],
    *,
    start_url: str | None,
    scope_document: ScopeDocument | None = None,
    auto_wildcard_start: bool = False,
) -> dict[tuple[str, str], str]:
    if start_url is None:
        result = {}
        if auto_wildcard_start and scope_document is not None:
            for target in selected_targets:
                if target.asset_type is AssetType.WILDCARD:
                    value = _auto_wildcard_start_url(target, scope_document)
                    if value:
                        result[(target.asset_type.value, target.asset)] = value
        return result
    if len(selected_targets) != 1:
        raise ReconCoordinatorError(
            "--start-url requires exactly one --target"
        )
    target = selected_targets[0]
    from aidast.recon.policy import validate_start_url_for_target

    try:
        validate_start_url_for_target(
            start_url,
            asset_type=target.asset_type,
            asset=target.asset,
        )
    except ValueError as exc:
        raise ReconCoordinatorError(f"unsafe --start-url: {exc}") from exc
    return {(target.asset_type.value, target.asset): start_url}


def _auto_wildcard_start_url(target: ScopeAsset, scope_document: ScopeDocument) -> str | None:
    """Select a concrete approved domain matching a wildcard asset."""
    from aidast.recon.policy import validate_start_url_for_target
    candidates = []
    for asset in scope_document.analysis.in_scope_assets:
        if asset.asset_type is not AssetType.DOMAIN:
            continue
        try:
            validate_start_url_for_target(
                f"https://{asset.asset}", asset_type=target.asset_type, asset=target.asset
            )
        except ValueError:
            continue
        candidates.append(asset.asset)
    if candidates:
        # The operator explicitly enabled automation; use the first stable
        # approved-domain candidate from Scope order. Patterns with no
        # concrete approved candidate still fall back to the prompt.
        return f"https://{candidates[0]}"
    return None


def _select_recon_targets(
    scope_document: ScopeDocument,
    *,
    requested_targets: Sequence[str],
    all_targets: bool,
) -> list[ScopeAsset]:
    approved = scope_document.analysis.in_scope_assets
    if all_targets or not requested_targets:
        return list(approved)

    seen: set[str] = set()
    duplicates: list[str] = []
    for value in requested_targets:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        raise ReconCoordinatorError(
            "duplicate --target value(s): " + ", ".join(duplicates)
        )

    approved_by_asset = {target.asset: target for target in approved}
    missing = [value for value in requested_targets if value not in approved_by_asset]
    if missing:
        available = ", ".join(target.asset for target in approved) or "(none)"
        raise ReconCoordinatorError(
            "--target is not an exact canonical in-scope asset: "
            f"{', '.join(missing)}. Available targets: {available}"
        )
    return [approved_by_asset[value] for value in requested_targets]


def _apply_scope_host_exclusions(
    policies: dict[tuple[str, str], TargetPolicy],
    out_of_scope_assets: Sequence[ScopeAsset],
    *,
    scope_markdown: str | None = None,
) -> dict[tuple[str, str], TargetPolicy]:
    """Compile hostname-shaped Scope exclusions into enforceable policies."""
    patterns: list[str] = []
    for asset in out_of_scope_assets:
        value = asset.asset.strip().lower().rstrip(".")
        root = value.removeprefix("*.")
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", root):
            patterns.append(value)

    result: dict[tuple[str, str], TargetPolicy] = {}
    for key, policy in policies.items():
        canonical = policy.asset.lower().rstrip(".").removeprefix("*.")
        applicable = {
            pattern
            for pattern in patterns
            if (
                pattern.removeprefix("*.") == canonical
                or pattern.removeprefix("*.").endswith("." + canonical)
            )
        }
        # Models may repeat wildcard-wide exclusions on every policy. Keep only
        # exclusions that belong to this target; never let one target's notes
        # invalidate an unrelated exact-domain policy.
        existing = {
            pattern.lower().rstrip(".")
            for pattern in policy.excluded_hosts
            if (
                policy.asset_type.value == "WILDCARD"
                and pattern.lower().rstrip(".").removeprefix("*.") != canonical
                and pattern.lower().rstrip(".").removeprefix("*.").endswith(
                    "." + canonical
                )
            )
        }
        excluded_hosts = sorted(existing | applicable)

        allowed_hosts = list(policy.allowed_hosts)
        # A Scope may approve "*.example.com" while separately marking its
        # own root "example.com" out of scope (e.g. a marketing site hosted
        # at the apex, with the real product on subdomains). A wildcard
        # never covers its own apex by DNS convention, so this is not a
        # contradiction in the Scope -- but the policy proposal always
        # seeds a WILDCARD's allowed_hosts with the bare root as its
        # crawl/DNS anchor, so applying the root exclusion above would
        # otherwise make the compiled policy self-contradictory. Keep the
        # exclusion (the root must stay unreachable) and re-anchor
        # allowed_hosts on the wildcard pattern instead, which every
        # WILDCARD host check already accepts in place of the bare root.
        if policy.asset_type.value == "WILDCARD" and canonical in excluded_hosts:
            allowed_hosts = [
                f"*.{canonical}" if host.lower().rstrip(".") == canonical else host
                for host in allowed_hosts
            ]

        narrowed = policy.model_copy(update={
            "excluded_hosts": excluded_hosts,
            "allowed_hosts": allowed_hosts,
        })
        try:
            validate_policy_for_target(
                narrowed,
                asset_type=narrowed.asset_type,
                asset=narrowed.asset,
                scope_markdown=scope_markdown,
            )
        except ValueError as exc:
            raise ReconCoordinatorError(
                f"Scope host exclusions make target policy unsafe: {exc}"
            ) from exc
        result[key] = narrowed
    return result


def _apply_policy_caps(
    policies: dict[tuple[str, str], TargetPolicy],
    *,
    profile: str | None,
    max_rps: float | None,
    max_requests: int | None,
    max_depth: int | None,
    max_concurrency: int | None,
    timeout_seconds: int | None,
) -> dict[tuple[str, str], TargetPolicy]:
    profile_limits = (
        EXECUTION_PROFILES[
            "focused-discovery" if profile == "focused-recon" else profile
        ]
        if profile
        else None
    )
    capped: dict[tuple[str, str], TargetPolicy] = {}
    for key, policy in policies.items():
        effective_rps = min(
            policy.limits.requests_per_second,
            (
                profile_limits.requests_per_second
                if profile_limits is not None
                else policy.limits.requests_per_second
            ),
            max_rps if max_rps is not None else float("inf"),
        )
        limits = policy.limits.model_copy(
            update={
                "requests_per_second": effective_rps,
                "max_requests": min(
                    policy.limits.max_requests,
                    (
                        profile_limits.max_requests
                        if profile_limits is not None
                        else policy.limits.max_requests
                    ),
                    max_requests if max_requests is not None else 100_000,
                ),
                "max_depth": min(
                    policy.limits.max_depth,
                    (
                        profile_limits.max_depth
                        if profile_limits is not None
                        else policy.limits.max_depth
                    ),
                    max_depth if max_depth is not None else 10,
                ),
                "concurrency": min(
                    policy.limits.concurrency,
                    (
                        profile_limits.concurrency
                        if profile_limits is not None
                        else policy.limits.concurrency
                    ),
                    max_concurrency if max_concurrency is not None else 20,
                    1 if effective_rps < 1 and (profile is not None or max_rps is not None) else policy.limits.concurrency,
                ),
                "timeout_seconds": min(
                    policy.limits.timeout_seconds,
                    (
                        profile_limits.timeout_seconds
                        if profile_limits is not None
                        else policy.limits.timeout_seconds
                    ),
                    timeout_seconds if timeout_seconds is not None else 120,
                ),
            }
        )
        capped[key] = policy.model_copy(update={"limits": limits})
    return capped


def _require_start_urls_allowed(
    policies: dict[tuple[str, str], TargetPolicy],
    start_urls: dict[tuple[str, str], str],
) -> None:
    for key, start_url in start_urls.items():
        policy = policies.get(key)
        if policy is None or not policy.allows_url(start_url):
            raise ReconCoordinatorError(
                "generated TargetPolicy does not authorize --start-url; "
                f"execution remains fail-closed: {start_url}"
            )


def _print_policy_preview(policies) -> None:
    print("도구 제어값 미리보기:")
    for policy in policies.values():
        limits = policy.limits
        print(f"- target: {policy.asset}")
        print(
            "  network: "
            f"schemes={policy.allowed_schemes}, hosts={policy.allowed_hosts}, "
            f"excluded_hosts={policy.excluded_hosts}, "
            f"ports={policy.allowed_ports}, methods={policy.allowed_methods}"
        )
        print(
            "  katana: "
            f"depth={limits.max_depth}, concurrency={limits.concurrency}, "
            f"rate={limits.requests_per_second}/s, "
            f"headless={policy.tools.katana_headless}"
        )
        print(
            "  ffuf: "
            f"enabled={policy.tools.ffuf_enabled}, "
            f"recursion={policy.tools.ffuf_recursion}, "
            f"rate={limits.requests_per_second}/s"
        )
        print(
            "  playwright: "
            f"interaction={policy.tools.playwright_interaction}, "
            f"form_submission={policy.tools.form_submission}"
        )
        print(
            "  mitmproxy: enforcement=true, "
            f"max_requests={limits.max_requests}, "
            f"allowed_paths={policy.allowed_path_prefixes}, "
            f"excluded_paths={policy.excluded_path_prefixes}"
        )


def _collect_scope(
    *,
    program_url: str,
    args: argparse.Namespace,
    coordinator: ScopeCoordinator,
    main_agent: CodexMainAgent,
):
    primary_reader = None
    if getattr(args, "scope_login_mode", "native") == "runtime-browser":
        primary_reader = RuntimeBrowserProgramPageReader(
            identity=args.scope_identity,
            timeout_seconds=args.page_timeout,
        )
    return coordinator.collect(
        program_url,
        main_agent=main_agent,
        primary_reader=primary_reader,
        fallback_reader=PlaywrightProgramPageReader(
            timeout_seconds=args.page_timeout
        ),
        approved_by=args.approved_by or getpass.getuser(),
        review=_review_scope_draft,
    )


if __name__ == "__main__":
    raise SystemExit(main())
