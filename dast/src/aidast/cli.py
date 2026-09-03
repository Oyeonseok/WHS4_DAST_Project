from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from aidast.agents.main import CodexMainAgent, MainAgentError
from aidast.auth.codex import CodexAuth, CodexAuthError
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.db import init_db
from aidast.recon.executor import ReconExecutor, ReconExecutionError
from aidast.scope.paths import ScopePathError, resolve_scope_directory
from aidast.scope.reader import PlaywrightProgramPageReader, ProgramPageError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aidast")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("login", help="sign in to Codex")

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

    recon = commands.add_parser(
        "recon",
        help="collect or reuse approved Scope, then create Recon Plan and Tasks",
    )
    recon.add_argument("program_url", help="bug bounty program URL")
    _add_workflow_options(recon)

    attack = commands.add_parser(
        "attack",
        help="run Attack → Validator → Report pipeline on recon results",
    )
    attack.add_argument(
        "--db",
        type=Path,
        required=True,
        help="path to the recon SQLite DB file",
    )
    attack.add_argument(
        "--scan-id",
        required=True,
        help="scan_id to attack (from recon DB)",
    )
    attack.add_argument(
        "--scope-dir",
        type=Path,
        required=True,
        help="directory containing Scope.md",
    )
    attack.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports"),
        help="directory to save report files (default: reports)",
    )
    attack.add_argument(
        "--codex-timeout",
        type=int,
        default=300,
        help="maximum Codex interpretation time in seconds (default: 300)",
    )
    attack.add_argument(
        "--model",
        default=None,
        help="Codex model for attack/validator/report (default: o4-mini)",
    )

    scan = commands.add_parser(
        "scan",
        help="full pipeline: Scope -> Recon -> Attack -> Validate -> Report",
    )
    scan.add_argument("program_url", help="target URL to scan")
    _add_workflow_options(scan)
    scan.add_argument(
        "--login-email",
        help="login email for authenticated crawling",
    )
    scan.add_argument(
        "--login-password",
        help="login password for authenticated crawling",
    )
    scan.add_argument(
        "--login-path",
        default="/login",
        help="login page path (default: /login)",
    )
    scan.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports"),
        help="directory to save report files (default: reports)",
    )
    scan.add_argument(
        "--db",
        type=Path,
        default=None,
        help="path to the SQLite DB file (default: auto-generated)",
    )
    scan.add_argument(
        "--ffuf-wordlist",
        help="path to ffuf wordlist for brute-force endpoint discovery",
    )
    scan.add_argument(
        "--proxy",
        help="HTTP proxy for mitmproxy observation (e.g. http://127.0.0.1:8080)",
    )
    scan.add_argument(
        "--model",
        default=None,
        help="Codex model for scope/recon (default: o4-mini)",
    )
    scan.add_argument(
        "--attack-model",
        default=None,
        help="Codex model for attack/validator/report (default: o4-mini)",
    )
    return parser


def _add_workflow_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--output-dir",
        type=Path,
        default=Path("Scope"),
        help="root directory for program scope artifacts (default: Scope)",
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "login":
            return _run_login()
        if args.command == "scope":
            return _run_scope(args, parser)
        if args.command == "recon":
            return _run_recon(args)
        if args.command == "attack":
            return _run_attack(args)
        if args.command == "scan":
            return _run_scan(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        AttackCoordinatorError,
        CoordinatorError,
        CodexAuthError,
        MainAgentError,
        ProgramPageError,
        ReconCoordinatorError,
        ReconExecutionError,
        ScopePathError,
    ) as exc:
        print(f"aidast: {exc}", file=sys.stderr)
        return 1


def _run_login() -> int:
    CodexAuth().login()
    print("Codex login verified. AI DAST is ready.")
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


def _run_recon(args: argparse.Namespace) -> int:
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

    plan = main_agent.create_recon_plan(
        scope_id=scope_document.scope_id,
        scope_markdown=scope_markdown,
    )
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope_document)
    print(
        f"Recon Plan created: {plan.plan_id} "
        f"({len(plan.targets)} targets, {len(tasks)} tasks)"
    )
    for task in tasks:
        print(f"- {task.task_type.value}: {task.target.asset}")
    return 0


def _run_attack(args: argparse.Namespace) -> int:
    db_path = args.db
    if not db_path.exists():
        print(f"aidast: DB 파일을 찾을 수 없습니다: {db_path}", file=sys.stderr)
        return 1

    scope_dir = args.scope_dir
    if not (scope_dir / "Scope.md").exists():
        print(
            f"aidast: Scope.md를 찾을 수 없습니다: {scope_dir / 'Scope.md'}",
            file=sys.stderr,
        )
        return 1

    conn = init_db(db_path)
    try:
        agent = CodexMainAgent(
            timeout_seconds=args.codex_timeout,
            attack_model=getattr(args, "model", None),
        )
        coordinator = AttackCoordinator(
            agent=agent,
            conn=conn,
            scope_dir=scope_dir,
            report_dir=args.report_dir,
        )
        confirmed = coordinator.run(args.scan_id)
        print(
            f"Attack 파이프라인 완료: {len(confirmed)}개 취약점 confirmed"
        )
        for fid in confirmed:
            print(f"  - {fid} → {args.report_dir / f'{fid}_report.md'}")
        return 0
    finally:
        conn.close()


def _run_scan(args: argparse.Namespace) -> int:
    """Scope -> Recon -> Attack -> Validate -> Report 전체 파이프라인."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    program_url = args.program_url
    program_dir = resolve_scope_directory(program_url, args.output_dir)
    scope_coordinator = ScopeCoordinator(program_dir)
    main_agent = CodexMainAgent(
        timeout_seconds=args.codex_timeout,
        model=getattr(args, "model", None),
        attack_model=getattr(args, "attack_model", None),
    )

    # --- Phase 1: Scope ---
    print("\n=== Phase 1: Scope Collection ===")
    if program_dir.exists():
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"기존 Scope 재사용: {program_dir / 'Scope.md'}")
    else:
        scope_document = _collect_scope(
            program_url=program_url,
            args=args,
            coordinator=scope_coordinator,
            main_agent=main_agent,
        )
        if scope_document is None:
            print("Scope 승인 거부됨. 스캔을 중단합니다.")
            return 1
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"Scope 저장됨: {program_dir / 'Scope.md'}")

    # --- Phase 2: Recon Plan ---
    print("\n=== Phase 2: Recon Plan ===")
    plan = main_agent.create_recon_plan(
        scope_id=scope_document.scope_id,
        scope_markdown=scope_markdown,
    )
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope_document)
    print(f"Recon Plan: {len(plan.targets)} targets, {len(tasks)} tasks")

    # --- Phase 3: Recon Execution ---
    print("\n=== Phase 3: Recon Execution ===")
    scan_id = f"scan_{uuid4().hex[:12]}"
    # in_scope_assets에서 첫 번째 URL 타겟을 scope_value로 사용
    scope_value = program_url
    for asset in scope_document.analysis.in_scope_assets:
        if asset.asset.startswith("http"):
            scope_value = asset.asset
            break

    db_path = args.db or Path(f"recon_{scan_id}.db")
    executor = ReconExecutor(
        scan_id=scan_id,
        scope_type="url",
        scope_value=scope_value,
        db_path=db_path,
        ffuf_wordlist=args.ffuf_wordlist,
        login_email=args.login_email,
        login_password=args.login_password,
        login_path=args.login_path,
        proxy=args.proxy,
    )
    executor.run(tasks)
    print(f"Recon 완료: DB={db_path}, scan_id={scan_id}")

    # DB 상태 확인
    ep_count = executor.conn.execute(
        "SELECT count(*) FROM endpoints"
    ).fetchone()[0]
    sess_count = executor.conn.execute(
        "SELECT count(*) FROM sessions"
    ).fetchone()[0]
    print(f"  endpoints: {ep_count}개, sessions: {sess_count}개")

    if ep_count == 0:
        print("엔드포인트가 발견되지 않았습니다. Attack을 건너뜁니다.")
        executor.conn.close()
        return 0

    # --- Phase 4: Attack -> Validate -> Report ---
    print("\n=== Phase 4: Attack -> Validate -> Report ===")
    coordinator = AttackCoordinator(
        agent=main_agent,
        conn=executor.conn,
        scope_dir=program_dir,
        report_dir=args.report_dir,
    )
    confirmed = coordinator.run(scan_id)

    # --- 결과 출력 ---
    print(f"\n=== 스캔 완료 ===")
    print(f"Confirmed 취약점: {len(confirmed)}개")
    for fid in confirmed:
        report_path = args.report_dir / f"{fid}_report.md"
        print(f"  - {fid}")
        if report_path.exists():
            print(f"    보고서: {report_path}")

    executor.conn.close()
    return 0


def _collect_scope(
    *,
    program_url: str,
    args: argparse.Namespace,
    coordinator: ScopeCoordinator,
    main_agent: CodexMainAgent,
):
    return coordinator.collect(
        program_url,
        main_agent=main_agent,
        fallback_reader=PlaywrightProgramPageReader(
            timeout_seconds=args.page_timeout
        ),
        approved_by=args.approved_by or getpass.getuser(),
        review=_review_scope_draft,
    )


if __name__ == "__main__":
    raise SystemExit(main())
