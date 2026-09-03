from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Sequence

from aidast.agents.main import CodexMainAgent, MainAgentError
from aidast.auth.codex import CodexAuth, CodexAuthError
from aidast.orchestration.policy import ReconPolicyCoordinator
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.policy import PolicyError, load_policy
from aidast.recon.policy_plan import PolicyExecutionPlan, build_execution_plan
from aidast.recon.policy_runner import PolicyToolRunner, supported_tool_ids
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

    policy_compile = commands.add_parser(
        "policy-compile",
        help="compile an approved Scope.md into recon-policy.json schema 1.0",
    )
    policy_compile.add_argument(
        "scope",
        type=Path,
        help="path to the approved Scope.md produced by the scope pipeline",
    )
    policy_compile.add_argument(
        "--output",
        type=Path,
        help="output path; defaults to recon-policy.json beside Scope.md",
    )
    policy_compile.add_argument(
        "--codex-timeout",
        type=int,
        default=300,
        help="maximum Codex policy compilation time in seconds",
    )

    policy_run = commands.add_parser(
        "policy-run",
        help="run explicitly selected recon tools through the policy mitmproxy",
    )
    policy_run.add_argument("policy", type=Path, help="recon-policy.json path")
    policy_run.add_argument(
        "target",
        nargs="?",
        help="optional HTTP(S) target; omitted means every concrete policy target",
    )
    policy_run.add_argument(
        "--target",
        action="append",
        default=[],
        dest="extra_targets",
        help="additional policy-approved target; repeat for multiple targets",
    )
    policy_run.add_argument(
        "--tool",
        action="append",
        dest="tools",
        help=(
            "canonical tool ID to execute; repeat for multiple tools; omitted "
            "means every executable registered tool in the policy"
        ),
    )
    policy_run.add_argument(
        "--db",
        type=Path,
        default=Path("recon-policy.sqlite3"),
        help="SQLite audit database path",
    )
    policy_run.add_argument(
        "--flow-log",
        type=Path,
        default=Path("recon-policy-flows.jsonl"),
        help="temporary redacted mitmproxy JSONL log path",
    )
    policy_run.add_argument(
        "--proxy-port", type=int, default=18080, help="local mitmdump listen port"
    )
    policy_run.add_argument(
        "--header",
        action="append",
        default=[],
        help="required target header in NAME:VALUE form",
    )
    policy_run.add_argument(
        "--runtime-input",
        action="append",
        default=[],
        help="resolved policy input in ID=VALUE form; values are not persisted",
    )
    policy_run.add_argument(
        "--wordlist", type=Path, help="wordlist required by the ffuf adapter"
    )
    policy_run.add_argument(
        "--plan-only",
        action="store_true",
        help="print the policy-derived execution plan without network activity",
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
        if args.command == "policy-compile":
            return _run_policy_compile(args)
        if args.command == "policy-run":
            return _run_policy_tools(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        CoordinatorError,
        CodexAuthError,
        MainAgentError,
        ProgramPageError,
        ReconCoordinatorError,
        ScopePathError,
        PolicyError,
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

    policy_path, policy = _compile_policy(
        scope_path=program_dir / "Scope.md",
        policy_path=program_dir / "recon-policy.json",
        scope_markdown=scope_markdown,
        main_agent=main_agent,
    )
    print(
        f"Recon policy compiled: {policy_path} "
        f"(schema={policy.schema_version}, status={policy.policy_status.value})"
    )
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


def _parse_pairs(values: list[str], *, separator: str, label: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        key, found, item_value = value.partition(separator)
        if not found or not key.strip() or not item_value:
            raise PolicyError(f"invalid {label}: {value}")
        key = key.strip()
        if key.casefold() in {existing.casefold() for existing in parsed}:
            raise PolicyError(f"duplicate {label}: {key}")
        parsed[key] = item_value.strip()
    return parsed


def _run_policy_tools(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    headers = _parse_pairs(args.header, separator=":", label="header")
    runtime_inputs = _parse_pairs(
        args.runtime_input, separator="=", label="runtime input"
    )
    explicit_targets = ([args.target] if args.target else []) + args.extra_targets
    plan = build_execution_plan(
        policy,
        supported_tool_ids=supported_tool_ids(),
        requested_targets=explicit_targets or None,
        requested_tool_ids=args.tools,
    )
    _print_policy_plan(plan)
    if args.plan_only:
        return 0

    for target in plan.targets:
        runner = PolicyToolRunner(
            policy=policy,
            policy_path=args.policy,
            target=target,
            db_path=args.db,
            flow_log_path=args.flow_log,
            proxy_port=args.proxy_port,
            headers=headers,
            runtime_inputs=runtime_inputs,
            wordlist=args.wordlist,
        )
        try:
            results = runner.run(list(plan.tool_ids))
        finally:
            runner.close()
        for result in results:
            print(
                f"{target} -> {result.tool_id}: completed "
                f"(execution_id={result.execution_id}, exit_code={result.exit_code})"
            )
    print(f"Audit database: {args.db}")
    return 0


def _run_policy_compile(args: argparse.Namespace) -> int:
    scope_path = args.scope
    try:
        scope_markdown = scope_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"failed to read approved Scope.md: {exc}") from exc
    policy_path = args.output or scope_path.with_name("recon-policy.json")
    if policy_path.resolve() == scope_path.resolve():
        raise PolicyError("policy output must not overwrite Scope.md")
    policy_path, policy = _compile_policy(
        scope_path=scope_path,
        policy_path=policy_path,
        scope_markdown=scope_markdown,
        main_agent=CodexMainAgent(timeout_seconds=args.codex_timeout),
    )
    print(
        f"Recon policy compiled: {policy_path} "
        f"(schema={policy.schema_version}, status={policy.policy_status.value})"
    )
    return 0


def _compile_policy(
    *,
    scope_path: Path,
    policy_path: Path,
    scope_markdown: str,
    main_agent: CodexMainAgent,
):
    policy = ReconPolicyCoordinator(policy_path).compile(
        scope_path=scope_path,
        scope_markdown=scope_markdown,
        main_agent=main_agent,
    )
    return policy_path, policy


def _print_policy_plan(plan: PolicyExecutionPlan) -> None:
    print("Policy execution plan:")
    for target in plan.targets:
        print(f"  target: {target}")
    for tool_id in plan.tool_ids:
        print(f"  tool: {tool_id}")
    for item in plan.skipped_targets:
        print(f"  skipped target: {item.item_id} ({item.reason})")
    for item in plan.skipped_tools:
        print(f"  skipped tool: {item.item_id} ({item.reason})")


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
