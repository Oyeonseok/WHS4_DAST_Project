"""Batch the complete Recon coverage ledger through native Attack Agents."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from aidast.attack.coverage import (
    claim_coverage_batch,
    coverage_status,
    ensure_coverage_manifest,
    reconcile_coverage_batch,
    requeue_credential_blocked_coverage,
    release_unattempted_coverage,
    resolve_abandoned_attack_leads,
    resolve_interrupted_stage_leads,
    transition_coverage,
)
from aidast.attack.graph import graph_context_for_endpoint, synchronize_attack_graph
from aidast.attack.online_chaining import refresh_online_chain_leads
from aidast.attack.work_queue import (
    mark_claimed_leads,
    reconcile_lead_queue,
    refresh_lead_queue,
    select_dual_queue,
)
from aidast.attack.preconditions import resolve_attack_preconditions
from aidast.attack.template_loader import template_ids_for_skill
from aidast.attack.db_cli import (
    commit_attempt, transition_task as transition_attack_task,
)
from aidast.attack.request_cli import RequestGuardError, guarded_request
from aidast.orchestration.attack import (
    AttackBatchFailure,
    AttackCoordinator,
    AttackCoordinatorError,
    AttackUnresolvedLeadFailure,
)
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run, transition_task


@dataclass(frozen=True)
class ExhaustiveAttackResult:
    scan_id: str
    database: str
    batches: int
    stage_run_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    coverage: dict[str, Any]
    attack_agent_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExhaustiveAttackCoordinator:
    """Execute every DB-derived coverage item in bounded native-agent batches."""

    def __init__(
        self, *, agent: Any, db_path: Path, scope_path: Path, policy_path: Path,
        batch_size: int = 10, max_batches: int = 100, retry_limit: int = 3,
    ) -> None:
        self.agent = agent
        self.db_path = Path(db_path).expanduser().resolve()
        self.scope_path = Path(scope_path).expanduser().resolve()
        self.policy_path = Path(policy_path).expanduser().resolve()
        if not 1 <= batch_size <= 50:
            raise ValueError("batch size must be between 1 and 50")
        if not 1 <= max_batches <= 1000:
            raise ValueError("max batches must be between 1 and 1000")
        if not 1 <= retry_limit <= 10:
            raise ValueError("retry limit must be between 1 and 10")
        self.batch_size = batch_size
        self.max_batches = max_batches
        self.retry_limit = retry_limit
        self._agent_ids: list[str] = []

    def run(self, scan_id: str) -> ExhaustiveAttackResult:
        if not self.db_path.is_file() or not self.scope_path.is_file() or not self.policy_path.is_file():
            raise ValueError("exhaustive Attack requires Pipeline.db, Scope.md, and TargetPolicy.json")
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            resolve_abandoned_attack_leads(conn, scan_id)
        manifest = ensure_coverage_manifest(self.db_path, scan_id)
        if not manifest.total:
            raise ValueError(
                "Recon DB has no executable black-box hypotheses or explicit "
                "source-import coverage annotations"
            )
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            synchronize_attack_graph(
                conn, scan_id, trigger_kind="coverage.manifest.ready",
            )
            refresh_online_chain_leads(conn, scan_id)
            synchronize_attack_graph(
                conn, scan_id, trigger_kind="online.chains.ready",
            )
        stages: list[str] = []
        for _batch_no in range(1, self.max_batches + 1):
            current = coverage_status(self.db_path, scan_id)
            if current.unfinished == 0:
                break
            stage_run_id, tasks = self._start_batch(scan_id)
            if not tasks:
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    after_preflight = coverage_status(self.db_path, scan_id)
                    if after_preflight.unfinished == 0:
                        finish_stage_run(conn, stage_run_id, status="completed")
                        stages.append(stage_run_id)
                        break
                    finish_stage_run(conn, stage_run_id, status="failed",
                                     error_message="unfinished coverage items are not schedulable")
                raise AttackCoordinatorError(
                    "unfinished coverage items remain but none are schedulable"
                )
            stages.append(stage_run_id)
            tasks = self._execute_deterministic_engineio(
                scan_id=scan_id, stage_run_id=stage_run_id, tasks=tasks,
            )
            if not tasks:
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    reconcile_coverage_batch(
                        conn, stage_run_id=stage_run_id,
                        retry_limit=self.retry_limit,
                    )
                    reconcile_lead_queue(
                        conn, scan_id, stage_run_id=stage_run_id,
                    )
                    finish_stage_run(conn, stage_run_id, status="completed")
                    synchronize_attack_graph(
                        conn, scan_id, stage_run_id=stage_run_id,
                        trigger_kind="deterministic.batch.completed",
                    )
                    refresh_online_chain_leads(
                        conn, scan_id, stage_run_id=stage_run_id,
                    )
                    synchronize_attack_graph(
                        conn, scan_id, stage_run_id=stage_run_id,
                        trigger_kind="online.chains.changed",
                    )
                continue
            selected_skills = tuple(dict.fromkeys(task["skill_name"] for task in tasks))
            reasons = {
                skill: ("exhaustive Recon DB coverage item",)
                for skill in selected_skills
            }
            existing_findings, existing_attempts = self._existing(scan_id)
            try:
                result = self.agent.run_attack_orchestrator(
                    scan_id=scan_id,
                    db_path=self.db_path,
                    scope_path=self.scope_path,
                    policy_path=self.policy_path,
                    stage_run_id=stage_run_id,
                    attack_tasks=tasks,
                    selected_skill_names=selected_skills,
                    selection_reasons=reasons,
                )
                verifier = AttackCoordinator(
                    agent=self.agent, db_path=self.db_path,
                    scope_path=self.scope_path, policy_path=self.policy_path,
                )
                verifier._verify_result(
                    result, scan_id=scan_id, stage_run_id=stage_run_id,
                    existing_findings=existing_findings,
                    existing_attempts=existing_attempts,
                )
                self._agent_ids.extend(result.attack_agent_ids)
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    reconcile_coverage_batch(
                        conn, stage_run_id=stage_run_id,
                        retry_limit=self.retry_limit,
                    )
                    reconcile_lead_queue(
                        conn, scan_id, stage_run_id=stage_run_id,
                    )
                    finish_stage_run(conn, stage_run_id, status="completed")
                    synchronize_attack_graph(
                        conn, scan_id, stage_run_id=stage_run_id,
                        trigger_kind="agent.batch.completed",
                    )
                    refresh_online_chain_leads(
                        conn, scan_id, stage_run_id=stage_run_id,
                    )
                    synchronize_attack_graph(
                        conn, scan_id, stage_run_id=stage_run_id,
                        trigger_kind="online.chains.changed",
                    )
            # A bounded native batch may legitimately fail as a whole after
            # every task has already persisted a terminal or retryable
            # disposition (for example, an OOB proof prohibited by policy).
            # Reconcile that batch and continue with unrelated coverage.  A
            # stopped read-only probes remain unknown in the HTTP ledger and
            # terminal errors in coverage. User/process interruptions and
            # completion integrity errors still propagate after lease recovery.
            except AttackCoordinatorError as exc:
                can_continue = self._recover_failed_batch(stage_run_id, exc)
                if isinstance(exc, AttackBatchFailure) and can_continue:
                    continue
                raise
            except BaseException as exc:
                can_continue = self._recover_failed_batch(stage_run_id, exc)
                if getattr(exc, "failure_code", None) in {
                    "model_policy_refusal", "model_capacity", "timeout",
                } and can_continue:
                    continue
                raise
        return self._finish_result(scan_id, stages)

    @staticmethod
    def _with_query(url: str, **values: str) -> str:
        parsed = urlsplit(url)
        pairs = [
            (name, value) for name, value in parse_qsl(
                parsed.query, keep_blank_values=True,
            ) if name not in values
        ]
        pairs.extend(values.items())
        return urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path or "/",
            urlencode(pairs), "",
        ))

    def _observed_engineio_version(self, endpoint_id: str) -> str | None:
        """Return one Recon-observed polling protocol version for this route."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT origin_id,normalized_path FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if row is None:
                return None
            urls = [
                str(item[0]) for item in conn.execute(
                    """SELECT h.url FROM http_transactions h
                       JOIN endpoints e ON e.endpoint_id=h.endpoint_id
                       WHERE e.origin_id=? AND e.normalized_path=?
                       ORDER BY h.captured_at DESC LIMIT 128""",
                    row,
                )
            ]
        versions = {
            value
            for url in urls
            for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            if name.casefold() == "eio" and value in {"3", "4"}
        }
        return next(iter(versions)) if len(versions) == 1 else None

    def _observed_engineio_base_url(self, endpoint_id: str) -> str | None:
        """Preserve the exact observed route spelling, including trailing slash."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT origin_id,normalized_path FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if row is None:
                return None
            urls = [
                str(item[0]) for item in conn.execute(
                    """SELECT h.url FROM http_transactions h
                       JOIN endpoints e ON e.endpoint_id=h.endpoint_id
                       WHERE e.origin_id=? AND e.normalized_path=?
                       ORDER BY h.captured_at DESC LIMIT 128""",
                    row,
                )
            ]
        for url in urls:
            parsed = urlsplit(url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if query.get("EIO") in {"3", "4"} and query.get("transport") == "polling":
                return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        return None

    @staticmethod
    def _engineio_task(task: dict[str, Any]) -> bool:
        return (
            task.get("skill_name") == "hunt-websocket"
            and str(task.get("normalized_path") or "").casefold().rstrip("/")
            .endswith("/socket.io")
            and str(task.get("vuln_class") or "") == "websocket"
            and str(task.get("injection_location") or "") == "query"
            and str(task.get("parameter_name") or "").casefold()
            in {"eio", "transport", "t"}
            and str(task.get("method") or "").upper() in {"GET", "POST"}
        )

    def _execute_deterministic_engineio(
        self, *, scan_id: str, stage_run_id: str,
        tasks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Execute the safe Engine.IO session-binding contract without a model.

        The OPEN sid is transient and is cryptographically bound by the request
        helper to the following root CONNECT request. Only its hash reaches the
        durable request ledger. A forged sid rejection is the negative security
        control; a successful OPEN or CONNECT alone is never a finding.
        """
        remaining: list[dict[str, Any]] = []
        for task in tasks:
            if not self._engineio_task(task):
                remaining.append(task)
                continue
            version = self._observed_engineio_version(str(task["endpoint_id"]))
            if version is None:
                remaining.append(task)
                continue
            task_id = str(task["task_id"])
            endpoint_id = str(task["endpoint_id"])
            method = str(task["method"]).upper()
            base_url = self._observed_engineio_base_url(endpoint_id) or (
                str(task["origin_url"]).rstrip("/")
                + "/" + str(task["normalized_path"]).lstrip("/")
            )
            marker = hashlib.sha256(task_id.encode()).hexdigest()[:12]
            opened_url = self._with_query(
                base_url, EIO=version, transport="polling", t=f"aidast-{marker}",
            )
            fake_sid = f"aidast-invalid-{marker}"
            transition_attack_task(
                self.db_path, scan_id, stage_run_id, task_id, "running",
            )
            try:
                with tempfile.TemporaryDirectory(prefix="aidast-engineio-") as temporary:
                    payload_path = Path(temporary) / "request.json"

                    def send(payload: dict[str, Any]) -> dict[str, Any]:
                        payload_path.write_text(
                            json.dumps(payload, ensure_ascii=False), encoding="utf-8",
                        )
                        return guarded_request(
                            self.db_path, scan_id=scan_id,
                            stage_run_id=stage_run_id, task_id=task_id,
                            policy_path=self.policy_path, payload_path=payload_path,
                        )

                    opened = send({
                        "method": "GET", "url": opened_url,
                        "captures": [{
                            "name": "engineio_sid",
                            "source": "engineio_open_json", "path": ["sid"],
                        }],
                        "assertions": [{
                            "name": "engineio-open", "kind": "body_contains",
                            "expected": '"sid"', "terminal": True,
                        }],
                    })
                    sid = str(opened["captures"]["engineio_sid"])
                    if method == "POST":
                        connected_url = self._with_query(
                            opened_url, sid=sid, t=f"aidast-{marker}-connect",
                        )
                        send({
                            "method": "POST", "url": connected_url,
                            "headers": {
                                "Content-Type": "text/plain;charset=UTF-8",
                            },
                            "body": "40", "risk_class": "application_mutation",
                            "bindings": [{
                                "name": "engineio_sid",
                                "source_request_id": opened["request_id"],
                                "capture_name": "engineio_sid", "value": sid,
                                "target_kind": "query_parameter",
                                "target_path": ["sid"],
                            }],
                            "assertions": [{
                                "name": "root-connect-accepted",
                                "kind": "body_contains", "expected": "ok",
                                "terminal": True,
                            }],
                        })
                    rejected_url = self._with_query(
                        opened_url, sid=fake_sid, t=f"aidast-{marker}-reject",
                    )
                    rejected = send({
                        "method": method, "url": rejected_url,
                        **({
                            "headers": {
                                "Content-Type": "text/plain;charset=UTF-8",
                            },
                            "body": "40", "risk_class": "application_mutation",
                        } if method == "POST" else {}),
                        "assertions": [
                            {
                                "name": "unknown-session-status",
                                "kind": "status_equals", "expected": 400,
                                "terminal": True,
                            },
                            {
                                "name": "unknown-session-body",
                                "kind": "body_contains",
                                "expected": "Session ID unknown", "terminal": True,
                            },
                        ],
                    })
                    negative = (
                        rejected["status"] == 400
                        and all(item["passed"] for item in rejected["assertions"])
                    )
                    attempt_path = Path(temporary) / "attempt.json"
                    attempt_path.write_text(json.dumps({
                        "task_id": task_id, "endpoint_id": endpoint_id,
                        "skill_name": "hunt-websocket",
                        "request_fingerprint": rejected["request_fingerprint"],
                        "method": method, "url": rejected["url"],
                        "identity_role": "unauthenticated",
                        "payload_variant": (
                            "engineio-session-binding-"
                            + str(task["parameter_name"]).casefold()
                        ),
                        "response_status": rejected["status"],
                        "response_signature": hashlib.sha256(
                            rejected["response_body"].encode("utf-8")
                        ).hexdigest(),
                        "outcome": "negative" if negative else "inconclusive",
                    }, ensure_ascii=False), encoding="utf-8")
                    commit_attempt(self.db_path, scan_id, attempt_path)
                transition_attack_task(
                    self.db_path, scan_id, stage_run_id, task_id, "completed",
                )
            except Exception as exc:
                controlled_guard_failure = isinstance(exc, RequestGuardError)
                reason = (
                    "[evidence] deterministic Engine.IO session-binding probe "
                    "could not complete: "
                    + (
                        str(exc)[:300]
                        if controlled_guard_failure
                        else f"internal {type(exc).__name__}"
                    )
                )
                transition_attack_task(
                    self.db_path, scan_id, stage_run_id, task_id,
                    (
                        "skipped"
                        if controlled_guard_failure
                        and "outcome is unknown" not in str(exc)
                        else "failed"
                    ),
                    reason,
                )
        return remaining

    def _recover_failed_batch(
        self, stage_run_id: str, exc: BaseException,
    ) -> bool:
        """Persist evidence, close the batch, and report safe continuation.

        A native ``FAILED`` envelope can be the aggregate representation of a
        bounded task outcome, such as one request deadline.  Once every task
        and request has a durable disposition, that batch completed its
        orchestration responsibility even though an individual task failed.
        Keep the task/coverage failure visible and reserve ``stage.failed`` for
        a batch whose execution or completion contract is actually incomplete.
        """
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            policy_refusal = getattr(exc, "failure_code", None) == "model_policy_refusal"
            model_capacity = getattr(exc, "failure_code", None) == "model_capacity"
            model_timeout = getattr(exc, "failure_code", None) == "timeout"
            unresolved_lead_failure = isinstance(exc, AttackUnresolvedLeadFailure)
            unresolved_attempt_ids = tuple(
                getattr(exc, "unresolved_attempt_ids", ())
            )
            if model_capacity or model_timeout:
                task_rows = conn.execute(
                    """SELECT task_id,status FROM attack_tasks
                       WHERE stage_run_id=? AND status IN ('pending','running')""",
                    (stage_run_id,),
                ).fetchall()
                reason = (
                    "Attack model capacity was temporarily unavailable; "
                    if model_capacity else
                    "Attack model stopped after the bounded no-progress deadline; "
                ) + (
                    "retry this coverage item in a fresh bounded batch."
                )
                for task in task_rows:
                    transition_task(
                        conn, task["task_id"], status="cancelled",
                        error_message=reason,
                    )
                release_unattempted_coverage(
                    conn, stage_run_id=stage_run_id, reason=reason,
                )
                resolve_interrupted_stage_leads(
                    conn, stage_run_id=stage_run_id,
                    reason=(
                        "bounded Attack model invocation ended before this lead "
                        "was promoted; fresh coverage retry must reproduce it"
                    ),
                )
                if model_capacity:
                    activate_fallback = getattr(
                        self.agent, "activate_attack_fallback_model", None,
                    )
                    if callable(activate_fallback):
                        activate_fallback()
            if unresolved_lead_failure and unresolved_attempt_ids:
                placeholders = ",".join("?" for _ in unresolved_attempt_ids)
                lead_coverage = conn.execute(
                    f"""SELECT DISTINCT c.coverage_id,c.attempt_count,c.last_task_id
                        FROM attack_attempts a
                        JOIN attack_tasks t ON t.task_id=a.task_id
                        JOIN attack_coverage_items c
                          ON c.last_task_id=t.task_id
                         AND c.last_stage_run_id=t.stage_run_id
                        WHERE t.stage_run_id=? AND c.status='running'
                          AND a.attempt_id IN ({placeholders})
                          AND a.outcome='lead' AND a.finding_id IS NULL
                          AND a.resolved_at IS NULL""",
                    (stage_run_id, *unresolved_attempt_ids),
                ).fetchall()
                reason = (
                    "Attack batch returned before resolving a provisional lead; "
                    "fresh coverage retry must reproduce or reject it."
                )
                resolve_interrupted_stage_leads(
                    conn, stage_run_id=stage_run_id, reason=reason,
                )
                task_rows = conn.execute(
                    """SELECT task_id,status FROM attack_tasks
                       WHERE stage_run_id=? AND status IN ('pending','running')""",
                    (stage_run_id,),
                ).fetchall()
                for task in task_rows:
                    transition_task(
                        conn, task["task_id"], status="cancelled",
                        error_message=reason,
                    )
                for coverage in lead_coverage:
                    terminal = coverage["attempt_count"] >= self.retry_limit
                    transition_coverage(
                        conn, coverage["coverage_id"],
                        "error_terminal" if terminal else "error_retryable",
                        (
                            "retry limit reached after unresolved provisional lead"
                            if terminal else reason
                        ),
                        stage_run_id=stage_run_id,
                        task_id=coverage["last_task_id"],
                    )
            if policy_refusal:
                open_leads = conn.execute(
                    """SELECT COUNT(*) FROM attack_attempts a
                       JOIN attack_tasks t ON t.task_id=a.task_id
                       WHERE t.stage_run_id=? AND a.outcome='lead'
                         AND a.finding_id IS NULL AND a.resolved_at IS NULL""",
                    (stage_run_id,),
                ).fetchone()[0]
                unknown_requests = conn.execute(
                    """SELECT COUNT(*) FROM attack_http_requests
                       WHERE stage_run_id=? AND status IN
                         ('reserved','running','outcome_unknown')""",
                    (stage_run_id,),
                ).fetchone()[0]
                if not open_leads and not unknown_requests:
                    task_rows = conn.execute(
                        """SELECT task_id,status FROM attack_tasks
                           WHERE stage_run_id=? AND status IN ('pending','running')""",
                        (stage_run_id,),
                    ).fetchall()
                    isolate_batch = len(task_rows) > 1
                    reason = (
                        "Attack model policy refused a multi-task batch before producing "
                        "HTTP evidence; retry each task independently."
                        if isolate_batch else
                        "Attack model policy refused this bounded task; no HTTP request "
                        "or unresolved lead was produced, so the task was not tested."
                    )
                    for task in task_rows:
                        transition_task(
                            conn, task["task_id"],
                            status=(
                                "cancelled" if isolate_batch or task["status"] == "running"
                                else "skipped"
                            ),
                            error_message=reason,
                        )
                    if not isolate_batch:
                        coverage_rows = conn.execute(
                            """SELECT coverage_id,last_task_id FROM attack_coverage_items
                               WHERE last_stage_run_id=? AND status='running'""",
                            (stage_run_id,),
                        ).fetchall()
                        for coverage in coverage_rows:
                            transition_coverage(
                                conn, coverage["coverage_id"], "unsupported", reason,
                                stage_run_id=stage_run_id,
                                task_id=coverage["last_task_id"],
                            )
            # Preserve per-task terminal evidence even when the native
            # orchestrator rejects the batch as a whole (for example,
            # one denied authorization among otherwise completed tasks).
            reconcile_coverage_batch(
                conn, stage_run_id=stage_run_id,
                retry_limit=self.retry_limit,
            )
            open_leads = conn.execute(
                """SELECT COUNT(*) FROM attack_attempts a
                   JOIN attack_tasks t ON t.task_id=a.task_id
                   WHERE t.stage_run_id=? AND a.outcome='lead'
                     AND a.finding_id IS NULL AND a.resolved_at IS NULL""",
                (stage_run_id,),
            ).fetchone()[0]
            if unresolved_attempt_ids:
                placeholders = ",".join("?" for _ in unresolved_attempt_ids)
                open_leads += conn.execute(
                    f"""SELECT COUNT(*) FROM attack_attempts
                        WHERE attempt_id IN ({placeholders}) AND outcome='lead'
                          AND finding_id IS NULL AND resolved_at IS NULL""",
                    unresolved_attempt_ids,
                ).fetchone()[0]
            stopped_probes = self._record_stopped_probes(conn, stage_run_id) if isinstance(exc, AttackBatchFailure) else set()
            unknown_requests = sum(row[0] not in stopped_probes for row in conn.execute(
                """SELECT request_id FROM attack_http_requests
                   WHERE stage_run_id=? AND status IN ('reserved','running','outcome_unknown')""",
                (stage_run_id,),
            ))
            incomplete_tasks = conn.execute(
                """SELECT COUNT(*) FROM attack_tasks
                   WHERE stage_run_id=? AND status IN ('pending','running')""",
                (stage_run_id,),
            ).fetchone()[0]
            can_continue = not (open_leads or unknown_requests or incomplete_tasks)
            recoverable = (
                isinstance(exc, AttackBatchFailure) or policy_refusal
                or model_capacity or model_timeout
            ) and can_continue
            row = conn.execute(
                "SELECT status FROM stage_runs WHERE stage_run_id=?",
                (stage_run_id,),
            ).fetchone()
            if row is not None and row[0] == "running":
                finish_stage_run(
                    conn, stage_run_id,
                    status="completed" if recoverable else "failed",
                    error_message=None if recoverable else str(exc),
                    allow_terminal_task_errors=recoverable,
                )
            scan_id = conn.execute(
                "SELECT scan_id FROM stage_runs WHERE stage_run_id=?",
                (stage_run_id,),
            ).fetchone()[0]
            reconcile_lead_queue(conn, scan_id, stage_run_id=stage_run_id)
            synchronize_attack_graph(
                conn, scan_id, stage_run_id=stage_run_id,
                trigger_kind="agent.batch.recovered",
            )
            refresh_online_chain_leads(
                conn, scan_id, stage_run_id=stage_run_id,
            )
            synchronize_attack_graph(
                conn, scan_id, stage_run_id=stage_run_id,
                trigger_kind="online.chains.changed",
            )
            return can_continue

    @staticmethod
    def _record_stopped_probes(conn: sqlite3.Connection, stage_run_id: str) -> set[str]:
        """Close failed read-only coverage without relabeling unknown HTTP evidence."""
        rows = conn.execute("""SELECT c.coverage_id,c.status,r.request_id,r.error_message,r.task_id
            FROM attack_http_requests r JOIN attack_tasks t
              ON t.task_id=r.task_id AND t.stage_run_id=r.stage_run_id AND t.scan_id=r.scan_id
            JOIN attack_coverage_items c ON c.last_task_id=t.task_id
              AND c.last_stage_run_id=t.stage_run_id AND c.scan_id=t.scan_id
            WHERE r.stage_run_id=? AND r.status='outcome_unknown'
              AND r.finished_at IS NOT NULL AND t.status='failed'
              AND r.risk_class='http_probe' AND r.method IN ('GET','HEAD','OPTIONS')
              AND c.status IN ('error_retryable','error_terminal')
            ORDER BY r.rowid""", (stage_run_id,)).fetchall()
        for row in rows:
            reason = f"Stopped HTTP probe {row['request_id']} has an unknown response ({row['error_message'] or 'transport failure'}); not tested, automatic retry disabled."
            current = conn.execute('SELECT status FROM attack_coverage_items WHERE coverage_id=?', (row['coverage_id'],)).fetchone()[0]
            if current == 'error_retryable':
                transition_coverage(conn, row['coverage_id'], 'error_terminal', reason,
                    stage_run_id=stage_run_id, task_id=row['task_id'])
            elif current == 'error_terminal':
                conn.execute('UPDATE attack_coverage_items SET disposition_reason=?,updated_at=CURRENT_TIMESTAMP WHERE coverage_id=?',
                    (reason, row['coverage_id']))
        return {row['request_id'] for row in rows}

    def _finish_result(
        self, scan_id: str, stages: list[str],
    ) -> ExhaustiveAttackResult:
        final = coverage_status(self.db_path, scan_id)
        if final.unfinished:
            raise AttackCoordinatorError(
                f"exhaustive Attack stopped with {final.unfinished} unfinished coverage item(s)"
            )
        with closing(sqlite3.connect(self.db_path)) as conn:
            findings = tuple(row[0] for row in conn.execute(
                "SELECT finding_id FROM findings WHERE scan_id=? ORDER BY created_at,finding_id",
                (scan_id,),
            ))
        return ExhaustiveAttackResult(
            scan_id=scan_id, database=str(self.db_path), batches=len(stages),
            stage_run_ids=tuple(stages), finding_ids=findings,
            coverage=final.to_dict(),
            attack_agent_ids=tuple(self._agent_ids),
        )

    def _start_batch(self, scan_id: str) -> tuple[str, list[dict[str, Any]]]:
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="attack")
            resolve_attack_preconditions(conn, scan_id)
            requeue_credential_blocked_coverage(conn, scan_id)
            synchronize_attack_graph(
                conn, scan_id, stage_run_id=stage_run_id,
                trigger_kind="batch.preflight",
            )
            refresh_online_chain_leads(
                conn, scan_id, stage_run_id=stage_run_id,
            )
            synchronize_attack_graph(
                conn, scan_id, stage_run_id=stage_run_id,
                trigger_kind="online.chains.preflight",
            )
            refresh_lead_queue(conn, scan_id)
            queue_selection = select_dual_queue(
                conn, scan_id, batch_size=self.batch_size,
            )
            claimed = claim_coverage_batch(
                conn, scan_id=scan_id, stage_run_id=stage_run_id,
                batch_size=self.batch_size, max_attempts=self.retry_limit,
                preferred_coverage_ids=queue_selection.preferred_coverage_ids,
            )
            mark_claimed_leads(
                conn, scan_id=scan_id, stage_run_id=stage_run_id,
                tasks=claimed, selection=queue_selection,
            )
            synchronize_attack_graph(
                conn, scan_id, stage_run_id=stage_run_id,
                trigger_kind="batch.claimed",
            )
            tasks = []
            for item in claimed:
                annotation_category = str(
                    item.get("source_context", {})
                    .get("active_annotation", {})
                    .get("category", "")
                )
                hypothesis_reason = (
                    f"black-box Recon hypothesis: {item['vuln_class']}"
                    if annotation_category == "attack_hypothesis"
                    else f"explicit source-import annotation: {item['vuln_class']}"
                )
                tasks.append({
                    **item,
                    "selection_reasons": [
                        "exhaustive Recon DB coverage item",
                        hypothesis_reason,
                    ],
                    "template_ids": list(template_ids_for_skill(item["skill_name"])),
                    "lead_queue_ids": [row[0] for row in conn.execute(
                        """SELECT lead_queue_id FROM attack_lead_queue
                           WHERE scan_id=? AND stage_run_id=? AND task_id=?
                           ORDER BY priority DESC,lead_queue_id""",
                        (scan_id, stage_run_id, item["task_id"]),
                    )],
                    "attack_graph_context": graph_context_for_endpoint(
                        conn, scan_id, str(item["endpoint_id"]),
                    ),
                })
            return stage_run_id, tasks

    def _existing(self, scan_id: str) -> tuple[set[str], set[str]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            findings = {
                row[0] for row in conn.execute(
                    "SELECT finding_id FROM findings WHERE scan_id=?", (scan_id,),
                )
            }
            attempts = {
                row[0] for row in conn.execute(
                    "SELECT attempt_id FROM attack_attempts WHERE scan_id=?", (scan_id,),
                )
            }
        return findings, attempts
