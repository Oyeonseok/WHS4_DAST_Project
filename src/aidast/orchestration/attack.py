"""Plan endpoint hypotheses and execute bounded native Attack batches."""

from __future__ import annotations

import sqlite3
import os
from uuid import uuid4
from contextlib import closing
from pathlib import Path

from aidast.agents.main import CodexMainAgent
from aidast.attack.models import AttackStageResult
from aidast.attack.skill_selector import (
    available_attack_skill_names,
    select_relevant_attack_skills,
)
from aidast.attack.template_loader import template_ids_for_skill
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run


class AttackCoordinatorError(RuntimeError):
    """The shared DB or native Attack stage violated its handoff contract."""


class AttackBatchFailure(AttackCoordinatorError):
    """An identified native batch reported failure; durable tasks decide continuation."""


class AttackCoordinator:
    """Bridge completed Recon state to a native Codex Attack sub-agent."""

    def __init__(
        self,
        *,
        agent: CodexMainAgent,
        db_path: Path,
        scope_path: Path,
        policy_path: Path,
    ) -> None:
        self._agent = agent
        self._db_path = Path(db_path).expanduser().resolve()
        self._scope_path = Path(scope_path).expanduser().resolve()
        self._policy_path = Path(policy_path).expanduser().resolve()

    def run(self, scan_id: str) -> AttackStageResult:
        from aidast.attack.coverage_snapshot import attack_work_unfinished
        from aidast.attack.recon_hypotheses import plan_recon_attack
        from aidast.attack.coverage import ensure_coverage_manifest
        from aidast.orchestration.coverage_attack import ExhaustiveAttackCoordinator

        for path in (self._db_path, self._scope_path, self._policy_path):
            if not path.is_file():
                raise AttackCoordinatorError(f'Attack input not found: {path}')
        with closing(sqlite3.connect(self._db_path)) as conn:
            scan = conn.execute('SELECT status,finished_at FROM scans WHERE scan_id=?', (scan_id,)).fetchone()
            if scan is None or scan[0] != 'completed' or not scan[1]:
                raise AttackCoordinatorError('Attack requires a completed Recon scan')
            prior = conn.execute("""SELECT stage_run_id,status FROM stage_runs
                WHERE scan_id=? AND stage='attack' ORDER BY rowid DESC LIMIT 1""", (scan_id,)).fetchone()
            if prior and (prior[1] in {'pending', 'running'} or (prior[1] == 'completed' and not attack_work_unfinished(conn, scan_id))):
                raise AttackCoordinatorError(f'Attack stage already exists for this scan: {prior[0]} ({prior[1]})')
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            planning_stage = start_stage_run(conn, scan_id=scan_id, stage='attack')
        try:
            plan_recon_attack(self._db_path, scan_id, agent=self._agent,
                progress=lambda processed, total: self._planning_progress(scan_id, processed, total),
                stage_run_id=planning_stage,
                repair_progress=lambda processed, total, attempt, issues: self._planning_progress(
                    scan_id, processed, total, repair_attempt=attempt, issue_count=issues))
            manifest = ensure_coverage_manifest(self._db_path, scan_id)
        except BaseException as exc:
            with closing(sqlite3.connect(self._db_path)) as conn, conn:
                finish_stage_run(conn, planning_stage, status='failed', error_message=str(exc))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise AttackCoordinatorError(str(exc)) from exc
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            finish_stage_run(conn, planning_stage, status='completed')
        if not manifest.total:
            return AttackStageResult(status='COMPLETED', scan_id=scan_id,
                db_path=str(self._db_path), stage_run_id=planning_stage,
                summary='Every endpoint was reviewed; no evidence-grounded executable hypothesis was identified.')
        try:
            result = ExhaustiveAttackCoordinator(agent=self._agent, db_path=self._db_path,
                scope_path=self._scope_path, policy_path=self._policy_path, batch_size=8,
                max_batches=min(1000, max(100, ((manifest.total + 7) // 8) * 3))).run(scan_id)
        except BaseException as exc:
            with closing(sqlite3.connect(self._db_path)) as conn, conn:
                latest = conn.execute("SELECT stage_run_id,status FROM stage_runs WHERE scan_id=? AND stage='attack' ORDER BY rowid DESC LIMIT 1", (scan_id,)).fetchone()
                if latest is None or latest[1] != 'failed':
                    failed_stage = latest[0] if latest and latest[1] == 'running' else start_stage_run(conn, scan_id=scan_id, stage='attack')
                    finish_stage_run(conn, failed_stage, status='failed', error_message=str(exc))
            if isinstance(exc, (KeyboardInterrupt, SystemExit, AttackCoordinatorError)):
                raise
            raise AttackCoordinatorError(str(exc)) from exc
        completion_stage = result.stage_run_ids[-1] if result.stage_run_ids else planning_stage
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            latest = conn.execute("SELECT stage_run_id,status FROM stage_runs WHERE scan_id=? AND stage='attack' ORDER BY rowid DESC LIMIT 1", (scan_id,)).fetchone()
            if latest and latest[1] != 'completed':
                completion_stage = start_stage_run(conn, scan_id=scan_id, stage='attack')
                finish_stage_run(conn, completion_stage, status='completed')
        return AttackStageResult(status='COMPLETED', scan_id=scan_id,
            db_path=str(self._db_path), stage_run_id=completion_stage,
            finding_ids=list(result.finding_ids), attack_agent_ids=list(result.attack_agent_ids),
            summary=f"Endpoint hypothesis coverage: {result.coverage['total']} dispositions across {result.batches} batches; {result.coverage['by_status']}")

    @staticmethod
    def _planning_progress(scan_id: str, processed: int, total: int, *, repair_attempt: int | None = None, issue_count: int = 0) -> None:
        root = os.environ.get('AIDAST_RESULT_ROOT')
        if not root:
            return
        from aidast.web.projection import DashboardProjector
        DashboardProjector(Path(root)).record_event(scan_id, source_key=f'work:{uuid4().hex}',
            event_type='log.appended', payload={'stage': 'Attack', 'level': 'info',
                'message': 'Agent work', 'message_code': 'agent.work',
                'message_params': {'agent': 'attack', 'step': 'planning', 'state': 'progress',
                                   'processed': processed, 'endpoint_total': total,
                                   **({'repair_attempt': repair_attempt, 'repair_limit': 2,
                                       'validation_issue_count': issue_count} if repair_attempt is not None else {})}})

    def run_selected_skills(self, scan_id: str) -> AttackStageResult:
        """Legacy explicit Skill-batch entrypoint; normal scans use endpoint coverage."""
        if not self._db_path.is_file():
            raise AttackCoordinatorError(f"pipeline DB not found: {self._db_path}")
        if not self._scope_path.is_file():
            raise AttackCoordinatorError(f"approved Scope.md not found: {self._scope_path}")
        if not self._policy_path.is_file():
            raise AttackCoordinatorError(f"TargetPolicy.json not found: {self._policy_path}")

        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute("PRAGMA foreign_keys=ON")
            scan = conn.execute(
                "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if scan is None or str(scan[0]).casefold() != "completed" or not scan[1]:
                raise AttackCoordinatorError("Attack requires a completed Recon scan")
            prior = conn.execute(
                """SELECT stage_run_id,status FROM stage_runs
                   WHERE scan_id=? AND stage='attack'
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,),
            ).fetchone()
            if prior is not None and prior[1] in {"pending", "running", "completed"}:
                raise AttackCoordinatorError(
                    f"Attack stage already exists for this scan: {prior[0]} ({prior[1]})"
                )
            existing_findings = {
                row[0]
                for row in conn.execute(
                    "SELECT finding_id FROM findings WHERE scan_id=?", (scan_id,)
                )
            }
            existing_attempts = {
                row[0]
                for row in conn.execute(
                    "SELECT attempt_id FROM attack_attempts WHERE scan_id=?", (scan_id,)
                )
            }
            credential_references = [
                {"credential_reference_id": row[0], "label": row[1],
                 "identity_role": row[2]}
                for row in conn.execute(
                    """SELECT c.credential_reference_id,c.label,c.identity_role
                       FROM credential_references c JOIN sessions s ON s.session_id=c.session_id
                       JOIN origins o ON o.origin_id=s.origin_id
                       JOIN assets a ON a.asset_id=o.asset_id
                       WHERE c.scan_id=? AND a.scan_id=? AND s.auth_state='authenticated'
                       ORDER BY c.label""", (scan_id, scan_id),
                )
            ]
            stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="attack")
            selected_skills, selection_reasons = select_relevant_attack_skills(
                self._db_path, scan_id, available_attack_skill_names()
            )
            attack_tasks = []
            for skill_name in selected_skills:
                task_id = create_task(
                    conn,
                    stage_run_id=stage_run_id,
                    skill_name=skill_name,
                    payload={
                        "selection_reasons": list(selection_reasons[skill_name]),
                        "resume_from_stage_run_id": prior[0] if prior is not None else None,
                        "credential_references": credential_references,
                    },
                )
                attack_tasks.append({
                    "task_id": task_id,
                    "skill_name": skill_name,
                    "selection_reasons": list(selection_reasons[skill_name]),
                    "template_ids": list(template_ids_for_skill(skill_name)),
                    "credential_references": credential_references,
                })

        try:
            result = self._agent.run_attack_orchestrator(
                scan_id=scan_id,
                db_path=self._db_path,
                scope_path=self._scope_path,
                policy_path=self._policy_path,
                stage_run_id=stage_run_id,
                attack_tasks=attack_tasks,
                selected_skill_names=selected_skills,
                selection_reasons=selection_reasons,
            )
            self._verify_result(
                result,
                scan_id=scan_id,
                stage_run_id=stage_run_id,
                existing_findings=existing_findings,
                existing_attempts=existing_attempts,
            )
            with closing(sqlite3.connect(self._db_path)) as conn, conn:
                conn.execute("PRAGMA foreign_keys=ON")
                finish_stage_run(conn, stage_run_id, status="completed")
            return result
        except Exception as exc:
            try:
                with closing(sqlite3.connect(self._db_path)) as conn, conn:
                    conn.execute("PRAGMA foreign_keys=ON")
                    row = conn.execute(
                        "SELECT status FROM stage_runs WHERE stage_run_id=?",
                        (stage_run_id,),
                    ).fetchone()
                    if row is not None and row[0] == "running":
                        conn.execute(
                            """UPDATE attack_http_requests
                               SET status='outcome_unknown',
                                   finished_at=CAST(strftime('%s','now') AS REAL),
                                   error_message=COALESCE(error_message,'Attack stage failed')
                               WHERE stage_run_id=? AND status IN ('reserved','running')""",
                            (stage_run_id,),
                        )
                        finish_stage_run(
                            conn, stage_run_id, status="failed", error_message=str(exc)
                        )
            except sqlite3.Error:
                pass
            if isinstance(exc, AttackCoordinatorError):
                raise
            raise AttackCoordinatorError(str(exc)) from exc

    def _verify_result(
        self, result: AttackStageResult, *, scan_id: str, stage_run_id: str,
        existing_findings: set[str], existing_attempts: set[str],
    ) -> None:
        mismatches = []
        if result.stage != "ATTACK":
            mismatches.append("stage")
        if result.scan_id != scan_id:
            mismatches.append("scan_id")
        if result.stage_run_id != stage_run_id:
            mismatches.append("stage_run_id")
        if Path(result.db_path).resolve() != self._db_path:
            mismatches.append("db_path")
        if len(result.attack_agent_ids) != 1:
            mismatches.append("attack_agent_ids")
        if len(result.finding_ids) != len(set(result.finding_ids)):
            mismatches.append("duplicate_finding_ids")
        if mismatches:
            raise AttackCoordinatorError(
                "native Attack completion envelope mismatch: " + ",".join(mismatches)
            )

        if result.status == "FAILED":
            reason = result.summary.strip() or "no failure summary"
            raise AttackBatchFailure(f"native Attack Agent returned FAILED: {reason}")

        with closing(sqlite3.connect(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT finding_id FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
            attempt_rows = conn.execute(
                """SELECT attempt_id,outcome,finding_id,resolved_at
                   FROM attack_attempts WHERE scan_id=?""",
                (scan_id,),
            ).fetchall()
            task_rows = conn.execute(
                "SELECT task_id,status FROM attack_tasks WHERE stage_run_id=?",
                (stage_run_id,),
            ).fetchall()
            unknown_requests = conn.execute(
                """SELECT request_id FROM attack_http_requests
                   WHERE stage_run_id=? AND status IN ('reserved','running','outcome_unknown')""",
                (stage_run_id,),
            ).fetchall()
            reproduction_findings = {
                row[0] for row in conn.execute(
                    """SELECT s.finding_id FROM finding_reproduction_specs s
                    JOIN findings f ON f.finding_id=s.finding_id WHERE f.scan_id=?""",
                    (scan_id,),
                )
            }
        committed = {row[0] for row in rows}
        reported = set(result.finding_ids)
        newly_committed = committed - existing_findings
        if not newly_committed <= reported or not reported <= committed:
            raise AttackCoordinatorError(
                "Attack Agent completion does not match newly committed findings"
            )
        if not set(result.finding_ids) <= reproduction_findings:
            raise AttackCoordinatorError(
                "new Attack findings require atomic reproduction specs"
            )
        new_attempts = [row for row in attempt_rows if row[0] not in existing_attempts]
        # A failed or interrupted earlier stage may have persisted a useful
        # lead before it could either promote or close it.  That historical
        # evidence belongs to the coverage retry which owns the old task; it
        # must not make an otherwise self-contained later batch impossible to
        # finish.  The current agent is authoritative only for attempts created
        # after its stage snapshot.
        unresolved = [row[0] for row in new_attempts if row[1] == "lead"]
        if unresolved:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(unresolved)} unresolved lead(s)"
            )
        invalid_confirmed = [
            row[0] for row in new_attempts
            if row[1] == "confirmed" and (not row[2] or not row[3])
        ]
        if invalid_confirmed:
            raise AttackCoordinatorError("confirmed attempts must link to a finding")
        incomplete_tasks = [task_id for task_id, status in task_rows if status not in {"completed", "skipped"}]
        if incomplete_tasks:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(incomplete_tasks)} incomplete task(s)"
            )
        if unknown_requests:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(unknown_requests)} HTTP outcome(s) unknown"
            )
