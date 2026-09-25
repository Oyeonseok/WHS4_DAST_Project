"""Batch the complete Recon coverage ledger through native Attack Agents."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aidast.attack.coverage import (
    claim_coverage_batch,
    coverage_status,
    ensure_coverage_manifest,
    reconcile_coverage_batch,
)
from aidast.attack.template_loader import template_ids_for_skill
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run


@dataclass(frozen=True)
class ExhaustiveAttackResult:
    scan_id: str
    database: str
    batches: int
    stage_run_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    coverage: dict[str, Any]

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

    def run(self, scan_id: str) -> ExhaustiveAttackResult:
        if not self.db_path.is_file() or not self.scope_path.is_file() or not self.policy_path.is_file():
            raise ValueError("exhaustive Attack requires Pipeline.db, Scope.md, and TargetPolicy.json")
        manifest = ensure_coverage_manifest(self.db_path, scan_id)
        if not manifest.total:
            raise ValueError("Recon DB has no source vulnerability coverage annotations")
        stages: list[str] = []
        for _batch_no in range(1, self.max_batches + 1):
            current = coverage_status(self.db_path, scan_id)
            if current.unfinished == 0:
                break
            stage_run_id, tasks = self._start_batch(scan_id)
            if not tasks:
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    finish_stage_run(
                        conn, stage_run_id, status="failed",
                        error_message="unfinished coverage items are not schedulable",
                    )
                raise AttackCoordinatorError(
                    "unfinished coverage items remain but none are schedulable"
                )
            stages.append(stage_run_id)
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
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    reconcile_coverage_batch(
                        conn, stage_run_id=stage_run_id,
                        retry_limit=self.retry_limit,
                    )
                    finish_stage_run(conn, stage_run_id, status="completed")
            # Operator interrupts and process-level exits must not strand a
            # running stage or coverage lease. Persist recovery state first,
            # then re-raise the original BaseException.
            except BaseException as exc:
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    # Preserve per-task terminal evidence even when the native
                    # orchestrator rejects the batch as a whole (for example,
                    # one denied authorization among otherwise completed
                    # tasks).  The normal reconciler adopts findings,
                    # negatives, and explicit skips; only tasks without a
                    # terminal disposition remain retryable.
                    reconcile_coverage_batch(
                        conn, stage_run_id=stage_run_id,
                        retry_limit=self.retry_limit,
                    )
                    row = conn.execute(
                        "SELECT status FROM stage_runs WHERE stage_run_id=?",
                        (stage_run_id,),
                    ).fetchone()
                    if row is not None and row[0] == "running":
                        finish_stage_run(
                            conn, stage_run_id, status="failed",
                            error_message=str(exc),
                        )
                raise
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
        )

    def _start_batch(self, scan_id: str) -> tuple[str, list[dict[str, Any]]]:
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="attack")
            claimed = claim_coverage_batch(
                conn, scan_id=scan_id, stage_run_id=stage_run_id,
                batch_size=self.batch_size, max_attempts=self.retry_limit,
            )
            tasks = []
            for item in claimed:
                tasks.append({
                    **item,
                    "selection_reasons": [
                        "exhaustive Recon DB coverage item",
                        f"source vulnerability annotation: {item['vuln_class']}",
                    ],
                    "template_ids": list(template_ids_for_skill(item["skill_name"])),
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
