"""Inspect and resume a persisted post-Recon scan without repeating Recon."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aidast.pipeline.models import HandoffManifest
from aidast.pipeline.locations import scan_run_directory
from aidast.pipeline.model_settings import (
    MODEL_SETTINGS_FILE, ScanModelChoices, load_scan_model_choices, read_scan_model_choices,
)


_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class ResumePlan:
    scan_id: str
    scope_id: str
    stage: str
    stage_run_id: str | None
    database: Path
    scope_path: Path
    policy_path: Path
    targets: tuple[str, ...]
    models: ScanModelChoices = field(default_factory=ScanModelChoices.resolve)
    program_url: str | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resumable_validation_stage(
    conn: sqlite3.Connection, scan_id: str,
) -> str | None:
    """Return the failed Validation run that still owns unfinished cases."""
    tables = {
        str(row[0]) for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if "validation_cases" not in tables:
        return None
    rows = conn.execute(
        """SELECT DISTINCT v.latest_stage_run_id
           FROM validation_cases v
           JOIN stage_runs s ON s.stage_run_id=v.latest_stage_run_id
           WHERE v.scan_id=? AND v.processing_phase IN ('queued','interrupted')
             AND s.stage='validation' AND s.status='failed'
           ORDER BY v.latest_stage_run_id""",
        (scan_id,),
    ).fetchall()
    if len(rows) > 1:
        raise ValueError("scan has multiple failed Validation runs with resumable cases")
    return str(rows[0][0]) if rows else None


def inspect_resume(result_root: Path, scan_id: str) -> ResumePlan:
    """Validate the original approved handoff and select the first unfinished stage."""
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("invalid scan identifier")
    root = result_root.expanduser().resolve()
    run_dir = scan_run_directory(root / "Runs", scan_id)
    attack_dir = scan_run_directory(root / "AttackRuns", scan_id)
    if run_dir is None or attack_dir is None:
        raise ValueError("this scan has no persisted post-Recon handoff")
    database = attack_dir / "Pipeline.db"
    handoff_path = run_dir / "Handoff.json"
    if not database.is_file() or not handoff_path.is_file():
        raise ValueError("this scan has no persisted post-Recon handoff")
    if not run_dir.resolve().is_relative_to(root) or not database.resolve().is_relative_to(root):
        raise ValueError("scan artifacts must remain inside the result root")

    manifest = HandoffManifest.model_validate_json(handoff_path.read_text(encoding="utf-8"))
    if manifest.scan_id != scan_id:
        raise ValueError("handoff scan identifier does not match")
    verified = manifest.verify_artifacts(root=run_dir)
    scope_path = verified.get("Scope.md")
    policy_path = verified.get("TargetPolicy.json")
    scope_json_path = verified.get("Scope.json")
    approval_path = verified.get("Approval.json")
    if not all((scope_path, policy_path, scope_json_path, approval_path)):
        raise ValueError("approved Scope artifacts are missing from the handoff")
    scope_document = json.loads(scope_json_path.read_text(encoding="utf-8"))
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    scope_id = str(scope_document.get("scope_id") or "")
    if (
        not scope_id or approval.get("scope_id") != scope_id
        or approval.get("scope_json_sha256") != _sha256(scope_json_path)
        or approval.get("scope_markdown_sha256") != _sha256(scope_path)
    ):
        raise ValueError("approved Scope integrity verification failed")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if policy.get("scope_id") != scope_id:
        raise ValueError("target policy does not match the approved Scope")
    saved_models = load_scan_model_choices(root, scan_id)
    model_path = verified.get(MODEL_SETTINGS_FILE)
    if model_path is not None:
        models = read_scan_model_choices(model_path, scan_id=scan_id)
        if saved_models is not None and saved_models != models:
            raise ValueError("scan model settings do not match the verified handoff")
    else:
        # Existing source imports and older scans have no model record.
        models = saved_models if saved_models is not None else ScanModelChoices.resolve()
    source_document = scope_document.get("source")
    program_url = source_document.get("requested_url") if isinstance(source_document, dict) else None
    if not isinstance(program_url, str):
        program_url = None

    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        source = conn.execute(
            """SELECT source_manifest_sha256,source_database_sha256
            FROM pipeline_sources WHERE scan_id=?""", (scan_id,)
        ).fetchone()
        if source is None or source[0] != _sha256(handoff_path) or source[1] != _sha256(verified[manifest.db_path]):
            raise ValueError("pipeline provenance does not match the verified Recon handoff")
        scan = conn.execute(
            "SELECT status,scope_value FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        # An explicit dashboard cancellation after Recon is a resumable
        # checkpoint.  The cancellation closes the active post-Recon stage and
        # marks the shared scan row cancelled, but it does not invalidate the
        # already verified Recon handoff.  Keep requiring that completed Recon
        # stage below so an interrupted Recon run can never enter Attack.
        if scan is None or scan[0] not in {
            "completed", "completed_with_errors", "cancelled",
        } or scan[1] != scope_id:
            raise ValueError("retry requires a completed approved Recon scan")
        latest: dict[str, tuple[str, str]] = {}
        for stage_run_id, stage, status in conn.execute(
            "SELECT stage_run_id,stage,status FROM stage_runs WHERE scan_id=? ORDER BY rowid",
            (scan_id,),
        ):
            latest[str(stage)] = (str(stage_run_id), str(status))
        if latest.get("recon", (None, None))[1] != "completed":
            raise ValueError("retry requires a completed Recon stage")
        from aidast.attack.coverage_snapshot import attack_work_unfinished
        unfinished_attack = attack_work_unfinished(conn, scan_id)
        resumable_validation_stage = _resumable_validation_stage(conn, scan_id)
        targets = tuple(
            str(row[0]) for row in conn.execute(
                "SELECT DISTINCT identifier FROM assets WHERE scan_id=? ORDER BY identifier",
                (scan_id,),
            )
        )

    # Once Validation owns queued or interrupted cases, resume that exact
    # failed run. A residual Attack review gap must not start new upstream
    # stages and then collide with the durable Validation cases.
    if resumable_validation_stage is not None:
        return ResumePlan(
            scan_id, scope_id, "validation", resumable_validation_stage,
            database, scope_path, policy_path, targets, models, program_url,
        )

    for stage in ("attack", "chaining", "validation", "report"):
        previous = latest.get(stage)
        if previous is None:
            return ResumePlan(scan_id, scope_id, stage, None, database, scope_path, policy_path,
                              targets, models, program_url)
        stage_run_id, status = previous
        if status in {"failed", "cancelled"} or (
            stage == "attack" and status == "completed" and unfinished_attack
        ):
            return ResumePlan(scan_id, scope_id, stage, stage_run_id, database, scope_path, policy_path,
                              targets, models, program_url)
        if status not in ({"completed"} if stage == "attack" else {"completed", "skipped"}):
            raise ValueError(f"{stage} is still active or cannot be retried: {status}")
    raise ValueError("all post-Recon stages have already completed")


def execute_resume(
    plan: ResumePlan,
    *,
    agent: Any | None = None,
    planning_agent: Any | None = None,
    validation_factory: Any | None = None,
) -> None:
    """Continue from the selected stage through Validation using the same scan ID."""
    # ``inspect_resume`` has already re-verified the immutable Recon handoff.
    # Dashboard cancellation marks the shared scan row cancelled even when
    # Recon finished long before a post-Recon worker was stopped.  Restore that
    # verified checkpoint before coordinators enforce their completed-Recon
    # precondition.
    with closing(sqlite3.connect(plan.database)) as conn, conn:
        restored = conn.execute(
            """UPDATE scans SET status='completed'
               WHERE scan_id=? AND status='cancelled'""",
            (plan.scan_id,),
        ).rowcount
        if restored:
            from aidast.pipeline.lifecycle import audit_event
            audit_event(
                conn, scan_id=plan.scan_id,
                event_type="scan.post_recon_checkpoint_restored",
                details={"resume_stage": plan.stage},
            )
    if plan.stage == "report":
        # Report retries are entirely offline; the CLI drafts from the current
        # verified cases after this function returns.
        return
    from aidast.agents.main import CodexMainAgent
    from aidast.orchestration.attack import AttackCoordinator
    from aidast.orchestration.chaining import ChainingCoordinator
    from aidast.validation import build_native_validation_coordinator

    main_agent = (agent or CodexMainAgent(**plan.models.agent_options())) if plan.stage in {"attack", "chaining"} else None
    if plan.stage == "attack":
        AttackCoordinator(
            agent=main_agent,
            planning_agent=(planning_agent or CodexMainAgent(main_model=plan.models.attack_model)),
            db_path=plan.database,
            scope_path=plan.scope_path, policy_path=plan.policy_path,
        ).run(plan.scan_id)
    if plan.stage in {"attack", "chaining"}:
        ChainingCoordinator(
            agent=main_agent, db_path=plan.database,
            scope_path=plan.scope_path, policy_path=plan.policy_path,
        ).run(plan.scan_id)
    coordinator = (
        validation_factory(db_path=plan.database, policy_path=plan.policy_path,
                           validation_model=plan.models.validation_model)
        if validation_factory is not None else
        build_native_validation_coordinator(db_path=plan.database, policy_path=plan.policy_path,
                                             validation_model=plan.models.validation_model)
    )
    validation_stage_run_id = plan.stage_run_id if plan.stage == "validation" else None
    if validation_stage_run_id is None:
        with closing(sqlite3.connect(plan.database)) as conn:
            validation_stage_run_id = _resumable_validation_stage(conn, plan.scan_id)
    if validation_stage_run_id is not None:
        coordinator.resume(validation_stage_run_id)
    else:
        coordinator.run(plan.scan_id)
