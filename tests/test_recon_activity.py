"""Recon records the active task before its handler starts."""

from aidast.recon import db
from aidast.recon.executor import ReconExecutor
from aidast.recon.models import ReconStep, ReconTask, ReconTaskTarget
from aidast.scope.models import AssetType


def test_recon_task_start_is_persisted_before_handler_runs(tmp_path):
    conn = db.init_db(tmp_path / "Recon.db")
    db.insert_scan(conn, scan_id="scan_activity", scope_type="test", scope_value="test")
    executor = ReconExecutor.__new__(ReconExecutor)
    executor.conn = conn
    executor.scan_id = "scan_activity"
    executor._candidate_task_hosts = {}
    executor._diagnostic = lambda *args, **kwargs: None
    observed = []

    def handler(task):
        observed.extend(
            row[0] for row in conn.execute(
                "SELECT status FROM pipeline_runs WHERE task_id=? ORDER BY rowid",
                (task.task_id,),
            )
        )

    executor._handle_dns_resolution = handler
    task = ReconTask(
        task_id="task_dns", plan_id="plan", scope_id="scope",
        task_type=ReconStep.DNS_RESOLUTION, sequence=1,
        target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="example.com"),
        depends_on_task_ids=[], constraints=[],
    )
    try:
        executor._execute(task)
        assert observed == ["running"]
        assert [row[0] for row in conn.execute(
            "SELECT status FROM pipeline_runs WHERE task_id=? ORDER BY rowid", (task.task_id,)
        )] == ["running", "success"]
    finally:
        conn.close()


def test_recon_scheduler_records_pending_work_before_first_task(tmp_path):
    conn = db.init_db(tmp_path / "Recon.db")
    db.insert_scan(conn, scan_id="scan_activity", scope_type="test", scope_value="test")
    executor = ReconExecutor.__new__(ReconExecutor)
    executor.conn = conn
    executor.scan_id = "scan_activity"
    executor._candidate_task_hosts = {}
    executor._spawned_tasks = []
    executor.prioritize_discovered_assets_first = False
    executor._diagnostic = lambda *args, **kwargs: None
    observed = []

    def handler(task):
        observed.append((
            task.task_id,
            list(conn.execute(
                "SELECT task_id, status FROM pipeline_runs ORDER BY rowid"
            )),
        ))

    executor._handle_dns_resolution = handler
    tasks = [
        ReconTask(
            task_id=f"task-{index}", plan_id="plan", scope_id="scope",
            task_type=ReconStep.DNS_RESOLUTION, sequence=index,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="example.com"),
            depends_on_task_ids=[f"task-{index - 1}"] if index > 1 else [],
            constraints=[],
        )
        for index in (1, 2)
    ]
    try:
        assert executor.run(tasks) == 0
        assert observed[0][1] == [
            ("task-1", "pending"), ("task-2", "pending"), ("task-1", "running"),
        ]
        assert observed[1][1][-2:] == [("task-1", "success"), ("task-2", "running")]
    finally:
        conn.close()
