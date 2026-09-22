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
