"""Dashboard restarts retain operator control of isolated local worker fixtures."""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

import aidast.web.launch as launch_module
from aidast.web.launch import ScanLaunchManager
from aidast.web.projection import DashboardProjector
from test_web_dashboard import SCAN_ID, _fixture


@pytest.fixture
def post_recon(tmp_path):
    recon = _fixture(tmp_path)
    with sqlite3.connect(recon) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='completed' WHERE scan_id=?", (SCAN_ID,))
    pipeline = recon.with_name("Pipeline.db")
    with sqlite3.connect(recon) as source, sqlite3.connect(pipeline) as destination:
        source.backup(destination)
        destination.execute("INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)", (
            "active-stage", SCAN_ID, "attack", "running", None,
            "2026-09-20T01:06:00Z", None, "2026-09-20T01:06:00Z",
        ))
    projector = DashboardProjector(tmp_path)
    assert projector.locate_database(SCAN_ID) == pipeline
    assert projector.snapshot(SCAN_ID)["status"] == "running"
    assert projector.snapshot(SCAN_ID)["stage"] == "Attack"
    return recon, pipeline, projector


def _wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


@pytest.fixture(params=["run", "resume"])
def recorded_worker(tmp_path, post_recon, request):
    # A local sleeping module provides authentic argv/cwd/session identity.
    # It has no scan implementation and makes no target or network requests.
    (tmp_path / "aidast.py").write_text("import time\ntime.sleep(60)\n")
    args = (["run", "https://example.test", "--scan-id", SCAN_ID]
            if request.param == "run" else ["resume", SCAN_ID])
    process = subprocess.Popen([sys.executable, "-m", "aidast", *args],
                               cwd=tmp_path, start_new_session=True)
    _, _, projector = post_recon
    first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    first._record_process(SCAN_ID, process)
    restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    try:
        _wait_for(lambda: restarted._isolated_scan_pid(SCAN_ID) == process.pid)
        assert not restarted.exists(SCAN_ID)
        yield process, restarted
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="uses isolated POSIX sleeping workers")
def test_restarted_dashboard_can_cancel_active_post_recon_worker(post_recon, recorded_worker):
    recon, pipeline, projector = post_recon
    process, restarted = recorded_worker
    original_recon = recon.read_bytes()
    assert restarted._persisted_scan_status(SCAN_ID) == "completed"
    assert restarted.cancel(SCAN_ID) == {"scan_id": SCAN_ID, "status": "cancelling"}
    process.wait(timeout=5)
    _wait_for(lambda: projector.snapshot(SCAN_ID)["status"] == "cancelled")
    with sqlite3.connect(pipeline) as conn:
        assert conn.execute("SELECT status FROM stage_runs WHERE stage_run_id='active-stage'").fetchone() == ("cancelled",)
        assert conn.execute("SELECT status FROM stage_runs WHERE stage_run_id='stage'").fetchone() == ("completed",)
    assert recon.read_bytes() == original_recon
    events = [event["payload"] for event in projector.stored_events_after(SCAN_ID, 0)
              if event["type"] == "log.appended"]
    assert [event["stage"] for event in events if event.get("message_code") in {
        "pipeline.cancel_requested", "pipeline.cancelled",
    }] == ["Attack", "Attack"]


@pytest.mark.skipif(os.name != "posix", reason="uses isolated POSIX sleeping workers")
def test_restarted_dashboard_cancel_falls_back_when_group_signal_is_denied(
    post_recon, recorded_worker, monkeypatch,
):
    _, _, projector = post_recon
    process, restarted = recorded_worker

    def deny_group_signal(*_args):
        raise PermissionError("protected helper")

    monkeypatch.setattr(launch_module, "signal_session", deny_group_signal)
    assert restarted.cancel(SCAN_ID) == {"scan_id": SCAN_ID, "status": "cancelling"}
    assert process.wait(timeout=5) == -signal.SIGTERM
    _wait_for(lambda: projector.snapshot(SCAN_ID)["status"] == "cancelled")


@pytest.mark.skipif(os.name != "posix", reason="uses isolated POSIX sleeping workers")
def test_pause_continue_after_another_restart_preserves_completed_recon(
    tmp_path, post_recon, recorded_worker,
):
    recon, pipeline, projector = post_recon
    process, restarted = recorded_worker
    original_recon = recon.read_bytes()
    assert restarted.pause(SCAN_ID)["status"] == "paused"
    assert projector.snapshot(SCAN_ID)["status"] == "paused"
    marker = json.loads(restarted._process_marker(SCAN_ID).read_text())
    assert marker["pause_resume_status"] == "completed"
    with pytest.raises(ValueError, match="not running"):
        restarted.pause(SCAN_ID)

    another_restart = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    assert another_restart.continue_scan(SCAN_ID)["status"] == "running"
    assert process.poll() is None
    assert another_restart._isolated_scan_pid(SCAN_ID) == process.pid
    assert another_restart._persisted_scan_status(SCAN_ID) == "completed"
    assert projector.snapshot(SCAN_ID)["status"] == "running"
    assert projector.snapshot(SCAN_ID)["stage"] == "Attack"
    with sqlite3.connect(pipeline) as conn:
        assert conn.execute("SELECT status FROM stage_runs WHERE stage_run_id='active-stage'").fetchone() == ("running",)
    assert recon.read_bytes() == original_recon
    # Cancellation also works when the adopted post-Recon worker is stopped.
    assert another_restart.pause(SCAN_ID)["status"] == "paused"
    assert another_restart.cancel(SCAN_ID)["status"] == "cancelling"
    process.wait(timeout=5)
    _wait_for(lambda: projector.snapshot(SCAN_ID)["status"] == "cancelled")


def _fake_identity(manager, root, monkeypatch, *, mismatch=None):
    manager._write_process_marker(SCAN_ID, {
        "pid": 43 if mismatch == "pid" else 42,
        "started": "other-start" if mismatch == "start" else "started",
        "pause_resume_status": "completed",
    })
    monkeypatch.setattr(manager, "_process_stat", lambda _pid: (
        "Z" if mismatch == "zombie" else "R", "started",
    ))
    monkeypatch.setattr(launch_module.os, "getpgid", lambda _pid: 41 if mismatch == "session" else 42)
    monkeypatch.setattr(launch_module, "process_cwd", lambda _pid: root.parent if mismatch == "cwd" else root)
    monkeypatch.setattr(launch_module, "process_args", lambda _pid: [
        "python", "-m", "other" if mismatch == "module" else "aidast", "run",
        "https://example.test", "--scan-id", "other_scan" if mismatch == "scan_id" else SCAN_ID,
    ])


@pytest.mark.skipif(os.name != "posix", reason="verifies POSIX session identity")
@pytest.mark.parametrize("action", ["pause", "cancel", "continue_scan"])
@pytest.mark.parametrize("mismatch", ["pid", "start", "session", "cwd", "module", "scan_id", "zombie"])
def test_active_pipeline_never_bypasses_adopted_process_identity(
    tmp_path, post_recon, monkeypatch, action, mismatch,
):
    _, pipeline, projector = post_recon
    if action == "continue_scan":
        with sqlite3.connect(pipeline) as conn:
            conn.execute("UPDATE scans SET status='paused' WHERE scan_id=?", (SCAN_ID,))
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    _fake_identity(manager, tmp_path, monkeypatch, mismatch=mismatch)
    signals = []
    monkeypatch.setattr(launch_module, "signal_session", lambda *args: signals.append(args))
    before = pipeline.read_bytes()
    with pytest.raises(ValueError, match="no isolated active process"):
        getattr(manager, action)(SCAN_ID)
    assert signals == []
    assert pipeline.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="verifies POSIX control rollback")
def test_continue_restores_paused_database_if_process_identity_changes_before_signal(
    tmp_path, post_recon, monkeypatch,
):
    _, pipeline, projector = post_recon
    with sqlite3.connect(pipeline) as conn:
        conn.execute("UPDATE scans SET status='paused' WHERE scan_id=?", (SCAN_ID,))
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    _fake_identity(manager, tmp_path, monkeypatch)
    signals = []

    def signal_failure(scan_id, signum):
        assert manager._persisted_scan_status(scan_id) == "completed"
        assert signum == signal.SIGCONT
        raise ValueError("scan process identity changed")

    monkeypatch.setattr(manager, "_signal_pid", signal_failure)
    monkeypatch.setattr(launch_module, "signal_session", lambda *args: signals.append(args))
    with pytest.raises(ValueError, match="identity changed"):
        manager.continue_scan(SCAN_ID)
    assert manager._persisted_scan_status(SCAN_ID) == "paused"
    assert signals == []


def test_windows_adopted_post_recon_pause_continue_cancel(tmp_path, post_recon, monkeypatch):
    recon, _, projector = post_recon
    original_recon = recon.read_bytes()

    class Worker:
        pid = 42

    alive = True
    actions = []

    def control(pid, started, action):
        nonlocal alive
        assert (pid, started) == (42, "started")
        if action == "resume":
            assert restarted._persisted_scan_status(SCAN_ID) == "completed"
        actions.append(action)
        if action == "terminate":
            alive = False

    monkeypatch.setattr(launch_module, "_windows_host", lambda: True)
    monkeypatch.setattr(launch_module.subprocess, "Popen", Worker)
    monkeypatch.setattr(launch_module, "process_cwd", lambda _pid: tmp_path)
    monkeypatch.setattr(launch_module, "process_args", lambda _pid: ["python.exe", "-m", "aidast", "resume", SCAN_ID])
    monkeypatch.setattr(ScanLaunchManager, "_process_stat", staticmethod(lambda _pid: ("R" if alive else "Z", "started")))
    monkeypatch.setattr(launch_module, "control_process", control)
    first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    first._record_process(SCAN_ID, Worker())
    restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    assert restarted.pause(SCAN_ID)["status"] == "paused"
    restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    assert restarted.continue_scan(SCAN_ID)["status"] == "running"
    assert restarted.cancel(SCAN_ID)["status"] == "cancelling"
    _wait_for(lambda: projector.snapshot(SCAN_ID)["status"] == "cancelled")
    assert actions == ["pause", "resume", "terminate"]
    assert recon.read_bytes() == original_recon
