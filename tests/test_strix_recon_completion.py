import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from agents.tool_context import ToolContext

from aidast.recon.executor import ReconExecutionError
from aidast.recon.strix_engine.agents.factory import _lifecycle_tool_completed
from aidast.recon.strix_engine.core.agents import AgentCoordinator
from aidast.recon.strix_engine.tools.finish.recon_tool import finish_recon
from aidast.recon.strix_integration import StrixReconExecutor


def _capture(path, records):
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


async def _finish_with_capture(path):
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", None)
    args = json.dumps({"summary": "Discovery finished"})
    ctx = ToolContext(
        {"coordinator": coordinator, "agent_id": "root", "parent_id": None,
         "aidast_capture_host_path": str(path)},
        tool_name="finish_recon", tool_call_id="call-1", tool_arguments=args,
    )
    output = await finish_recon.on_invoke_tool(ctx, args)
    return json.loads(output), coordinator.statuses["root"]


def test_finish_recon_marks_unrecovered_rate_limited_page_assets_as_blocked(tmp_path):
    capture = tmp_path / "capture.jsonl"
    _capture(capture, [
        {"url": "http://host.docker.internal:3001/", "scope_allowed": True},
        {"url": "http://host.docker.internal:3001/main.js", "block_reason": "rate_limit"},
        {"url": "http://host.docker.internal:3001/styles.css", "block_reason": "rate_limit"},
    ])

    result, status = asyncio.run(_finish_with_capture(capture))

    assert result["recon_blocked"] is True
    assert result["recon_completed"] is False
    assert result["unrecovered_asset_count"] == 2
    assert status == "failed"
    assert _lifecycle_tool_completed("finish_recon", json.dumps(result)) is True


def test_finish_recon_accepts_page_assets_recovered_after_rate_limit(tmp_path):
    capture = tmp_path / "capture.jsonl"
    _capture(capture, [
        {"url": "http://host.docker.internal:3001/main.js", "block_reason": "rate_limit"},
        {"url": "http://host.docker.internal:3001/main.js", "scope_allowed": True,
         "policy_blocked": False, "response_status": 200},
    ])

    result, status = asyncio.run(_finish_with_capture(capture))

    assert result["recon_completed"] is True
    assert status == "completed"


def test_strix_executor_does_not_persist_blocked_recon(tmp_path):
    capture = tmp_path / "capture.jsonl"
    run = AsyncMock(return_value=(
        SimpleNamespace(final_output=json.dumps({
            "success": True, "recon_completed": False, "recon_blocked": True,
            "error": "Page JavaScript/CSS remained blocked",
        })), capture, {},
    ))
    with patch("aidast.recon.strix_integration.run_strix_recon", run), patch(
        "aidast.recon.strix_integration.persist_strix_capture"
    ) as persist:
        executor = StrixReconExecutor(
            scan_id="scan_test", scope_document=SimpleNamespace(scope_id="scope_test"),
            selected_targets=[SimpleNamespace(asset="http://localhost:3001/")],
            target_policies=[SimpleNamespace(limits=SimpleNamespace(max_depth=2))],
            start_urls={}, request_headers=None,
            db_path=tmp_path / "Recon.db", surface_path=tmp_path / "Surface.json",
            capture_directory=tmp_path, diagnostic_logs=False,
        )
        try:
            with pytest.raises(ReconExecutionError, match="Page JavaScript/CSS remained blocked"):
                executor.run([])
        finally:
            executor.close()
    persist.assert_not_called()
