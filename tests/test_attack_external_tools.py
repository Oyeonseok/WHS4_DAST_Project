from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch

import pytest

from aidast.attack.coverage import ensure_coverage_manifest
from aidast.attack.external_tools import (
    ToolAdapterError,
    compile_tool_manifest,
    execute_tool_adapter,
)
from aidast.attack.graph import synchronize_attack_graph
from aidast.pipeline.lifecycle import create_task, start_stage_run, transition_task
from test_attack_coverage import imported_pipeline


def test_nuclei_contract_rejects_executable_and_credential_fields() -> None:
    with pytest.raises(ToolAdapterError, match="not allowed"):
        compile_tool_manifest({
            "adapter_id": "nuclei-http-template-v1", "template_id": "bad",
            "command": "nuclei -u target", "requests": [{
                "url": "https://example.test/",
            }],
        })
    with pytest.raises(ToolAdapterError, match="credential headers"):
        compile_tool_manifest({
            "adapter_id": "nuclei-http-template-v1", "template_id": "bad-auth",
            "requests": [{
                "url": "https://example.test/",
                "headers": {"Authorization": "Bearer secret"},
            }],
        })


def test_sqlmap_contract_expands_only_bounded_url_payload_slots() -> None:
    compiled = compile_tool_manifest({
        "adapter_id": "sqlmap-payload-family-v1",
        "payload_family": "boolean",
        "request": {
            "method": "GET", "url": "https://example.test/items?id={{PAYLOAD}}",
        },
        "payloads": ["1 AND 1=1", "1 AND 1=2"],
    })
    assert len(compiled.requests) == 2
    assert compiled.requests[0]["url"].endswith("id=1%20AND%201%3D1")
    assert compiled.summary == {"payload_family": "boolean", "request_count": 2}
    assert "payloads" not in compiled.summary


def test_tool_requests_are_dispatched_through_guard_and_audited(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        task = create_task(
            conn, stage_run_id=stage, skill_name="hunt-sqli", endpoint_id=endpoint_id,
        )
        transition_task(conn, task, status="running")

    payload_paths = []
    calls = []
    def guarded(_database, **kwargs):
        payload_paths.append(kwargs["payload_path"])
        request = json.loads(kwargs["payload_path"].read_text())
        calls.append(request)
        return {"request_id": f"request-{len(calls)}", "status": 200}

    manifest = {
        "adapter_id": "nuclei-http-template-v1", "template_id": "header-diff",
        "requests": [
            {"method": "GET", "url": "https://lab.example/a"},
            {"method": "GET", "url": "https://lab.example/b"},
        ],
    }
    with patch("aidast.attack.external_tools.guarded_request", side_effect=guarded):
        result = execute_tool_adapter(
            imported.pipeline_database, scan_id=imported.scan_id,
            stage_run_id=stage, task_id=task,
            policy_path=imported.recon_database.parent / "TargetPolicy.json",
            manifest=manifest,
        )

    assert [call["url"] for call in calls] == [
        "https://lab.example/a", "https://lab.example/b",
    ]
    assert all(not path.exists() for path in payload_paths)
    assert result["request_ids"] == ["request-1", "request-2"]
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM attack_tool_runs WHERE tool_run_id=?",
            (result["tool_run_id"],),
        ).fetchone()
        assert row["status"] == "completed"
        assert row["completed_request_count"] == 2
        assert json.loads(row["request_ids_json"]) == result["request_ids"]
        assert "https://" not in row["result_summary_json"]
        synchronize_attack_graph(conn, imported.scan_id, trigger_kind="tool.completed")
        assert conn.execute(
            """SELECT state FROM attack_graph_nodes
               WHERE node_kind='tool_run' AND node_key=?""", (result["tool_run_id"],),
        ).fetchone()[0] == "resolved"
