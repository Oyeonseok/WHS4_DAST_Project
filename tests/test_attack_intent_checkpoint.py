from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.attack.coverage import (
    claim_coverage_batch,
    ensure_coverage_manifest,
    reconcile_coverage_batch,
)
from aidast.attack.intent_checkpoint import commit_intent_checkpoint
from aidast.attack.db_cli import main as db_cli_main
from aidast.attack.graph import synchronize_attack_graph
from aidast.attack.recon_hypotheses import plan_recon_attack
from aidast.pipeline.lifecycle import start_stage_run
from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.pipeline.live_schema import migrate_live_pipeline_schema


class Planner:
    def _run_structured(self, *, prompt, model_type, **kwargs):
        context = json.loads(
            prompt.split("<untrusted_recon_json>\n", 1)[1]
            .split("\n</untrusted_recon_json>", 1)[0]
        )
        endpoint = context["endpoints"][0]
        return model_type.model_validate({
            "endpoints": [{
                "endpoint_id": endpoint["endpoint_id"],
                "hypotheses": [{
                    "vuln_class": "sqli",
                    "annotation_ids": [endpoint["annotations"][0]["annotation_id"]],
                    "parameter_name": "q",
                    "injection_location": "query",
                    "required_identity_role": "unauthenticated",
                    "rationale": "Observed input warrants bounded differential probes.",
                }],
                "disposition": "planned",
                "reason": "Observed input.",
            }],
        })


def _pipeline(tmp_path: Path) -> Path:
    path = tmp_path / "Pipeline.db"
    conn = db.init_db(path)
    migrate_live_pipeline_schema(conn)
    db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="approved")
    asset = db.insert_asset(
        conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN",
    )
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    ObservationRecorder(conn, origin_id=origin, scan_id="scan").record("browser", [{
        "method": "GET", "path": "/search",
        "url": "https://example.test/search?q=redacted", "source": "playwright_http",
    }])
    observation = conn.execute(
        "SELECT observation_id FROM endpoint_observations LIMIT 1"
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO annotation_runs VALUES "
        "('tags','scan','fixture','tags','1','completed',NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
    )
    conn.execute(
        """INSERT INTO endpoint_annotations
           VALUES ('tag',?,'tags','function','search','fixture',NULL,CURRENT_TIMESTAMP)""",
        (observation,),
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP"
    )
    conn.commit()
    conn.close()
    plan_recon_attack(path, "scan", agent=Planner())
    ensure_coverage_manifest(path, "scan")
    return path


def _claim(path: Path) -> tuple[str, dict]:
    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id="scan", stage="attack")
        task = claim_coverage_batch(
            conn, scan_id="scan", stage_run_id=stage, batch_size=1,
        )[0]
        conn.execute(
            "UPDATE attack_tasks SET status='running',started_at=CURRENT_TIMESTAMP "
            "WHERE task_id=?", (task["task_id"],),
        )
    return stage, task


def _negative_request(
    conn: sqlite3.Connection, stage: str, task: dict, *, request_id: str = "control",
) -> None:
    fingerprint = "f" * 64
    conn.execute(
        """INSERT INTO attack_http_requests
           (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
            request_fingerprint,status,response_status,response_bytes,scheduled_at,
            endpoint_reference_id,result_json)
           VALUES (?,'scan',?,?, 'policy',?,'https://example.test/search',?,
                   'completed',200,16,0,?,'{}')""",
        (
            request_id, stage, task["task_id"], task["method"], fingerprint,
            task["endpoint_id"],
        ),
    )
    conn.execute(
        """INSERT INTO attack_attempts
           (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
            identity_role,payload_variant,response_status,response_signature,outcome)
           VALUES (?,'scan',?,?,?,?, 'unauthenticated','boolean-control',200,?,'negative')""",
        (
            "attempt-" + request_id, task["task_id"], task["skill_name"],
            task["endpoint_id"], fingerprint, "a" * 64,
        ),
    )


def _checkpoint(
    conn: sqlite3.Connection, stage: str, task: dict, *, adequate: bool,
) -> dict:
    if adequate:
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,response_bytes,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('strategy-probe','scan',?,?, 'policy',?,
                       'https://example.test/search',?,'completed',200,18,0,?,'{}')""",
            (stage, task["task_id"], task["method"], "e" * 64, task["endpoint_id"]),
        )
    features = [{
        "request_id": "control", "status": 200,
        "body_sha256": "b" * 64,
        "assertion_kinds": ["status_equals"],
    }]
    if adequate:
        features.append({
            "request_id": "strategy-probe", "status": 200,
            "body_sha256": "c" * 64,
            "assertion_kinds": ["body_digest_differs"],
        })
    return commit_intent_checkpoint(
        conn, scan_id="scan", task_id=task["task_id"], document={
            "strategy_families": (
                ["syntax mutation", "identity differential"]
                if adequate else ["syntax mutation"]
            ),
            "payload_families": [],
            "response_features": features,
            "acquired_fact_refs": [],
            "remaining_todos": [],
            "control_request_ids": ["control"],
        },
    )


def test_weak_checkpoint_retries_and_is_passed_to_the_next_task(tmp_path: Path) -> None:
    path = _pipeline(tmp_path)
    stage, task = _claim(path)
    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        _negative_request(conn, stage, task)
        checkpoint = _checkpoint(conn, stage, task, adequate=False)
        assert checkpoint["evidence_quality"] == "weak"
        conn.execute(
            "UPDATE attack_tasks SET status='completed',finished_at=CURRENT_TIMESTAMP "
            "WHERE task_id=?", (task["task_id"],),
        )
        reconcile_coverage_batch(conn, stage_run_id=stage)
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (task["coverage_id"],),
        ).fetchone()[0] == "error_retryable"

        retry = claim_coverage_batch(
            conn, scan_id="scan", stage_run_id=stage, batch_size=5,
        )[0]
        assert retry["intent_checkpoint"]["checkpoint_id"] == checkpoint["checkpoint_id"]
        assert retry["intent_checkpoint"]["remaining_todos"] == []
        payload = json.loads(conn.execute(
            "SELECT payload_json FROM attack_tasks WHERE task_id=?", (retry["task_id"],),
        ).fetchone()[0])
        assert payload["intent_checkpoint"]["evidence_quality"] == "weak"


def test_adequate_checkpoint_allows_terminal_negative(tmp_path: Path) -> None:
    path = _pipeline(tmp_path)
    stage, task = _claim(path)
    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        _negative_request(conn, stage, task)
        checkpoint = _checkpoint(conn, stage, task, adequate=True)
        assert checkpoint["evidence_quality"] == "adequate"
        conn.execute(
            "UPDATE attack_tasks SET status='completed',finished_at=CURRENT_TIMESTAMP "
            "WHERE task_id=?", (task["task_id"],),
        )
        reconcile_coverage_batch(conn, stage_run_id=stage)
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (task["coverage_id"],),
        ).fetchone()[0] == "tested_negative"


def test_checkpoint_rejects_raw_secret_shapes_and_is_append_only(tmp_path: Path) -> None:
    path = _pipeline(tmp_path)
    stage, task = _claim(path)
    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        _negative_request(conn, stage, task)
        with pytest.raises(ValueError, match="credentials"):
            commit_intent_checkpoint(
                conn, scan_id="scan", task_id=task["task_id"], document={
                    "strategy_families": [], "payload_families": [],
                    "response_features": [], "acquired_fact_refs": [],
                    "remaining_todos": ["retry Authorization: bearer secret"],
                    "control_request_ids": [],
                },
            )
        checkpoint = _checkpoint(conn, stage, task, adequate=True)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE attack_intent_checkpoints SET evidence_quality='weak' "
                "WHERE checkpoint_id=?", (checkpoint["checkpoint_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "DELETE FROM attack_intent_checkpoints WHERE checkpoint_id=?",
                (checkpoint["checkpoint_id"],),
            )


def test_db_cli_commits_checkpoint_and_graph_projects_only_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    path = _pipeline(tmp_path)
    stage, task = _claim(path)
    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        _negative_request(conn, stage, task)
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,response_bytes,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('strategy-probe','scan',?,?,'policy',?,
                       'https://example.test/search',?,'completed',200,18,0,?,'{}')""",
            (stage, task["task_id"], task["method"], "e" * 64, task["endpoint_id"]),
        )
    payload = tmp_path / "checkpoint.json"
    payload.write_text(json.dumps({
        "task_id": task["task_id"],
        "strategy_families": ["syntax mutation", "identity differential"],
        "payload_families": [],
        "response_features": [
            {"request_id": "control", "status": 200, "body_sha256": "b" * 64,
             "assertion_kinds": ["status_equals"]},
            {"request_id": "strategy-probe", "status": 200,
             "body_sha256": "c" * 64, "assertion_kinds": ["body_digest_differs"]},
        ],
        "acquired_fact_refs": [], "remaining_todos": [],
        "control_request_ids": ["control"],
    }), encoding="utf-8")

    assert db_cli_main([
        "commit-checkpoint", "--db", str(path), "--scan-id", "scan",
        "--payload", str(payload),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["evidence_quality"] == "adequate"

    with sqlite3.connect(path) as conn, conn:
        conn.row_factory = sqlite3.Row
        synchronize_attack_graph(conn, "scan", stage_run_id=stage)
        node = conn.execute(
            """SELECT node_kind,node_key,metadata_json FROM attack_graph_nodes
               WHERE node_key=?""",
            (f"intent-checkpoint:{result['checkpoint_id']}",),
        ).fetchone()
        assert tuple(node[:2]) == (
            "fact", f"intent-checkpoint:{result['checkpoint_id']}",
        )
        metadata = json.loads(node["metadata_json"])
        assert metadata["strategy_count"] == 2
        assert "response_features" not in metadata
        assert conn.execute(
            """SELECT COUNT(*) FROM attack_graph_edges
               WHERE relationship='has_intent_checkpoint'"""
        ).fetchone()[0] == 1
