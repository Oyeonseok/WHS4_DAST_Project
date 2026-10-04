from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.attack.coverage import (
    VULNERABILITY_SKILLS,
    _select_parameter,
    coverage_status,
    ensure_coverage_manifest,
    fail_running_coverage,
    requeue_auth_gated_negative_coverage,
    requeue_redacted_login_differential_coverage,
    requeue_interrupted_coverage,
    requeue_coverage,
    resolve_abandoned_attack_leads,
    transition_coverage,
    _credential_role,
    _execution_identity_role,
    _task_context_facts,
    _task_fixtures,
    claim_coverage_batch,
)
from aidast.attack.db_cli import transition_task
from aidast.attack.models import AttackStageResult
from aidast.orchestration.coverage_attack import ExhaustiveAttackCoordinator
from aidast.pipeline.lifecycle import (
    create_task,
    register_credential_reference,
    start_stage_run,
)
from aidast.recon.source_import import import_flask_source
from aidast.validation import canonical_reproduction_spec


SOURCE = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/users/<int:user_id>", methods=["GET", "POST"])
def user(user_id):
    # Vulnerability: SQL injection and IDOR
    data = request.get_json() or {}
    query = request.args.get("q")
    return data.get("display_name", query)
'''


def test_imported_information_disclosure_uses_general_evidence_workflow() -> None:
    assert VULNERABILITY_SKILLS["source_leak"] == "hunt-misc"


def test_jwt_coverage_requests_an_issued_authenticated_token() -> None:
    assert _credential_role("jwt_crypto", "unauthenticated") == "authenticated"


@pytest.mark.parametrize(
    "vuln_class",
    [
        "session", "auth_bypass", "cors", "sqli", "ssrf", "lfi",
        "file_upload", "open_redirect", "llm_ai", "business_logic",
        "race_condition", "xss", "forgot_password",
    ],
)
def test_control_differentials_receive_an_opaque_authenticated_reference(
    vuln_class: str,
) -> None:
    assert _credential_role(vuln_class, "unauthenticated") == "authenticated"


def test_safe_local_mutation_rebinds_passive_identity_to_disposable_account() -> None:
    references = [{
        "credential_reference_id": "credref-synthetic",
        "label": "synthetic",
        "identity_role": "identity_synthetic",
    }]
    fixtures = [{
        "fact_type": "owned_test_object",
        "fact_value": {
            "credential_label": "synthetic", "resource": "account",
            "disposable": True, "cleanup_allowed": True,
        },
    }]
    assert _execution_identity_role(
        method="POST", normalized_path="/upload_profile_picture_url",
        planned_role="unauthenticated", credential_references=references,
        test_fixtures=fixtures,
    ) == "authenticated"
    assert _execution_identity_role(
        method="POST", normalized_path="/transfer",
        planned_role="unauthenticated", credential_references=references,
        test_fixtures=fixtures,
    ) == "unauthenticated"


def test_brute_force_prefers_verifier_secret_over_replacement_password() -> None:
    class Parameter(dict):
        pass

    location, name = _select_parameter("brute_force", [
        Parameter(name="new_password", location="json", role="credential",
                  data_type="string", is_identifier=0),
        Parameter(name="pin", location="json", role="unknown",
                  data_type="string", is_identifier=0),
        Parameter(name="username", location="json", role="identity",
                  data_type="string", is_identifier=0),
    ])

    assert (location, name) == ("json", "pin")


class UnsupportedCoverageAgent:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        self.calls.append(kwargs)
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "skipped", "unsupported safe test contract",
            )
        return AttackStageResult(
            status="COMPLETED", scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["coverage-agent"], summary="coverage items classified",
        )


class AuthBlockedCoverageAgent(UnsupportedCoverageAgent):
    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        self.calls.append(kwargs)
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "skipped", "missing authentication identity",
            )
        return AttackStageResult(
            status="COMPLETED", scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["coverage-agent"], summary="credentials required",
        )


class UnauthenticatedEvidenceAgent(UnsupportedCoverageAgent):
    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        self.calls.append(kwargs)
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "skipped",
                "equivalent unauthenticated request already has durable evidence",
            )
        return AttackStageResult(
            status="COMPLETED", scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["coverage-agent"], summary="duplicate evidence",
        )


def imported_pipeline(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(SOURCE, encoding="utf-8")
    return import_flask_source(
        source, target_url="https://lab.example/", result_root=tmp_path / "result",
        approved_by="fixture", source_ref="fixture-commit",
    )


def test_running_task_can_be_skipped_after_request_bound_policy_denial(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(conn, stage_run_id=stage, skill_name="hunt-business-logic")
    transition_task(
        imported.pipeline_database, imported.scan_id, stage, task, "running",
    )
    transition_task(
        imported.pipeline_database, imported.scan_id, stage, task, "skipped",
        "[policy] exact request envelope was denied before dispatch",
    )
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,error_message FROM attack_tasks WHERE task_id=?", (task,),
        ).fetchone() == (
            "skipped", "[policy] exact request envelope was denied before dispatch",
        )
        assert conn.execute(
            "SELECT event_type FROM audit_events WHERE task_id=? ORDER BY created_at", (task,),
        ).fetchall()[-1] == ("task.skipped",)


def test_manifest_has_one_item_per_source_annotation_and_is_idempotent(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)

    first = ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    second = ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)

    assert first.total == 4
    assert first.inserted == 4
    assert first.by_vulnerability == {"idor": 2, "sqli": 2}
    assert second.total == 4
    assert second.inserted == 0
    assert second.existing == 4
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute("PRAGMA user_version").fetchone() == (12,)
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute(
            "SELECT count(DISTINCT endpoint_id || ':' || annotation_id) "
            "FROM attack_coverage_items"
        ).fetchone() == (4,)


def test_operator_interruption_releases_coverage_without_retry_isolation(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=row["skill_name"],
            endpoint_id=row["endpoint_id"], payload={"coverage_id": row["coverage_id"]},
        )
        conn.execute(
            "UPDATE attack_coverage_items SET attempt_count=1 WHERE coverage_id=?",
            (row["coverage_id"],),
        )
        transition_coverage(
            conn, row["coverage_id"], "running", "claimed",
            stage_run_id=stage, task_id=task,
        )
        fail_running_coverage(
            conn, stage_run_id=stage, reason="operator interrupted",
        )
        assert requeue_interrupted_coverage(
            conn, stage_run_id=stage, reason="returned after interruption",
        ) == 1
        assert tuple(conn.execute(
            """SELECT status,attempt_count,last_stage_run_id,last_task_id
               FROM attack_coverage_items WHERE coverage_id=?""",
            (row["coverage_id"],),
        ).fetchone()) == ("pending", 0, None, None)


def test_captured_public_security_declaration_is_scheduled_first(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id DESC LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
                association_method,observed_at,evidence_json)
               VALUES ('priority-public-api',?,'openapi','api_spec_declaration',
                       'https://lab.example/openapi.json','exact','2026-10-05T00:00:00Z',?)""",
            (endpoint_id, json.dumps({
                "operation_description": "Intentionally vulnerable to injection",
            })),
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        tasks = claim_coverage_batch(
            conn, scan_id=imported.scan_id, stage_run_id=stage, batch_size=1,
        )

    assert len(tasks) == 1
    assert tasks[0]["endpoint_id"] == endpoint_id
    assert tasks[0]["vuln_class"] == "sqli"


def test_public_security_declaration_prioritizes_matching_vulnerability_class(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id DESC LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
                association_method,observed_at,evidence_json)
               VALUES ('priority-bola',?,'openapi','api_spec_declaration',
                       'https://lab.example/openapi.json','exact',
                       '2026-10-05T00:00:00Z',?)""",
            (endpoint_id, json.dumps({
                "operation_description": "Intentionally vulnerable to BOLA",
            })),
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        tasks = claim_coverage_batch(
            conn, scan_id=imported.scan_id, stage_run_id=stage, batch_size=1,
        )

    assert len(tasks) == 1
    assert tasks[0]["endpoint_id"] == endpoint_id
    assert tasks[0]["vuln_class"] == "idor"


def test_login_injection_is_prioritized_without_a_public_security_hint(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints WHERE method='POST' LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            "UPDATE endpoints SET normalized_path='/login' WHERE endpoint_id=?",
            (endpoint_id,),
        )
        conn.execute(
            "UPDATE endpoints SET normalized_path='/login' WHERE method='GET'",
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        tasks = claim_coverage_batch(
            conn, scan_id=imported.scan_id, stage_run_id=stage, batch_size=1,
        )

    assert len(tasks) == 1
    assert tasks[0]["endpoint_id"] == endpoint_id
    assert tasks[0]["vuln_class"] == "sqli"


def test_coverage_task_cannot_complete_without_a_durable_attempt(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    manifest = ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    assert manifest.total
    with sqlite3.connect(imported.pipeline_database) as conn:
        coverage_id = conn.execute(
            "SELECT coverage_id FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()[0]
        stage_run_id = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task_id = create_task(
            conn, stage_run_id=stage_run_id, skill_name="hunt-sqli",
            payload={"coverage_id": coverage_id},
        )

    transition_task(
        imported.pipeline_database, imported.scan_id, stage_run_id,
        task_id, "running",
    )
    with pytest.raises(ValueError, match="durable attempt"):
        transition_task(
            imported.pipeline_database, imported.scan_id, stage_run_id,
            task_id, "completed",
        )


def test_abandoned_stage_lead_is_preserved_as_inconclusive(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        stage_run_id = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task_id = create_task(
            conn, stage_run_id=stage_run_id, skill_name="hunt-sqli",
        )
        conn.execute(
            "UPDATE attack_tasks SET status='failed' WHERE task_id=?", (task_id,),
        )
        conn.execute(
            "UPDATE stage_runs SET status='failed',finished_at=CURRENT_TIMESTAMP "
            "WHERE stage_run_id=?", (stage_run_id,),
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,
                request_fingerprint,outcome)
               VALUES ('attempt-abandoned',?,?,?,?,?,'lead')""",
            (imported.scan_id, task_id, "hunt-sqli", endpoint_id, "a" * 64),
        )
        assert resolve_abandoned_attack_leads(conn, imported.scan_id) == 1
        row = conn.execute(
            "SELECT outcome,resolution_reason,resolved_at FROM attack_attempts "
            "WHERE attempt_id='attempt-abandoned'"
        ).fetchone()

    assert row[0] == "inconclusive"
    assert "coverage retry" in row[1]
    assert row[2]


def test_exhaustive_batches_leave_no_silent_unfinished_items(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    agent = UnsupportedCoverageAgent()

    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    status = coverage_status(imported.pipeline_database, imported.scan_id)
    assert result.batches == 2
    assert len(agent.calls) == 2
    assert all(len(call["attack_tasks"]) == 2 for call in agent.calls)
    assert status.total == 4
    assert status.unfinished == 0
    assert status.by_status == {"unsupported": 4}
    assert status.disposition_coverage == 1.0
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT count(*) FROM attack_coverage_events WHERE next_status='running'"
        ).fetchone() == (4,)
        assert conn.execute(
            "SELECT count(*) FROM attack_coverage_events WHERE next_status='unsupported'"
        ).fetchone() == (4,)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_explicit_auth_prerequisite_is_blocked_before_native_agent_dispatch(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        authenticated = conn.execute(
            "SELECT coverage_id FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            "UPDATE attack_coverage_items SET required_identity_role='authenticated' "
            "WHERE coverage_id=?",
            (authenticated,),
        )

    agent = UnsupportedCoverageAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    assert len(agent.calls) == 1
    assert len(agent.calls[0]["attack_tasks"]) == 3
    assert all(
        task["required_identity_role"] == "unauthenticated"
        for task in agent.calls[0]["attack_tasks"]
    )
    assert result.coverage["by_status"] == {"blocked_auth": 1, "unsupported": 3}
    with sqlite3.connect(imported.pipeline_database) as conn:
        row = conn.execute(
            "SELECT status,disposition_reason,attempt_count,last_task_id "
            "FROM attack_coverage_items WHERE coverage_id=?",
            (authenticated,),
        ).fetchone()
        assert row == (
            "blocked_auth",
            "[auth] authenticated identity prerequisite has no usable "
            "same-origin credential reference",
            0,
            None,
        )
        assert conn.execute(
            "SELECT previous_status,next_status,stage_run_id,task_id "
            "FROM attack_coverage_events WHERE coverage_id=? ORDER BY rowid DESC LIMIT 1",
            (authenticated,),
        ).fetchone() == ("pending", "blocked_auth", result.stage_run_ids[0], None)


def test_all_auth_blocked_batch_completes_without_calling_native_agent(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.execute(
            "UPDATE attack_coverage_items SET required_identity_role='authenticated'"
        )

    agent = UnsupportedCoverageAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert agent.calls == []
    assert result.batches == 1
    assert result.coverage["by_status"] == {"blocked_auth": 4}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,error_message FROM stage_runs WHERE stage_run_id=?",
            (result.stage_run_ids[0],),
        ).fetchone() == ("completed", None)


def test_failed_native_batches_reconcile_and_continue_to_other_coverage(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)

    class TerminalFailureAgent:
        def __init__(self) -> None:
            self.calls = 0

        def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
            self.calls += 1
            for task in kwargs["attack_tasks"]:
                transition_task(
                    kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                    task["task_id"], "running",
                )
                transition_task(
                    kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                    task["task_id"], "failed", "bounded proof unavailable",
                )
            return AttackStageResult(
                status="FAILED", scan_id=kwargs["scan_id"],
                db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
                attack_agent_ids=["coverage-agent"], summary="bounded proof unavailable",
            )

    agent = TerminalFailureAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2, retry_limit=1,
    ).run(imported.scan_id)

    assert result.coverage["unfinished"] == 0
    assert result.coverage["by_status"] == {"error_terminal": 4}
    assert agent.calls == 2
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,count(*) FROM stage_runs WHERE stage='attack' GROUP BY status"
        ).fetchall() == [("completed", 2)]
        assert conn.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='stage.failed'"
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='task.failed'"
        ).fetchone() == (4,)


def test_coverage_tasks_include_non_secret_owned_object_fixtures(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.execute(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
               VALUES ('fact-user-a',?,'owned_test_object','user-a.user_id',?,1.0)""",
            (imported.scan_id, json.dumps({
                "credential_label": "user-a", "object_id": "41",
                "object_type": "user_id", "principal": "fixture-user-a",
            })),
        )
    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)
    fixtures = [
        fixture
        for task in agent.calls[0]["attack_tasks"]
        for fixture in task["test_fixtures"]
    ]
    assert any(
        item["fact_key"] == "user-a.user_id"
        and item["fact_value"]["object_id"] == "41"
        for item in fixtures
    )


def test_coverage_tasks_retain_safe_black_box_facts_across_batches(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        conn.executemany(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,
                source_endpoint_id) VALUES (?,?,?,?,?,?,?)""",
            [
                ("fact-behavior", imported.scan_id, "endpoint_behavior",
                 "users.response_shape", json.dumps({"id_field": "user_id"}),
                 0.9, endpoint_id),
                ("fact-secret", imported.scan_id, "auth_behavior",
                 "login.access_token", "must-not-leak", 1.0, endpoint_id),
            ],
        )
    agent = UnsupportedCoverageAgent()

    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    facts = agent.calls[0]["attack_tasks"][0]["context_facts"]
    assert any(
        item["fact_key"] == "users.response_shape"
        and item["fact_value"] == {"id_field": "user_id"}
        and item["source_endpoint_id"] == endpoint_id
        for item in facts
    )
    assert all(item["fact_key"] != "login.access_token" for item in facts)


@pytest.mark.parametrize("fact_type", ["owned_test_object", "endpoint_behavior"])
def test_shareable_fact_contents_do_not_expose_nested_secrets(
    tmp_path: Path, fact_type: str,
) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = conn.execute("SELECT endpoint_id FROM endpoints LIMIT 1").fetchone()[0]
        conn.execute(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,source_endpoint_id)
               VALUES ('fact-nested',?,?,?, ?,1.0,?)""",
            (imported.scan_id, fact_type, "users.metadata", json.dumps({
                "object_type": "user_id", "object_id": "owned-fixture",
                "nested": [{"access_token": "nested-must-not-leak"}],
                "request_headers": {"X-Custom": "header-must-not-leak"},
                "response_body": "body-must-not-leak",
                "note": "Authorization: Bearer text-must-not-leak",
            }), endpoint_id),
        )
        if fact_type == "owned_test_object":
            facts = _task_fixtures(conn, imported.scan_id, parameter_name="user_id")
        else:
            facts = _task_context_facts(
                conn, imported.scan_id, endpoint_id=endpoint_id, parameter_name="user_id",
            )
        assert len(facts) == 1
        assert facts[0]["fact_value"]["object_type"] == "user_id"
        assert "must-not-leak" not in json.dumps(facts)


def test_owned_fixture_retains_registered_label_without_exposing_principal(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="user-a",
            reference_uri="env://TEST_FIXTURE_USER_A", identity_role="authenticated",
        )
        conn.execute(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
               VALUES ('fact-label',?,'owned_test_object','user-a.user_id',?,1.0)""",
            (imported.scan_id, json.dumps({
                "credential_label": "user-a", "object_type": "user_id",
                "principal": "personal-address@example.test", "password": "must-not-leak",
            })),
        )
        value = _task_fixtures(conn, imported.scan_id, parameter_name="user_id")[0]["fact_value"]
        assert value["credential_label"] == "user-a"
        assert "principal" not in value
        assert "must-not-leak" not in json.dumps(value)


def test_coverage_task_exposes_all_db_parameters_and_source_context(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        endpoint_id, method, normalized_path = conn.execute(
            """SELECT endpoint_id,method,normalized_path FROM endpoints
               WHERE normalized_path LIKE '%users%' ORDER BY endpoint_id LIMIT 1"""
        ).fetchone()
        conn.execute(
            """INSERT INTO http_transactions
               (http_transaction_id,endpoint_id,source,method,url,response_status,
                response_body,content_type,captured_at)
               VALUES ('public-api-response',?,'openapi','GET',
                       'https://lab.example/openapi.json',200,?,
                       'application/json','2026-10-05T00:00:00Z')""",
            (endpoint_id, json.dumps({
                "openapi": "3.0.0",
                "paths": {normalized_path: {method.lower(): {
                    "summary": "Look up a user",
                    "description": "Vulnerable lookup; password=must-not-leak",
                    "tags": ["users"],
                }}},
            })),
        )
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
                association_method,observed_at,evidence_json)
               VALUES ('public-api-fixture',?,'openapi','api_spec_declaration',
                       'https://lab.example/openapi.json','exact','2026-10-05T00:00:00Z',?)""",
            (endpoint_id, "{}"),
        )
    agent = UnsupportedCoverageAgent()

    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    task = next(item for item in agent.calls[0]["attack_tasks"]
                if item["vuln_class"] == "sqli" and item["endpoint_id"] == endpoint_id)
    assert {(item["location"], item["name"]) for item in task["parameter_candidates"]} == {
        ("json", "display_name"), ("path", "user_id"), ("query", "q"),
    }
    assert sum(bool(item["preferred"]) for item in task["parameter_candidates"]) == 1
    assert task["source_context"]["active_annotation"]["tag"] == "sqli"
    assert "SQL injection" in task["source_context"]["active_annotation"]["rationale"]
    declarations = task["source_context"]["public_api_declarations"]
    assert declarations[0]["operation_summary"] == "Look up a user"
    assert declarations[0]["operation_tags"] == ["users"]
    assert "must-not-leak" not in json.dumps(declarations)


def test_coverage_context_exposes_request_shape_without_captured_values(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    with sqlite3.connect(imported.pipeline_database) as conn:
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints WHERE normalized_path LIKE '%users%' LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO http_transactions(
                   http_transaction_id,endpoint_id,source,method,url,request_body,content_type
               ) VALUES(?,?,?,?,?,?,?)""",
            ("tx-shape", endpoint_id, "browser", "POST", "https://example.test/api/users/7",
             json.dumps({"display_name": "must-not-leak", "profile": {"age": 37},
                         "roles": ["admin-secret"]}), "application/json"),
        )

    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    task = next(item for item in agent.calls[0]["attack_tasks"]
                if item["endpoint_id"] == endpoint_id)
    shapes = task["source_context"]["request_shapes"]
    assert shapes == [{
        "method": "POST", "encoding": "json",
        "fields": {"display_name": "string", "profile": {"age": "number"},
                   "roles": {"type": "array", "item": "string"}},
    }]
    serialized = json.dumps(shapes)
    assert "must-not-leak" not in serialized
    assert "admin-secret" not in serialized


def test_terminal_coverage_can_be_explicitly_requeued_without_deleting_evidence(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    reopened = requeue_coverage(
        imported.pipeline_database, imported.scan_id, ["unsupported"],
        reason="planner now consumes complete Recon parameter context",
    )

    assert reopened == 4
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,count(*) FROM attack_coverage_items GROUP BY status"
        ).fetchall() == [("pending", 4)]
        assert conn.execute(
            "SELECT count(*) FROM attack_coverage_events WHERE next_status='pending'"
        ).fetchone() == (4,)
        assert conn.execute("SELECT count(*) FROM attack_tasks").fetchone() == (4,)


def test_disruptive_rate_and_concurrency_classes_are_scheduled_last(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.execute(
            "UPDATE attack_coverage_items SET vuln_class='brute_force', "
            "skill_name='hunt-brute-force' WHERE rowid=(SELECT max(rowid) FROM attack_coverage_items)"
        )
    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)
    first_batch_classes = {task["vuln_class"] for task in agent.calls[0]["attack_tasks"]}
    assert "brute_force" not in first_batch_classes


def test_each_batch_gives_distinct_vulnerability_classes_a_turn(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        rows = conn.execute(
            "SELECT coverage_id FROM attack_coverage_items ORDER BY rowid"
        ).fetchall()
        for (coverage_id,) in rows[:-1]:
            conn.execute(
                "UPDATE attack_coverage_items SET vuln_class='auth_bypass' "
                "WHERE coverage_id=?", (coverage_id,),
            )
        conn.execute(
            "UPDATE attack_coverage_items SET vuln_class='cors' WHERE coverage_id=?",
            (rows[-1][0],),
        )
    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert {task["vuln_class"] for task in agent.calls[0]["attack_tasks"]} == {
        "auth_bypass", "cors",
    }


def test_later_batches_prioritize_classes_without_a_prior_disposition(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        rows = conn.execute(
            "SELECT coverage_id FROM attack_coverage_items ORDER BY rowid"
        ).fetchall()
        assert len(rows) >= 4
        assignments = ("auth_bypass", "auth_bypass", "cors", "sqli")
        for (coverage_id,), vuln_class in zip(rows[:4], assignments, strict=True):
            conn.execute(
                "UPDATE attack_coverage_items SET vuln_class=?,skill_name=? "
                "WHERE coverage_id=?",
                (vuln_class, f"hunt-{vuln_class.replace('_', '-')}", coverage_id),
            )
    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=1,
    ).run(imported.scan_id)

    assert agent.calls[0]["attack_tasks"][0]["vuln_class"] == "auth_bypass"
    assert agent.calls[1]["attack_tasks"][0]["vuln_class"] == "cors"
    assert agent.calls[2]["attack_tasks"][0]["vuln_class"] == "sqli"


def test_exhaustive_interrupt_persists_retryable_recovery_state(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)

    class InterruptedAgent:
        def run_attack_orchestrator(self, **kwargs):
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        ExhaustiveAttackCoordinator(
            agent=InterruptedAgent(), db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent / "Scope.md",
            policy_path=imported.recon_database.parent / "TargetPolicy.json",
            batch_size=2,
        ).run(imported.scan_id)

    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM stage_runs WHERE stage='attack' ORDER BY rowid DESC LIMIT 1"
        ).fetchone() == ("failed",)
        assert conn.execute(
            "SELECT status,count(*) FROM attack_coverage_items GROUP BY status ORDER BY status"
        ).fetchall() == [("error_retryable", 2), ("pending", 2)]


def test_model_policy_refusal_without_requests_is_terminal_and_other_batches_continue(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)

    class RefusingAgent:
        calls = 0

        def run_attack_orchestrator(self, **kwargs):
            self.calls += 1
            error = RuntimeError("bounded model invocation was refused")
            error.failure_code = "model_policy_refusal"
            raise error

    agent = RefusingAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert agent.calls == 6
    assert result.coverage["by_status"] == {"unsupported": 4}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM attack_attempts").fetchone() == (0,)
        assert conn.execute(
            "SELECT DISTINCT status FROM stage_runs WHERE stage='attack'"
        ).fetchall() == [("completed",)]


@pytest.mark.parametrize("failure_code", ["model_capacity", "timeout"])
def test_transient_model_failure_retries_without_failing_pipeline(
    tmp_path: Path, failure_code: str,
) -> None:
    imported = imported_pipeline(tmp_path)

    class CapacityOnceAgent(UnsupportedCoverageAgent):
        def run_attack_orchestrator(self, **kwargs):
            if not self.calls:
                self.calls.append(kwargs)
                error = RuntimeError("transient model execution failure")
                error.failure_code = failure_code
                raise error
            return super().run_attack_orchestrator(**kwargs)

    agent = CapacityOnceAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert len(agent.calls) > 1
    assert result.coverage["by_status"] == {"unsupported": 4}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT DISTINCT status FROM stage_runs WHERE stage='attack'"
        ).fetchall() == [("completed",)]


@pytest.mark.parametrize("summary", [
    (
        "The single Attack Agent failed to start because its selected model "
        "was at capacity. Database verification found all configured tasks "
        "pending, with no attempts or HTTP requests for this stage."
    ),
    "The selected model is at capacity. Please try a different model.",
])
def test_structured_model_capacity_result_retries_without_failing_pipeline(
    tmp_path: Path, summary: str,
) -> None:
    imported = imported_pipeline(tmp_path)

    class StructuredCapacityOnceAgent(UnsupportedCoverageAgent):
        fallback_activated = False

        def activate_attack_fallback_model(self):
            self.fallback_activated = True
            return True

        def run_attack_orchestrator(self, **kwargs):
            if not self.calls:
                self.calls.append(kwargs)
                return AttackStageResult(
                    status="FAILED", scan_id=kwargs["scan_id"],
                    db_path=str(kwargs["db_path"]),
                    stage_run_id=kwargs["stage_run_id"],
                    attack_agent_ids=["capacity-agent"], summary=summary,
                )
            return super().run_attack_orchestrator(**kwargs)

    agent = StructuredCapacityOnceAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert len(agent.calls) > 1
    assert agent.fallback_activated is True
    assert len(agent.calls[1]["attack_tasks"]) == 2
    assert result.coverage["by_status"] == {"unsupported": 4}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT DISTINCT status FROM stage_runs WHERE stage='attack'"
        ).fetchall() == [("completed",)]


@pytest.mark.parametrize("summary", [
    (
        "Recon verified completed. The single Attack Agent failed "
        "following a cybersecurity safety rejection."
    ),
    (
        "The single Attack Agent failed because automatic cybersecurity "
        "review rejected its task. Verified DB state: one pending task."
    ),
    (
        "The single Attack Agent failed because automatic safety review flagged "
        "the delegated task for cybersecurity risk. Database verification shows "
        "the task remains pending, with no attempts or HTTP requests committed."
    ),
])
def test_structured_model_policy_refusal_isolated_without_stopping_coverage(
    tmp_path: Path, summary: str,
) -> None:
    imported = imported_pipeline(tmp_path)

    class StructuredRefusingAgent:
        calls = 0

        def run_attack_orchestrator(self, **kwargs):
            self.calls += 1
            return AttackStageResult(
                status="FAILED", scan_id=kwargs["scan_id"],
                db_path=str(kwargs["db_path"]),
                stage_run_id=kwargs["stage_run_id"],
                attack_agent_ids=[f"refusing-agent-{self.calls}"],
                summary=summary,
            )

    agent = StructuredRefusingAgent()
    result = ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    ).run(imported.scan_id)

    assert agent.calls == 6
    assert result.coverage["by_status"] == {"unsupported": 4}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM attack_attempts").fetchone() == (0,)
        assert conn.execute(
            "SELECT DISTINCT status FROM stage_runs WHERE stage='attack'"
        ).fetchall() == [("completed",)]


def test_retryable_coverage_is_replayed_one_task_at_a_time(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)

    class InterruptedAgent:
        def run_attack_orchestrator(self, **kwargs):
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        ExhaustiveAttackCoordinator(
            agent=InterruptedAgent(), db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent / "Scope.md",
            policy_path=imported.recon_database.parent / "TargetPolicy.json",
            batch_size=2,
        ).run(imported.scan_id)

    agent = UnsupportedCoverageAgent()
    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    assert [len(call["attack_tasks"]) for call in agent.calls] == [1, 1, 2]


def test_failed_batch_preserves_terminal_per_task_dispositions(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)

    class PartiallyCompletedAgent:
        def run_attack_orchestrator(self, **kwargs):
            first = kwargs["attack_tasks"][0]
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                first["task_id"], "skipped", "unsupported safe test contract",
            )
            raise RuntimeError("one sibling task failed")

    with pytest.raises(RuntimeError, match="sibling task failed"):
        ExhaustiveAttackCoordinator(
            agent=PartiallyCompletedAgent(), db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent / "Scope.md",
            policy_path=imported.recon_database.parent / "TargetPolicy.json",
            batch_size=2,
        ).run(imported.scan_id)

    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,count(*) FROM attack_coverage_items GROUP BY status ORDER BY status"
        ).fetchall() == [
            ("error_retryable", 1), ("pending", 2), ("unsupported", 1),
        ]


def test_unauthenticated_word_is_not_misclassified_as_auth_blocker(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ExhaustiveAttackCoordinator(
        agent=UnauthenticatedEvidenceAgent(), db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)
    assert coverage_status(
        imported.pipeline_database, imported.scan_id,
    ).by_status == {"unsupported": 4}


def test_opaque_credentials_reopen_only_compatible_auth_blockers(
    tmp_path: Path, monkeypatch,
) -> None:
    imported = imported_pipeline(tmp_path)
    ExhaustiveAttackCoordinator(
        agent=AuthBlockedCoverageAgent(), db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    with sqlite3.connect(imported.pipeline_database) as conn:
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="user-a",
            reference_uri="env://AIDAST_TEST_USER_A", identity_role="authenticated",
        )
    monkeypatch.setenv("AIDAST_TEST_USER_A", '{"Authorization":"Bearer test-a"}')
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        states = conn.execute(
            "SELECT vuln_class,status,count(*) FROM attack_coverage_items "
            "GROUP BY vuln_class,status ORDER BY vuln_class,status"
        ).fetchall()
    assert states == [("idor", "blocked_auth", 2), ("sqli", "pending", 2)]

    with sqlite3.connect(imported.pipeline_database) as conn:
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="user-b",
            reference_uri="env://AIDAST_TEST_USER_B", identity_role="authenticated",
        )
    monkeypatch.setenv("AIDAST_TEST_USER_B", '{"Authorization":"Bearer test-b"}')
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status,count(*) FROM attack_coverage_items GROUP BY status"
        ).fetchall() == [("pending", 4)]


def test_safe_local_mutation_skipped_without_binding_reopens_for_synthetic_session(
    tmp_path: Path, monkeypatch,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()
        conn.execute(
            "UPDATE endpoints SET normalized_path='/upload_profile_picture_url' WHERE endpoint_id=?",
            (row["endpoint_id"],),
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=row["skill_name"],
            endpoint_id=row["endpoint_id"], payload={"credential_references": []},
        )
        transition_coverage(
            conn, row["coverage_id"], "running", "fixture",
            stage_run_id=stage, task_id=task,
        )
        transition_coverage(
            conn, row["coverage_id"], "policy_excluded",
            "no synthetic account binding", stage_run_id=stage, task_id=task,
        )
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="synthetic",
            reference_uri="env://AIDAST_TEST_SYNTHETIC",
            identity_role="identity_synthetic",
        )
    monkeypatch.setenv(
        "AIDAST_TEST_SYNTHETIC", '{"Authorization":"Bearer synthetic"}',
    )

    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)

    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (row["coverage_id"],),
        ).fetchone() == ("pending",)


def test_merchant_login_reopens_after_disposable_merchant_is_bound(
    tmp_path: Path, monkeypatch,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()
        conn.execute(
            "UPDATE endpoints SET normalized_path='/api/v1/merchants/login' "
            "WHERE endpoint_id=?", (row["endpoint_id"],),
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=row["skill_name"],
            endpoint_id=row["endpoint_id"], payload={"credential_references": []},
        )
        transition_coverage(
            conn, row["coverage_id"], "running", "fixture",
            stage_run_id=stage, task_id=task,
        )
        transition_coverage(
            conn, row["coverage_id"], "policy_excluded",
            "[policy] no scanner-created synthetic merchant email is supplied",
            stage_run_id=stage, task_id=task,
        )
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="merchant-fixture",
            reference_uri="env://AIDAST_TEST_MERCHANT",
            identity_role="merchant_synthetic",
        )
        conn.execute(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
               VALUES ('merchant-fact',?,'owned_test_object','merchant.email',?,1.0)""",
            (imported.scan_id, json.dumps({
                "credential_label": "merchant-fixture", "resource": "merchant",
                "disposable": True, "cleanup_allowed": True,
                "value": "scanner@example.invalid",
            })),
        )
    monkeypatch.setenv(
        "AIDAST_TEST_MERCHANT", '{"Authorization":"Bearer merchant"}',
    )

    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)

    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (row["coverage_id"],),
        ).fetchone() == ("pending",)

    # A fully bound replay that remains inapplicable must not loop forever.
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.execute(
            """UPDATE attack_coverage_items SET status='policy_excluded',
               disposition_reason='no scanner-created synthetic merchant email is supplied',
               last_stage_run_id=?,last_task_id=? WHERE coverage_id=?""",
            (stage, task, row["coverage_id"]),
        )
        conn.execute(
            "UPDATE attack_tasks SET payload_json=? WHERE task_id=?",
            (json.dumps({"credential_references": [{
                "identity_role": "merchant_synthetic",
            }]}), task),
        )
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (row["coverage_id"],),
        ).fetchone() == ("policy_excluded",)


@pytest.mark.parametrize("terminal_status", ["tested_negative", "unsupported"])
def test_legacy_anonymous_auth_gate_reopens_once_session_is_available(
    tmp_path: Path, monkeypatch, terminal_status: str,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        coverage = conn.execute(
            "SELECT * FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=coverage["skill_name"],
            endpoint_id=coverage["endpoint_id"], payload={},
        )
        conn.execute(
            """UPDATE attack_coverage_items
               SET status=?,attempt_count=1,last_stage_run_id=?,last_task_id=?
               WHERE coverage_id=?""",
            (terminal_status, stage, task, coverage["coverage_id"]),
        )
        method = conn.execute(
            "SELECT method FROM endpoints WHERE endpoint_id=?",
            (coverage["endpoint_id"],),
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('auth-gate',?,?,?,?,?,'https://lab.example/gated',
                       ?,'completed',401,0,?,'{}')""",
            (
                imported.scan_id, stage, task, "policy", method, "f" * 64,
                coverage["endpoint_id"],
            ),
        )
        register_credential_reference(
            conn, scan_id=imported.scan_id, label="user-a",
            reference_uri="env://AIDAST_TEST_AUTH_GATE",
            identity_role="authenticated",
        )
    monkeypatch.setenv(
        "AIDAST_TEST_AUTH_GATE", '{"Authorization":"Bearer test-a"}',
    )

    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        assert requeue_auth_gated_negative_coverage(
            conn, imported.scan_id,
        ) == 1
        assert tuple(conn.execute(
            """SELECT status,attempt_count,last_stage_run_id,last_task_id
               FROM attack_coverage_items WHERE coverage_id=?""",
            (coverage["coverage_id"],),
        ).fetchone()) == ("pending", 0, None, None)

    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        assert requeue_auth_gated_negative_coverage(
            conn, imported.scan_id,
        ) == 0


def test_redacted_login_differential_reopens_once_for_secret_shape_assertion(
    tmp_path: Path,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        coverage = conn.execute(
            "SELECT * FROM attack_coverage_items WHERE vuln_class='sqli' LIMIT 1"
        ).fetchone()
        conn.execute(
            "UPDATE endpoints SET normalized_path='/login',method='POST' WHERE endpoint_id=?",
            (coverage["endpoint_id"],),
        )
        stage = start_stage_run(conn, scan_id=imported.scan_id, stage="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=coverage["skill_name"],
            endpoint_id=coverage["endpoint_id"], payload={},
        )
        transition_coverage(
            conn, coverage["coverage_id"], "running", "fixture",
            stage_run_id=stage, task_id=task,
        )
        transition_coverage(
            conn, coverage["coverage_id"], "unsupported",
            "broker redacted the credential marker", stage_run_id=stage, task_id=task,
        )
        for suffix, status, outcome in (("true", 200, "inconclusive"), ("false", 401, "negative")):
            fingerprint = ("a" if suffix == "true" else "b") * 64
            conn.execute(
                """INSERT INTO attack_attempts
                   (attempt_id,scan_id,task_id,skill_name,endpoint_id,
                    request_fingerprint,response_status,outcome)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    f"attempt-{suffix}", imported.scan_id, task,
                    coverage["skill_name"], coverage["endpoint_id"],
                    fingerprint, status, outcome,
                ),
            )
            conn.execute(
                """INSERT INTO attack_http_requests
                   (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                    request_fingerprint,status,response_status,scheduled_at,
                    endpoint_reference_id,result_json)
                   VALUES (?,?,?,?,?,'POST','https://lab.example/login',?,
                           'completed',?,0,?,'{"assertions":[]}')""",
                (
                    f"request-{suffix}", imported.scan_id, stage, task, "policy",
                    fingerprint, status, coverage["endpoint_id"],
                ),
            )
        assert requeue_redacted_login_differential_coverage(
            conn, imported.scan_id,
        ) == 1
        assert tuple(conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (coverage["coverage_id"],),
        ).fetchone()) == ("pending",)

        conn.execute(
            """UPDATE attack_coverage_items SET status='unsupported',
               disposition_reason='broker redacted the credential marker',
               last_stage_run_id=?,last_task_id=? WHERE coverage_id=?""",
            (stage, task, coverage["coverage_id"]),
        )
        conn.execute(
            """UPDATE attack_http_requests SET result_json=?
               WHERE request_id='request-true'""",
            (json.dumps({"assertions": [{
                "kind": "json_path_nonempty_string", "passed": True,
            }]}),),
        )
        assert requeue_redacted_login_differential_coverage(
            conn, imported.scan_id,
        ) == 0


def test_unreplayable_candidate_is_requeued_and_not_readopted(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        conn.row_factory = sqlite3.Row
        coverage = conn.execute(
            "SELECT * FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
        ).fetchone()
        transition_coverage(
            conn, coverage["coverage_id"], "running", "fixture execution",
        )
        finding_id = "finding_without_runtime_contract"
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,vuln_type,title,severity,endpoint_id)
               VALUES (?,?,?,'fixture','LOW',?)""",
            (finding_id, imported.scan_id, coverage["vuln_class"], coverage["endpoint_id"]),
        )
        attempt_id = "attempt_without_runtime_contract"
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,endpoint_id,skill_name,identity_role,
                request_fingerprint,payload_variant,outcome,finding_id)
               VALUES (?,?,?,?,?,'fixture','fixture','confirmed',?)""",
            (
                attempt_id, imported.scan_id, coverage["endpoint_id"],
                coverage["skill_name"], coverage["required_identity_role"], finding_id,
            ),
        )
        spec = canonical_reproduction_spec(
            finding_id=finding_id,
            attack_skill_name=coverage["skill_name"],
            endpoint_id=coverage["endpoint_id"], method="GET",
            endpoint_template="/fixture", injection_location="query",
            parameter_name=coverage["parameter_name"] or "fixture",
            payload_template={}, required_identity_roles=[],
            source_attempt_ids=[attempt_id], source_request_ids=[],
            source_policy_sha256="f" * 64,
        )
        conn.execute(
            """INSERT INTO finding_reproduction_specs
               (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
                injection_location,parameter_name,payload_template_json,
                required_identity_roles_json,source_attempt_ids_json,
                source_request_ids_json,payload_structure_sha256,
                source_policy_sha256,spec_sha256,runtime_contract_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (
                spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"],
                spec["method"], spec["endpoint_template"],
                spec["injection_location"], spec["parameter_name"],
                json.dumps(spec["payload_template"]),
                json.dumps(spec["required_identity_roles"]),
                json.dumps(spec["source_attempt_ids"]),
                json.dumps(spec["source_request_ids"]),
                spec["payload_structure_sha256"], spec["source_policy_sha256"],
                spec["spec_sha256"],
            ),
        )
        transition_coverage(
            conn, coverage["coverage_id"], "candidate", "fixture candidate",
            finding_id=finding_id,
        )

    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?",
            (coverage["coverage_id"],),
        ).fetchone() == ("pending",)


class StoppedProbeAgent(UnsupportedCoverageAgent):
    def __init__(self, *, status='outcome_unknown', finished=True, method='GET', risk='http_probe', foreign=False):
        super().__init__()
        self.status, self.finished, self.method, self.risk, self.foreign = status, finished, method, risk, foreign

    def run_attack_orchestrator(self, **kwargs):
        if self.calls:
            return super().run_attack_orchestrator(**kwargs)
        self.calls.append(kwargs)
        failed = kwargs['attack_tasks'][0]
        transition_task(kwargs['db_path'], kwargs['scan_id'], kwargs['stage_run_id'], failed['task_id'], 'running')
        transition_task(kwargs['db_path'], kwargs['scan_id'], kwargs['stage_run_id'], failed['task_id'], 'failed', 'Guarded probe timed out; response outcome remains unknown.')
        for task in kwargs['attack_tasks'][1:]:
            transition_task(kwargs['db_path'], kwargs['scan_id'], kwargs['stage_run_id'], task['task_id'], 'skipped', 'unsupported fixture test')
        with sqlite3.connect(kwargs['db_path']) as conn:
            conn.execute('''INSERT INTO attack_http_requests
                (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,request_fingerprint,status,risk_class,error_message,scheduled_at,finished_at)
                VALUES ('stopped-probe',?,?,?,'fixture-policy',?,'https://lab.example/api/users/1',?,?,?,'TimeoutError',0,?)''',
                (kwargs['scan_id'],kwargs['stage_run_id'],failed['task_id'],self.method,'e'*64,self.status,self.risk,1 if self.finished else None))
        return AttackStageResult(status='FAILED', scan_id='foreign-scan' if self.foreign else kwargs['scan_id'],
            db_path=str(kwargs['db_path']),stage_run_id=kwargs['stage_run_id'],attack_agent_ids=['coverage-agent'],
            summary='One stopped HTTP probe has an unknown response.')


def test_stopped_unknown_probe_is_kept_as_failed_while_other_coverage_continues(tmp_path):
    imported = imported_pipeline(tmp_path)
    agent = StoppedProbeAgent()
    result = ExhaustiveAttackCoordinator(agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent/'Scope.md', policy_path=imported.recon_database.parent/'TargetPolicy.json',
        batch_size=2).run(imported.scan_id)
    assert len(agent.calls) == 2
    assert result.coverage['unfinished'] == 0
    assert result.coverage['by_status'] == {'error_terminal':1,'unsupported':3}
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute("SELECT status,error_message FROM stage_runs WHERE stage_run_id=?", (result.stage_run_ids[0],)).fetchone() == ('completed',None)
        assert conn.execute("SELECT count(*) FROM audit_events WHERE stage_run_id=? AND event_type='stage.failed'", (result.stage_run_ids[0],)).fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM audit_events WHERE stage_run_id=? AND event_type='task.failed'", (result.stage_run_ids[0],)).fetchone() == (1,)
        assert conn.execute("SELECT status,error_message,response_status FROM attack_http_requests WHERE request_id='stopped-probe'").fetchone() == ('outcome_unknown','TimeoutError',None)
        status,reason,attempts = conn.execute("SELECT status,disposition_reason,attempt_count FROM attack_coverage_items WHERE last_task_id=?", (agent.calls[0]['attack_tasks'][0]['task_id'],)).fetchone()
        assert status == 'error_terminal' and attempts == 1
        assert 'stopped-probe' in reason and 'TimeoutError' in reason
        assert conn.execute('SELECT count(*) FROM findings').fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM attack_coverage_items WHERE status='tested_negative'").fetchone()[0] == 0


@pytest.mark.parametrize('status,finished,method,risk', [
    ('reserved', False, 'GET', 'http_probe'),
    ('running', False, 'GET', 'http_probe'),
    ('outcome_unknown', False, 'GET', 'http_probe'),
    ('outcome_unknown', True, 'POST', 'application_mutation'),
    ('outcome_unknown', True, 'GET', None),
])
def test_active_or_mutating_unknown_request_still_blocks_continuation(tmp_path,status,finished,method,risk):
    from aidast.orchestration.attack import AttackCoordinatorError
    imported = imported_pipeline(tmp_path)
    agent = StoppedProbeAgent(status=status,finished=finished,method=method,risk=risk)
    with pytest.raises(AttackCoordinatorError):
        ExhaustiveAttackCoordinator(agent=agent, db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent/'Scope.md', policy_path=imported.recon_database.parent/'TargetPolicy.json',
            batch_size=2, retry_limit=1).run(imported.scan_id)
    assert len(agent.calls) == 1
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT count(*) FROM stage_runs WHERE stage='attack' AND status='failed'"
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='stage.failed'"
        ).fetchone() == (1,)


def test_failed_result_with_foreign_envelope_still_stops_the_stage(tmp_path):
    from aidast.orchestration.attack import AttackCoordinatorError
    imported = imported_pipeline(tmp_path)
    agent = StoppedProbeAgent(foreign=True)
    with pytest.raises(AttackCoordinatorError, match='envelope mismatch'):
        ExhaustiveAttackCoordinator(agent=agent, db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent/'Scope.md', policy_path=imported.recon_database.parent/'TargetPolicy.json',
            batch_size=2).run(imported.scan_id)
    assert len(agent.calls) == 1
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT count(*) FROM stage_runs WHERE stage='attack' AND status='failed'"
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='stage.failed'"
        ).fetchone() == (1,)


def test_failed_result_omitting_new_finding_still_stops_the_stage(tmp_path: Path) -> None:
    from aidast.orchestration.attack import AttackCoordinatorError

    class MissingFindingAgent(StoppedProbeAgent):
        def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
            result = super().run_attack_orchestrator(**kwargs)
            with sqlite3.connect(kwargs["db_path"]) as conn:
                conn.execute(
                    """INSERT INTO findings
                       (finding_id,scan_id,title,vuln_type,severity,endpoint_id)
                       VALUES ('unreported-finding',?,'fixture','fixture','INFO',?)""",
                    (kwargs["scan_id"], kwargs["attack_tasks"][0]["endpoint_id"]),
                )
            return result

    imported = imported_pipeline(tmp_path)
    agent = MissingFindingAgent()
    with pytest.raises(AttackCoordinatorError, match="newly committed findings"):
        ExhaustiveAttackCoordinator(
            agent=agent, db_path=imported.pipeline_database,
            scope_path=imported.recon_database.parent / "Scope.md",
            policy_path=imported.recon_database.parent / "TargetPolicy.json",
            batch_size=2,
        ).run(imported.scan_id)

    assert len(agent.calls) == 1
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute(
            "SELECT status FROM stage_runs WHERE stage_run_id=?",
            (agent.calls[0]["stage_run_id"],),
        ).fetchone() == ("failed",)
        assert conn.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='stage.failed'"
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT finding_id FROM findings WHERE scan_id=?", (imported.scan_id,),
        ).fetchall() == [("unreported-finding",)]
        assert conn.execute(
            "SELECT status FROM attack_http_requests WHERE request_id='stopped-probe'"
        ).fetchone() == ("outcome_unknown",)


def test_last_failed_batch_does_not_leave_normal_attack_failed(tmp_path):
    from aidast.orchestration.attack import AttackCoordinator
    imported = imported_pipeline(tmp_path)
    agent = StoppedProbeAgent()
    result = AttackCoordinator(agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent/'Scope.md', policy_path=imported.recon_database.parent/'TargetPolicy.json').run(imported.scan_id)
    assert result.status == 'COMPLETED'
    assert len(agent.calls) == 1
    with sqlite3.connect(imported.pipeline_database) as conn:
        assert conn.execute("SELECT status FROM stage_runs WHERE stage_run_id=?", (result.stage_run_id,)).fetchone() == ('completed',)
        assert conn.execute("SELECT count(*) FROM stage_runs WHERE stage='attack' AND status='failed'").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM attack_http_requests WHERE status='outcome_unknown'").fetchone()[0] == 1
    status = coverage_status(imported.pipeline_database, imported.scan_id)
    assert status.unfinished == 0
    assert status.by_status == {'error_terminal':1,'unsupported':3}
