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
    requeue_coverage,
    resolve_abandoned_attack_leads,
    transition_coverage,
    _credential_role,
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


def test_coverage_task_exposes_all_db_parameters_and_source_context(tmp_path: Path) -> None:
    imported = imported_pipeline(tmp_path)
    agent = UnsupportedCoverageAgent()

    ExhaustiveAttackCoordinator(
        agent=agent, db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=4,
    ).run(imported.scan_id)

    task = next(item for item in agent.calls[0]["attack_tasks"]
                if item["vuln_class"] == "sqli")
    assert {(item["location"], item["name"]) for item in task["parameter_candidates"]} == {
        ("json", "display_name"), ("path", "user_id"), ("query", "q"),
    }
    assert sum(bool(item["preferred"]) for item in task["parameter_candidates"]) == 1
    assert task["source_context"]["active_annotation"]["tag"] == "sqli"
    assert "SQL injection" in task["source_context"]["active_annotation"]["rationale"]


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
    assert states == [("idor", "blocked_auth", 2), ("sqli", "blocked_auth", 2)]

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
        ).fetchall() == [("blocked_auth", 2), ("pending", 2)]


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
