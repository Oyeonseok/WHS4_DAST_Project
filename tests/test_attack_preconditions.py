from __future__ import annotations

import sqlite3

from aidast.attack.coverage import ensure_coverage_manifest
from aidast.attack.preconditions import (
    acknowledge_operator_action,
    list_operator_actions,
    resolve_attack_preconditions,
)
from aidast.pipeline.lifecycle import register_credential_reference
from test_attack_coverage import imported_pipeline


def _authenticated_coverage(conn: sqlite3.Connection) -> tuple[str, str]:
    row = conn.execute(
        "SELECT coverage_id,vuln_class FROM attack_coverage_items ORDER BY coverage_id LIMIT 1"
    ).fetchone()
    conn.execute(
        """UPDATE attack_coverage_items
           SET required_identity_role='authenticated',status='blocked_auth',
               disposition_reason='[auth] no usable same-origin credential reference'
           WHERE coverage_id=?""", (row[0],),
    )
    return str(row[0]), str(row[1])


def test_explicit_auth_blocker_creates_durable_operator_action(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        coverage_id, _ = _authenticated_coverage(conn)
        first = resolve_attack_preconditions(conn, imported.scan_id)
        second = resolve_attack_preconditions(conn, imported.scan_id)
        actions = list_operator_actions(conn, imported.scan_id)

        assert first.discovered >= 1
        assert first.actions_created >= 1
        assert second.discovered == 0
        assert second.actions_created == 0
        assert {action["coverage_id"] for action in actions} == {coverage_id}
        assert all(action["status"] == "pending" for action in actions)
        assert "credential reference" not in str(actions).casefold()


def test_operator_acknowledgement_never_claims_missing_evidence(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        coverage_id, _ = _authenticated_coverage(conn)
        resolve_attack_preconditions(conn, imported.scan_id)
        action_id = list_operator_actions(conn, imported.scan_id)[0]["action_id"]

        result = acknowledge_operator_action(
            conn, imported.scan_id, action_id, operator="test-operator",
        )

        assert result["action"]["status"] == "acknowledged"
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?", (coverage_id,),
        ).fetchone()[0] == "blocked_auth"


def test_two_usable_opaque_identities_satisfy_idor_and_requeue(
    tmp_path, monkeypatch,
) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    monkeypatch.setenv("AIDAST_PRECONDITION_A", '{"Authorization":"Bearer a"}')
    monkeypatch.setenv("AIDAST_PRECONDITION_B", '{"Authorization":"Bearer b"}')
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """SELECT coverage_id FROM attack_coverage_items
               WHERE vuln_class='idor' ORDER BY coverage_id LIMIT 1"""
        ).fetchone()
        coverage_id = str(row[0])
        conn.execute(
            """UPDATE attack_coverage_items
               SET required_identity_role='authenticated',status='blocked_auth',
                   disposition_reason='IDOR requires a second identity'
               WHERE coverage_id=?""", (coverage_id,),
        )
        for suffix in ("A", "B"):
            register_credential_reference(
                conn, scan_id=imported.scan_id, label=f"identity-{suffix.lower()}",
                reference_uri=f"env://AIDAST_PRECONDITION_{suffix}",
                identity_role="authenticated",
            )

        result = resolve_attack_preconditions(conn, imported.scan_id)

        assert result.satisfied == 2
        assert result.coverage_requeued == 1
        assert conn.execute(
            "SELECT status FROM attack_coverage_items WHERE coverage_id=?", (coverage_id,),
        ).fetchone()[0] == "pending"
        assert conn.execute(
            """SELECT count(*) FROM attack_preconditions
               WHERE coverage_id=? AND state='satisfied'""", (coverage_id,),
        ).fetchone()[0] == 2
