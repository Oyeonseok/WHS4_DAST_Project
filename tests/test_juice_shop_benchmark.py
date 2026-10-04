from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aidast.benchmarks.juice_shop import (
    _scope_authorizes_disposable_fixtures,
    bootstrap_juice_shop,
)
from aidast.pipeline.schema import migrate_pipeline_schema
from aidast.recon import db
from aidast.validation.execution.credentials import PipelineCredentialResolver


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    database = tmp_path / "Pipeline.db"
    conn = db.init_db(database)
    db.insert_scan(conn, scan_id="scan_juice", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(
        conn, scan_id="scan_juice", identifier="http://127.0.0.1:5001/", asset_type="URL",
    )
    db.upsert_origin(
        conn, asset_id=asset, scheme="http", host="127.0.0.1", port=5001,
        base_url="http://127.0.0.1:5001/",
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan_juice'"
    )
    migrate_pipeline_schema(conn)
    conn.commit()
    conn.close()
    scope = tmp_path / "Scope.md"
    scope.write_text(
        "OWASP Juice Shop local lab. 스캐너가 생성한 합성 계정과 "
        "일회성 데이터에 한해 폼 제출을 허용합니다.",
        encoding="utf-8",
    )
    policy = tmp_path / "TargetPolicy.json"
    policy.write_text(json.dumps({"policies": [{
        "scope_id": "scope", "policy_id": "policy", "asset_type": "URL",
        "asset": "http://127.0.0.1:5001/", "allowed_schemes": ["http"],
        "allowed_hosts": ["127.0.0.1"], "allowed_ports": [5001],
        "allowed_path_prefixes": ["/"], "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "attack_allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
        "attack_authorization_mode": "active_non_destructive",
        "attack_authorization_evidence": "fixture", "limits": {}, "tools": {},
        "api_probe": {},
    }]}), encoding="utf-8")
    return database, scope, policy, tmp_path / "result"


def test_disposable_juice_fixture_authorization_supports_approved_scope_locales() -> None:
    assert _scope_authorizes_disposable_fixtures(
        "Scanner-created synthetic accounts and disposable data are authorized."
    )
    assert _scope_authorizes_disposable_fixtures(
        "스캐너가 생성한 합성 계정과 일회성 데이터에 한해 허용합니다."
    )
    assert not _scope_authorizes_disposable_fixtures(
        "OWASP Juice Shop testing is allowed without account creation."
    )


def test_bootstrap_persists_three_opaque_sessions_without_secrets(tmp_path: Path) -> None:
    database, scope, policy, result_root = _fixture(tmp_path)
    counter = {"user": 0}
    secrets_seen: list[str] = []

    def transport(url: str, method: str, payload: dict[str, object] | None) -> dict[str, object]:
        if url.endswith("/api/SecurityQuestions"):
            return {"data": [{"id": 1}]}
        if url.endswith("/api/Users"):
            counter["user"] += 1
            return {"data": {"id": counter["user"]}}
        token = f"header.account-{counter['user']}.signature"
        secrets_seen.append(token)
        return {"authentication": {"token": token, "bid": counter["user"] + 10}}

    result = bootstrap_juice_shop(
        database, scan_id="scan_juice", target_url="http://127.0.0.1:5001/",
        scope_path=scope, policy_path=policy, result_root=result_root,
        transport=transport,
    )
    assert result == {
        "credential_reference_count": 3,
        "owned_test_object_count": 6,
        "roles": ["authenticated", "identity_b", "identity_synthetic"],
        "reused": False,
    }
    raw_database = database.read_bytes()
    assert all(secret.encode() not in raw_database for secret in secrets_seen)
    with sqlite3.connect(database) as conn:
        rows = conn.execute(
            "SELECT credential_reference_id,identity_role FROM credential_references ORDER BY identity_role"
        ).fetchall()
        assert len(rows) == 3
        assert conn.execute(
            "SELECT count(*) FROM attack_facts WHERE fact_type='owned_test_object'"
        ).fetchone() == (6,)
    resolver = PipelineCredentialResolver(
        database, result_root=result_root, browser_sessions=True,
    )
    headers = {
        role: resolver(reference, destination_url="http://127.0.0.1:5001/rest/user/whoami")
        for reference, role in rows
    }
    assert {value["Authorization"] for value in headers.values()} == {
        f"Bearer {secret}" for secret in secrets_seen
    }

    def no_more_requests(*_args, **_kwargs):
        raise AssertionError("available private sessions must be reused")

    repeated = bootstrap_juice_shop(
        database, scan_id="scan_juice", target_url="http://127.0.0.1:5001/",
        scope_path=scope, policy_path=policy, result_root=result_root,
        transport=no_more_requests,
    )
    assert repeated["reused"] is True
