from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.benchmarks.vulnbank import VulnBankBootstrapError, bootstrap_vulnbank
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db


def _pipeline(tmp_path: Path) -> tuple[Path, Path, Path]:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    recon = bundle / "Recon.db"
    conn = db.init_db(recon)
    db.insert_scan(conn, scan_id="scan_fixture", scope_type="lab", scope_value="scope")
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP "
        "WHERE scan_id='scan_fixture'"
    )
    conn.commit()
    conn.close()
    handoff = bundle / "Handoff.json"
    handoff.write_text(HandoffManifest(
        scan_id="scan_fixture", db_path="Recon.db",
        artifacts=[hash_artifact(recon, root=bundle, role="database")],
    ).model_dump_json(), encoding="utf-8")
    pipeline = tmp_path / "Pipeline.db"
    materialize_pipeline(handoff, pipeline)
    scope = tmp_path / "Scope.md"
    scope.write_text(
        "Bounded active security testing with PUT, PATCH, and DELETE against "
        "disposable local lab fixtures is authorized; state may be reset between cases.",
        encoding="utf-8",
    )
    policy = tmp_path / "TargetPolicy.json"
    policy.write_text(json.dumps({"policies": [{
        "scope_id": "scope", "policy_id": "policy", "asset_type": "URL",
        "asset": "http://127.0.0.1:5001/", "allowed_schemes": ["http"],
        "allowed_hosts": ["127.0.0.1"], "allowed_ports": [5001],
        "allowed_path_prefixes": ["/"], "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "attack_allowed_methods": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
        "attack_authorization_mode": "active_non_destructive",
        "attack_authorization_evidence": "fixture", "limits": {}, "tools": {},
        "api_probe": {},
    }]}), encoding="utf-8")
    return pipeline, scope, policy


def test_bootstrap_keeps_tokens_out_of_database(tmp_path: Path, monkeypatch) -> None:
    pipeline, scope, policy = _pipeline(tmp_path)
    counter = {"user": 0, "merchant": 0}

    def transport(url: str, payload: dict[str, object]) -> dict[str, object]:
        if url.endswith("/register") and "/merchants/" not in url:
            counter["user"] += 1
            return {"debug_data": {
                "account_number": f"account-{counter['user']}",
                "user_id": counter["user"],
            }}
        if url.endswith("/login"):
            return {"token": f"user-secret-{counter['user']}"}
        counter["merchant"] += 1
        return {"token": f"merchant-secret-{counter['merchant']}",
                "merchant": {"id": counter["merchant"]}}

    result = bootstrap_vulnbank(
        pipeline, scan_id="scan_fixture", target_url="http://127.0.0.1:5001/",
        scope_path=scope, policy_path=policy, transport=transport,
    )
    assert result["credential_reference_count"] == 5
    raw = pipeline.read_bytes()
    assert b"user-secret" not in raw
    assert b"merchant-secret" not in raw
    with sqlite3.connect(pipeline) as conn:
        assert conn.execute(
            "SELECT count(*) FROM credential_references WHERE reference_uri LIKE 'env://%'"
        ).fetchone() == (5,)
        assert conn.execute(
            "SELECT count(*) FROM attack_facts WHERE fact_type='owned_test_object'"
        ).fetchone() == (8,)

    repeated = bootstrap_vulnbank(
        pipeline, scan_id="scan_fixture", target_url="http://127.0.0.1:5001/",
        scope_path=scope, policy_path=policy, transport=transport,
    )
    assert repeated["credential_reference_count"] == 5
    with sqlite3.connect(pipeline) as conn:
        assert conn.execute("SELECT count(*) FROM credential_references").fetchone() == (5,)


def test_bootstrap_records_two_disposable_card_ids_without_card_secrets(
    tmp_path: Path,
) -> None:
    pipeline, scope, policy = _pipeline(tmp_path)
    counter = {"user": 0, "merchant": 0, "card": 0}

    def transport(url: str, payload: dict[str, object]) -> dict[str, object]:
        if url.endswith("/register") and "/merchants/" not in url:
            counter["user"] += 1
            return {"debug_data": {
                "account_number": f"account-{counter['user']}",
                "user_id": counter["user"],
            }}
        if url.endswith("/login"):
            return {"token": f"user-secret-{counter['user']}"}
        counter["merchant"] += 1
        return {"token": f"merchant-secret-{counter['merchant']}",
                "merchant": {"id": counter["merchant"]}}

    def authenticated_transport(
        url: str, payload: dict[str, object], headers: dict[str, str],
    ) -> dict[str, object]:
        assert headers["Authorization"].startswith("Bearer user-secret-")
        if url.endswith("/request_loan"):
            assert payload == {"amount": "123.45"}
            return {"status": "success"}
        assert url.endswith("/api/virtual-cards/create")
        counter["card"] += 1
        return {"card_details": {
            "id": 100 + counter["card"], "card_number": "must-not-be-stored",
            "cvv": "999",
        }}

    def read_transport(url: str, headers: dict[str, str]) -> dict[str, object]:
        assert headers == {}
        if url.endswith("/api/bill-categories"):
            return {"categories": [{"id": 7, "name": "fixture"}]}
        assert url.endswith("/api/billers/by-category/7")
        return {"billers": [{"id": 9, "name": "fixture"}]}

    def text_read_transport(url: str, headers: dict[str, str]) -> str:
        assert url.endswith("/sup3r_s3cr3t_admin?loan_page=1")
        assert headers == {"Authorization": "Bearer user-secret-3"}
        return """
        <tr>
          <td>#77</td>
          <td>1</td>
          <td class="mono balance-cell">$123.45</td>
          <td><span>pending</span></td>
        </tr>
        """

    result = bootstrap_vulnbank(
        pipeline, scan_id="scan_fixture", target_url="http://127.0.0.1:5001/",
        scope_path=scope, policy_path=policy, transport=transport,
        authenticated_transport=authenticated_transport,
        read_transport=read_transport,
        text_read_transport=text_read_transport,
    )
    assert result["owned_test_object_count"] == 12
    raw = pipeline.read_bytes()
    assert b"must-not-be-stored" not in raw
    with sqlite3.connect(pipeline) as conn:
        assert conn.execute(
            "SELECT fact_key FROM attack_facts WHERE fact_key LIKE '%.card_id' ORDER BY fact_key"
        ).fetchall() == [
            ("admin-a.card_id",), ("user-a.card_id",), ("user-b.card_id",),
        ]
        assert conn.execute(
            "SELECT fact_key,json_extract(fact_value,'$.object_id') "
            "FROM attack_facts WHERE fact_key LIKE '%.loan_id'"
        ).fetchall() == [("user-a.loan_id", "77")]
        assert conn.execute(
            "SELECT fact_key FROM attack_facts WHERE fact_type='benchmark_fixture' "
            "ORDER BY fact_key"
        ).fetchall() == [("biller.biller_id",), ("category.category_id",)]


def test_bootstrap_rejects_non_loopback(tmp_path: Path) -> None:
    pipeline, scope, policy = _pipeline(tmp_path)
    with pytest.raises(VulnBankBootstrapError, match="loopback-only"):
        bootstrap_vulnbank(
            pipeline, scan_id="scan_fixture", target_url="https://example.com/",
            scope_path=scope, policy_path=policy, transport=lambda *_: {},
        )
