"""Authenticated BOLA lab contracts require a real cross-owner marker."""

from pathlib import Path
import shutil
import sqlite3

from aidast.validation.contracts.runtime_semantics import validate_runtime_semantics
from aidast.validation.contracts.runtime_contract import validate_runtime_contract
from aidast.validation.core.profiles import SkillProfileResolver

from scripts.validation_auth_lab import AUTH_CASES, ORDER_A, ORDER_B, auth_contract, control_response_matches, ensure_fixture, observe_fixture, score_auth_cases, verify_source_guards


def test_three_auth_contracts_have_distinct_target_and_negative_requests() -> None:
    profile = SkillProfileResolver().resolve("hunt-idor").profile
    for case in AUTH_CASES:
        endpoint, runtime = auth_contract(case, a_id=1, b_id=2, a_payment=1,
                                          b_payment=2)
        parsed = validate_runtime_contract(runtime)
        validate_runtime_semantics(parsed, profile)
        assert endpoint.startswith("/api/v1/payments")
        assert parsed.target.assertions == parsed.negative_control.assertions
        assert parsed.target.request != parsed.negative_control.request


def test_source_guards_bind_exact_pinned_routes() -> None:
    source = Path(__file__).resolve().parents[1] / "result/lab/vuln-bank/merchant_payments.py"
    assert verify_source_guards(source)
    modified = source.read_text().replace("WHERE mp.merchant_id = {merchant_id}",
                                          "WHERE mp.merchant_id = {current_merchant['id']}")
    assert not verify_source_guards(modified)


def test_prepare_creates_two_idempotent_declined_payment_markers(monkeypatch) -> None:
    import scripts.validation_auth_lab as lab

    payments = {"A": [], "B": []}
    posted = []

    def fake_fetch(path, *, api_key=None, payload=None):
        if path == "/api/v1/payments":
            return 200, {"payments": payments[api_key]}, "a" * 64, 10
        assert path == "/api/v1/payments/charge"
        assert payload["card_number"] == "0000000000000000"
        posted.append((api_key, payload["merchant_order_id"]))
        payments[api_key].insert(0, {"id": len(posted), "merchant_id": 1 if api_key == "A" else 2,
                                     "merchant_order_id": payload["merchant_order_id"],
                                     "payment_status": "failed"})
        return 400, {"failure_reason": "invalid_card_number", "payment_id": len(posted)}, "b" * 64, 10

    monkeypatch.setattr(lab, "_fetch", fake_fetch)
    monkeypatch.setattr(lab, "verify_runtime_identity", lambda: {"pinned": True})
    roles = {"a": {"id": 1, "key": "A"}, "b": {"id": 2, "key": "B"}}
    ensure_fixture(roles)
    ensure_fixture(roles)
    assert posted == [("A", ORDER_A), ("B", ORDER_B)]


def test_fixture_setup_checks_runtime_identity_before_post(monkeypatch) -> None:
    import pytest
    import scripts.validation_auth_lab as lab

    def reject_runtime():
        raise ValueError("wrong running image")

    monkeypatch.setattr(lab, "verify_runtime_identity", reject_runtime)
    monkeypatch.setattr(lab, "_fetch", lambda *args, **kwargs: pytest.fail("request sent before runtime check"))
    with pytest.raises(ValueError, match="wrong running image"):
        ensure_fixture({"a": {"id": 1, "key": "A"}, "b": {"id": 2, "key": "B"}})


def test_observation_records_all_control_response_digests(monkeypatch) -> None:
    import hashlib
    import scripts.validation_auth_lab as lab

    own = {"id": 1, "merchant_id": 1, "merchant_order_id": ORDER_A}
    foreign = {"id": 2, "merchant_id": 2, "merchant_order_id": ORDER_B}

    def fake_fetch(path, *, api_key=None, payload=None):
        if path == "/api/v1/payments":
            body = {"payments": [own] if api_key == "A" else [foreign]}
            status = 200
        elif path == "/api/v1/payments?probe=inert":
            body, status = {"payments": [own]}, 200
        elif path == "/api/v1/payments/1":
            body, status = {"payment": own}, 200
        elif path == "/api/v1/payments/2":
            body, status = ({"payment": foreign}, 200) if api_key == "B" else ({"status": "error"}, 404)
        elif path == "/api/v1/payments/999999":
            body, status = {"status": "error"}, 404
        elif path == "/api/v1/payments/merchant_id/1":
            body, status = {"merchant_id": 1, "payments": [own]}, 200
        elif path == "/api/v1/payments/merchant_id/2":
            body, status = {"merchant_id": 2, "payments": [foreign]}, 200
        elif path == "/api/v1/payments/merchant_id/999999":
            body, status = {"merchant_id": 999999, "payments": []}, 200
        else:
            raise AssertionError(path)
        return status, body, hashlib.sha256((path + api_key).encode()).hexdigest(), 10

    monkeypatch.setattr(lab, "_fetch", fake_fetch)
    result = observe_fixture({"a": {"id": 1, "key": "A"}, "b": {"id": 2, "key": "B"}})
    assert len(result["controls"]) == 3
    assert all(set(pair) == {"positive_control", "negative_control"}
               for pair in result["controls"].values())
    assert result["controls"]["detail"]["positive_control"]["status"] == 200
    assert result["controls"]["detail"]["negative_control"]["status"] == 404


def test_query_control_matches_raw_response_url_and_digest() -> None:
    expected = {"path": "/api/v1/payments?probe=inert", "status": 200,
                "sha256": "a" * 64}
    details = {"response_status": 200,
               "response_url": "http://127.0.0.1:5001/api/v1/payments?probe=inert",
               "response_body_sha256": "a" * 64}
    assert control_response_matches(details, expected)
    assert not control_response_matches({**details, "response_body_sha256": "b" * 64}, expected)


def test_independent_score_rejects_missing_control_request_ledger(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates/validation-auth-run-20260926-v2"
    if not source.exists():
        import pytest
        pytest.skip("local authenticated Agent experiment is unavailable")
    bundle = tmp_path / "tampered"
    shutil.copytree(source, bundle)
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        row = conn.execute(
            """SELECT h.request_id FROM validation_http_requests h
               JOIN validation_attempts a ON a.attempt_id=h.attempt_id
               JOIN validation_cases c ON c.case_id=a.case_id
               WHERE c.finding_id='auth-finding-d1fbeb605d692465'
                 AND a.attempt_kind='negative_control'"""
        ).fetchone()
        assert row is not None
        conn.execute("UPDATE validation_http_requests SET status='failed' WHERE request_id=?", row)
    scored = score_auth_cases(bundle, live_check=False)
    by_id = {item["candidate_id"]: item for item in scored["rows"]}
    assert by_id["vuln-bank:case:GET:/api/v1/payments/<int:payment_id>:bola"]["result"] == "UNSUPPORTED_EVIDENCE"
