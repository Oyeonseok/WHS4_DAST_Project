"""Operator confirmation identity and expiry tests using local metadata only."""

from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from aidast.auth.manual_login import ManualLoginGate, ManualLoginStore


@pytest.mark.parametrize("operation", ["begin", "confirm"])
def test_mutation_returns_its_own_request_when_replaced_after_commit(
    tmp_path, monkeypatch, operation,
):
    store = ManualLoginStore(tmp_path)
    first = store.begin("scan_one", "https://example.test", 30)
    original_connect = store._connect
    replacement = None

    @contextmanager
    def replace_after_commit():
        nonlocal replacement
        with original_connect() as connection:
            yield connection
        if replacement is None:
            replacement = {}
            replacement = store.begin("scan_one", "https://other.test", 30)

    monkeypatch.setattr(store, "_connect", replace_after_commit)
    if operation == "begin":
        result = store.begin("scan_one", "https://example.test", 30)
        assert result["status"] == "waiting"
    else:
        result = store.confirm("scan_one", first["request_id"])
        assert result["request_id"] == first["request_id"]
        assert result["status"] == "confirmed"
    assert result["target_origin"] == "https://example.test"
    assert result["request_id"] != replacement["request_id"]
    assert store.read("scan_one")["request_id"] == replacement["request_id"]


def test_replaced_request_cannot_be_adopted_by_gate(tmp_path, monkeypatch):
    store = ManualLoginStore(tmp_path)
    original_begin = store.begin
    replacement = None

    def replace_before_wait(*args, **kwargs):
        nonlocal replacement
        first = original_begin(*args, **kwargs)
        replacement = original_begin("scan_one", "https://other.test", 30)
        store.confirm("scan_one", replacement["request_id"])
        return first

    monkeypatch.setattr(store, "begin", replace_before_wait)
    check = Mock(return_value=None)
    gate = ManualLoginGate(store, "scan_one", "https://example.test")
    with pytest.raises(RuntimeError, match="request was replaced"):
        gate.wait(check)
    check.assert_not_called()
    assert store.read("scan_one")["request_id"] == replacement["request_id"]
    assert store.read("scan_one")["status"] == "confirmed"


def test_confirmation_cannot_be_accepted_at_expiry_boundary(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr("aidast.auth.manual_login.time.time", lambda: now[0])
    store = ManualLoginStore(tmp_path)
    request = store.begin("scan_one", "https://example.test", 30)
    store.confirm("scan_one", request["request_id"])
    now[0] = 130.0
    with pytest.raises(ValueError):
        store.finish("scan_one", request["request_id"], "accepted")
    current = store.read("scan_one")
    assert current["status"] == "expired"
    assert current["auth_state"] is None


def test_gate_preserves_browser_error_when_cleanup_request_is_replaced(
    tmp_path, monkeypatch,
):
    store = ManualLoginStore(tmp_path)
    original_begin, original_finish = store.begin, store.finish
    replacement = None

    def confirmed_begin(*args, **kwargs):
        request = original_begin(*args, **kwargs)
        store.confirm("scan_one", request["request_id"])
        return request

    def replaced_finish(scan_id, request_id, status):
        nonlocal replacement
        if status == "failed":
            replacement = original_begin("scan_one", "https://other.test", 30)
        return original_finish(scan_id, request_id, status)

    monkeypatch.setattr(store, "begin", confirmed_begin)
    monkeypatch.setattr(store, "finish", replaced_finish)
    gate = ManualLoginGate(store, "scan_one", "https://example.test")
    check = Mock(side_effect=RuntimeError("browser check failed"))
    with pytest.raises(RuntimeError, match="browser check failed"):
        gate.wait(check)
    current = store.read("scan_one")
    assert current["request_id"] == replacement["request_id"]
    assert current["status"] == "waiting"
    assert current["auth_state"] is None
