import base64
import json
import time

from aidast.recon.strix_engine.config import codex


def _access_token(expires_at: int) -> str:
    payload = json.dumps({"exp": expires_at}).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"header.{encoded}.signature"


def _write_codex_auth(path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "auth_mode": "chatgpt",
        "tokens": {"access_token": token, "account_id": "account-test", "refresh_token": "unused"},
    }), encoding="utf-8")


def test_strix_uses_codex_cli_login_without_copying_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "strix" / "subscription-auth.json")
    auth_path = tmp_path / "codex" / "auth.json"
    token = _access_token(int(time.time()) + 3600)
    _write_codex_auth(auth_path, token)
    original = auth_path.read_bytes()

    assert codex.is_authenticated()
    assert codex.get_valid_token() == (token, "account-test")
    assert auth_path.read_bytes() == original
    assert not codex.AUTH_PATH.exists()


def test_strix_asks_codex_to_refresh_expiring_cli_token(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "strix" / "subscription-auth.json")
    auth_path = tmp_path / "codex" / "auth.json"
    _write_codex_auth(auth_path, _access_token(int(time.time()) + 10))
    refreshed = _access_token(int(time.time()) + 3600)
    calls = []

    def refresh():
        calls.append(True)
        _write_codex_auth(auth_path, refreshed)

    monkeypatch.setattr(codex, "_refresh_codex_cli_auth", refresh, raising=False)
    assert codex.get_valid_token() == (refreshed, "account-test")
    assert calls == [True]


def test_strix_prefers_its_own_login_when_both_exist(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "strix" / "subscription-auth.json")
    _write_codex_auth(tmp_path / "codex" / "auth.json", _access_token(int(time.time()) + 3600))
    codex.save_record({
        "type": "oauth", "access": "strix-access", "refresh": "strix-refresh",
        "account_id": "strix-account", "expires_at": time.time() + 3600,
    })

    assert codex.get_valid_token() == ("strix-access", "strix-account")


def test_strix_ignores_invalid_codex_login(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "strix" / "subscription-auth.json")
    _write_codex_auth(tmp_path / "codex" / "auth.json", "broken.token.signature")

    assert not codex.is_authenticated()
