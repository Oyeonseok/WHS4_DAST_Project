from __future__ import annotations

import asyncio
import io
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aidast.recon.strix_engine.runtime import session_manager


def _proxy_dependencies() -> dict[str, str]:
    return {
        "core/request_governor.py": "# governor",
        "core/capture_receipt.py": "# receipt",
        "core/exclusion_guard.py": "# guard",
        "recon/tools/request_identity.py": "# identity",
    }


def test_mitm_start_failure_discards_session_and_stages_complete_runtime(
    monkeypatch,
) -> None:
    client = SimpleNamespace(
        delete=AsyncMock(),
        docker_client=SimpleNamespace(close=MagicMock()),
    )
    session = object()

    async def backend(**_kwargs):
        return client, session

    staged_members: set[str] = set()

    async def capture_archive(_session, archive: bytes) -> None:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r") as bundle:
            staged_members.update(bundle.getnames())

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="fixture")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: backend)
    monkeypatch.setattr(
        session_manager, "backend_supports_bind_mounts", lambda _name: True
    )
    monkeypatch.setattr(session_manager, "stage_extra_files", capture_archive)
    monkeypatch.setattr(
        session_manager,
        "_start_scope_mitmproxy",
        AsyncMock(side_effect=RuntimeError("proxy startup failed")),
    )

    with pytest.raises(RuntimeError, match="proxy startup failed"):
        asyncio.run(
            session_manager.create_or_reuse(
                "scan_failed_startup",
                image="fixture",
                local_sources=[],
                proxy_backend="mitmproxy",
                proxy_scope_rules={"allowed_hosts": ["example.com"]},
                proxy_addon_source="# addon",
                proxy_safety_source="# safety",
                proxy_dependency_sources=_proxy_dependencies(),
            )
        )

    assert staged_members == {
        ".aidast/ScopeRules.json",
        ".aidast/core/capture_receipt.py",
        ".aidast/core/exclusion_guard.py",
        ".aidast/core/http_safety.py",
        ".aidast/core/request_governor.py",
        ".aidast/recon/tools/mitm_addon.py",
        ".aidast/recon/tools/request_identity.py",
    }
    client.delete.assert_awaited_once_with(session)
    client.docker_client.close.assert_called_once_with()
    assert "scan_failed_startup" not in session_manager._SESSION_CACHE


def test_mitm_runtime_rejects_missing_dependency(monkeypatch) -> None:
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="fixture")),
    )
    dependencies = _proxy_dependencies()
    dependencies.pop("core/request_governor.py")

    with pytest.raises(ValueError, match="complete dependency-free proxy runtime"):
        asyncio.run(
            session_manager.create_or_reuse(
                "scan_incomplete_runtime",
                image="fixture",
                local_sources=[],
                proxy_backend="mitmproxy",
                proxy_scope_rules={"allowed_hosts": ["example.com"]},
                proxy_addon_source="# addon",
                proxy_safety_source="# safety",
                proxy_dependency_sources=dependencies,
            )
        )


def test_mitm_startup_uses_stable_ready_marker_and_reports_stdout() -> None:
    failed = SimpleNamespace(
        ok=lambda: False,
        stdout=b"addon dependency failed",
        stderr=b"",
    )
    session = SimpleNamespace(exec=AsyncMock(return_value=failed))

    with pytest.raises(RuntimeError, match="addon dependency failed"):
        asyncio.run(
            session_manager._start_scope_mitmproxy(
                session, capture_path="/workspace/capture.jsonl"
            )
        )

    startup_command = session.exec.await_args.args[2]
    assert "AIDAST_SCOPE_PROXY_READY" in startup_command
