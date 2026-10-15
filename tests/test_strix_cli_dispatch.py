import asyncio
import runpy
import json
import sqlite3
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlsplit

import pytest

from aidast.cli import (
    _parser, _run_recon, _validate_strix_recon_options,
    _validate_strix_recon_targets,
)
from aidast.orchestration.recon import ReconCoordinatorError
from aidast.recon.strix_bridge import _safe_agent_event_sink, build_strix_proxy_rules, run_strix_recon
from aidast.recon.strix_integration import StrixReconExecutor, persist_strix_capture
from aidast.recon.api_spec_ingestion import _matching_rule
from aidast.recon.policy import RequestGovernorBinding, TargetPolicy
from aidast.core.request_governor import RequestGovernor
from aidast.scope.models import RequestLimit
from aidast.scope.models import AssetType


def _args(**overrides):
    return SimpleNamespace(login_mode="none", diagnostic_logs=False, **overrides)


def _policy(asset="http://127.0.0.1:15002"):
    parsed = urlsplit(asset)
    return TargetPolicy.model_validate({
        "scope_id": "scope_test", "policy_id": "policy_test",
        "asset_type": "URL", "asset": asset,
        "allowed_hosts": [parsed.hostname], "allowed_schemes": [parsed.scheme],
        "allowed_ports": [parsed.port or (443 if parsed.scheme == "https" else 80)],
    })


def test_strix_executor_calls_embedded_engine_for_loopback(tmp_path, capsys):
    args = _parser().parse_args([
        "recon", "https://program.example", "--execute", "--target",
        "http://127.0.0.1:15002", "--login-mode", "none",
        "--recon-engine", "strix",
    ])
    assert args.recon_engine == "strix"
    scope = SimpleNamespace(scope_id="scope_test")
    targets = [SimpleNamespace(asset_type=AssetType.URL, asset="http://127.0.0.1:15002")]
    run = AsyncMock(return_value=(object(), tmp_path / "capture.jsonl", {}))
    persist = MagicMock(return_value={"observed": 1, "blocked": 0, "endpoints": 1})
    progress = MagicMock()
    with patch(
        "aidast.recon.strix_integration.run_strix_recon", run
    ), patch(
        "aidast.recon.strix_integration.persist_strix_capture", persist,
    ):
        executor = StrixReconExecutor(
            scan_id="scan_test", scope_document=scope, selected_targets=targets,
            target_policies=[_policy()], start_urls={},
            request_headers={"X-Test": "ok"}, db_path=tmp_path / "Recon.db",
            surface_path=tmp_path / "Surface.json",
            capture_directory=tmp_path / "logs/scan_test/recon-capture",
            diagnostic_logs=False,
            recon_model="chatgpt/gpt-6-luna",
            progress_callback=progress,
        )
        try:
            assert executor.run([]) == 0
        finally:
            executor.close()
    assert run.await_args.args == (scope, targets)
    assert run.await_args.kwargs["capture_directory"] == tmp_path / "logs/scan_test/recon-capture"
    assert run.await_args.kwargs["request_headers"] == {"X-Test": "ok"}
    assert "read_only" not in run.await_args.kwargs
    assert "target_policies" not in run.await_args.kwargs
    assert "max_requests" not in run.await_args.kwargs
    assert run.await_args.kwargs["model"] == "chatgpt/gpt-6-luna"
    assert run.await_args.kwargs["progress_callback"] is progress
    assert run.await_args.kwargs["allow_authorized_account_registration"] is False
    assert persist.call_args.kwargs["scope_id"] == "scope_test"
    assert persist.call_args.kwargs["capture_path"] == tmp_path / "capture.jsonl"
    assert persist.call_args.kwargs["manage_lifecycle"] is False
    assert "endpoints=1" in capsys.readouterr().out


def test_strix_executor_passes_explicit_registration_option(tmp_path):
    args = _parser().parse_args([
        "recon", "https://program.example", "--execute", "--all-targets",
        "--recon-engine", "strix", "--allow-authorized-account-registration",
    ])
    assert args.allow_authorized_account_registration is True
    _validate_strix_recon_options(args)
    run = AsyncMock(return_value=(object(), tmp_path / "capture.jsonl", {}))
    with patch("aidast.recon.strix_integration.run_strix_recon", run), patch(
        "aidast.recon.strix_integration.persist_strix_capture",
        return_value={"observed": 1, "blocked": 0, "endpoints": 1},
    ):
        executor = StrixReconExecutor(
            scan_id="scan_test", scope_document=SimpleNamespace(scope_id="scope_test"),
            selected_targets=[SimpleNamespace(asset_type=AssetType.URL, asset="https://example.com")],
            target_policies=[_policy("https://example.com")], start_urls={},
            request_headers={}, db_path=tmp_path / "Recon.db",
            surface_path=tmp_path / "Surface.json", capture_directory=tmp_path,
            diagnostic_logs=False, allow_authorized_account_registration=True,
        )
        try:
            assert executor.run([]) == 0
        finally:
            executor.close()
    assert run.await_args.kwargs["allow_authorized_account_registration"] is True
    assert "First discover read-only" in run.await_args.kwargs["user_instructions"]


def test_strix_runtime_proxy_uses_scope_methods_without_policy_caps():
    scope = SimpleNamespace(analysis=SimpleNamespace(
        allowed_activities=[], prohibited_activities=[], operational_constraints=[],
        ambiguities=[], out_of_scope_assets=[],
    ), source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="https://example.com")
    rules = build_strix_proxy_rules(scope, [target])
    assert "POST" in rules["allowed_methods"]
    assert "max_requests" not in rules
    assert "max_rps" not in rules


def test_strix_safe_event_sink_counts_completed_tools_without_diagnostics(tmp_path):
    counts = []
    sink = _safe_agent_event_sink(None, progress_callback=lambda count, activity: counts.append((count, activity)))
    call = SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(
        type="tool_call_item", raw_item=SimpleNamespace(call_id="call-1", name="browser"),
    ))
    result = SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(
        type="tool_call_output_item", raw_item=SimpleNamespace(call_id="call-1", output="secret"),
    ))

    sink("agent-1", call)
    sink("agent-1", result)
    sink("agent-1", result)

    assert counts == [(1, "browser"), (2, "browser")]
    assert list(tmp_path.iterdir()) == []


def test_strix_safe_event_sink_only_publishes_known_activity_names():
    activities = []
    sink = _safe_agent_event_sink(None, progress_callback=lambda count, activity: activities.append((count, activity)))
    for index, name in enumerate(("aidast_view_captured_request", "unexpected_secret_tool"), 1):
        call_id = f"call-{index}"
        sink("agent-1", SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(
            type="tool_call_item", raw_item=SimpleNamespace(call_id=call_id, name=name),
        )))
        sink("agent-1", SimpleNamespace(type="run_item_stream_event", item=SimpleNamespace(
            type="tool_call_output_item", raw_item=SimpleNamespace(call_id=call_id, output="secret"),
        )))
    assert activities == [(1, "capture_review"), (2, "tool_work")]


@pytest.mark.parametrize(("image_override", "configured_image", "expected_image"), [
    (None, "ghcr.io/usestrix/strix-sandbox:1.3.0", "aidast-strix-mitm:local"),
    ("custom-mitm:latest", "ghcr.io/usestrix/strix-sandbox:1.3.0", "custom-mitm:latest"),
    (None, "configured-mitm:latest", "configured-mitm:latest"),
])
def test_strix_bridge_passes_selected_model_to_engine(
    tmp_path, monkeypatch, image_override, configured_image, expected_image,
):
    if image_override is None:
        monkeypatch.delenv("AIDAST_STRIX_IMAGE", raising=False)
    else:
        monkeypatch.setenv("AIDAST_STRIX_IMAGE", image_override)
    run = AsyncMock(return_value=object())
    settings_module = types.ModuleType("aidast.recon.strix_engine.config")
    settings_module.load_settings = lambda: SimpleNamespace(
        runtime=SimpleNamespace(image=configured_image),
        llm=SimpleNamespace(api_key=None, model=None),
    )
    settings_module.codex = SimpleNamespace(is_authenticated=lambda: True)
    runner_module = types.ModuleType("aidast.recon.strix_engine.core.runner")
    runner_module.run_strix_scan = run
    with patch("aidast.recon.strix_bridge.build_strix_proxy_rules", return_value={}), patch(
        "aidast.recon.strix_bridge.build_strix_scan_config", return_value={}
    ), patch.dict(sys.modules, {
        "aidast.recon.strix_engine.config": settings_module,
        "aidast.recon.strix_engine.core.runner": runner_module,
    }):
        asyncio.run(run_strix_recon(
            SimpleNamespace(), [], scan_id="scan_test", capture_directory=tmp_path,
            model="chatgpt/gpt-6-luna",
        ))
    assert run.await_args.kwargs["model"] == "chatgpt/gpt-6-luna"
    assert run.await_args.kwargs["image"] == expected_image
    assert callable(run.await_args.kwargs["event_sink"])


@pytest.mark.parametrize(("model", "api_key", "authenticated", "expected"), [
    ("gpt-6-luna", None, True, "chatgpt/gpt-6-luna"),
    ("gpt-6-luna", "api-key", True, "gpt-6-luna"),
    ("gpt-6-luna", None, False, "gpt-6-luna"),
    ("chatgpt/gpt-6-luna", None, True, "chatgpt/gpt-6-luna"),
    ("openai/gpt-6-luna", None, True, "openai/gpt-6-luna"),
])
def test_strix_bridge_routes_selected_model_with_codex_login(
    tmp_path, monkeypatch, model, api_key, authenticated, expected,
):
    monkeypatch.delenv("AIDAST_STRIX_IMAGE", raising=False)
    run = AsyncMock(return_value=object())
    settings_module = types.ModuleType("aidast.recon.strix_engine.config")
    settings_module.load_settings = lambda: SimpleNamespace(
        runtime=SimpleNamespace(image="aidast-strix-mitm:local"),
        llm=SimpleNamespace(api_key=api_key, model=None),
    )
    settings_module.codex = SimpleNamespace(is_authenticated=lambda: authenticated)
    runner_module = types.ModuleType("aidast.recon.strix_engine.core.runner")
    runner_module.run_strix_scan = run
    with patch("aidast.recon.strix_bridge.build_strix_proxy_rules", return_value={}), patch(
        "aidast.recon.strix_bridge.build_strix_scan_config", return_value={}
    ), patch.dict(sys.modules, {
        "aidast.recon.strix_engine.config": settings_module,
        "aidast.recon.strix_engine.core.runner": runner_module,
    }):
        asyncio.run(run_strix_recon(
            SimpleNamespace(), [], scan_id="scan_test", capture_directory=tmp_path,
            model=model,
        ))
    assert run.await_args.kwargs["model"] == expected


def test_strix_accepts_approved_external_url_target():
    _validate_strix_recon_targets(
        [SimpleNamespace(asset_type=AssetType.URL, asset="https://example.com")],
        {},
    )


def test_strix_proxy_accepts_external_target_policy():
    scope = SimpleNamespace(analysis=SimpleNamespace(
        allowed_activities=[], prohibited_activities=[], operational_constraints=[],
        ambiguities=[], out_of_scope_assets=[],
    ), source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="https://example.com/app")
    rules = build_strix_proxy_rules(
        scope, [target], read_only=True, max_requests=10,
        target_policies=[_policy(target.asset)],
    )
    assert rules["target_rules"][0]["host_pattern"] == "example.com"
    assert rules["allowed_methods"] == ["GET", "HEAD", "OPTIONS"]
    assert rules["timeout_seconds"] == 20


def test_strix_rejects_start_url_on_other_port():
    with pytest.raises(ReconCoordinatorError, match="selected target origin"):
        _validate_strix_recon_targets(
            [SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")],
            {("url", "http://localhost:15002"): "http://localhost:15003/"},
        )


def test_strix_option_requires_execute():
    args = _parser().parse_args([
        "recon", "https://program.example", "--recon-engine", "strix",
    ])
    with pytest.raises(ReconCoordinatorError, match="requires recon --execute"):
        _run_recon(args)
    integrated = _parser().parse_args([
        "run", "https://program.example", "--target", "http://localhost:15002",
        "--recon-engine", "strix",
    ])
    assert integrated.recon_engine == "strix"


def test_strix_accepts_policy_limits_without_proxy_enforcement():
    _validate_strix_recon_options(_args(timeout_seconds=1, max_depth=1,
                                       profile="bug-bounty-safe"))


def test_strix_preview_proxy_rules_are_bounded():
    analysis = SimpleNamespace(
        allowed_activities=[], prohibited_activities=[], operational_constraints=[],
        ambiguities=[], out_of_scope_assets=[],
    )
    scope = SimpleNamespace(analysis=analysis, source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    rules = build_strix_proxy_rules(scope, [target], read_only=True, max_requests=10)
    assert rules["allowed_methods"] == ["GET", "HEAD", "OPTIONS"]
    assert rules["allowed_ports"] == [15002]
    assert rules["max_requests"] == 10


def test_strix_preview_does_not_override_scope_scheme_prohibition():
    analysis = SimpleNamespace(
        allowed_activities=[], prohibited_activities=["HTTP is prohibited"],
        operational_constraints=[], ambiguities=[], out_of_scope_assets=[],
    )
    scope = SimpleNamespace(analysis=analysis, source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    with pytest.raises(ValueError, match="scheme is prohibited"):
        build_strix_proxy_rules(scope, [target], read_only=True, max_requests=10)


def test_strix_proxy_intersects_target_policy_and_alias_exclusions():
    analysis = SimpleNamespace(
        allowed_activities=[], prohibited_activities=[], operational_constraints=[],
        ambiguities=[], out_of_scope_assets=[],
    )
    scope = SimpleNamespace(analysis=analysis, source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    data = _policy(target.asset).model_dump()
    data.update(allowed_methods=["GET"], allowed_path_prefixes=["/api"],
                excluded_path_prefixes=["/api/admin"])
    data["limits"].update(max_requests=7, requests_per_second=2, concurrency=1)
    policy = TargetPolicy.model_validate(data)

    rules = build_strix_proxy_rules(
        scope, [target], read_only=True, max_requests=10,
        target_policies=[policy],
    )

    assert rules["max_requests"] == 7
    assert rules["max_rps"] == 2
    assert rules["max_concurrency"] == 1
    assert rules["allowed_methods"] == ["GET"]
    assert any(rule["host_pattern"] == "host.docker.internal"
               and rule["paths"] == ["/api/admin"]
               for rule in rules["excluded_target_rules"])


def test_strix_proxy_allows_shared_quotas_without_enforcing_them(tmp_path):
    scope = SimpleNamespace(
        analysis=SimpleNamespace(
            allowed_activities=[], prohibited_activities=[], operational_constraints=[],
            ambiguities=[], out_of_scope_assets=[],
        ), source=None,
    )
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    binding = RequestGovernorBinding(
        ledger_path=str(tmp_path / "budget.db"), scan_id="scan_test",
        program_id="program_test", scan_max_requests=10,
        requests_per_second=1, concurrency=1,
        request_limits=[RequestLimit(
            maximum=2, period_seconds=60.0, scope="program",
            source_quote="Two requests per minute",
        )],
    )
    policy = _policy(target.asset).model_copy(update={"request_governor": binding})
    rules = build_strix_proxy_rules(
        scope, [target], read_only=True, max_requests=10,
        target_policies=[policy],
    )
    assert rules["max_requests"] == 10
    assert rules["max_rps"] == 1
    assert "request_limits" not in rules


def test_strix_proxy_does_not_reject_disabled_ffuf_tool():
    scope = SimpleNamespace(analysis=SimpleNamespace(
        allowed_activities=[], prohibited_activities=[], operational_constraints=[],
        ambiguities=[], out_of_scope_assets=[],
    ), source=None)
    target = SimpleNamespace(asset_type=AssetType.URL, asset="https://example.com")
    policy = _policy(target.asset)
    policy = policy.model_copy(update={
        "tools": policy.tools.model_copy(update={"ffuf_enabled": False}),
    })
    rules = build_strix_proxy_rules(
        scope, [target], read_only=True, max_requests=10,
        target_policies=[policy],
    )
    assert rules["allowed_hosts"] == ["example.com"]


def test_scope_proxy_blocks_after_request_cap():
    proxy = types.ModuleType("mitmproxy")
    proxy.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
    proxy.http = SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status),
    ))
    addon_path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
    with patch.dict(sys.modules, {"mitmproxy": proxy}):
        addon = runpy.run_path(str(addon_path))["ScopeAndCaptureAddon"]()
    addon.scope_loaded = True
    addon.allowed_hosts = {"localhost"}
    addon.rules = {
        "allowed_hosts": ["localhost"], "allowed_schemes": ["http"],
        "allowed_ports": [15002], "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/"], "max_requests": 1,
    }

    def flow():
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_url="http://localhost:15002/", method="GET", headers={},
            ),
            metadata={}, response=None,
        )

    first, second = flow(), flow()
    asyncio.run(addon.request(first))
    asyncio.run(addon.request(second))
    assert first.response is None
    assert addon.request_count == 1
    assert second.response.status_code == 403
    assert second.metadata["aidast_block_reason"] == "request_limit"


def test_scope_proxy_accepts_strix_rules_without_request_cap():
    proxy = types.ModuleType("mitmproxy")
    proxy.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
    proxy.http = SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status),
    ))
    addon_path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
    with patch.dict(sys.modules, {"mitmproxy": proxy}):
        addon = runpy.run_path(str(addon_path))["ScopeAndCaptureAddon"]()
    addon.scope_loaded = True
    addon.allowed_hosts = {"localhost"}
    addon.rules = {
        "allowed_hosts": ["localhost"], "allowed_schemes": ["http"],
        "allowed_ports": [15002], "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/"],
    }
    for _ in range(2):
        flow = SimpleNamespace(
            request=SimpleNamespace(
                pretty_url="http://localhost:15002/", method="GET", headers={},
            ), metadata={}, response=None,
        )
        asyncio.run(addon.request(flow))
        assert flow.response is None
    assert addon.request_count == 2


def test_scope_proxy_paces_strix_rate_and_concurrency_limits():
    proxy = types.ModuleType("mitmproxy")
    proxy.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
    proxy.http = SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status),
    ))
    addon_path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
    with patch.dict(sys.modules, {"mitmproxy": proxy}):
        addon = runpy.run_path(str(addon_path))["ScopeAndCaptureAddon"]()
    addon.scope_loaded = True
    addon.allowed_hosts = {"localhost"}
    addon.rules = {
        "allowed_hosts": ["localhost"], "allowed_schemes": ["http"],
        "allowed_ports": [15002], "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/"], "max_requests": 10,
        "max_rps": 20, "max_concurrency": 1, "timeout_seconds": 2,
    }

    def flow():
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_url="http://localhost:15002/", method="GET", headers={},
            ), metadata={}, response=None,
        )

    first, second, third = (flow() for _ in range(3))

    async def exercise():
        await addon.request(first)
        second_task = asyncio.create_task(addon.request(second))
        await asyncio.sleep(0.02)
        assert not second_task.done()
        addon.response(first)
        await second_task
        addon.response(second)
        await addon.request(third)

    asyncio.run(exercise())
    assert all(item.response is None for item in (first, second, third))
    assert addon.request_count == 3
    assert third.metadata["aidast_scope_allowed"] is True


def test_scope_proxy_serves_browser_asset_burst_without_rate_blocks():
    import time

    proxy = types.ModuleType("mitmproxy")
    proxy.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
    proxy.http = SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status),
    ))
    addon_path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
    with patch.dict(sys.modules, {"mitmproxy": proxy}):
        addon = runpy.run_path(str(addon_path))["ScopeAndCaptureAddon"]()
    addon.scope_loaded = True
    addon.allowed_hosts = {"localhost"}
    addon.rules = {
        "allowed_hosts": ["localhost"], "allowed_schemes": ["http"],
        "allowed_ports": [15002], "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/"], "max_requests": 10,
        "max_rps": 20, "max_concurrency": 2, "timeout_seconds": 2,
    }
    flows = [SimpleNamespace(
        request=SimpleNamespace(
            pretty_url=f"http://localhost:15002/asset{index}.js", method="GET", headers={},
        ), metadata={}, response=None,
    ) for index in range(6)]
    dispatch_times = []

    async def send(flow):
        await addon.request(flow)
        dispatch_times.append(time.monotonic())
        addon.response(flow)

    async def exercise():
        await asyncio.gather(*(send(flow) for flow in flows))

    asyncio.run(exercise())

    assert addon.request_count == 6
    assert all(flow.response is None for flow in flows)
    assert min(b - a for a, b in zip(dispatch_times, dispatch_times[1:])) >= 0.035


def test_scope_proxy_stops_waiting_at_policy_timeout():
    proxy = types.ModuleType("mitmproxy")
    proxy.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
    proxy.http = SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status),
    ))
    addon_path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
    with patch.dict(sys.modules, {"mitmproxy": proxy}):
        addon = runpy.run_path(str(addon_path))["ScopeAndCaptureAddon"]()
    addon.scope_loaded = True
    addon.allowed_hosts = {"localhost"}
    addon.rules = {
        "allowed_hosts": ["localhost"], "allowed_schemes": ["http"],
        "allowed_ports": [15002], "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/"], "max_requests": 10,
        "max_rps": 0.5, "max_concurrency": 2, "timeout_seconds": 1,
    }

    def flow():
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_url="http://localhost:15002/main.js", method="GET", headers={},
            ), metadata={}, response=None,
        )

    first, waiting = flow(), flow()

    async def exercise():
        await addon.request(first)
        await addon.request(waiting)

    asyncio.run(exercise())
    assert addon.request_count == 1
    assert waiting.metadata["aidast_block_reason"] == "admission_timeout"


def test_strix_capture_populates_recon_db_and_surface(tmp_path):
    scope = SimpleNamespace(
        analysis=SimpleNamespace(
            allowed_activities=[], prohibited_activities=[], operational_constraints=[],
            ambiguities=[], out_of_scope_assets=[SimpleNamespace(
                asset_type=AssetType.URL, asset="http://localhost:15002/admin",
            )],
        ), source=None,
    )
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    rules = build_strix_proxy_rules(scope, [target], read_only=True, max_requests=10)
    capture = tmp_path / "mitm_capture.jsonl"
    records = [
        {"url": "http://host.docker.internal:15002/api/items?id=1", "method": "GET",
         "scope_allowed": True, "response_status": 200, "source_tool": "agent-browser",
         "discovered_forms": [{
             "action": "http://host.docker.internal:15002/admin", "method": "GET",
             "parameters": [],
         }]},
        {"url": "http://evil.example/data", "method": "GET",
         "scope_allowed": True, "response_status": 200},
    ]
    capture.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    db_path = tmp_path / "Recon.db"
    surface_path = tmp_path / "Surface.json"

    counts = persist_strix_capture(
        scan_id="scan_test", scope_id="scope_test", capture_path=capture,
        db_path=db_path, surface_path=surface_path, rules=rules,
    )

    assert counts["observed"] == 1
    assert counts["blocked"] == 1
    assert counts["endpoints"] == 1
    assert _matching_rule("http://host.docker.internal:15002/admin", "GET", rules) is None
    surface = json.loads(surface_path.read_text(encoding="utf-8"))
    assert surface["origins"][0]["base_url"] == "http://localhost:15002"
    assert surface["origins"][0]["endpoints"][0]["path"] == "/api/items"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT status FROM scans WHERE scan_id='scan_test'").fetchone()[0] == "completed"
        assert conn.execute("SELECT url FROM http_transactions").fetchone()[0] == "http://localhost:15002/api/items?id=1"


def test_strix_executor_ingestion_is_visible_to_common_recon_lifecycle(tmp_path):
    scope = SimpleNamespace(
        scope_id="scope_test",
        analysis=SimpleNamespace(
            allowed_activities=[], prohibited_activities=[], operational_constraints=[],
            ambiguities=[], out_of_scope_assets=[],
        ), source=None,
    )
    target = SimpleNamespace(asset_type=AssetType.URL, asset="http://localhost:15002")
    rules = build_strix_proxy_rules(scope, [target], read_only=True, max_requests=10)
    capture = tmp_path / "mitm_capture.jsonl"
    capture.write_text(json.dumps({
        "url": "http://host.docker.internal:15002/api", "method": "GET",
        "scope_allowed": True, "response_status": 200,
    }) + "\n", encoding="utf-8")
    executor = StrixReconExecutor(
        scan_id="scan_test", scope_document=scope, selected_targets=[target],
        target_policies=[_policy(target.asset)], start_urls={},
        request_headers=None, db_path=tmp_path / "Recon.db",
        surface_path=tmp_path / "Surface.json",
        capture_directory=tmp_path, diagnostic_logs=False,
    )
    try:
        with patch("aidast.recon.strix_integration.run_strix_recon",
                   new=AsyncMock(return_value=(object(), capture, rules))):
            assert executor.run([]) == 0
        assert executor.conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] == 1
        assert executor.conn.execute("SELECT status FROM scans").fetchone()[0] == "running"
        assert not (tmp_path / "Surface.json").exists()
    finally:
        executor.close()
