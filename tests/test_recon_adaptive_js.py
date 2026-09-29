"""Sparse SPA Recon extracts bounded, verified first-party API candidates."""

from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools import endpoint_discovery as discovery
from unittest.mock import MagicMock
import pytest
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


def test_sparse_surface_recovers_api_paths_from_first_party_script(monkeypatch) -> None:
    requested = []

    def fake_request(url, **_kwargs):
        requested.append(url)
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/products"); fetch("/rest/users");'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "text/html"}, b"missing"
        return 200, {"content-type": "application/json"}, b'{"items":[]}'

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    discover = getattr(secondary, "discover_adaptive_js_api_candidates", None)

    assert discover is not None
    results = discover(
        "https://example.test/",
        [{"method": "GET", "path": "/main.js", "url": "https://example.test/main.js"}],
    )
    assert {item["path"] for item in results} == {"/api/products", "/rest/users"}
    assert all(item["source"] == "adaptive_js" for item in results)
    assert len(requested) <= 5


def test_dense_surface_verifies_new_query_conditions_on_a_seen_path(monkeypatch) -> None:
    requested = []

    def fake_request(url, **kwargs):
        requested.append((url, kwargs.get("method", "GET")))
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/seen"); fetch("/api/new")'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        return 200, {"content-type": "application/json"}, b'{"data":[]}'

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    observed = [{"method": "GET", "path": "/main.js", "url": "https://example.test/main.js"}]
    observed += [{"method": "GET", "path": f"/api/route{i}"} for i in range(10)]
    observed.append({"method": "GET", "path": "/api/seen", "url": "https://example.test/api/seen?view=full"})
    results = secondary.discover_adaptive_js_api_candidates("https://example.test/", observed)

    assert {item["path"] for item in results} == {"/api/new", "/api/seen"}
    assert requested.count(("https://example.test/api/seen", "GET")) == 1
    assert not any(url.endswith("/api/seen?view=full") for url, _ in requested)
    assert all(method == "GET" for _, method in requested)


def test_spa_fallback_response_is_not_accepted_as_api(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/missing")'
        return 200, {"content-type": "text/html"}, b"SPA shell"

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    discover = getattr(secondary, "discover_adaptive_js_api_candidates", None)

    assert discover is not None
    assert discover(
        "https://example.test/",
        [{"method": "GET", "path": "/main.js", "url": "https://example.test/main.js"}],
    ) == []


def test_candidate_is_not_accepted_when_missing_route_control_fails(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/items")'
        if "__aidast_missing_control__" in url:
            return None, {}, b""
        return 200, {"content-type": "application/json"}, b'{"items":[]}'

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    assert secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    ) == []


def test_reflected_html_fallback_is_not_an_api_candidate(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/items")'
        return 200, {"content-type": "text/html"}, ("No route: " + url).encode()

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    assert secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    ) == []


def test_reflected_json_missing_route_is_not_an_api_candidate(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/items")'
        return 200, {"content-type": "application/json"}, ('{"error":"No route: ' + url + '"}').encode()

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    assert secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    ) == []


def test_collection_response_supplies_real_id_for_detail_get(monkeypatch) -> None:
    requested = []

    def fake_request(url, **kwargs):
        requested.append((url, kwargs.get("method", "GET")))
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/Products")'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        if url.endswith("/api/Products"):
            return 200, {"content-type": "application/json"}, b'{"status":"success","data":[{"id":7,"name":"Apple"},{"id":8,"name":"Pear"}]}'
        if url.endswith("/api/Products/7"):
            return 200, {"content-type": "application/json"}, b'{"status":"success","data":{"id":7,"name":"Apple"}}'
        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    )

    assert {item["path"] for item in results} == {"/api/Products", "/api/Products/7"}
    assert ("https://example.test/api/Products/7", "GET") in requested
    assert all(method == "GET" for _, method in requested)


def test_collection_detail_probe_rejects_untrusted_ids_and_error_responses(monkeypatch) -> None:
    requested = []

    def fake_request(url, **_kwargs):
        requested.append(url)
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/Products")'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        if url.endswith("/api/Products"):
            return 200, {"content-type": "application/json"}, b'{"data":[{"id":"../admin"},{"id":true},{"id":9}]}'
        if url.endswith("/api/Products/9"):
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    )

    assert [item["path"] for item in results] == ["/api/Products"]
    assert "https://example.test/api/Products/9" in requested
    assert not any("admin" in url for url in requested)


def test_collection_detail_rejects_json_200_fallback(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/Products")'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        if url.endswith("/api/Products"):
            return 200, {"content-type": "application/json"}, b'{"data":[{"id":7}]}'
        if url.endswith("/api/Products/7"):
            return 200, {"content-type": "application/json"}, b'{"error":"No route: /api/Products/7"}'
        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    )
    assert [item["path"] for item in results] == ["/api/Products"]


def test_collection_detail_requires_id_field_even_when_selected_id_is_none_text(monkeypatch) -> None:
    def fake_request(url, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, b'fetch("/api/Products")'
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        if url.endswith("/api/Products"):
            return 200, {"content-type": "application/json"}, b'{"data":[{"id":"None"}]}'
        if url.endswith("/api/Products/None"):
            return 200, {"content-type": "application/json"}, b'{"message":"fallback"}'
        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/",
        [{"path": "/main.js", "url": "https://example.test/main.js"}],
    )
    assert [item["path"] for item in results] == ["/api/Products"]


def test_endpoint_discovery_feeds_adaptive_candidates_to_final_surface(monkeypatch) -> None:
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    driver.get_auth_headers.return_value = {}
    driver.get_chrome_ws_url.return_value = "ws://127.0.0.1/devtools"
    monkeypatch.setattr(discovery, "PlaywrightDriver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(discovery, "discover_with_katana", lambda *_args, **_kwargs: [
        {"method": "GET", "path": "/main.js", "url": "https://example.test/main.js", "source": "katana"}
    ])
    monkeypatch.setattr(discovery, "discover_with_ffuf", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_api_secondary", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_adaptive_js_api_candidates", lambda *_args, **_kwargs: [
        {"method": "GET", "path": "/api/products", "url": "https://example.test/api/products", "source": "adaptive_js"}
    ], raising=False)

    results = discovery.discover_endpoints(
        "https://example.test/", ffuf_wordlist=None,
        enable_playwright_interaction=False,
    )

    assert any(item["path"] == "/api/products" for item in results)


def test_endpoint_discovery_hands_katana_isolated_cdp_and_closes_it(monkeypatch) -> None:
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    driver.get_auth_headers.return_value = {}
    lease = MagicMock(chrome_ws_url="ws://127.0.0.1/isolated")
    calls = []
    monkeypatch.setattr(discovery, "PlaywrightDriver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(discovery, "open_katana_browser", lambda *_args, **_kwargs: lease, raising=False)
    monkeypatch.setattr(discovery, "discover_with_katana", lambda *_args, **kwargs: calls.append(kwargs) or [])
    monkeypatch.setattr(discovery, "discover_with_ffuf", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_api_secondary", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_adaptive_js_api_candidates", lambda *_args, **_kwargs: [])

    discovery.discover_endpoints("https://example.test/", ffuf_wordlist=None,
                                 enable_playwright_interaction=False)

    assert [call["chrome_ws_url"] for call in calls if call["mode"] == "headless"] == [lease.chrome_ws_url]
    lease.close.assert_called_once()
    driver.pause_policy_routing.assert_not_called()
    driver.resume_policy_routing.assert_not_called()


def test_endpoint_discovery_falls_back_to_headers_when_clone_unavailable(monkeypatch) -> None:
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    driver.get_auth_headers.return_value = {"Authorization": "Bearer private"}
    calls = []
    diagnostics = []
    def fake_katana(*_args, **kwargs):
        calls.append(kwargs)
        if kwargs["mode"] == "headless":
            kwargs["diagnostic_callback"]("tool_error", mode="headless", error_type="TimeoutExpired")
        return []
    monkeypatch.setattr(discovery, "PlaywrightDriver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(discovery, "open_katana_browser", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(discovery, "discover_with_katana", fake_katana)
    monkeypatch.setattr(discovery, "discover_with_ffuf", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_api_secondary", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_adaptive_js_api_candidates", lambda *_args, **_kwargs: [])

    discovery.discover_endpoints("https://example.test/", ffuf_wordlist=None,
                                 enable_playwright_interaction=False,
                                 diagnostic_callback=lambda event, **details: diagnostics.append((event, details)))

    headless = next(call for call in calls if call["mode"] == "headless")
    assert headless["chrome_ws_url"] is None
    assert headless["auth_headers"] == {"Authorization": "Bearer private"}
    assert any(event == "phase_error" and details.get("phase") == "katana_headless"
               and details.get("error_type") == "TimeoutExpired" for event, details in diagnostics)
    driver.pause_policy_routing.assert_not_called()
    driver.resume_policy_routing.assert_not_called()


def test_api_spec_candidate_is_observed_but_not_promoted_to_verified_surface(monkeypatch) -> None:
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    driver.get_auth_headers.return_value = {}
    driver.get_chrome_ws_url.return_value = "ws://127.0.0.1/devtools"
    monkeypatch.setattr(discovery, "PlaywrightDriver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(discovery, "discover_with_katana", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_with_ffuf", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_adaptive_js_api_candidates", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_api_secondary", lambda *_args, **_kwargs: [
        {"method": "GET", "path": "/b2b", "url": "https://example.test/b2b",
         "source": "zap_openapi", "verification_status": "candidate",
         "discovery_kind": "api_spec_candidate"},
    ])
    observations = []

    results = discovery.discover_endpoints(
        "https://example.test/", ffuf_wordlist=None,
        enable_playwright_interaction=False,
        observation_callback=lambda phase, items: observations.append((phase, items)),
    )

    assert not any(item["path"] == "/b2b" for item in results)
    assert any(phase == "api_secondary" and any(item["path"] == "/b2b" for item in items)
               for phase, items in observations)


def test_authenticated_discovery_fails_if_session_cannot_be_restored_before_js(monkeypatch) -> None:
    """A lost browser login must stop the scan before anonymous JS probes."""
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    driver.get_auth_headers.return_value = {"Authorization": "Bearer valid"}
    driver.get_chrome_ws_url.return_value = None
    state = {"interaction_passes": 0, "lost": False, "raised": False}

    def interact(_endpoints):
        state["interaction_passes"] += 1
        if state["interaction_passes"] == 2:
            state["lost"] = True

    def ensure_session():
        if state["lost"] and not state["raised"]:
            state["raised"] = True
            raise RuntimeError("authenticated session recovery failed")

    driver.run_interaction_pass.side_effect = interact
    driver.ensure_session.side_effect = ensure_session
    monkeypatch.setattr(discovery, "PlaywrightDriver", lambda *_args, **_kwargs: driver)
    monkeypatch.setattr(discovery, "discover_with_katana", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_with_ffuf", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_api_secondary", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(discovery, "discover_adaptive_js_api_candidates", lambda *_args, **_kwargs: [])

    with pytest.raises(RuntimeError, match="authenticated session recovery failed"):
        discovery.discover_endpoints(
            "https://example.test/", ffuf_wordlist=None,
            enable_playwright_interaction=True, preauthenticated=True,
        )


def test_adaptive_js_requires_proxy_for_policy_guarded_requests() -> None:
    policy = TargetPolicy(
        scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
        asset="https://example.test/", allowed_hosts=["example.test"],
    )
    with pytest.raises(ValueError, match="proxy"):
        secondary.discover_adaptive_js_api_candidates(
            "https://example.test/",
            [{"path": "/main.js", "url": "https://example.test/main.js"}],
            target_policy=policy,
        )
