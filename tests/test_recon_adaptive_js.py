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
