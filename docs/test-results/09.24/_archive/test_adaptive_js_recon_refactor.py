"""Juice Shop SPA route extraction and conservative candidate validation."""

from __future__ import annotations

from aidast.recon.tools import api_secondary_discovery as secondary


SCRIPT = [{
    "method": "GET", "path": "/main.js", "url": "https://example.test/main.js",
}]


def test_static_backtick_api_paths_are_extracted_but_templates_are_not(monkeypatch) -> None:
    requested: list[str] = []

    def fake_request(url: str, **_kwargs):
        requested.append(url)
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, (
                b'fetch(`/api/Products`); fetch(`/rest/order-history`); '
                b'fetch("/api/Users"); fetch(`/api/Users/${id}`);'
            )
        if "__aidast_missing_control__" in url:
            return 404, {"content-type": "application/json"}, b'{"error":"missing"}'
        return 200, {"content-type": "application/json"}, b'{"ok":true}'

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/", SCRIPT,
    )

    assert {item["path"] for item in results} == {
        "/api/Products", "/rest/order-history", "/api/Users",
    }
    assert not any("${id}" in url for url in requested)


def test_500_missing_route_control_keeps_only_distinct_success(monkeypatch) -> None:
    diagnostics: list[tuple[str, dict]] = []

    def fake_request(url: str, **_kwargs):
        if url.endswith("main.js"):
            return 200, {"content-type": "application/javascript"}, (
                b'fetch("/api/verified"); fetch("/api/auth-only"); '
                b'fetch("/api/fake"); fetch("/api/proxy-blocked");'
            )
        if "__aidast_missing_control__" in url:
            return 500, {"content-type": "application/json"}, b'{"error":"missing"}'
        if url.endswith("/verified"):
            return 200, {"content-type": "application/json"}, b'{"ok":true}'
        if url.endswith("/auth-only"):
            return 401, {"content-type": "application/json"}, b'{"error":"login"}'
        if url.endswith("/fake"):
            return 200, {"content-type": "application/json"}, b'{"error":"missing"}'
        return 403, {"content-type": "text/plain"}, b"Blocked by AI-DAST TargetPolicy\n"

    monkeypatch.setattr(secondary, "_http_request", fake_request)
    results = secondary.discover_adaptive_js_api_candidates(
        "https://example.test/", SCRIPT,
        diagnostic_callback=lambda event, **details: diagnostics.append((event, details)),
    )

    assert [item["path"] for item in results] == ["/api/verified"]
    assert results[0]["evidence"]["response_status"] == 200
    assert ("completed", {
        "component": "adaptive_js", "accepted_count": 1,
        "unverified_count": 1,
    }) in diagnostics
