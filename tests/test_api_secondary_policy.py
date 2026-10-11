from __future__ import annotations

import unittest
import json
from io import BytesIO
from unittest.mock import patch
from urllib.request import Request

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.api_secondary_discovery import (
    _http_request, _NoRedirect, _RequiredProxy, _openapi_server_url,
    _parse_zap_har, detect_openapi, discover_api_secondary,
)
from aidast.scope.models import AssetType


class ApiSecondaryPolicyTests(unittest.TestCase):
    def _policy(self) -> TargetPolicy:
        return TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_test",
            asset_type=AssetType.URL,
            asset="https://example.com/api",
            allowed_schemes=["https"],
            allowed_hosts=["example.com"],
            allowed_ports=[443],
            allowed_path_prefixes=["/api"],
            allowed_methods=["GET"],
        )

    def test_http_request_is_blocked_before_network_for_out_of_scope_url(self) -> None:
        with patch(
            "aidast.recon.tools.api_secondary_discovery.build_opener"
        ) as build_opener:
            result = _http_request(
                "https://example.com/admin/openapi.json",
                target_policy=self._policy(),
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(result, (None, {}, b""))
        build_opener.assert_not_called()

    def test_zap_har_reports_unverified_candidate_not_http_evidence(self) -> None:
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'openapi.har'
            path.write_text(json.dumps({'log': {'entries': [{
                'request': {'method': 'GET', 'url': 'https://example.com/api/b2b'},
                'response': {'status': 200},
            }]}}), encoding='utf-8')
            results = _parse_zap_har(
                path, base_url='https://example.com/api', source='zap_openapi',
                target_policy=self._policy(),
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['verification_status'], 'candidate')
        self.assertEqual(results[0]['discovery_kind'], 'api_spec_candidate')
        self.assertNotIn('response_status', results[0].get('evidence', {}))

    def test_get_candidate_verifier_promotes_only_distinct_json_response(self) -> None:
        from aidast.recon.tools.api_secondary_discovery import _verify_get_candidates

        policy = self._policy().model_copy(deep=True)
        policy.asset = 'https://example.com/'
        policy.allowed_path_prefixes = ['/']
        candidates = [
            {'method': 'GET', 'url': 'https://example.com/api/Products',
             'path': '/api/Products', 'source': 'zap_openapi', 'verification_status': 'candidate'},
            {'method': 'GET', 'url': 'https://example.com/api/missing',
             'path': '/api/missing', 'source': 'zap_openapi', 'verification_status': 'candidate'},
            {'method': 'POST', 'url': 'https://example.com/api/orders',
             'path': '/api/orders', 'source': 'zap_openapi', 'verification_status': 'candidate'},
        ]
        requested = []

        def fetch(url, **kwargs):
            requested.append((url, kwargs.get('method', 'GET'),
                              (kwargs.get('headers') or {}).get('X-AIDAST-Phase')))
            if url.endswith('/api/Products'):
                return 200, {'Content-Type': 'application/json'}, b'{"data":[{"id":1}]}'
            return 200, {'Content-Type': 'application/json'}, (
                json.dumps({'error': f'No route: {url}'}).encode()
            )

        with patch('aidast.recon.tools.api_secondary_discovery._http_request', side_effect=fetch):
            result = _verify_get_candidates(
                candidates, base_url='https://example.com/', target_policy=policy,
                headers={}, broker=None, proxy_url='http://127.0.0.1:8080', max_probes=2,
            )

        self.assertEqual([item['verification_status'] for item in result],
                         ['verified', 'candidate', 'candidate'])
        self.assertEqual(result[0]['evidence']['response_status'], 200)
        self.assertEqual(result[0]['discovery_kind'], 'api_get_verified')
        self.assertEqual(result[1]['evidence']['verification_reason'], 'non_positive_json')
        self.assertEqual(len(requested), 3)
        self.assertTrue(all(method == 'GET' and phase == 'candidate_probe'
                            for _, method, phase in requested))

    def test_get_candidate_verifier_caps_probes_and_keeps_unauthorized_response(self) -> None:
        from aidast.recon.tools.api_secondary_discovery import _verify_get_candidates

        policy = self._policy().model_copy(deep=True)
        policy.asset = 'https://example.com/'
        policy.allowed_path_prefixes = ['/']
        candidates = [
            {'method': 'GET', 'url': f'https://example.com/api/{name}',
             'path': f'/api/{name}', 'source': 'zap_openapi', 'verification_status': 'candidate'}
            for name in ('private', 'later')
        ]
        requested = []

        def fetch(url, **_kwargs):
            requested.append(url)
            if url.endswith('/__aidast_missing_control__'):
                return 404, {'Content-Type': 'application/json'}, b'{"error":"missing"}'
            return 401, {'Content-Type': 'application/json'}, b'{"error":"login required"}'

        with patch('aidast.recon.tools.api_secondary_discovery._http_request', side_effect=fetch):
            result = _verify_get_candidates(
                candidates, base_url='https://example.com/', target_policy=policy,
                headers={}, broker=None, proxy_url='http://127.0.0.1:8080', max_probes=1,
            )

        self.assertEqual([item['verification_status'] for item in result], ['candidate', 'candidate'])
        self.assertEqual(result[0]['evidence']['response_status'], 401)
        self.assertEqual(result[0]['evidence']['verification_reason'], 'non_positive_json')
        self.assertEqual(result[1]['evidence']['verification_reason'], 'probe_limit')
        self.assertEqual(requested, [
            'https://example.com/api/__aidast_missing_control__',
            'https://example.com/api/private',
        ])

    def test_secondary_discovery_returns_verified_get_after_candidate_probe(self) -> None:
        from aidast.recon.tools.api_secondary_discovery import OpenAPIDefinition

        policy = self._policy().model_copy(deep=True)
        policy.asset = 'https://example.com/'
        policy.allowed_path_prefixes = ['/']
        candidate = {
            'method': 'GET', 'url': 'https://example.com/api/Products?mode=bad',
            'path': '/api/Products', 'source': 'zap_openapi',
            'verification_status': 'candidate', 'discovery_kind': 'api_spec_candidate',
        }
        successful_variant = dict(candidate, url='https://example.com/api/Products?mode=good')

        def fetch(url, **_kwargs):
            if url.endswith('/__aidast_missing_control__'):
                return 404, {'Content-Type': 'application/json'}, b'{"error":"missing"}'
            if url.endswith('mode=bad'):
                return 401, {'Content-Type': 'application/json'}, b'{"error":"unauthorized"}'
            if url.endswith('mode=good'):
                return 200, {'Content-Type': 'application/json'}, b'{"data":[{"id":1}]}'
            raise AssertionError(url)

        with patch('aidast.recon.tools.api_secondary_discovery.detect_openapi',
                   return_value=[OpenAPIDefinition(url='https://example.com/openapi.json', document={'openapi': '3.0.0', 'paths': {}})]), patch(
                       'aidast.recon.tools.api_secondary_discovery.detect_graphql', return_value=[]
                   ), patch('aidast.recon.tools.api_secondary_discovery._run_zap', return_value=True), patch(
                       'aidast.recon.tools.api_secondary_discovery._parse_zap_har',
                       return_value=[candidate, successful_variant]
                   ), patch('aidast.recon.tools.api_secondary_discovery._http_request', side_effect=fetch):
            result = discover_api_secondary(
                'https://example.com/', [], target_policy=policy,
                proxy_url='http://127.0.0.1:8080',
            )

        self.assertEqual([item['verification_status'] for item in result],
                         ['candidate', 'verified'])
        self.assertEqual(result[1]['evidence']['response_status'], 200)

    def test_get_candidate_verifier_rejects_graphql_error_payload(self) -> None:
        from aidast.recon.tools.api_secondary_discovery import _verify_get_candidates

        policy = self._policy().model_copy(deep=True)
        policy.asset = 'https://example.com/'
        policy.allowed_path_prefixes = ['/']
        candidate = {
            'method': 'GET', 'url': 'https://example.com/api/graphql',
            'path': '/api/graphql', 'source': 'zap_graphql',
            'verification_status': 'candidate',
        }

        def fetch(url, **_kwargs):
            if url.endswith('/__aidast_missing_control__'):
                return 404, {'Content-Type': 'application/json'}, b'{"error":"missing"}'
            return 200, {'Content-Type': 'application/json'}, (
                b'{"data":null,"errors":[{"message":"query failed"}]}'
            )

        with patch('aidast.recon.tools.api_secondary_discovery._http_request', side_effect=fetch):
            result = _verify_get_candidates(
                [candidate], base_url='https://example.com/', target_policy=policy,
                headers={}, broker=None, proxy_url='http://127.0.0.1:8080',
            )

        self.assertEqual(result[0]['verification_status'], 'candidate')

    def test_get_candidate_verifier_rejects_error_with_empty_data(self) -> None:
        from aidast.recon.tools.api_secondary_discovery import _verify_get_candidates

        policy = self._policy().model_copy(deep=True)
        policy.asset = 'https://example.com/'
        policy.allowed_path_prefixes = ['/']
        candidate = {
            'method': 'GET', 'url': 'https://example.com/api/Products',
            'path': '/api/Products', 'source': 'zap_openapi',
            'verification_status': 'candidate',
        }

        def fetch(url, **_kwargs):
            if url.endswith('/__aidast_missing_control__'):
                return 404, {'Content-Type': 'application/json'}, b'{"error":"missing"}'
            return 200, {'Content-Type': 'application/json'}, b'{"error":"forbidden","data":{}}'

        with patch('aidast.recon.tools.api_secondary_discovery._http_request', side_effect=fetch):
            result = _verify_get_candidates(
                [candidate], base_url='https://example.com/', target_policy=policy,
                headers={}, broker=None, proxy_url='http://127.0.0.1:8080',
            )

        self.assertEqual(result[0]['verification_status'], 'candidate')

    def test_missing_policy_blocks_network(self) -> None:
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            self.assertEqual(_http_request("https://example.com/api"), (None, {}, b""))
        opener.assert_not_called()

    @staticmethod
    def _response(status=200, headers=None, body=b"{}"):
        response = BytesIO(body)
        response.status = status
        response.headers = headers or {}
        return response

    def test_disallowed_redirect_is_returned_but_never_followed(self) -> None:
        for location in ["https://outside.example/secret", "/admin", "http://example.com/api"]:
            with self.subTest(location=location), patch(
                "aidast.recon.tools.api_secondary_discovery.build_opener"
            ) as opener:
                opener.return_value.open.return_value = self._response(302, {"Location": location})
                status, headers, _body = _http_request(
                    "https://example.com/api", target_policy=self._policy(),
                    proxy_url="http://127.0.0.1:8080",
                )
                # Preserve the in-scope redirect response as evidence, but do
                # not request its out-of-policy Location.
                self.assertEqual(status, 302)
                self.assertEqual(headers["Location"], location)
                self.assertEqual(opener.return_value.open.call_count, 1)
                self.assertTrue(any(isinstance(item, _NoRedirect) for item in opener.call_args.args))

    def test_allowed_redirect_is_checked_and_response_headers_are_sanitized(self) -> None:
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            opener.return_value.open.side_effect = [
                self._response(302, {"Location": "/api/spec"}),
                self._response(200, {"Set-Cookie": "secret", "Content-Type": "application/json"}),
            ]
            status, headers, body = _http_request("https://example.com/api", target_policy=self._policy())
        self.assertEqual(status, 200)
        self.assertNotIn("secret", str(headers))
        self.assertEqual(body, b"{}")
        self.assertEqual([call.args[0].full_url for call in opener.return_value.open.call_args_list],
                         ["https://example.com/api", "https://example.com/api/spec"])

    def test_discovery_candidates_share_one_request_budget(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.limits.max_requests = 2
        events: list[tuple[str, str]] = []
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            opener.return_value.open.side_effect = lambda *args, **kwargs: self._response()
            result = discover_api_secondary("https://example.com/api", [], target_policy=policy,
                                            proxy_url="http://127.0.0.1:8080",
                                            diagnostic_callback=lambda event, **details: events.append((event, details["phase"])))
        self.assertEqual(result, [])
        self.assertIn(("phase_started", "openapi_detection"), events)
        self.assertIn(("phase_completed", "graphql_detection"), events)
        self.assertIn(("phase_skipped", "zap_openapi"), events)
        self.assertEqual(opener.call_count, 1)
        self.assertEqual(opener.return_value.open.call_count, 2)

    def test_swagger_ui_embedded_spec_is_imported_as_local_file(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.asset = "https://example.com/"
        policy.allowed_path_prefixes = ["/"]
        fetched: list[str] = []
        spec = {"openapi": "3.0.0", "servers": [{"url": "/b2b/v2"}],
                "paths": {"/orders": {"get": {"responses": {"200": {"description": "OK"}}},
                                      "post": {"responses": {"200": {"description": "OK"}}}}}}
        page = b'<html><script src="./swagger-ui-init.js"></script></html>'
        init = ("window.onload = function () {\nvar options = " + json.dumps({"swaggerDoc": spec}) + ";\n}").encode()

        def fetch(url: str, **_kwargs):
            fetched.append(url)
            if url == "https://example.com/api-docs":
                return 200, {"Content-Type": "text/html"}, page
            if url == "https://example.com/api-docs/swagger-ui-init.js":
                return 200, {"Content-Type": "application/javascript"}, init
            return 404, {}, b""

        imported: list[dict] = []
        target_urls: list[str] = []

        def inspect_plan(plan_path, **_kwargs):
            plan = plan_path.read_text()
            file_line = next(line for line in plan.splitlines() if "apiFile:" in line)
            from pathlib import Path
            spec_path = Path(json.loads(file_line.split("apiFile:", 1)[1].strip()))
            imported.append(json.loads(spec_path.read_text()))
            target_line = next(line for line in plan.splitlines() if "targetUrl:" in line)
            target_urls.append(json.loads(target_line.split("targetUrl:", 1)[1].strip()))
            return False

        with patch("aidast.recon.tools.api_secondary_discovery.build_opener"), patch(
            "aidast.recon.tools.api_secondary_discovery._http_request", side_effect=fetch
        ), patch("aidast.recon.tools.api_secondary_discovery._run_zap", side_effect=inspect_plan):
            discover_api_secondary(
                "https://example.com/", [], target_policy=policy,
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(len(imported), 1)
        self.assertEqual(set(imported[0]["paths"]), {"/b2b/v2/orders"})
        self.assertEqual(set(imported[0]["paths"]["/b2b/v2/orders"]), {"get"})
        self.assertEqual(imported[0]["servers"], [{"url": "https://example.com"}])
        self.assertEqual(target_urls, ["https://example.com/"])
        self.assertIn("https://example.com/api-docs/swagger-ui-init.js", fetched)

    def test_swagger_ui_skips_invalid_and_cross_origin_initializers(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.asset = "https://example.com/"
        policy.allowed_path_prefixes = ["/"]
        fetched: list[str] = []

        def fetch(url: str, **_kwargs):
            fetched.append(url)
            if url == "https://example.com/api-docs":
                return 200, {"Content-Type": "text/html"}, (
                    b'<script src="http://[bad/swagger-ui-init.js"></script>'
                    b'<script src="https://elsewhere.example/swagger-ui-init.js"></script>'
                    b'<script src="./swagger-ui-init.js"></script>'
                )
            if url == "https://example.com/api-docs/swagger-ui-init.js":
                return 200, {}, b'var options = {"swaggerDoc":{"openapi":"3.0.0","paths":{"/ping":{}}}};'
            return 404, {}, b""

        with patch("aidast.recon.tools.api_secondary_discovery.build_opener"), patch(
            "aidast.recon.tools.api_secondary_discovery._http_request", side_effect=fetch
        ):
            found = detect_openapi(
                "https://example.com/", [], target_policy=policy,
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(len(found), 1)
        self.assertNotIn("https://elsewhere.example/swagger-ui-init.js", fetched)

    def test_swagger_ui_initializer_is_relative_to_index_html_directory(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.asset = "https://example.com/"
        policy.allowed_path_prefixes = ["/"]
        fetched: list[str] = []

        def fetch(url: str, **_kwargs):
            fetched.append(url)
            if url == "https://example.com/swagger-ui/index.html":
                return 200, {}, b'<script src="./swagger-ui-init.js"></script>'
            if url == "https://example.com/swagger-ui/swagger-ui-init.js":
                return 200, {}, b'var options = {"swaggerDoc":{"openapi":"3.0.0","paths":{"/ping":{}}}};'
            return 404, {}, b""

        with patch("aidast.recon.tools.api_secondary_discovery.build_opener"), patch(
            "aidast.recon.tools.api_secondary_discovery._http_request", side_effect=fetch
        ):
            found = detect_openapi(
                "https://example.com/", [{"path": "/swagger-ui/index.html"}],
                target_policy=policy, proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(len(found), 1)
        self.assertIn("https://example.com/swagger-ui/swagger-ui-init.js", fetched)

    def test_swagger_2_base_path_is_kept_for_local_import(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.asset = "https://example.com/"
        policy.allowed_path_prefixes = ["/"]
        document = {"swagger": "2.0", "host": "elsewhere.example", "basePath": "/v2", "paths": {"/orders": {}}}

        self.assertEqual(
            _openapi_server_url(document, "https://example.com/", policy),
            "https://example.com/v2",
        )

    def test_explicit_proxy_ignores_ambient_no_proxy(self) -> None:
        request = Request("https://example.com/api")
        handler = _RequiredProxy({"https": "http://127.0.0.1:8080"})
        with patch("urllib.request.proxy_bypass", return_value=True):
            handler.proxy_open(request, "http://127.0.0.1:8080", "https")
        self.assertEqual(request.host, "127.0.0.1:8080")
        self.assertEqual(request._tunnel_host, "example.com")

    def test_http_request_is_blocked_before_network_for_disallowed_method(self) -> None:
        with patch(
            "aidast.recon.tools.api_secondary_discovery.build_opener"
        ) as build_opener:
            result = _http_request(
                "https://example.com/api/graphql",
                method="POST",
                target_policy=self._policy(),
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(result, (None, {}, b""))
        build_opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
