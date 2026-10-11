"""Explicit GETs outside conventional prefixes require real response evidence."""
import pytest

from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


@pytest.mark.parametrize('script,want', [
    ('http.get("/reports/daily")', [('/reports/daily', 'GET')]),
    ('fetch("/metrics")', [('/metrics', 'GET')]),
    ('fetch("/reports/daily", {headers:{"X-Next":"/private/hint"}})', [('/reports/daily', 'GET')]),
    ('http.get(`${settings.hostServer}/metrics`)', [('/metrics', 'GET')]),
    ('class Reports{host="/reports";read(){return http.get(this.host+"/daily")}}', [('/reports/daily', 'GET')]),
])
def test_explicit_nonprefix_get_is_extracted(script, want):
    assert extract_js_api_paths(script, literal_call_method) == want


@pytest.mark.parametrize('script', [
    'const route="/reports/daily";const ui={path:"/dashboard"}',
    'http.post("/reports/write", body)',
    'fetch("/reports/write", {method:"POST"})',
    'fetch("/reports/unknown", options)',
    'http.get("https://outside.test/reports/private")',
    'http.get("//outside.test/reports/private")',
    'http.get("/reports/with spaces")',
    'http.get(`${"https://outside.test"}/reports/daily`)',
    'http.get(`${"/reports/" + unknown}/daily`)',
    'http.get("/reports/" + unknown)',
    'http.get(this.host + "/daily")',
    'class C{host="//outside.test/reports";r(){http.get(this.host+"/daily")}}',
    'class C{host="https://outside.test";r(){http.get(`${this.host}/reports/daily`)}}',
    'class C{host="//outside.test";r(){http.get(`${this.host}/reports/daily`)}}',
    'class C{host="/reports/"+unknown;r(){http.get(this.host+"/daily")}}',
    'class C{host="/reports/"+unknown;r(){http.get(`${this.host}/daily`)}}',
    'class C{host=`/reports/${unknown}`;r(){http.get(`${this.host}/daily`)}}',
    'class C{host="/reports";r(){this.host=`/archive/${unknown}`;http.get(`${this.host}/daily`)}}',
    'class C{host="/reports" && unknown;r(){http.get(`${this.host}/daily`)}}',
    'class C{host="/reports" || unknown;r(){http.get(`${this.host}/daily`)}}',
])
def test_nonprefix_hints_writes_external_and_unbound_paths_are_not_extracted(script):
    assert extract_js_api_paths(script, literal_call_method) == []


@pytest.mark.parametrize('script,want', [
    ('http.get(`/reports/${reportKey}`)', [('/reports/${reportKey}', 'GET')]),
    ('class C{host="/reports";get(key){return http.get(`${this.host}/${key}`)}}',
     [('/reports/${key}', 'GET')]),
    ('class C{host="/reports";get(key){return http.get(this.host+`/${key}`)}}',
     [('/reports/${key}', 'GET')]),
    ('http.get(`/reports/${report.key}/history`)', [('/reports/${report.key}/history', 'GET')]),
])
def test_nonprefix_get_templates_keep_method_and_complete_expression(script, want):
    assert extract_js_api_paths(script, literal_call_method) == want


@pytest.mark.parametrize('script', [
    'http.get(`/reports/${makeKey()}`)',
    'http.get(`/reports/prefix-${key}`)',
    'http.get(`/reports/${key}` + unknown)',
    'http.post(`/reports/${key}`, body)',
    'const hint=`/reports/${key}`',
    'http.get(`//outside.test/reports/${key}`)',
])
def test_nonprefix_templates_reject_unsupported_expressions_and_incomplete_urls(script):
    assert extract_js_api_paths(script, literal_call_method) == []


def _discover(monkeypatch, script, responses, **options):
    requests = []
    def request(url, **kwargs):
        requests.append(url)
        if url == 'https://example.test/main.js':
            return 200, {'content-type':'application/javascript'}, script.encode()
        if url in responses:
            return responses[url]
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        raise AssertionError('Unexpected probe: '+url)
    monkeypatch.setattr(secondary, '_http_request', request)
    rows = secondary.discover_adaptive_js_api_candidates(
        'https://example.test/', [{'path':'/main.js'}], **options)
    return rows, requests


def test_nonprefix_get_reaches_results_with_actual_source(monkeypatch):
    rows, _ = _discover(monkeypatch, 'http.get("/reports/daily")', {
        'https://example.test/reports/daily': (200, {'content-type':'application/json'}, b'{"rows":[1]}'),
    })
    assert [r['path'] for r in rows] == ['/reports/daily']
    assert rows[0]['evidence']['source_scripts'] == ['https://example.test/main.js']


def test_nonprefix_template_never_probes_a_guessed_value(monkeypatch):
    rows, requests = _discover(monkeypatch, 'http.get(`/reports/${unknown}`)', {})
    assert rows == []
    assert not any('/reports/' in url for url in requests)


def test_root_dynamic_template_does_not_abort_adaptive_discovery(monkeypatch):
    rows, requests = _discover(monkeypatch, 'class Reader{get(k){return http.get(`/${k}`)}}', {})
    assert rows == []
    assert not any('${' in url for url in requests)


def test_joined_get_reaches_results_without_partial_or_write_probes(monkeypatch):
    rows, requests = _discover(monkeypatch,
        'fetch("/reports/"+"daily");http.post("/reports/"+"write",body)', {
            'https://example.test/reports/daily':
                (200, {'content-type':'application/json'}, b'{"rows":[1]}'),
        })
    assert [r['path'] for r in rows] == ['/reports/daily']
    assert rows[0]['evidence']['source_scripts'] == ['https://example.test/main.js']
    assert not any(url.endswith(('/reports/', '/reports/write')) for url in requests)


def test_nonprefix_get_uses_sibling_control_to_reject_reflected_fallback(monkeypatch):
    path='https://example.test/reports/daily'
    control='https://example.test/reports/__aidast_missing_control__'
    rows, requests = _discover(monkeypatch, 'http.get("/reports/daily")', {
        path: (200, {'content-type':'application/json'}, ('{"error":"No route: '+path+'"}').encode()),
        control: (200, {'content-type':'application/json'}, ('{"error":"No route: '+control+'"}').encode()),
    })
    assert rows == []
    assert control in requests


@pytest.mark.parametrize('media', ['text/html', 'text/plain'])
def test_nonprefix_get_html_shell_is_not_a_route(monkeypatch, media):
    rows, _ = _discover(monkeypatch, 'http.get("/dashboard")', {
        'https://example.test/dashboard': (200, {'content-type':media}, b'<!doctype html><html><body>SPA</body></html>'),
    })
    assert rows == []


def test_nonprefix_html_shell_with_long_whitespace_is_not_a_route(monkeypatch):
    rows, _ = _discover(monkeypatch, 'http.get("/dashboard")', {
        'https://example.test/dashboard': (200, {'content-type':'text/plain'},
            b' ' * 1500 + b'<!doctype html><html><body>SPA</body></html>'),
    })
    assert rows == []


@pytest.mark.parametrize('preamble', [
    b'<!-- app generated -->\n',
    b'<?xml version="1.0"?>\n',
    b'<!-- first --><!-- second -->\n<?xml version="1.0"?>\n',
])
def test_nonprefix_html_preamble_is_not_a_route(monkeypatch, preamble):
    rows, _ = _discover(monkeypatch, 'http.get("/dashboard")', {
        'https://example.test/dashboard': (200, {'content-type':'text/plain'},
            preamble + b'<html><body>SPA</body></html>'),
    })
    assert rows == []


def test_nonprefix_xml_data_is_preserved(monkeypatch):
    rows, _ = _discover(monkeypatch, 'http.get("/reports/daily")', {
        'https://example.test/reports/daily': (200, {'content-type':'application/xml'},
            b'<?xml version="1.0"?><report><count>7</count></report>'),
    })
    assert [r['path'] for r in rows] == ['/reports/daily']


def test_nonprefix_get_respects_excluded_path(monkeypatch):
    policy=TargetPolicy(scope_id='s',policy_id='p',asset_type=AssetType.URL,asset='https://example.test/',
        allowed_schemes=['https'],allowed_hosts=['example.test'],allowed_ports=[443],
        excluded_path_prefixes=['/reports'])
    rows, requests = _discover(monkeypatch, 'http.get("/reports/private")', {},
        target_policy=policy,proxy_url='http://127.0.0.1:8080')
    assert rows == []
    assert 'https://example.test/reports/private' not in requests


def test_nonprefix_dynamic_query_does_not_invent_values(monkeypatch):
    rows, requests = _discover(monkeypatch, 'http.get(`/reports/daily?filter=${unknown}`)', {
        'https://example.test/reports/daily': (200, {'content-type':'application/json'}, b'{"rows":[1]}'),
    })
    assert rows == []
    assert not any('unknown' in url or url.endswith('/reports/daily') for url in requests)
