"""New evidence remains useful after fuzzing, within unchanged policy limits."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools import endpoint_discovery as discovery
from aidast.recon.tools import mitm_proxy
from aidast.recon.tools.js_argument_bindings import extract_response_argument_bindings, bind_response_values
from test_recon_capture_recovery import record, policy
from test_recon_js_argument_bindings import SERVICES, PAGE


def test_capture_reader_keeps_late_documents_and_json_after_large_fuzz_traffic(tmp_path):
    capture = tmp_path / 'capture.jsonl'
    noise = json.dumps(record(response_status=404, capture_bodies=False, response_body='x' * 900)) + '\n'
    document = record(url='https://example.test/late', response_headers={'content-type': 'text/html'},
                      response_body='<script src="/late.js"></script>')
    with capture.open('w') as stream:
        for _ in range(14000):
            stream.write(noise)
        stream.write(json.dumps(document) + '\n')
        stream.write(json.dumps(record(url='https://example.test/directory?view=late')) + '\n')
    rows = mitm_proxy.read_observed_recon_responses(capture)
    assert {r['url'] for r in rows} == {document['url'], 'https://example.test/directory?view=late'}


def test_capture_cursor_reads_only_new_complete_rows_and_resets_after_truncation(tmp_path):
    cls = getattr(mitm_proxy, 'ReconCaptureCursor', None)
    assert callable(cls)
    capture = tmp_path / 'capture.jsonl'
    first = json.dumps(record(url='https://example.test/first')) + '\n'
    second = json.dumps(record(url='https://example.test/second')) + '\n'
    capture.write_text(first + second[:40])
    cursor = cls()
    assert [r['url'] for r in cursor.read(capture)] == ['https://example.test/first']
    assert cursor.read(capture) == []
    with capture.open('a') as stream:
        stream.write(second[40:])
    assert [r['url'] for r in cursor.read(capture)] == ['https://example.test/second']
    capture.write_text(first)
    assert [r['url'] for r in cursor.read(capture)] == ['https://example.test/first']


def test_capture_reader_skips_complete_oversized_row_and_bounds_retained_bodies(tmp_path):
    capture = tmp_path / 'capture.jsonl'
    with capture.open('w') as stream:
        stream.write('x' * 2_200_000 + '\n')
        for i in range(120):
            stream.write(json.dumps(record(url=f'https://example.test/{i}', response_body='x' * 100000)) + '\n')
    rows = mitm_proxy.read_observed_recon_responses(capture)
    assert rows and rows[-1]['url'] == 'https://example.test/119'
    assert sum(len(r.get('response_body') or '') for r in rows) <= 8_000_000


def test_detail_budget_gives_distinct_path_templates_a_turn_before_second_id():
    collection = [secondary._DetailProbeJob('collection', f'https://example.test/items/{i}',
                  'https://example.test/items') for i in range(20)]
    templates = [secondary._DetailProbeJob('template', f'https://example.test/reader{i}/1',
                  'https://example.test/items', f'/reader{i}/${{key}}') for i in range(20)]
    rows = list(secondary._round_robin_detail_jobs(collection, templates, is_ready=lambda _: True))
    assert len({r.url.rpartition('/')[0] for r in rows[:20]}) == 20
    assert {r.url for r in rows} == {r.url for r in collection + templates}


def test_dynamic_source_query_binds_actual_observed_response_without_dropping_query():
    source = SERVICES.replace('find(){return http.get(this.host+"/")}',
                              'find(q){return http.get(`${this.host}/?group=${q}&visible=yes`)}')
    bindings = extract_response_argument_bindings({'services.js': source, 'page.js': PAGE})
    assert len(bindings) == 1
    binding = bindings[0]
    assert binding.source_path == '/api/Examples/?group=${q}&visible=yes'
    assert bind_response_values(binding, 'https://example.test/api/Examples/?group=actual&visible=yes',
                                {'data': [{'key': 'item/a'}]}) == ['/documents/item%2Fa']
    for query in ['group=actual&visible=no', 'group=actual&visible=yes&extra=x', 'visible=yes',
                  'group=actual&group=other&visible=yes']:
        assert bind_response_values(binding, 'https://example.test/api/Examples/?' + query,
                                    {'data': [{'key': 'wrong'}]}) == []


def test_dynamic_source_path_is_not_inferred_from_an_unrelated_capture():
    source = SERVICES.replace('find(){return http.get(this.host+"/")}',
                              'find(q){return http.get(`${this.host}/${q}`)}')
    assert extract_response_argument_bindings({'services.js': source, 'page.js': PAGE}) == []


@pytest.mark.parametrize('maximum,expected', [(0, None), (2, 32)])
def test_ffuf_baseline_is_preserved_when_ai_selects_only_extra_root(tmp_path, monkeypatch, maximum, expected):
    words = tmp_path / 'words'; words.write_text('read\n')
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        Path(command[command.index('-o') + 1]).write_text('{"results":[]}')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(discovery.subprocess, 'run', run)
    monkeypatch.setattr(discovery.shutil, 'which', lambda *_: '/fake/ffuf')
    discovery.discover_with_ffuf('https://example.test/', wordlist=str(words),
        seed_endpoints=[{'path': '/assets/client.js'}, {'path': '/directory/items'}, {'path': '/reader/items'}],
        auth_headers=None, target_policy=policy(), proxy_url='http://127.0.0.1:8888',
        root_selector=lambda _: ['/reader/items'], max_time_seconds=maximum)
    urls = [args[args.index('-u') + 1] for args, _ in calls]
    assert urls[:3] == ['https://example.test/FUZZ', 'https://example.test/directory/FUZZ',
                       'https://example.test/reader/FUZZ']
    assert 'https://example.test/reader/items/FUZZ' in urls
    assert all(kwargs['timeout'] == expected for _, kwargs in calls)


def test_cli_accepts_unlimited_ffuf_time_but_rejects_negative():
    from aidast.cli import _parser
    for command in ['recon', 'run']:
        args = _parser().parse_args([command, 'https://hackerone.com/example', '--target', 'example.test', '--ffuf-max-time-seconds', '0'])
        assert args.ffuf_max_time_seconds == 0
        with pytest.raises(SystemExit):
            _parser().parse_args([command, 'https://hackerone.com/example', '--target', 'example.test', '--ffuf-max-time-seconds', '-1'])


def test_incremental_analysis_combines_new_module_with_old_service_without_repeating_gets(monkeypatch):
    cls = getattr(secondary, 'AdaptiveDiscoveryState', None)
    assert callable(cls)
    state = cls()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith('/services.js'):
            return 200, {'content-type': 'application/javascript'}, SERVICES.encode()
        if url.endswith('/page.js'):
            return 200, {'content-type': 'application/javascript'}, PAGE.encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        if url.rstrip('/').endswith('/api/Examples'):
            return 200, {'content-type': 'application/json'}, b'{"data":[{"key":"actual","id":17}]}'
        return 200, {'content-type': 'application/json'}, b'{"found":true}'
    monkeypatch.setattr(secondary, '_http_request', fetch)
    endpoints = [{'method': 'GET', 'url': 'https://example.test/services.js', 'path': '/services.js'}]
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, state=state)
    endpoints.append({'method': 'GET', 'url': 'https://example.test/late', 'path': '/late'})
    document = record(url='https://example.test/late', response_headers={'content-type': 'text/html'},
                      response_body='<script src="/page.js"></script>')
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[document], state=state)
    assert any(row['path'] == '/documents/actual' for row in rows)
    assert calls.count('https://example.test/services.js') == 1
    before = len(calls)
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[document], state=state)
    assert len(calls) == before


def test_endpoint_discovery_analyzes_html_discovered_after_ffuf(monkeypatch):
    driver = MagicMock()
    driver.get_http_results.return_value = []
    driver.get_websocket_results.return_value = []
    driver.get_auth_headers.return_value = {}
    driver.drain_observations.return_value = []
    driver.drain_authentication_observations.return_value = []
    monkeypatch.setattr(discovery, 'PlaywrightDriver', lambda *a, **k: driver)
    monkeypatch.setattr(discovery, 'discover_with_katana', lambda *a, **k: [])
    monkeypatch.setattr(discovery, 'discover_api_secondary', lambda *a, **k: [])
    monkeypatch.setattr(discovery, 'recover_observed_json_gets', lambda *a, **k: [])
    captured, phases = [], []
    monkeypatch.setattr(discovery, 'read_observed_recon_responses', lambda *a, **k: captured.copy())
    def ffuf(*a, **k):
        phases.append('ffuf')
        captured.append(record(url='https://example.test/late', response_headers={'content-type': 'text/html'},
                               response_body='<script src="/late.js"></script>'))
        return [{'method': 'GET', 'url': 'https://example.test/late', 'path': '/late', 'source': 'ffuf'}]
    def adaptive(*a, **kwargs):
        phases.append('adaptive')
        if kwargs.get('observed_responses'):
            return [{'method': 'GET', 'url': 'https://example.test/reader/actual',
                     'path': '/reader/actual', 'source': 'adaptive_js'}]
        return []
    monkeypatch.setattr(discovery, 'discover_with_ffuf', ffuf)
    monkeypatch.setattr(discovery, 'discover_adaptive_js_api_candidates', adaptive)
    rows = discovery.discover_endpoints('https://example.test/', enable_playwright_interaction=False)
    assert phases.index('adaptive') < phases.index('ffuf') < len(phases) - 1
    assert any(row['path'] == '/reader/actual' for row in rows)


def test_json_recovery_cannot_reuse_a_response_from_other_authentication(monkeypatch):
    from aidast.recon.tools.request_identity import authentication_key
    from test_recon_capture_recovery import recover
    rows, calls = recover(monkeypatch, [record(authentication_key=authentication_key({'Authorization': 'other'}))],
                          headers={'Authorization': 'current'})
    assert rows == [] and calls == []


def test_successful_document_survives_body_enabled_ffuf_error_flood(tmp_path):
    capture = tmp_path / 'capture.jsonl'
    document = record(url='https://example.test/late', response_headers={'content-type': 'text/html'},
                      response_body='<script src="/late.js"></script>')
    with capture.open('w') as stream:
        stream.write(json.dumps(document) + '\n')
        for i in range(2500):
            stream.write(json.dumps(record(url=f'https://example.test/missing{i}', response_status=404)) + '\n')
    assert document['url'] in {row['url'] for row in mitm_proxy.ReconCaptureCursor().read(capture)}


def test_access_denied_flood_does_not_evict_successful_documents(tmp_path):
    capture = tmp_path / 'capture.jsonl'
    document = record(url='https://example.test/late', response_headers={'content-type':'text/html'},
                      response_body='<script src="/late.js"></script>')
    capture.write_text(json.dumps(document) + '\n' + ''.join(
        json.dumps(record(url=f'https://example.test/denied{i}', response_status=401)) + '\n'
        for i in range(200)))
    rows = mitm_proxy.ReconCaptureCursor().read(capture)
    assert document['url'] in {row['url'] for row in rows}
    assert len(rows) <= 150


def test_cursor_legacy_anonymous_capture_is_usable_by_incremental_state(tmp_path):
    capture = tmp_path / 'capture.jsonl'
    capture.write_text(json.dumps(record()) + '\n')
    state = secondary.AdaptiveDiscoveryState()
    state.observe(mitm_proxy.ReconCaptureCursor().read(capture), {})
    assert [r['url'] for r in state.observations({})] == [record()['url']]


@pytest.mark.parametrize('headers', [{}, {'Authorization': 'Bearer local-test'}])
def test_required_identity_is_matched_in_captured_json_recovery(monkeypatch, headers):
    from aidast.core.http_safety import merge_hackerone_identity
    from aidast.recon.tools.request_identity import authentication_key
    target = policy().model_copy(update={'required_identity_headers': {'X-Researcher': 'local-test'}})
    effective = merge_hackerone_identity(headers, None, required_identity_headers=target.required_identity_headers)
    monkeypatch.setattr(secondary, '_http_request', lambda url, **kw: (404, {'content-type': 'application/json'}, b'{"error":"missing"}'))
    rows = secondary.recover_observed_json_gets('https://example.test/', [],
        observed_responses=[record(authentication_key=authentication_key(effective))], headers=headers,
        target_policy=target, proxy_url='http://127.0.0.1:8888', broker=object())
    assert len(rows) == 1 and rows[0]['verification_status'] == 'verified'


def test_new_script_has_its_own_allowance_and_reuses_evicted_old_response(monkeypatch):
    state = secondary.AdaptiveDiscoveryState()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith('/services.js'):
            return 200, {'content-type': 'application/javascript'}, SERVICES.encode()
        if url.endswith('/page.js'):
            return 200, {'content-type': 'application/javascript'}, PAGE.encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        if url.rstrip('/').endswith('/api/Examples'):
            return 200, {'content-type': 'application/json'}, b'{"data":[{"key":"actual","id":17}]}'
        return 200, {'content-type': 'application/json'}, b'{"found":true}'
    monkeypatch.setattr(secondary, '_http_request', fetch)
    endpoints = [{'method': 'GET', 'url': 'https://example.test/services.js', 'path': '/services.js'}]
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, state=state, max_scripts=1)
    state.observe([record(url=f'https://example.test/noise/{i}') for i in range(150)], {})
    state.responses.pop(('GET', 'https://example.test/services.js', secondary.authentication_key({})), None)
    endpoints.append({'method': 'GET', 'url': 'https://example.test/page.js', 'path': '/page.js'})
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, state=state, max_scripts=1)
    assert calls.count('https://example.test/services.js') == 1
    assert calls.count('https://example.test/page.js') == 1
    assert any(row['path'] == '/documents/actual' for row in rows)


def test_detail_budget_retains_unverified_routes_and_reports_the_limit(monkeypatch):
    script = 'http.get("/api/Inventory");' + ''.join(
        f'http.get(`/rest/Inventory/${{id}}/reader{i}`);\n' for i in range(22))
    calls, diagnostics = [], []
    monkeypatch.setattr(secondary, 'extract_js_api_paths', lambda *args: [('/api/Inventory', 'GET')] + [
        (f'/rest/Inventory/${{id}}/reader{i}', 'GET') for i in range(22)])
    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith('/main.js'):
            return 200, {'content-type': 'application/javascript'}, script.encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        if url.endswith('/api/Inventory'):
            return 200, {'content-type': 'application/json'}, b'{"data":[{"id":7}]}'
        return 200, {'content-type': 'application/json'}, b'{"found":true}'
    monkeypatch.setattr(secondary, '_http_request', fetch)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path': '/main.js'}],
        diagnostic_callback=lambda event, **kw: diagnostics.append((event, kw)))
    candidates = [row for row in rows if row.get('verification_status') == 'candidate']
    assert len(candidates) == 3
    assert all(row['evidence']['verification_reason'] == 'detail_probe_limit' for row in candidates)
    assert all(row['url'] not in calls for row in candidates)
    details = next(kw for event, kw in diagnostics if event == 'completed')
    assert details['detail_probe_limit'] == 20 and details['detail_deferred_candidates'] == 3
    assert details['detail_route_templates'] == 23


def test_changed_script_capture_is_analyzed_without_another_get(tmp_path, monkeypatch):
    from aidast.recon.tools.request_identity import authentication_key
    state = secondary.AdaptiveDiscoveryState()
    calls = []
    def fetch(url, **kw):
        calls.append(url)
        if url.endswith('/main.js'):
            return 200, {'content-type': 'application/javascript'}, b'http.get("/api/first");'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        return 200, {'content-type': 'application/json'}, b'{"found":true}'
    monkeypatch.setattr(secondary, '_http_request', fetch)
    endpoints = [{'path': '/main.js'}]
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, state=state)
    capture = tmp_path / 'capture.jsonl'
    capture.write_text(json.dumps(record(url='https://example.test/main.js',
        response_headers={'content-type': 'application/javascript'},
        response_body='http.get("/api/changed");', static_resource=True, duplicate=True,
        authentication_key=authentication_key({}))) + '\n')
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=mitm_proxy.ReconCaptureCursor().read(capture), state=state)
    assert calls.count('https://example.test/main.js') == 1
    assert any(row['path'] == '/api/changed' for row in rows)


def test_changed_inline_document_rebinds_only_current_code(monkeypatch):
    state = secondary.AdaptiveDiscoveryState()
    monkeypatch.setattr(secondary, '_http_request', lambda *args, **kw: (
        404, {'content-type': 'application/json'}, b'{"error":"missing"}'))
    endpoints = [{'path': '/workspace'}]
    def document(path):
        return record(url='https://example.test/workspace', response_headers={'content-type': 'text/html'},
                      response_body=f'<script>http.get(`/{path}/${{key}}`);</script>')
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[document('first')], state=state)
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[document('changed')], state=state)
    parsed = state.parsed_scripts({})['https://example.test/workspace#inline-dom-0']
    assert '/changed/' in parsed[0] and '/first/' not in parsed[0]
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[document('first')], state=state)
    assert '/first/' in state.parsed_scripts({})['https://example.test/workspace#inline-dom-0'][0]


def test_removed_inline_script_is_not_reused_from_previous_document(monkeypatch):
    state = secondary.AdaptiveDiscoveryState()
    monkeypatch.setattr(secondary, '_http_request', lambda *args, **kw: (
        404, {'content-type': 'application/json'}, b'{"error":"missing"}'))
    old = record(url='https://example.test/workspace', response_headers={'content-type':'text/html'},
                 response_body='<script>http.get(`/reader/${key}`);</script>')
    endpoints = [{'path':'/workspace'}]
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, observed_responses=[old], state=state)
    secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints,
        observed_responses=[dict(old, response_body='<html>Removed</html>')], state=state)
    assert 'https://example.test/workspace#inline-dom-0' not in state.parsed_scripts({})


def test_later_verified_observation_replaces_candidate_representative_without_losing_query():
    from aidast.recon.verification import result_verification_status
    candidate = dict(method='GET', path='/reader/7', url='https://example.test/reader/7?view=first',
                     verification_status='candidate', source='adaptive_js_detail_candidate')
    observed = dict(method='GET', path='/reader/7', url='https://example.test/reader/7?view=actual',
                    source='ffuf', evidence={'response_status':200})
    row, = discovery._deduplicate_results([candidate, observed])
    assert result_verification_status(row) == 'verified'
    assert row['url'] == observed['url']
    assert {r['url'] for r in row['observation_variants']} == {candidate['url'], observed['url']}


def test_candidate_verification_reuses_controls_but_keeps_query_and_auth_identities(monkeypatch):
    state = secondary.AdaptiveDiscoveryState()
    calls = []
    def fetch(url, **options):
        calls.append((url, (options.get('headers') or {}).get('Authorization')))
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        return 200, {'content-type':'application/json'}, b'{"found":true}'
    monkeypatch.setattr(secondary, '_http_request', fetch)
    def cached(url, **options):
        return state.request(fetch, url, **options)
    for query, auth in [('first','one'), ('second','one'), ('first','two')]:
        rows = secondary._verify_get_candidates([dict(method='GET', path='/reader',
            url='https://example.test/reader?view='+query, verification_status='candidate')],
            base_url='https://example.test/', target_policy=policy(), headers={'Authorization':auth},
            broker=object(), proxy_url='http://127.0.0.1:8888', request_fn=cached)
        assert rows[0]['verification_status'] == 'verified'
    assert len(calls) == 5  # Two credential-specific controls plus three full URLs.
