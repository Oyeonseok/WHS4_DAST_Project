"""Bind GET arguments only through an explicit response-field relationship."""
import json

import pytest

from aidast.recon.tools.js_argument_bindings import extract_response_argument_bindings, bind_response_values


SERVICES = '''
Catalog=(()=>{class C{host="/api/Examples";find(){return http.get(this.host+"/")}}return C})();
Reader=(()=>{class C{host="/documents";get(k){return http.get(`${this.host}/${k}`)}}return C})();
'''
PAGE = '''class Page{
catalog=inject(Catalog);reader=inject(Reader);
load(){join({items:this.catalog.find(),doc:this.reader.get(this.selectedKey)})
.subscribe(({items:rows,doc:document})=>{let item=rows.find(row=>row.key===this.selectedKey)})}
}'''


def test_response_field_comparison_links_injected_get_services_across_scripts():
    bindings = extract_response_argument_bindings({'services.js': SERVICES, 'page.js': PAGE})
    assert len(bindings) == 1
    assert bindings[0].template == '/documents/${k}'
    assert bindings[0].source_path == '/api/Examples/'
    assert bindings[0].field == 'key'
    assert set(bindings[0].source_scripts) == {'services.js', 'page.js'}


@pytest.mark.parametrize('page', [
    PAGE.replace('row.key===this.selectedKey', 'row.key===this.unrelatedKey'),
    PAGE.replace('rows.find', 'unknown.find'),
    PAGE.replace('this.catalog.find()', 'this.other.find()'),
    'class P{reader=inject(Reader);load(){this.reader.get(this.selectedKey)}}',
    'const text=' + json.dumps(PAGE),
    '/*' + PAGE + '*/',
])
def test_unrelated_values_and_source_text_are_not_bindings(page):
    assert extract_response_argument_bindings({'services.js': SERVICES, 'page.js': page}) == []


@pytest.mark.parametrize('page', [
    PAGE.replace('let item=', 'rows=[];let item='),
    PAGE.replace('let item=', 'other.subscribe(rows=>{let item=').replace('this.selectedKey)})', 'this.selectedKey)})})'),
    PAGE.replace('catalog=inject(Catalog)', 'catalog=ignore(Catalog)'),
    PAGE.replace('load(){', 'load(){this.catalog=unknown;'),
    PAGE.replace('let item=', 'this.selectedKey=unknown;let item='),
    PAGE.replace('let item=rows.find(row=>row.key===this.selectedKey)', '')
        .replace('})}', '});other.subscribe(()=>{rows.find(row=>row.key===this.selectedKey)})}'),
    'function make(Catalog){'+PAGE+'}',
    'function make(){const Catalog=Other;'+PAGE+'}',
    'const Catalog=Other;'+PAGE,
    'function inject(x){return local;}'+PAGE,
    PAGE.replace('catalog=inject(Catalog);', 'catalog=inject(Catalog);catalog=local;'),
    PAGE.replace('this.catalog.find()', 'this.catalog.find().pipe(map(x=>localCollection))'),
    PAGE.replace('})\n.subscribe', '}).pipe(map(x=>({items:localCollection})))\n.subscribe'),
    PAGE.replace('})\n.subscribe', '}),other\n.subscribe'),
    PAGE.replace('let item=rows.find(row=>row.key===this.selectedKey)',
                 'function inspect(){rows.find(row=>row.key===this.selectedKey)}'),
    'class Page{catalog=inject(Catalog);reader=inject(Reader);load(){const unused={items:this.catalog.find()};this.reader.get(this.selectedKey);other.subscribe(({items:rows})=>{rows.find(row=>row.key===this.selectedKey)})}}',
])
def test_mutation_shadowing_and_later_callbacks_cannot_prove_response_origin(page):
    assert extract_response_argument_bindings({'services.js': SERVICES, 'page.js': page}) == []


def test_zero_response_value_limit_does_not_emit_a_request():
    binding = extract_response_argument_bindings({'s.js': SERVICES, 'p.js': PAGE})[0]
    assert bind_response_values(binding, '/api/Examples/', {'data':[{'key':'daily'}]}, limit=0) == []


def test_write_service_and_conflicting_service_definitions_are_not_bindings():
    writes = SERVICES.replace('http.get(`${this.host}/${k}`)', 'http.post(`${this.host}/${k}`,body)')
    assert extract_response_argument_bindings({'s.js': writes, 'p.js': PAGE}) == []
    duplicate = SERVICES.replace('/documents', '/other-documents')
    assert extract_response_argument_bindings({'s.js': SERVICES, 'd.js': duplicate, 'p.js': PAGE}) == []


@pytest.mark.parametrize('services', [
    SERVICES.replace('get(k){return', 'get(k){k="fixed";return'),
    SERVICES.replace('get(k){return', 'get(k){k++;return'),
    SERVICES.replace('get(k){return', 'get(k){++k;return'),
    SERVICES.replace('return http.get(this.host+"/")', 'return http.get(this.host+"/").pipe(map(x=>localCollection))'),
    SERVICES.replace('return http.get(this.host+"/")', 'return http.get(this.host+"/").pipe(map((x)=>localCollection))'),
    SERVICES.replace('return http.get(this.host+"/")', 'return http.get(this.host+"/").pipe(map(toLocal))'),
    SERVICES.replace('find(){return http.get(this.host+"/")}', 'find(){http.get(this.host+"/");return localCollection}'),
])
def test_mutated_parameters_and_nonreturned_gets_do_not_prove_provenance(services):
    assert extract_response_argument_bindings({'s.js': services, 'p.js': PAGE}) == []


def test_repeated_subscriptions_keep_one_binding_without_callback_crossing():
    join = '''join({items:this.catalog.find(),doc:this.reader.get(this.selectedKey)})
    .subscribe(({items:rows})=>{rows.find(row=>row.key===this.selectedKey)});'''
    page = 'class Page{catalog=inject(Catalog);reader=inject(Reader);load(){'+join*1000+'}}'
    bindings = extract_response_argument_bindings({'s.js': SERVICES, 'p.js': page})
    assert len(bindings) == 1
    assert bindings[0].template == '/documents/${k}'


def test_binding_reads_only_named_collection_field_and_encodes_one_segment():
    binding = extract_response_argument_bindings({'s.js': SERVICES, 'p.js': PAGE})[0]
    values = bind_response_values(binding, '/api/Examples/?sort=name',
                                  {'data': [{'key': 'daily/report'}, {'key': 'a?b'}, {'id': 99}]})
    assert values == ['/documents/daily%2Freport', '/documents/a%3Fb']
    assert bind_response_values(binding, '/api/Other', {'data': [{'key': 'wrong'}]}) == []


@pytest.mark.parametrize('payload', [
    {'data': [{'key': True}, {'key': None}, {'key': {}}, {'key': '..'}, {'key': ''}]},
    {'secret': {'key': 'unrelated'}},
    {'data': {'key': 'not-a-collection'}},
])
def test_invalid_or_unrelated_json_values_are_not_request_arguments(payload):
    binding = extract_response_argument_bindings({'s.js': SERVICES, 'p.js': PAGE})[0]
    assert bind_response_values(binding, '/api/Examples/', payload) == []


def _discovery(monkeypatch, document_response, **options):
    from aidast.recon.tools import api_secondary_discovery as secondary
    requests = []
    def request(url, **kwargs):
        requests.append(url)
        if url.endswith('/main.js'):
            return 200, {'content-type': 'application/javascript'}, (SERVICES+PAGE).encode()
        if url.rstrip('/').endswith('/api/Examples'):
            return 200, {'content-type': 'application/json'}, b'{"data":[{"key":"daily"}]}'
        if url.endswith('/documents/daily'):
            return document_response
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        raise AssertionError('Unexpected request: '+url)
    monkeypatch.setattr(secondary, '_http_request', request)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}],
                                                        proxy_url='http://127.0.0.1:8080', **options)
    return rows, requests


def test_provenance_bound_get_is_probed_and_retains_response_source(monkeypatch):
    rows, _ = _discovery(monkeypatch, (200, {'content-type':'application/json'}, b'{"document":"report"}'))
    row = next(row for row in rows if row['path'] == '/documents/daily')
    assert row['evidence']['argument_source'] == 'https://example.test/api/Examples/'
    assert row['evidence']['argument_field'] == 'key'
    assert row['evidence']['path_template'] == '/documents/${k}'


def test_two_get_templates_share_remaining_probe_capacity(monkeypatch):
    from aidast.recon.tools import api_secondary_discovery as secondary
    services = SERVICES + 'Other=(()=>{class C{host="/reports";get(k){return http.get(`${this.host}/${k}`)}}return C})();'
    page = PAGE.replace('reader=inject(Reader);', 'reader=inject(Reader);other=inject(Other);')
    page = page.replace('doc:this.reader.get(this.selectedKey)',
                        'doc:this.reader.get(this.selectedKey),other:this.other.get(this.selectedKey)')
    def request(url, **kwargs):
        if url.endswith('/main.js'):
            return 200, {'content-type':'application/javascript'}, (services+page).encode()
        if url.rstrip('/').endswith('/api/Examples'):
            return 200, {'content-type':'application/json'}, b'{"data":[{"key":"first"},{"key":"second"}]}'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if '/documents/' in url or '/reports/' in url:
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 2)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}])
    assert {row['path'] for row in rows if row['source']=='adaptive_js_response_argument'} == {
        '/documents/first', '/reports/first',
    }


@pytest.mark.parametrize('response', [
    (200, {'content-type':'text/html'}, b'<html>SPA</html>'),
    (404, {'content-type':'application/json'}, b'{"error":"missing"}'),
    (200, {'content-type':'application/json'}, b'not json'),
])
def test_bound_get_still_requires_actual_valid_route_response(monkeypatch, response):
    rows, _ = _discovery(monkeypatch, response)
    assert not any(row['path'].startswith('/documents/') for row in rows)


def test_provenance_binding_does_not_probe_excluded_target(monkeypatch):
    from aidast.recon.policy import TargetPolicy
    from aidast.scope.models import AssetType
    policy = TargetPolicy(scope_id='s', policy_id='p', asset_type=AssetType.URL, asset='https://example.test/',
                          allowed_schemes=['https'], allowed_hosts=['example.test'], allowed_ports=[443],
                          excluded_path_prefixes=['/documents'])
    rows, requests = _discovery(monkeypatch, (200, {'content-type':'application/json'}, b'{"ok":true}'), target_policy=policy)
    assert not any('/documents/' in url for url in requests)
    assert not any(row['path'].startswith('/documents/') for row in rows)
