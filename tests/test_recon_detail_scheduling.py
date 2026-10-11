"""Deduplicate resolved GET details without conflating collection queries."""
import json
from urllib.parse import urlsplit

import pytest

from aidast.recon.tools import api_secondary_discovery as secondary


@pytest.mark.parametrize('variants', [
    ['/api/Inventory', '/api/Inventory/'],
    ['/api/Inventory?sort=asc', '/api/Inventory?sort=desc'],
])
def test_equivalent_collection_results_probe_detail_once_and_keep_other_resource(monkeypatch, variants):
    script = ''.join('http.get('+json.dumps(path)+');' for path in variants + ['/api/Zones'])
    requested = []
    def request(url, **kwargs):
        requested.append(url)
        path = urlsplit(url).path
        if path == '/main.js':
            return 200, {'content-type':'application/javascript'}, script.encode()
        if '__aidast_missing_control__' in path:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if path.rstrip('/') in {'/api/Inventory', '/api/Zones'}:
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}'
        if path in {'/api/Inventory/7', '/api/Zones/7'}:
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 2)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}])
    assert requested.count('https://example.test/api/Inventory/7') == 1
    assert '/api/Zones/7' in {row['path'] for row in rows}
    assert all('https://example.test'+path in requested for path in variants)


def test_query_variants_with_different_actual_ids_keep_both_details(monkeypatch):
    requested = []
    def request(url, **kwargs):
        requested.append(url)
        parsed = urlsplit(url)
        if parsed.path == '/main.js':
            return 200, {'content-type':'application/javascript'}, b'http.get("/api/Inventory?page=1");http.get("/api/Inventory?page=2");'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if parsed.path == '/api/Inventory':
            item_id = 7 if parsed.query == 'page=1' else 8
            return 200, {'content-type':'application/json'}, json.dumps({'data':[{'id':item_id}]}).encode()
        if parsed.path in {'/api/Inventory/7','/api/Inventory/8'}:
            return 200, {'content-type':'application/json'}, json.dumps({'data':{'id':int(parsed.path.rsplit('/',1)[1])}}).encode()
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 2)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}])
    assert {row['path'] for row in rows if row['source']=='adaptive_collection_detail'} == {'/api/Inventory/7','/api/Inventory/8'}


@pytest.mark.parametrize('resource, document', [('Inventory','documents'), ('Packages','receipts')])
def test_all_discovery_sources_share_slots_before_second_collection(monkeypatch, resource, document):
    script = f'''
    Catalog=(()=>{{class C{{host="/api/{resource}";find(){{return http.get(this.host+"/")}}}}return C}})();
    Reader=(()=>{{class C{{host="/{document}";get(k){{return http.get(`${{this.host}}/${{k}}`)}}}}return C}})();
    class Page{{catalog=inject(Catalog);reader=inject(Reader);
    load(){{join({{items:this.catalog.find(),doc:this.reader.get(this.selectedKey)}})
    .subscribe(({{items:rows}})=>{{rows.find(row=>row.key===this.selectedKey)}})}}}}
    http.get("/api/Zones");http.get(`/rest/{resource}/${{id}}/history`);
    '''
    requested = []
    def request(url, **kwargs):
        requested.append(urlsplit(url).path)
        path = urlsplit(url).path
        if path == '/main.js':
            return 200, {'content-type':'application/javascript'}, script.encode()
        if '__aidast_missing_control__' in path:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if path.rstrip('/') in {'/api/'+resource,'/api/Zones'}:
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7,"key":"daily"},{"id":8,"key":"weekly"}]}'
        if path in {'/api/'+resource+'/7','/api/Zones/7'}:
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        if path in {'/rest/'+resource+'/7/history', '/'+document+'/daily','/'+document+'/weekly'}:
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 3)
    diagnostics = []
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}],
                diagnostic_callback=lambda event, **details:diagnostics.append((event,details)))
    assert {row['path'] for row in rows if row['source']!='adaptive_js' and row.get('verification_status')!='candidate'} == {
        '/api/'+resource+'/7', '/rest/'+resource+'/7/history', '/'+document+'/daily',
    }
    assert '/api/Zones/7' not in requested
    assert '/'+document+'/weekly' not in requested
    completed = next(details for event,details in diagnostics if event=='completed')
    assert completed['detail_probes'] == 3
    assert completed['detail_probes_by_source'] == {'collection':1, 'template':1, 'response_argument':1}


def test_observed_and_excluded_detail_jobs_do_not_consume_other_source_slots(monkeypatch):
    from aidast.recon.policy import TargetPolicy
    from aidast.scope.models import AssetType
    policy = TargetPolicy(scope_id='s', policy_id='p', asset_type=AssetType.URL, asset='https://example.test/',
                          allowed_schemes=['https'], allowed_hosts=['example.test'], allowed_ports=[443],
                          excluded_path_prefixes=['/rest/Inventory/7/private'])
    requested = []
    def request(url, **kwargs):
        requested.append(urlsplit(url).path)
        if url.endswith('/main.js'):
            return 200, {'content-type':'application/javascript'}, b'http.get("/api/Inventory");http.get(`/rest/Inventory/${id}/private`);http.get(`/rest/Inventory/${id}/history`);'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if url.endswith('/api/Inventory'):
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}'
        if url.endswith('/rest/Inventory/7/history'):
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 1)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/',
                [{'path':'/main.js'}, {'path':'/api/Inventory/7'}], target_policy=policy, proxy_url='http://127.0.0.1:8080')
    assert '/rest/Inventory/7/history' in {row['path'] for row in rows}
    assert '/api/Inventory/7' not in requested
    assert '/rest/Inventory/7/private' not in requested


@pytest.mark.parametrize('observed', [False, True])
def test_detail_response_reused_for_collection_provenance_without_second_request(monkeypatch, observed):
    requested = []
    def request(url, **kwargs):
        requested.append(url)
        if url.endswith('/main.js'):
            return 200, {'content-type':'application/javascript'}, b'http.get("/api/Inventory");http.get("/api/Inventory/7");http.get("/api/Zones");'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if url.endswith(('/api/Inventory','/api/Zones')):
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}'
        if url.endswith(('/api/Inventory/7','/api/Zones/7')):
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 1)
    endpoints = [{'path':'/main.js'}]
    responses = []
    if observed:
        endpoints.append({'method':'GET','url':'https://example.test/api/Inventory/7'})
        responses.append({'method':'GET','url':'https://example.test/api/Inventory/7',
                          'response_status':200,'response_headers':{'content-type':'application/json'},
                          'response_body':'{"data":{"id":7}}','policy_blocked':False,'capture_bodies':True})
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', endpoints, observed_responses=responses)
    detail = next(row for row in rows if row['path']=='/api/Inventory/7' and row['source']=='adaptive_collection_detail')
    assert detail['evidence']['collection_url']=='https://example.test/api/Inventory'
    assert requested.count('https://example.test/api/Inventory/7') == int(not observed)
    assert '/api/Zones/7' in {row['path'] for row in rows}


def test_duplicate_collection_jobs_do_not_spend_turns_while_templates_compete(monkeypatch):
    collections = [('/api/Inventory?view='+str(i), 'GET') for i in range(25)] + [('/api/Zones','GET')]
    templates = [('/rest/Inventory/${id}/report'+str(i), 'GET') for i in range(25)]
    monkeypatch.setattr(secondary, 'extract_js_api_paths', lambda *args:collections+templates)
    requested = []
    def request(url, **kwargs):
        path = urlsplit(url).path
        requested.append(path)
        if path == '/main.js':
            return 200, {'content-type':'application/javascript'}, b'// synthetic API metadata'
        if '__aidast_missing_control__' in path:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if path in {'/api/Inventory','/api/Zones'}:
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}'
        if path in {'/api/Inventory/7','/api/Zones/7'}:
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        if path.startswith('/rest/Inventory/7/report'):
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}])
    assert '/api/Zones/7' in {row['path'] for row in rows}
    assert requested.index('/api/Zones/7') < requested.index('/rest/Inventory/7/report10')
    assert requested.count('/api/Inventory/7') == 1
    assert sum(path.startswith('/rest/Inventory/7/report') and '__aidast_missing_control__' not in path for path in requested)==18


def test_unavailable_controls_have_separate_bounded_attempts(monkeypatch):
    paths = [('/api/Inventory','GET')] + [('/rest/Inventory/${id}/report'+str(i)+'/show','GET') for i in range(25)]
    monkeypatch.setattr(secondary, 'extract_js_api_paths', lambda *args:paths)
    controls = []
    def request(url, **kwargs):
        path = urlsplit(url).path
        if path == '/main.js':
            return 200, {'content-type':'application/javascript'}, b'// synthetic metadata'
        if path.startswith('/rest/Inventory/7/report'):
            controls.append(path)
            return None, {}, b''
        if '__aidast_missing_control__' in path:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if path == '/api/Inventory':
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}'
        if path == '/api/Inventory/7':
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    diagnostics = []
    secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}],
                diagnostic_callback=lambda event, **details:diagnostics.append((event,details)))
    assert len(controls) == 20
    completed = next(details for event,details in diagnostics if event=='completed')
    assert completed['detail_control_probes'] == 20
    assert completed['detail_probes'] == 1


@pytest.mark.parametrize('cached_literal', [False, True])
def test_failed_control_spends_a_turn_without_starving_response_source(monkeypatch, cached_literal):
    from aidast.recon.tools.js_argument_bindings import ResponseArgumentBinding
    paths = [('/api/Inventory','GET'),('/api/Zones','GET'),('/documents/${key}','GET')]
    paths += [('/rest/Inventory/${id}/report'+str(i)+'/show','GET') for i in range(25)]
    if cached_literal:
        paths += [('/rest/Inventory/7/report'+str(i)+'/show','GET') for i in range(25)]
    monkeypatch.setattr(secondary, 'extract_js_api_paths', lambda *args:paths)
    monkeypatch.setattr(secondary, 'extract_response_argument_bindings', lambda *args:[
        ResponseArgumentBinding('/documents/${key}','/api/Inventory','key',('main.js',))])
    def request(url, **kwargs):
        path = urlsplit(url).path
        if path == '/main.js':
            return 200, {'content-type':'application/javascript'}, b'// synthetic metadata'
        if path.startswith('/rest/Inventory/7/report'):
            if '__aidast_missing_control__' in path:
                return None, {}, b''
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        if '__aidast_missing_control__' in path:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if path in {'/api/Inventory','/api/Zones'}:
            return 200, {'content-type':'application/json'}, b'{"data":[{"id":7,"key":"daily"}]}'
        if path in {'/api/Inventory/7','/api/Zones/7'}:
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        if path == '/documents/daily':
            return 200, {'content-type':'application/json'}, b'{"found":true}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    monkeypatch.setattr(secondary, 'ADAPTIVE_MAX_DETAIL_PROBES', 2)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/', [{'path':'/main.js'}])
    assert '/documents/daily' in {row['path'] for row in rows}
