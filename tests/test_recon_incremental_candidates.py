"""Regression coverage for discovery losses seen in the local Recon experiment."""
from aidast.recon.tools import api_secondary_discovery as secondary


def _discover(monkeypatch, scripts, **options):
    requests = []
    def request(url, **kwargs):
        requests.append(url)
        name = url.rsplit('/', 1)[-1]
        if name in scripts:
            return 200, {'content-type': 'application/javascript'}, scripts[name].encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        return 200, {'content-type': 'application/json'}, b'{"data":[]}'
    monkeypatch.setattr(secondary, '_http_request', request)
    results = secondary.discover_adaptive_js_api_candidates(
        'https://example.test/', [{'path': '/'+name} for name in scripts], **options)
    return results, requests


def test_late_literal_get_is_not_lost_after_thirty_candidates(monkeypatch):
    script = ';'.join(f'http.get("/api/item{i}")' for i in range(35))
    results, _ = _discover(monkeypatch, {'main.js': script})
    assert '/api/item34' in {item['path'] for item in results}


def test_explicit_writes_do_not_displace_get_probes(monkeypatch):
    script = 'http.post("/api/write");http.delete("/api/remove");http.get("/api/read")'
    results, requests = _discover(monkeypatch, {'main.js': script}, max_candidates=1)
    assert [item['path'] for item in results] == ['/api/read']
    assert 'https://example.test/api/write' not in requests
    assert 'https://example.test/api/remove' not in requests


def test_get_in_later_bundle_is_prioritized_over_unknown_literals(monkeypatch):
    results, _ = _discover(monkeypatch, {
        'vendor.js': 'const hint="/api/unknown";',
        'main.js': 'http.get("/api/read")',
    }, max_candidates=1)
    assert [item['path'] for item in results] == ['/api/read']


def test_fetch_write_options_are_not_probed_as_get(monkeypatch):
    results, _ = _discover(monkeypatch, {'main.js':
        'fetch("/api/write",{method:"POST"});fetch("/api/read")'})
    assert [item['path'] for item in results] == ['/api/read']


def test_origin_prefixed_template_get_is_discovered(monkeypatch):
    results, _ = _discover(monkeypatch, {'main.js':
        'http.get(`${settings.hostServer}/rest/account/status`);'
        'http.post(`${settings.hostServer}/rest/account/setup`, body);'})
    assert [item['path'] for item in results] == ['/rest/account/status']


def test_literal_suffix_uses_its_own_class_url_base(monkeypatch):
    script = '''class Orders {host=this.server+`/rest/order-history`;
        list(){return this.http.get(this.host+"/orders")}}
        class Other {host=this.server+"/rest/other";
        list(){return this.http.get(`${this.host}/summary`)}}'''.replace('        ', '       ')
    results, _ = _discover(monkeypatch, {'main.js': script})
    paths = {item['path'] for item in results}
    assert '/rest/order-history/orders' in paths
    assert '/rest/other/summary' in paths
    assert '/rest/order-history/summary' not in paths
    assert '/rest/other/orders' not in paths


def test_unresolved_path_parameter_is_not_requested_as_literal(monkeypatch):
    results, requests = _discover(monkeypatch, {'main.js':
        'http.get(`${host}/rest/items/${unknown}/reviews`);'
        'http.get("https://outside.test/api/private");'})
    assert results == []
    assert not any('unknown' in url or 'outside.test' in url for url in requests)


def test_unterminated_js_string_has_bounded_analysis_time():
    import subprocess
    import sys
    code = '''from aidast.recon.tools.js_api_paths import extract_js_api_paths
script = "const path='" + "\\\\" * 5000
assert extract_js_api_paths(script, lambda *args: None) == []
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=2)
    assert result.returncode == 0, result.stderr.decode()


def test_regex_literals_do_not_hide_later_api_calls(monkeypatch):
    script = '''const pattern=/["'`]/; const braces=/[{}]/;
    http.get(`${server}/rest/after-regex`);'''
    results, _ = _discover(monkeypatch, {'main.js': script})
    assert [item['path'] for item in results] == ['/rest/after-regex']


def _reviews_discovery(monkeypatch, collection_body, review_body=b'{"data":[{"message":"ok"}]}'):
    requested = []
    def request(url, **kwargs):
        requested.append(url)
        if url.endswith('main.js'):
            script = '''http.get("/api/Products");class Reviews {host="/rest/products";
              get(id){return http.get(`${this.host}/${id}/reviews`)}}'''
            return 200, {'content-type': 'application/javascript'}, script.encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        if url.endswith('/api/Products'):
            return 200, {'content-type': 'application/json'}, collection_body
        if url.endswith('/rest/products/7/reviews'):
            return 200, {'content-type': 'application/json'}, review_body
        return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
    monkeypatch.setattr(secondary, '_http_request', request)
    results = secondary.discover_adaptive_js_api_candidates(
        'https://example.test/', [{'path': '/main.js'}])
    return results, requested


def test_nested_get_template_uses_observed_collection_id(monkeypatch):
    results, requests = _reviews_discovery(monkeypatch, b'{"data":[{"id":7}]}')
    assert '/rest/products/7/reviews' in {item['path'] for item in results}
    assert 'https://example.test/rest/products/7/reviews' in requests


def test_empty_collection_does_not_invent_template_id(monkeypatch):
    _, requests = _reviews_discovery(monkeypatch, b'{"data":[]}')
    assert not any('/reviews' in url for url in requests)


def test_template_binding_rejects_untrusted_ids(monkeypatch):
    _, requests = _reviews_discovery(monkeypatch, b'{"data":[{"id":"../private"},{"id":true}]}')
    assert not any('/reviews' in url or 'private' in url for url in requests)


def test_template_response_error_is_not_promoted(monkeypatch):
    results, _ = _reviews_discovery(monkeypatch, b'{"data":[{"id":7}]}',
                                   b'{"error":"missing"}')
    assert '/rest/products/7/reviews' not in {item['path'] for item in results}


def test_unresolved_origin_keeps_complete_api_literal(monkeypatch):
    results, _ = _discover(monkeypatch, {'main.js':
        'class Client{read(){return this.http.get(this.hostServer+"/rest/account")}}'})
    assert [item['path'] for item in results] == ['/rest/account']


def test_nested_and_indirect_fetch_options_do_not_become_get(monkeypatch):
    results, requests = _discover(monkeypatch, {'main.js':
        'fetch("/api/write",{method:"POST",headers:{"Content-Type":"application/json"}});'
        'fetch("/api/unknown",options);http.post(/* comment */ "/api/commented",body);'
        'fetch("/api/read",{headers:{accept:"application/json"}})'})
    assert [item['path'] for item in results] == ['/api/read']
    assert not any(url.endswith(('/api/write','/api/unknown','/api/commented')) for url in requests)


def test_unrelated_local_and_static_assignments_do_not_resolve_instance_base(monkeypatch):
    script = '''class Other { build(){other.host="/api/wrong"}
      read(){return http.get(`${this.host}/read`)}}
      class Local {build(){const host="/api/local"}
      read(){return http.get(`${this.host}/read`)}}
      class Static {static host="/api/static";
      read(){return http.get(`${this.host}/read`)}}'''
    _, requests = _discover(monkeypatch, {'main.js':script})
    assert not any(url.endswith(('/api/wrong/read','/api/local/read','/api/static/read')) for url in requests)


def test_query_collection_detail_is_built_from_path():
    url = secondary._collection_detail_url('https://example.test/api/Products?limit=10',
        200, {'content-type':'application/json'}, b'{"data":[{"id":7}]}', None)
    assert url == 'https://example.test/api/Products/7'


def test_large_bundle_scope_lookup_has_bounded_runtime():
    import subprocess
    import sys
    code = '''from aidast.recon.tools.js_api_paths import extract_js_api_paths
script = 'class Client{host="/api/Items";read(){return http.get(`${this.host}/all`)}};'*18000
assert len(extract_js_api_paths(script,lambda *args:None)) == 36000
'''
    result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=6)
    assert result.returncode==0,result.stderr.decode()


def test_bracket_and_parenthesized_writes_are_excluded(monkeypatch):
    results, _ = _discover(monkeypatch, {'main.js':
        'http["post"]("/api/write",body);http.post(("/api/grouped"),body);'
        'http["get"]("/api/read")'})
    assert [item['path'] for item in results] == ['/api/read']


def test_plain_fetch_classification_has_bounded_runtime():
    import subprocess
    import sys
    code='''from aidast.recon.tools.js_api_paths import extract_js_api_paths,literal_call_method
paths=extract_js_api_paths('fetch("/api/x");'*10000,literal_call_method)
assert len(paths)==10000 and all(method=='GET' for _,method in paths)
'''
    result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=3)
    assert result.returncode==0,result.stderr.decode()
