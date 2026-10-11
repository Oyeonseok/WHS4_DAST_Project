"""GET endpoints in referenced first-party modules must reach the surface."""
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType
from aidast.recon.tools.js_api_paths import extract_js_module_references, extract_js_api_paths, literal_call_method


def _discover(monkeypatch, files, **options):
    requested = []
    def request(url, **kwargs):
        requested.append(url)
        if url in files:
            if isinstance(files[url], tuple):
                return files[url]
            return 200, {'content-type': 'application/javascript'}, files[url].encode()
        if '__aidast_missing_control__' in url:
            return 404, {'content-type': 'application/json'}, b'{"error":"missing"}'
        if url == 'https://example.test/api/chunk-only':
            return 200, {'content-type': 'application/json'}, b'{"data":[]}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary, '_http_request', request)
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [{'path': '/assets/main.js'}], **options)
    return rows, requested


def test_get_in_transitive_relative_chunk_is_discovered_with_its_source(monkeypatch):
    rows, requests = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./lazy.js");',
        'https://example.test/assets/lazy.js': 'export * from "./nested.js";',
        'https://example.test/assets/nested.js': 'http.get("/api/chunk-only");import("./lazy.js")',
    })
    assert [row['path'] for row in rows] == ['/api/chunk-only']
    assert rows[0]['evidence']['source_scripts'] == ['https://example.test/assets/nested.js']
    assert requests.count('https://example.test/assets/lazy.js') == 1


def test_dependency_array_chunk_is_followed(monkeypatch):
    rows, _ = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'const dependencies=["lazy.js"];',
        'https://example.test/assets/lazy.js': 'http.get("/api/chunk-only")',
    })
    assert [row['path'] for row in rows] == ['/api/chunk-only']


def test_external_credentials_comments_and_unresolved_modules_are_not_fetched(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': r'''import("https://outside.test/lazy.js");
          import("https://user:password@example.test/private.js");
          import(`./${unknown}.js`); // import("./comment.js")
          const regex=/".\/regex.js"/; /* import("./comment2.js") */''',
    })
    assert rows == []
    assert not any(url.endswith(('.js', '.mjs')) for url in requested[1:])


def test_script_request_limit_includes_seed_and_imports(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./one.js");import("./two.js")',
        'https://example.test/assets/one.js': '',
    }, max_scripts=2)
    assert rows == []
    assert 'https://example.test/assets/two.js' not in requested


def test_script_byte_limit_stops_graph_and_api_extraction(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./lazy.js");' + ' '*100,
    }, max_script_bytes=50)
    assert rows == []
    assert 'https://example.test/assets/lazy.js' not in requested


def test_chunk_write_methods_remain_excluded(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./lazy.js")',
        'https://example.test/assets/lazy.js': 'http.post("/api/write",body);http.get("/api/chunk-only")',
    })
    assert [row['path'] for row in rows] == ['/api/chunk-only']
    assert 'https://example.test/api/write' not in requested


def test_identical_module_bodies_keep_different_relative_dependency_bases(monkeypatch):
    rows, _ = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./a/same.js");import("./b/same.js")',
        'https://example.test/assets/a/same.js': 'import("./lazy.js")',
        'https://example.test/assets/b/same.js': 'import("./lazy.js")',
        'https://example.test/assets/a/lazy.js': '',
        'https://example.test/assets/b/lazy.js': 'http.get("/api/chunk-only")',
    })
    assert [row['path'] for row in rows] == ['/api/chunk-only']


def test_html_and_error_scripts_do_not_supply_get_candidates(monkeypatch):
    rows, _ = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("./missing.js");import("./fallback.js")',
        'https://example.test/assets/missing.js': (404, {'content-type': 'application/javascript'}, b'http.get("/api/chunk-only")'),
        'https://example.test/assets/fallback.js': (200, {'content-type': 'text/html'}, b'http.get("/api/chunk-only")'),
    })
    assert rows == []


def test_same_origin_chunk_still_respects_excluded_policy_path(monkeypatch):
    policy = TargetPolicy(scope_id='scope', policy_id='policy', asset_type=AssetType.URL,
        asset='https://example.test/', allowed_hosts=['example.test'], allowed_ports=[443],
        allowed_schemes=['https'], allowed_methods=['GET'], allowed_path_prefixes=['/'],
        excluded_path_prefixes=['/private'])
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'import("/private/lazy.js")',
    }, target_policy=policy, proxy_url='http://127.0.0.1:8888', broker=object())
    assert rows == []
    assert 'https://example.test/private/lazy.js' not in requested


def test_js_extension_in_http_write_or_plain_hint_is_not_a_module(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': 'http.post("/api/write.js",body);const hint="notes.js";',
    })
    assert rows == []
    assert not any(url.endswith('.js') for url in requested[1:])


def test_plain_text_html_body_does_not_supply_api_paths(monkeypatch):
    rows, _ = _discover(monkeypatch, {
        'https://example.test/assets/main.js': (200, {'content-type': 'text/plain'},
            b'<html><script>http.get("/api/chunk-only")</script></html>'),
    })
    assert rows == []


def test_import_worker_and_bundler_dependency_contexts_are_recognized():
    script = '''import("./lazy.js");import {x} from "./shared.mjs";
      new Worker("./worker.js");
      const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["chunk-01.js","chunk-02.js"])))=>i.map(i=>d[i]);
      const hint="notes.js";http.post("/api/write.js",body);'''
    assert extract_js_module_references(script) == [
        './lazy.js', './shared.mjs', './worker.js', 'chunk-01.js', 'chunk-02.js']


def test_nested_http_argument_and_generic_new_url_are_not_modules(monkeypatch):
    rows, requested = _discover(monkeypatch, {
        'https://example.test/assets/main.js': '''http.post(new URL("/api/write.js",location.origin),body);
          const asset=new URL("notes.js",location.href);
          http.post({files:["/api/other.js"]},body);''',
    })
    assert rows == []
    assert not any(url.endswith('.js') for url in requested[1:])


def test_worker_import_meta_url_is_a_module_reference():
    assert extract_js_module_references(
        'new Worker(new URL("./worker.js",import.meta.url),{type:"module"})') == ['./worker.js']


def test_long_named_import_list_does_not_hide_module_reference():
    script = 'import {' + ','.join('symbol'+str(i) for i in range(100)) + '} from "./lazy.js";'
    assert extract_js_module_references(script) == ['./lazy.js']


def test_get_options_hint_does_not_become_explicit_get_evidence():
    paths = dict(extract_js_api_paths(
        'http.get("/api/read", {headers:{"X-Next":"/api/hint"}})', literal_call_method))
    assert paths['/api/read'] == 'GET'
    assert paths['/api/hint'] is None
