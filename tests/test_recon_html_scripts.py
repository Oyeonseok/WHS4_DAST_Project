import json
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools import mitm_proxy


def document(url='https://example.test/workspace', body='<script src="/assets/business.js"></script>', **changes):
    return dict(method='GET', url=url, response_status=200,
                response_headers={'content-type':'text/html'}, response_body=body,
                capture_bodies=True, **changes)


def discover(monkeypatch, records, **options):
    requests=[]
    def request(url, **kwargs):
        requests.append(url)
        if url.endswith('/assets/business.js'):
            return 200, {'content-type':'application/javascript'}, b'fetch("/api/business");'
        if url.endswith('/api/business'):
            return 200, {'content-type':'application/json'}, b'{"data":[]}'
        return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
    monkeypatch.setattr(secondary, '_http_request', request)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [{'method':'GET','path':'/workspace'}], observed_responses=records, **options)
    return rows,requests


def test_captured_html_supplies_business_script_even_without_js_endpoints(monkeypatch):
    rows,requests=discover(monkeypatch,[document()])
    assert [row['path'] for row in rows]==['/api/business']
    assert rows[0]['evidence']['source_scripts']==['https://example.test/assets/business.js']
    assert requests.count('https://example.test/assets/business.js')==1


def test_html_base_and_script_types_are_respected(monkeypatch):
    rows,requests=discover(monkeypatch,[document(body='''<base href="/assets/">
      <script type="application/json" src="/data.js"></script>
      <script type="module" src="business.js#one"></script>
      <script src="business.js#two"></script>''')])
    assert [row['path'] for row in rows]==['/api/business']
    assert requests.count('https://example.test/assets/business.js')==1
    assert not any('/data.js' in url for url in requests)


def test_external_base_or_untrusted_html_cannot_seed_requests(monkeypatch):
    records=[document(body='<base href="https://outside.test/"><script src="/assets/business.js"></script>'),
             document(url='https://example.test/unobserved'),
             dict(document(), response_status=404),dict(document(),policy_blocked=True),
             document(body='<script src="https://u:p@example.test/assets/business.js"></script>')]
    rows,requests=discover(monkeypatch,records)
    assert rows==[] and requests==[]


def test_declared_script_limit_includes_all_document_seeds(monkeypatch):
    rows,requests=discover(monkeypatch,[document(body='<script src="/one.js"></script><script src="/assets/business.js"></script>')],max_scripts=1)
    assert rows==[] and 'https://example.test/assets/business.js' not in requests


def test_capture_reader_includes_successful_html_and_nonprefix_json(tmp_path):
    file=tmp_path/'capture.jsonl'
    records=[document(),dict(document(url='https://example.test/items'),response_headers={'content-type':'application/json'},response_body='[]'),
             dict(document(),response_status=404),dict(document(),capture_bodies=False)]
    file.write_text(''.join(json.dumps(r)+'\n' for r in records))
    rows=mitm_proxy.read_observed_recon_responses(file)
    assert [r['url'] for r in rows]==['https://example.test/workspace','https://example.test/items']
    assert mitm_proxy.read_observed_collection_responses(file)==[]


def test_malformed_base_skips_one_document_without_aborting_other_documents(monkeypatch):
    rows,requests=discover(monkeypatch,[document(body='<base href="http://[invalid"><script src="/bad.js"></script>'),document()])
    assert [r['path'] for r in rows]==['/api/business']


def test_duplicate_and_external_declarations_do_not_use_real_script_slots(monkeypatch):
    html='<script src="https://outside.test/vendor.js"></script>'*40
    html+='<script src="/one.js"></script>'*40+'<script src="/assets/business.js"></script>'
    rows,requests=discover(monkeypatch,[document(body=html)],max_scripts=2)
    assert [r['path'] for r in rows]==['/api/business']
    assert requests.count('https://example.test/one.js')==1


def test_reader_keeps_late_documents_and_collection_evidence_separately(tmp_path):
    file=tmp_path/'capture.jsonl'
    records=[document(url=f'https://example.test/page/{i}') for i in range(120)]
    records+=[dict(document(url='https://example.test/api/Items'),response_headers={'content-type':'application/json'},response_body='[{"id":7}]'),document()]
    file.write_text(''.join(json.dumps(r)+'\n' for r in records))
    rows=mitm_proxy.read_observed_recon_responses(file)
    assert len(rows)<=150
    assert any(r['url'].endswith('/api/Items') for r in rows)
    assert any(r['url'].endswith('/workspace') for r in rows)
