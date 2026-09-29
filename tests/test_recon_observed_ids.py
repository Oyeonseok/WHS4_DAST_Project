"""Observed collection IDs must unlock details without refetching the collection."""
import json
from pathlib import Path
import pytest
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools import mitm_proxy


def _record(url='https://example.test/api/Items', body=None, **overrides):
    record={'method':'GET','url':url,'response_status':200,
            'response_headers':{'content-type':'application/json'},
            'response_body':json.dumps({'data':[{'id':7}]} if body is None else body),
            'policy_blocked':False,'capture_bodies':True}
    record.update(overrides)
    return record


def _run(monkeypatch, records):
    requests=[]
    def request(url, **kwargs):
        requests.append(url)
        if url.endswith('/main.js'):
            return 200, {'content-type':'application/javascript'}, b'http.get("/api/Items");http.get(`/rest/items/${id}/reviews`)'
        if '__aidast_missing_control__' in url:
            return 404, {'content-type':'application/json'}, b'{"error":"missing"}'
        if url.endswith('/api/Items'):
            return 200, {'content-type':'application/json'}, b'{"data":[]}'
        if url.endswith('/api/Items/7'):
            return 200, {'content-type':'application/json'}, b'{"data":{"id":7}}'
        if url.endswith('/rest/items/7/reviews'):
            return 200, {'content-type':'application/json'}, b'{"data":[{"text":"ok"}]}'
        raise AssertionError(url)
    monkeypatch.setattr(secondary,'_http_request',request)
    kwargs={'observed_responses':records} if records else {}
    return secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [{'path':'/main.js'},{'method':'GET','url':'https://example.test/api/Items?limit=10'}],**kwargs),requests


def test_previously_observed_collection_unlocks_detail_and_template(monkeypatch):
    rows,requested=_run(monkeypatch,[_record()])
    assert {r['path'] for r in rows}=={'/api/Items/7','/rest/items/7/reviews'}
    assert not any(url.endswith('/api/Items') for url in requested)


@pytest.mark.parametrize('record',[
    _record(response_status=401),_record(method='POST'),_record(policy_blocked=True),
    _record(url='https://other.test/api/Items'),_record(body={'data':[]}),
    _record(body={'data':[{'id':'../private'},{'id':True}]}),
    _record(capture_bodies=False),_record(response_headers={'content-type':'text/html'}),
])
def test_invalid_observation_does_not_supply_an_id(monkeypatch,record):
    _,requested=_run(monkeypatch,[record])
    assert not any(url.endswith('/7') or '/reviews' in url for url in requested)


def test_capture_reader_recovers_complete_rows_only(tmp_path):
    p=tmp_path/'capture.jsonl'
    p.write_text(json.dumps(_record())+'\n'+json.dumps(_record(method='POST'))+'\n{broken\n'+json.dumps(_record())[:-4])
    reader=getattr(mitm_proxy,'read_observed_collection_responses',lambda *args: [])
    rows=reader(p)
    assert len(rows)==1
    assert rows[0]['url']=='https://example.test/api/Items'
    assert 'request_headers' not in rows[0]


def test_capture_reader_honors_body_capture_setting(tmp_path):
    p=tmp_path/'capture.jsonl';p.write_text(json.dumps(_record(capture_bodies=False))+'\n')
    reader=getattr(mitm_proxy,'read_observed_collection_responses',lambda *args: [])
    assert reader(p)==[]


@pytest.mark.parametrize('payload',[
    {'error':'denied','data':[{'id':7}]},
    {'status':'error','data':[{'id':7}]},
])
def test_error_collection_does_not_supply_an_id(monkeypatch,payload):
    _,requested=_run(monkeypatch,[_record(body=payload)])
    assert not any(url.endswith('/7') or '/reviews' in url for url in requested)


def test_error_detail_with_matching_id_is_not_promoted():
    row=secondary._verified_collection_detail('https://example.test/api/Items/7',
        'https://example.test/api/Items',200,{'content-type':'application/json'},
        b'{"error":"denied","data":{"id":7}}')
    assert row is None


def test_capture_reader_skips_oversized_complete_row_and_reads_later_evidence(tmp_path):
    p=tmp_path/'capture.jsonl'
    p.write_bytes(b'x'*2_100_001+b'\n'+(json.dumps(_record())+'\n').encode())
    assert [r['url'] for r in mitm_proxy.read_observed_collection_responses(p)] == [_record()['url']]
