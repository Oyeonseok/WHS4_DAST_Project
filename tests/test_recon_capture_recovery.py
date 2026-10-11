import json
import pytest
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools import mitm_proxy
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


def record(url='https://example.test/reports/27', **changes):
    r=dict(method='GET',url=url,response_status=200,response_headers={'content-type':'application/json'},
           response_body='{"records":[]}',capture_bodies=True,policy_blocked=False,
           static_resource=False,duplicate=False,candidate_probe=False)
    r.update(changes)
    return r


def policy():
    return TargetPolicy(scope_id='scope',policy_id='policy',asset_type=AssetType.URL,
        asset='https://example.test/',allowed_hosts=['example.test'],allowed_ports=[443],
        allowed_schemes=['https'],allowed_methods=['GET'],allowed_path_prefixes=['/'])


def recover(monkeypatch, records, endpoints=(), **options):
    requests=[]
    def request(url, **kwargs):
        requests.append(url)
        assert '__aidast_missing_control__' in url, 'Captured response must be reused'
        return 404,{'content-type':'application/json'},b'{"error":"missing"}'
    monkeypatch.setattr(secondary,'_http_request',request)
    rows=secondary.recover_observed_json_gets('https://example.test/',list(endpoints),
        observed_responses=records,target_policy=policy(),proxy_url='http://127.0.0.1:8888',broker=object(),**options)
    return rows,requests


def test_unassociated_captured_get_is_verified_without_repeating_actual_request(monkeypatch):
    rows,requests=recover(monkeypatch,[record()])
    assert len(rows)==1 and rows[0]['verification_status']=='verified'
    assert rows[0]['path']=='/reports/27'
    assert rows[0]['evidence']['response_status']==200
    assert len(requests)==1


@pytest.mark.parametrize('r',[record(method='POST'),record(policy_blocked=True),record(capture_bodies=False),
    record(candidate_probe=True),record(static_resource=True),record(url='https://outside.test/x'),
    record(response_status=401),record(response_status=200,response_body='{"error":"denied"}'),
    record(response_headers={'content-type':'text/html'})])
def test_untrusted_or_unverified_capture_is_not_promoted(monkeypatch,r):
    rows,requests=recover(monkeypatch,[r]);assert rows==[] and requests==[]


def test_known_verified_url_is_not_rechecked_but_candidate_can_recover(monkeypatch):
    rows,requests=recover(monkeypatch,[record()],endpoints=[{'method':'GET','url':record()['url'],'verification_status':'verified'}])
    assert rows==[] and requests==[]
    rows,_=recover(monkeypatch,[record()],endpoints=[{'method':'GET','url':record()['url'],'verification_status':'candidate'}])
    assert rows[0]['verification_status']=='verified'


def test_capture_matching_missing_control_is_not_verified(monkeypatch):
    monkeypatch.setattr(secondary,'_http_request',lambda url,**kw:(200,{'content-type':'application/json'},b'{"records":[]}'))
    rows=secondary.recover_observed_json_gets('https://example.test/',[],observed_responses=[record()],
        target_policy=policy(),proxy_url='http://127.0.0.1:8888',broker=object())
    assert not any(r['verification_status']=='verified' for r in rows)


def test_policy_blocked_missing_control_cannot_verify_capture(monkeypatch):
    monkeypatch.setattr(secondary,'_http_request',lambda url,**kw:(403,{'content-type':'text/plain'},secondary._POLICY_BLOCK_BODY))
    rows=secondary.recover_observed_json_gets('https://example.test/',[],observed_responses=[record()],
        target_policy=policy(),proxy_url='http://127.0.0.1:8888',broker=object())
    assert rows[0]['verification_status']=='candidate'
    assert rows[0]['evidence']['verification_reason']=='control_unavailable'


def test_recent_reader_recovers_json_after_long_ffuf_prefix_and_ignores_partial_tail(tmp_path):
    p=tmp_path/'capture.jsonl'
    p.write_text((json.dumps(record(response_status=404))+'\n')*2500+json.dumps(record())+'\n'+json.dumps(record(url='https://example.test/partial'))[:-5])
    rows=mitm_proxy.read_recent_json_responses(p)
    assert [r['url'] for r in rows]==[record()['url']]


def test_recovered_capture_is_associated_in_database_and_exported(monkeypatch, tmp_path):
    from aidast.recon import db
    from aidast.recon.annotations import ObservationRecorder
    from aidast.recon.surface import export_surface
    conn=db.init_db(tmp_path/'recon.db')
    try:
        db.insert_scan(conn,scan_id='scan',scope_type='test',scope_value='example.test')
        asset=db.insert_asset(conn,scan_id='scan',identifier='example.test',asset_type='DOMAIN')
        origin=db.upsert_origin(conn,asset_id=asset,scheme='https',host='example.test',port=443,base_url='https://example.test')
        rows,_=recover(monkeypatch,[record()])
        ObservationRecorder(conn,origin_id=origin,scan_id='scan').record('observed_json_recovery',rows)
        p=tmp_path/'capture.jsonl'
        p.write_text(json.dumps(record())+'\n')
        mitm_proxy.ingest_mitm_capture(conn,p,origin_id=origin)
        assert conn.execute('SELECT endpoint_id FROM http_transactions').fetchone()[0] is not None
        surface=json.loads(export_surface(conn,scan_id='scan',output_path=tmp_path/'surface.json').read_text())
        endpoints=surface['origins'][0]['endpoints']
        assert [e['path'] for e in endpoints]==['/reports/:id']
        assert endpoints[0]['verification_status']=='verified'
    finally:
        conn.close()
