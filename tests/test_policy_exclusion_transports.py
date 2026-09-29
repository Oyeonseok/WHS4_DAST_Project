"""Exclusions stop physical calls before consuming request capacity (offline IO)."""
import io
import time
from types import SimpleNamespace

import pytest

from aidast.core.capture_receipt import prepare_http_request
from aidast.core.exclusion_guard import request_key, evaluate_exclusions
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy
from test_policy_exclusion_guard import policy as compiled, rule, predicate

URL = 'https://example.test/public'


def target(snapshot):
    return TargetPolicy(scope_id='scope', policy_id='policy', asset_type='URL',
        asset='https://example.test/', allowed_hosts=['example.test'],
        allowed_methods=['GET','POST'], request_exclusions=snapshot)


class Wire:
    def __init__(self, location=None):
        self.calls = []
        self.location = location

    def __call__(self, request, **kwargs):
        self.calls.append((request.full_url, request.get_method(), dict(request.header_items()), request.data))
        result = io.BytesIO(b'ok')
        result.status = 302 if self.location else 200
        result.headers = {'Location': self.location} if self.location else {}
        return result


def semantic(url=URL, headers=None, body=None, method='GET'):
    d = prepare_http_request(url, method=method, headers=headers, body=body)
    return compiled(rule(predicate('semantic', 'resource category')), bindings=[dict(
        request_key=request_key(url, method, d['headers'], d['body']),
        rule_key='restricted', predicate_key='p', classification='nonmatch', evidence_ids=['capture'])])


@pytest.mark.parametrize('snapshot,url,method,body,headers', [
    (compiled(), 'https://example.test/support', 'GET', None, {}),
    (compiled(rule(predicate('semantic','category'))), URL, 'GET', None, {}),
    (compiled(rule(predicate('json_body','feedback',name='/operation'))), URL, 'POST', b'{"operation":"feedback"}', {'Content-Type':'application/json'}),
])
def test_core_exclusions_precede_physical_call_and_budget(snapshot,url,method,body,headers):
    wire = Wire()
    broker = RequestBroker(target(snapshot), transport=wire)
    with pytest.raises(RequestPolicyError, match='exclusion'):
        broker.request(url, method=method, data=body, headers=headers)
    assert wire.calls == []
    assert broker.request_count == 0


def test_core_nonmatch_sends_once_with_exact_prepared_headers():
    wire = Wire()
    RequestBroker(target(semantic()), transport=wire).request(URL)
    assert len(wire.calls) == 1
    assert {k.lower():v for k,v in wire.calls[0][2].items()} == {
        k.lower():v for k,v in prepare_http_request(URL)['headers'].items()}


@pytest.mark.parametrize('change', ['header','query','method','body'])
def test_changed_request_cannot_reuse_semantic_nonmatch(change):
    wire = Wire()
    broker = RequestBroker(target(semantic()), transport=wire)
    kwargs = {'headers':{'Authorization':'different'}} if change=='header' else {'method':'POST'} if change=='method' else {'data':b'changed'} if change=='body' else {}
    with pytest.raises(RequestPolicyError, match='exclusion'):
        broker.request(URL+'?changed=1' if change=='query' else URL, **kwargs)
    assert not wire.calls and broker.request_count == 0


def test_core_redirect_into_exclusion_never_sends_second_hop():
    wire = Wire('/support')
    broker = RequestBroker(target(compiled()), transport=wire)
    with pytest.raises(RequestPolicyError, match='exclusion'):
        broker.request(URL)
    assert len(wire.calls) == 1
    assert broker.request_count == 1


def test_wait_expiry_rechecks_before_send(monkeypatch):
    snapshot = semantic()
    snapshot['expires_at'] = time.time()+20
    wire = Wire()
    broker = RequestBroker(target(snapshot), transport=wire)
    def expire():
        monkeypatch.setattr('aidast.core.exclusion_guard.time.time', lambda: snapshot['expires_at']+1)
    broker.governor = SimpleNamespace(reserve=lambda *a,**k: SimpleNamespace(wait=expire,complete=lambda:None,timeout_seconds=10))
    with pytest.raises(RequestPolicyError, match='exclusion'):
        broker.request(URL)
    assert not wire.calls


def test_wait_cannot_mutate_admitted_body():
    data = bytearray(b'original')
    wire = Wire()
    broker = RequestBroker(target(compiled()), transport=wire)
    broker.governor = SimpleNamespace(reserve=lambda *a,**k: SimpleNamespace(wait=lambda:data.extend(b'changed'),complete=lambda:None,timeout_seconds=10))
    broker.request(URL,data=data)
    assert wire.calls[0][3] == b'original'


def test_unknown_identity_does_not_inherit_semantics_but_preserves_false_direct():
    d = prepare_http_request(URL)
    assert evaluate_exclusions(semantic(),url=URL,headers=d['headers'],body=b'',body_available=True,identity_available=False)['decision']=='hold'
    assert evaluate_exclusions(compiled(),url=URL,body=b'',body_available=True,identity_available=False)['decision']=='continue'

@pytest.fixture
def validation_fixture():
    from test_validation_request_broker import ValidationRequestBrokerTests
    fixture = ValidationRequestBrokerTests()
    fixture.setUp()
    yield fixture
    fixture.doCleanups()


def vpolicy(f, expression):
    r = rule(expression)
    r['source_quote'] += ' /items/7'
    s = compiled(r)
    s['target_asset'] = 'test'
    from aidast.scope.exclusions import CompiledExclusionPolicy
    f.policy = f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(s)})


def test_validation_inner_and_observed_gate_before_ledger(validation_fixture):
    f = validation_fixture
    vpolicy(f,predicate('semantic','category'))
    from aidast.validation.execution.request_broker import ValidationRequestError
    b = f.broker()
    calls=[]
    b.transport=lambda *a,**k:calls.append(a)
    for observed in (False,True):
        with pytest.raises(ValidationRequestError,match='exclusion'):
            if observed:
                b.begin_observed_request('https://test/items/7',method='GET',headers={},data=b'')
            else:
                b.request('https://test/items/7',method='GET')
    assert not calls
    assert f.conn.execute('SELECT count(*) FROM validation_http_requests').fetchone()[0]==0


def test_group_exclusion_rejects_every_member_before_reservation(validation_fixture):
    f = validation_fixture
    from aidast.validation.execution.transport_broker import TransportOperationSpec,ValidationTransportBroker,ValidationTransportError
    vpolicy(f,predicate('path','/items/7'))
    b = ValidationTransportBroker(db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',attempt_id='attempt',blind_case=f.blind,policy=f.policy)
    specs=tuple(TransportOperationSpec(runtime_kind='concurrent',operation_kind='member',destination='https://test/items/'+x,policy_url='https://test/items/'+x,method='GET',request_bytes=0,max_response_bytes=1) for x in ('6','7'))
    with pytest.raises(ValidationTransportError,match='exclusion'):
        b.reserve_group(specs,'group')
    assert f.conn.execute('SELECT count(*) FROM validation_transport_operations').fetchone()[0]==0


def test_native_destination_cannot_hide_behind_policy_url(validation_fixture):
    f=validation_fixture
    from aidast.validation.execution.transport_broker import TransportOperationSpec,ValidationTransportBroker,ValidationTransportError
    b=ValidationTransportBroker(db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',attempt_id='attempt',blind_case=f.blind,policy=f.policy)
    s=TransportOperationSpec(runtime_kind='grpc',operation_kind='unary',destination='https://other.test/items/7',policy_url='https://test/items/7',method='GET',request_bytes=0,max_response_bytes=1)
    with pytest.raises(ValidationTransportError): b.reserve(s)
    assert f.conn.execute('SELECT count(*) FROM validation_transport_operations').fetchone()[0]==0


def proxy_fixture(snapshot):
    from test_mitm_proxy import MitmAddonBudgetTests
    a=MitmAddonBudgetTests._addon()
    snapshot=dict(snapshot,target_asset='example.com')
    a.rules.update(asset='example.com',request_exclusions=snapshot)
    f=MitmAddonBudgetTests._flow('/support')
    f.request.url=f.request.pretty_url
    f.request.host='example.com'
    f.request.port=443
    f.request.raw_content=b''
    f.request.stream=False
    return a,f


def test_proxy_block_before_budget_and_private_support_cannot_bypass():
    a,f=proxy_fixture(compiled(rule(predicate('method','POST'))))
    f.request.method='POST'
    f.request.headers.update({'x-aidast-browser-token':'test-token','x-aidast-browser-mode':'same-origin'})
    a.request(f)
    assert f.response is not None and f.response.status_code==403
    assert a.request_count==0


def test_proxy_actual_destination_disagrees_with_pretty_host():
    a,f=proxy_fixture(compiled())
    f.request.pretty_url='https://example.com/public'
    f.request.url='https://outside.test/support'
    f.request.host='outside.test'
    a.request(f)
    assert f.response is not None and f.response.status_code==403
    assert a.request_count==0


def browser_driver(snapshot):
    from aidast.recon.tools.playwright_driver import PlaywrightDriver,ManualSessionConfig
    p=target(snapshot)
    return PlaywrightDriver(URL,ManualSessionConfig(login_url=URL,session_file='unused.json'),target_policy=p,proxy_url='http://127.0.0.1:8080')


def test_recon_browser_full_physical_post_is_not_support_get():
    from unittest.mock import Mock
    d=browser_driver(compiled(rule(predicate('method','POST'))))
    d.browser_context_token='private'
    d.target_policy.allowed_methods=['GET']
    request=SimpleNamespace(url=URL,method='POST',all_headers=lambda:{'Cookie':'sid=actual'},post_data_buffer=b'',frame=SimpleNamespace(url=URL),resource_type='xhr',is_navigation_request=lambda:False)
    r=Mock(request=request)
    d._guard_request(r)
    r.abort.assert_called_once()
    r.fetch.assert_not_called()
    r.continue_.assert_not_called()


def test_manual_login_and_routing_pause_hold_before_side_effects():
    from unittest.mock import Mock
    d=browser_driver(compiled())
    d._ensure_playwright=Mock(side_effect=AssertionError('browser bootstrap ran'))
    with pytest.raises(ValueError,match='exclusion'): d._launch_manual_browser(manual_login=True)
    d.context=Mock()
    with pytest.raises(ValueError,match='exclusion'): d.pause_policy_routing()
    d.context.unroute.assert_not_called()


def test_session_adapter_cannot_claim_complete_identity(tmp_path):
    from aidast.attack.playwright_transport import PlaywrightSessionTransport
    from aidast.attack.session_pool import PersistentSessionPool
    state=tmp_path/'session.json';state.write_text('{}')
    for adapter in (PlaywrightSessionTransport(state),PersistentSessionPool().transport(target='example.test',identity='user',storage_state=state)):
        assert getattr(adapter,'identity_available',True) is False

@pytest.mark.parametrize('semantic_rule,expected',[(True,0),(False,0)])
def test_dom_action_has_own_context_and_does_not_borrow_page_get(semantic_rule,expected):
    from unittest.mock import Mock
    snapshot=semantic() if semantic_rule else compiled()
    d=browser_driver(snapshot)
    page=Mock(url=URL)
    element=Mock()
    page.locator.return_value.count.return_value=1
    page.locator.return_value.nth.return_value=element
    element.is_visible.return_value=True
    element.inner_text.return_value='menu'
    element.get_attribute.return_value=None
    element.evaluate.side_effect=['button',False]
    d._ensure_page=lambda:page
    assert d.trigger_safe_actions()==expected
    assert element.click.call_count==expected


@pytest.mark.parametrize('stage', ['_handle_asset_discovery','_handle_dns_resolution','_handle_host_port_discovery'])
def test_unmanaged_discovery_holds_before_any_binary(stage,monkeypatch):
    from aidast.recon.executor import ReconExecutor,ReconExecutionError
    from aidast.scope.models import AssetType
    from unittest.mock import Mock
    owner=SimpleNamespace(_ensure_asset=lambda t:'asset',_policy_for=lambda t:target(compiled()),_diagnostic=lambda *a,**k:None)
    task=SimpleNamespace(target=SimpleNamespace(asset_type=AssetType.DOMAIN,asset='example.test'))
    wires=[]
    for name in ('run_subfinder','run_dnsx','run_naabu','run_nmap'):
        monkeypatch.setattr('aidast.recon.executor.'+name,lambda *a,**k:wires.append(a) or [])
    with pytest.raises(ReconExecutionError,match='exclusion'):
        getattr(ReconExecutor,stage).__wrapped__(owner,task)
    assert wires==[]


def test_proxy_receipt_roundtrip_preserves_actual_raw_request_and_stored_response(tmp_path):
    import json,sqlite3,hashlib
    from aidast.recon.tools.mitm_proxy import ingest_mitm_capture
    from test_policy_exclusion_preparation import document,capture,api
    doc=document();path=capture(tmp_path,doc,receipt=False)
    a,f=proxy_fixture(compiled())
    f.request.url=f.request.pretty_url='https://example.com/'
    f.request.headers={'Host':'example.com','Content-Encoding':'gzip','Cookie':'sid=secret'}
    f.request.raw_content=b'actual-compressed-wire'
    f.request.content=b'decoded-body'
    a.rules['mitm_capture_bodies']=True
    a.out_path=tmp_path/'capture.jsonl'
    a.request(f)
    assert f.response is None
    f.response=SimpleNamespace(status_code=200,headers={'content-type':'text/plain'},raw_content=b'raw',content=b'Public documentation for all visitors.',get_text=lambda strict=False:'Public documentation for all visitors.',stream=False)
    a.response(f)
    record=json.loads(a.out_path.read_text())
    assert record['request_receipt']['body_sha256']==hashlib.sha256(b'actual-compressed-wire').hexdigest()
    assert record['request_receipt']['request_key']==request_key(f.request.url,'GET',f.request.headers,f.request.raw_content)
    with sqlite3.connect(path) as conn:
        origin=conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        assert ingest_mitm_capture(conn,a.out_path,origin_id=origin)==(1,0)
    snapshot=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    assert len(snapshot.candidates)==1
    assert snapshot.candidates[0].request_key==record['request_receipt']['request_key']


@pytest.mark.parametrize('control',['blocked','missing_body','streamed','candidate','error'])
def test_proxy_never_certifies_synthetic_or_incomplete_capture(tmp_path,control):
    import json
    a,f=proxy_fixture(compiled())
    f.request.pretty_url=f.request.url='https://example.com/public'
    a.rules['mitm_capture_bodies']=True
    a.out_path=tmp_path/'capture.jsonl'
    if control=='missing_body':f.request.raw_content=None
    if control=='streamed':f.request.stream=True
    if control=='candidate':f.request.headers['X-AIDAST-Phase']='candidate_probe'
    if control=='blocked':f.request.url=f.request.pretty_url='https://example.com/support'
    a.request(f)
    if control=='error':a.error(f)
    if control!='blocked':
        f.response=SimpleNamespace(status_code=200,headers={},raw_content=b'visible',content=b'visible',get_text=lambda strict=False:'visible',stream=False)
    else:
        f.response.get_text=lambda strict=False:'Blocked'
        f.response.raw_content=b'Blocked'
    a.response(f)
    assert 'request_receipt' not in json.loads(a.out_path.read_text())


def test_policy_service_guard_precedes_durable_ledger():
    from test_policy_service import PolicyServiceTests
    from test_attack_authorization import bindings,intent
    from aidast.attack.authorization import canonical_digest
    from aidast.scope.exclusions import CompiledExclusionPolicy
    f=PolicyServiceTests();f.setUp()
    try:
        snapshot=dict(compiled(rule(predicate('semantic','category'))),target_asset='example.com')
        f.policy=f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(snapshot)})
        f.binding=bindings(policy_digest=canonical_digest(f.policy));f.intent=intent(f.binding)
        service=f.service()
        with pytest.raises(RequestPolicyError,match='exclusion'):service.request(f.intent)
        import sqlite3
        with sqlite3.connect(f.path) as conn:
            assert conn.execute('SELECT count(*) FROM policy_reservations').fetchone()[0]==0
        f.transport.assert_not_called()
    finally:f.doCleanups()

@pytest.mark.parametrize('kind',['websocket','grpc'])
def test_native_incomplete_semantic_context_holds_before_connector(kind):
    from aidast.scope.exclusions import CompiledExclusionPolicy
    from test_validation_grpc_runtime import GrpcAdapterTests
    from test_validation_websocket_runtime import WebSocketAdapterTests
    f=(GrpcAdapterTests if kind=='grpc' else WebSocketAdapterTests)();f.setUp()
    try:
        snapshot=dict(compiled(rule(predicate('semantic','category'))),target_asset='test')
        f.policy=f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(snapshot)})
        calls=[]
        kw={'channel_factory':lambda *a,**k:calls.append(a)} if kind=='grpc' else {'connector':lambda *a,**k:calls.append(a)}
        result=f.execute(**kw)
        assert result.outcome=='blocked'
        assert not calls and f.rows()==[]
    finally:f.doCleanups()


def test_grpc_known_false_direct_predicate_retains_one_operation():
    from aidast.scope.exclusions import CompiledExclusionPolicy
    from test_validation_grpc_runtime import GrpcAdapterTests,ScriptedChannel
    f=GrpcAdapterTests();f.setUp()
    try:
        snapshot=dict(compiled(),target_asset='test')
        f.policy=f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(snapshot)})
        calls=[]
        result=f.execute(channel_factory=lambda *a,**k:calls.append(a) or ScriptedChannel())
        assert result.signal_observed and len(calls)==1 and len(f.rows())==1
    finally:f.doCleanups()


def test_multipart_body_required_context_holds_before_transport():
    from test_validation_multipart_runtime import MultipartAdapterSafetyTests
    f=MultipartAdapterSafetyTests();f.setUp()
    try:
        vpolicy(f,predicate('form_body','feedback',name='operation'))
        calls=[]
        result=f.execute(f.runtime(),lambda *a,**k:calls.append(a))
        assert result.outcome=='blocked' and not calls
        assert f.conn.execute('SELECT count(*) FROM validation_transport_operations').fetchone()[0]==0
    finally:f.doCleanups()


def test_group_rechecks_all_members_after_first_wait(validation_fixture):
    from aidast.scope.exclusions import CompiledExclusionPolicy
    from aidast.validation.execution.transport_broker import TransportOperationSpec,ValidationTransportBroker,ValidationTransportError
    f=validation_fixture
    condition=dict(operator='all',predicate=None,children=[predicate('method','POST',key='m'),predicate('semantic','category')])
    snapshot=compiled(rule(condition),bindings=[dict(request_key=request_key('https://test/items/7','POST',{},b''),rule_key='restricted',predicate_key='p',classification='nonmatch',evidence_ids=['capture'])])
    snapshot.update(target_asset='test',expires_at=150)
    f.policy=f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(snapshot), 'allowed_methods':['GET','POST'], 'attack_allowed_methods':['GET','POST'], 'attack_authorization_mode':'active_non_destructive', 'attack_authorization_evidence':'authorized'})
    now=[100]
    b=ValidationTransportBroker(db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',attempt_id='attempt',blind_case=f.blind,policy=f.policy,clock=lambda:now[0])
    specs=tuple(TransportOperationSpec(runtime_kind='concurrent',operation_kind='member',destination='https://test/items/7',policy_url='https://test/items/7',method=m,request_bytes=0,max_response_bytes=1,body=b'',body_available=True,identity_available=True) for m in ('GET','POST'))
    reservations=b.reserve_group(specs,'group')
    b._permits[reservations[0].operation_id]=SimpleNamespace(wait=lambda:now.__setitem__(0,151),complete=lambda:None,timeout_seconds=10)
    calls=[]
    with pytest.raises(ValidationTransportError,match='exclusion'):
        b.dispatch_reserved(reservations[0],lambda *a:calls.append(a))
    assert calls==[]
    b.abandon_reserved(reservations)


@pytest.mark.parametrize('denied',[True,False])
def test_attack_cli_final_admission_before_ledger_and_send(tmp_path,monkeypatch,denied):
    import json,sqlite3
    from test_attack_request_guard import fixture,FakeOpener
    from aidast.attack.request_cli import guarded_request,RequestGuardError
    database,p,payload,stage,task=fixture(tmp_path)
    doc=json.loads(p.read_text())
    snapshot=compiled(rule(predicate('semantic','category'))) if denied else compiled()
    snapshot['target_asset']=doc['policies'][0]['asset']
    doc['policies'][0]['request_exclusions']=snapshot
    p.write_text(json.dumps(doc));payload.write_text(json.dumps({'url':'https://example.test/api/profile'}))
    opener=FakeOpener()
    monkeypatch.setattr('aidast.attack.request_cli.build_opener',lambda *a,**k:opener)
    def send():return guarded_request(database,scan_id='scan',stage_run_id=stage,task_id=task,policy_path=p,payload_path=payload)
    if denied:
        with pytest.raises(RequestGuardError,match='exclusion'):send()
    else:send()
    assert len(opener.calls)==int(not denied)
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT count(*) FROM attack_http_requests').fetchone()[0]==int(not denied)


def test_validation_browser_exclusions_activate_controls_without_governor(validation_fixture,monkeypatch):
    from unittest.mock import MagicMock
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor
    f=validation_fixture;vpolicy(f,predicate())
    context=MagicMock();browser=MagicMock();browser.new_context.return_value=context
    page=context.new_page.return_value;page.url='https://test/items/1'
    callbacks={};context.route.side_effect=lambda pat,fn:callbacks.update(route=fn)
    wire=[]
    def navigate(*a,**k):
        request=SimpleNamespace(url=page.url,method='GET',all_headers=lambda:{'Cookie':'actual'},post_data_buffer=None,is_navigation_request=lambda:True)
        route=MagicMock();response=MagicMock(status=200,headers={})
        route.fetch.side_effect=lambda **kw:wire.append(kw) or response
        callbacks['route'](route,request)
        route.continue_.assert_not_called()
    page.goto.side_effect=navigate
    manager=MagicMock();manager.__enter__.return_value.chromium.launch.return_value=browser
    monkeypatch.setattr('playwright.sync_api.sync_playwright',lambda:manager)
    PlaywrightBrowserExecutor()(url=page.url,headers={},wait_ms=0,selectors=(),attributes={},policy=f.policy,db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',attempt_id='attempt')
    assert browser.new_context.call_args.kwargs['service_workers']=='block'
    assert context.route_web_socket.call_count==1
    assert len(wire)==1 and wire[0]['max_redirects']==wire[0]['max_retries']==0
    assert wire[0]['headers']['Cookie']=='actual'
    assert f.conn.execute('SELECT count(*) FROM validation_http_requests').fetchone()[0]==1


def test_browser_resume_failure_under_exclusions_is_not_silenced():
    from unittest.mock import Mock
    d=browser_driver(compiled());d.context=Mock()
    d.context.route.side_effect=RuntimeError('registration failed')
    with pytest.raises(ValueError,match='exclusion'):d.resume_policy_routing()


def test_native_group_holds_unsupported_json_even_for_empty_grpc_message(validation_fixture):
    from aidast.validation.execution.transport_broker import TransportOperationSpec,ValidationTransportBroker,ValidationTransportError
    f=validation_fixture;vpolicy(f,predicate('json_body','feedback',name='/operation'))
    b=ValidationTransportBroker(db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',attempt_id='attempt',blind_case=f.blind,policy=f.policy)
    spec=TransportOperationSpec(runtime_kind='grpc',operation_kind='unary',destination='https://test/items/7',policy_url='https://test/items/7',method='GET',request_bytes=0,max_response_bytes=1,headers={'Content-Type':'application/grpc'},body=b'',body_available=False)
    with pytest.raises(ValidationTransportError,match='exclusion'):b.reserve(spec)
    assert b.operation_ids==[]


def test_session_semantic_hold_precedes_chromium_and_direct_nonmatch_can_send(tmp_path,monkeypatch):
    from aidast.attack.playwright_transport import PlaywrightSessionTransport
    from unittest.mock import MagicMock
    state=tmp_path/'session.json';state.write_text('{}')
    calls=[]
    manager=MagicMock()
    browser=manager.__enter__.return_value.chromium.launch.return_value
    response=SimpleNamespace(status=200,headers={},url=URL,body=lambda:b'ok')
    browser.new_context.return_value.request.fetch.side_effect=lambda *a,**k:calls.append((a,k)) or response
    monkeypatch.setattr('aidast.attack.playwright_transport.sync_playwright',lambda:manager)
    adapter=PlaywrightSessionTransport(state)
    with pytest.raises(RequestPolicyError,match='exclusion'):
        RequestBroker(target(semantic()),transport=adapter).request(URL)
    manager.__enter__.assert_not_called()
    RequestBroker(target(compiled()),transport=adapter).request(URL)
    assert len(calls)==1 and calls[0][1]['max_redirects']==0


def test_standalone_proxy_dependency_free_import(tmp_path):
    import subprocess,sys
    from pathlib import Path
    addon=Path(__file__).parents[1]/'src/aidast/recon/tools/mitm_addon.py'
    code='''import sys,types,runpy
class DenyPackages:
 def find_spec(self,fullname,path=None,target=None):
  if fullname.startswith(('aidast','pydantic')): raise AssertionError('package dependency: '+fullname)
sys.meta_path.insert(0,DenyPackages())
sys.modules['mitmproxy']=types.SimpleNamespace(ctx=types.SimpleNamespace(),http=types.SimpleNamespace())
value=runpy.run_path(sys.argv[1])
assert value['require_request_admission']({'asset':'test','request_exclusions':None},url='https://test/',method='GET')['decision']=='continue'
print('isolated proxy loaded')
'''
    result=subprocess.run([sys.executable,'-I','-c',code,str(addon)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='isolated proxy loaded'


@pytest.mark.parametrize('raw,allowed',[(None,True),({},False),([],False),('empty_rules',True)])
def test_proxy_malformed_present_guard_cannot_disable_enforcement(raw,allowed):
    a,f=proxy_fixture(compiled())
    if raw == 'empty_rules':
        from aidast.core.exclusion_guard import rule_digest
        raw = dict(compiled(), target_asset='example.com', rules=[], rule_digest=rule_digest([]))
    a.rules['request_exclusions']=raw
    f.request.url=f.request.pretty_url='https://example.com/public'
    a.request(f)
    assert (f.response is None)==allowed
    assert a.request_count==int(allowed)


def test_attack_dictionary_preserves_embedded_glob_excluded_host(tmp_path):
    import json
    from aidast.attack.request_cli import _policy_allows
    from test_attack_request_guard import fixture
    _,p,_,_,_=fixture(tmp_path)
    policy=json.loads(p.read_text())['policies'][0]
    policy['excluded_hosts']=['exam*test']
    assert not _policy_allows(policy,'https://example.test/api/profile','GET')


@pytest.mark.parametrize('compound',[False,True])
def test_dom_form_control_does_not_inherit_enclosing_page_resource(compound):
    from unittest.mock import Mock
    condition=predicate('path','/support')
    if compound:
        condition=dict(operator='all',predicate=None,children=[condition,predicate('semantic','excluded form',key='category')])
    d=browser_driver(compiled(rule(condition)))
    d.interaction_config.allow_form_submission=True
    page=Mock(url=URL)
    element=Mock()
    page.locator.return_value.count.return_value=1
    page.locator.return_value.nth.return_value=element
    element.is_visible.return_value=True
    element.inner_text.return_value='menu'
    attrs={'type':'button','aria-controls':'support-form','formaction':'/support'}
    element.get_attribute.side_effect=lambda name,**kw:attrs.get(name)
    element.evaluate.side_effect=['button',True]
    d._ensure_page=lambda:page
    assert d.trigger_safe_actions()==0
    element.click.assert_not_called()


@pytest.mark.parametrize('expire_on_connect',[False,True])
def test_concurrent_native_postconnect_checks_entire_group(validation_fixture,monkeypatch,expire_on_connect):
    """A broker-admitted sibling expires during connect before any HTTP bytes."""
    from aidast.scope.exclusions import CompiledExclusionPolicy
    from aidast.validation.execution.concurrent_adapter import ConcurrentReproductionPort
    from test_validation_concurrent_runtime import ConcurrentTransportRegressionTests
    import aidast.validation.execution.http_deadline as native
    f=validation_fixture
    first='http://first.test/items'
    second='http://second.test/items'
    real_time=time.time
    offset=[0]
    monkeypatch.setattr('aidast.core.exclusion_guard.time.time',lambda:real_time()+offset[0])
    from aidast.validation.execution.transport_broker import ValidationTransportBroker
    monkeypatch.setattr('aidast.validation.execution.concurrent_adapter.ValidationTransportBroker',
        lambda **kwargs:ValidationTransportBroker(**kwargs,clock=lambda:real_time()+offset[0]))
    expression=dict(operator='all',predicate=None,children=[predicate('host','second.test',key='host'),predicate('semantic','resource category')])
    r=rule(expression);r['source_quote']+=' second.test'
    descriptor=prepare_http_request(second)
    snapshot=compiled(r,bindings=[dict(request_key=request_key(second,'GET',descriptor['headers'],b''),rule_key='restricted',predicate_key='p',classification='nonmatch',evidence_ids=['capture'])])
    snapshot.update(target_asset='test',expires_at=real_time()+10)
    policy=f.policy.model_copy(update={'request_exclusions':CompiledExclusionPolicy.model_validate(snapshot),'allowed_schemes':['http'],'allowed_hosts':['first.test','second.test'],'allowed_ports':[80]})
    runtime=ConcurrentTransportRegressionTests.runtime(f,seconds=2)
    blind=f.blind.model_copy(update={'endpoint':first,'credential_references':(),'signal_types':('timing',),'runtime_contract':runtime.model_dump(mode='json')})
    port=ConcurrentReproductionPort()
    # Feed distinct trusted descriptors to the public heterogeneous-group broker.
    members=iter([port._prepare(runtime.target,url,{}) for url in (first,second)])
    monkeypatch.setattr(port,'_prepare',lambda *a,**k:next(members))
    import threading
    sent=[];connected=[]
    first_connected=threading.Event()
    class Connection:
        sock=None
        def __init__(self,host,port,timeout):self.host=host
        def connect(self):
            connected.append(self.host)
            if self.host=='first.test':
                if expire_on_connect:offset[0]=20
                first_connected.set()
            else:
                # No sibling may legitimately send before the simulated expiry.
                assert first_connected.wait(1)
        def request(self,method,target,**kwargs):sent.append((self.host,method,target))
        def getresponse(self):
            response=io.BytesIO(b'ok');response.status=200;response.headers={'Content-Length':'2'}
            return response
        def close(self):pass
    monkeypatch.setattr(native.http.client,'HTTPConnection',Connection)
    monkeypatch.setattr(native._RESOLVER_FACILITY,'resolve',lambda *a,**k:pytest.fail('real resolver ran'))
    result=port.execute(blind,attempt_kind='target',batch_no=1,ordinal=1,attempt_id='attempt',db_path=f.path,scan_id='scan',stage_run_id='stage',case_id='case',policy=policy)
    assert 'first.test' in connected
    if expire_on_connect:
        assert sent==[]
        assert result.outcome=='outcome_unknown'
    else:
        assert len(sent)==2
        assert result.signal_observed
