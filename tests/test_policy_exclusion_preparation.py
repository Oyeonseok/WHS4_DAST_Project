"""Offline launch/capture contract; all traffic/model boundaries are local fakes."""
import hashlib
import importlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from aidast.scope.models import ScopeDocument, ScopeAsset, ScopeExecutionRules, SourceEvidence
from aidast.scope.exclusions import ScopeExclusion
from aidast.scope.exclusion_binding import ExclusionBindingResolver
from test_recon_workflow import FakeReconMainAgent, PROGRAM_URL

URL = 'https://example.com/'
QUOTE = 'Do not test managed resources. Do not request /private.'

def api():
    try:
        return importlib.import_module('aidast.scope.exclusion_preparation')
    except ModuleNotFoundError:
        pytest.fail('shared offline exclusion preparation is missing')

def receipt_api():
    try:
        return importlib.import_module('aidast.core.capture_receipt')
    except ModuleNotFoundError:
        pytest.fail('stdlib full-wire capture receipt API is missing')


def test_capture_database_discovery_uses_bounded_recent_window(tmp_path):
    created = []
    for index in range(70):
        path = tmp_path / 'Runs' / f'scan_{index:02d}' / 'Recon.db'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'')
        timestamp = 1_700_000_000 + index
        path.touch()
        import os
        os.utime(path, (timestamp, timestamp))
        created.append(path.resolve())

    found = api().capture_databases(tmp_path)

    assert len(found) == 64
    assert created[-1] == found[0]
    assert set(created[:6]).isdisjoint(found)

def rule(semantic=True):
    return ScopeExclusion(key='restricted', label='Restricted resource', source_quote=QUOTE,
        condition=dict(operator='predicate', predicate=dict(key='category', field='semantic' if semantic else 'path',
            operator='equals', value='managed resources' if semantic else '/private')))

def document(semantic=True):
    page, analysis = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    text = page.text + '\n' + QUOTE + '\n' + URL
    page = page.model_copy(update={'text':text, 'content_sha256':hashlib.sha256(text.encode()).hexdigest()})
    data = analysis.model_dump()
    data.update(required_request_headers=[], execution_rules=dict(exclusions=[rule(semantic).model_dump()]),
        in_scope_assets=[dict(asset_type='URL', asset=URL, description='fixture', eligibility='eligible', maximum_severity='High')])
    data['source_evidence'] += [dict(section='Rules',quote=QUOTE),dict(section='Scope',quote=URL)]
    return ScopeDocument(scope_id='scope_preparation', created_at=datetime.now(timezone.utc), source=page,
        analysis=type(analysis).model_validate(data))

def guarded_semantic_rule():
    """A mixed rule remains request-enforced after advisory review."""
    semantic = rule()
    direct = rule(False).condition.model_copy(update={
        'predicate': rule(False).condition.predicate.model_copy(update={'key': 'private_path'})})
    return semantic.model_copy(update={'condition': type(semantic.condition).model_validate(dict(
        operator='any', children=[semantic.condition.model_dump(), direct.model_dump()]))})

def guarded_semantic_document():
    doc = document()
    rules = doc.analysis.execution_rules.model_copy(update={'exclusions': [guarded_semantic_rule()]})
    return doc.model_copy(update={'analysis': doc.analysis.model_copy(update={'execution_rules': rules})})

def capture(tmp_path, doc, *, url=URL, receipt=True, scope_id=None, source_type='approved_scope', response=b'Public documentation for all visitors.', headers=None, body=b''):
    from aidast.recon import db
    path = tmp_path / 'Runs' / 'scan_local' / 'Recon.db'
    conn = db.init_db(path)
    db.insert_scan(conn, scan_id='scan_local', scope_type=source_type, scope_value=scope_id or doc.scope_id)
    asset = db.insert_asset(conn,scan_id='scan_local',identifier=URL,asset_type='URL')
    origin = db.upsert_origin(conn,asset_id=asset,scheme='https',host='example.com',port=443,base_url=URL)
    endpoint = db.upsert_endpoint(conn,origin_id=origin,method='GET',path='/',normalized_path='/')
    raw_headers = headers or {'User-Agent':'aidast-recon/0.1','Host':'example.com','Accept-Encoding':'identity','Connection':'close'}
    meta = None
    if receipt:
        meta = receipt_api().make_capture_receipt(url=url,method='GET',headers=raw_headers,body=body,
            response_body=response,captured_at=time.time())
    columns = {r[1] for r in conn.execute('PRAGMA table_info(http_transactions)')}
    if 'request_receipt' not in columns:
        conn.execute('ALTER TABLE http_transactions ADD COLUMN request_receipt TEXT')
    conn.execute('INSERT INTO http_transactions(http_transaction_id,endpoint_id,source,method,url,request_headers,request_body,response_body,captured_at,request_receipt) VALUES(?,?,?,?,?,?,?,?,?,?)',
        ('tx_fixture',endpoint,'mitmproxy','GET',url,json.dumps({'Authorization':'[REDACTED]','X-Researcher':'[REDACTED]'}),None,response,datetime.now(timezone.utc).isoformat(),json.dumps(meta) if meta else None))
    conn.commit(); conn.close()
    return path

def interpret(context):
    return {'decisions':[dict(candidate_id=c['candidate_id'],rule_key='restricted',predicate_key='category',
        classification='nonmatch',reason='Affirmative public documentation description',
        citations=[dict(evidence_id=c['evidence_ids'][0],quote='Public documentation for all visitors.')]) for c in context['candidates']]}

def test_stdlib_wire_descriptor_is_complete_and_opaque_receipt(tmp_path):
    m = receipt_api()
    descriptor=m.prepare_http_request(URL, headers={'X-Researcher':'private-handle'},body=None)
    assert descriptor['headers']['Host']=='example.com'
    assert descriptor['headers']['Accept-Encoding']=='identity'
    assert descriptor['headers']['Connection']=='close'
    assert descriptor['body']==b''
    receipt=m.make_capture_receipt(**descriptor,response_body=b'visible',captured_at=time.time())
    assert 'private-handle' not in json.dumps(receipt)
    assert receipt['request_key'] != m.make_capture_receipt(**m.prepare_http_request(URL),response_body=b'visible',captured_at=time.time())['request_key']
    import runpy
    assert callable(runpy.run_path(m.__file__)['prepare_http_request'])
    with pytest.raises(ValueError):
        m.prepare_http_request(URL,headers={'X-A':'a','x-a':'b'})

@pytest.mark.parametrize('body,method,expected',[(b'x=1','POST','3'),(b'','POST','0'),(None,'GET',None)])
def test_wire_body_framing(body,method,expected):
    d=receipt_api().prepare_http_request(URL,method=method,body=body)
    assert d['headers'].get('Content-Length')==expected
    if body is not None:
        assert d['headers']['Content-Type']=='application/x-www-form-urlencoded'

def test_verified_readonly_capture_binds_exact_initial_wire_and_preserves_originals(tmp_path):
    doc=document(); before=doc.model_dump_json(); path=capture(tmp_path,doc); raw=path.read_bytes()
    snapshot=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    assert len(snapshot.candidates)==len(snapshot.evidence)==1
    assert 'REDACTED' not in snapshot.candidates[0].public_headers.values()
    calls=[]
    def classify(context):
        calls.append(context); return interpret(context)
    preparation=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,resolver=ExclusionBindingResolver(tmp_path/'cache',classify))
    assert preparation.diagnostics[0]['decision']=='continue'
    assert len(calls)==1
    assert path.read_bytes()==raw and doc.model_dump_json()==before
    assert preparation.policies[URL].scope_digest==api().approved_scope_digest(doc)

@pytest.mark.parametrize('option', ['wrong_scope','wrong_origin','source_import','legacy','tampered_response','oversize'])
def test_unverified_capture_cannot_supply_semantic_evidence(tmp_path,option):
    doc=document()
    path=capture(tmp_path,doc,scope_id='other' if option=='wrong_scope' else None,
        source_type='source_import' if option=='source_import' else 'approved_scope',
        url='https://evil.test/' if option=='wrong_origin' else URL,receipt=option!='legacy',
        response=b'x'*300000 if option=='oversize' else b'Public documentation for all visitors.')
    if option=='tampered_response':
        with sqlite3.connect(path) as conn: conn.execute("UPDATE http_transactions SET response_body='fabricated nonmatch'")
    result=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    assert result.candidates==[] and result.evidence==[]


def test_symlink_capture_rejected(tmp_path):
    doc=document(); path=capture(tmp_path,doc); alias=tmp_path/'alias.db';alias.symlink_to(path)
    with pytest.raises(ValueError,match='symlink'):
        api().load_capture_snapshot([alias],document=doc,target=doc.analysis.in_scope_assets[0])


def test_annotations_and_endpoint_templates_do_not_create_candidates(tmp_path):
    doc=document(); path=capture(tmp_path,doc,receipt=False)
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE invented_annotations(url TEXT, category TEXT)')
        conn.execute('INSERT INTO invented_annotations VALUES (?,?)',(URL,'definitely safe'))
    result=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    assert not result.candidates


def test_unknown_seed_holds_without_model_or_target_io_and_system_browser_always_holds(tmp_path):
    doc=document()
    preparation=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,result_root=tmp_path,
        resolver=ExclusionBindingResolver(tmp_path/'cache',lambda _:pytest.fail('no capture must not call model')))
    assert preparation.diagnostics[0]['decision']=='hold'
    with pytest.raises(ValueError,match='restricted'):
        preparation.require_ready()
    direct=document(False)
    with pytest.raises(ValueError,match='system-browser'):
        api().prepare_exclusions(document=direct,analysis=direct.analysis,targets=direct.analysis.in_scope_assets,
            result_root=tmp_path,login_mode='system-browser').require_ready()


def test_direct_exclusions_apply_without_evidence_and_offline_inspection_returns_denials(tmp_path):
    doc=document(False)
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,start_urls={('URL',URL):URL+'private'},resolver=ExclusionBindingResolver(tmp_path/'cache',lambda _:pytest.fail('direct rule calls model')))
    assert result.diagnostics[0]['decision']=='deny'
    assert result.diagnostics[0]['rule_keys']==['restricted']

@pytest.mark.parametrize('option',['session','browser','identity'])
def test_changed_or_unknown_seed_identity_never_inherits_a_capture(tmp_path,option):
    doc=document(); capture(tmp_path,doc)
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,result_root=tmp_path,
        resolver=ExclusionBindingResolver(tmp_path/'cache',interpret),
        seed_identity_complete=option not in {'session','browser'},headers={'X-Researcher':'changed'} if option=='identity' else {})
    assert result.diagnostics[0]['decision']=='hold'


def test_legacy_requirements_are_pending_without_model():
    from aidast.web.requirements import build_scope_execution_requirements
    doc=document(); old=doc.analysis.model_copy(update={'execution_rules':ScopeExecutionRules()})
    assert build_scope_execution_requirements(old).execution_requirements_status=='pending'

def test_wire_default_user_agent_preserves_urllib_and_receipt_requires_actual_body():
    import urllib.request
    module=receipt_api()
    assert module.prepare_http_request(URL)['headers']['User-Agent']==f'Python-urllib/{urllib.request.__version__}'
    assert module.prepare_http_request(URL,headers={'User-Agent':'chosen'})['headers']['User-Agent']=='chosen'
    with pytest.raises(ValueError,match='body'):
        module.make_capture_receipt(url=URL,method='GET',headers={},body=None,response_body=b'',captured_at=time.time())

@pytest.mark.parametrize('method,body,headers',[('GET',None,{}),('POST',None,{}),('GET',b'',{}),('POST',b'',{}),('GET',None,{'Content-Type':'custom/type'}),('POST',b'x',{})])
def test_frozen_descriptor_survives_urllib_default_headers(method,body,headers):
    import urllib.request
    module=receipt_api()
    descriptor=module.prepare_http_request(URL,method=method,headers=headers,body=body)
    assert hasattr(module,'urllib_request_data'), 'wire-data selector must prevent hidden urllib headers'
    request=urllib.request.Request(URL,method=method,headers=descriptor['headers'],data=module.urllib_request_data(descriptor))
    handler=urllib.request.HTTPHandler()
    handler.parent=type('OfflineOpener',(),{'addheaders':[]})()
    handler.do_request_(request)  # Adds defaults but performs no target IO.
    assert {k.lower():v for k,v in request.header_items()}=={k.lower():v for k,v in descriptor['headers'].items()}


def approved(tmp_path,doc):
    from aidast.orchestration.scope import ScopeCoordinator
    class Agent(FakeReconMainAgent):
        def collect_scope(self,_): return doc.source,doc.analysis
    coordinator=ScopeCoordinator(tmp_path/'Scope'/'bugcrowd'/'example')
    coordinator.collect(PROGRAM_URL,main_agent=Agent(),approved_by='operator',review=lambda _:True)
    return coordinator.load_approved_scope()[0]


@pytest.mark.parametrize('semantic,login,start',[(True,'runtime-browser',None),(False,'system-browser',None),(False,'none',URL+'private')])
def test_cli_exclusion_gate_precedes_login_plan_and_executor(tmp_path,monkeypatch,semantic,login,start):
    import aidast.cli as cli
    doc=approved(tmp_path,guarded_semantic_document() if semantic else document(False))
    class Agent(FakeReconMainAgent):
        def create_recon_plan(self,**kwargs): pytest.fail('held seed must stop before plan/executor')
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('held seed opened login'))
    args=['recon',PROGRAM_URL,'--target',URL,'--execute','--login-mode',login,'--output-dir',str(tmp_path/'Scope')]
    if start:args+=['--start-url',start]
    assert cli.main(args)==1


def test_web_preparation_is_explicit_same_origin_and_catalog_get_is_cache_only(tmp_path):
    import asyncio,httpx
    from aidast.web.launch import ScanLaunchManager,ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    from aidast.web.server import create_app
    doc=approved(tmp_path,guarded_semantic_document());capture(tmp_path,doc)
    calls=[]
    def classify(ctx):calls.append(ctx);return interpret(ctx)
    manager=ScanLaunchManager(tmp_path,DashboardProjector(tmp_path),process_factory=lambda *a,**k:pytest.fail('offline preparation launched process'))
    manager.exclusion_resolver=ExclusionBindingResolver(tmp_path/'.exclusion-bindings',classify)
    app=create_app(result_root=tmp_path,launch_manager=manager)
    before={p.name:p.read_bytes() for p in (tmp_path/'Scope'/'bugcrowd'/'example').iterdir() if p.is_file()}
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            result=await client.get('/api/v1/scopes');assert result.status_code==200;assert not calls
            endpoint=f'/api/v1/scopes/{doc.scope_id}/exclusion-preparation'
            payload=dict(scope_id=doc.scope_id,targets=[URL],authorization_confirmed=True)
            assert (await client.post(endpoint,json=payload)).status_code==403
            response=await client.post(endpoint,json=payload,headers={'Origin':'http://test'})
            assert response.status_code==200,response.text
            assert response.json()['preparation']['held']==0
            assert len(calls)==1
            assert (await client.get('/api/v1/scopes')).status_code==200;assert len(calls)==1
            payload['refresh']=True
            assert (await client.post(endpoint,json=payload,headers={'Origin':'http://test'})).status_code==200
            assert len(calls)==2
    asyncio.run(exercise())
    assert before=={p.name:p.read_bytes() for p in (tmp_path/'Scope'/'bugcrowd'/'example').iterdir() if p.is_file()}


def test_web_launch_holds_unknown_seed_before_process(tmp_path):
    from aidast.web.launch import ScanLaunchManager,ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    doc=approved(tmp_path,guarded_semantic_document())
    manager=ScanLaunchManager(tmp_path,DashboardProjector(tmp_path),process_factory=lambda *a,**k:pytest.fail('held seed launched process'))
    with pytest.raises(ValueError,match='restricted'):
        manager.launch(ScanLaunchRequest(scope_id=doc.scope_id,targets=[URL],authorization_confirmed=True))


def test_db_new_capture_accepts_optional_opaque_receipt(tmp_path):
    import inspect
    from aidast.recon import db
    assert 'request_receipt' in inspect.signature(db.insert_http_transaction).parameters
    with db.connect(tmp_path/'new.db') as conn:
        meta=receipt_api().make_capture_receipt(url=URL,method='GET',headers={},body=b'',response_body=b'public',captured_at=time.time())
        transaction=db.insert_http_transaction(conn,endpoint_id=None,source='mitmproxy',method='GET',url=URL,
            response_body=b'public',request_receipt=meta)
        assert json.loads(conn.execute('SELECT request_receipt FROM http_transactions WHERE http_transaction_id=?',(transaction,)).fetchone()[0])==meta


def test_model_receives_redacted_evidence_and_no_credentials(tmp_path):
    doc=document(); path=capture(tmp_path,doc,response=b'{"description":"Public documentation for all visitors.","token":"supersecret","password":"hidden"}',
        headers={'Authorization':'Bearer private','X-Researcher':'operator'})
    with sqlite3.connect(path) as conn:
        conn.execute('UPDATE http_transactions SET request_headers=?',(json.dumps({'X-Researcher':'operator','Authorization':'Bearer private'}),))
    snapshot=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    exposed=json.dumps([item.model_dump() for item in [*snapshot.candidates,*snapshot.evidence]])
    for secret in ['supersecret','hidden','Bearer private','operator']:
        assert secret not in exposed
    assert snapshot.candidates[0].request_key != __import__('aidast.core.exclusion_guard',fromlist=['request_key']).request_key(URL,'GET',{})


def test_capture_database_budget_and_request_body_budget_reject_before_classification(tmp_path):
    doc=document();path=capture(tmp_path,doc,body=b'x'*300000)
    assert not api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0]).candidates
    with path.open('ab') as stream:
        stream.truncate(api().MAX_DATABASE_BYTES+1)
    assert not api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0]).candidates


def test_policy_final_header_mutation_holds_before_login(tmp_path):
    from aidast.recon.policy import TargetPolicy
    doc=document();capture(tmp_path,doc)
    preparation=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,resolver=ExclusionBindingResolver(tmp_path/'cache',interpret))
    policy=TargetPolicy(scope_id=doc.scope_id,policy_id='fixture',asset_type='URL',asset=URL,allowed_hosts=['example.com'],required_identity_headers={'X-Researcher':'new'})
    bound=preparation.attach({('URL',URL):policy})
    assert hasattr(preparation,'require_policy_starts_ready'),'generated-policy seed identity must be rechecked before login'
    with pytest.raises(ValueError,match='restricted'):
        preparation.require_policy_starts_ready(bound,{})


@pytest.mark.parametrize("capture_location",["standard","custom_recon","pipeline"])
@pytest.mark.parametrize("final_identity_change",[False,True])
@pytest.mark.parametrize("initial_step",["HTTP_PROBE","ORIGIN_DISCOVERY"])
def test_cli_policy_only_prepares_semantic_snapshot_without_login_or_executor(tmp_path,monkeypatch,capsys,capture_location,final_identity_change,initial_step):
    import aidast.cli as cli
    from aidast.recon.policy import TargetPolicy
    from aidast.recon.models import ReconPlan,ReconPlanTarget,ReconStep
    doc=approved(tmp_path,guarded_semantic_document());path=capture(tmp_path,doc)
    extra=[]
    if capture_location!='standard':
        destination=tmp_path/'explicit.db' if capture_location=='custom_recon' else tmp_path/'AttackRuns'/'scan_local'/'Pipeline.db'
        destination.parent.mkdir(parents=True,exist_ok=True)
        path.rename(destination)
        if capture_location=='custom_recon':extra=['--db-path',str(destination)]
    calls=[]
    class Agent(FakeReconMainAgent):
        def classify_exclusion_resources(self,context):calls.append(context);return interpret(context)
        def create_recon_plan(self,**kwargs):
            return ReconPlan(plan_id='plan_fixture',scope_id=doc.scope_id,objective='Offline policy inspection',mode='FULL_RECON',targets=[ReconPlanTarget(asset_type='URL',asset=URL,steps=[ReconStep(initial_step)],constraints=[])],global_constraints=[],completion_criteria=['policy'])
        def create_target_policies(self,**kwargs):
            return {('URL',URL):TargetPolicy(scope_id=doc.scope_id,policy_id='fixture',asset_type='URL',asset=URL,allowed_hosts=['example.com'],required_identity_headers={'X-Researcher':'changed'} if final_identity_change else {})}
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('offline login'))
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:pytest.fail('offline executor'))
    directory=tmp_path/'Scope'/'bugcrowd'/'example'; before={p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}
    assert cli.main(['recon',PROGRAM_URL,'--target',URL,'--policy-only','--refresh-exclusions','--output-dir',str(tmp_path/'Scope'),*extra])==0
    assert len(calls)==1
    saved=json.loads((directory/'TargetPolicy.json').read_text())['policies'][0]['request_exclusions']
    assert saved['scope_digest']==api().approved_scope_digest(doc)
    assert saved['semantic_bindings'][0]['classification']=='nonmatch'
    assert all((directory/name).read_bytes()==raw for name,raw in before.items())
    assert ('"held": 1' if final_identity_change else '"held": 0') in capsys.readouterr().out


def test_cli_current_sidecar_overrides_complete_embedded_rules_before_login(tmp_path,monkeypatch):
    import aidast.cli as cli
    from aidast.scope.execution_rules import ScopeExecutionResolver,EXECUTION_INTERPRETATION_VERSION
    source=document();doc=approved(tmp_path,source.model_copy(update={'analysis':source.analysis.model_copy(update={'execution_rules':ScopeExecutionRules(exclusions=[])})}))
    resolver=ScopeExecutionResolver(tmp_path/'.execution-requirements');resolver.cache_dir.mkdir()
    reviewed = resolver._validate(doc, dict(required_request_headers=[], execution_rules=dict(exclusions=[guarded_semantic_rule().model_dump()])), fresh=True)
    resolver.cache_path(doc).write_text(json.dumps(dict(interpretation_version=EXECUTION_INTERPRETATION_VERSION,approved_digest=resolver.digest(doc),requirements=dict(required_request_headers=[],execution_rules=reviewed.execution_rules.model_dump()))))
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:FakeReconMainAgent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('sidecar was ignored before login'))
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:pytest.fail('sidecar was ignored before executor'))
    assert cli.main(['recon',PROGRAM_URL,'--target',URL,'--execute','--login-mode','system-browser','--output-dir',str(tmp_path/'Scope')])==1


def test_existing_session_bundle_can_be_validated_offline_with_direct_exclusions(tmp_path,monkeypatch):
    import aidast.cli as cli
    from aidast.recon.policy import TargetPolicy
    from aidast.recon.models import ReconPlan,ReconPlanTarget,ReconStep
    doc=approved(tmp_path,document(False))
    class Agent(FakeReconMainAgent):
        def create_recon_plan(self,**kwargs):
            return ReconPlan(plan_id='plan_fixture',scope_id=doc.scope_id,objective='Review',mode='FULL_RECON',targets=[ReconPlanTarget(asset_type='URL',asset=URL,steps=[ReconStep.HTTP_PROBE],constraints=[])],global_constraints=[],completion_criteria=['policy'])
        def create_target_policies(self,**kwargs):
            return {('URL',URL):TargetPolicy(scope_id=doc.scope_id,policy_id='fixture',asset_type='URL',asset=URL,allowed_hosts=['example.com'])}
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    class ReachedOfflineBundle(Exception): pass
    def collect(*args,**kwargs):
        assert kwargs['session_bundle']==tmp_path/'Session.json'
        raise ReachedOfflineBundle
    monkeypatch.setattr(cli,'collect_target_sessions',collect)
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:pytest.fail('executor before offline bundle validation'))
    with pytest.raises(ReachedOfflineBundle):
        cli.main(['recon',PROGRAM_URL,'--target',URL,'--execute','--session-bundle',str(tmp_path/'Session.json'),
                  '--login-mode','system-browser','--output-dir',str(tmp_path/'Scope')])


def test_newer_capture_replaces_stale_duplicate_from_another_database(tmp_path):
    doc=document();path=capture(tmp_path,doc)
    old=tmp_path/'Recon.db';old.write_bytes(path.read_bytes())
    with sqlite3.connect(old) as conn:
        receipt=json.loads(conn.execute('SELECT request_receipt FROM http_transactions').fetchone()[0])
        receipt['captured_at']-=172800
        conn.execute('UPDATE http_transactions SET request_receipt=?',(json.dumps(receipt),))
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,resolver=ExclusionBindingResolver(tmp_path/'cache',interpret))
    assert result.captured_candidates==1
    assert result.diagnostics[0]['decision']=='continue'


def retarget_document(asset_type,asset):
    doc=document(False)
    target=doc.analysis.in_scope_assets[0].model_copy(update={'asset_type':__import__('aidast.scope.models',fromlist=['AssetType']).AssetType(asset_type),'asset':asset})
    text=doc.source.text+'\n'+asset
    return doc.model_copy(update={'source':doc.source.model_copy(update={'text':text,'content_sha256':hashlib.sha256(text.encode()).hexdigest()}),
        'analysis':doc.analysis.model_copy(update={'in_scope_assets':[target],
            'source_evidence':[*doc.analysis.source_evidence,SourceEvidence(section='Scope',quote=asset)]})})


@pytest.mark.parametrize('kind,asset',[('DOMAIN','example.com'),('IP_ADDRESS','127.0.0.1')])
def test_unknown_domain_or_ip_startup_is_pending_not_a_hypothetical_get(tmp_path,kind,asset):
    doc=retarget_document(kind,asset)
    prepared=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,database_paths=[],cache_only=True)
    assert prepared.public()['held']==1
    assert prepared.diagnostics[0]['url'] is None
    with pytest.raises(ValueError,match='startup'):
        prepared.require_ready()


def test_empty_startup_diagnostics_cannot_prove_readiness():
    with pytest.raises(ValueError,match='startup'):
        api().ExclusionPreparation({},[]).require_ready()


@pytest.mark.parametrize('capability',['DNS_RESOLUTION','HOST_PORT_DISCOVERY'])
def test_cli_completed_plan_unmanaged_startup_holds_before_policy_login_executor(tmp_path,monkeypatch,capability):
    import aidast.cli as cli
    from aidast.recon.models import ReconPlan,ReconPlanTarget
    doc=approved(tmp_path,retarget_document('DOMAIN','example.com'))
    class Agent(FakeReconMainAgent):
        def create_recon_plan(self,**kwargs):
            return ReconPlan(plan_id='startup_fixture',scope_id=doc.scope_id,objective='Offline fixture',mode='FULL_RECON',
                targets=[ReconPlanTarget(asset_type='DOMAIN',asset='example.com',steps=[capability,'HTTP_PROBE'],constraints=[])],global_constraints=[],completion_criteria=['review'])
        def create_target_policies(self,**kwargs):pytest.fail('unmanaged startup must stop before policies/login/executor')
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('unmanaged startup opened login'))
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:pytest.fail('unmanaged startup created executor'))
    assert cli.main(['recon',PROGRAM_URL,'--target','example.com','--execute','--login-mode','runtime-browser','--output-dir',str(tmp_path/'Scope')])==1


def test_web_explicit_wildcard_start_matches_cli_discovery_hold(tmp_path,monkeypatch):
    import aidast.cli as cli
    from aidast.web.launch import ScanLaunchManager,ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    doc=approved(tmp_path,retarget_document('WILDCARD','*.example.com'))
    manager=ScanLaunchManager(tmp_path,DashboardProjector(tmp_path),process_factory=lambda *a,**k:pytest.fail('wildcard discovery spawned a process'))
    request=ScanLaunchRequest(scope_id=doc.scope_id,targets=['*.example.com'],start_url='https://docs.example.com/',authorization_confirmed=True)
    with pytest.raises(ValueError,match='restricted'):
        manager.launch(request)
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:FakeReconMainAgent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('wildcard discovery opened login'))
    assert cli.main(['recon',PROGRAM_URL,'--target','*.example.com','--start-url','https://docs.example.com/',
        '--execute','--login-mode','runtime-browser','--output-dir',str(tmp_path/'Scope')])==1


def test_capture_query_is_accepted_with_complete_identity_and_changed_query_holds(tmp_path):
    from aidast.core.exclusion_guard import evaluate_exclusions
    doc=document();url=URL+'items?page=2';path=capture(tmp_path,doc,url=url)
    snapshot=api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0])
    assert len(snapshot.candidates)==1
    assert 'page=2' not in snapshot.candidates[0].url
    assert 'page=' in snapshot.candidates[0].url
    compiled=ExclusionBindingResolver(tmp_path/'cache',interpret).resolve(scope_digest=api().approved_scope_digest(doc),
        target_asset=URL,rules=doc.analysis.execution_rules.exclusions,candidates=snapshot.candidates,evidence=snapshot.evidence)
    for query,expected in [('2','continue'),('3','hold')]:
        descriptor=receipt_api().prepare_http_request(URL+'items?page='+query,headers={'User-Agent':'aidast-recon/0.1'})
        assert evaluate_exclusions(compiled.model_dump(mode='json'),**descriptor,body_available=True)['decision']==expected


@pytest.mark.parametrize('url',[URL+'items?page=%zz',URL+'items?page=2#fragment','https://user:secret@example.com/items?page=2'])
def test_untrusted_queried_capture_urls_remain_rejected(tmp_path,url):
    doc=document();path=capture(tmp_path,doc)
    # Tampered rows with malformed URL cannot use even a structurally present receipt.
    with sqlite3.connect(path) as conn:
        receipt=json.loads(conn.execute('SELECT request_receipt FROM http_transactions').fetchone()[0])
        receipt['url_sha256']=hashlib.sha256(url.encode()).hexdigest()
        conn.execute('UPDATE http_transactions SET url=?,request_receipt=?',(url,json.dumps(receipt)))
    assert not api().load_capture_snapshot([path],document=doc,target=doc.analysis.in_scope_assets[0]).candidates


@pytest.mark.parametrize('steps,expected',[(['HTTP_PROBE'],'continue'),(['DNS_RESOLUTION','HTTP_PROBE'],'hold'),(['HOST_PORT_DISCOVERY','HTTP_PROBE'],'hold'),(['ENDPOINT_DISCOVERY'],'hold')])
def test_selected_startup_capabilities_preserve_http_only_and_hold_missing_or_unmanaged(tmp_path,steps,expected):
    from aidast.recon.models import ReconPlan,ReconPlanTarget
    doc=retarget_document('DOMAIN','example.com')
    plan=ReconPlan(plan_id='capability_fixture',scope_id=doc.scope_id,objective='Offline',mode='FULL_RECON',
        targets=[ReconPlanTarget(asset_type='DOMAIN',asset='example.com',steps=steps,constraints=[])],global_constraints=[],completion_criteria=['review'])
    operations=api().selected_startup_operations(doc.analysis.in_scope_assets,plan=plan)
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,database_paths=[],cache_only=True,startup_operations=operations)
    assert ('hold' if result.public()['held'] else 'continue')==expected
    if expected=='continue':
        result.require_ready()
        assert result.diagnostics[0]['url']=='https://example.com'
    else:
        with pytest.raises(ValueError,match='startup'):
            result.require_ready()


def test_url_startup_ignores_model_proposed_domain_discovery_steps(tmp_path):
    from aidast.recon.models import ReconPlan,ReconPlanTarget
    doc=document(False)
    target=doc.analysis.in_scope_assets[0]
    plan=ReconPlan(plan_id='url_capability_fixture',scope_id=doc.scope_id,objective='Offline',mode='FULL_RECON',
        targets=[ReconPlanTarget(asset_type=target.asset_type,asset=target.asset,
            steps=['DNS_RESOLUTION','HOST_PORT_DISCOVERY','HTTP_PROBE'],constraints=[])],
        global_constraints=[],completion_criteria=['review'])
    operations=api().selected_startup_operations([target],plan=plan)
    assert operations[target.asset] == [api().StartupOperation('HTTP_PROBE', target.asset)]
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=[target],
        result_root=tmp_path,database_paths=[],cache_only=True,startup_operations=operations)
    result.require_ready()
    assert result.public()['held']==0


def test_empty_explicit_startup_map_does_not_fall_back_to_an_invented_probe(tmp_path):
    doc=document(False)
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,database_paths=[],cache_only=True,startup_operations={})
    assert result.public()['held']==1
    assert result.diagnostics[0]['capability']=='MISSING_STARTUP'


@pytest.mark.parametrize('kind,asset',[('DOMAIN','example.com'),('IP_ADDRESS','127.0.0.1'),('WILDCARD','*.example.com')])
def test_empty_exclusions_preserve_known_legacy_discovery_startups(tmp_path,kind,asset):
    doc=retarget_document(kind,asset)
    doc=doc.model_copy(update={'analysis':doc.analysis.model_copy(update={'execution_rules':ScopeExecutionRules(exclusions=[])})})
    result=api().prepare_exclusions(document=doc,analysis=doc.analysis,targets=doc.analysis.in_scope_assets,
        result_root=tmp_path,database_paths=[],cache_only=True)
    result.require_ready()
    assert result.public()['held']==0


@pytest.mark.parametrize('kind,asset',[('DOMAIN','example.com'),('IP_ADDRESS','127.0.0.1')])
def test_web_holds_unknown_domain_ip_capabilities_before_process(tmp_path,kind,asset):
    from aidast.web.launch import ScanLaunchManager,ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    doc=approved(tmp_path,retarget_document(kind,asset))
    manager=ScanLaunchManager(tmp_path,DashboardProjector(tmp_path),process_factory=lambda *a,**k:pytest.fail('unsupported startup spawned process'))
    with pytest.raises(ValueError,match='UNKNOWN_STARTUP'):
        manager.launch(ScanLaunchRequest(scope_id=doc.scope_id,targets=[asset],authorization_confirmed=True))


def test_all_targets_does_not_force_domain_discovery_for_a_url_plan(tmp_path,monkeypatch):
    import aidast.cli as cli
    from aidast.recon.policy import TargetPolicy
    from aidast.recon.models import ReconPlan,ReconPlanTarget
    doc=approved(tmp_path,document(False))
    class Agent(FakeReconMainAgent):
        def create_recon_plan(self,**kwargs):
            return ReconPlan(plan_id='all_fixture',scope_id=doc.scope_id,objective='Offline fixture',mode='FULL_RECON',
                targets=[ReconPlanTarget(asset_type='URL',asset=URL,steps=['HTTP_PROBE'],constraints=[])],global_constraints=[],completion_criteria=['review'])
        def create_target_policies(self,**kwargs):
            assert kwargs['plan'].targets[0].steps == [
                'HTTP_PROBE','ORIGIN_DISCOVERY','ENDPOINT_DISCOVERY']
            return {('URL',URL):TargetPolicy(scope_id=doc.scope_id,policy_id='fixture',
                asset_type='URL',asset=URL,allowed_hosts=['example.com'])}
    class ReachedSessionSetup(Exception): pass
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('runtime browser collected a session too early'))
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:(_ for _ in ()).throw(ReachedSessionSetup()))
    with pytest.raises(ReachedSessionSetup):
        cli.main(['recon',PROGRAM_URL,'--all-targets','--execute','--login-mode','runtime-browser','--output-dir',str(tmp_path/'Scope')])


@pytest.mark.parametrize('selection', ['denied_url','held_url','held_wildcard','system_browser','ready_url','empty_rules'])
def test_mixed_pending_startup_never_suppresses_known_preplan_blocks(tmp_path,monkeypatch,selection):
    import aidast.cli as cli
    from aidast.scope.models import AssetType
    if selection=='held_wildcard':
        doc=retarget_document('WILDCARD','*.example.com')
    elif selection=='denied_url':
        doc=retarget_document('URL',URL+'private')
    else:
        doc=guarded_semantic_document() if selection=='held_url' else document(False)
    target=ScopeAsset(asset_type=AssetType.DOMAIN,asset='other.example.test',description='Pending startup',eligibility='eligible',maximum_severity='High')
    text=doc.source.text+'\n'+target.asset
    analysis=doc.analysis.model_copy(update={
        'in_scope_assets':[*doc.analysis.in_scope_assets,target],
        'source_evidence':[*doc.analysis.source_evidence,SourceEvidence(section='Scope',quote=target.asset)]})
    if selection=='empty_rules':
        analysis=analysis.model_copy(update={'execution_rules':ScopeExecutionRules(exclusions=[])})
    doc=approved(tmp_path,doc.model_copy(update={'analysis':analysis,
        'source':doc.source.model_copy(update={'text':text,'content_sha256':hashlib.sha256(text.encode()).hexdigest()})}))
    may_plan=selection in {'ready_url','empty_rules'}
    calls=[]
    class ReachedOfflinePlanner(Exception): pass
    class Agent(FakeReconMainAgent):
        def create_recon_plan(self,**kwargs):
            calls.append(kwargs)
            if not may_plan:
                pytest.fail('a definite selection block must precede offline planning')
            raise ReachedOfflinePlanner
    monkeypatch.setattr(cli,'CodexMainAgent',lambda **_:Agent())
    monkeypatch.setattr(cli,'collect_target_sessions',lambda *a,**k:pytest.fail('unexpected login'))
    monkeypatch.setattr(cli,'ReconExecutor',lambda *a,**k:pytest.fail('unexpected executor'))
    args=['recon',PROGRAM_URL,'--execute','--login-mode','system-browser' if selection=='system_browser' else 'runtime-browser',
        '--output-dir',str(tmp_path/'Scope')]
    for item in doc.analysis.in_scope_assets:
        args+=['--target',item.asset]
    if may_plan:
        with pytest.raises(ReachedOfflinePlanner):cli.main(args)
        assert len(calls)==1
    else:
        assert cli.main(args)==1
        assert calls==[]
