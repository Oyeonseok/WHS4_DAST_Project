"""Grounded read requests in arbitrary application routes and response shapes."""
import json
from urllib.parse import urlsplit
import pytest
import yaml
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.tools.js_fetch_bindings import extract_fetch_response_bindings
from aidast.recon.tools.js_argument_bindings import bind_response_values
from aidast.recon.tools.openapi_get import declared_get_candidates
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType

SCRIPT = """async function openLedger(){
 const ownerKey=document.getElementById('owner-key').textContent;
 const r=await fetch(`/records?owner_key=${ownerKey}&view=recent`);
} """
HTML = '<span id="owner-key">team/a &amp; b</span><script src="/assets/client.js"></script>'
AUTH = {'Authorization':'Bearer local-test-session', 'Cookie':'sid=local-test-cookie'}

def policy():
 return TargetPolicy(scope_id='scope',policy_id='policy',asset_type=AssetType.URL,
   asset='https://example.test/',allowed_hosts=['example.test'],allowed_ports=[443],
   allowed_schemes=['https'],allowed_methods=['GET'],allowed_path_prefixes=['/'])

def record(url, body, media='text/html', status=200, headers=None):
 return dict(method='GET',url='https://example.test'+url,response_status=status,
   response_headers={'content-type':media},response_body=body,capture_bodies=True,
   request_headers=AUTH if headers is None else headers)

def test_json_to_query_binding_keeps_query_and_encodes_actual_nested_value():
 script="""async function load(){const r=await fetch('/directory');const data=await r.json();
 data.result.members.forEach(row=>{fetch(`/records?owner_key=${row.key}&view=recent`);});}"""
 bindings=extract_fetch_response_bindings({'client.js':script})
 assert len(bindings)==1
 assert bind_response_values(bindings[0],'/directory',{'result':{'members':[{'key':'team/a & b'}]}})==[
   '/records?owner_key=team%2Fa%20%26%20b&view=recent']

def test_dom_query_retries_a_path_previously_seen_without_credentials(monkeypatch):
 calls=[]
 def request(url,**kwargs):
  calls.append((url,kwargs.get('headers')))
  if urlsplit(url).path=='/assets/client.js':return 200,{'content-type':'application/javascript'},SCRIPT.encode()
  if url=='https://example.test/records?owner_key=team%2Fa%20%26%20b&view=recent':
   return 200,{'content-type':'application/json'},b'{"entries":[]}'
  return 404,{'content-type':'application/json'},b'{"error":"missing"}'
 monkeypatch.setattr(secondary,'_http_request',request)
 rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
   [{'path':'/workspace'},{'path':'/records','url':'https://example.test/records?owner_key=unrelated'}],
   headers=AUTH,target_policy=policy(),proxy_url='http://127.0.0.1:8888',observed_responses=[
     record('/workspace',HTML),record('/records?owner_key=unrelated','{"error":"authentication required"}',
       'application/json',401,{})])
 assert any(r['url']=='https://example.test/records?owner_key=team%2Fa%20%26%20b&view=recent'
            and r['evidence']['response_status']==200 for r in rows)
 assert all(h==AUTH for _,h in calls)
 assert not any('owner_key=unrelated' in u for u,_ in calls)

def test_required_openapi_query_uses_observed_named_values_not_schema_examples():
 spec={'openapi':'3.0.0','paths':{'/records':{'get':{'parameters':[
   {'in':'query','name':'owner_key','required':True,'schema':{'type':'string','example':'invented'}}]}}}}
 rows=declared_get_candidates(spec,document_url='https://example.test/schema',base_url='https://example.test/',
   observed_values={'owner_key':['team/a & b']})
 assert [r['url'] for r in rows]==['https://example.test/records?owner_key=team%2Fa%20%26%20b']
 assert declared_get_candidates(spec,document_url='https://example.test/schema',base_url='https://example.test/')==[]
 assert declared_get_candidates(spec,document_url='https://example.test/schema',base_url='https://example.test/',
   observed_values={'other':['invented']})==[]

def test_zap_authentication_rules_are_scoped_to_exact_origin(tmp_path):
 text=secondary._create_zap_plan(base_url='https://example.test/',output_har=tmp_path/'capture.har',
   openapi_files=[(tmp_path/'spec.json','https://example.test/')],headers=AUTH)
 plan=yaml.safe_load(text)
 rules=next(job for job in plan['jobs'] if job['type']=='replacer')['rules']
 import re
 for rule in rules:
  # ZAP uses Java Matcher.matches(), which consumes the complete URL.
  assert re.fullmatch(rule['url'],'https://example.test/records?x=y')
  assert not re.fullmatch(rule['url'],'https://example.test.evil/records')
  assert not re.fullmatch(rule['url'],'http://example.test/records')
 assert {r['matchString']:r['replacementString'] for r in rules}['Authorization']==AUTH['Authorization']

@pytest.mark.parametrize('document,script',[
 ('<span id="owner-key">first</span><span id="owner-key">second</span>',SCRIPT),
 ('<input id="owner-key" type="password" value="secret">',SCRIPT.replace('.textContent','.value')),
 ('<span id="owner-key">observed</span>',SCRIPT.replace('const r=','ownerKey="changed"; const r=')),
 ('<span id="owner-key">observed</span>',SCRIPT.replace('fetch(`','fetch(`').replace('view=recent`);',"view=recent`,{method:'POST'});")),
 ('<span id="owner-key">observed</span>',SCRIPT.replace('owner-key','absent')),
])
def test_dom_binding_rejects_ambiguous_secret_mutated_and_write_inputs(document,script):
 from aidast.recon.tools.observed_parameters import bind_dom_gets
 assert bind_dom_gets({'https://example.test/assets/client.js':script},
   [('https://example.test/workspace',document+'<script src="/assets/client.js"></script>')])==[]

def test_dom_binding_does_not_choose_an_unselected_option_or_an_unrelated_script():
 from aidast.recon.tools.observed_parameters import bind_dom_gets
 script=SCRIPT.replace('.textContent','.value')
 assert bind_dom_gets({'https://example.test/assets/client.js':script},[
  ('https://example.test/workspace','<select id="owner-key"><option value="">Choose</option>'
   '<option value="someone-else">Other</option></select><script src="/assets/client.js"></script>')])==[]
 assert bind_dom_gets({'https://example.test/unrelated.js':SCRIPT},[
  ('https://example.test/workspace',HTML)])==[]

def test_proxy_duplicate_identity_keeps_authenticated_retry_separate():
 import runpy, sys
 from types import SimpleNamespace
 from unittest.mock import patch
 from pathlib import Path
 with patch.dict(sys.modules, {'mitmproxy':SimpleNamespace(ctx=SimpleNamespace(),http=SimpleNamespace())}):
  _canonical_request_key=runpy.run_path(str(Path(secondary.__file__).with_name('mitm_addon.py')))['_canonical_request_key']
 from urllib.parse import urlsplit
 url=urlsplit('https://example.test/records?owner_key=observed')
 assert _canonical_request_key('GET',url,headers={})!=_canonical_request_key('GET',url,headers=AUTH)
 assert _canonical_request_key('GET',url,headers=AUTH)==_canonical_request_key('GET',url,headers={
  'authorization':AUTH['Authorization'],'cookie':AUTH['Cookie'],'User-Agent':'different'})


def test_openapi_success_does_not_skip_grounded_parameters_or_generate_examples(monkeypatch):
 spec={'openapi':'3.0.0','info':{'title':'Generic app','version':'1'},'paths':{
  '/records':{'get':{'parameters':[{'in':'query','name':'owner_key','required':True,
     'schema':{'type':'string','example':'someone-else'}}]}},
  '/read':{'get':{'responses':{'200':{'description':'ok'}}}}, '/write':{'post':{}}}}
 monkeypatch.setattr(secondary,'detect_openapi',lambda *a,**k:[secondary.OpenAPIDefinition(document=spec)])
 monkeypatch.setattr(secondary,'detect_graphql',lambda *a,**k:[])
 def zap(plan_path,**kwargs):
  from pathlib import Path
  plan=yaml.safe_load(plan_path.read_text())
  jobs=[j for j in plan['jobs'] if j['type']=='openapi']
  for job in jobs:
   doc=json.loads(Path(job['parameters']['apiFile']).read_text())
   assert '/records' not in doc['paths'] and '/write' not in doc['paths']
   assert set(doc['paths'])=={'/read'}
  return True
 monkeypatch.setattr(secondary,'_run_zap',zap)
 monkeypatch.setattr(secondary,'_parse_zap_har',lambda *a,**k:[])
 calls=[]
 def request(url,**kwargs):
  calls.append(url)
  if url=='https://example.test/records?owner_key=team%2Fa%20%26%20b':
   return 200,{'content-type':'application/json'},b'{"entries":[]}'
  if urlsplit(url).path=='/read':return 200,{'content-type':'application/json'},b'{"entries":[]}'
  return 404,{'content-type':'application/json'},b'{"error":"missing"}'
 monkeypatch.setattr(secondary,'_http_request',request)
 rows=secondary.discover_api_secondary('https://example.test/',[],headers=AUTH,target_policy=policy(),
   proxy_url='http://127.0.0.1:8888',observed_responses=[record('/workspace',HTML)])
 assert any(r['url']=='https://example.test/records?owner_key=team%2Fa%20%26%20b' and
   r['verification_status']=='verified' for r in rows)
 assert all('someone-else' not in url for url in calls)


@pytest.mark.parametrize('script',[
 SCRIPT.replace('.textContent;', '.textContent + "-changed";'),
 SCRIPT.replace('.textContent;', '.textContent.toUpperCase();'),
 SCRIPT.replace('openLedger()', 'openLedger(document)'),
 'const document=fake;'+SCRIPT,
 SCRIPT.replace('const r=', '++ownerKey; const r='),
])
def test_dom_initializers_and_dom_identity_must_be_preserved(script):
 from aidast.recon.tools.observed_parameters import bind_dom_gets
 assert bind_dom_gets({'https://example.test/assets/client.js':script},[
  ('https://example.test/workspace',HTML)])==[]


def test_custom_auth_headers_and_duplicate_cookie_order_keep_distinct_identities():
 from aidast.recon.tools.request_identity import authentication_key
 assert authentication_key({'X-API-Key':'one'})!=authentication_key({'X-API-Key':'two'})
 assert authentication_key({'X-API-Key':'one'})!=authentication_key({})
 assert authentication_key({'Cookie':'sid=one; sid=two'})!=authentication_key({'Cookie':'sid=two; sid=one'})


def test_response_binding_retains_the_exact_source_query():
 from aidast.recon.tools.js_argument_bindings import ResponseArgumentBinding
 binding=ResponseArgumentBinding('/reader/${key}', '/directory?visible=yes','key',('client.js',),('members',))
 assert bind_response_values(binding,'https://example.test/directory?visible=yes',{'members':[{'key':'actual'}]})==['/reader/actual']
 assert bind_response_values(binding,'https://example.test/directory?visible=no',{'members':[{'key':'wrong'}]})==[]


def test_grounded_read_survives_budget_pressure_from_wordlist(monkeypatch):
 from aidast.recon.tools import endpoint_discovery as discovery
 from unittest.mock import MagicMock
 browser=MagicMock()
 browser.get_http_results.return_value=[]
 browser.get_websocket_results.return_value=[]
 browser.get_auth_headers.return_value=AUTH
 monkeypatch.setattr(discovery,'PlaywrightDriver',lambda *a,**k:browser)
 monkeypatch.setattr(discovery,'open_katana_browser',lambda *a,**k:None)
 monkeypatch.setattr(discovery,'discover_with_katana',lambda *a,**k:[])
 monkeypatch.setattr(discovery,'read_observed_recon_responses',lambda *a,**k:[])
 monkeypatch.setattr(discovery,'read_recent_json_responses',lambda *a,**k:[])
 monkeypatch.setattr(discovery,'recover_observed_json_gets',lambda *a,**k:[])
 budget={'remaining':2}
 def adaptive(*args,**kwargs):
  if not budget['remaining']:return []
  budget['remaining']-=1
  return [dict(method='GET',path='/grounded-read',url='https://example.test/grounded-read',
    source='adaptive_js_response_argument',evidence={'response_status':200})]
 def schema(*args,**kwargs):
  if not budget['remaining']:return []
  budget['remaining']-=1
  return [dict(method='GET',path='/schema-read',url='https://example.test/schema-read',
    source='openapi_get_fallback',verification_status='verified',evidence={'response_status':200})]
 def ffuf(*args,**kwargs):
  budget['remaining']=0
  return []
 monkeypatch.setattr(discovery,'discover_adaptive_js_api_candidates',adaptive)
 monkeypatch.setattr(discovery,'discover_api_secondary',schema)
 monkeypatch.setattr(discovery,'discover_with_ffuf',ffuf)
 rows=discovery.discover_endpoints('https://example.test/',preauthenticated=True,
   enable_playwright_interaction=False,target_policy=policy(),mitm_proxy_url='http://127.0.0.1:8888')
 assert {'/grounded-read','/schema-read'} <= {r['path'] for r in rows}


def test_model_evidence_never_contains_embedded_credentials():
 from aidast.recon.tools.ai_patterns import build_pattern_evidence
 script="const token='private-session-value'; fetch('/records'); fetch('/reader?access_token=private-query-value');"
 evidence=build_pattern_evidence('https://example.test/',{'https://example.test/client.js':script},[],target_policy=policy())
 serialized=json.dumps(evidence.context)
 assert 'private-session-value' not in serialized
 assert 'private-query-value' not in serialized
 assert '/records' in serialized


def test_ai_recipe_can_bind_one_complete_query_value_from_observed_json():
 from aidast.recon.tools.ai_patterns import build_pattern_evidence, resolve_pattern_plan, PatternPlan
 script="""const r=await fetch('/directory');const data=await r.json();
 data.result.members.forEach(row=>{fetch(`/records?owner_key=${row.key}&view=recent`);});"""
 evidence=build_pattern_evidence('https://example.test/',{'https://example.test/client.js':script},[
  record('/directory',json.dumps({'result':{'members':[{'key':'team/a & b'}]}}),'application/json')],target_policy=policy())
 literal=next(row for row in evidence.context['literals'] if '${' in row['path'])
 plan=PatternPlan(bindings=[dict(response_ref=evidence.context['responses'][0]['ref'],target_ref=literal['ref'],
   collection_path=['result','members'],value_field='key',evidence_refs=[literal['snippet_ref']])])
 rows,_=resolve_pattern_plan(evidence,plan,target_policy=policy())
 assert [r['url'] for r in rows]==['https://example.test/records?owner_key=team%2Fa%20%26%20b&view=recent']
 assert 'team/a & b' not in json.dumps(evidence.context)


def test_secret_response_field_never_becomes_a_url_argument():
 from aidast.recon.tools.js_argument_bindings import ResponseArgumentBinding
 binding=ResponseArgumentBinding('/reader/${row.token}','/directory','token',('client.js',),('members',))
 assert bind_response_values(binding,'/directory',{'members':[{'token':'private-session-value'}]})==[]


@pytest.mark.parametrize('code',[
 "xhr.setRequestHeader('Authorization','Bearer private-session-value');",
 "headers.set('X-API-Key','private-session-value');",
 "const token=/*comment*/'private-session-value';",
])
def test_header_setters_and_commented_assignments_do_not_leak_to_model(code):
 from aidast.recon.tools.ai_patterns import build_pattern_evidence
 evidence=build_pattern_evidence('https://example.test/',{'https://example.test/client.js':code+"fetch('/records');"},[],target_policy=policy())
 assert 'private-session-value' not in json.dumps(evidence.context)


@pytest.mark.parametrize('tail',['- 1','&& "different"','| 1','< 5','instanceof String'])
def test_dom_initializer_continuation_is_not_a_direct_read(tail):
 from aidast.recon.tools.observed_parameters import bind_dom_gets
 script=SCRIPT.replace('.textContent;', '.textContent\n'+tail+';')
 assert bind_dom_gets({'https://example.test/assets/client.js':script},[('https://example.test/workspace',HTML)])==[]


def test_dom_value_keeps_observed_whitespace_and_known_session_values_stay_local():
 from aidast.recon.tools.observed_parameters import bind_dom_gets
 from aidast.recon.tools.ai_patterns import build_pattern_evidence
 html='<input id="owner-key" value="  actual  "><script src="/assets/client.js"></script>'
 rows=bind_dom_gets({'https://example.test/assets/client.js':SCRIPT.replace('.textContent','.value')},[
  ('https://example.test/workspace',html)])
 assert rows[0].path=='/records?owner_key=%20%20actual%20%20&view=recent'
 evidence=build_pattern_evidence('https://example.test/',{'https://example.test/client.js':
   "const alias='private-session-value';fetch('/records');"},[],target_policy=policy(),
   sensitive_values=['private-session-value'])
 assert 'private-session-value' not in json.dumps(evidence.context)


def test_custom_prefixed_authentication_payload_stays_out_of_model_context():
 from aidast.recon.tools.ai_patterns import build_pattern_evidence
 from aidast.recon.tools.request_identity import credential_values
 evidence=build_pattern_evidence('https://example.test/',{'https://example.test/client.js':
   "const alias='private-session-value';fetch('/records');"},[],target_policy=policy(),
   sensitive_values=credential_values({'X-Custom-Auth':'Token private-session-value'}))
 assert 'private-session-value' not in json.dumps(evidence.context)


def test_zap_uses_disposable_private_profile_and_copies_only_addon_packages(tmp_path,monkeypatch,capsys):
 from pathlib import Path
 from types import SimpleNamespace
 home=tmp_path/'home';global_profile=home/'Library/Application Support/ZAP'
 plugins=global_profile/'plugin';plugins.mkdir(parents=True)
 (plugins/'automation.zap').write_bytes(b'installed-version')
 (plugins/'user-state.json').write_text('private-user-state')
 (global_profile/'config.xml').write_text('private-user-config')
 monkeypatch.setattr(Path,'home',classmethod(lambda cls:home))
 profiles=[]
 def run(command,**kwargs):
  assert '-dir' in command
  profile=Path(command[command.index('-dir')+1]);profiles.append(profile)
  assert profile.stat().st_mode & 0o077 == 0
  assert (profile/'plugin/automation.zap').read_bytes()==b'installed-version'
  assert not (profile/'plugin/user-state.json').exists()
  assert not (profile/'config.xml').exists()
  (profile/'config.xml').write_text('private-session-value')
  (profile/'zap.log').write_text('private-session-value')
  return SimpleNamespace(returncode=0,stdout='private-session-value',stderr='private-session-value')
 monkeypatch.setattr(secondary.subprocess,'run',run)
 assert secondary._run_zap(tmp_path/'plan.yaml',zap_executable='zaproxy')
 assert profiles and not profiles[0].exists()
 assert (global_profile/'config.xml').read_text()=='private-user-config'
 assert 'private-session-value' not in capsys.readouterr().out


def test_ffuf_stops_launching_roots_after_proxy_active_budget_is_exhausted(tmp_path,monkeypatch):
 from aidast.recon.tools import endpoint_discovery as discovery
 from types import SimpleNamespace
 from pathlib import Path
 wordlist=tmp_path/'words.txt';wordlist.write_text('read\n')
 calls=[]
 def run(command,**kwargs):
  calls.append(command)
  Path(command[command.index('-o')+1]).write_text(json.dumps({'results':[
   {'url':'https://example.test/read','status':200}]}))
  return SimpleNamespace(returncode=0,stdout='',stderr='')
 monkeypatch.setattr(discovery.subprocess,'run',run)
 monkeypatch.setattr(discovery.shutil,'which',lambda *a:'/fake/ffuf')
 available=iter([True,False])
 rows=discovery.discover_with_ffuf('https://example.test/',wordlist=str(wordlist),seed_endpoints=[],
  auth_headers=AUTH,proxy_url='http://127.0.0.1:8888',target_policy=policy(),root_selector=lambda *a:['/','/v1'],
  budget_available=lambda:next(available))
 assert len(calls)==1
 assert [row['path'] for row in rows]==['/read']
