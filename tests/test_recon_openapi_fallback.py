import json
import pytest
from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.scope.models import AssetType
from aidast.recon.policy import TargetPolicy


def extract(document, **kwargs):
    from aidast.recon.tools.openapi_get import declared_get_candidates
    return declared_get_candidates(document, document_url='https://example.test/docs/openapi.json',
                                   base_url='https://example.test/', **kwargs)


def test_malformed_write_schema_does_not_discard_literal_get():
    rows=extract({'openapi':'3.0.0','servers':[{'url':'/v1'}],'paths':{
        '/items':{'get':{},'post':{'requestBody':{'schema':{'required':'invalid'}}}},
        '/items/{id}':{'get':{}}, '/write':{'post':{}}, '/broken':{'get':None}}})
    assert [row['url'] for row in rows]==['https://example.test/v1/items']
    assert rows[0]['verification_status']=='candidate'


@pytest.mark.parametrize('server',['https://outside.test/v1','https://u:p@example.test/v1','/v1?q=1','/v1#x','/{tenant}'])
def test_external_or_unresolved_servers_never_fall_back_to_local_root(server):
    assert extract({'openapi':'3.0.0','servers':[{'url':server}],'paths':{'/items':{'get':{}}}})==[]


def test_path_and_operation_servers_override_document_servers():
    rows=extract({'openapi':'3.1.0','servers':[{'url':'https://outside.test/'}],'paths':{
        '/one':{'servers':[{'url':'/path'}],'get':{}},
        '/two':{'servers':[{'url':'/path'}],'get':{'servers':[{'url':'../operation'}]}}}})
    assert [row['url'] for row in rows]==['https://example.test/path/one','https://example.test/operation/two']


def test_swagger_host_scheme_and_base_path_are_used():
    rows=extract({'swagger':'2.0','host':'example.test','schemes':['https'],'basePath':'/v2','paths':{'/items':{'get':{}}}})
    assert rows[0]['url']=='https://example.test/v2/items'
    assert extract({'swagger':'2.0','host':'outside.test','paths':{'/items':{'get':{}}}})==[]


def test_invalid_path_and_required_unknown_parameters_are_skipped():
    assert extract({'openapi':'3.0.0','paths':{
        '//outside.test/x':{'get':{}}, '/a/../x':{'get':{}}, '/x?foo':{'get':{}},
        '/items':{'get':{'parameters':[{'in':'query','name':'key','required':True}]}}}})==[]


def test_fallback_fetches_only_declared_get_and_requires_distinct_positive_json(monkeypatch):
    policy=TargetPolicy(scope_id='scope',policy_id='policy',asset_type=AssetType.URL,
        asset='https://example.test/',allowed_hosts=['example.test'],allowed_ports=[443],
        allowed_schemes=['https'],allowed_methods=['GET'],allowed_path_prefixes=['/'])
    spec={'openapi':'3.0.0','paths':{'/read':{'get':{}},'/write':{'post':{}},'/fake':{'get':{}}}}
    monkeypatch.setattr(secondary,'detect_openapi',lambda *a,**k:[secondary.OpenAPIDefinition(document=spec)])
    monkeypatch.setattr(secondary,'detect_graphql',lambda *a,**k:[])
    monkeypatch.setattr(secondary,'_run_zap',lambda *a,**k:False)
    requests=[]
    def request(url, **kwargs):
        requests.append(url)
        if url.endswith('/read'):return 200,{'content-type':'application/json'},b'{"items":[]}'
        return 404,{'content-type':'application/json'},b'{"error":"missing"}'
    monkeypatch.setattr(secondary,'_http_request',request)
    rows=secondary.discover_api_secondary('https://example.test/',[],target_policy=policy,proxy_url='http://127.0.0.1:8888')
    verified=[row for row in rows if row['verification_status']=='verified']
    assert [row['path'] for row in verified]==['/read']
    assert verified[0]['source']=='openapi_get_fallback'
    assert verified[0]['evidence']['seed_paths']==['/read']
    assert not any(url.endswith('/write') for url in requests)


def test_malformed_server_entry_does_not_hide_later_valid_server():
    rows=extract({'openapi':'3.0.0','servers':[{'url':'http://[invalid'},{'url':'/v1'}],
                  'paths':{'/items':{'get':{}}}})
    assert [r['url'] for r in rows]==['https://example.test/v1/items']


def test_malformed_swagger_scheme_entry_does_not_abort_valid_scheme():
    rows=extract({'swagger':'2.0','schemes':['https',{}],'paths':{'/items':{'get':{}}}})
    assert [r['url'] for r in rows]==['https://example.test/items']


def test_embedded_invalid_server_is_isolated_before_zap_plan():
    assert secondary._openapi_server_url({'servers':[{'url':'http://[invalid'}]},'https://example.test/',None)=='https://example.test/'


def test_embedded_document_retains_its_source_url(monkeypatch):
    spec={'openapi':'3.0.0','servers':[{'url':'./v1'}],'paths':{'/items':{'get':{}}}}
    monkeypatch.setattr(secondary,'_build_openapi_candidates',lambda *a:['https://example.test/docs/'])
    monkeypatch.setattr(secondary,'_http_request',lambda *a,**k:(200,{'content-type':'text/html'},b'<html></html>'))
    monkeypatch.setattr(secondary,'_swagger_ui_document',lambda *a,**k:spec)
    definitions=secondary.detect_openapi('https://example.test/',[])
    assert definitions[0].url is None
    assert definitions[0].document_url=='https://example.test/docs/'
    from aidast.recon.tools.openapi_get import declared_get_candidates
    rows=declared_get_candidates(spec,document_url=definitions[0].document_url,base_url='https://example.test/')
    assert rows[0]['url']=='https://example.test/docs/v1/items'
    from aidast.recon.annotations import sanitize_evidence
    assert sanitize_evidence(rows[0]['evidence'])==rows[0]['evidence']


def test_zap_target_base_and_document_relative_server_are_separate():
    helper=secondary._openapi_server_url
    assert helper({'openapi':'3.0.0'},'https://example.test/',None,document_url='https://example.test/docs/')=='https://example.test/'
    assert helper({'openapi':'3.0.0','servers':[{'url':'./v1'}]},'https://example.test/',None,
                  document_url='https://example.test/docs/index.html')=='https://example.test/docs/v1'
