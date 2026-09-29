"""AI proposes relationships; real captures and source constrain executable URLs."""
import importlib.util
import json

import pytest

from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


SCRIPT = """const load=async()=>{
 const r=await fetch('/catalog');const payload=await r.json();
 payload.results.items.forEach(row=>{fetch(`/v1/documents/${row.slug}`);});
};"""


def api():
    assert importlib.util.find_spec('aidast.recon.tools.ai_patterns') is not None, 'AI pattern interpreter is missing'
    from aidast.recon.tools import ai_patterns
    return ai_patterns


@pytest.fixture
def policy():
    return TargetPolicy(policy_id='policy',scope_id='scope',asset_type=AssetType.URL,asset='https://example.test/',
                        allowed_schemes=['https'],allowed_hosts=['example.test'],allowed_ports=[443],
                        allowed_path_prefixes=['/'],allowed_methods=['GET'])


def response(payload=None, **changes):
    row=dict(method='GET',url='https://example.test/catalog',response_status=200,
             response_headers={'Content-Type':'application/json'},capture_bodies=True,
             response_body=json.dumps(payload if payload is not None else
                                      {'results':{'items':[{'slug':'daily'},{'slug':'a/b'}]}}))
    row.update(changes)
    return row


def evidence(policy,script=SCRIPT,records=None):
    return api().build_pattern_evidence('https://example.test/',
        {'https://example.test/app.js':script},records or [response()],target_policy=policy)


def plan(bundle, **changes):
    target=next(x for x in bundle.context['literals'] if x['path']=='/v1/documents/${row.slug}')
    row=dict(response_ref='response-1',target_ref=target['ref'],collection_path=['results','items'],
             value_field='slug',evidence_refs=[target['snippet_ref']])
    row.update(changes)
    return api().PatternPlan(bindings=[row],literal_gets=[],summary='Observed callback relation')


def test_arrow_named_array_non_api_template_uses_only_actual_values(policy):
    bundle=evidence(policy)
    rows,decisions=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/daily',
                                     'https://example.test/v1/documents/a%2Fb']
    assert all(r['verification_status']=='candidate' for r in rows)
    assert all(r['evidence']['relationship_status']=='ai_hypothesis' for r in rows)
    assert decisions[0]['accepted'] is True


@pytest.mark.parametrize('change',[
    {'response_ref':'fabricated'}, {'target_ref':'fabricated'},
    {'collection_path':['unobserved']}, {'value_field':'invented'},
    {'evidence_refs':['fabricated']}, {'value_field':'password'},
])
def test_unsubstantiated_references_and_fields_do_not_create_requests(policy,change):
    bundle=evidence(policy)
    rows,decisions=api().resolve_pattern_plan(bundle,plan(bundle,**change),target_policy=policy)
    assert rows==[] and decisions[0]['accepted'] is False


@pytest.mark.parametrize('changes',[
    {'method':'POST'}, {'response_status':401}, {'capture_bodies':False},
    {'policy_blocked':True}, {'candidate_probe':True}, {'duplicate':True},
    {'url':'https://outside.test/catalog'},
])
def test_ineligible_capture_never_supplies_binding_values(policy,changes):
    bundle=evidence(policy,records=[response(**changes)])
    assert bundle.context['responses']==[]


def test_post_and_commented_template_do_not_become_get_literals(policy):
    script="fetch('/catalog'); fetch(`/v1/documents/${row.slug}`,{method:'POST'}); /* fetch('/ghost') */"
    bundle=evidence(policy,script)
    assert [r['path'] for r in bundle.context['literals']]==['/catalog']


def test_duplicate_plan_and_known_url_are_not_reprobed(policy):
    bundle=evidence(policy)
    proposal=plan(bundle)
    proposal=api().PatternPlan(bindings=proposal.bindings*2,literal_gets=[],summary='duplicate')
    rows,_=api().resolve_pattern_plan(bundle,proposal,target_policy=policy,
                                    known_urls=['https://example.test/v1/documents/daily'])
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/a%2Fb']


def test_empty_collection_does_not_invent_identifier(policy):
    bundle=evidence(policy,records=[response({'results':{'items':[]}})])
    rows,decisions=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert rows==[] and decisions[0]['accepted'] is False


def test_payload_samples_redact_credentials_and_leave_fields_available(policy):
    bundle=evidence(policy,records=[response({'token':'private-token','results':{'items':[
        {'slug':'daily','password':'private-password'}]}})])
    rendered=json.dumps(bundle.context)
    assert 'private-token' not in rendered and 'private-password' not in rendered
    rows,_=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/daily']


def test_model_context_exposes_structure_without_captured_scalar_values(policy):
    bundle=evidence(policy,records=[response({'results':{'items':[
        {'slug':'private-slug-value','account_number':123456789,'email':'private@example.test'}]}})])
    rendered=json.dumps(bundle.context)
    assert 'private-slug-value' not in rendered and '123456789' not in rendered
    assert 'private@example.test' not in rendered
    rows,_=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/private-slug-value']


def test_capture_on_same_origin_without_its_source_literal_is_not_linked(policy):
    bundle=evidence(policy,records=[response(url='https://example.test/other')])
    rows,decisions=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert rows==[] and decisions[0]['accepted'] is False


def test_one_object_response_can_supply_a_code_evidenced_field(policy):
    script="const r=await fetch('/catalog');const row=await r.json();fetch(`/v1/documents/${row.slug}`);"
    bundle=evidence(policy,script,records=[response({'slug':'daily'})])
    rows,_=api().resolve_pattern_plan(bundle,plan(bundle,collection_path=[]),target_policy=policy)
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/daily']


def test_source_ranges_belong_to_actual_get_occurrence_not_earlier_post(policy):
    script="fetch(`/v1/documents/${row.slug}`,{method:'POST'});"+' '*4000+SCRIPT
    bundle=evidence(policy,script)
    literal=next(x for x in bundle.context['literals'] if x['path']=='/v1/documents/${row.slug}')
    snippet=next(x for x in bundle.context['snippets'] if x['ref']==literal['snippet_ref'])
    assert snippet['start']>0
    assert 'payload.results.items.forEach' in snippet['text']


def test_unresolved_query_expression_is_not_an_executable_recipe(policy):
    bundle=evidence(policy,SCRIPT.replace('${row.slug}`','${row.slug}?view=${compute()}`'))
    target=next(x for x in bundle.context['literals'] if x['path'].startswith('/v1/documents/'))
    proposal=api().PatternPlan(bindings=[dict(response_ref='response-1',target_ref=target['ref'],
        collection_path=['results','items'],value_field='slug',evidence_refs=[target['snippet_ref']])])
    rows,decisions=api().resolve_pattern_plan(bundle,proposal,target_policy=policy)
    assert rows==[] and decisions[0]['accepted'] is False


def test_class_local_source_base_keeps_exact_get_evidence(policy):
    script='class API{root="/catalog";get(){return http.get(this.root+"/")} item(row){return http.get(`/v1/documents/${row.slug}`)}}'
    bundle=evidence(policy,script)
    source=next(x for x in bundle.context['literals'] if x['path']=='/catalog/')
    assert script[source['literal_start']:source['literal_end']]=='"/"'
    rows,_=api().resolve_pattern_plan(bundle,plan(bundle),target_policy=policy)
    assert [r['url'] for r in rows]==['https://example.test/v1/documents/daily','https://example.test/v1/documents/a%2Fb']


class FixturePlanner:
    def propose(self, context):
        target=next(x for x in context['literals'] if x['path']=='/v1/documents/${row.slug}')
        source=next(x for x in context['responses'] if x['url']=='https://example.test/catalog')
        return api().PatternPlan(bindings=[dict(response_ref=source['ref'],target_ref=target['ref'],
            collection_path=['results','items'],value_field='slug',evidence_refs=[target['snippet_ref']])])


def transport(monkeypatch, *, wildcard=False):
    from aidast.recon.tools import api_secondary_discovery as secondary
    def request(url,**kwargs):
        if url.endswith('/app.js'):
            return 200,{'content-type':'application/javascript'},SCRIPT.encode()
        if '__aidast_missing_control__' in url:
            return (200,{'content-type':'application/json'},b'{"content":[]}') if wildcard else (
                404,{'content-type':'application/json'},b'{"error":"missing"}')
        if url.endswith('/catalog'):
            return 200,{'content-type':'application/json'},response()['response_body'].encode()
        if url.endswith(('/v1/documents/daily','/v1/documents/a%2Fb')):
            return 200,{'content-type':'application/json'},b'{"content":[]}'
        raise AssertionError('Unexpected URL '+url)
    monkeypatch.setattr(secondary,'_http_request',request)
    return secondary


def test_ai_plan_reaches_existing_response_verifier_and_preserves_prior_routes(policy,monkeypatch):
    secondary=transport(monkeypatch)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/app.js')],target_policy=policy,proxy_url='http://127.0.0.1:8080',
        ai_pattern_planner=FixturePlanner())
    verified={r['url'] for r in rows if r.get('verification_status')=='verified'}
    assert verified=={'https://example.test/v1/documents/daily','https://example.test/v1/documents/a%2Fb'}
    assert any(r['path']=='/catalog' and r['source']=='adaptive_js' for r in rows)


def test_ai_wildcard_does_not_promote_candidates(policy,monkeypatch):
    secondary=transport(monkeypatch,wildcard=True)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/app.js')],target_policy=policy,proxy_url='http://127.0.0.1:8080',
        observed_responses=[response()],ai_pattern_planner=FixturePlanner())
    assert not any(r['source']=='ai_pattern' and r['verification_status']=='verified' for r in rows)


def test_full_rejected_capture_input_does_not_starve_new_positive_response(policy,monkeypatch):
    secondary=transport(monkeypatch)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/app.js')],target_policy=policy,proxy_url='http://127.0.0.1:8080',
        observed_responses=[{}]*150,ai_pattern_planner=FixturePlanner())
    assert {r['url'] for r in rows if r.get('source')=='ai_pattern' and r.get('verification_status')=='verified'}=={
        'https://example.test/v1/documents/daily','https://example.test/v1/documents/a%2Fb'}


@pytest.mark.parametrize('flag',['candidate_probe','duplicate','static_resource'])
def test_observed_only_capture_flags_survive_integration(policy,monkeypatch,flag):
    secondary=transport(monkeypatch)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/app.js'),dict(method='GET',path='/catalog')],
        target_policy=policy,proxy_url='http://127.0.0.1:8080',
        observed_responses=[response(**{flag:True})],ai_pattern_planner=FixturePlanner())
    assert not any(r.get('source')=='ai_pattern' for r in rows)


def test_large_nested_response_samples_keep_model_input_bounded(policy):
    payload={'results':{'items':[{'slug':'daily'}]},'wide':{
        str(i): {str(j):'x'*200 for j in range(20)} for i in range(20)}}
    bundle=evidence(policy,records=[response(payload,url=f'https://example.test/catalog?view={i}') for i in range(50)])
    assert len(json.dumps(bundle.context))<160_000


def test_provider_failure_leaves_existing_results_available(policy,monkeypatch):
    secondary=transport(monkeypatch)
    class FailedPlanner:
        def propose(self, context):
            raise RuntimeError('Unavailable provider')
    events=[]
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/app.js')],target_policy=policy,proxy_url='http://127.0.0.1:8080',
        ai_pattern_planner=FailedPlanner(),diagnostic_callback=lambda event,**data: events.append((event,data)))
    assert any(r['path']=='/catalog' for r in rows)
    assert any(event=='phase_error' and data.get('component')=='ai_patterns' for event,data in events)
