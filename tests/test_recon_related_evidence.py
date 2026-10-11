"""Related code is evidence for a model, never executable generated code."""
import json

import pytest

from aidast.recon.tools.ai_patterns import build_pattern_evidence
from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method
from tests.test_recon_ai_patterns import policy, response


def test_direct_class_base_get_is_a_source_anchor_with_actual_argument_position():
    script='class Store{endpoint="/catalog";all(){return client.get(this.endpoint)}one(x){return client.get(`${this.endpoint}/${x.slug}`)}}'
    positions=[]
    paths=extract_js_api_paths(script,literal_call_method,include_class_get_anchors=True,
        location_callback=lambda *args:positions.append(args))
    assert ('/catalog','GET') in paths
    position=next(p for p in positions if p[0]=='/catalog' and p[1]=='GET')
    assert script[position[2]:position[3]]=='this.endpoint'


def test_direct_get_base_does_not_cross_class_owners_or_dynamic_mutation():
    script='class A{root="/catalog";all(){return c.get(this.root)}}class B{root="/other";all(){return c.get(this.root)}}'
    assert {p for p,m in extract_js_api_paths(script,literal_call_method,include_class_get_anchors=True) if m=='GET'}=={'/catalog','/other'}
    bad='class A{root="/catalog";change(x){this.root=x}all(){return c.get(this.root)}}'
    assert ('/catalog','GET') not in extract_js_api_paths(bad,literal_call_method,include_class_get_anchors=True)
    assert ('/catalog','GET') not in extract_js_api_paths('class A{root="/catalog";all(){return c.post(this.root)}}',literal_call_method,include_class_get_anchors=True)


def test_full_arrow_body_and_far_caller_are_in_target_related_refs(policy):
    script=('const inspect=key=>fetch(`/records/${key}`);'+' '*4500+
            'const load=async()=>{const r=await fetch("/catalog");const p=await r.json();'+
            ' '*4500+'p.results.items.forEach(row=>inspect(row.slug));};')
    bundle=build_pattern_evidence('https://example.test/',{'https://example.test/app.js':script},
                                  [response()],target_policy=policy)
    target=next(x for x in bundle.context['literals'] if x['path']=='/records/${key}')
    snippets={x['ref']:x for x in bundle.context['snippets']}
    text='\n'.join(snippets[ref]['text'] for ref in target['related_refs'])
    assert 'p.results.items.forEach(row=>inspect(row.slug))' in text
    assert 'await fetch("/catalog")' in text
    assert all(snippets[ref]['script_url']=='https://example.test/app.js' for ref in target['related_refs'])


def test_cross_script_caller_and_html_event_wiring_keep_original_js(policy):
    scripts={'https://example.test/detail.js':'function inspect(key){return fetch(`/records/${key}`)}',
             'https://example.test/list.js':'async function load(){const r=await fetch("/catalog");const p=await r.json();document.getElementById("choices").innerHTML=p.results.items.map(row=>`<option value="${row.slug}">${row.label}</option>`).join("");}'}
    html='<select id="choices" onchange="inspect(this.value)"></select><script>load();</script>'
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html)
    bundle=build_pattern_evidence('https://example.test/',scripts,[response(),doc],target_policy=policy)
    target=next(x for x in bundle.context['literals'] if x['path']=='/records/${key}')
    snippets={x['ref']:x for x in bundle.context['snippets']}
    related=[snippets[ref] for ref in target['related_refs']]
    assert any(s.get('event')=='onchange' and s.get('dom_id')=='choices'
               and s['text']=='inspect(this.value)' for s in related)
    assert any('row.slug' in s['text'] for s in related)
    assert '<select' not in '\n'.join(s['text'] for s in bundle.context['snippets'])


def test_inline_get_is_code_evidence_but_json_and_comment_scripts_are_not(policy):
    html='<script type="application/json">{"url":"/unused"}</script><script>fetch("/catalog");fetch(`/records/${row.slug}`);/* fetch("/ghost") */</script>'
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html)
    bundle=build_pattern_evidence('https://example.test/',{},[response(),doc],target_policy=policy)
    paths={x['path'] for x in bundle.context['literals']}
    assert paths=={'/catalog','/records/${row.slug}'}
    assert all(x['script_url'].startswith('https://example.test/page#') for x in bundle.context['literals'])


def test_connected_context_stays_bounded_and_excludes_ineligible_documents(policy):
    scripts={'https://example.test/app.js':'function inspect(key){fetch(`/records/${key}`)}'+
             ''.join(f'function load{i}(){{inspect(row.slug);'+(' '*15000)+'}' for i in range(15))}
    html='<script>fetch("/should-not-enter")</script>'
    docs=[response(url='https://outside.test/',response_headers={'Content-Type':'text/html'},response_body=html),
          response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html,candidate_probe=True)]
    bundle=build_pattern_evidence('https://example.test/',scripts,[response(),*docs],target_policy=policy)
    assert sum(len(s['text']) for s in bundle.context['snippets'])<=100_000
    assert '/should-not-enter' not in json.dumps(bundle.context)


@pytest.mark.parametrize('change',["this['root']=x",'this.root ||= x','this.root ??= x'])
def test_direct_get_does_not_trust_mutated_base_syntax(change):
    script='class Store{root="/catalog";change(x){'+change+'}all(){return c.get(this.root)}}'
    assert ('/catalog','GET') not in extract_js_api_paths(script,literal_call_method,include_class_get_anchors=True)


def test_ambiguous_names_do_not_link_unrelated_scripts(policy):
    scripts={'https://example.test/one.js':'function inspect(x){fetch(`/records/${x}`)}',
             'https://example.test/two.js':'function inspect(x){return x}',
             'https://example.test/caller.js':'function other(){inspect(unrelated.code)}'}
    bundle=build_pattern_evidence('https://example.test/',scripts,[response()],target_policy=policy)
    target=next(x for x in bundle.context['literals'] if x['path']=='/records/${x}')
    snippets={s['ref']:s for s in bundle.context['snippets']}
    assert all(snippets[r]['script_url']!='https://example.test/caller.js' for r in target['related_refs'])


def test_inline_only_document_reaches_ai_verifier(policy,monkeypatch):
    from aidast.recon.tools import api_secondary_discovery as secondary
    from aidast.recon.tools.ai_patterns import PatternPlan
    html='<script>fetch("/catalog");fetch("/records");</script>'
    doc=response(url='https://example.test/',response_headers={'Content-Type':'text/html'},response_body=html)
    class Planner:
        def propose(self,ctx):
            target=next(x for x in ctx['literals'] if x['path']=='/records')
            return PatternPlan(literal_gets=[dict(target_ref=target['ref'])])
    def request(url,**kwargs):
        if '__aidast_missing_control__' in url:
            return 404,{'content-type':'application/json'},b'{"error":"missing"}'
        assert url=='https://example.test/records'
        return 200,{'content-type':'application/json'},b'{"records":[]}'
    monkeypatch.setattr(secondary,'_http_request',request)
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [dict(method='GET',path='/')],target_policy=policy,proxy_url='http://127.0.0.1:8080',
        observed_responses=[doc],ai_pattern_planner=Planner())
    assert any(r.get('source')=='ai_pattern' and r.get('verification_status')=='verified' for r in rows)


@pytest.mark.parametrize('method',[
    'static all(){return c.get(this.root)}',
    'all(){function work(){return c.get(this.root)}return work.call({root:"/other"})}',
    'all(){function* work(){return c.get(this.root)}return work.call({root:"/other"}).next()}',
])
def test_direct_get_requires_instance_receiver(method):
    script='class Store{root="/catalog";'+method+'}'
    assert ('/catalog','GET') not in extract_js_api_paths(script,literal_call_method,include_class_get_anchors=True)


@pytest.mark.parametrize('change',['delete this.root','this.root **= x','this.root >>= x', 'this.$root=x',
                                   '++this.root','[this.root]=[x]'])
def test_other_mutations_are_not_source_anchors(change):
    name='$root' if '$root' in change else 'root'
    script='class Store{'+name+'="/catalog";change(x){'+change+'}all(){return c.get(this.'+name+')}}'
    assert ('/catalog','GET') not in extract_js_api_paths(script,literal_call_method,include_class_get_anchors=True)


@pytest.mark.parametrize('declaration',[
    'function $inspect(key){fetch(`/records/${key}`)}',
    'const $inspect=key=>fetch(`/records/${key}`);',
])
def test_dollar_names_preserve_distant_caller_relationship(policy,declaration):
    script=declaration+' '*4500+'function load(){fetch("/catalog");$inspect(row.slug)}'
    bundle=build_pattern_evidence('https://example.test/',{'https://example.test/app.js':script},[response()],target_policy=policy)
    target=next(x for x in bundle.context['literals'] if x['path']=='/records/${key}')
    snippets={s['ref']:s for s in bundle.context['snippets']}
    assert any('$inspect(row.slug)' in snippets[ref]['text'] for ref in target['related_refs'])


def test_dom_metadata_does_not_bypass_context_bounds(policy):
    html='<select id="'+('x'*150_000)+'" onchange="inspect(this.value)"></select>'
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html)
    scripts={'https://example.test/app.js':'function inspect(key){fetch(`/records/${key}`)}'}
    bundle=build_pattern_evidence('https://example.test/',scripts,[response(),doc],target_policy=policy)
    assert len(json.dumps(bundle.context))<160_000
    assert all(len(s.get('dom_id',''))<=256 for s in bundle.context['snippets'])


@pytest.mark.parametrize('padding',['','x'*5000])
def test_inline_bootstrap_json_values_stay_local(policy,padding):
    bootstrap=json.dumps({'padding':padding,'email':'private-person@example.test','account_number':987654321})
    html='<script>const bootstrap='+bootstrap+';fetch("/catalog");</script>'
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html)
    bundle=build_pattern_evidence('https://example.test/',{},[response(),doc],target_policy=policy)
    rendered=json.dumps(bundle.context)
    assert 'private-person@example.test' not in rendered and '987654321' not in rendered
    assert '/catalog' in rendered
    if not padding:
        assert 'account_number' in rendered


@pytest.mark.parametrize('declaration',[
    'const people=["private-person@example.test"]',
    'const people=[987654321,"private-person@example.test"]',
    'const people=[true,"private-person@example.test"]',
    'const people=[null,"private-person@example.test"]',
    'function people(){return ["private-person@example.test"]}',
])
def test_inline_bootstrap_array_values_are_not_model_input(policy,declaration):
    html='<script>'+declaration+';fetch("/catalog");</script>'
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body=html)
    bundle=build_pattern_evidence('https://example.test/',{},[response(),doc],target_policy=policy)
    assert 'private-person@example.test' not in json.dumps(bundle.context)


def test_sanitized_text_expansion_keeps_retained_snippets_under_budget(policy):
    script=''.join(f'fetch("/records/{i:03}");'+('window.x={"a":1};'*50) for i in range(80))
    doc=response(url='https://example.test/page',response_headers={'Content-Type':'text/html'},response_body='<script>'+script+'</script>')
    bundle=build_pattern_evidence('https://example.test/',{},[response(),doc],target_policy=policy)
    assert sum(len(s['text']) for s in bundle.context['snippets'])<=100_000


def test_model_source_anchors_do_not_change_default_collector_paths():
    script='class Store{endpoint="/catalog";all(){return c.get(this.endpoint)}one(x){return c.get(`${this.endpoint}/${x}`)}}'
    paths=extract_js_api_paths(script,literal_call_method)
    assert ('/catalog','GET') not in paths
    assert ('/catalog/${x}','GET') in paths
