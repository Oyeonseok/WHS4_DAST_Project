import pytest
from aidast.recon.tools.js_api_paths import extract_js_api_paths, literal_call_method, _literals
from aidast.recon.tools.js_argument_bindings import bind_response_values


SCRIPT='''
async function load(){
 const response=await fetch('/groups');
 const data=await response.json();
 const select=document.getElementById('group');
 select.innerHTML=`${data.groups.map(row=>`<option value="${row.code}">${row.title}</option>`).join('')}`;
}
async function details(key){const response=await fetch(`/reports/${key}/entries`,{headers:{Authorization:token}});}
'''
HTML='<select id="group" onchange="details(this.value)"></select>'


def bindings(script=SCRIPT, html=HTML):
    from aidast.recon.tools.js_fetch_bindings import extract_fetch_response_bindings
    return extract_fetch_response_bindings({'app.js':script}, documents=[html])


def test_nested_render_templates_do_not_hide_later_get_calls():
    assert ('/reports/${key}/entries','GET') in extract_js_api_paths(SCRIPT,literal_call_method)
    render=next(lit for lit in _literals(SCRIPT) if lit.value and lit.value.startswith('${data.groups.map'))
    assert ".join('')" in render.value


def test_template_expression_regex_braces_do_not_end_a_string():
    script='const html=`${/`}/.test(value) ? `yes` : `no`} fetch("/api/decoy")`;fetch("/api/actual");'
    assert extract_js_api_paths(script,literal_call_method)==[('/api/actual','GET')]


def test_option_values_bind_only_through_explicit_select_handler():
    rows=bindings()
    assert len(rows)==1
    b=rows[0]
    assert b.source_path=='/groups' and b.field=='code' and b.collection_path==('groups',)
    assert bind_response_values(b,'/groups',{'groups':[{'code':'alpha/beta'}]})==['/reports/alpha%2Fbeta/entries']


def test_callback_after_target_get_does_not_invalidate_its_parameter():
    script=SCRIPT.replace('headers:{Authorization:token}});}',
        'headers:{Authorization:token}});const data=await response.json();data.entries.map(row=>row.title);}')
    assert len(bindings(script))==1


@pytest.mark.parametrize('script,html',[
    (SCRIPT,HTML.replace('group','other')),
    (SCRIPT,HTML.replace('this.value','unknown')),
    (SCRIPT.replace("fetch(`/reports/${key}/entries`,{headers:{Authorization:token}})","fetch(`/reports/${key}/entries`,{method:'POST'})"),HTML),
    (SCRIPT.replace('const data=await response.json();','const data=await other.json();'),HTML),
    (SCRIPT.replace('const data=await response.json();','const data=await response.json();data=unknown;'),HTML),
    (SCRIPT.replace('async function details(key){','async function details(key){key=unknown;'),HTML),
    ('/*'+SCRIPT+'*/',HTML),
])
def test_missing_provenance_or_write_operations_are_not_bindings(script,html):
    assert bindings(script,html)==[]


@pytest.mark.parametrize('script',[
    "async function load(fetch){const r=await fetch('/catalog');const payload=await r.json();payload.entries.forEach(row=>{fetch(`/reader/${row.slug}/info`);});}",
    "async function load(){const r=await fetch('/catalog');const payload=await r.json();payload.entries.forEach(row=>{function inner(row){fetch(`/reader/${row.slug}/info`);}});}",
    "async function load(){const r=await fetch('/catalog');const payload=await r.json();payload.entries.forEach(row=>{row['slug']='changed';fetch(`/reader/${row.slug}/info`);});}",
    SCRIPT.replace('async function details(key){','async function details(key){function inner(key){').replace('headers:{Authorization:token}});}', 'headers:{Authorization:token}});}}'),
    SCRIPT.replace("const select=document.getElementById('group');","/* const select=document.getElementById('group'); */"),
    SCRIPT+'details=unknown;',
    SCRIPT.replace('async function details(key){','async function details(key){const inner=(key)=>'),
    SCRIPT.replace('async function load(){','async function load(){const document=unknown;'),
    'window.fetch=unknown;'+SCRIPT,
    'const {fetch}=unknown;'+SCRIPT,
    "import {fetch} from './fake.js';"+SCRIPT,
    "async function load(){const r=await fetch('/catalog');const payload=await r.json();payload.entries.forEach(row=>{{let row;fetch(`/reader/${row.slug}/info`);}});}",
])
def test_shadowed_values_computed_writes_and_commented_dom_are_not_provenance(script):
    assert bindings(script)==[]


def test_documents_are_consumed_only_within_the_reader_limit():
    from aidast.recon.tools.js_fetch_bindings import extract_fetch_response_bindings
    def documents():
        for _ in range(50):
            yield ''
        raise AssertionError('Document limit exceeded')
    assert extract_fetch_response_bindings({},documents=documents())==[]


@pytest.mark.parametrize('patch',['details=unknown;','fetch=unknown;','window.details=unknown;'])
def test_other_loaded_script_can_invalidate_function_identity(patch):
    from aidast.recon.tools.js_fetch_bindings import extract_fetch_response_bindings
    assert extract_fetch_response_bindings({'app.js':SCRIPT,'patch.js':patch},documents=[HTML])==[]


def test_direct_array_callback_supports_nested_payload_and_non_id_field():
    script='''async function load(){const r=await fetch('/catalog');const payload=await r.json();
    payload.result.entries.forEach(row=>{fetch(`/reader/${row.slug}/info`);});}'''
    rows=bindings(script,'')
    assert len(rows)==1 and rows[0].collection_path==('result','entries')
    assert bind_response_values(rows[0],'/catalog',{'result':{'entries':[{'slug':'daily'}]}})==['/reader/daily/info']


def test_native_binding_reaches_actual_response_verified_discovery(monkeypatch):
    from aidast.recon.tools import api_secondary_discovery as secondary
    import json
    requested=[]
    def request(url,**kwargs):
        requested.append(url)
        if url.endswith('/assets/app.js'):
            return 200,{'content-type':'application/javascript'},SCRIPT.encode()
        if url.endswith('/groups'):
            return 200,{'content-type':'application/json'},json.dumps({'groups':[{'code':'daily'}]}).encode()
        if url.endswith('/reports/daily/entries'):
            return 200,{'content-type':'application/json'},b'{"entries":[]}'
        return 404,{'content-type':'application/json'},b'{"error":"missing"}'
    monkeypatch.setattr(secondary,'_http_request',request)
    records=[dict(method='GET',url='https://example.test/workspace',response_status=200,
        response_headers={'content-type':'text/html'},capture_bodies=True,
        response_body=HTML+'<script src="/assets/app.js"></script>')]
    rows=secondary.discover_adaptive_js_api_candidates('https://example.test/',[{'path':'/workspace'}],observed_responses=records)
    assert any(r['path']=='/reports/daily/entries' and r['evidence']['response_status']==200 for r in rows)
    assert requested.count('https://example.test/reports/daily/entries')==1
