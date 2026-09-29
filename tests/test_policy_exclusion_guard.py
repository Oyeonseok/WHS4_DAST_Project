"""Behavioral contracts for the offline exclusion boundary (no target I/O)."""
import hashlib
import importlib.util
import json
from pathlib import Path
import runpy

import pytest


GUARD = Path(__file__).parents[1] / 'src/aidast/core/exclusion_guard.py'


def api():
    assert GUARD.exists(), 'shared exclusion evaluator has not been implemented'
    return runpy.run_path(str(GUARD))


def predicate(field='path', value='/support', key='p', operator='equals', name=None):
    return dict(operator='predicate', predicate=dict(key=key, field=field,
        operator=operator, name=name, value=value), children=[])


def rule(condition=None, key='restricted', targets=None):
    return dict(key=key, label='문의 제외', source_quote='Do not access /support or POST operation feedback /operation example.test.',
        target_assets=targets or [], condition=condition or predicate())


def policy(*rules, bindings=None):
    rows = list(rules or [rule()])
    return dict(schema_version='1', scope_digest='1'*64,
        rule_digest=hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        evidence_digest='2'*64, target_asset='https://example.test/',
        rules=rows, semantic_bindings=bindings or [], expires_at=4102444800.0)


def evaluate(data, url='https://example.test/support', **kwargs):
    return api()['evaluate_exclusions'](data, url=url, **kwargs)


def test_missing_guard_legacy_and_present_invalid_hold():
    assert evaluate(None)['decision'] == 'continue'
    for invalid in ({}, [], False, {'schema_version': '2'}):
        assert evaluate(invalid)['decision'] == 'hold'


def test_direct_path_exclusion_and_segment_prefix():
    p = policy(rule(predicate(operator='prefix')))
    assert evaluate(p)['decision'] == 'deny'
    assert evaluate(p, 'https://example.test/support/new')['decision'] == 'deny'
    assert evaluate(p, 'https://example.test/supporting')['decision'] == 'continue'


@pytest.mark.parametrize('operator,other,expected', [
    ('all', True, 'hold'), ('all', False, 'continue'),
    ('any', True, 'deny'), ('any', False, 'hold'),
])
def test_tristate_truth_tables(operator, other, expected):
    expr = dict(operator=operator, predicate=None, children=[
        predicate('semantic', 'arbitrary localized category', key='category'),
        predicate('method', 'POST', key='method')])
    assert evaluate(policy(rule(expr)), method='POST' if other else 'GET')['decision'] == expected


def test_not_unknown_and_true_rule_dominates_unknown():
    unknown = rule(dict(operator='not', predicate=None, children=[predicate('unsupported', 'ownership cannot be established')]), key='unknown')
    assert evaluate(policy(unknown))['decision'] == 'hold'
    result = evaluate(policy(unknown, rule()))
    assert result['decision'] == 'deny'
    assert result['rule_keys'] == ['restricted']


@pytest.mark.parametrize('suffix', ['/supp%6frt', '/support'])
def test_unambiguous_percent_encoding_is_compared_canonically(suffix):
    assert evaluate(policy(), 'https://example.test'+suffix)['decision'] == 'deny'


@pytest.mark.parametrize('suffix', ['/a/../support', '/%2e%2e/support', '/a%2fsupport', '/a%5csupport',
    '/%252fsupport', '/support%', '//support', '/support;v=1', '/support#fragment'])
def test_ambiguous_url_never_bypasses(suffix):
    assert evaluate(policy(), 'https://example.test'+suffix)['decision'] == 'hold'


@pytest.mark.parametrize('query,expected', [('operation=feedback','deny'), ('operation=other','continue'),
    ('operation=feedback&operation=other','hold'), ('operation=%FF','hold'), ('operation=%','hold')])
def test_query_exact_values_and_duplicate_ambiguity(query, expected):
    p = policy(rule(predicate('query', 'feedback', name='operation')))
    assert evaluate(p, 'https://example.test/api?'+query)['decision'] == expected


@pytest.mark.parametrize('field,body,headers,expected', [
    ('json_body', b'{"operation":"feedback"}', {'Content-Type':'application/json'}, 'deny'),
    ('json_body', b'{"operation":"other"}', {'Content-Type':'application/json'}, 'continue'),
    ('json_body', b'{"operation":"other","operation":"feedback"}', {'Content-Type':'application/json'}, 'hold'),
    ('json_body', b'{', {'Content-Type':'application/json'}, 'hold'),
    ('json_body', b'{"operation":"feedback"}', {}, 'hold'),
    ('form_body', b'operation=feedback', {'Content-Type':'application/x-www-form-urlencoded'}, 'deny'),
    ('form_body', b'operation=x&operation=feedback', {'Content-Type':'application/x-www-form-urlencoded'}, 'hold'),
])
def test_body_parsers_require_available_unambiguous_supported_content(field, body, headers, expected):
    p = policy(rule(predicate(field, 'feedback', name='/operation' if field=='json_body' else 'operation')))
    assert evaluate(p, body=body, headers=headers, body_available=True)['decision'] == expected
    assert evaluate(p, body=body, headers=headers)['decision'] == 'hold'


def test_absent_empty_body_and_unrelated_predicates():
    p = policy(rule(predicate('json_body', None, name='/operation', operator='present')))
    assert evaluate(p, body=b'', body_available=True)['decision'] == 'continue'
    assert evaluate(policy(), body=None, body_available=False)['decision'] == 'deny'


def test_json_nested_pointer_and_scalar_text_comparison():
    r = rule(predicate('json_body', 'feedback', name='/items/0/a~1b'))
    r['source_quote'] += ' /items/0/a~1b'
    assert evaluate(policy(r), headers={'content-type':'application/json'},
        body=b'{"items":[{"a/b":"feedback"}]}', body_available=True)['decision'] == 'deny'
    r = rule(predicate('json_body', 'false', name=''))
    r['source_quote'] += ' false'
    assert evaluate(policy(r), headers={'content-type':'application/json'}, body=b'false', body_available=True)['decision'] == 'deny'
    assert evaluate(policy(r), headers={'content-type':'application/json'}, body=b'"false"', body_available=True)['decision'] == 'deny'


def test_semantic_binding_uses_complete_request_identity_and_available_body():
    guard = api()
    r = rule(predicate('semantic', '고객 의견 제출'))
    request = dict(url='https://example.test/api?a=1', method='POST', headers={'Authorization':'token1'}, body=b'{}')
    binding = dict(request_key=guard['request_key'](**request), rule_key=r['key'], predicate_key='p',
        classification='nonmatch', evidence_ids=['capture_1'])
    p = policy(r, bindings=[binding])
    assert guard['evaluate_exclusions'](p, **request, body_available=True)['decision'] == 'continue'
    assert guard['evaluate_exclusions'](p, **request)['decision'] == 'hold'
    for change in (dict(url='https://example.test/api?a=2'), dict(method='GET'),
                   dict(headers={'Authorization':'token2'}), dict(body=b'{ }'),
                   dict(context={'transport_kind':'websocket', 'operation_kind':'frame'})):
        assert guard['evaluate_exclusions'](p, **(request | change), body_available=True)['decision'] == 'hold'
    binding['classification'] = 'match'
    assert guard['evaluate_exclusions'](policy(r, bindings=[binding]), **request, body_available=True)['decision'] == 'deny'


def test_request_fingerprint_header_order_case_and_context():
    key = api()['request_key']
    first = key('HTTPS://EXAMPLE.TEST:443/a?x=1', 'get', {'X-A':'v','X-B':'b'}, b'')
    assert first == key('https://example.test/a?x=1', 'GET', {'x-b':'b','x-a':'v'}, None)
    assert first != key('https://example.test/a?x=1', 'GET', {'x-b':'b','x-a':'v'}, None, context={'operation_kind':'frame'})
    assert len(first) == 64
    with pytest.raises(ValueError):
        key('https://example.test/a', 'GET', {'X-A':'one', 'x-a':'two'})
    for url in ('https://user:secret@example.test/', 'https://example.test/#', 'https://example.test/\n'):
        with pytest.raises(ValueError):
            key(url, 'GET')


def test_semantic_bindings_expire_and_missing_expiry_cannot_authorize():
    guard = api()
    r = rule(predicate('semantic', 'an arbitrary category'))
    binding = dict(request_key=guard['request_key']('https://example.test/support', 'GET'),
        rule_key='restricted', predicate_key='p', classification='nonmatch', evidence_ids=['e'])
    p = policy(r, bindings=[binding])
    p['expires_at'] = 100.0
    assert evaluate(p, body_available=True, now=99.0)['decision'] == 'continue'
    assert evaluate(p, body_available=True, now=100.0)['decision'] == 'hold'
    del p['expires_at']
    assert evaluate(p, body_available=True, now=99.0)['decision'] == 'hold'


def test_stale_digest_invalid_binding_and_target_membership_hold():
    p = policy()
    p['rules'][0]['condition']['predicate']['value'] = '/changed'
    assert evaluate(p)['decision'] == 'hold'
    p = policy(bindings=[dict(request_key='a'*64, rule_key='missing', predicate_key='p', classification='match', evidence_ids=['e'])])
    assert evaluate(p)['decision'] == 'hold'
    p = policy(rule(targets=['https://elsewhere.test/']))
    assert evaluate(p)['decision'] == 'continue'


def test_grammar_bounds_arity_unique_ids_and_no_executable_operators():
    validate = api()['validate_exclusion_policy']
    for expr in (dict(operator='not', children=[], predicate=None),
                 dict(operator='all', children=[predicate(), predicate()], predicate=None),
                 predicate(operator='regex'), predicate('query', 'x', operator='prefix', name='x')):
        with pytest.raises(ValueError):
            validate(policy(rule(expr)))
    expr = predicate()
    for _ in range(8):
        expr = dict(operator='not', predicate=None, children=[expr])
    with pytest.raises(ValueError):
        validate(policy(rule(expr)))


def test_scope_models_ground_direct_literals_and_allow_legacy():
    from aidast.scope.models import ScopeExecutionRules
    assert 'exclusions' in ScopeExecutionRules.model_fields, 'Scope execution exclusions are missing'
    from aidast.scope.exclusions import ScopeExclusion
    assert ScopeExecutionRules().exclusions is None
    assert ScopeExecutionRules(exclusions=[]).exclusions == []
    item = ScopeExclusion.model_validate(rule())
    assert ScopeExecutionRules(exclusions=[item]).quoted_requirements() == [item]
    with pytest.raises(ValueError):
        ScopeExecutionRules(exclusions=[item, item])
    changed = rule(predicate(value='/invented'))
    with pytest.raises(ValueError, match='ground'):
        ScopeExclusion.model_validate(changed)


def test_compiled_model_roundtrip_matches_runpy_and_target_policy_legacy_serialization():
    from aidast.recon.policy import TargetPolicy
    assert 'request_exclusions' in TargetPolicy.model_fields, 'TargetPolicy exclusion integration is missing'
    from aidast.scope.exclusions import CompiledExclusionPolicy
    snapshot = CompiledExclusionPolicy.model_validate(policy())
    target = TargetPolicy(scope_id='s', policy_id='p', asset_type='URL', asset='https://example.test/', allowed_hosts=['example.test'])
    assert 'request_exclusions' not in target.model_dump()
    assert 'request_exclusions' not in target.mitm_rules()
    target.request_exclusions = snapshot
    assert target.allows_url('https://example.test/support')
    assert target.check_request_exclusions('https://example.test/support', method='GET')['decision'] == 'deny'
    saved = target.mitm_rules()['request_exclusions']
    assert saved == snapshot.model_dump(mode='json')
    assert evaluate(saved)['decision'] == 'deny'


def test_resource_models_reject_unsubstantiated_classifications_and_invalid_identity():
    assert importlib.util.find_spec('aidast.scope.exclusions'), 'exclusion model contracts are missing'
    from aidast.scope.exclusions import ResourceCandidate, ResourceClassification
    with pytest.raises(ValueError):
        ResourceCandidate(candidate_id='c', request_key='wrong', url='https://example.test/', method='GET',
            public_headers={}, body_sha256='a'*64, body_preview=None, evidence_ids=[])
    with pytest.raises(ValueError):
        ResourceClassification(decisions=[dict(candidate_id='c', rule_key='r', predicate_key='p',
            classification='nonmatch', reason='keyword absent', citations=[])])


def test_runpy_has_no_package_dependency(tmp_path):
    import subprocess
    import sys
    assert GUARD.exists(), 'stdlib gate is missing'
    isolated = tmp_path / 'gate.py'
    isolated.write_bytes(GUARD.read_bytes())
    code = 'import runpy; g=runpy.run_path(' + repr(str(isolated)) + '); assert g["evaluate_exclusions"](None, url="https://example.test/")["decision"]=="continue"'
    completed = subprocess.run([sys.executable, '-I', '-S', '-c', code], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize('headers,body', [
    ({'content-type':'application/json; charset=iso-8859-1'}, b'{"operation":"other"}'),
    ({'content-type':'application/x-www-form-urlencoded; charset=iso-8859-1'}, b'operation=other'),
    ({'content-type':'application/json', 'content-encoding':'gzip'}, b'{"operation":"other"}'),
])
def test_unsupported_body_decoding_cannot_be_treated_as_nonmatch(headers, body):
    field = 'json_body' if 'application/json' in headers['content-type'] else 'form_body'
    p = policy(rule(predicate(field, 'feedback', name='/operation' if field=='json_body' else 'operation')))
    assert evaluate(p, headers=headers, body=body, body_available=True)['decision'] == 'hold'


@pytest.mark.parametrize('field,body,content_type', [
    ('json_body', b'{"operation":"feedback"}', 'application/json; charset=UTF-8'),
    ('form_body', b'operation=feedback', 'application/x-www-form-urlencoded; charset="utf-8"'),
])
def test_supported_utf8_content_type_preserves_predicate_parameter(field, body, content_type):
    p = policy(rule(predicate(field, 'feedback', name='/operation' if field=='json_body' else 'operation')))
    assert evaluate(p, headers={'content-type':content_type}, body=body, body_available=True)['decision'] == 'deny'


def test_alternate_query_separator_is_unknown():
    p = policy(rule(predicate('query', 'feedback', name='operation')))
    assert evaluate(p, 'https://example.test/api?x=1;operation=feedback')['decision'] == 'hold'


def test_invalid_request_availability_flag_holds():
    assert evaluate(policy(), body_available='false')['decision'] == 'hold'


def test_zero_port_is_not_normalized_to_default_port():
    with pytest.raises(ValueError):
        api()['request_key']('https://example.test:0/support', 'GET')


def test_target_policy_cannot_attach_another_targets_guard():
    from aidast.recon.policy import TargetPolicy
    from aidast.scope.exclusions import CompiledExclusionPolicy
    snapshot = CompiledExclusionPolicy.model_validate(policy())
    kwargs = dict(scope_id='s', policy_id='p', asset_type='URL', asset='https://other.test/', allowed_hosts=['other.test'])
    with pytest.raises(ValueError, match='target'):
        TargetPolicy(**kwargs, request_exclusions=snapshot)
    # model_copy bypasses Pydantic validation; admission must still hold.
    target = TargetPolicy(**kwargs).model_copy(update={'request_exclusions': snapshot})
    assert target.check_request_exclusions('https://other.test/api', method='GET')['decision'] == 'hold'


def test_scope_analysis_exclusion_quote_and_target_must_be_approved():
    from aidast.scope.models import ScopeAnalysis
    from test_scope_execution_rules import document
    data = document().analysis.model_dump()
    data['execution_rules'] = {'exclusions': [rule()]}
    with pytest.raises(ValueError, match='ground'):
        ScopeAnalysis.model_validate(data)
    data['source_evidence'].append({'section':'Exclusions', 'quote':rule()['source_quote']})
    data['execution_rules']['exclusions'][0]['target_assets'] = ['https://unapproved.test/']
    with pytest.raises(ValueError, match='exact approved asset'):
        ScopeAnalysis.model_validate(data)


def test_policy_and_expression_bounds_and_duplicate_bindings_are_validated():
    guard = api()
    child = predicate('semantic', 'category', key='category')
    r = rule(child)
    binding = dict(request_key='a'*64, rule_key='restricted', predicate_key='category', classification='unknown', evidence_ids=[])
    assert evaluate(policy(r, bindings=[binding, binding]))['decision'] == 'hold'
    oversized = dict(operator='any', predicate=None, children=[predicate('semantic', 'category', key='p'+str(i)) for i in range(128)])
    with pytest.raises(ValueError):
        guard['validate_exclusion_expression'](oversized)
    rules = [rule(key='r'+str(i)) for i in range(129)]
    with pytest.raises(ValueError):
        guard['rule_digest'](rules)


def test_models_reject_duplicate_decisions_and_nonfinite_expiry():
    from aidast.scope.exclusions import CompiledExclusionPolicy, ResourceClassification, ResourceEvidence
    decision = dict(candidate_id='c', rule_key='r', predicate_key='p', classification='unknown', reason='not enough evidence', citations=[])
    with pytest.raises(ValueError):
        ResourceClassification(decisions=[decision, decision])
    for expiry in (float('nan'), float('inf'), True):
        with pytest.raises(ValueError):
            CompiledExclusionPolicy.model_validate(policy() | {'expires_at':expiry})
    with pytest.raises(ValueError):
        ResourceEvidence(evidence_id='e', candidate_ids=['c','c'], source_url='https://example.test/',
            kind='html', content_sha256='a'*64, excerpt='captured content')


@pytest.mark.parametrize('captured_at', [1750000000.125, 1750000000])
def test_resource_evidence_capture_time_survives_json_roundtrip(captured_at):
    from aidast.scope.exclusions import ResourceEvidence
    assert 'captured_at' in ResourceEvidence.model_fields, 'evidence capture time is missing'
    evidence = ResourceEvidence(evidence_id='e', candidate_ids=['c'], source_url='https://example.test/',
        kind='html', content_sha256='a'*64, excerpt='captured content', captured_at=captured_at)
    restored = ResourceEvidence.model_validate_json(evidence.model_dump_json())
    assert restored.captured_at == captured_at
    assert restored.model_dump(mode='json')['captured_at'] == captured_at


def test_resource_evidence_without_capture_time_retains_explicit_unknown():
    from aidast.scope.exclusions import ResourceEvidence
    assert 'captured_at' in ResourceEvidence.model_fields, 'evidence capture time is missing'
    evidence = ResourceEvidence(evidence_id='e', candidate_ids=['c'], source_url='https://example.test/',
        kind='html', content_sha256='a'*64, excerpt='captured content')
    assert evidence.captured_at is None
    assert ResourceEvidence.model_validate_json(evidence.model_dump_json()).captured_at is None


@pytest.mark.parametrize('captured_at,error_type', [
    (True, 'float_type'), (False, 'float_type'), ('1750000000', 'float_type'),
    (float('nan'), 'finite_number'), (float('inf'), 'finite_number'),
    (-float('inf'), 'finite_number'), (0, 'greater_than'), (-1.0, 'greater_than'),
])
def test_resource_evidence_rejects_invalid_capture_time(captured_at, error_type):
    from pydantic import ValidationError
    from aidast.scope.exclusions import ResourceEvidence
    with pytest.raises(ValidationError) as error:
        ResourceEvidence(evidence_id='e', candidate_ids=['c'], source_url='https://example.test/',
            kind='html', content_sha256='a'*64, excerpt='captured content', captured_at=captured_at)
    assert [(item['loc'], item['type']) for item in error.value.errors()] == [(('captured_at',), error_type)]
