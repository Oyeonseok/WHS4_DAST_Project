"""Final review regressions: fake wire only, no target or model calls."""
import json
from types import SimpleNamespace

import pytest

from aidast.core.capture_receipt import prepare_http_request, make_capture_receipt
from aidast.core.exclusion_guard import evaluate_exclusions, request_key, rule_digest
from aidast.core.http_safety import has_request_exclusions, require_request_admission
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.scope.exclusion_binding import ExclusionBindingResolver
from aidast.scope.exclusions import CompiledExclusionPolicy
from test_policy_exclusion_guard import policy as compiled, rule, predicate
from test_policy_exclusion_transports import Wire, target, proxy_fixture, validation_fixture


def snapshot(kind):
    if kind == 'legacy':
        return None
    value = compiled()
    if kind == 'empty':
        value.update(rules=[], rule_digest=rule_digest([]))
    return value


@pytest.mark.parametrize('form', ['upgrade', 'connection', 'connect', 'extended_header', 'extended_attribute'])
@pytest.mark.parametrize('kind', ['applicable', 'malformed', 'legacy', 'empty', 'disjoint'])
def test_proxy_upgrade_entire_exchange_precedes_budget_and_receipt(tmp_path, form, kind):
    a, f = proxy_fixture(compiled())
    f.request.url = f.request.pretty_url = 'https://example.com/public'
    value = snapshot(kind)
    if value is not None:
        value['target_asset'] = 'example.com'
    if kind == 'malformed':
        value = {}
    if kind == 'disjoint':
        value = dict(compiled(rule(targets=['https://elsewhere.test/'])), target_asset='example.com')
    a.rules['request_exclusions'] = value
    if form == 'upgrade':
        f.request.headers['Upgrade'] = 'websocket'
    elif form == 'connection':
        f.request.headers['Connection'] = 'keep-alive, UpGrAdE'
    elif form == 'connect':
        f.request.method = 'CONNECT'
        a.rules['allowed_methods'] = ['GET', 'CONNECT']
    elif form == 'extended_header':
        f.request.headers[':protocol'] = 'websocket'
    else:
        f.request.protocol = 'websocket'
    reservations = []
    a.governor = SimpleNamespace(reserve=lambda *args, **kwargs: reservations.append(args) or
        SimpleNamespace(wait=lambda: None, complete=lambda: None))
    a.out_path = tmp_path / 'capture.jsonl'
    a.rules['mitm_capture_bodies'] = True
    a.request(f)
    held = kind in {'applicable', 'malformed'}
    assert bool(f.metadata.get('aidast_forwarded')) is not held
    assert a.request_count == len(reservations) == int(not held)
    if held:
        f.response.get_text = lambda strict=False: 'Blocked'
        f.response.raw_content = b'Blocked'
        a.response(f)
        assert 'request_receipt' not in json.loads(a.out_path.read_text())


@pytest.mark.parametrize('kind', ['legacy', 'empty', 'applicable'])
@pytest.mark.parametrize('suffix', ['/public;version=1', '/a%2Fb'])
def test_core_legacy_wire_urls_keep_baseline_authority(kind, suffix):
    url = 'https://example.test' + suffix
    policy = target(snapshot(kind))
    assert policy.allows_url(url)
    wire = Wire()
    broker = RequestBroker(policy, transport=wire)
    if kind == 'applicable':
        with pytest.raises(RequestPolicyError, match='exclusion'):
            broker.request(url)
    else:
        broker.request(url)
        assert wire.calls[0][0] == url
    assert len(wire.calls) == broker.request_count == int(kind != 'applicable')


@pytest.mark.parametrize('kind', ['legacy', 'empty', 'applicable'])
def test_raw_attack_legacy_url_compatibility_and_real_guard(tmp_path, monkeypatch, kind):
    from test_attack_request_guard import fixture, FakeOpener
    from aidast.attack.request_cli import guarded_request, RequestGuardError
    database, path, payload, stage, task = fixture(tmp_path)
    document = json.loads(path.read_text())
    value = snapshot(kind)
    if value is not None:
        value['target_asset'] = document['policies'][0]['asset']
    document['policies'][0]['request_exclusions'] = value
    path.write_text(json.dumps(document))
    url = 'https://example.test/api/profile;version=1'
    payload.write_text(json.dumps({'url': url}))
    opener = FakeOpener()
    monkeypatch.setattr('aidast.attack.request_cli.build_opener', lambda *a, **k: opener)
    def send():
        return guarded_request(database, scan_id='scan', stage_run_id=stage, task_id=task,
                               policy_path=path, payload_path=payload)
    if kind == 'applicable':
        with pytest.raises(RequestGuardError, match='exclusion'):
            send()
    else:
        send()
        assert opener.calls[0][0].full_url == url
    assert len(opener.calls) == int(kind != 'applicable')


@pytest.mark.parametrize('kind', ['legacy', 'empty', 'applicable'])
def test_validation_legacy_url_compatibility_and_real_guard(validation_fixture, kind):
    from aidast.validation.execution.request_broker import ValidationRequestError
    f = validation_fixture
    value = snapshot(kind)
    if value is not None:
        value['target_asset'] = f.policy.asset
        f.policy = f.policy.model_copy(update={'request_exclusions': CompiledExclusionPolicy.model_validate(value)})
    wire = Wire()
    broker = f.broker()
    broker.transport = wire
    if kind == 'applicable':
        with pytest.raises(ValidationRequestError, match='exclusion'):
            broker.request('https://test/items/7;version=1', method='GET')
    else:
        broker.request('https://test/items/7;version=1', method='GET')
    assert len(wire.calls) == int(kind != 'applicable')


def test_wire_preparation_does_not_weaken_strict_receipt_identity():
    url = 'https://example.test/public;version=1'
    descriptor = prepare_http_request(url, method='POST', body=bytearray(b'abc'))
    assert descriptor['body'] == b'abc'
    assert descriptor['headers']['Content-Length'] == '3'
    with pytest.raises(ValueError):
        request_key(url, 'POST', descriptor['headers'], b'abc')
    with pytest.raises(ValueError):
        make_capture_receipt(url=url, method='POST', headers=descriptor['headers'], body=b'abc',
                             response_body=b'ok', captured_at=1)


@pytest.mark.parametrize('selected,bound', [
    ('*.example.test', 'https://a.example.test/'),
    ('https://*.example.test', 'https://a.example.test/private'),
    ('a.example.test', 'https://a.example.test/'),
    ('https://a.example.test/', '*.example.test'),
    ('https://a.example.test/private', 'https://a.example.test/'),
    ('*.example.test', '*.a.example.test'),
    ('api-*.example.test', 'https://api-one.example.test/'),
    ('https://a.example.test/public', 'http://a.example.test:8080/private'),
    ('https://a.example.test/', '10.0.0.0/8'),
    ('https://a.example.test/', 'uninterpretable asset'),
    ('https://127.0.0.1/', '127.1'),
])
def test_overlapping_alias_cannot_disarm_serialized_policy(selected, bound):
    value = dict(compiled(rule(predicate('method', 'POST'), targets=[bound])), target_asset=selected)
    serialized = CompiledExclusionPolicy.model_validate(value).model_dump(mode='json')
    policy = {'asset': selected, 'request_exclusions': serialized}
    assert has_request_exclusions(policy)
    decision = evaluate_exclusions(serialized, url='https://a.example.test/public', method='GET')
    assert decision['decision'] == 'hold'
    assert decision['rule_keys'] == ['restricted']
    assert 'overlap' in decision['reason']
    with pytest.raises(ValueError, match='exclusion hold'):
        require_request_admission(policy, url='https://a.example.test/public', method='POST')
    assert serialized['rules'] == value['rules']


@pytest.mark.parametrize('selected,bound', [
    ('*.example.test', 'https://different.test/'),
    ('a.example.test', 'https://b.example.test/'),
    ('https://a.example.test/', '*.different.test'),
])
def test_proven_disjoint_alias_keeps_unrelated_rules_inert(selected, bound):
    value = dict(compiled(rule(targets=[bound])), target_asset=selected)
    assert not has_request_exclusions({'request_exclusions': value})
    assert evaluate_exclusions(value, url='https://a.example.test/support')['decision'] == 'continue'


@pytest.mark.parametrize('asset_type,selected,bound', [
    ('WILDCARD', '*.example.com', 'https://a.example.com/'),
    ('DOMAIN', 'a.example.com', 'https://a.example.com/'),
    ('URL', 'https://a.example.com/', '*.example.com'),
])
@pytest.mark.parametrize('cache_only', [False, True])
def test_overlap_preparation_holds_before_startup_and_exports_armed_policy(tmp_path, asset_type, selected, bound, cache_only):
    from test_policy_exclusion_preparation import document, rule as preparation_rule
    from aidast.scope.exclusion_preparation import prepare_exclusions, StartupOperation
    from aidast.scope.models import ScopeAsset
    doc = document(False)
    details = dict(description='Approved fixture asset', eligibility='eligible', maximum_severity='High')
    chosen = ScopeAsset(asset_type=asset_type, asset=selected, **details)
    other = ScopeAsset(asset_type='WILDCARD' if '*' in bound else 'URL', asset=bound, **details)
    restriction = preparation_rule(False).model_copy(update={'target_assets': [bound]})
    analysis_data = doc.analysis.model_dump()
    analysis_data.update(in_scope_assets=[chosen.model_dump(), other.model_dump()],
        execution_rules=doc.analysis.execution_rules.model_copy(update={'exclusions': [restriction]}).model_dump())
    analysis = type(doc.analysis).model_validate(analysis_data)
    doc = doc.model_copy(update={'analysis': analysis})
    prepared = prepare_exclusions(document=doc, analysis=analysis, targets=[chosen], result_root=tmp_path,
        startup_operations={selected: [StartupOperation('HTTP_PROBE', 'https://a.example.com/public')]},
        resolver=ExclusionBindingResolver(tmp_path / 'cache', lambda _: pytest.fail('direct rule called model')),
        cache_only=cache_only)
    assert prepared.diagnostics[0]['decision'] == 'hold'
    with pytest.raises(ValueError, match='overlap'):
        prepared.require_ready()
    stored = json.loads(prepared.policies[selected].model_dump_json())
    assert stored['rules'][0]['target_assets'] == [bound]
    assert stored['rules'][0]['source_quote'] == restriction.source_quote
    assert has_request_exclusions({'asset': selected, 'request_exclusions': stored})
    prepared.reconcile_startup({selected: [StartupOperation('DNS_RESOLUTION')]})
    assert prepared.diagnostics[0]['decision'] == 'hold'


def test_overlap_semantic_pairs_remain_complete_and_old_cache_is_not_used(tmp_path, monkeypatch):
    from test_policy_exclusion_binding import inputs, decisions
    from aidast.scope import exclusion_binding
    data = inputs()
    data['target_asset'] = 'https://app.example.com/'
    calls = []
    resolver = ExclusionBindingResolver(tmp_path, lambda context: calls.append(context) or decisions(context))
    # Materialize the previous pair-filtering cache identity without changing live sources.
    current_version = exclusion_binding.BINDING_VERSION
    monkeypatch.setattr(exclusion_binding, 'BINDING_VERSION', '1')
    context = resolver._context(**data)
    old_path = resolver._path(context)
    monkeypatch.setattr(exclusion_binding, 'BINDING_VERSION', current_version)
    old_path.write_text('{}')
    policy = resolver.resolve(**data)
    assert len(calls) == 1
    assert len(policy.semantic_bindings) == 3
    assert resolver.cached(**data) == policy
    assert old_path.read_text() == '{}'
    assert evaluate_exclusions(policy.model_dump(mode='json'), url=data['candidates'][2].url)['decision'] == 'hold'
