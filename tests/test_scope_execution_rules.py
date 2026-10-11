from datetime import datetime, timezone
import hashlib
import pytest
from aidast.scope import models
from test_recon_workflow import FakeReconMainAgent, PROGRAM_URL

QUOTE = 'Keep requests to 10 per second or lower.'

def document():
    page, analysis = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    text = page.text + '\n' + QUOTE
    page = page.model_copy(update={'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()})
    return models.ScopeDocument(scope_id='legacy', created_at=datetime.now(timezone.utc), source=page,
        analysis=analysis.model_copy(update={'required_request_headers': None}))

def test_structured_rules_reject_invalid_limits_and_types():
    assert hasattr(models, 'ScopeExecutionRules')
    for item in [{'maximum': 0, 'period_seconds': 1}, {'maximum': True, 'period_seconds': 1},
                 {'maximum': 10, 'period_seconds': float('inf')}]:
        with pytest.raises(ValueError):
            models.ScopeExecutionRules(request_limits=[dict(item, scope='program', source_quote=QUOTE)])
    with pytest.raises(ValueError):
        models.ScopeExecutionRules(option_limits=[dict(field='concurrency', value=True, source_quote=QUOTE)])

def test_combined_resolver_grounds_and_caches_immutable_source(tmp_path):
    from aidast.scope.execution_rules import ScopeExecutionResolver
    doc = document(); original = doc.model_dump_json()
    calls = []
    def interpret(page):
        calls.append(page)
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[], request_limits=[dict(
            maximum=10, period_seconds=1, scope='program', source_quote=QUOTE)]))
    resolver = ScopeExecutionResolver(tmp_path, interpret)
    assert resolver.cached(doc) is None
    result = resolver.resolve(doc)
    assert result.execution_rules.request_limits[0].maximum == 10
    assert resolver.resolve(doc) == result
    assert len(calls) == 1
    assert doc.model_dump_json() == original
    resolver.cache_path(doc).write_text('{}')
    assert resolver.cached(doc) is None
    resolver.interpreter = lambda _: dict(required_request_headers=[], execution_rules=dict(exclusions=[],
        blocking_requirements=[dict(label='Unknown', reason='Unsupported', source_quote='invented')]))
    with pytest.raises(ValueError, match='interpretation failed'):
        resolver.resolve(doc)

def test_target_bound_email_and_acknowledgement():
    from aidast.scope.execution_rules import validate_policy_prerequisites
    rules = models.ScopeExecutionRules(required_inputs=[dict(key='email', label='Testing email', kind='email',
        allowed_email_domains=['wearehackerone.com'], source_quote=QUOTE)], required_confirmations=[dict(
        key='contact', label='Contacted production', target_assets=['https://production.example/'], source_quote=QUOTE)])
    validate_policy_prerequisites(rules, ['https://stage.example/'], {'email':'a@wearehackerone.com'}, [])
    with pytest.raises(ValueError, match='contact'):
        validate_policy_prerequisites(rules, ['https://production.example/'], {'email':'a@wearehackerone.com'}, [])
    with pytest.raises(ValueError, match='domain'):
        validate_policy_prerequisites(rules, ['https://stage.example/'], {'email':'a@example.com'}, [])

def test_profile_bounds_use_structured_rules_only():
    from aidast.recon.profiles import grounded_scope_request_rate
    from aidast.web.requirements import build_scope_execution_requirements
    doc = document()
    assert grounded_scope_request_rate(doc.analysis) is None
    data = doc.analysis.model_dump()
    data.update(required_request_headers=[], execution_rules=dict(exclusions=[], request_limits=[dict(
        maximum=10, period_seconds=60, scope='program', source_quote=QUOTE)], option_limits=[dict(
        field='concurrency', value=1, source_quote=QUOTE)]))
    data['source_evidence'].append(dict(section='Limits', quote=QUOTE))
    analysis = models.ScopeAnalysis.model_validate(data)
    requirements = build_scope_execution_requirements(analysis)
    assert requirements.execution_requirements_status == 'ready'
    assert requirements.profiles[0].limits.requests_per_second == pytest.approx(1/6)
    assert requirements.profiles[0].limits.concurrency == 1
    assert build_scope_execution_requirements(doc.analysis).header_requirements_status == 'pending'


def test_narrow_rules_and_shared_binding(tmp_path):
    from aidast.scope.execution_rules import bind_execution_policies
    from aidast.recon.policy import TargetPolicy
    policy = TargetPolicy(scope_id='scope', policy_id='one', asset_type='URL',
        asset='https://example.test/', allowed_hosts=['example.test'])
    rules = models.ScopeExecutionRules(option_limits=[dict(field='concurrency', value=1, source_quote=QUOTE),
        dict(field='ffuf_enabled', value=False, source_quote=QUOTE), dict(field='max_scan_seconds', value=30, source_quote=QUOTE)],
        request_limits=[dict(maximum=50, period_seconds=86400, scope='program', source_quote=QUOTE)])
    bound = bind_execution_policies({'one': policy, 'two': policy}, rules, result_root=tmp_path,
        program_url=PROGRAM_URL, scan_id='scan_test', prerequisite_evidence={})
    assert bound['one'].limits.concurrency == 1
    assert not bound['one'].tools.ffuf_enabled
    assert bound['one'].request_governor == bound['two'].request_governor
    assert bound['one'].request_governor.scan_max_requests == 2000
    assert bound['one'].request_governor.scan_max_seconds == 30
    assert bound['one'].request_governor.ledger_path.startswith(str(tmp_path))
    assert policy.request_governor is None

@pytest.mark.parametrize('field,value', [('period_seconds', True), ('period_seconds', '1'), ('maximum', '1')])
def test_request_limit_does_not_coerce_model_values(field, value):
    data = dict(maximum=10, period_seconds=1, scope='program', source_quote=QUOTE)
    data[field] = value
    with pytest.raises(ValueError):
        models.RequestLimit.model_validate(data)

@pytest.mark.parametrize('value', ['1', 'false', None])
def test_option_limit_does_not_coerce_model_values(value):
    with pytest.raises(ValueError):
        models.OptionLimit(field='concurrency', value=value, source_quote=QUOTE)


def test_bound_budget_directory_can_be_opened_by_governor(tmp_path):
    from aidast.scope.execution_rules import bind_execution_policies
    from aidast.recon.policy import TargetPolicy
    from aidast.core.request_governor import RequestGovernor
    policy = TargetPolicy(scope_id='scope', policy_id='one', asset_type='URL',
        asset='https://example.test/', allowed_hosts=['example.test'])
    root = tmp_path / 'new-result-root'
    bound = bind_execution_policies({'one': policy}, models.ScopeExecutionRules(), result_root=root,
        program_url=PROGRAM_URL, scan_id='scan_test', prerequisite_evidence={})
    permit = RequestGovernor(bound['one'].request_governor.model_dump()).reserve('https://example.test/')
    permit.wait()
    permit.complete()


def test_shared_header_policy_input_values_cannot_disagree():
    from aidast.scope.execution_rules import validate_shared_policy_values
    data = document().analysis.model_dump()
    quote = 'Send Research-Contact with your testing email.'
    data.update(required_request_headers=[dict(name='Research-Contact', value_template='{email}',
        inputs=[dict(key='email', label='Email', kind='email')], source_quote=quote)],
        execution_rules=dict(exclusions=[], required_inputs=[dict(key='email', label='Email', kind='email', source_quote=quote)]))
    data['source_evidence'].append(dict(section='Contact', quote=quote))
    analysis = models.ScopeAnalysis.model_validate(data)
    with pytest.raises(ValueError, match='conflicting'):
        validate_shared_policy_values(analysis, {'email':'a@example.test'}, {'email':'b@example.test'})
    validate_shared_policy_values(analysis, {'email':'a@example.test'}, {'email':'a@example.test'})
    data['execution_rules']['required_inputs'][0]['kind'] = 'text'
    with pytest.raises(ValueError, match='conflicting'):
        models.ScopeAnalysis.model_validate(data)


def test_combined_endpoint_resolves_legacy_and_launch_blocks_missing_input(tmp_path):
    import asyncio
    import httpx
    from aidast.orchestration.scope import ScopeCoordinator
    from aidast.scope.execution_rules import ScopeExecutionResolver
    from aidast.web.launch import ScanLaunchManager, ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    from aidast.web.server import create_app
    class Legacy(FakeReconMainAgent):
        def collect_scope(self, url):
            doc = document()
            return doc.source, doc.analysis.model_copy(update={'execution_rules':None})
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    from scope_test_support import publish_legacy_scope
    # Simulate an archive created before fresh execution-rule decisions were required.
    publish_legacy_scope(directory, *Legacy().collect_scope(PROGRAM_URL))
    before = {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}
    calls = []
    def interpret(page):
        calls.append(page)
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[], required_inputs=[dict(
            key='testing_email', label='Testing email', kind='email', allowed_email_domains=['wearehackerone.com'], source_quote=QUOTE)]))
    resolver = ScopeExecutionResolver(tmp_path / '.execution-requirements', interpret)
    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path), execution_resolver=resolver,
        process_factory=lambda *a, **k: pytest.fail('missing prerequisites must never create a process'))
    app = create_app(result_root=tmp_path, launch_manager=manager)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            scope = (await client.get('/api/v1/scopes')).json()['scopes'][0]
            assert scope['execution_requirements']['execution_requirements_status'] == 'pending'
            assert calls == []
            endpoint = f"/api/v1/scopes/{scope['scope_id']}/execution-requirements"
            assert (await client.post(endpoint)).status_code == 403
            response = await client.post(endpoint, headers={'Origin':'http://test'})
            assert response.status_code == 200
            assert response.json()['scope']['execution_requirements']['execution_requirements_status'] == 'ready'
            assert len(calls) == 1
            with pytest.raises(ValueError, match='testing_email'):
                manager.launch(ScanLaunchRequest(scope_id=scope['scope_id'], targets=['*.example.com'], authorization_confirmed=True))
    asyncio.run(exercise())
    assert before == {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}


def test_cli_prerequisites_block_before_login(tmp_path):
    from unittest.mock import patch
    from aidast.cli import main
    from aidast.orchestration.scope import ScopeCoordinator
    class Restricted(FakeReconMainAgent):
        def collect_scope(self, url):
            doc = document()
            data = doc.analysis.model_dump()
            data.update(required_request_headers=[], execution_rules=dict(exclusions=[], required_confirmations=[dict(
                key='production_contact', label='Contacted production', target_assets=['*.example.com'], source_quote=QUOTE)]))
            data['source_evidence'].append(dict(section='Contact', quote=QUOTE))
            return doc.source, models.ScopeAnalysis.model_validate(data)
    output = tmp_path / 'Scope'
    ScopeCoordinator(output / 'bugcrowd' / 'example').collect(PROGRAM_URL, main_agent=Restricted(),
        approved_by='operator', review=lambda _: True)
    with patch('aidast.cli.CodexMainAgent', return_value=Restricted()), patch('aidast.cli.collect_target_sessions',
            side_effect=AssertionError('must not open login before prerequisites')), patch('subprocess.run',
            side_effect=AssertionError('must not run external process')):
        assert main(['recon', PROGRAM_URL, '--target', '*.example.com', '--execute', '--login-mode',
                     'system-browser', '--output-dir', str(output)]) == 1


def test_conditional_blockers_only_apply_to_selected_exact_assets(tmp_path):
    from aidast.scope.execution_rules import validate_policy_prerequisites, bind_execution_policies
    from aidast.recon.policy import TargetPolicy
    rules = models.ScopeExecutionRules(blocking_requirements=[dict(label='Contact', reason='Unsupported action',
        source_quote=QUOTE, target_assets=['https://production.example/', 'Extension integration'])])
    stage = 'https://stage.example/'
    validate_policy_prerequisites(rules, [stage])
    policy = TargetPolicy(scope_id='scope', policy_id='stage', asset_type='URL', asset=stage, allowed_hosts=['stage.example'])
    assert bind_execution_policies({'stage':policy}, rules, result_root=tmp_path,
        program_url=PROGRAM_URL, scan_id=None, prerequisite_evidence={})['stage'].asset == stage
    for asset in ['https://production.example/', 'Extension integration']:
        with pytest.raises(ValueError, match='mandatory'):
            validate_policy_prerequisites(rules, [asset])
    global_rules = models.ScopeExecutionRules(blocking_requirements=[dict(label='Stop', reason='Unsupported', source_quote=QUOTE)])
    with pytest.raises(ValueError, match='mandatory'):
        validate_policy_prerequisites(global_rules, [stage])
    with pytest.raises(ValueError, match='mandatory'):
        bind_execution_policies({'stage':policy}, global_rules, result_root=tmp_path,
            program_url=PROGRAM_URL, scan_id=None, prerequisite_evidence={})
    data = document().analysis.model_dump()
    data['source_evidence'].append(dict(section='Limits', quote=QUOTE))
    data['execution_rules'] = rules.model_dump()
    with pytest.raises(ValueError, match='exact approved asset'):
        models.ScopeAnalysis.model_validate(data)


def test_explicit_method_ceiling_blocks_browser_post_and_graphql(tmp_path):
    from aidast.scope.execution_rules import bind_execution_policies
    from aidast.recon.policy import TargetPolicy
    policy = TargetPolicy(scope_id='scope', policy_id='one', asset_type='URL',
        asset='https://example.test/', allowed_hosts=['example.test'], api_probe={'graphql':True,'allowed_paths':['/graphql']})
    assert policy.allows_browser_support_url('https://example.test/api', method='POST')
    rules = models.ScopeExecutionRules(allowed_methods=dict(values=['GET'], source_quote=QUOTE))
    bound = bind_execution_policies({'one':policy}, rules, result_root=tmp_path,
        program_url=PROGRAM_URL, scan_id=None, prerequisite_evidence={})['one']
    assert not bound.allows_browser_support_url('https://example.test/api', method='POST')
    assert not bound.allows_graphql_probe_url('https://example.test/graphql')
    for check in (bound.allows_url, bound.allows_attack_url, bound.allows_validation_url):
        assert check('https://example.test/', method='GET')
        assert not check('https://example.test/', method='HEAD')
    restored = TargetPolicy.model_validate_json(bound.model_dump_json())
    assert restored.execution_allowed_methods == ['GET']
    assert restored.mitm_rules()['execution_allowed_methods'] == ['GET']
    assert 'execution_allowed_methods' not in policy.model_dump()


def test_browser_support_compatibility_cannot_override_hard_method_ceiling():
    from types import SimpleNamespace
    from test_recon_browser_transport import ReconBrowserTransportTests
    fixture = ReconBrowserTransportTests(); fixture.setUp()
    fixture.driver.target_policy = fixture.policy.model_copy(update={'execution_allowed_methods':['GET']})
    request = SimpleNamespace(is_navigation_request=lambda:False, frame=SimpleNamespace(url='https://example.com/api'),
        url='https://example.com/support', method='POST', resource_type='xhr')
    assert fixture.driver._browser_support_mode(request) is None
    request.url = 'https://cdn.example.test/script.js'; request.method = 'HEAD'; request.resource_type = 'script'
    assert fixture.driver._browser_support_mode(request) is None
    request.method = 'GET'
    assert fixture.driver._browser_support_mode(request) == 'passive'
