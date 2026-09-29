from __future__ import annotations

import pytest
from scope_test_support import publish_legacy_scope
from aidast.scope.models import ScopeAnalysis
from aidast.scope.identity_headers import resolve_scope_identity_headers
from aidast.web.requirements import build_scope_execution_requirements
from test_recon_workflow import FakeReconMainAgent, PROGRAM_URL

QUOTE = 'Send X-Research-Identity: bounty-<username> and Research-Contact and Research-Session on each request.'


def analysis(specs):
    _, base = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    data = base.model_dump()
    data['required_request_headers'] = specs
    data['source_evidence'].append({'section': 'Rules', 'quote': QUOTE})
    return ScopeAnalysis.model_validate(data)


def spec(name='X-Research-Identity', template='bounty-{researcher_username}', inputs=None, quote=QUOTE):
    return dict(name=name, value_template=template, inputs=inputs if inputs is not None else [
        dict(key='researcher_username', label='Researcher username', kind='username')], source_quote=quote)


def test_arbitrary_header_template_and_shared_input_are_resolved():
    scope = analysis([spec(), spec('Research-Contact', '{researcher_username}@example.test'),
                      spec('Research-Session', 'fixed-marker', [])])
    assert resolve_scope_identity_headers(scope, identity_values={'researcher_username': 'alice'}) == {
        'X-Research-Identity': 'bounty-alice', 'Research-Contact': 'alice@example.test',
        'Research-Session': 'fixed-marker'}
    req = build_scope_execution_requirements(scope, identity_header=None)
    assert req.header_requirements_status == 'ready'
    assert len(req.header_inputs) == 1
    assert len(req.required_headers) == 3


def test_missing_input_and_legacy_analysis_fail_closed():
    with pytest.raises(ValueError, match='researcher_username'):
        resolve_scope_identity_headers(analysis([spec()]), identity_values={})
    _, legacy = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    legacy = legacy.model_copy(update={'required_request_headers': None})
    assert build_scope_execution_requirements(legacy, identity_header=None).header_requirements_status == 'pending'
    with pytest.raises(ValueError, match='interpret'):
        resolve_scope_identity_headers(legacy, identity_values={})


@pytest.mark.parametrize('item', [spec('Authorization'), spec('Host'), spec('X-AIDAST-Browser-Token'),
    spec('bad name'), spec(template='{researcher_username.attr}'), spec(template='{researcher_username!r}'), spec(template='{researcher_username:}'),
    spec(template='{other}'), spec(quote='invented quote')])
def test_invalid_structured_headers_are_rejected(item):
    with pytest.raises(ValueError):
        analysis([item])


def test_ai_empty_result_does_not_infer_requirements_from_policy_text():
    scope = analysis([])
    assert resolve_scope_identity_headers(scope, identity_values={}) == {}
    assert build_scope_execution_requirements(scope, identity_header='hackerone').required_header is None


def test_legacy_catalog_pending_cache_reuse_and_source_preservation(tmp_path):
    from aidast.orchestration.scope import ScopeCoordinator
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.web.launch import ApprovedScopeCatalog
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    class LegacyAgent(FakeReconMainAgent):
        def collect_scope(self, url):
            page, scope = super().collect_scope(url)
            import hashlib
            text = page.text + '\n' + QUOTE
            page = page.model_copy(update={'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()})
            return page, scope.model_copy(update={'required_request_headers': None})
    publish_legacy_scope(directory, *LegacyAgent().collect_scope(PROGRAM_URL))
    document, _ = ScopeCoordinator(directory).load_approved_scope()
    # Simulate an old approved file even after the common fresh fixture evolves.
    assert document.analysis.required_request_headers is None
    before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
    calls = []
    def interpret(page):
        calls.append(page)
        return {'required_request_headers': [spec(template='fixed', inputs=[], quote=QUOTE)]}
    resolver = ScopeHeaderResolver(tmp_path / '.header-requirements', interpret)
    catalog = ApprovedScopeCatalog(tmp_path, header_resolver=resolver)
    listed = catalog.list()[0]
    assert listed.execution_requirements.header_requirements_status == 'pending'
    assert calls == []
    resolved = catalog.resolve_header_requirements(listed.scope_id)
    assert resolved.execution_requirements.header_requirements_status == 'ready'
    assert len(calls) == 1
    catalog.resolve_header_requirements(listed.scope_id)
    assert len(calls) == 1
    assert before == {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}


def test_failed_legacy_resolution_keeps_visible_scope_and_blocks_launch(tmp_path):
    from aidast.orchestration.scope import ScopeCoordinator
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.web.launch import ApprovedScopeCatalog, ScanLaunchManager, ScanLaunchRequest
    from aidast.web.projection import DashboardProjector
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    class LegacyAgent(FakeReconMainAgent):
        def collect_scope(self, url):
            page, scope = super().collect_scope(url)
            import hashlib
            text = page.text + '\n' + QUOTE
            page = page.model_copy(update={'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()})
            return page, scope.model_copy(update={'required_request_headers': None})
    publish_legacy_scope(directory, *LegacyAgent().collect_scope(PROGRAM_URL))
    def fail(page):
        raise RuntimeError('offline model failure')
    resolver = ScopeHeaderResolver(tmp_path / '.header-requirements', fail)
    catalog = ApprovedScopeCatalog(tmp_path, header_resolver=resolver)
    scope = catalog.list()[0]
    with pytest.raises(ValueError, match='interpretation failed'):
        catalog.resolve_header_requirements(scope.scope_id)
    assert len(catalog.list()) == 1
    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path), header_resolver=resolver,
                                process_factory=lambda *a, **kw: pytest.fail('must not launch'))
    with pytest.raises(ValueError, match='requirements'):
        manager.launch(ScanLaunchRequest(scope_id=scope.scope_id, targets=[scope.targets[0]['asset']],
                                        authorization_confirmed=True))


def test_proxy_enforces_generic_policy_headers_and_redacts_capture(tmp_path):
    import json
    from test_mitm_proxy import MitmAddonBudgetTests
    addon = MitmAddonBudgetTests._addon()
    addon.rules['required_identity_headers'] = {'Research-Contact': 'private@example.test'}
    addon.out_path = tmp_path / 'capture.jsonl'
    flow = MitmAddonBudgetTests._flow('/app', headers={'research-contact': 'forged', 'Cookie': 'sid=secret'})
    addon.request(flow)
    assert flow.request.headers.get('Research-Contact') == 'private@example.test'
    assert 'research-contact' not in flow.request.headers
    addon.response(flow)
    entry = json.loads(addon.out_path.read_text())
    assert entry['request_headers']['Research-Contact'] == '[REDACTED]'
    assert entry['request_headers']['Cookie'] == '[REDACTED]'


def test_browser_applies_policy_header_after_case_variant_page_headers():
    from test_recon_browser_transport import ReconBrowserTransportTests
    from unittest.mock import Mock
    from types import SimpleNamespace
    fixture = ReconBrowserTransportTests()
    fixture.setUp()
    fixture.driver.target_policy = fixture.policy.model_copy(update={
        'required_identity_headers': {'Research-Contact': 'private@example.test'}})
    route = Mock(request=SimpleNamespace(url='https://example.com/api', method='GET',
        all_headers=lambda: {'research-contact': 'forged', 'Cookie': 'sid=owned'}))
    fixture.driver._guard_request(route)
    sent = route.continue_.call_args.kwargs['headers']
    assert sent['Research-Contact'] == 'private@example.test'
    assert 'research-contact' not in sent
    assert sent['Cookie'] == 'sid=owned'


def test_header_name_must_be_grounded_in_quoted_evidence():
    with pytest.raises(ValueError, match='header name'):
        analysis([spec(name='Invented-Header')])


def test_unambiguous_legacy_username_flag_binds_generic_ai_slot():
    generic = analysis([spec(template='{username}', inputs=[dict(key='username', label='Researcher username', kind='username')])])
    assert resolve_scope_identity_headers(generic, hackerone_username='alice') == {'X-Research-Identity': 'alice'}


def test_non_latin1_header_input_fails_before_transport():
    with pytest.raises(ValueError, match='Latin-1'):
        resolve_scope_identity_headers(analysis([spec(template='{contact}', inputs=[dict(key='contact', label='Contact', kind='text')])]), identity_values={'contact': '🙂'})


def test_fresh_scope_ai_response_cannot_omit_header_decision():
    from aidast.agents.main import CodexMainAgent, MainAgentError
    _, legacy = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    page, _ = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    legacy = legacy.model_copy(update={'required_request_headers': None})
    with pytest.raises(MainAgentError, match='required_request_headers'):
        CodexMainAgent._verify_grounding(page, legacy)


def test_multiple_declared_inputs_and_fixed_headers_bind_without_platform_flags():
    specs = [spec(template='{handle}:{contact}', inputs=[
        dict(key='handle', label='Handle', kind='username'),
        dict(key='contact', label='Research contact', kind='email')]),
        spec('Research-Session', 'program-marker', [])]
    result = resolve_scope_identity_headers(analysis(specs), identity_values={'handle': 'alice', 'contact': 'alice@example.test'})
    assert result == {'X-Research-Identity': 'alice:alice@example.test', 'Research-Session': 'program-marker'}
    with pytest.raises(ValueError, match='contact'):
        resolve_scope_identity_headers(analysis(specs), identity_values={'handle': 'alice'})


def test_legacy_resolver_rejects_ungrounded_results_and_changed_content_cache(tmp_path):
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.scope.models import ScopeDocument
    from datetime import datetime, timezone
    page, legacy = FakeReconMainAgent().collect_scope(PROGRAM_URL)
    legacy = legacy.model_copy(update={'required_request_headers': None})
    doc = ScopeDocument(scope_id='legacy', created_at=datetime.now(timezone.utc), source=page, analysis=legacy)
    resolver = ScopeHeaderResolver(tmp_path / 'cache', lambda _: {'required_request_headers': [spec()]})
    with pytest.raises(ValueError, match='interpretation failed'):
        resolver.resolve(doc)
    assert resolver.cached(doc) is None
    resolver.interpreter = lambda _: {'required_request_headers': []}
    assert resolver.resolve(doc).required_request_headers == []
    changed = doc.model_copy(update={'scope_id': 'changed'})
    assert resolver.cached(changed) is None


def test_header_resolution_api_returns_public_scope_and_requires_origin(tmp_path):
    import asyncio
    import httpx
    from aidast.orchestration.scope import ScopeCoordinator
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.web.launch import ScanLaunchManager
    from aidast.web.projection import DashboardProjector
    from aidast.web.server import create_app
    class LegacyAgent(FakeReconMainAgent):
        def collect_scope(self, url):
            page, scope = super().collect_scope(url)
            return page, scope.model_copy(update={'required_request_headers': None})
    publish_legacy_scope(tmp_path / 'Scope' / 'bugcrowd' / 'example',
                         *LegacyAgent().collect_scope(PROGRAM_URL))
    calls = []
    def interpret(page):
        calls.append(page)
        return {'required_request_headers': []}
    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path),
        header_resolver=ScopeHeaderResolver(tmp_path / '.header-requirements', interpret))
    app = create_app(result_root=tmp_path, launch_manager=manager)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            scope = (await client.get('/api/v1/scopes')).json()['scopes'][0]
            assert scope['execution_requirements']['header_requirements_status'] == 'pending'
            assert calls == []
            url = f"/api/v1/scopes/{scope['scope_id']}/header-requirements"
            assert (await client.post(url)).status_code == 403
            response = await client.post(url, headers={'Origin': 'http://test'})
            assert response.status_code == 200
            assert response.json()['scope']['execution_requirements']['header_requirements_status'] == 'ready'
            assert 'text' not in response.json()['scope']
            await client.post(url, headers={'Origin': 'http://test'})
            assert len(calls) == 1
    asyncio.run(exercise())


@pytest.mark.parametrize('name', ['X-API-Key', 'Api-Key', 'X-Auth-Token', 'X-Access-Token', 'X_Api_Key'])
def test_identification_map_cannot_overwrite_common_credential_headers(name):
    from aidast.core.http_safety import merge_hackerone_identity
    with pytest.raises(ValueError, match='protected credential'):
        merge_hackerone_identity({name: 'resolved-authentication-secret'}, None,
                                 required_identity_headers={name: 'identity-value'})


def test_unfamiliar_identification_names_remain_generic_with_credential_denylist():
    from aidast.core.http_safety import merge_hackerone_identity
    merged = merge_hackerone_identity({'X-API-Key': 'resolved-authentication-secret'}, None,
                                     required_identity_headers={'Research-Contact': 'alice@example.test',
                                                                'X-Research-Token': 'program-marker'})
    assert merged['X-API-Key'] == 'resolved-authentication-secret'
    assert merged['Research-Contact'] == 'alice@example.test'
    assert merged['X-Research-Token'] == 'program-marker'


@pytest.mark.parametrize('corrupt', [[], None, 7, 'broken', True, {}, {'requirements': []}])
def test_corrupt_cache_keeps_approved_scope_visible_and_pending(tmp_path, corrupt):
    import json
    from aidast.orchestration.scope import ScopeCoordinator
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.web.launch import ApprovedScopeCatalog
    class LegacyAgent(FakeReconMainAgent):
        def collect_scope(self, url):
            page, scope = super().collect_scope(url)
            return page, scope.model_copy(update={'required_request_headers': None})
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    publish_legacy_scope(directory, *LegacyAgent().collect_scope(PROGRAM_URL))
    document, _ = ScopeCoordinator(directory).load_approved_scope()
    resolver = ScopeHeaderResolver(tmp_path / '.header-requirements',
                                   lambda _: pytest.fail('cache reads must not invoke AI'))
    resolver.cache_dir.mkdir()
    resolver.cache_path(document).write_text(json.dumps(corrupt), encoding='utf-8')
    assert resolver.cached(document) is None
    scopes = ApprovedScopeCatalog(tmp_path, header_resolver=resolver).list()
    assert len(scopes) == 1
    assert scopes[0].execution_requirements.header_requirements_status == 'pending'


def test_missing_arbitrary_input_error_suggests_only_an_existing_cli_option():
    generic = analysis([spec(template='{username}', inputs=[
        dict(key='username', label='Researcher username', kind='username')])])
    with pytest.raises(ValueError) as error:
        resolve_scope_identity_headers(generic)
    assert '--header-input username=VALUE' in str(error.value)
    assert '--username' not in str(error.value)
