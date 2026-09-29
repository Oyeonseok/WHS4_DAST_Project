"""Offline contracts for collection-time reference evidence and saved rules."""
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.scope.models import CaptureReason, CaptureStatus, ProgramPage, ScopeAnalysis
from aidast.scope.execution_rules import ScopeExecutionResolver

PRIMARY = 'example.org is in scope. No denial of service. Read the 안내서 for testing rules.'
REFERENCE = 'Requests must stay at or below 3 per second. Reports must be private.'
URL = 'https://program.example/policy'
GUIDE = 'https://docs.example/arbitrary-guide'


def page():
    data = dict(requested_url=URL, final_url=URL, title='Program',
                captured_at=datetime.now(timezone.utc), capture_status='COMPLETE',
                capture_reason='NONE', text=PRIMARY,
                content_sha256=hashlib.sha256(PRIMARY.encode()).hexdigest())
    result = ProgramPage(**data)
    # Pre-feature source accepts this test capture; the behavioral assertion is
    # final saved evidence/rules, not an import or missing constructor failure.
    link = dict(candidate_id=7, url=GUIDE, label='안내서', source_url=URL)
    if 'observed_links' in ProgramPage.model_fields:
        return ProgramPage(**data, observed_links=[link])
    return result.model_copy(update={'observed_links': [link]})


def analysis(with_reference=False):
    data = dict(program_name='Program', program_description='A test program',
                in_scope_assets=[dict(asset_type='DOMAIN', asset='example.org',
                                      description='', eligibility='', maximum_severity='')],
                out_of_scope_assets=[], allowed_activities=['Non-destructive testing'],
                prohibited_activities=['No denial of service'], submission_requirements=[],
                operational_constraints=[], safe_harbor='', ambiguities=[],
                required_request_headers=[], execution_rules={'exclusions': []},
                source_evidence=[dict(section='Scope', quote='example.org is in scope.')])
    if with_reference:
        quote = 'Requests must stay at or below 3 per second.'
        data['source_evidence'].append(dict(section='Testing', quote=quote))
        data['execution_rules']['request_limits'] = [dict(maximum=3, period_seconds=1,
            scope='program', source_quote=quote)]
        data['submission_requirements'] = ['Reports must be private.']
    return ScopeAnalysis(**data)


class Agent:
    def collect_scope(self, _):
        return page(), analysis()

    def select_policy_references(self, page_text, candidates):
        return {'selections': [{'candidate_id': 7,
                'source_quote': 'Read the 안내서 for testing rules.', 'applicability': 'mixed'}]}

    def interpret_captured_scope(self, captured):
        return analysis(REFERENCE in getattr(captured, 'evidence_text', captured.text))


class Reader:
    def read(self, url):
        from aidast.scope.policy_references import CapturedPolicyDocument
        return CapturedPolicyDocument(requested_url=url, final_url=url,
            captured_at=datetime.now(timezone.utc), text=REFERENCE, observed_links=[])


def test_reference_prepared_before_save_and_approved_launch_needs_no_interpreter(tmp_path):
    coordinator = ScopeCoordinator(tmp_path / 'approved')
    coordinator.reference_reader = Reader()
    document, draft = coordinator.collect_draft(URL, main_agent=Agent())
    assert document.analysis.execution_rules.request_limits, 'referenced limit was not prepared at Scope creation'
    assert document.analysis.execution_rules.request_limits[0].maximum == 3
    assert document.source.text == PRIMARY
    assert document.source.content_sha256 == hashlib.sha256(PRIMARY.encode()).hexdigest()
    assert GUIDE in (draft / 'Scope.md').read_text()
    coordinator.approve_draft(draft, approved_by='tester')
    saved, _ = coordinator.load_approved_scope()
    def forbidden(_):
        raise AssertionError('complete approved Scope must not invoke another interpreter')
    resolver = ScopeExecutionResolver(tmp_path / 'cache', interpreter=forbidden)
    assert resolver.resolve(saved).execution_rules.request_limits[0].maximum == 3
    assert saved.analysis.submission_requirements == ['Reports must be private.']
    assert not saved.analysis.execution_rules.blocking_requirements


def test_fresh_draft_rejects_missing_explicit_headers(tmp_path):
    class IncompleteAgent(Agent):
        def collect_scope(self, _):
            return page().model_copy(update={'observed_links': []}), analysis().model_copy(update={'required_request_headers': None})
        def interpret_captured_scope(self, _):
            return analysis().model_copy(update={'required_request_headers': None})
    with pytest.raises(CoordinatorError, match='required_request_headers'):
        ScopeCoordinator(tmp_path / 'approved').collect_draft(URL, main_agent=IncompleteAgent())

@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_model_adapters_select_offline_and_interpret_combined_evidence(module_name):
    import importlib
    from aidast.scope.policy_references import enrich_policy_references
    adapter = importlib.import_module(module_name).CodexMainAgent()
    captured = enrich_policy_references(page(), Agent().select_policy_references, Reader())
    with patch.object(adapter, '_run_structured', return_value=analysis(True)) as run:
        result = adapter.interpret_captured_scope(captured)
        assert result.execution_rules.request_limits[0].maximum == 3
        assert REFERENCE in run.call_args.kwargs['prompt']
        assert run.call_args.kwargs['allow_browser'] is False
    with patch.object(adapter, '_run_structured', return_value=Agent().select_policy_references('', [])) as run:
        selection = adapter.select_policy_references(PRIMARY, captured.observed_links)
        assert selection.selections[0].candidate_id == 7
        assert run.call_args.kwargs['allow_browser'] is False
        assert 'submission_requirements' in run.call_args.kwargs['prompt']


def test_public_reader_observes_landing_and_scope_view_links():
    from unittest.mock import MagicMock
    from aidast.scope.reader import PlaywrightProgramPageReader
    browser_page = MagicMock()
    browser_page.url = URL
    browser_page.title.return_value = 'Program'
    browser_page.locator.return_value.evaluate_all.side_effect = [
        [{'href': GUIDE, 'label': '안내서'}], [{'href': '/nested', 'label': 'Nested terms'}]]
    reader = PlaywrightProgramPageReader()
    with patch.object(reader, '_wait_for_stable_text', return_value=PRIMARY * 20), \
         patch.object(reader, '_read_scope_view', return_value=(URL, 'Scope view text' * 50)), \
         patch('aidast.scope.reader._validate_public_https_url'):
        captured = reader._capture_loaded_page(browser_page, URL)
    links = [link for view in captured.primary_views for link in view.observed_links]
    assert [link.url for link in links] == [GUIDE, 'https://program.example/nested']
    assert all(link.source_url == URL for link in links)
    assert captured.observed_links == []


@pytest.mark.parametrize('mode', ['public', 'authenticated'])
def test_full_landing_link_budget_preserves_later_guide_and_saved_rule(tmp_path, mode):
    """A full first DOM view must not erase a later view's applicable guide."""
    from unittest.mock import MagicMock
    from aidast.scope.reader import PlaywrightProgramPageReader, RuntimeBrowserProgramPageReader
    from aidast.scope.models import ScopeNavigationDecision
    browser_page = MagicMock(url=URL)
    browser_page.title.return_value = 'Program'
    landing = 'example.org is in scope. No denial of service. ' * 20
    later = 'Read the 안내서 for testing rules. ' * 20
    browser_page.locator.return_value.evaluate_all.side_effect = [
        [{'href': f'https://program.example/navigation/{i}', 'label': str(i)} for i in range(128)],
        [{'href': GUIDE, 'label': '안내서'}],
    ]
    def navigate(*args, **kwargs):
        browser_page.url = URL + '/scope'
        return browser_page.url, later
    if mode == 'public':
        reader = PlaywrightProgramPageReader()
        with patch.object(reader, '_wait_for_stable_text', return_value=landing), \
             patch.object(reader, '_read_scope_view', side_effect=navigate), \
             patch('aidast.scope.reader._validate_public_https_url'):
            captured = reader._capture_loaded_page(browser_page, URL)
    else:
        decisions = iter([ScopeNavigationDecision(action='open', candidate_id=1),
                          ScopeNavigationDecision(action='capture', candidate_id=None)])
        reader = RuntimeBrowserProgramPageReader(identity='test-user', navigation_agent=lambda *_: next(decisions), output_fn=lambda _: None)
        control = MagicMock()
        control.click.side_effect = navigate
        with patch.object(reader, '_wait_for_stable_text', side_effect=[landing, later]), \
             patch.object(reader, '_navigation_candidates', return_value=([{'id': 1, 'label': 'Scope'}], {1: control})):
            captured = reader._capture_agent_guided(browser_page, URL)
    selections = []
    class ViewAgent(Agent):
        def collect_scope(self, _):
            return captured, analysis()
        def select_policy_references(self, text, candidates):
            selections.append((text, candidates))
            return {'selections': [dict(candidate_id=item.candidate_id,
                source_quote='Read the 안내서 for testing rules.', applicability='testing')
                for item in candidates if item.url == GUIDE]}
    coordinator = ScopeCoordinator(tmp_path / mode, reference_reader=Reader())
    document, draft = coordinator.collect_draft(URL, main_agent=ViewAgent())
    assert document.analysis.execution_rules.request_limits, 'later primary guide was lost after 128 landing links'
    assert document.analysis.execution_rules.request_limits[0].maximum == 3
    assert len(selections) == 2
    assert [len(links) for _, links in selections] == [128, 1]
    assert selections[0][0] == landing.strip()
    assert selections[1][0] == later.strip()
    assert document.source.policy_references[0].parent_url == URL + '/scope'
    assert document.source.text == captured.text
    assert document.source.content_sha256 == captured.content_sha256
    coordinator.approve_draft(draft, approved_by='tester')
    saved, _ = coordinator.load_approved_scope()
    def forbidden(_):
        raise AssertionError('saved rules must not be reinterpreted')
    rules = ScopeExecutionResolver(tmp_path / 'cache', interpreter=forbidden).resolve(saved)
    assert rules.execution_rules.request_limits[0].maximum == 3


@pytest.mark.parametrize('choices', [
    [{'candidate_id': 999, 'source_quote': PRIMARY, 'applicability': 'testing'}],
    [{'candidate_id': 7, 'source_quote': 'Read the for testing rules.', 'applicability': 'testing'}],
    [{'candidate_id': 7, 'source_quote': PRIMARY, 'applicability': 'testing'}] * 2,
])
def test_unobserved_duplicate_and_noncontiguous_selection_rejected(choices):
    from aidast.scope.policy_references import enrich_policy_references, PolicyReferenceError
    with pytest.raises(PolicyReferenceError):
        enrich_policy_references(page(), lambda *_: {'selections': choices}, Reader())


@pytest.mark.parametrize('phase,advised', [('testing', True), ('mixed', True), ('unknown', True), ('disclosure', False), ('reporting', False)])
def test_failed_reference_phase_is_preserved_without_label_filter(tmp_path, phase, advised):
    class FailingReader:
        def read(self, _):
            raise OSError('unavailable')
    class PhaseAgent(Agent):
        def select_policy_references(self, *args):
            result = super().select_policy_references(*args)
            result['selections'][0]['applicability'] = phase
            return result
    document, draft = ScopeCoordinator(tmp_path / 'approved', reference_reader=FailingReader()).collect_draft(URL, main_agent=PhaseAgent())
    assert document.source.policy_references[0].status == 'unresolved'
    assert bool(document.analysis.execution_rules.advisories) is advised
    assert document.analysis.execution_rules.blocking_requirements == []
    markdown = (draft / 'Scope.md').read_text()
    assert 'relationship: uncertain' in markdown
    for item in document.analysis.execution_rules.advisories:
        assert item.source_quote in markdown
        assert item.reason in markdown
        assert item.guidance in markdown
    from aidast.scope.execution_rules import validate_policy_prerequisites
    validate_policy_prerequisites(document.analysis.execution_rules, ['example.org'])


def test_external_evidence_cannot_authorize_assets_or_add_activities(tmp_path):
    class ExpansionAgent(Agent):
        def interpret_captured_scope(self, captured):
            data = analysis(True).model_dump()
            data['allowed_activities'] = ['Denial of service']
            return ScopeAnalysis(**data)
    document, _ = ScopeCoordinator(tmp_path / 'first', reference_reader=Reader()).collect_draft(URL, main_agent=ExpansionAgent())
    assert document.analysis.allowed_activities == ['Non-destructive testing']
    class ExternalReader(Reader):
        def read(self, url):
            return super().read(url).model_copy(update={'text': REFERENCE + ' external.example is in scope.'})
    class ExternalAgent(Agent):
        def interpret_captured_scope(self, captured):
            data = analysis(True).model_dump()
            data['in_scope_assets'][0]['asset'] = 'external.example'
            data['source_evidence'].append(dict(section='Scope', quote='external.example is in scope.'))
            return ScopeAnalysis(**data)
    with pytest.raises(CoordinatorError, match='in-scope asset'):
        ScopeCoordinator(tmp_path / 'second', reference_reader=ExternalReader()).collect_draft(URL, main_agent=ExternalAgent())


def test_duplicate_url_keeps_later_testing_phase_after_disclosure_failure(tmp_path):
    from aidast.scope.models import ObservedPolicyLink
    class DuplicateAgent(Agent):
        def collect_scope(self, _):
            captured = page()
            captured.observed_links.append(ObservedPolicyLink(candidate_id=8, url=GUIDE, label='Testing', source_url=URL))
            return captured, analysis()
        def select_policy_references(self, *_):
            return {'selections': [dict(candidate_id=7, source_quote=PRIMARY, applicability='disclosure'),
                                   dict(candidate_id=8, source_quote=PRIMARY, applicability='testing')]}
    class FailingReader:
        def read(self, _):
            raise OSError('unavailable')
    document, _ = ScopeCoordinator(tmp_path / 'approved', reference_reader=FailingReader()).collect_draft(URL, main_agent=DuplicateAgent())
    assert [item.applicability for item in document.source.policy_references] == ['disclosure', 'testing']
    assert document.analysis.execution_rules.advisories
    assert document.analysis.execution_rules.blocking_requirements == []


def test_recursive_reference_depth_and_document_budgets_are_explicit():
    from aidast.scope.models import ObservedPolicyLink
    from aidast.scope.policy_references import enrich_policy_references, CapturedPolicyDocument
    calls = []
    selections = []
    def selector(text, candidates):
        selections.append(text)
        return {'selections': [dict(candidate_id=item.candidate_id, source_quote=text,
                                    applicability='unknown') for item in candidates]}
    class RecursiveReader:
        def read(self, url):
            calls.append(url)
            links = [ObservedPolicyLink(candidate_id=i, url=f'{url}/{i}', label='Nested', source_url=url) for i in range(8)]
            return CapturedPolicyDocument(requested_url=url, final_url=url, captured_at=datetime.now(timezone.utc),
                                          text=f'Rules for {url}', observed_links=links)
    enriched = enrich_policy_references(page(), selector, RecursiveReader())
    assert len(calls) == 8
    assert len(selections) == 9
    assert max(item.depth for item in enriched.policy_references) == 3
    errors = {item.error for item in enriched.policy_references if item.status == 'unresolved'}
    assert errors == {'reference document budget exhausted', 'reference depth budget exhausted'}
    assert len(enriched.policy_references) <= 72


def test_combined_evidence_budget_records_unresolved_without_truncating_primary():
    from aidast.scope.policy_references import enrich_policy_references
    class LargeReader(Reader):
        def read(self, url):
            return super().read(url).model_copy(update={'text': 'x' * 120000})
    enriched = enrich_policy_references(page(), Agent().select_policy_references, LargeReader())
    assert enriched.policy_references[0].status == 'unresolved'
    assert enriched.policy_references[0].error == 'reference exceeds combined evidence budget'
    assert enriched.evidence_text == PRIMARY


def test_legacy_reference_fields_default_empty_and_original_digest_stable():
    original = page().model_dump(exclude={'observed_links', 'policy_references', 'primary_views'})
    parsed = ProgramPage.model_validate(original)
    assert parsed.evidence_text == PRIMARY
    assert parsed.observed_links == parsed.policy_references == parsed.primary_views == []


class Response:
    def __init__(self, body=b'Public rules', status=200, headers=None):
        import io
        self.body = io.BytesIO(body)
        self.status = status
        self.headers = headers if headers is not None else {'Content-Type': 'text/plain'}
    def getheader(self, key, default=None):
        return self.headers.get(key, default)
    def getheaders(self):
        return list(self.headers.items())
    def read1(self, size):
        return self.body.read(size)
    def close(self):
        self.body.close()


def public_addresses(host, port, **_):
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))]


def transport(responses, resolver=public_addresses):
    from aidast.scope.policy_transport import PublicPolicyDocumentReader
    events = []
    class Connection:
        sock = None
        def __init__(self, host, port, address, timeout):
            events.append(('connect', host, port, address, timeout))
            self.response = responses.pop(0)
        def request(self, method, path, headers):
            events.append(('request', method, path, headers))
        def getresponse(self):
            return self.response
        def close(self):
            events.append(('close',))
    return PublicPolicyDocumentReader(resolver=resolver, connection_factory=Connection), events


def test_transport_ignores_environment_credentials_cookies_and_proxy(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://secret:password@127.0.0.1:9999')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:9999')
    monkeypatch.setenv('AUTHORIZATION', 'Bearer secret')
    reader, events = transport([Response(status=302, headers={'Location': '/final', 'Set-Cookie': 'session=secret'}), Response()])
    captured = reader.read(GUIDE)
    assert captured.final_url == 'https://docs.example/final'
    assert captured.requested_url == GUIDE
    for event in events:
        if event[0] == 'request':
            assert event[1] == 'GET'
            assert event[3] == {'Accept': 'text/html, text/plain, application/xhtml+xml'}
        if event[0] == 'connect':
            assert event[1:4] == ('docs.example', 443, '93.184.216.34')
            assert 0 < event[4] <= 15


@pytest.mark.parametrize('url', ['http://docs.example/policy', 'https://user:secret@docs.example/policy',
                                  'https://docs.example:bad/policy', 'https://docs.example/a\r\nb',
                                  'file:///tmp/policy', 'https://docs.example\\evil/policy'])
def test_transport_rejects_invalid_url_before_connect(url):
    from aidast.scope.policy_transport import PolicyReferenceError
    reader, events = transport([])
    with pytest.raises(PolicyReferenceError):
        reader.read(url)
    assert events == []


@pytest.mark.parametrize('address', ['127.0.0.1', '10.1.2.3', '169.254.169.254', '::1', 'fc00::1', '224.0.0.1'])
def test_transport_rejects_private_or_multicast_dns_before_connect(address):
    from aidast.scope.policy_transport import PolicyReferenceError
    def resolver(host, port, **kwargs):
        return [(2, 1, 6, '', (address, port))]
    reader, events = transport([], resolver)
    with pytest.raises(PolicyReferenceError, match='non-public'):
        reader.read(GUIDE)
    assert events == []


def test_transport_validates_redirect_destination_and_mixed_dns():
    from aidast.scope.policy_transport import PolicyReferenceError
    def resolver(host, port, **kwargs):
        answers = public_addresses(host, port)
        return answers if host == 'docs.example' else [*answers, (2, 1, 6, '', ('127.0.0.1', port))]
    reader, events = transport([Response(status=302, headers={'Location': 'https://internal.example/policy'})], resolver)
    with pytest.raises(PolicyReferenceError, match='non-public'):
        reader.read(GUIDE)
    assert len([e for e in events if e[0] == 'connect']) == 1


@pytest.mark.parametrize('response', [
    Response(headers={'Content-Type': 'application/pdf'}),
    Response(headers={'Content-Type': 'text/plain', 'Content-Length': str(1024 * 1024 + 1)}),
    Response(body=b'a' * (1024 * 1024 + 1)),
    Response(headers={'Content-Type': 'text/plain', 'Content-Encoding': 'gzip'}),
    Response(status=403), Response(body=b''),
])
def test_transport_fails_closed_on_unsupported_unreadable_and_oversized_response(response):
    from aidast.scope.policy_transport import PolicyReferenceError
    reader, _ = transport([response])
    with pytest.raises(PolicyReferenceError):
        reader.read(GUIDE)


def test_transport_stops_after_three_redirects():
    from aidast.scope.policy_transport import PolicyReferenceError
    reader, events = transport([Response(status=302, headers={'Location': f'/hop/{i}'}) for i in range(4)])
    with pytest.raises(PolicyReferenceError, match='redirect limit'):
        reader.read(GUIDE)
    assert len([e for e in events if e[0] == 'request']) == 4


def test_html_reader_observes_real_href_and_omits_script_content():
    body = '<h1>Policy</h1><p>Read <a href="/guide">안내서</a>.</p><script>secret()</script>'.encode()
    reader, _ = transport([Response(body=body, headers={'Content-Type': 'text/html; charset=utf-8'})])
    document = reader.read(GUIDE)
    assert '안내서' in document.text
    assert 'secret()' not in document.text
    assert document.observed_links[0].url == 'https://docs.example/guide'
    assert document.observed_links[0].source_url == GUIDE


@pytest.mark.parametrize('stage', ['headers', 'body'])
def test_absolute_deadline_interrupts_real_socketpair_slow_trickle(monkeypatch, stage):
    import http.client
    import socket
    import threading
    import time
    from aidast.scope import policy_transport as module
    monkeypatch.setattr(module, 'TIMEOUT_SECONDS', 0.08)
    client, server = socket.socketpair()
    class Connection:
        sock = client
        def __init__(self, *args):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            response = http.client.HTTPResponse(client)
            response.begin()
            return response
        def close(self):
            client.close()
    def trickle():
        try:
            if stage == 'headers':
                server.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
            else:
                server.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\n')
            for _ in range(100):
                server.sendall(b'x')
                time.sleep(0.01)
        except OSError:
            pass
        finally:
            server.close()
    worker = threading.Thread(target=trickle, daemon=True)
    worker.start()
    started = time.monotonic()
    reader = module.PublicPolicyDocumentReader(resolver=public_addresses, connection_factory=Connection)
    with pytest.raises(module.PolicyReferenceError):
        reader.read(GUIDE)
    assert time.monotonic() - started < 0.5
    worker.join(timeout=0.5)


def test_incomplete_initial_native_analysis_is_prepared_during_collection(tmp_path):
    class InitialLegacy(Agent):
        def collect_scope(self, _):
            return page().model_copy(update={'observed_links': []}), analysis().model_copy(update={'required_request_headers': None})
    document, _ = ScopeCoordinator(tmp_path / 'approved').collect_draft(URL, main_agent=InitialLegacy())
    assert document.analysis.required_request_headers == []


def test_direct_approval_rejects_incomplete_fresh_draft(tmp_path):
    from aidast.scope.models import ScopeDocument
    coordinator = ScopeCoordinator(tmp_path / 'approved')
    legacy = ScopeDocument(scope_id='incomplete-fresh', created_at=datetime.now(timezone.utc),
                           source=page(), analysis=analysis().model_copy(update={'required_request_headers': None}))
    draft = coordinator._create_scope_draft(legacy)
    with pytest.raises(CoordinatorError, match='required_request_headers'):
        coordinator.approve_draft(draft, approved_by='operator')
    assert not coordinator.output_dir.exists()


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_native_collection_preserves_observed_links_before_final_analysis(module_name):
    import importlib
    from aidast.scope.models import ScopeCollectionResult
    adapter = importlib.import_module(module_name).CodexMainAgent()
    result = ScopeCollectionResult(final_url=URL, title='Program', capture_status='COMPLETE',
        capture_reason='NONE', captured_text=PRIMARY, observed_links=page().observed_links,
        analysis=analysis().model_copy(update={'required_request_headers': None}))
    with patch(f'{module_name}.identify_program'), patch.object(adapter, '_run_structured', return_value=result):
        captured, initial = adapter.collect_scope(URL)
    assert captured.observed_links == page().observed_links
    assert initial.required_request_headers is None


def test_runtime_reader_records_each_primary_view_before_navigation():
    from unittest.mock import MagicMock
    from aidast.scope.reader import RuntimeBrowserProgramPageReader
    from aidast.scope.models import ScopeNavigationDecision
    browser_page = MagicMock(url=URL)
    browser_page.title.return_value = 'Program'
    browser_page.locator.return_value.evaluate_all.side_effect = [
        [{'href': GUIDE, 'label': '안내서'}], [{'href': '/other-rules', 'label': 'Other'}]]
    decisions = iter([ScopeNavigationDecision(action='open', candidate_id=1),
                      ScopeNavigationDecision(action='capture', candidate_id=None)])
    reader = RuntimeBrowserProgramPageReader(identity='test-user', navigation_agent=lambda *_: next(decisions), output_fn=lambda _: None)
    control = MagicMock()
    def navigate(**_):
        assert browser_page.locator.return_value.evaluate_all.call_count == 1
        browser_page.url = URL + '/scope'
    control.click.side_effect = navigate
    with patch.object(reader, '_wait_for_stable_text', return_value=PRIMARY * 20), \
         patch.object(reader, '_navigation_candidates', return_value=([{'id': 1, 'label': 'Scope'}], {1: control})):
        captured = reader._capture_agent_guided(browser_page, URL)
    links = [link for view in captured.primary_views for link in view.observed_links]
    assert [link.source_url for link in links] == [URL, URL + '/scope']
    assert [link.url for link in links] == [GUIDE, 'https://program.example/other-rules']


@pytest.mark.parametrize('mode', ['primary', 'fallback'])
def test_primary_and_fallback_flow_enrich_before_final_save(tmp_path, mode):
    class Primary:
        def read(self, _):
            return page()
    class FallbackAgent(Agent):
        def collect_scope(self, _):
            return page().model_copy(update={'capture_status': CaptureStatus.PARTIAL,
                'capture_reason': CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE}), analysis()
    kwargs = {'primary_reader': Primary()} if mode == 'primary' else {'fallback_reader': Primary()}
    document, _ = ScopeCoordinator(tmp_path / 'approved', reference_reader=Reader()).collect_draft(URL, main_agent=FallbackAgent(), **kwargs)
    assert document.analysis.execution_rules.request_limits[0].maximum == 3


def test_reference_headers_are_grounded_in_both_saved_resolvers(tmp_path):
    from aidast.scope.models import ScopeDocument
    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.scope.policy_references import enrich_policy_references
    quote = 'Send X-Study: research on every request.'
    class HeaderReader(Reader):
        def read(self, url):
            return super().read(url).model_copy(update={'text': quote})
    captured = enrich_policy_references(page(), Agent().select_policy_references, HeaderReader())
    data = analysis().model_dump()
    data['required_request_headers'] = [dict(name='X-Study', value_template='research', inputs=[], source_quote=quote)]
    data['source_evidence'].append(dict(section='Header', quote=quote))
    from aidast.scope.policy_references import require_unresolved_testing_holds
    reviewed = require_unresolved_testing_holds(captured, ScopeAnalysis(**data))
    document = ScopeDocument(scope_id='reference-header', created_at=datetime.now(timezone.utc), source=captured, analysis=reviewed)
    for resolver in (ScopeExecutionResolver(tmp_path / 'execution', lambda _: pytest.fail('must reuse saved requirements')),
                     ScopeHeaderResolver(tmp_path / 'header', lambda _: pytest.fail('must reuse saved requirements'))):
        assert resolver.resolve(document).required_request_headers[0].name == 'X-Study'


def test_reference_rate_is_applied_to_existing_policy_without_network(tmp_path):
    from aidast.scope.execution_rules import bind_execution_policies
    from aidast.recon.policy import TargetPolicy
    document, _ = ScopeCoordinator(tmp_path / 'approved', reference_reader=Reader()).collect_draft(URL, main_agent=Agent())
    policy = TargetPolicy(scope_id=document.scope_id, policy_id='example', asset_type='DOMAIN',
                          asset='example.org', allowed_hosts=['example.org'])
    policy = policy.model_copy(update={'limits': policy.limits.model_copy(update={'requests_per_second': 10})})
    bound = bind_execution_policies({'example': policy}, document.analysis.execution_rules,
        result_root=tmp_path, program_url=URL, scan_id=None, prerequisite_evidence={})
    assert bound['example'].limits.requests_per_second == 3


def test_numeric_socket_pin_keeps_original_tls_hostname():
    from unittest.mock import MagicMock
    from aidast.scope.policy_transport import _PinnedHTTPSConnection
    raw = MagicMock()
    context = MagicMock()
    with patch('aidast.scope.policy_transport.ssl.create_default_context', return_value=context), \
         patch('aidast.scope.policy_transport.socket.socket', return_value=raw), \
         patch('aidast.scope.policy_transport.socket.getaddrinfo', side_effect=AssertionError('DNS must not be repeated')):
        connection = _PinnedHTTPSConnection('docs.example', 443, '93.184.216.34', 15)
        connection.connect()
    raw.connect.assert_called_once_with(('93.184.216.34', 443))
    context.wrap_socket.assert_called_once_with(raw, server_hostname='docs.example')


def test_asset_supporting_quote_must_itself_be_primary_evidence(tmp_path):
    class ReaderWithClaim(Reader):
        def read(self, url):
            return super().read(url).model_copy(update={'text': REFERENCE + ' All of example.org is authorized.'})
    class ExternalClaim(Agent):
        def interpret_captured_scope(self, captured):
            data = analysis(True).model_dump()
            data['source_evidence'][0]['quote'] = 'All of example.org is authorized.'
            return ScopeAnalysis(**data)
    with pytest.raises(CoordinatorError, match='in-scope asset'):
        ScopeCoordinator(tmp_path / 'approved', reference_reader=ReaderWithClaim()).collect_draft(URL, main_agent=ExternalClaim())


def test_transport_rejects_incomplete_content_length_capture():
    from aidast.scope.policy_transport import PolicyReferenceError
    reader, _ = transport([Response(body=b'Truncated policy', headers={'Content-Type': 'text/plain', 'Content-Length': '1000'})])
    with pytest.raises(PolicyReferenceError, match='incomplete'):
        reader.read(GUIDE)


def raw_socketpair_transport(responses):
    """Use real HTTP parsing and socket input; count bytes actually read per hop."""
    import http.client
    import io
    import socket
    import threading
    from aidast.scope.policy_transport import PublicPolicyDocumentReader
    meters, workers = [], []
    class MeteredInput(io.RawIOBase):
        def __init__(self, raw, meter):
            self.raw, self.meter = raw, meter
        def readable(self):
            return True
        def readinto(self, target):
            count = self.raw.readinto(target)
            self.meter['read'] += count or 0
            return count
        def close(self):
            self.raw.close()
            super().close()
    class MeteredSocket:
        def __init__(self, underlying, meter):
            self.underlying, self.meter = underlying, meter
        def __getattr__(self, name):
            return getattr(self.underlying, name)
        def makefile(self, mode, buffering=-1):
            raw = MeteredInput(self.underlying.makefile(mode, buffering=0), self.meter)
            return raw if buffering == 0 else io.BufferedReader(raw)
    def factory(host, port, address, timeout):
        client, server = socket.socketpair()
        wire = responses.pop(0)
        meter = {'read': 0}
        meters.append(meter)
        def serve():
            try:
                request = bytearray()
                while b'\r\n\r\n' not in request:
                    chunk = server.recv(4096)
                    if not chunk:
                        return
                    request.extend(chunk)
                server.sendall(wire)
            except OSError:
                pass  # A bounded reader deliberately closes early on overflow.
            finally:
                server.close()
        worker = threading.Thread(target=serve, daemon=True)
        workers.append(worker)
        worker.start()
        connection = http.client.HTTPConnection(host, port=port, timeout=timeout)
        client.settimeout(timeout)
        connection.sock = MeteredSocket(client, meter)
        return connection
    return PublicPolicyDocumentReader(resolver=public_addresses, connection_factory=factory), meters, workers


def raw_sized_response(size, status=b'200 OK', extra_headers=b''):
    body = b'Public rules'
    prefix = b'HTTP/1.1 ' + status + b'\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n' + extra_headers + b'X-Padding: '
    suffix = b'\r\n\r\n' + body
    assert size >= len(prefix) + len(suffix)
    return prefix + b'a' * (size - len(prefix) - len(suffix)) + suffix


@pytest.mark.parametrize('extra', [0, 1])
def test_raw_response_content_length_exact_boundary(monkeypatch, extra):
    from aidast.scope import policy_transport as module
    limit = 256
    monkeypatch.setattr(module, 'MAX_RESPONSE_BYTES', limit)
    reader, meters, workers = raw_socketpair_transport([raw_sized_response(limit + extra)])
    try:
        if extra:
            with pytest.raises(module.PolicyReferenceError, match='raw response byte budget'):
                reader.read(GUIDE)
        else:
            assert reader.read(GUIDE).text == 'Public rules'
        assert meters[0]['read'] <= limit
    finally:
        for worker in workers:
            worker.join(timeout=1)


@pytest.mark.parametrize('case', ['status', 'headers', 'chunk_extensions', 'trailers', 'interim', 'redirect', 'non200'])
def test_raw_response_budget_includes_http_parser_input(monkeypatch, case):
    from aidast.scope import policy_transport as module
    limit = 256
    monkeypatch.setattr(module, 'MAX_RESPONSE_BYTES', limit)
    headers = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n'
    if case == 'status':
        wire = raw_sized_response(400, status=b'200 ' + b'R' * 260)
    elif case == 'headers':
        wire = raw_sized_response(400)
    elif case == 'chunk_extensions':
        wire = headers + b'1;' + b'e' * 260 + b'\r\na\r\n0\r\n\r\n'
    elif case == 'trailers':
        wire = headers + b'1\r\na\r\n0\r\nX-Trailer: ' + b't' * 260 + b'\r\n\r\n'
    elif case == 'interim':
        wire = b'HTTP/1.1 100 Continue\r\nX-Interim: ' + b'i' * 170 + b'\r\n\r\n' + raw_sized_response(128)
    elif case == 'redirect':
        wire = raw_sized_response(400, status=b'302 Found', extra_headers=b'Location: /next\r\n')
    else:
        wire = raw_sized_response(400, status=b'403 Forbidden')
    reader, meters, workers = raw_socketpair_transport([wire, raw_sized_response(128)])
    try:
        with pytest.raises(module.PolicyReferenceError) as failure:
            reader.read(GUIDE)
        assert len(meters) == 1, 'an over-budget redirect must not make the next request'
        assert meters[0]['read'] == limit, 'input must stop at the cumulative limit before parsing more bytes'
        assert 'raw response byte budget' in str(failure.value)
    finally:
        for worker in workers:
            worker.join(timeout=1)


def test_raw_response_budget_resets_for_each_redirect_hop(monkeypatch):
    from aidast.scope import policy_transport as module
    limit = 256
    monkeypatch.setattr(module, 'MAX_RESPONSE_BYTES', limit)
    wire = raw_sized_response(limit, status=b'302 Found', extra_headers=b'Location: /next\r\n')
    reader, meters, workers = raw_socketpair_transport([wire, raw_sized_response(limit)])
    try:
        assert reader.read(GUIDE).text == 'Public rules'
        assert len(meters) == 2
        assert all(item['read'] <= limit for item in meters)
    finally:
        for worker in workers:
            worker.join(timeout=1)


def structured_page():
    """Two views of one URL deliberately reuse candidate IDs, as browser tabs do."""
    data = page().model_dump()
    data['observed_links'] = []
    data['primary_views'] = [
        dict(url=URL, text='example.org is in scope. No denial of service.',
             observed_links=[dict(candidate_id=7, url='https://docs.example/other', label='Other', source_url=URL)]),
        dict(url=URL, text='Read the 안내서 for testing rules.', observed_links=[
            dict(candidate_id=7, url=GUIDE, label='안내서', source_url=URL)]),
    ]
    return ProgramPage.model_validate(data)


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_native_structured_views_reach_offline_selection_and_saved_rules(tmp_path, module_name):
    import importlib
    from aidast.scope.models import ScopeCollectionResult, PolicyReferenceSelection
    adapter = importlib.import_module(module_name).CodexMainAgent()
    source = structured_page()
    data = source.model_dump()
    data['primary_views'][0]['observed_links'] = [dict(candidate_id=i,
        url=f'https://docs.example/irrelevant/{i}', label=str(i), source_url=URL) for i in range(128)]
    source = ProgramPage.model_validate(data)
    result = ScopeCollectionResult(final_url=URL, title='Program', capture_status='COMPLETE',
        capture_reason='NONE', captured_text=source.text, primary_views=source.primary_views,
        analysis=analysis())
    selection_inputs = []
    def run(**kwargs):
        if kwargs['model_type'] is ScopeCollectionResult:
            return result
        assert kwargs['allow_browser'] is False
        if kwargs['model_type'] is PolicyReferenceSelection:
            import json
            supplied = json.loads(kwargs['prompt'].split('Parent capture and candidates JSON:\n')[1])
            selection_inputs.append(supplied)
            return PolicyReferenceSelection(selections=[dict(candidate_id=link['candidate_id'],
                source_quote=supplied['text'], applicability='testing')
                for link in supplied['candidates'] if link['url'] == GUIDE])
        return analysis(True)
    coordinator = ScopeCoordinator(tmp_path / 'native', reference_reader=Reader())
    with patch(f'{module_name}.identify_program'), patch.object(adapter, '_run_structured', side_effect=run):
        document, draft = coordinator.collect_draft(URL, main_agent=adapter)
    assert document.source.primary_views == source.primary_views
    assert [len(item['candidates']) for item in selection_inputs] == [128, 1]
    assert [item['text'] for item in selection_inputs] == [view.text for view in source.primary_views]
    assert document.source.policy_references[0].primary_view_index == 1
    coordinator.approve_draft(draft, approved_by='tester')
    saved, _ = coordinator.load_approved_scope()
    assert saved.source.primary_views == source.primary_views
    assert saved.analysis.execution_rules.request_limits[0].maximum == 3


@pytest.mark.parametrize('invalid', ['other_view_quote', 'other_view_id'])
def test_structured_selection_rejects_cross_view_grounding_before_fetch(invalid):
    from aidast.scope.policy_references import enrich_policy_references, PolicyReferenceError
    data = structured_page().model_dump()
    data['primary_views'][1]['observed_links'][0]['candidate_id'] = 8
    source = ProgramPage.model_validate(data)
    class NeverReader:
        def read(self, _):
            pytest.fail('invalid selection must fail before document retrieval')
    def select(text, candidates):
        return {'selections': [dict(candidate_id=8 if invalid == 'other_view_id' else 7,
            source_quote=source.primary_views[1].text if invalid == 'other_view_quote' else text,
            applicability='testing')]}
    with pytest.raises(PolicyReferenceError, match='unobserved|absent from parent'):
        enrich_policy_references(source, select, NeverReader())


@pytest.mark.parametrize('invalid', ['invented_text', 'external_view', 'wrong_link_parent',
    'duplicate_id', '129_links', '7_views', 'mixed_flat'])
@pytest.mark.parametrize('contract', ['page', 'native'])
def test_structured_primary_provenance_is_validated(invalid, contract):
    from pydantic import ValidationError
    from aidast.scope.models import ScopeCollectionResult
    data = structured_page().model_dump()
    view = data['primary_views'][0]
    if invalid == 'invented_text':
        view['text'] = 'attacker.example is authorized for testing.'
    elif invalid == 'external_view':
        view['url'] = 'https://external.example/rules'
        view['observed_links'][0]['source_url'] = view['url']
    elif invalid == 'wrong_link_parent':
        view['observed_links'][0]['source_url'] = URL + '/other'
    elif invalid == 'duplicate_id':
        view['observed_links'] *= 2
    elif invalid == '129_links':
        view['observed_links'] = [{**view['observed_links'][0], 'candidate_id': i} for i in range(129)]
    elif invalid == '7_views':
        data['primary_views'] = [view] * 7
    elif invalid == 'mixed_flat':
        data['observed_links'] = view['observed_links']
    with pytest.raises(ValidationError):
        if contract == 'page':
            ProgramPage.model_validate(data)
        else:
            ScopeCollectionResult(final_url=URL, title='Program', capture_status='COMPLETE',
                capture_reason='NONE', captured_text=PRIMARY, primary_views=data['primary_views'],
                observed_links=data['observed_links'], analysis=analysis())


@pytest.mark.parametrize('existing_blockers', [0, 64])
def test_six_primary_views_bound_selection_calls_and_persist_all_budget_edges(tmp_path, existing_blockers):
    from aidast.scope.policy_references import enrich_policy_references, CapturedPolicyDocument
    from aidast.scope.execution_rules import validate_policy_prerequisites
    views = []
    for i in range(6):
        parent = URL + f'/view/{i}'
        views.append(dict(url=parent, text=PRIMARY + f' View {i} lists applicable testing documents.',
            observed_links=[dict(candidate_id=j, url=f'https://docs.example/view/{i}/{j}',
                label='Guide', source_url=parent) for j in range(8)]))
    data = page().model_dump()
    data.update(primary_views=views, observed_links=[], text='\n'.join(view['text'] for view in views))
    data['content_sha256'] = hashlib.sha256(data['text'].encode()).hexdigest()
    calls, selections = [], []
    def select(text, candidates):
        selections.append(text)
        return {'selections': [dict(candidate_id=item.candidate_id, source_quote=text,
            applicability='unknown') for item in candidates]}
    class NestedReader:
        def read(self, url):
            calls.append(url)
            return CapturedPolicyDocument(requested_url=url, final_url=url,
                captured_at=datetime.now(timezone.utc), text=f'Nested rules at {url}',
                observed_links=[dict(candidate_id=i, url=f'{url}/nested/{i}', label='Nested',
                    source_url=url) for i in range(8)])
    source = ProgramPage.model_validate(data)
    initial = analysis().model_dump()
    original_blockers = [dict(target_assets=[], label=f'Existing obligation {i}',
        source_quote='No denial of service.', reason='Existing unresolved testing obligation')
        for i in range(existing_blockers)]
    initial['source_evidence'].append(dict(section='Original testing restrictions', quote='No denial of service.'))
    initial['execution_rules']['blocking_requirements'] = original_blockers
    prepared = ScopeAnalysis.model_validate(initial)
    class MaximumAgent(Agent):
        def collect_scope(self, _):
            return source, prepared
        def select_policy_references(self, text, candidates):
            return select(text, candidates)
        def interpret_captured_scope(self, _):
            return prepared
    coordinator = ScopeCoordinator(tmp_path / 'maximum', reference_reader=NestedReader())
    document, draft = coordinator.collect_draft(URL, main_agent=MaximumAgent())
    enriched = document.source
    assert len(calls) == 8
    assert len(selections) == 14
    assert len(enriched.policy_references) == 112
    captured = [item for item in enriched.policy_references if item.status == 'captured']
    unresolved = [item for item in enriched.policy_references if item.status == 'unresolved']
    assert len(captured) == 8
    assert len(unresolved) == 104
    assert {item.error for item in unresolved} == {'reference document budget exhausted'}
    assert {item.primary_view_index for item in enriched.policy_references} == {None, 0, 1, 2, 3, 4, 5}
    assert len(enriched.evidence_text) <= 120000
    blockers = document.analysis.execution_rules.blocking_requirements
    assert len(blockers) == existing_blockers
    assert [item.model_dump() for item in blockers] == original_blockers
    advisories = document.analysis.execution_rules.advisories
    assert len(advisories) == 104
    assert [item.source_quote for item in advisories] == [item.source_quote for item in unresolved]
    coordinator.approve_draft(draft, approved_by='tester')
    saved, _ = coordinator.load_approved_scope()
    assert saved.source.policy_references == enriched.policy_references
    def forbidden(_):
        pytest.fail('saved reviewed Scope must not invoke interpretation')
    resolved = ScopeExecutionResolver(tmp_path / 'cache', interpreter=forbidden).resolve(saved)
    assert resolved.execution_rules.blocking_requirements == blockers
    assert resolved.execution_rules.advisories == advisories
    if existing_blockers:
        with pytest.raises(ValueError, match='unsupported mandatory requirements'):
            validate_policy_prerequisites(resolved.execution_rules, ['example.org'])
    else:
        validate_policy_prerequisites(resolved.execution_rules, ['example.org'])


def test_same_url_and_candidate_id_in_distinct_views_preserve_parent_provenance():
    from aidast.scope.policy_references import enrich_policy_references
    source = structured_page()
    def select(text, candidates):
        return {'selections': [dict(candidate_id=7, source_quote=text, applicability='testing')]}
    enriched = enrich_policy_references(source, select, Reader())
    assert [item.primary_view_index for item in enriched.policy_references] == [0, 1]
    assert [item.source_quote for item in enriched.policy_references] == [view.text for view in source.primary_views]
    assert [item.requested_url for item in enriched.policy_references] == ['https://docs.example/other', GUIDE]


def test_persisted_primary_edge_cannot_claim_another_view():
    from pydantic import ValidationError
    from aidast.scope.policy_references import enrich_policy_references
    source = structured_page()
    enriched = enrich_policy_references(source, lambda text, candidates: {'selections': [
        dict(candidate_id=7, source_quote=text, applicability='testing')]}, Reader())
    data = enriched.model_dump()
    data['policy_references'][1]['primary_view_index'] = 0
    with pytest.raises(ValidationError, match='primary view'):
        ProgramPage.model_validate(data)


def test_fresh_hold_preparation_rejects_more_than_64_extracted_blockers():
    from aidast.scope.policy_references import require_unresolved_testing_holds, PolicyReferenceError
    from aidast.scope.models import BlockingRequirement
    original = analysis()
    blocker = BlockingRequirement(label='Existing unresolved rule', target_assets=[],
        source_quote='example.org is in scope.', reason='Needs review')
    # Bypass the old schema cap only to test the preparation boundary itself.
    raw = original.model_copy(update={'execution_rules': original.execution_rules.model_copy(
        update={'blocking_requirements': [blocker] * 65})})
    with pytest.raises(PolicyReferenceError, match='extracted.*64'):
        require_unresolved_testing_holds(page(), raw)


def test_persisted_advisory_capacity_reserves_every_bounded_reference_edge():
    from pydantic import ValidationError
    from aidast.scope.models import PolicyReferenceCapture, PolicyAdvisory
    from aidast.scope.policy_references import require_unresolved_testing_holds, PolicyReferenceError
    source = page()
    unresolved = PolicyReferenceCapture(candidate_id=7, parent_url=URL, requested_url=GUIDE,
        source_quote=PRIMARY, applicability='unknown', depth=1,
        captured_at=datetime.now(timezone.utc), status='unresolved', error='reference document budget exhausted')
    source = ProgramPage.model_validate(source.model_copy(update={'policy_references': [unresolved] * 112}).model_dump())
    original = analysis()
    advisory = PolicyAdvisory(label='Existing unresolved rule', target_assets=[],
        source_quote='example.org is in scope.', reason='Needs review', guidance='Avoid unclear operations and record why.')
    raw = original.model_copy(update={'execution_rules': original.execution_rules.model_copy(
        update={'advisories': [advisory] * 64})})
    prepared = require_unresolved_testing_holds(source, raw)
    assert len(prepared.execution_rules.advisories) == 176
    assert prepared.execution_rules.advisories[:64] == [advisory] * 64
    assert [item.source_quote for item in prepared.execution_rules.advisories[64:]] == [PRIMARY] * 112
    # Saved capacity must not become raw model capacity or grow on re-preparation.
    with pytest.raises(PolicyReferenceError, match='extracted.*64'):
        require_unresolved_testing_holds(source, prepared)
    oversized = prepared.model_dump()
    oversized['execution_rules']['advisories'].append(advisory.model_dump())
    with pytest.raises(ValidationError, match='at most 176'):
        ScopeAnalysis.model_validate(oversized)
