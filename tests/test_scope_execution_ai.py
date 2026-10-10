"""Offline contract tests: AI decisions are preserved; evidence is not trusted."""
import hashlib
import pytest

from aidast.agents import main, native_pipeline
from aidast.orchestration.scope import ScopeCoordinator, CoordinatorError
from aidast.scope.models import ScopeAnalysis, ScopeDocument
from test_scope_workflow import sample_page, sample_analysis

RATE = 'Keep requests to 10 per second or lower.'
EMAIL = 'Use @wearehackerone.com email addresses for testing.'
CONTACT = 'Contact us before testing production.'
UNSUPPORTED = 'All traffic must use our proprietary signed VPN.'
ADVICE = 'We recommend testing on weekdays.'
ASSET = '*.example.com'


def capture():
    page = sample_page()
    text = page.text + '\n' + '\n'.join([RATE, EMAIL, CONTACT, UNSUPPORTED, ADVICE])
    return page.model_copy(update={'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()})


def rules():
    return {
        'exclusions': [],
        'request_limits': [{'maximum': 10, 'period_seconds': 1, 'scope': 'program', 'source_quote': RATE}],
        'required_inputs': [{'key': 'testing_email', 'label': 'Testing email', 'kind': 'email',
                             'allowed_email_domains': ['wearehackerone.com'], 'source_quote': EMAIL}],
        'required_confirmations': [{'key': 'production_contact', 'label': 'Contacted program',
                                   'target_assets': [ASSET], 'source_quote': CONTACT}],
        'blocking_requirements': [{'label': 'Signed VPN', 'reason': 'Unsupported transport control',
                                  'source_quote': UNSUPPORTED}],
    }


def fresh_analysis():
    data = sample_analysis().model_dump()
    data['execution_rules'] = rules()
    data['source_evidence'] += [{'section': 'Execution', 'quote': q} for q in [RATE, EMAIL, CONTACT, UNSUPPORTED]]
    return ScopeAnalysis.model_validate(data)


@pytest.fixture(params=[main, native_pipeline], ids=['main', 'native'])
def adapter(request):
    return request.param


def fake_response(monkeypatch, adapter, payload):
    agent = adapter.CodexMainAgent()
    def respond(**kwargs):
        assert kwargs['allow_browser'] is False
        return kwargs['model_type'].model_validate(payload)
    monkeypatch.setattr(agent, '_run_structured', respond)
    return agent


def test_capture_only_interpretation_preserves_ai_restrictions_and_optional_advice(monkeypatch, adapter):
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': rules()})
    result = agent.interpret_scope_execution_requirements(capture())
    assert result.execution_rules.request_limits[0].maximum == 10
    assert result.execution_rules.request_limits[0].period_seconds == 1
    assert result.execution_rules.required_inputs[0].allowed_email_domains == ['wearehackerone.com']
    assert result.execution_rules.required_confirmations[0].target_assets == [ASSET]
    assert result.execution_rules.blocking_requirements[0].label == 'Signed VPN'
    assert all(item.source_quote != ADVICE for item in result.execution_rules.quoted_requirements())


def test_empty_ai_decision_does_not_infer_rules_from_incidental_numbers(monkeypatch, adapter):
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': {'exclusions': []}})
    assert agent.interpret_scope_execution_requirements(capture()).execution_rules.quoted_requirements() == []


@pytest.mark.parametrize('method', ['interpret_scope_execution_requirements', 'interpret_scope_header_requirements'])
def test_feasible_identification_is_an_automatically_supported_control(monkeypatch, adapter, method):
    agent = adapter.CodexMainAgent()
    def respond(**kwargs):
        assert 'whenever feasible' in kwargs['prompt']
        assert 'required_request_headers' in kwargs['prompt']
        assert 'automatically' in kwargs['prompt']
        assert 'not merely an advisory' in kwargs['prompt']
        payload = {'required_request_headers': []}
        if method == 'interpret_scope_execution_requirements':
            payload['execution_rules'] = {'exclusions': []}
        return kwargs['model_type'].model_validate(payload)
    monkeypatch.setattr(agent, '_run_structured', respond)
    getattr(agent, method)(capture())


def test_interpretation_rejects_fabricated_capture_evidence(monkeypatch, adapter):
    response = rules()
    response['request_limits'][0]['source_quote'] = 'Invented ceiling'
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': response})
    with pytest.raises(adapter.MainAgentError, match='quote'):
        agent.interpret_scope_execution_requirements(capture())


def test_interpretation_enforces_capture_and_response_bounds(monkeypatch, adapter):
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': {'exclusions': []}})
    agent._max_page_chars = 10
    with pytest.raises(adapter.MainAgentError, match='budget'):
        agent.interpret_scope_execution_requirements(capture())
    agent._max_page_chars = 120000
    quote = 'x' * 16000
    response = {'blocking_requirements': [{'label': str(i), 'reason': 'unsupported', 'source_quote': quote} for i in range(20)]}
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': response})
    with pytest.raises(adapter.MainAgentError, match='budget'):
        agent.interpret_scope_execution_requirements(capture().model_copy(update={'text': quote}))


def test_fresh_adapter_rejects_missing_rules_but_accepts_grounded_rules(adapter):
    with pytest.raises(adapter.MainAgentError, match='execution_rules'):
        adapter.CodexMainAgent._verify_grounding(capture(), fresh_analysis().model_copy(update={'execution_rules': None}))
    adapter.CodexMainAgent._verify_grounding(capture(), fresh_analysis())


def test_fresh_coordinator_rejects_missing_execution_decision():
    with pytest.raises(CoordinatorError, match='execution_rules'):
        ScopeCoordinator._require_grounded_analysis(capture(), fresh_analysis().model_copy(update={'execution_rules': None}))


def test_fresh_coordinator_rejects_tampered_approved_target_binding():
    analysis = fresh_analysis()
    analysis.execution_rules.required_confirmations[0].target_assets = ['https://unapproved.example/']
    with pytest.raises(ValueError, match='exact approved asset'):
        ScopeCoordinator._require_grounded_analysis(capture(), analysis)


def test_approval_displays_execution_limits_prerequisites_and_evidence():
    page = capture()
    document = ScopeDocument(scope_id='review', created_at=page.captured_at, source=page, analysis=fresh_analysis())
    markdown = ScopeCoordinator._render_markdown(document)
    section = markdown.split('## Execution requirements', 1)[1].split('## Safe harbor', 1)[0]
    for expected in ['10', '1', 'program', 'Testing email', 'wearehackerone.com',
                     'Contacted program', 'Signed VPN', 'Unsupported transport control', RATE, EMAIL, CONTACT, UNSUPPORTED]:
        assert expected in section
    assert 'acknowledg' in section.lower()
    assert 'example.com' in section


@pytest.mark.parametrize('missing', ['execution_rules', 'required_request_headers'])
def test_combined_interpretation_requires_explicit_decisions(monkeypatch, adapter, missing):
    payload = {'required_request_headers': [], 'execution_rules': {'exclusions': []}}
    del payload[missing]
    agent = fake_response(monkeypatch, adapter, payload)
    with pytest.raises(ValueError, match=missing):
        agent.interpret_scope_execution_requirements(capture())


def test_fresh_grounding_rejects_quotes_not_in_source_evidence(adapter):
    analysis = fresh_analysis()
    analysis.source_evidence = analysis.source_evidence[:1]
    with pytest.raises(ValueError, match='source evidence'):
        adapter.CodexMainAgent._verify_grounding(capture(), analysis)


def test_fresh_grounding_rejects_evidence_absent_from_capture(adapter):
    with pytest.raises(adapter.MainAgentError, match='quote'):
        adapter.CodexMainAgent._verify_grounding(sample_page(), fresh_analysis())


def test_approval_displays_total_quotas_option_caps_and_permission_restrictions():
    page = capture()
    data = fresh_analysis().model_dump()
    quote = 'Use GET only, at concurrency one, and never exceed 20 total requests.'
    data['source_evidence'].append({'section': 'Execution', 'quote': quote})
    data['execution_rules'] = {
        'request_limits': [{'maximum': 20, 'period_seconds': None, 'scope': 'scan', 'source_quote': quote}],
        'option_limits': [{'field': 'concurrency', 'value': 1, 'source_quote': quote}],
        'allowed_methods': {'values': ['GET'], 'source_quote': quote},
        'allowed_target_assets': {'values': [ASSET], 'source_quote': quote},
    }
    doc = ScopeDocument(scope_id='review', created_at=page.captured_at, source=page,
                        analysis=ScopeAnalysis.model_validate(data))
    markdown = ScopeCoordinator._render_markdown(doc)
    section = markdown.split('## Execution requirements', 1)[1].split('## Safe harbor', 1)[0]
    assert '20 requests total/lifetime quota; scope: scan' in section
    assert 'concurrency = 1' in section
    assert 'Allowed methods: GET' in section
    assert 'Allowed target assets:' in section
    assert quote in section


def test_legacy_markdown_stays_readable_without_interpretation():
    page = sample_page()
    analysis = sample_analysis().model_copy(update={'execution_rules': None})
    document = ScopeDocument(scope_id='legacy', created_at=page.captured_at, source=page, analysis=analysis)
    assert 'AI execution interpretation required before launch' in ScopeCoordinator._render_markdown(document)


@pytest.mark.parametrize('corrected', [True, False], ids=['corrected', 'still-invalid'])
def test_interpretation_retries_grounding_once_using_same_capture(monkeypatch, adapter, corrected):
    import json
    agent = adapter.CodexMainAgent()
    page = capture()
    prompts = []
    def respond(**kwargs):
        prompts.append(kwargs['prompt'])
        assert kwargs['allow_browser'] is False
        assert json.dumps(page.text, ensure_ascii=False) in kwargs['prompt']
        result = rules()
        if len(prompts) == 1 or not corrected:
            result['request_limits'][0]['source_quote'] = 'Invented ceiling'
        return kwargs['model_type'].model_validate({'required_request_headers': [], 'execution_rules': result})
    monkeypatch.setattr(agent, '_run_structured', respond)
    if corrected:
        result = agent.interpret_scope_execution_requirements(page)
        assert result.execution_rules.request_limits[0].source_quote == RATE
    else:
        with pytest.raises(adapter.MainAgentError, match='quote'):
            agent.interpret_scope_execution_requirements(page)
    assert len(prompts) == 2
    assert 'source quote absent from approved capture' in prompts[1]
    assert 'Invented ceiling' in prompts[1]


def test_approval_displays_blocker_target_binding():
    data = fresh_analysis().model_dump()
    data['execution_rules']['blocking_requirements'][0]['target_assets'] = [ASSET]
    analysis = ScopeAnalysis.model_validate(data)
    page = capture()
    doc = ScopeDocument(scope_id='conditional', created_at=page.captured_at, source=page, analysis=analysis)
    section = ScopeCoordinator._render_markdown(doc).split('Signed VPN', 1)[1].split('\n', 1)[0]
    assert ASSET in section


def test_interpretation_prompt_preserves_conditional_unsupported_controls(monkeypatch, adapter):
    agent = adapter.CodexMainAgent()
    def respond(**kwargs):
        prompt = kwargs['prompt']
        assert 'blocking_requirements: label, source_quote, reason, target_assets' in prompt
        assert 'OTHER' in prompt
        assert 'unrelated targets' in prompt
        return kwargs['model_type'].model_validate({'required_request_headers': [], 'execution_rules': {'exclusions': []}})
    monkeypatch.setattr(agent, '_run_structured', respond)
    agent.interpret_scope_execution_requirements(capture())


def test_fresh_grounding_rejects_unapproved_blocker_binding(adapter):
    data = fresh_analysis().model_dump()
    data['execution_rules']['blocking_requirements'][0]['target_assets'] = ['https://unapproved.example/']
    with pytest.raises(ValueError, match='exact approved asset'):
        adapter.CodexMainAgent._verify_grounding(capture(), ScopeAnalysis.model_validate(data))


def test_interpretation_preserves_conditional_blocker_binding(monkeypatch, adapter):
    response = rules()
    response['blocking_requirements'][0]['target_assets'] = [ASSET]
    agent = fake_response(monkeypatch, adapter, {'required_request_headers': [], 'execution_rules': response})
    assert agent.interpret_scope_execution_requirements(capture()).execution_rules.blocking_requirements[0].target_assets == [ASSET]
