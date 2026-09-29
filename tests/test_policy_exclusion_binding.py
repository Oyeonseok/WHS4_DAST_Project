"""Offline safety boundary: immutable evidence, explicit freshness, no dispatch."""
import hashlib
import json
import time

import pytest

from aidast.agents import main, native_pipeline
from aidast.core.exclusion_guard import evaluate_exclusions, request_key
from aidast.scope import execution_rules
from aidast.scope.exclusions import ResourceCandidate, ResourceEvidence, ScopeExclusion
from aidast.scope.models import ScopeAnalysis, ScopeDocument, ScopeExecutionRules
from aidast.orchestration.scope import ScopeCoordinator, CoordinatorError
from test_scope_workflow import sample_page, sample_analysis

QUOTE = 'Do not test customer assistance functionality.'
TARGET = '*.example.com'


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def rule():
    return ScopeExclusion(key='restriction-1', label='Customer assistance', source_quote=QUOTE,
        target_assets=[TARGET], condition={'operator': 'predicate', 'predicate': {
            'key': 'category-1', 'field': 'semantic', 'operator': 'equals',
            'value': 'customer assistance functionality'}})


def inputs():
    candidates, evidence = [], []
    for cid, eid, path, excerpt in [
        ('candidate-alpha', 'evidence-alpha', '/q7', 'This page opens a conversation with a customer assistance specialist.'),
        ('candidate-beta', 'evidence-beta', '/v2/letters', 'Send this request to submit a customer assistance case.'),
        ('candidate-gamma', 'evidence-gamma', '/p9', 'This page displays the public release history of the product.')]:
        url = 'https://app.example.com' + path
        candidates.append(ResourceCandidate(candidate_id=cid, request_key=request_key(url, 'GET'),
            url=url, method='GET', body_sha256=digest(''), evidence_ids=[eid]))
        evidence.append(ResourceEvidence(evidence_id=eid, candidate_ids=[cid], source_url=url,
            kind='captured_response', content_sha256=digest(excerpt), excerpt=excerpt,
            captured_at=time.time() - 60))
    return dict(scope_digest=digest('approved-scope'), target_asset=TARGET, rules=[rule()],
                candidates=candidates, evidence=evidence)


def decisions(context):
    return {'decisions': [dict(candidate_id=c['candidate_id'], rule_key='restriction-1',
        predicate_key='category-1', classification='nonmatch' if c['candidate_id'] == 'candidate-gamma' else 'match',
        reason='The cited content affirmatively describes the function of this resource.',
        citations=[dict(evidence_id=e['evidence_id'], quote=e['excerpt'])])
        for c, e in zip(context['candidates'], context['evidence'])]}


def resolver(tmp_path, interpreter=decisions):
    from aidast.scope import exclusion_binding
    return exclusion_binding.ExclusionBindingResolver(tmp_path, interpreter)


def gate(policy, candidate, **kwargs):
    return evaluate_exclusions(policy.model_dump(mode='json'), url=candidate.url, method=candidate.method,
                               body_available=True, **kwargs)['decision']


def test_semantic_category_binds_unrelated_names_and_affirmative_nonmatch(tmp_path):
    data = inputs()
    policy = resolver(tmp_path).resolve(**data)
    assert [gate(policy, c) for c in data['candidates']] == ['deny', 'deny', 'continue']
    assert policy.expires_at == min(e.captured_at for e in data['evidence']) + 86400


@pytest.mark.parametrize('mutation', ['unrelated', 'invented', 'noncontiguous', 'missing', 'no-evidence', 'wrong-id', 'duplicate'])
def test_invalid_classification_cannot_authorize(tmp_path, mutation):
    data = inputs()
    def classify(context):
        result = decisions(context)
        d = result['decisions'][2]
        if mutation == 'unrelated':
            d['citations'] = result['decisions'][0]['citations']
        elif mutation == 'invented':
            d['citations'][0]['quote'] = 'This endpoint is safe and unrelated.'
        elif mutation == 'noncontiguous':
            d['citations'][0]['quote'] = 'This page displays the product.'
        elif mutation == 'missing':
            result['decisions'].pop()
        elif mutation == 'no-evidence':
            d['reason'] = 'No assistance words were found.'
            d['citations'] = []
        elif mutation == 'wrong-id':
            d['candidate_id'] = 'invented-candidate'
        else:
            result['decisions'].append(d.copy())
        return result
    assert gate(resolver(tmp_path, classify).resolve(**data), data['candidates'][2]) == 'hold'


def test_changed_full_request_never_inherits_nonmatch(tmp_path):
    data = inputs()
    policy = resolver(tmp_path).resolve(**data)
    candidate = data['candidates'][2]
    assert gate(policy, candidate, headers={'X-Identity': 'new'}) == 'hold'
    assert gate(policy, candidate, body=b'changed') == 'hold'
    assert gate(policy, candidate, context={'session': 'new'}) == 'hold'


@pytest.mark.parametrize('age', [None, -30, 86401])
def test_missing_future_expired_evidence_cannot_authorize(tmp_path, age):
    data = inputs()
    data['evidence'] = [e.model_copy(update={'captured_at': None if age is None else time.time() - age}) for e in data['evidence']]
    assert gate(resolver(tmp_path).resolve(**data), data['candidates'][2]) == 'hold'


def test_cache_reads_never_classify_and_corruption_requires_explicit_refresh(tmp_path):
    data = inputs()
    calls = []
    def classify(context):
        calls.append(context)
        return decisions(context)
    binding = resolver(tmp_path, classify)
    policy = binding.resolve(**data)
    assert binding.cached(**data) == policy
    assert binding.resolve(**data) == policy
    assert len(calls) == 1
    path = next(tmp_path.glob('*.json'))
    path.write_text('{}')
    assert binding.cached(**data) is None
    assert gate(binding.resolve(**data), data['candidates'][2]) == 'hold'
    assert len(calls) == 1
    assert gate(binding.refresh(**data), data['candidates'][2]) == 'continue'
    assert len(calls) == 2


def test_cache_identity_covers_evidence_associations_and_scope(tmp_path):
    data = inputs()
    binding = resolver(tmp_path)
    binding.resolve(**data)
    for field, value in [('scope_digest', digest('changed')), ('target_asset', 'https://other.example.com/')]:
        assert binding.cached(**dict(data, **{field: value})) is None
    changed = list(data['evidence'])
    changed[2] = changed[2].model_copy(update={'excerpt': 'Changed capture'})
    assert binding.cached(**dict(data, evidence=changed)) is None


def test_direct_rules_and_empty_rules_need_no_classifier(tmp_path):
    data = inputs()
    data.update(candidates=[], evidence=[], rules=[])
    binding = resolver(tmp_path, lambda _: pytest.fail('direct policies must be offline and deterministic'))
    assert binding.resolve(**data).semantic_bindings == []
    data['rules'] = [ScopeExclusion(key='direct', label='Path', source_quote='Do not test /private.',
        condition={'operator': 'predicate', 'predicate': {'key': 'p', 'field': 'path', 'operator': 'prefix', 'value': '/private'}})]
    policy = binding.resolve(**data)
    assert evaluate_exclusions(policy.model_dump(mode='json'), url='https://app.example.com/private', body_available=True)['decision'] == 'deny'


def doc():
    page = sample_page()
    text = page.text + '\n' + QUOTE
    page = page.model_copy(update={'text': text, 'content_sha256': digest(text)})
    return ScopeDocument(scope_id='legacy', created_at=page.captured_at, source=page,
        analysis=sample_analysis().model_copy(update={'execution_rules': ScopeExecutionRules()}))


def interpretation():
    return {'required_request_headers': [], 'execution_rules': {'exclusions': [rule().model_dump()]}}


def test_legacy_embedded_rules_upgrade_v4_and_preserve_approval_bytes(tmp_path):
    document = doc()
    approval = tmp_path / 'Approval.json'
    approval.write_bytes(b'{"approved": "original bytes"}\n')
    before = document.model_dump_json(), approval.read_bytes()
    calls = []
    def interpret(page):
        calls.append(page)
        return interpretation()
    binding = execution_rules.ScopeExecutionResolver(tmp_path / 'cache', interpret)
    assert execution_rules.EXECUTION_INTERPRETATION_VERSION == '4'
    assert binding.cached(document) is None
    assert not execution_rules.execution_interpretation_complete(document.analysis)
    result = binding.resolve(document)
    assert result.execution_rules.exclusions == [rule()]
    assert binding.cached(document) == result
    assert binding.resolve(document) == result
    assert len(calls) == 1
    assert execution_rules.execution_interpretation_complete(result)
    assert (document.model_dump_json(), approval.read_bytes()) == before


@pytest.mark.parametrize('adapter', [main, native_pipeline])
def test_both_adapters_classify_offline_and_validate_returned_evidence(monkeypatch, adapter):
    data = inputs()
    context = {k: [x.model_dump(mode='json') for x in v] if isinstance(v, list) else v for k, v in data.items()}
    agent = adapter.CodexMainAgent()
    def respond(**kwargs):
        assert kwargs['allow_browser'] is False
        return kwargs['model_type'].model_validate(decisions(context))
    monkeypatch.setattr(agent, '_run_structured', respond)
    result = agent.classify_exclusion_resources(context)
    assert [d.classification for d in result.decisions] == ['match', 'match', 'nonmatch']


@pytest.mark.parametrize('adapter', [main, native_pipeline])
@pytest.mark.parametrize('quote', [QUOTE, 'Do not test invented.', 'Do not test functionality.'])
def test_generic_scope_ai_exclusions_require_exact_source_span(monkeypatch, adapter, quote):
    response = interpretation()
    response['execution_rules']['exclusions'][0]['source_quote'] = quote
    agent = adapter.CodexMainAgent()
    monkeypatch.setattr(agent, '_run_structured', lambda **kw: kw['model_type'].model_validate(response))
    if quote == QUOTE:
        assert agent.interpret_scope_execution_requirements(doc().source).execution_rules.exclusions == [rule()]
    else:
        with pytest.raises(adapter.MainAgentError, match='quote'):
            agent.interpret_scope_execution_requirements(doc().source)


@pytest.mark.parametrize('adapter', [main, native_pipeline])
def test_fresh_adapter_rejects_legacy_exclusions(monkeypatch, adapter):
    agent = adapter.CodexMainAgent()
    monkeypatch.setattr(agent, '_run_structured', lambda **kw: kw['model_type'].model_validate({'required_request_headers': [], 'execution_rules': {}}))
    with pytest.raises(adapter.MainAgentError, match='exclusions'):
        agent.interpret_scope_execution_requirements(doc().source)
    with pytest.raises(adapter.MainAgentError, match='exclusions'):
        agent._verify_grounding(doc().source, doc().analysis)


def test_fresh_coordinator_rejects_legacy_exclusions():
    with pytest.raises(CoordinatorError, match='exclusions'):
        ScopeCoordinator._require_grounded_analysis(doc().source, doc().analysis)


def test_review_markdown_displays_exclusion_and_condition():
    document = doc()
    data = document.analysis.model_dump()
    data.update(interpretation())
    data['source_evidence'].append({'section': 'Exclusion', 'quote': QUOTE})
    document = document.model_copy(update={'analysis': ScopeAnalysis.model_validate(data)})
    markdown = ScopeCoordinator._render_markdown(document)
    assert QUOTE in markdown
    assert 'category-1' in markdown


def test_expired_cache_read_holds_without_classification(monkeypatch, tmp_path):
    from aidast.scope import exclusion_binding
    data = inputs()
    now = 1800000000.0
    data['evidence'] = [e.model_copy(update={'captured_at': now}) for e in data['evidence']]
    monkeypatch.setattr(exclusion_binding.time, 'time', lambda: now)
    calls = []
    binding = resolver(tmp_path, lambda ctx: (calls.append(ctx), decisions(ctx))[1])
    assert binding.resolve(**data).semantic_bindings[2].classification == 'nonmatch'
    monkeypatch.setattr(exclusion_binding.time, 'time', lambda: now + 86400)
    assert binding.cached(**data) is None
    assert binding.resolve(**data).semantic_bindings[2].classification == 'unknown'
    assert len(calls) == 1
    # Explicit refresh with the same expired capture cannot revive its facts.
    assert binding.refresh(**data).semantic_bindings[2].classification == 'unknown'
    assert len(calls) == 2


def test_tampered_sidecar_policy_never_authorizes(tmp_path):
    data = inputs()
    binding = resolver(tmp_path)
    binding.resolve(**data)
    path = next(tmp_path.glob('*.json'))
    record = json.loads(path.read_text())
    record['policy']['semantic_bindings'][0]['classification'] = 'nonmatch'
    path.write_text(json.dumps(record))
    assert binding.cached(**data) is None
    assert gate(binding.resolve(**data), data['candidates'][0]) == 'hold'


def test_reviewed_v4_sidecar_takes_precedence_over_complete_embedded_rules(tmp_path):
    document = doc()
    document.analysis.execution_rules.exclusions = []
    binding = execution_rules.ScopeExecutionResolver(tmp_path, lambda _: pytest.fail('cache must not interpret'))
    reviewed = binding._validate(document, interpretation(), fresh=True)
    requirements = dict(required_request_headers=[], execution_rules=reviewed.execution_rules.model_dump())
    binding.cache_path(document).write_text(json.dumps(dict(
        interpretation_version='4', approved_digest=binding.digest(document), requirements=requirements)))
    assert binding.cached(document).execution_rules.exclusions == [rule()]


@pytest.mark.parametrize('adapter', [main, native_pipeline])
def test_classifier_direct_context_never_invokes_model(monkeypatch, adapter):
    agent = adapter.CodexMainAgent()
    monkeypatch.setattr(agent, '_run_structured', lambda **_: pytest.fail('no semantic pairs'))
    assert agent.classify_exclusion_resources(dict(scope_digest=digest('scope'), target_asset=TARGET,
        rules=[], candidates=[], evidence=[])).decisions == []


@pytest.mark.parametrize('adapter', [main, native_pipeline])
@pytest.mark.parametrize('operation', ['classification', 'interpretation'])
def test_adapter_subprocess_disables_tools_and_browser(monkeypatch, adapter, operation):
    from pathlib import Path
    from types import SimpleNamespace
    agent = adapter.CodexMainAgent()
    data = inputs()
    context = {k: [_x.model_dump(mode='json') for _x in v] if isinstance(v, list) else v for k, v in data.items()}
    monkeypatch.setattr(adapter.shutil, 'which', lambda _: '/fake/codex')
    monkeypatch.setattr(agent, '_require_login', lambda _: None)
    def run(command, **kwargs):
        disabled = {command[i + 1] for i, arg in enumerate(command[:-1]) if arg == '--disable'}
        assert {'shell_tool', 'unified_exec', 'apps', 'standalone_web_search', 'browser_use',
                'computer_use', 'in_app_browser'} <= disabled
        assert '--ignore-user-config' in command
        assert '--enable' not in command
        workdir = Path(command[command.index('--cd') + 1])
        assert workdir != Path.cwd()
        from aidast.agents.policy_guidance import policy_skill_text
        skill = workdir / '.agents/skills/aidast-policy/SKILL.md'
        assert [p for p in (workdir / '.agents').rglob('*') if p.is_file()] == [skill]
        assert skill.read_text() == policy_skill_text()
        assert 0 < kwargs['timeout'] <= 600
        payload = decisions(context) if operation == 'classification' else interpretation()
        Path(command[command.index('--output-last-message') + 1]).write_text(json.dumps(payload))
        return SimpleNamespace(returncode=0, stderr='')
    monkeypatch.setattr(adapter.subprocess, 'run', run)
    if operation == 'classification':
        assert agent.classify_exclusion_resources(context).decisions[0].classification == 'match'
    else:
        assert agent.interpret_scope_execution_requirements(doc().source).execution_rules.exclusions == [rule()]


def test_interpreter_mutation_cannot_change_validation_snapshot(tmp_path):
    data = inputs()
    def classify(ctx):
        ctx['evidence'][2]['excerpt'] = 'Forged function description'
        return decisions(ctx)
    assert gate(resolver(tmp_path, classify).resolve(**data), data['candidates'][2]) == 'hold'


def test_bounded_model_inputs_reject_before_classifier(tmp_path):
    data = inputs()
    data['candidates'] = data['candidates'] * 100
    with pytest.raises(ValueError, match='budget'):
        resolver(tmp_path, lambda _: pytest.fail('oversized context reached model')).resolve(**data)


def test_oversized_model_output_becomes_unknown(tmp_path):
    data = inputs()
    def classify(ctx):
        result = decisions(ctx)
        result['decisions'][0]['reason'] = 'a' * 262145
        return result
    assert gate(resolver(tmp_path, classify).resolve(**data), data['candidates'][2]) == 'hold'
