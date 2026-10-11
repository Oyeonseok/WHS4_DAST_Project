"""Offline regressions for grounded advisory review and observed reference admission."""
from datetime import datetime, timezone
import hashlib
from unittest.mock import patch
import importlib

import pytest
from aidast.scope import models
from aidast.scope.policy_references import enrich_policy_references, require_unresolved_testing_holds
from aidast.scope.execution_rules import ScopeExecutionResolver, validate_policy_prerequisites
from test_scope_policy_preparation import page, analysis, Reader, PRIMARY, URL, GUIDE


def unresolved_source(count=1):
    source = page().model_dump()
    source['policy_references'] = [dict(candidate_id=7, parent_url=URL, requested_url=GUIDE,
        source_quote=PRIMARY, applicability='unknown', depth=1,
        captured_at=datetime.now(timezone.utc), status='unresolved', error='reference capture failed')] * count
    return models.ProgramPage.model_validate(source)


def advisory_data(quote=PRIMARY):
    return dict(label='Interpret with care', source_quote=quote, reason='Applicability is unclear',
        guidance='Proceed within explicit authorization; avoid any operation whose authorization is unclear.', target_assets=[])


def document(source=None, prepared=None):
    return models.ScopeDocument(scope_id='advisories', created_at=datetime.now(timezone.utc),
        source=source or page(), analysis=prepared or analysis())


def test_unresolved_reference_is_visible_guidance_without_launch_hold():
    reviewed = require_unresolved_testing_holds(unresolved_source(), analysis())
    assert reviewed.execution_rules.blocking_requirements == []
    assert reviewed.execution_rules.policy_review_version == 2
    assert reviewed.execution_rules.advisories[0].source_quote == PRIMARY
    assert reviewed.execution_rules.advisories[0].guidance
    validate_policy_prerequisites(reviewed.execution_rules, ['example.org'])


def test_generated_advisories_preserve_explicit_blockers_without_label_filters():
    data = analysis().model_dump()
    data['execution_rules']['blocking_requirements'] = [dict(label='Referenced testing policy requires review',
        source_quote=PRIMARY, reason='An explicit mandatory unsupported control')]
    data['source_evidence'].append(dict(section='Policy', quote=PRIMARY))
    reviewed = require_unresolved_testing_holds(unresolved_source(), models.ScopeAnalysis.model_validate(data))
    assert len(reviewed.execution_rules.blocking_requirements) == 1
    with pytest.raises(ValueError, match='mandatory'):
        validate_policy_prerequisites(reviewed.execution_rules, ['example.org'])


def test_advisory_quotes_and_applicability_are_grounded_like_restrictions():
    for override, match in [(dict(source_quote='invented quote'), 'grounded'),
                             (dict(target_assets=['external.example']), 'exact approved asset')]:
        data = analysis().model_dump()
        data['source_evidence'].append(dict(section='Policy', quote=PRIMARY))
        data['execution_rules']['advisories'] = [{**advisory_data(), **override}]
        with pytest.raises(ValueError, match=match):
            models.ScopeAnalysis.model_validate(data)


def test_fresh_advisory_limit_reserves_112_generated_edges_and_cache_does_not_duplicate(tmp_path):
    data = analysis().model_dump()
    data['source_evidence'].append(dict(section='Policy', quote=PRIMARY))
    data['execution_rules']['advisories'] = [advisory_data()] * 64
    initial = models.ScopeAnalysis.model_validate(data)
    oversized = initial.model_copy(update={'execution_rules': initial.execution_rules.model_copy(
        update={'advisories': initial.execution_rules.advisories + [initial.execution_rules.advisories[0]]})})
    with pytest.raises(ValueError, match='extracted.*64'):
        require_unresolved_testing_holds(unresolved_source(), oversized)
    source = unresolved_source(112)
    reviewed = require_unresolved_testing_holds(source, initial)
    assert len(reviewed.execution_rules.advisories) == 176
    with pytest.raises(ValueError, match='extracted.*64'):
        require_unresolved_testing_holds(source, reviewed)
    saved = document(source, reviewed)
    resolver = ScopeExecutionResolver(tmp_path, lambda _: pytest.fail('reviewed Scope must not call model'))
    assert len(resolver.resolve(saved).execution_rules.advisories) == 176
    raw = reviewed.model_dump()
    raw['execution_rules']['advisories'].append(advisory_data())
    with pytest.raises(ValueError, match='at most 176'):
        models.ScopeAnalysis.model_validate(raw)


def test_fragment_equivalent_retrieval_preserves_edges_and_queries_are_distinct():
    urls = [GUIDE + '#one', GUIDE + '#two', GUIDE, GUIDE + '?mode=one', GUIDE + '?mode=two']
    data = page().model_dump()
    data['observed_links'] = [dict(candidate_id=i, url=url, label='Guide', source_url=URL) for i, url in enumerate(urls)]
    calls = []
    class CountingReader(Reader):
        def read(self, url):
            calls.append(url)
            return super().read(url)
    def selector(text, links):
        return {'selections': [dict(candidate_id=i, source_quote=PRIMARY, applicability='mixed',
            relationship='required' if i == 1 else 'supporting') for i in range(5)]}
    captured = enrich_policy_references(models.ProgramPage.model_validate(data), selector, CountingReader())
    assert len(calls) == 3
    assert set(calls) == {GUIDE + '#two', GUIDE + '?mode=one', GUIDE + '?mode=two'}
    assert {item.requested_url for item in captured.policy_references} == set(urls)
    assert {item.relationship for item in captured.policy_references} == {'required', 'supporting'}
    assert all(item.source_quote == PRIMARY and item.status == 'captured' for item in captured.policy_references)
    assert captured.evidence_text.count('Requests must stay at or below 3 per second.') == 3


def test_required_choice_uses_last_collection_slot_before_supporting_choice():
    data = page().model_dump()
    views = []
    for index, size in [(0, 7), (1, 2)]:
        views.append(dict(url=URL, text=PRIMARY, observed_links=[dict(candidate_id=i,
            url=f'{GUIDE}/{index}/{i}', label='Guide', source_url=URL) for i in range(size)]))
    data.update(primary_views=views, observed_links=[])
    def selector(text, links):
        return {'selections': [dict(candidate_id=item.candidate_id, source_quote=text, applicability='testing',
            relationship='required' if item.url.endswith('/1/1') else 'supporting') for item in links]}
    captured = enrich_policy_references(models.ProgramPage.model_validate(data), selector, Reader())
    by_url = {item.requested_url: item.status for item in captured.policy_references}
    assert by_url[GUIDE + '/1/1'] == 'captured'
    assert by_url[GUIDE + '/1/0'] == 'unresolved'


def test_legacy_reference_review_reinterprets_and_caches_without_changing_approved_document(tmp_path):
    from aidast.scope.execution_rules import requires_policy_advisory_review
    data = analysis().model_dump()
    data['source_evidence'].append(dict(section='Old hold', quote=PRIMARY))
    data['execution_rules']['blocking_requirements'] = [dict(label='Old ambiguity', source_quote=PRIMARY, reason='Unknown')]
    saved = document(unresolved_source(), models.ScopeAnalysis.model_validate(data))
    original = saved.model_dump_json()
    calls = []
    def interpret(source):
        calls.append(source)
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[], advisories=[advisory_data()]))
    resolver = ScopeExecutionResolver(tmp_path, interpret)
    assert requires_policy_advisory_review(saved)
    assert resolver.cached(saved) is None
    result = resolver.resolve(saved)
    assert result.execution_rules.policy_review_version == 2
    assert result.execution_rules.blocking_requirements == []
    assert len(result.execution_rules.advisories) == 2
    assert calls[0].policy_references[0].source_quote == PRIMARY
    assert resolver.resolve(saved) == result
    assert len(calls) == 1
    assert saved.model_dump_json() == original
    assert not requires_policy_advisory_review(document())


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_legacy_model_receives_reference_provenance_and_rejects_ungrounded_advisories(module_name):
    adapter = importlib.import_module(module_name).CodexMainAgent()
    source = unresolved_source()
    good = models.ScopeExecutionInterpretation(required_request_headers=[],
        execution_rules=dict(exclusions=[], advisories=[advisory_data()]))
    bad = good.model_copy(update={'execution_rules': good.execution_rules.model_copy(update={
        'advisories': [models.PolicyAdvisory(**advisory_data('invented quote'))]})})
    with patch.object(adapter, '_run_structured', side_effect=[bad, good]) as run:
        result = adapter.interpret_scope_execution_requirements(source)
    assert run.call_count == 2
    assert 'reference capture failed' in run.call_args.kwargs['prompt']
    assert GUIDE in run.call_args.kwargs['prompt']
    assert result.execution_rules.advisories[0].source_quote == PRIMARY


def test_advisory_renderer_includes_quote_reason_guidance_and_applicability():
    from aidast.scope.execution_rules import render_execution_advisories
    rules = models.ScopeExecutionRules(advisories=[advisory_data()])
    rendered = render_execution_advisories(rules)
    assert PRIMARY in rendered
    assert 'Applicability is unclear' in rendered
    assert 'Proceed within explicit authorization' in rendered
    assert 'all selected targets' in rendered


def test_large_generated_reference_advisories_remain_reusable_in_bounded_v4_cache(tmp_path):
    raw = unresolved_source(112).model_dump()
    text = PRIMARY + ' Context.' * 1600
    raw['text'] = text
    raw['content_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    for item in raw['policy_references']:
        item['source_quote'] = text
    saved = document(models.ProgramPage.model_validate(raw))
    calls = []
    def interpret(_):
        calls.append('interpreted')
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[]))
    resolver = ScopeExecutionResolver(tmp_path, interpret)
    reviewed = resolver.resolve(saved)
    assert len(reviewed.execution_rules.advisories) == 112
    assert resolver.resolve(saved) == reviewed
    assert calls == ['interpreted']


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_fresh_model_interpretation_cannot_use_persisted_advisory_capacity(module_name):
    adapter = importlib.import_module(module_name).CodexMainAgent()
    output = models.ScopeExecutionInterpretation(required_request_headers=[],
        execution_rules=dict(exclusions=[], advisories=[advisory_data()] * 65, policy_review_version=2))
    with patch.object(adapter, '_run_structured', return_value=output):
        with pytest.raises(ValueError, match='extracted.*64'):
            adapter.interpret_scope_execution_requirements(page())
