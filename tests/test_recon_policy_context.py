"""Duplicate-heavy captured evidence must fit the real offline planner boundary."""
import hashlib
import importlib
import json

import pytest

from aidast.cli import main
from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.execution_rules import ScopeExecutionResolver
from aidast.scope.models import BlockingRequirement, ProgramPage, ScopeDocument
from aidast.scope.policy_references import enrich_policy_references, require_unresolved_testing_holds
from test_scope_policy_preparation import page, analysis
from test_recon_workflow import PROGRAM_URL


class ReachedPlanner(Exception):
    pass


def capture():
    raw = page().model_dump()
    text = (raw['text'] + ' Policy context.' * 800)[:11778]
    text += 'x' * (11778 - len(text))
    raw.update(requested_url=PROGRAM_URL, final_url=PROGRAM_URL, text=text,
               content_sha256=hashlib.sha256(text.encode()).hexdigest(),
               observed_links=[dict(candidate_id=i, url=f'https://docs.example/policy-{i}',
                                    label='Policy', source_url=PROGRAM_URL) for i in range(8)])
    class UnavailableReader:
        def read(self, url):
            raise ValueError('Offline reference unavailable')
    def select(text, links):
        return {'selections': [dict(candidate_id=link.candidate_id, source_quote=text,
                                   applicability='unknown') for link in links]}
    return enrich_policy_references(ProgramPage.model_validate(raw), select, UnavailableReader())


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
@pytest.mark.parametrize('legacy', [False, True])
def test_duplicate_evidence_reaches_real_planner_with_all_guidance_and_approval_intact(tmp_path, monkeypatch, module_name, legacy):
    source = capture()
    reviewed = require_unresolved_testing_holds(source, analysis().model_copy(update={
        'program_name': 'P', 'program_description': 'X'}))
    assert len(source.text) == 11778
    assert len(reviewed.execution_rules.advisories) == 8
    assert not reviewed.execution_rules.blocking_requirements
    # A legacy approval has no new advisories but repeats reference evidence.
    initial = reviewed
    if legacy:
        initial = reviewed.model_copy(update={'execution_rules': analysis().execution_rules.model_copy(update={
            'blocking_requirements': [BlockingRequirement(
                **item.model_dump(exclude={'guidance'})) for item in reviewed.execution_rules.advisories]})})
    document = ScopeDocument(scope_id='scope_capacity', created_at=source.captured_at,
                             source=source, analysis=initial)
    directory = tmp_path / 'Scope/bugcrowd/example'
    coordinator = ScopeCoordinator(directory)
    staging = coordinator._create_scope_draft(document)
    coordinator.approve_draft(staging, approved_by='offline-fixture')
    document, markdown = coordinator.load_approved_scope()
    assert len(markdown) > 250000
    if not legacy:
        assert len(markdown) == 289559
    before = {p: p.read_bytes() for p in directory.iterdir() if p.is_file()}
    if legacy:
        resolver = ScopeExecutionResolver(tmp_path / '.execution-requirements', lambda _: dict(
            required_request_headers=[], execution_rules=dict(exclusions=[])))
        resolver.resolve(document)
    agent = importlib.import_module(module_name).CodexMainAgent()
    seen = []
    def model(**kwargs):
        seen.append(kwargs['prompt'])
        raise ReachedPlanner()
    monkeypatch.setattr(agent, '_run_structured', model)
    monkeypatch.setattr(agent, 'interpret_scope_execution_requirements', lambda _: pytest.fail('must reuse reviewed data'))
    monkeypatch.setattr('aidast.cli.CodexMainAgent', lambda **_: agent)
    with pytest.raises(ReachedPlanner):
        main(['recon', PROGRAM_URL, '--policy-only', '--output-dir', str(tmp_path / 'Scope')])
    prompt = seen[0]
    context = json.loads(prompt.split('<execution_scope_json>\n')[1].split('\n</execution_scope_json>')[0])
    assert context['approved_markdown_sha256'] == hashlib.sha256(markdown.encode()).hexdigest()
    assert context['approved_document_sha256'] == hashlib.sha256(document.model_dump_json().encode()).hexdigest()
    evidence = context['captured_evidence']
    assert evidence == source.evidence_text
    def expand(value):
        if isinstance(value, dict):
            if 'captured_evidence_span' in value:
                start, end = value['captured_evidence_span']
                quote = evidence[start:end]
                assert hashlib.sha256(quote.encode()).hexdigest() == value['sha256']
                return quote
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        return value
    assert expand(context['approved_document']) == document.model_dump(mode='json')
    warnings = context['effective_execution']['execution_rules']['advisories']
    assert len(warnings) == 8
    for actual, expected in zip(warnings, reviewed.execution_rules.advisories):
        assert actual['guidance'] == expected.guidance
        assert actual['reason'] == expected.reason
        start, end = actual['source_quote']['captured_evidence_span']
        assert evidence[start:end] == expected.source_quote
        assert actual['source_quote']['sha256'] == hashlib.sha256(expected.source_quote.encode()).hexdigest()
    assert len(prompt) < 250000
    for p, content in before.items():
        assert p.read_bytes() == content
    assert coordinator.load_approved_scope()[1] == markdown


@pytest.mark.parametrize('module_name', ['aidast.agents.main', 'aidast.agents.native_pipeline'])
def test_unique_oversize_execution_context_keeps_guard_and_complete_guidance(monkeypatch, module_name):
    from aidast.agents.policy_guidance import recon_scope_context
    source = capture()
    reviewed = require_unresolved_testing_holds(source, analysis())
    reviewed = reviewed.model_copy(update={'program_description': 'Unique authority detail ' * 12000})
    document = ScopeDocument(scope_id='capacity', created_at=source.captured_at, source=source, analysis=reviewed)
    markdown = ScopeCoordinator._render_markdown(document)
    context = recon_scope_context(approved_document=document, approved_markdown=markdown,
                                  effective_analysis=reviewed, scope_markdown=markdown)
    assert len(context) > 250000
    assert reviewed.execution_rules.advisories[-1].guidance in context
    adapter = importlib.import_module(module_name)
    agent = adapter.CodexMainAgent()
    monkeypatch.setattr(agent, '_run_structured', lambda **_: pytest.fail('oversized input reached model'))
    with pytest.raises(adapter.MainAgentError, match='250000-character prompt budget'):
        agent.create_recon_plan(scope_id=document.scope_id, scope_markdown=context,
                                allowed_targets=reviewed.in_scope_assets)
