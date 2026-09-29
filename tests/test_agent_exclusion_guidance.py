"""Reviewed semantic conditions reach Agents without blocking the first request."""
import pytest

from aidast.agents.policy_guidance import effective_advisory_context, policy_guidance_context
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.orchestration.scope import ScopeCoordinator
from aidast.recon.policy import TargetPolicy
from aidast.scope.exclusion_binding import ExclusionBindingResolver
from aidast.scope.exclusion_preparation import prepare_exclusions
from aidast.scope.execution_rules import bind_execution_policies
from aidast.web.launch import ScanLaunchManager, ScanLaunchRequest
from aidast.web.projection import DashboardProjector
from test_policy_exclusion_preparation import document, URL, QUOTE
from test_policy_exclusion_transports import Wire


def reviewed_document(*, field='semantic', bound=None, direct=False):
    doc = document(not direct)
    rule = doc.analysis.execution_rules.exclusions[0]
    if not direct:
        condition = rule.condition.model_dump()
        condition['predicate']['field'] = field
        rule = rule.model_copy(update={'condition': type(rule.condition).model_validate(condition)})
    if bound:
        source_text = doc.source.text + '\n' + bound
        from hashlib import sha256
        source = doc.source.model_copy(update={'text': source_text,
            'content_sha256': sha256(source_text.encode()).hexdigest()})
        data = doc.analysis.model_dump()
        data['in_scope_assets'].append(dict(asset_type='OTHER', asset=bound,
            description='Additional approved asset', eligibility='eligible', maximum_severity='High'))
        data['source_evidence'].append(dict(section='Scope', quote=bound))
        doc = doc.model_copy(update={'source': source, 'analysis': type(doc.analysis).model_validate(data)})
        rule = rule.model_copy(update={'target_assets': [bound]})
    rules = doc.analysis.execution_rules.model_copy(update={'exclusions': [rule], 'policy_review_version': 2})
    return doc.model_copy(update={'analysis': doc.analysis.model_copy(update={'execution_rules': rules})})


def prepare(doc, tmp_path):
    return prepare_exclusions(document=doc, analysis=doc.analysis,
        targets=[doc.analysis.in_scope_assets[0]], result_root=tmp_path,
        resolver=ExclusionBindingResolver(tmp_path / 'bindings',
            lambda _: pytest.fail('Agent-guided conditions must not require captured-resource classification')),
        database_paths=[])


def target_policy():
    return TargetPolicy(scope_id='scope_preparation', policy_id='fixture', asset_type='URL',
        asset=URL, allowed_hosts=['example.com'], allowed_methods=['GET'],
        attack_allowed_methods=['GET'], required_identity_headers={'X-Researcher': 'fixture'})


@pytest.mark.parametrize('field', ['semantic', 'unsupported'])
@pytest.mark.parametrize('bound', [None, 'Managed database extensions'])
def test_reviewed_meaning_conditions_allow_first_probe_and_reach_agent_policy(tmp_path, field, bound):
    doc = reviewed_document(field=field, bound=bound)
    original = doc.model_dump_json()
    prepared = prepare(doc, tmp_path)
    prepared.require_ready()
    assert prepared.public()['agent_guidance'][0]['source_quote'] == QUOTE
    assert prepared.policies[URL].rules == []
    policies = bind_execution_policies({'fixture': target_policy()}, doc.analysis.execution_rules,
        result_root=tmp_path, program_url='https://bugcrowd.com/example', scan_id=None,
        prerequisite_evidence={})
    attached = prepared.attach(policies)['fixture']
    context = policy_guidance_context(attached)
    assert QUOTE in context
    assert 'managed resources' in context
    assert 'Agent' in context
    wire = Wire()
    RequestBroker(attached, transport=wire).request(URL)
    assert len(wire.calls) == 1
    assert doc.model_dump_json() == original


def test_web_launch_preparation_accepts_existing_reviewed_semantic_scope_without_rewriting_approval(tmp_path):
    doc = reviewed_document(bound='Managed database extensions')
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    coordinator = ScopeCoordinator(directory)
    coordinator.approve_draft(coordinator._create_scope_draft(doc), approved_by='operator')
    before = {p: p.read_bytes() for p in directory.iterdir() if p.is_file()}
    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path),
        process_factory=lambda *_a, **_kw: pytest.fail('Preparation must never start a scan'))
    _, prepared = manager._prepare_launch(ScanLaunchRequest(scope_id=doc.scope_id, targets=[URL],
        authorization_confirmed=True, login_mode='none'))
    prepared.require_ready()
    assert prepared.public()['agent_guidance']
    assert {p: p.read_bytes() for p in before} == before


def test_direct_exclusion_still_blocks_wire_after_advisory_review(tmp_path):
    doc = reviewed_document(direct=True)
    prepared = prepare(doc, tmp_path)
    prepared.require_ready()
    wire = Wire()
    policy = prepared.attach({'fixture': target_policy()})['fixture']
    with pytest.raises(RequestPolicyError, match='exclusion'):
        RequestBroker(policy, transport=wire).request(URL + 'private')
    assert wire.calls == []


def test_mixed_condition_and_unreviewed_semantics_still_require_request_evidence(tmp_path):
    doc = document()
    with pytest.raises(ValueError, match='offline review'):
        prepare(doc, tmp_path).require_ready()
    doc = reviewed_document()
    semantic = doc.analysis.execution_rules.exclusions[0]
    direct = document(False).analysis.execution_rules.exclusions[0]
    direct = direct.model_copy(update={'condition': direct.condition.model_copy(update={
        'predicate': direct.condition.predicate.model_copy(update={'key': 'direct_path'})})})
    mixed = semantic.model_copy(update={'condition': type(semantic.condition).model_validate(dict(
        operator='any', children=[semantic.condition.model_dump(), direct.condition.model_dump()]))})
    rules = doc.analysis.execution_rules.model_copy(update={'exclusions': [mixed]})
    doc = doc.model_copy(update={'analysis': doc.analysis.model_copy(update={'execution_rules': rules})})
    with pytest.raises(ValueError, match='offline review'):
        prepare(doc, tmp_path).require_ready()


def test_recon_execution_context_labels_agent_conditions_even_without_other_advisories():
    doc = reviewed_document()
    context = effective_advisory_context(doc.analysis.execution_rules)
    assert 'Agent' in context
    assert 'managed resources' in context
    assert doc.analysis.execution_rules.exclusions[0].key in context
    assert doc.analysis.execution_rules.exclusions[0].source_quote in doc.source.evidence_text


def test_cli_existing_reviewed_scope_passes_agent_conditions_to_the_planner(tmp_path, monkeypatch):
    from aidast.cli import main
    from test_recon_workflow import FakeReconMainAgent, PROGRAM_URL
    doc = reviewed_document()
    coordinator = ScopeCoordinator(tmp_path / 'Scope' / 'bugcrowd' / 'example')
    coordinator.approve_draft(coordinator._create_scope_draft(doc), approved_by='operator')
    before = {p: p.read_bytes() for p in coordinator.output_dir.iterdir() if p.is_file()}
    class ReachedPlanner(Exception):
        pass
    agent = FakeReconMainAgent()
    def plan(**kwargs):
        assert 'Agent-guided exclusion context' in kwargs['scope_markdown']
        assert 'managed resources' in kwargs['scope_markdown']
        raise ReachedPlanner()
    monkeypatch.setattr(agent, 'create_recon_plan', plan)
    monkeypatch.setattr('aidast.cli.CodexMainAgent', lambda **_kw: agent)
    with pytest.raises(ReachedPlanner):
        main(['recon', PROGRAM_URL, '--output-dir', str(coordinator.output_dir.parent.parent),
              '--policy-only', '--target', URL])
    assert {p: p.read_bytes() for p in before} == before


def test_compact_planner_view_preserves_agent_enforcement_mode():
    from aidast.agents.policy_guidance import recon_scope_context
    import json
    doc = reviewed_document()
    projected = recon_scope_context(approved_document=doc, approved_markdown='# Approved',
        effective_analysis=doc.analysis, scope_markdown=QUOTE * 8000)
    payload = json.loads(projected.split('<execution_scope_json>\n')[1].split('\n</execution_scope_json>')[0])
    assert payload['effective_execution']['agent_guided_exclusion_keys'] == ['restricted']
