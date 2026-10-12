"""Offline dashboard migration: listing preserves authority; preparation reviews it."""
from datetime import datetime, timezone

import pytest

from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.execution_rules import ScopeExecutionResolver, validate_policy_prerequisites
from aidast.scope.models import ScopeAnalysis, ScopeDocument
from aidast.web.launch import ApprovedScopeCatalog, ScanLaunchManager, ScanLaunchRequest
from aidast.web.projection import DashboardProjector
from aidast.web.scope_workflow import ScopeWorkflowManager
from test_scope_workflow import sample_analysis, sample_page

QUOTE = "*.example.com is in scope"


def legacy_document(*, reference=True, blocker=True):
    source = sample_page().model_dump()
    source.update(requested_url='https://bugcrowd.com/engagements/example', final_url='https://bugcrowd.com/engagements/example')
    if reference:
        source['policy_references'] = [dict(candidate_id=0, parent_url=str(source['requested_url']),
            requested_url='https://example.com/policy', source_quote=QUOTE,
            applicability='unknown', relationship='supporting', depth=1,
            captured_at=datetime.now(timezone.utc), status='unresolved', error='Not captured')]
    data = sample_analysis().model_dump()
    if blocker:
        data['execution_rules']['blocking_requirements'] = [dict(label='Legacy policy review',
            source_quote=QUOTE, reason='Unclear applicability')]
    return ScopeDocument(scope_id='legacy_advisory_scope', created_at=datetime.now(timezone.utc),
                         source=source, analysis=ScopeAnalysis.model_validate(data))


@pytest.mark.parametrize('reference,blocker', [(True, True), (True, False), (False, True)])
def test_catalog_legacy_policy_requires_preparation_then_warning_only_ready_without_artifact_changes(tmp_path, reference, blocker):
    document = legacy_document(reference=reference, blocker=blocker)
    directory = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    coordinator = ScopeCoordinator(directory)
    coordinator.approve_draft(coordinator._create_scope_draft(document), approved_by='operator')
    original = {path: path.read_bytes() for path in directory.iterdir() if path.is_file()}

    def interpret(source):
        assert source.evidence_text == document.source.evidence_text
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[], advisories=[dict(
            label='Policy uncertainty', source_quote=QUOTE, reason='Applicability is unclear',
            guidance='Proceed within explicit authorization and avoid questionable operations.', target_assets=[])]))

    resolver = ScopeExecutionResolver(tmp_path / '.execution-requirements', interpreter=interpret)
    catalog = ApprovedScopeCatalog(tmp_path, execution_resolver=resolver)
    pending = catalog.get(document.scope_id).execution_requirements
    assert pending.execution_requirements_status == 'pending'
    assert pending.header_requirements_status == 'pending'
    assert len(pending.policy_blockers) == int(blocker)
    assert not resolver.cache_dir.exists()  # Read-only listing cannot prepare a cache.

    ready = catalog.resolve_execution_requirements(document.scope_id).execution_requirements
    assert ready.execution_requirements_status == 'ready'
    assert ready.header_requirements_status == 'ready'
    assert ready.policy_blockers == ()
    assert ready.execution_rules.policy_review_version == 3
    assert ready.execution_rules.advisories[0].label == 'Policy uncertainty'
    validate_policy_prerequisites(ready.execution_rules, ['*.example.com'])
    assert {path: path.read_bytes() for path in original} == original
    assert coordinator.load_approved_scope()[0].analysis.execution_rules.policy_review_version == 1


def test_review_payload_retains_reference_relationship():
    payload = ScopeWorkflowManager._review_payload(legacy_document())
    assert payload['policy_references'][0]['relationship'] == 'supporting'


def test_previous_review_reinterprets_feasible_header_and_binds_operator_identity(tmp_path):
    from aidast.scope.identity_headers import resolve_scope_identity_headers
    quote = 'If using automated scanning tools, include your HackerOne username in requests whenever feasible using a custom header: X-HackerOne: your_username'
    document = legacy_document(reference=False, blocker=False)
    source = document.source.model_copy(update={'text': document.source.text + '\n' + quote})
    rules = document.analysis.execution_rules.model_copy(update={'policy_review_version': 2})
    document = document.model_copy(update={'source': source, 'analysis': document.analysis.model_copy(update={'execution_rules': rules})})
    original = document.model_dump_json()
    calls = []
    def interpret(page):
        calls.append(page)
        return dict(required_request_headers=[dict(name='X-HackerOne', value_template='{hackerone_username}',
            inputs=[dict(key='hackerone_username', label='HackerOne username', kind='username')], source_quote=quote)],
            execution_rules=dict(exclusions=[]))
    resolver = ScopeExecutionResolver(tmp_path / 'cache', interpreter=interpret)
    assert resolver.cached(document) is None
    prepared = resolver.resolve(document)
    assert len(calls) == 1
    with pytest.raises(ValueError, match='hackerone_username'):
        resolve_scope_identity_headers(prepared)
    assert resolve_scope_identity_headers(prepared, hackerone_username='researcher_1') == {'X-HackerOne': 'researcher_1'}
    assert resolver.resolve(document) == prepared
    assert len(calls) == 1
    assert document.model_dump_json() == original


def test_reviewed_hard_blocker_remains_a_launch_error():
    rules = legacy_document(reference=False).analysis.execution_rules.model_copy(update={'policy_review_version': 2})
    with pytest.raises(ValueError, match='mandatory'):
        validate_policy_prerequisites(rules, ['*.example.com'])


@pytest.mark.parametrize('hard_blocker', [False, True])
def test_launch_preparation_accepts_reviewed_warnings_and_rejects_mandatory_blockers(tmp_path, hard_blocker):
    document = legacy_document()
    coordinator = ScopeCoordinator(tmp_path / 'Scope' / 'bugcrowd' / 'example')
    coordinator.approve_draft(coordinator._create_scope_draft(document), approved_by='operator')
    def interpret(_source):
        return dict(required_request_headers=[], execution_rules=dict(exclusions=[], advisories=[dict(
            label='Warning', source_quote=QUOTE, reason='Unclear context', guidance='Avoid questionable operations.')],
            blocking_requirements=[dict(label='Explicit mandatory prerequisite', source_quote=QUOTE,
                reason='Unsupported required control')] if hard_blocker else []))
    resolver = ScopeExecutionResolver(tmp_path / '.execution-requirements', interpreter=interpret)
    manager = ScanLaunchManager(tmp_path, DashboardProjector(tmp_path), execution_resolver=resolver,
        process_factory=lambda *_args, **_kwargs: pytest.fail('Preparation must never spawn a process'))
    request = ScanLaunchRequest(scope_id=document.scope_id, targets=['*.example.com'],
        authorization_confirmed=True, login_mode='none')
    if hard_blocker:
        with pytest.raises(ValueError, match='mandatory'):
            manager._prepare_launch(request)
    else:
        scope, preparation = manager._prepare_launch(request)
        preparation.require_ready()
        assert scope.execution_requirements.execution_requirements_status == 'ready'
        assert scope.execution_requirements.execution_rules.advisories
