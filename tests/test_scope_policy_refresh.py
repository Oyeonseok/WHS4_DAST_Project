"""Offline revision behavior: immutable approvals, persisted destinations and review."""
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import HttpUrl

from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.models import PolicyReferenceCapture, RequestLimit, SourceEvidence
from aidast.web.launch import ApprovedScopeCatalog, ScanLaunchManager, ScanLaunchRequest
from aidast.web.programs import ProgramRegistrationRequest, ProgramRegistry
from aidast.web.projection import DashboardProjector
from aidast.web.scope_workflow import ScopeCollectionRequest, ScopeDecisionRequest, ScopeWorkflowManager
from test_scope_workflow import FakeMainAgent, sample_analysis, sample_page

URL = 'https://bugcrowd.com/engagements/example'
YES = ScopeDecisionRequest(decision='yes', approved_by='revision-reviewer', confirmation=True)

class OriginalAgent(FakeMainAgent):
    def collect_scope(self, _url):
        return sample_page().model_copy(update={'requested_url':HttpUrl(URL), 'final_url':HttpUrl(URL)}), sample_analysis()

class RevisedAgent(FakeMainAgent):
    def collect_scope(self, _url):
        body = 'Testing must use at most three requests per second.'
        reference = PolicyReferenceCapture(candidate_id=4, parent_url=URL,
            source_quote='*.example.com is in scope', applicability='testing', depth=1,
            requested_url='https://docs.example.test/testing', final_url='https://docs.example.test/guide',
            captured_at=datetime.now(timezone.utc), status='captured', text=body,
            content_sha256=hashlib.sha256(body.encode()).hexdigest())
        return sample_page().model_copy(update={'requested_url':HttpUrl(URL), 'final_url':HttpUrl(URL), 'policy_references':[reference]}), self.interpret_captured_scope(None)

    def interpret_captured_scope(self, _page):
        analysis = sample_analysis()
        return analysis.model_copy(update={'source_evidence':[*analysis.source_evidence, SourceEvidence(section='Testing guide', quote='Testing must use at most three requests per second.')], 'execution_rules':analysis.execution_rules.model_copy(update={
            'request_limits':[RequestLimit(maximum=3, period_seconds=1.0, scope='program',
                source_quote='Testing must use at most three requests per second.')]})})

@pytest.fixture
def setup(tmp_path):
    registry = ProgramRegistry(tmp_path)
    program = registry.register(ProgramRegistrationRequest(program_url=URL, visibility='public'))
    canonical = tmp_path / 'Scope' / 'bugcrowd' / 'example'
    old = ScopeCoordinator(canonical).collect(URL, main_agent=OriginalAgent(),
        approved_by='original-reviewer', review=lambda _:True)
    manager = ScopeWorkflowManager(tmp_path, registry, agent_factory=RevisedAgent, worker_mode=True)
    return tmp_path, registry, program['id'], canonical, old, manager

def start(manager, program_id, refresh=True):
    # Keeps the first RED behavioral even before the public request field exists.
    request = ScopeCollectionRequest().model_copy(update={'refresh':refresh})
    with patch('aidast.web.scope_workflow.threading.Thread.start', lambda thread:thread.run()):
        return manager.start(program_id, request)

def archive_bytes(directory):
    return {name:(directory/name).read_bytes() for name in ['Scope.json','Scope.md','Approval.json','Manifest.json']}

def test_refresh_creates_reviewed_revision_preserves_old_bytes_and_launch_rules(setup):
    root, _, program_id, canonical, old, manager = setup
    original = archive_bytes(canonical)
    assert manager.start(program_id, ScopeCollectionRequest())['scope_status'] == 'approved'
    job = start(manager, program_id)
    assert job['scope_status'] == 'review_required'
    draft = manager.draft(program_id)
    assert draft['scope_id'] != old.scope_id
    assert draft['execution_rules']['request_limits'][0]['maximum'] == 3
    reference = draft['policy_references'][0]
    assert (reference['status'], reference['applicability']) == ('captured', 'testing')
    assert reference['requested_url'] == 'https://docs.example.test/testing'
    assert reference['final_url'] == 'https://docs.example.test/guide'
    assert 'text' not in reference  # review is compact; full capture stays in archive
    assert manager.approved_scope(program_id)['scope']['scope_id'] == old.scope_id
    manager.decide(program_id, YES)
    revision = canonical/'revisions'/job['scope_job_id']
    assert revision.is_dir()
    assert archive_bytes(canonical) == original
    assert manager.approved_scope(program_id)['scope']['scope_id'] == draft['scope_id']
    catalog = ApprovedScopeCatalog(root)
    versions = catalog.list()
    assert {v.scope_id for v in versions} == {old.scope_id,draft['scope_id']}
    assert {v.program_id for v in versions} == {'bugcrowd-example'}
    selected = catalog.get(draft['scope_id'])
    assert selected.execution_requirements.scope_max_requests_per_second == 3
    launcher = ScanLaunchManager(root, DashboardProjector(root), project_root=root)
    with patch('aidast.agents.main.CodexMainAgent', side_effect=AssertionError('no model')):
        scope, preparation = launcher._prepare_launch(ScanLaunchRequest(scope_id=draft['scope_id'],
            targets=['*.example.com'], profile='safe-recon', max_requests=5, max_rps=3,
            authorization_confirmed=True))
    assert scope.scope_id == draft['scope_id']
    assert scope.directory == revision
    preparation.require_ready()

@pytest.mark.parametrize('status', ['collecting','awaiting_browser','paused','cancelling','review_required'])
@pytest.mark.parametrize('refresh', [False,True])
def test_existing_approval_never_bypasses_active_or_review_job(setup, status, refresh):
    _, _, program_id, _, _, manager = setup
    manager.start(program_id, ScopeCollectionRequest())
    job_id = manager.get_job(program_id)['scope_job_id']
    manager._update(job_id, status=status)
    with pytest.raises(ValueError, match='running|waiting for review'):
        start(manager, program_id, refresh)
    assert manager.get_job(program_id)['scope_status'] == status
    assert manager.get_job(program_id)['scope_job_id'] == job_id

@pytest.mark.parametrize('outcome', ['rejected','failed','pending','collecting','cancelled'])
def test_prior_approved_revision_survives_unapproved_next_refresh(setup, outcome):
    _, registry, program_id, canonical, _, manager = setup
    start(manager, program_id)
    manager.decide(program_id, YES)
    approved = manager.approved_scope(program_id)['scope']['scope_id']
    previous = manager._job_and_program(program_id)[0]['output_path']
    original = archive_bytes(Path(previous))
    if outcome == 'failed':
        def fail_collection():
            raise RuntimeError('offline capture failed')
        manager._agent_factory = fail_collection
    job = start(manager, program_id)
    if outcome == 'rejected':
        manager.decide(program_id, ScopeDecisionRequest(decision='no'))
    elif outcome in {'collecting','cancelled'}:
        manager._update(job['scope_job_id'], status=outcome)
    elif outcome == 'failed':
        assert job['scope_status'] == 'failed'
        assert job['scope_error'] == 'offline capture failed'
    assert manager.approved_scope(program_id)['scope']['scope_id'] == approved
    restarted = ScopeWorkflowManager(manager.result_root, registry, agent_factory=RevisedAgent, worker_mode=True)
    assert restarted.approved_scope(program_id)['scope']['scope_id'] == approved
    assert archive_bytes(Path(previous)) == original
    assert len(ApprovedScopeCatalog(manager.result_root).list()) == 2

def test_worker_uses_persisted_destination_without_recomputing_on_changed_state(setup):
    root, registry, program_id, canonical, _, manager = setup
    with patch('aidast.web.scope_workflow.threading.Thread.start', lambda thread:None):
        job = manager.start(program_id, ScopeCollectionRequest().model_copy(update={'refresh':True}))
    expected = canonical/'revisions'/job['scope_job_id']
    assert Path(manager._job_and_program(program_id)[0]['output_path']) == expected
    worker = ScopeWorkflowManager(root, registry, agent_factory=RevisedAgent, worker_mode=True)
    assert worker.run_worker(program_id, job['scope_job_id'], ScopeCollectionRequest()) == 0
    draft_id = worker.draft(program_id)['scope_id']
    manager.decide(program_id, YES)
    assert ScopeCoordinator(expected).load_approved_scope()[0].scope_id == draft_id

@pytest.mark.parametrize('bad_path', ['outside','other_job','symlink'])
def test_worker_and_approval_reject_changed_or_symlink_output_paths(setup, bad_path):
    root, _, program_id, canonical, _, manager = setup
    with patch('aidast.web.scope_workflow.threading.Thread.start', lambda thread:None):
        job = manager.start(program_id, ScopeCollectionRequest().model_copy(update={'refresh':True}))
    if bad_path == 'outside':
        path = root/'elsewhere'
    elif bad_path == 'other_job':
        path = canonical/'revisions'/('scopejob_'+'f'*32)
    else:
        (canonical/'revisions').symlink_to(root/'external', target_is_directory=True)
        path = canonical/'revisions'/job['scope_job_id']
    with sqlite3.connect(manager.database) as conn:
        conn.execute('UPDATE scope_jobs SET output_path=?', (str(path),))
    with pytest.raises(ValueError, match='path|link|destination'):
        manager.run_worker(program_id, job['scope_job_id'], ScopeCollectionRequest())
    assert not (root/'external').exists()

def test_legacy_job_migration_keeps_null_canonical_fallback(tmp_path):
    registry = ProgramRegistry(tmp_path)
    program_id = registry.register(ProgramRegistrationRequest(program_url=URL, visibility='public'))['id']
    db = tmp_path/'.webui'/'scope_jobs.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE scope_jobs (job_id TEXT PRIMARY KEY, program_key TEXT UNIQUE,status TEXT,login_mode TEXT,draft_path TEXT,error TEXT,created_at TEXT,updated_at TEXT)')
        conn.execute('INSERT INTO scope_jobs VALUES (?,?,?,?,?,?,?,?)',
            ('scopejob_'+'a'*32, registry.get(program_id)['program_key'],'collecting','headless',None,None,'old','old'))
    manager = ScopeWorkflowManager(tmp_path, registry, agent_factory=FakeMainAgent, worker_mode=True)
    assert manager._job_and_program(program_id)[0]['output_path'] is None
    assert manager.run_worker(program_id, 'scopejob_'+'a'*32, ScopeCollectionRequest()) == 0
    manager.decide(program_id, YES)
    assert (tmp_path/'Scope'/'bugcrowd'/'example'/'Approval.json').is_file()

def test_catalog_ignores_symlink_revision_nonjob_revision_and_unapproved_archive(setup):
    root, _, program_id, canonical, old, manager = setup
    start(manager, program_id)
    manager.decide(program_id, YES)
    revisions = canonical/'revisions'
    (revisions/('scopejob_'+'b'*32)).symlink_to(canonical, target_is_directory=True)
    import shutil
    shutil.copytree(canonical, revisions/'manual', ignore=shutil.ignore_patterns('revisions'))
    rejected = revisions/('scopejob_'+'c'*32)
    shutil.copytree(canonical, rejected, ignore=shutil.ignore_patterns('revisions'))
    (rejected/'Approval.json').unlink()
    assert len(ApprovedScopeCatalog(root).list()) == 2


def test_request_accepts_explicit_refresh_but_no_filesystem_destination():
    assert ScopeCollectionRequest.model_validate({'refresh':True}).refresh is True
    assert ScopeCollectionRequest().refresh is False
    with pytest.raises(ValueError):
        ScopeCollectionRequest.model_validate({'output_path':'/tmp/arbitrary'})


def test_isolated_worker_entrypoint_reads_saved_revision_and_approves_same_directory(setup):
    import io
    from aidast.web import scope_worker
    root, registry, program_id, canonical, _, manager = setup
    with patch('aidast.web.scope_workflow.threading.Thread.start', lambda thread:None):
        job = manager.start(program_id, ScopeCollectionRequest(refresh=True))
    revision = canonical/'revisions'/job['scope_job_id']
    # The isolated entrypoint receives a refresh=False request on purpose: the
    # database destination is authoritative, not current options/filesystem state.
    with patch.object(scope_worker.sys, 'argv', ['scope_worker',str(root),program_id,job['scope_job_id']]), \
         patch.object(scope_worker.sys, 'stdin', io.StringIO('{"login_mode":"headless"}')), \
         patch.object(scope_worker, 'ScopeWorkflowManager', lambda *args, **kwargs:
             ScopeWorkflowManager(root, registry, agent_factory=RevisedAgent, worker_mode=True)):
        assert scope_worker.main() == 0
    new_id = manager.draft(program_id)['scope_id']
    manager.decide(program_id, YES)
    assert ScopeCoordinator(revision).load_approved_scope()[0].scope_id == new_id


def test_launch_and_cli_bind_selected_revision_instead_of_canonical(setup):
    from types import SimpleNamespace
    from aidast import cli
    root, _, program_id, canonical, old, manager = setup
    job = start(manager, program_id)
    manager.decide(program_id, YES)
    new_id = manager.approved_scope(program_id)['scope']['scope_id']
    captured = {}
    def fake_process(argv, **kwargs):
        captured['argv'] = argv
        return SimpleNamespace(pid=424242)
    launcher = ScanLaunchManager(root, DashboardProjector(root), project_root=root, process_factory=fake_process)
    request = ScanLaunchRequest(scope_id=new_id, targets=['*.example.com'], profile='safe-recon',
        max_requests=5, max_rps=3, authorization_confirmed=True)
    with patch.object(launcher, '_record_process', lambda *args:None), \
         patch('aidast.web.launch.threading.Thread.start', lambda thread:None), \
         patch('aidast.agents.main.CodexMainAgent', side_effect=AssertionError('no interpretation')):
        result = launcher.launch(request)
    assert launcher._jobs[result['scan_id']].scope.scope_id == new_id
    argv = captured['argv']
    assert argv[argv.index('--scope-revision')+1] == job['scope_job_id']
    class SelectionReached(Exception):
        pass
    def stop_before_recon(document, **kwargs):
        assert document.scope_id == new_id
        assert document.scope_id != old.scope_id
        assert document.analysis.execution_rules.request_limits[0].maximum == 3
        raise SelectionReached
    with patch('aidast.cli.CodexMainAgent', return_value=FakeMainAgent()), \
         patch('aidast.cli._select_recon_targets', stop_before_recon):
        with pytest.raises(SelectionReached):
            cli.main(argv[3:])


@pytest.mark.parametrize('revision', ['../../elsewhere','scopejob_'+'d'*32])
def test_cli_invalid_or_unapproved_revision_cannot_fall_back_or_collect(setup, revision, capsys):
    from aidast import cli
    root, _, _, _, _, _ = setup
    with patch('aidast.cli.CodexMainAgent', side_effect=AssertionError('no collection/model')):
        assert cli.main(['run',URL,'--target','*.example.com','--output-dir',str(root/'Scope'),
            '--scope-revision',revision]) == 1
    assert 'Reusing approved Scope' not in capsys.readouterr().out


def test_first_collection_refresh_without_canonical_uses_canonical(setup):
    import shutil
    _, _, program_id, canonical, _, manager = setup
    shutil.rmtree(canonical)
    job = start(manager, program_id)
    assert job['scope_status'] == 'review_required'
    assert manager._job_and_program(program_id)[0]['output_path'] == str(canonical)
    manager.decide(program_id, YES)
    assert (canonical/'Approval.json').is_file()


def test_review_exposes_unresolved_reference_failure_and_legacy_execution_pending():
    from aidast.scope.models import ScopeDocument
    ref = PolicyReferenceCapture(candidate_id=5, parent_url=URL, source_quote='Read the disclosure guide.',
        applicability='disclosure', depth=1, requested_url='https://docs.example.test/disclosure',
        captured_at=datetime.now(timezone.utc), status='unresolved', error='Unsupported document format')
    doc = ScopeDocument(scope_id='scope_legacy', created_at=datetime.now(timezone.utc),
        source=sample_page().model_copy(update={'policy_references':[ref]}),
        analysis=sample_analysis().model_copy(update={'execution_rules':None,'required_request_headers':None}))
    payload = ScopeWorkflowManager._review_payload(doc)
    assert payload['execution_rules'] is None
    assert payload['required_request_headers'] is None
    assert payload['policy_references'][0]['error'] == 'Unsupported document format'
    assert payload['policy_references'][0]['applicability'] == 'disclosure'


def test_review_and_decision_reject_symlink_destination_inserted_after_collection(setup):
    root, _, program_id, canonical, _, manager = setup
    job = start(manager, program_id)
    original = archive_bytes(canonical)
    (canonical/'revisions').symlink_to(root/'redirected', target_is_directory=True)
    with pytest.raises(ValueError, match='symbolic link'):
        manager.draft(program_id)
    with pytest.raises(ValueError, match='symbolic link'):
        manager.decide(program_id, YES)
    assert archive_bytes(canonical) == original
    assert not (root/'redirected').exists()


def test_concurrent_managers_cannot_replace_an_active_refresh_job(setup):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    root, registry, program_id, _, _, manager = setup
    second = ScopeWorkflowManager(root, registry, agent_factory=RevisedAgent, worker_mode=True)
    barrier = threading.Barrier(2)
    original_get = registry.get
    entered = threading.local()
    def get_together(key):
        result = original_get(key)
        if not getattr(entered, 'started', False):
            entered.started = True
            barrier.wait(timeout=3)
        return result
    def attempt(item):
        try:
            return item.start(program_id, ScopeCollectionRequest(refresh=True))
        except ValueError as exc:
            return str(exc)
    # Delay is injected only at the registry read, before the database lock.
    # Workers are kept pending so the test cannot accidentally finish a job.
    with patch.object(registry, 'get', get_together), \
         patch.object(ScopeWorkflowManager, '_collect', lambda *args:None):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [manager,second]))
    accepted = [result for result in results if isinstance(result,dict)]
    refused = [result for result in results if isinstance(result,str)]
    assert len(accepted) == 1
    assert refused == ['Scope collection is already running']
    assert manager.get_job(program_id)['scope_job_id'] == accepted[0]['scope_job_id']


def test_verified_revision_with_foreign_program_identity_is_not_catalogued_or_run(setup):
    from aidast import cli
    root, _, _, canonical, old, _ = setup
    job_id = 'scopejob_'+'e'*32
    directory = canonical/'revisions'/job_id
    foreign_url = 'https://bugcrowd.com/engagements/another'
    class ForeignAgent(FakeMainAgent):
        def collect_scope(self, _url):
            return sample_page().model_copy(update={'requested_url':HttpUrl(foreign_url),
                'final_url':HttpUrl(foreign_url)}), sample_analysis()
    ScopeCoordinator(directory).collect(foreign_url, main_agent=ForeignAgent(),
        approved_by='foreign-reviewer', review=lambda _:True)
    assert [item.scope_id for item in ApprovedScopeCatalog(root).list()] == [old.scope_id]
    with patch('aidast.cli.CodexMainAgent', side_effect=AssertionError('no collection/model')):
        assert cli.main(['run',URL,'--target','*.example.com','--output-dir',str(root/'Scope'),
            '--scope-revision',job_id]) == 1
