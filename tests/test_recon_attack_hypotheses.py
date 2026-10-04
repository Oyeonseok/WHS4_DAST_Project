import json
import sqlite3
from pathlib import Path

import pytest

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.attack.coverage import (
    ensure_coverage_manifest, claim_coverage_batch, _task_fixtures,
)
from aidast.pipeline.lifecycle import start_stage_run


def pipeline(tmp_path: Path):
    path = tmp_path / 'Pipeline.db'
    conn = db.init_db(path)
    migrate_live_pipeline_schema(conn)
    db.insert_scan(conn, scan_id='scan', scope_type='test', scope_value='approved')
    asset = db.insert_asset(conn, scan_id='scan', identifier='example.test', asset_type='DOMAIN')
    origin = db.upsert_origin(conn, asset_id=asset, scheme='https', host='example.test', port=443, base_url='https://example.test')
    ObservationRecorder(conn, origin_id=origin, scan_id='scan').record('browser', [
        {'method': 'GET', 'path': '/search', 'url': 'https://example.test/search?q=private-value', 'source': 'playwright_http'},
        {'method': 'GET', 'path': '/opaque', 'url': 'https://example.test/opaque', 'source': 'playwright_http'},
    ])
    conn.execute("INSERT INTO annotation_runs VALUES ('tags','scan','fixture','tags','1','completed',NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
    for index, row in enumerate(conn.execute('SELECT observation_id,e.normalized_path FROM endpoint_observations o JOIN endpoints e ON e.endpoint_id=o.endpoint_id').fetchall()):
        conn.execute("INSERT INTO endpoint_annotations VALUES (?,?, 'tags','function',?, 'fixture evidence',NULL,CURRENT_TIMESTAMP)",
                     (f'tag-{index}', row[0], 'search' if row[1] == '/search' else 'unknown'))
    conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP")
    conn.commit()
    conn.close()
    return path


class Planner:
    def __init__(self, change=None):
        self.contexts = []
        self.change = change

    def _run_structured(self, *, prompt, model_type, **kwargs):
        context = json.loads(prompt.split('<untrusted_recon_json>\n', 1)[1].split('\n</untrusted_recon_json>', 1)[0])
        self.contexts.append(context)
        endpoints = []
        for endpoint in context['endpoints']:
            search = endpoint['path'] == '/search'
            hypotheses = [{
                'vuln_class': name, 'annotation_ids': [endpoint['annotations'][0]['annotation_id']],
                'parameter_name': 'q', 'injection_location': 'query',
                'required_identity_role': 'unauthenticated',
                'rationale': 'Observed search input warrants a bounded differential test.',
            } for name in ('sqli', 'xss')] if search else []
            endpoints.append({'endpoint_id': endpoint['endpoint_id'], 'hypotheses': hypotheses,
                              'disposition': 'planned' if search else 'insufficient_evidence',
                              'reason': 'Search evidence' if search else 'No function or input evidence.'})
        response = {'endpoints': endpoints}
        if self.change:
            self.change(response, context)
        return model_type.model_validate(response)


def test_normal_tags_create_parameter_bound_hypotheses_and_account_for_unknowns(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    agent = Planner()
    plan_recon_attack(path, 'scan', agent=agent)
    manifest = ensure_coverage_manifest(path, 'scan')
    assert manifest.total == 2
    assert manifest.by_vulnerability == {'sqli': 1, 'xss': 1}
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT status,count(*) FROM attack_endpoint_reviews GROUP BY status').fetchall() == [
            ('insufficient_evidence', 1), ('planned', 1)]
        assert conn.execute('SELECT injection_location,parameter_name,required_identity_role FROM attack_coverage_items').fetchall() == [
            ('query', 'q', 'unauthenticated'), ('query', 'q', 'unauthenticated')]
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    assert 'private-value' not in json.dumps(agent.contexts)
    ordinary_observation = agent.contexts[0]['endpoints'][0]['observations'][0]
    assert 'discovery_kind' not in ordinary_observation
    assert 'evidence_json' not in ordinary_observation


def test_black_box_planning_never_consumes_source_or_benchmark_answers(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack

    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        observation = conn.execute(
            "SELECT o.observation_id FROM endpoint_observations o "
            "JOIN endpoints e ON e.endpoint_id=o.endpoint_id "
            "WHERE e.normalized_path='/search'"
        ).fetchone()[0]
        conn.executemany(
            "INSERT INTO endpoint_annotations(annotation_id,observation_id,annotation_run_id,"
            "category,tag,rationale,created_at) VALUES (?,?,'tags',?,?,'answer',CURRENT_TIMESTAMP)",
            [
                ('source-answer', observation, 'source_vulnerability', 'sqli'),
                ('benchmark-answer', observation, 'benchmark_catalog_vulnerability', 'xss'),
            ],
        )
        conn.executemany(
            "INSERT INTO attack_facts(fact_id,scan_id,fact_type,fact_key,fact_value,confidence) "
            "VALUES (?,'scan',?,?,?,1.0)",
            [
                ('owned', 'owned_test_object', 'owned.id', '{"object_id":"1"}'),
                ('benchmark', 'benchmark_fixture', 'answer.id', '{"object_id":"2"}'),
            ],
        )

    agent = Planner()
    plan_recon_attack(path, 'scan', agent=agent)
    manifest = ensure_coverage_manifest(path, 'scan')

    serialized = json.dumps(agent.contexts)
    assert 'source-answer' not in serialized
    assert 'benchmark-answer' not in serialized
    assert manifest.by_vulnerability == {'sqli': 1, 'xss': 1}
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute(
            "SELECT count(*) FROM attack_coverage_items "
            "WHERE annotation_id IN ('source-answer','benchmark-answer')"
        ).fetchone()[0] == 0
        assert [item['fact_type'] for item in _task_fixtures(
            conn, 'scan', parameter_name='id',
        )] == ['owned_test_object']


def test_grounded_baseline_keeps_strong_recon_signals_in_attack_queue(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)

    def omit_search_hypotheses(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row.update({
            'hypotheses': [],
            'disposition': 'insufficient_evidence',
            'reason': 'Model omitted the observed input.',
        })

    plan_recon_attack(path, 'scan', agent=Planner(omit_search_hypotheses))
    manifest = ensure_coverage_manifest(path, 'scan')
    assert manifest.by_vulnerability == {'sqli': 1, 'xss': 1}
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT status FROM attack_endpoint_reviews r JOIN endpoints e "
            "ON e.endpoint_id=r.endpoint_id WHERE e.normalized_path='/search'"
        ).fetchone() == ('planned',)
        rationales = [row[0] for row in conn.execute(
            "SELECT rationale FROM endpoint_annotations WHERE category='attack_hypothesis'"
        )]
    assert all('private-value' not in rationale for rationale in rationales)


def test_grounded_black_box_hypotheses_supplement_partial_model_plan(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)

    def omit_one_observed_input_class(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row['hypotheses'] = [
            item for item in row['hypotheses'] if item['vuln_class'] == 'sqli'
        ]

    agent = Planner(omit_one_observed_input_class)
    plan_recon_attack(path, 'scan', agent=agent)
    manifest = ensure_coverage_manifest(path, 'scan')

    assert manifest.by_vulnerability == {'sqli': 1, 'xss': 1}
    assert 'private-value' not in json.dumps(agent.contexts)


def test_grounded_baseline_reviews_observed_successful_api_reads_for_exposure():
    from aidast.attack.coverage import hypothesis_skill_catalog
    from aidast.attack.recon_hypotheses import _grounded_baseline_hypotheses

    hypotheses = _grounded_baseline_hypotheses({
        'path': '/api/Profiles', 'method': 'GET', 'auth_required': False,
        'http_statuses': [200], 'parameters': [], 'technology_context': {},
        'response_header_names': [],
    }, hypothesis_skill_catalog())

    assert 'api_misconfig' in {item.vuln_class for item in hypotheses}


@pytest.mark.parametrize(
    ('path', 'method', 'expected'),
    [
        ('/rest/user/whoami', 'GET', {'auth_bypass', 'session'}),
        ('/rest/order-history', 'GET', {'auth_bypass'}),
        ('/rest/saveLoginIp', 'GET', {'business_logic', 'csrf'}),
        ('/rest/2fa/disable', 'POST', {'mfa_bypass', 'session', 'business_logic', 'csrf'}),
    ],
)
def test_grounded_route_semantics_create_black_box_boundary_hypotheses(
    path, method, expected,
):
    from aidast.attack.coverage import hypothesis_skill_catalog
    from aidast.attack.recon_hypotheses import _grounded_baseline_hypotheses

    hypotheses = _grounded_baseline_hypotheses({
        'path': path, 'method': method, 'auth_required': False,
        'http_statuses': [200], 'parameters': [], 'technology_context': {},
        'response_header_names': [],
    }, hypothesis_skill_catalog())
    by_class = {item.vuln_class: item for item in hypotheses}

    assert expected <= set(by_class)
    for name in expected & {'business_logic', 'csrf'}:
        assert by_class[name].required_identity_role == 'authenticated'


def test_attack_plans_exact_public_client_declarations_but_not_inferred_crud(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        origin = conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        ObservationRecorder(conn, origin_id=origin, scan_id='scan').record('passive', [
            {
                'method': 'POST', 'path': '/rest/chat',
                'url': 'https://example.test/rest/chat',
                'source': 'adaptive_js', 'discovery_kind': 'js_http_call',
                'verification_status': 'candidate', 'traffic_class': 'passive',
                'declared_parameters': [
                    {'name': 'messages', 'location': 'json', 'data_type': 'array'},
                ],
            },
            {
                'method': 'DELETE', 'path': '/api/Guesses/{id}',
                'url': 'https://example.test/api/Guesses/{id}',
                'source': 'passive_route_inference',
                'discovery_kind': 'rest_resource_family',
                'verification_status': 'candidate', 'traffic_class': 'passive',
            },
            {
                'method': 'GET', 'path': '/%7B%7Bhref%7D%7D',
                'url': 'https://example.test/%7B%7Bhref%7D%7D',
                'source': 'playwright_http', 'discovery_kind': 'http_request',
            },
        ])

    agent = Planner()
    result = plan_recon_attack(path, 'scan', agent=agent)
    manifest = ensure_coverage_manifest(path, 'scan')

    planned_paths = {
        endpoint['path']
        for call in agent.contexts
        for endpoint in call['endpoints']
    }
    assert '/rest/chat' in planned_paths
    assert '/api/Guesses/{id}' not in planned_paths
    assert '/%7B%7Bhref%7D%7D' not in planned_paths
    assert result['total_endpoints'] == 3
    assert manifest.by_vulnerability['llm_ai'] == 1
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT is_excluded,exclude_reason FROM endpoints WHERE normalized_path='/rest/chat'"
        ).fetchone()
    assert row == (1, 'unverified_candidate')


def test_planner_receives_sanitized_public_openapi_operation_metadata(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack

    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        origin = conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        ObservationRecorder(conn, origin_id=origin, scan_id='scan').record('passive', [{
            'method': 'POST', 'path': '/transfer',
            'url': 'https://example.test/transfer',
            'source': 'passive_declaration',
            'discovery_kind': 'api_spec_declaration',
            'verification_status': 'candidate', 'traffic_class': 'passive',
            'evidence': {
                'operation_summary': 'Transfer funds',
                'operation_description': 'password=hidden Check transfer invariants.',
                'operation_tags': ['transactions'],
            },
            'declared_parameters': [
                {'name': 'amount', 'location': 'json', 'data_type': 'number'},
            ],
        }])

    agent = Planner()
    plan_recon_attack(path, 'scan', agent=agent)
    transfer = next(endpoint for call in agent.contexts for endpoint in call['endpoints']
                    if endpoint['path'] == '/transfer')
    declaration = transfer['observations'][0]['declaration_evidence']
    assert declaration['operation_summary'] == 'Transfer funds'
    assert 'hidden' not in declaration['operation_description']
    assert declaration['operation_tags'] == ['transactions']


def test_replanning_is_idempotent_and_respects_parameter_identity_variants(tmp_path, monkeypatch):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def change(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row['hypotheses'].append({**row['hypotheses'][0], 'required_identity_role': 'authenticated'})
    agent = Planner(change)
    plan_recon_attack(path, 'scan', agent=agent)
    plan_recon_attack(path, 'scan', agent=agent)
    assert len(agent.contexts) == 1
    assert ensure_coverage_manifest(path, 'scan').total == 3
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        from aidast.pipeline.lifecycle import register_credential_reference
        register_credential_reference(
            conn, scan_id='scan', label='fixture-auth',
            reference_uri='env://AIDAST_TEST_COVERAGE_AUTH',
            identity_role='authenticated',
        )
        monkeypatch.setenv(
            'AIDAST_TEST_COVERAGE_AUTH',
            '{"Authorization":"Bearer fixture"}',
        )
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        tasks = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=8)
        assert len(tasks) == 3
        assert {task['required_identity_role'] for task in tasks} == {'authenticated', 'unauthenticated'}
        assert all(task['parameter_name'] == 'q' for task in tasks)
        assert all(task['source_context']['active_annotation']['category'] == 'attack_hypothesis' for task in tasks)


@pytest.mark.parametrize('invalid', ['endpoint', 'annotation', 'parameter', 'skill', 'omitted'])
def test_model_cannot_invent_or_omit_endpoint_evidence(tmp_path, invalid):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def change(response, context):
        if invalid == 'omitted':
            response['endpoints'] = [row for row in response['endpoints'] if row['hypotheses']]
            return
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        if invalid == 'endpoint': row['endpoint_id'] = 'invented'
        elif invalid == 'annotation': row['hypotheses'][0]['annotation_ids'] = ['foreign-annotation']
        elif invalid == 'parameter': row['hypotheses'][0]['parameter_name'] = 'invented'
        elif invalid == 'skill': row['hypotheses'][0]['vuln_class'] = 'invented'
    agent = Planner(change)
    plan_recon_attack(path, 'scan', agent=agent)
    assert len(agent.contexts) == 3
    manifest = ensure_coverage_manifest(path, 'scan')
    expected = {} if invalid == 'endpoint' else ({'sqli': 1, 'xss': 1} if invalid == 'omitted' else {'xss': 1})
    assert manifest.by_vulnerability == expected
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT count(*) FROM attack_endpoint_reviews').fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM attack_planning_diagnostics WHERE status='unresolved'").fetchone()[0] >= 1
        metadata = conn.execute("SELECT rationale FROM endpoint_annotations WHERE category='attack_hypothesis'").fetchall()
        assert 'invented' not in json.dumps(metadata)
        assert 'foreign-annotation' not in json.dumps(metadata)


def test_more_than_eight_hypotheses_are_retained(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import VULNERABILITY_SKILLS
    path = pipeline(tmp_path)
    def change(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        first = row['hypotheses'][0]
        row['hypotheses'] = [{**first, 'vuln_class': name} for name in list(VULNERABILITY_SKILLS)[:10]]
    plan_recon_attack(path, 'scan', agent=Planner(change))
    assert ensure_coverage_manifest(path, 'scan').total == 12


def test_normal_attack_processes_the_whole_endpoint_queue_in_batches_of_eight(tmp_path):
    from aidast.attack.coverage import VULNERABILITY_SKILLS
    from aidast.orchestration.attack import AttackCoordinator
    from test_attack_coverage import UnsupportedCoverageAgent
    path = pipeline(tmp_path)
    def change(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row['hypotheses'] = [{**row['hypotheses'][0], 'vuln_class': name}
                             for name in list(VULNERABILITY_SKILLS)[:10]]
    class Agent(Planner):
        run_attack_orchestrator = UnsupportedCoverageAgent.run_attack_orchestrator
    agent = Agent(change)
    agent.calls = []
    scope, policy = tmp_path/'Scope.md', tmp_path/'TargetPolicy.json'
    scope.write_text('# Approved fixture')
    policy.write_text('{"policies":[]}')
    result = AttackCoordinator(agent=agent, db_path=path, scope_path=scope, policy_path=policy).run('scan')
    assert result.status == 'COMPLETED'
    assert [len(call['attack_tasks']) for call in agent.calls] == [8, 4]
    assert all(task.get('endpoint_id') and task.get('coverage_id')
               for call in agent.calls for task in call['attack_tasks'])
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM attack_tasks').fetchone()[0] == 12
        assert conn.execute("SELECT COUNT(*) FROM attack_coverage_items WHERE status='unsupported'").fetchone()[0] == 12


def test_planner_service_failure_records_a_failed_attack_stage_for_resume(tmp_path):
    from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
    path = pipeline(tmp_path)
    def change(response, context):
        raise RuntimeError('model service unavailable')
    scope, policy = tmp_path/'Scope.md', tmp_path/'TargetPolicy.json'
    scope.write_text('# Approved fixture')
    policy.write_text('{"policies":[]}')
    with pytest.raises(AttackCoordinatorError, match='model service unavailable'):
        AttackCoordinator(agent=Planner(change), db_path=path, scope_path=scope, policy_path=policy).run('scan')
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM stage_runs WHERE stage='attack' ORDER BY rowid DESC LIMIT 1").fetchone() == ('failed',)


def test_batch_failure_after_planning_is_durable_and_resumable(tmp_path, monkeypatch):
    from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
    from aidast.orchestration.coverage_attack import ExhaustiveAttackCoordinator
    path = pipeline(tmp_path)
    scope, policy = tmp_path/'Scope.md', tmp_path/'TargetPolicy.json'
    scope.write_text('# Approved fixture')
    policy.write_text('{"policies":[]}')
    def fail(self, scan_id):
        raise AttackCoordinatorError('batch budget exhausted with pending coverage')
    monkeypatch.setattr(ExhaustiveAttackCoordinator, 'run', fail)
    with pytest.raises(AttackCoordinatorError, match='pending coverage'):
        AttackCoordinator(agent=Planner(), db_path=path, scope_path=scope, policy_path=policy).run('scan')
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT status FROM stage_runs WHERE stage='attack' ORDER BY rowid DESC LIMIT 1").fetchone() == ('failed',)


def test_dashboard_reports_whole_queue_and_exact_endpoint_without_writing(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        tasks = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)
    before = path.read_bytes()
    response = DashboardProjector(tmp_path, database=path).attack_tasks('scan')
    assert path.read_bytes() == before
    assert response['coverage']['total'] == 2
    assert response['coverage']['endpoints_reviewed'] == 2
    assert response['coverage']['insufficient_evidence_endpoints'] == 1
    assert response['coverage']['tested'] == 0
    assert response['coverage']['unfinished'] == 2
    assert response['tasks'][0]['coverage']['parameter_name'] == 'q'
    assert response['tasks'][0]['observed_urls'] == [{'method': 'GET', 'url': 'https://example.test/search', 'hint': 'Endpoint hypothesis'}]
    assert 'private-value' not in json.dumps(response)
    assert response['coverage']['gaps'][0]['url'] == 'https://example.test/opaque'


def test_dashboard_does_not_show_completed_between_coverage_batches(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.pipeline.lifecycle import finish_stage_run
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        finish_stage_run(conn, stage, status='completed')
        conn.execute("UPDATE attack_coverage_items SET status='unsupported',disposition_reason='Budget exhausted' WHERE vuln_class='sqli'")
    projector = DashboardProjector(tmp_path, database=path)
    response = projector.attack_tasks('scan')
    assert response['coverage']['tested'] == 0
    assert response['coverage']['resolved'] == 1
    assert response['coverage']['budget_limited'] == 1
    snapshot = projector.snapshot('scan')
    assert snapshot['status'] == 'running'
    assert snapshot['stage_statuses']['Attack'] == 'running'
    # Attack planning occupies 0-20%; one of two durable coverage items then
    # advances halfway through the remaining execution range.
    assert snapshot['progress'] == 60


def test_completed_batch_with_pending_queue_can_resume_normal_attack(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.orchestration.attack import AttackCoordinator
    from aidast.pipeline.lifecycle import finish_stage_run
    from test_attack_coverage import UnsupportedCoverageAgent
    path = pipeline(tmp_path)
    planner = Planner()
    plan_recon_attack(path, 'scan', agent=planner)
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        finish_stage_run(conn, stage, status='completed')
    scope, policy = tmp_path/'Scope.md', tmp_path/'TargetPolicy.json'
    scope.write_text('# Approved fixture')
    policy.write_text('{"policies":[]}')
    class Agent(Planner):
        run_attack_orchestrator = UnsupportedCoverageAgent.run_attack_orchestrator
    agent = Agent()
    agent.calls = []
    result = AttackCoordinator(agent=agent, db_path=path, scope_path=scope, policy_path=policy).run('scan')
    assert result.status == 'COMPLETED'
    assert len(agent.contexts) == 0
    assert len(agent.calls[0]['attack_tasks']) == 2


def test_resume_inspection_returns_attack_for_unreviewed_endpoints_after_a_completed_batch(tmp_path):
    from aidast.pipeline.resume import inspect_resume
    from test_scan_resume import _fixture, SCAN_ID
    from aidast.pipeline.lifecycle import finish_stage_run
    path = _fixture(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('unreviewed','origin','GET','/opaque')")
        conn.execute("INSERT INTO attack_endpoint_reviews(scan_id,endpoint_id,evidence_sha256,status,reason,hypothesis_count) VALUES (?, 'login', ?, 'insufficient_evidence','fixture',0)", (SCAN_ID, 'f'*64))
        stage = start_stage_run(conn, scan_id=SCAN_ID, stage='attack')
        finish_stage_run(conn, stage, status='completed')
    assert inspect_resume(tmp_path, SCAN_ID).stage == 'attack'


@pytest.mark.parametrize('has_http', [False, True])
def test_prior_finding_does_not_cover_different_parameter_or_identity_hypotheses(tmp_path, has_http):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import _adopt_existing_findings
    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        endpoint_id = conn.execute("SELECT endpoint_id FROM endpoints WHERE normalized_path='/search'").fetchone()[0]
        conn.execute("INSERT INTO parameters(parameter_id,endpoint_id,name,location) VALUES ('filter',?,'filter','query')", (endpoint_id,))
    def variants(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        first = row['hypotheses'][0]
        row['hypotheses'] = [first, {**first, 'required_identity_role':'authenticated'}, {**first, 'parameter_name':'filter'}]
    plan_recon_attack(path, 'scan', agent=Planner(variants))
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        matched = conn.execute(
            "SELECT * FROM attack_coverage_items WHERE vuln_class='sqli' "
            "AND parameter_name='q' AND required_identity_role='unauthenticated'"
        ).fetchone()
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        from aidast.pipeline.lifecycle import create_task
        task = create_task(conn, stage_run_id=stage, skill_name='hunt-sqli', endpoint_id=endpoint_id, payload={'coverage_id':matched['coverage_id']})
        conn.execute("INSERT INTO findings(finding_id,scan_id,vuln_type,title,severity,endpoint_id) VALUES ('finding','scan','sqli','fixture','LOW',?)", (endpoint_id,))
        conn.execute("INSERT INTO attack_attempts(attempt_id,scan_id,task_id,endpoint_id,skill_name,identity_role,request_fingerprint,payload_variant,outcome,finding_id) VALUES ('attempt','scan',?,?,'hunt-sqli','unauthenticated',?,'fixture','confirmed','finding')", (task,endpoint_id,'f'*64))
        conn.execute("""INSERT INTO finding_reproduction_specs(finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,parameter_name,payload_template_json,required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,source_policy_sha256,spec_sha256,runtime_contract_json,runtime_contract_sha256)
            VALUES ('finding','hunt-sqli',?,'GET','/search','query','q','{}','[]','["attempt"]','["request"]',?,?,?,'{}',?)""", (endpoint_id, *(['f'*64]*4)))
        if has_http:
            conn.execute("INSERT INTO attack_http_requests(request_id,scan_id,stage_run_id,task_id,policy_id,method,url,request_fingerprint,status,response_status,scheduled_at,endpoint_reference_id,result_json) VALUES ('request','scan',?,?,'policy','GET','https://example.test/search',?,'completed',200,0,?,'{}')", (stage,task,'f'*64,endpoint_id))
        _adopt_existing_findings(conn, 'scan')
        states = {
            (row['vuln_class'], row['parameter_name'], row['required_identity_role']): row['status']
            for row in conn.execute('SELECT * FROM attack_coverage_items')
        }
        assert states == {
            ('sqli', 'q', 'unauthenticated'): 'candidate' if has_http else 'pending',
            ('sqli', 'q', 'authenticated'): 'pending',
            ('sqli', 'filter', 'unauthenticated'): 'pending',
            ('xss', 'q', 'unauthenticated'): 'pending',
        }


def test_a_negative_attempt_without_completed_http_evidence_is_not_tested(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import reconcile_coverage_batch
    from aidast.attack.db_cli import commit_attempt, transition_task
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        task = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)[0]
    transition_task(path, 'scan', stage, task['task_id'], 'running')
    payload = tmp_path/'negative.json'
    payload.write_text(json.dumps({'endpoint_id':task['endpoint_id'], 'skill_name':task['skill_name'], 'task_id':task['task_id'], 'request_fingerprint':'0'*64, 'outcome':'negative'}))
    commit_attempt(path, 'scan', payload)
    transition_task(path, 'scan', stage, task['task_id'], 'completed')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        reconcile_coverage_batch(conn, stage_run_id=stage)
        assert conn.execute('SELECT status FROM attack_coverage_items WHERE coverage_id=?', (task['coverage_id'],)).fetchone()[0] == 'error_retryable'


def test_completed_inconclusive_http_evidence_is_terminal_unsupported(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import reconcile_coverage_batch
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        task = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)[0]
        endpoint = conn.execute(
            """SELECT e.method,e.normalized_path,o.base_url FROM endpoints e
               JOIN origins o ON o.origin_id=e.origin_id WHERE e.endpoint_id=?""",
            (task['endpoint_id'],),
        ).fetchone()
        conn.execute("UPDATE attack_tasks SET status='completed' WHERE task_id=?", (task['task_id'],))
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,endpoint_id,skill_name,request_fingerprint,
                outcome,resolution_reason,resolved_at)
               VALUES ('attempt-inconclusive','scan',?,?,?,?,'inconclusive',?,CURRENT_TIMESTAMP)""",
            (task['task_id'], task['endpoint_id'], task['skill_name'], 'f'*64,
             'The response did not establish the required security property.'),
        )
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('request-inconclusive','scan',?,?,'policy',?,?,?,'completed',200,0,?,'{}')""",
            (stage, task['task_id'], endpoint['method'],
             endpoint['base_url'].rstrip('/') + endpoint['normalized_path'],
             'f'*64, task['endpoint_id']),
        )
        reconcile_coverage_batch(conn, stage_run_id=stage)
        status, reason = conn.execute(
            'SELECT status,disposition_reason FROM attack_coverage_items WHERE coverage_id=?',
            (task['coverage_id'],),
        ).fetchone()
        assert status == 'unsupported'
        assert reason == 'The response did not establish the required security property.'


def test_off_target_attempt_does_not_poison_exact_inconclusive_evidence(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import reconcile_coverage_batch
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        task = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)[0]
        method = conn.execute(
            'SELECT method FROM endpoints WHERE endpoint_id=?', (task['endpoint_id'],),
        ).fetchone()[0]
        conn.execute("UPDATE attack_tasks SET status='completed' WHERE task_id=?", (task['task_id'],))
        conn.executemany(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,endpoint_id,skill_name,request_fingerprint,
                outcome,resolution_reason,resolved_at)
               VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
            [
                ('selected','scan',task['task_id'],task['endpoint_id'],task['skill_name'],
                 'a'*64,'inconclusive','Exact response remained inconclusive'),
                ('redirect','scan',task['task_id'],None,task['skill_name'],
                 'b'*64,'negative','Redirect target was outside the selected endpoint'),
            ],
        )
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('selected-request','scan',?,?,'policy',?,'https://example.test/exact',
                       ?,'completed',308,0,?,'{}')""",
            (stage, task['task_id'], method, 'a'*64, task['endpoint_id']),
        )
        reconcile_coverage_batch(conn, stage_run_id=stage)
        status, reason = conn.execute(
            'SELECT status,disposition_reason FROM attack_coverage_items WHERE coverage_id=?',
            (task['coverage_id'],),
        ).fetchone()
        assert status == 'unsupported'
        assert reason == 'Exact response remained inconclusive'


@pytest.mark.parametrize('request_endpoint,credential_reference,expected', [('exact',None,'tested_negative'),('other',None,'error_retryable'),('exact','invented-auth','error_retryable')])
def test_negative_coverage_requires_the_selected_endpoint_and_identity(tmp_path, request_endpoint, credential_reference, expected):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import reconcile_coverage_batch
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        task = claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)[0]
        conn.execute("UPDATE attack_tasks SET status='completed' WHERE task_id=?", (task['task_id'],))
        conn.execute("INSERT INTO attack_attempts(attempt_id,scan_id,task_id,endpoint_id,skill_name,request_fingerprint,outcome) VALUES ('negative','scan',?,?,?,?,'negative')", (task['task_id'], task['endpoint_id'],task['skill_name'],'f'*64))
        other = conn.execute("SELECT endpoint_id FROM endpoints WHERE normalized_path='/opaque'").fetchone()[0]
        conn.execute("""INSERT INTO attack_http_requests(request_id,scan_id,stage_run_id,task_id,policy_id,method,url,request_fingerprint,status,response_status,scheduled_at,endpoint_reference_id,result_json)
            VALUES ('request','scan',?,?,'policy','GET','https://example.test/search',?,'completed',200,0,?,?)""", (stage,task['task_id'],'f'*64,task['endpoint_id'] if request_endpoint == 'exact' else other,json.dumps({'credential_reference_id':credential_reference})))
        reconcile_coverage_batch(conn, stage_run_id=stage)
        assert conn.execute('SELECT status FROM attack_coverage_items WHERE coverage_id=?', (task['coverage_id'],)).fetchone()[0] == expected


def test_authenticated_positive_control_counts_for_anonymous_planned_task(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.attack.coverage import reconcile_coverage_batch
    from aidast.pipeline.lifecycle import register_credential_reference
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        reference = register_credential_reference(
            conn, scan_id='scan', label='positive-control',
            reference_uri='env://AIDAST_POSITIVE_CONTROL',
            identity_role='authenticated',
        )
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        task = claim_coverage_batch(
            conn, scan_id='scan', stage_run_id=stage, batch_size=1,
        )[0]
        payload = json.loads(conn.execute(
            'SELECT payload_json FROM attack_tasks WHERE task_id=?',
            (task['task_id'],),
        ).fetchone()[0])
        assert payload['required_identity_role'] == 'unauthenticated'
        assert payload['optional_control_identity_roles'] == ['authenticated']
        conn.execute(
            "UPDATE attack_tasks SET status='completed' WHERE task_id=?",
            (task['task_id'],),
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,endpoint_id,skill_name,
                request_fingerprint,outcome)
               VALUES ('auth-negative','scan',?,?,?,?,'negative')""",
            (task['task_id'], task['endpoint_id'], task['skill_name'], 'a'*64),
        )
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                request_fingerprint,status,response_status,scheduled_at,
                endpoint_reference_id,result_json)
               VALUES ('auth-request','scan',?,?,'policy','GET',
                       'https://example.test/search',?,'completed',200,0,?,?)""",
            (
                stage, task['task_id'], 'a'*64, task['endpoint_id'],
                json.dumps({'credential_reference_id': reference}),
            ),
        )
        reconcile_coverage_batch(conn, stage_run_id=stage)
        assert conn.execute(
            'SELECT status FROM attack_coverage_items WHERE coverage_id=?',
            (task['coverage_id'],),
        ).fetchone()[0] == 'tested_negative'


def test_dashboard_uses_captured_http_path_even_after_legacy_endpoint_window(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=Planner())
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        endpoint = conn.execute("SELECT endpoint_id,origin_id FROM endpoints WHERE normalized_path='/search'").fetchone()
        conn.execute("UPDATE endpoints SET rowid=3000,normalized_path='/search/:id' WHERE endpoint_id=?", (endpoint['endpoint_id'],))
        conn.executemany("INSERT INTO endpoints(rowid,endpoint_id,origin_id,method,normalized_path) VALUES (?,?,?,'GET',?)", [(index+3,f'fill-{index}',endpoint['origin_id'],f'/fill/{index}') for index in range(2000)])
        conn.execute("UPDATE origins SET scheme='http',port=80,base_url='http://example.test'")
        conn.execute("UPDATE endpoint_observations SET observed_url='http://example.test/search/123?token=private-token' WHERE endpoint_id=?", (endpoint['endpoint_id'],))
        stage = start_stage_run(conn, scan_id='scan', stage='attack')
        claim_coverage_batch(conn, scan_id='scan', stage_run_id=stage, batch_size=1)
    response = DashboardProjector(tmp_path, database=path).attack_tasks('scan')
    assert response['tasks'][0]['observed_urls'] == [{'method':'GET','url':'http://example.test/search/123','hint':'Endpoint hypothesis'}]
    assert 'private-token' not in json.dumps(response)


def test_framework_specific_installed_skill_can_be_planned_without_static_catalog_cap(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def framework(response, context):
        assert context['available_vulnerability_skills']['nodejs'] == 'hunt-nodejs'
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row['hypotheses'] = [{**row['hypotheses'][0], 'vuln_class':'nodejs'}]
    plan_recon_attack(path, 'scan', agent=Planner(framework))
    ensure_coverage_manifest(path, 'scan')
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT skill_name FROM attack_coverage_items').fetchall() == [
            ('hunt-nodejs',), ('hunt-sqli',), ('hunt-xss',),
        ]


def test_candidate_only_request_provenance_preserves_method_at_shared_path(tmp_path):
    from aidast.attack.request_cli import _endpoint_provenance
    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        origin = conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,path,normalized_path) VALUES ('aaa-get',?,'GET','/shared','/shared')", (origin,))
        conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,path,normalized_path) VALUES ('zzz-post',?,'POST','/shared','/shared')", (origin,))
    assert _endpoint_provenance(path, scan_id='scan', method='POST', url='https://example.test/shared') == ('recon_candidate', 'zzz-post')


def test_request_provenance_accepts_only_unambiguous_terminal_slash_variant(tmp_path):
    from aidast.attack.request_cli import _endpoint_provenance
    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        search = conn.execute(
            "SELECT endpoint_id FROM endpoints WHERE normalized_path='/search'"
        ).fetchone()[0]
        conn.execute("""INSERT INTO endpoint_observations
            (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
             association_method,observed_at)
            VALUES ('search-response',?,'browser','http_response',
                    'https://example.test/search','exact','2026-10-04')""", (search,))

    assert _endpoint_provenance(
        path, scan_id='scan', method='GET', url='https://example.test/search/'
    )[0] == 'network_observed'

    with sqlite3.connect(path) as conn:
        origin = conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,path,normalized_path) VALUES ('slash-variant',?,'GET','/search/','/search/')", (origin,))
        conn.execute("""INSERT INTO endpoint_observations
            (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
             association_method,observed_at)
            VALUES ('slash-observation','slash-variant','browser','http_response',
                    'https://example.test/search/','exact','2026-10-04')""")
    assert _endpoint_provenance(
        path, scan_id='scan', method='GET', url='https://example.test/search/'
    ) == ('agent_proposed', None)


def test_planning_streams_every_endpoint_through_bounded_model_batches(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    with sqlite3.connect(path) as conn:
        origin = conn.execute('SELECT origin_id FROM origins').fetchone()[0]
        ObservationRecorder(conn, origin_id=origin, scan_id='scan').record('browser', [
            {'method':'GET','path':f'/opaque-{index}','url':f'https://example.test/opaque-{index}','source':'playwright_http'} for index in range(18)])
    agent = Planner()
    progress = []
    result = plan_recon_attack(path, 'scan', agent=agent, progress=lambda done,total: progress.append((done,total)))
    assert [len(batch['endpoints']) for batch in agent.contexts] == [16,4]
    assert result == {'total_endpoints':20,'by_status':{'insufficient_evidence':19,'planned':1}}
    assert progress[-1] == (20,20)


class RepairingPlanner(Planner):
    def __init__(self, *, repair=True):
        super().__init__()
        self.repair = repair

    def _run_structured(self, **kwargs):
        response = super()._run_structured(**kwargs)
        for endpoint in response.endpoints:
            if endpoint.hypotheses:
                if self.repair and len(self.contexts) > 1:
                    # Return only the repaired SQLi; the already validated XSS stays queued.
                    endpoint.hypotheses = [endpoint.hypotheses[0]]
                else:
                    endpoint.hypotheses[0].parameter_name = 'unobserved_filter'
        return response


def test_invalid_hypothesis_is_repaired_using_feedback_without_losing_valid_work(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    agent = RepairingPlanner()
    plan_recon_attack(path, 'scan', agent=agent)
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'sqli':1,'xss':1}
    assert len(agent.contexts) == 2
    feedback = agent.contexts[1]['validation_feedback']
    assert any(item['reason_code'] == 'unobserved_parameter' for item in feedback)
    assert feedback[0]['proposal']['parameter_name'] == 'unobserved_filter'
    assert agent.contexts[1]['endpoints'][0]['parameters'][0]['name'] == 'q'
    assert 'private-value' not in json.dumps(agent.contexts)
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT status FROM attack_planning_diagnostics').fetchall() == [('resolved',)]
        assert conn.execute('SELECT count(*) FROM attack_endpoint_reviews').fetchone()[0] == 2


def test_persistent_invalid_hypothesis_is_recorded_and_valid_work_continues(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    agent = RepairingPlanner(repair=False)
    plan_recon_attack(path, 'scan', agent=agent)
    assert len(agent.contexts) == 3
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'xss':1}
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM attack_planning_diagnostics WHERE status='unresolved'").fetchone()[0] == 1
        diagnostic = conn.execute("SELECT reason,proposal_json FROM attack_planning_diagnostics WHERE status='unresolved'").fetchone()
        assert 'unobserved_filter' in diagnostic[0]
        assert 'query' in diagnostic[0]
        assert json.loads(diagnostic[1])['parameter_name'] == 'unobserved_filter'
    snapshot = DashboardProjector(tmp_path,database=path).attack_tasks('scan')
    assert snapshot['coverage']['planning_unresolved'] == 1
    assert snapshot['coverage']['tested'] == 0
    assert any(gap['status'] == 'planning_rejected' for gap in snapshot['coverage']['gaps'])


def test_normal_attack_continues_after_repair_exhaustion(tmp_path):
    from aidast.orchestration.attack import AttackCoordinator
    from test_attack_coverage import UnsupportedCoverageAgent
    class Agent(RepairingPlanner):
        run_attack_orchestrator = UnsupportedCoverageAgent.run_attack_orchestrator
    path = pipeline(tmp_path)
    scope,policy=tmp_path/'Scope.md',tmp_path/'TargetPolicy.json'
    scope.write_text('# Approved fixture')
    policy.write_text('{"policies":[]}')
    agent=Agent(repair=False)
    agent.calls=[]
    result=AttackCoordinator(agent=agent,db_path=path,scope_path=scope,policy_path=policy).run('scan')
    assert result.status == 'COMPLETED'
    assert len(agent.calls) == 1
    assert [task['skill_name'] for task in agent.calls[0]['attack_tasks']] == ['hunt-xss']
    assert agent.calls[0]['attack_tasks'][0]['selection_reasons'] == [
        'exhaustive Recon DB coverage item', 'black-box Recon hypothesis: xss',
    ]


def test_all_invalid_proposals_become_unexecuted_and_do_not_claim_tests(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    def invalidate(response, context):
        for row in response['endpoints']:
            for hypothesis in row['hypotheses']:
                hypothesis['parameter_name'] = 'unobserved_filter'
    agent = Planner(invalidate)
    corrections = []
    plan_recon_attack(path, 'scan', agent=agent,
                      repair_progress=lambda *args: corrections.append(args))
    assert corrections == [(0, 2, 1, 2), (0, 2, 2, 2)]
    assert ensure_coverage_manifest(path, 'scan').total == 0
    before = path.read_bytes()
    snapshot = DashboardProjector(tmp_path, database=path).attack_tasks('scan')['coverage']
    assert path.read_bytes() == before
    assert snapshot['tested'] == 0
    assert snapshot['insufficient_evidence_endpoints'] == 2
    assert snapshot['planning_unresolved'] == 2


def test_withdrawal_of_invalid_proposal_preserves_valid_hypotheses(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def withdraw(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        if 'validation_feedback' in context:
            row.update(hypotheses=[], disposition='insufficient_evidence', reason='Unsupported SQLi proposal withdrawn.')
        else:
            row['hypotheses'][0]['parameter_name'] = 'unobserved_filter'
    agent = Planner(withdraw)
    plan_recon_attack(path, 'scan', agent=agent)
    assert len(agent.contexts) == 2
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'sqli': 1, 'xss': 1}
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT status FROM attack_planning_diagnostics').fetchall() == [('resolved',)]
        assert 'withdrawn' in conn.execute("SELECT reason FROM attack_endpoint_reviews WHERE status='planned'").fetchone()[0]


def test_new_evidence_supersedes_previous_unresolved_planning_diagnostics(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=RepairingPlanner(repair=False))
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE endpoint_annotations SET rationale='New captured search evidence' WHERE tag='search'")
    plan_recon_attack(path, 'scan', agent=Planner())
    snapshot = DashboardProjector(tmp_path, database=path).attack_tasks('scan')['coverage']
    assert snapshot['planning_unresolved'] == 0
    assert not any(gap['status'] == 'planning_rejected' for gap in snapshot['gaps'])
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT count(*) FROM attack_planning_diagnostics').fetchone()[0] == 3


def test_valid_hypotheses_survive_provider_failure_during_correction_and_resume(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    class FailingRepair(RepairingPlanner):
        def _run_structured(self, **kwargs):
            if self.contexts:
                raise RuntimeError('repair service unavailable')
            return super()._run_structured(**kwargs)
    with pytest.raises(RuntimeError, match='repair service unavailable'):
        plan_recon_attack(path, 'scan', agent=FailingRepair())
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM endpoint_annotations WHERE category='attack_hypothesis'").fetchone()[0] == 1
        # A partial result cannot cause the endpoint to skip planning on resume.
        assert conn.execute('SELECT count(*) FROM attack_endpoint_reviews').fetchone()[0] == 0
    def withdraw(response, context):
        for row in response['endpoints']:
            row.update(hypotheses=[], disposition='insufficient_evidence', reason='Unsupported SQLi withdrawn.')
    agent = Planner(withdraw)
    plan_recon_attack(path, 'scan', agent=agent)
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'sqli': 1, 'xss': 1}
    assert any(h['vuln_class'] == 'xss' for items in agent.contexts[0]['retained_hypotheses'].values() for h in items)


def test_correction_cannot_relabel_rejected_input_as_endpoint_wide_test(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def relabel(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        if 'validation_feedback' in context:
            row['hypotheses'][0].update(injection_location='endpoint', parameter_name='')
        else:
            row['hypotheses'][0]['parameter_name'] = 'unobserved_filter'
    plan_recon_attack(path, 'scan', agent=Planner(relabel))
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'xss': 1}
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT reason_code FROM attack_planning_diagnostics WHERE status='unresolved'").fetchall() == [('ungrounded_endpoint_fallback',)]


def test_resume_cannot_forget_rejected_input_and_relabel_it_as_endpoint_wide(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    class FailingRepair(RepairingPlanner):
        def _run_structured(self, **kwargs):
            if self.contexts:
                raise RuntimeError('repair service unavailable')
            return super()._run_structured(**kwargs)
    with pytest.raises(RuntimeError):
        plan_recon_attack(path, 'scan', agent=FailingRepair())
    def relabel(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        row['hypotheses'][0].update(injection_location='endpoint', parameter_name='')
    agent = Planner(relabel)
    plan_recon_attack(path, 'scan', agent=agent)
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'xss': 1}
    assert agent.contexts[0]['validation_feedback'][0]['reason_code'] == 'unobserved_parameter'


def test_correction_keeps_independently_valid_endpoint_hypothesis_with_invalid_sibling(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    path = pipeline(tmp_path)
    def independent_endpoint(response, context):
        row = next(row for row in response['endpoints'] if row['hypotheses'])
        original = row['hypotheses'][0]
        endpoint_test = {**original, 'injection_location': 'endpoint', 'parameter_name': ''}
        if 'validation_feedback' in context:
            row['hypotheses'] = [endpoint_test]
        else:
            row['hypotheses'] = [endpoint_test, {**original, 'parameter_name': 'unobserved_filter'}]
    agent = Planner(independent_endpoint)
    plan_recon_attack(path, 'scan', agent=agent)
    assert len(agent.contexts) == 2
    assert ensure_coverage_manifest(path, 'scan').by_vulnerability == {'sqli': 2, 'xss': 1}
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM attack_planning_diagnostics WHERE status='unresolved'").fetchone()[0] == 0
        assert sorted(conn.execute(
            'SELECT injection_location,parameter_name FROM attack_coverage_items'
        ).fetchall()) == [('endpoint', ''), ('query', 'q'), ('query', 'q')]


def test_source_evidence_review_supersedes_old_ordinary_planning_rejections(tmp_path):
    from aidast.attack.recon_hypotheses import plan_recon_attack
    from aidast.web.projection import DashboardProjector
    path = pipeline(tmp_path)
    plan_recon_attack(path, 'scan', agent=RepairingPlanner(repair=False))
    with sqlite3.connect(path) as conn:
        observation = conn.execute("SELECT o.observation_id FROM endpoint_observations o JOIN endpoints e ON e.endpoint_id=o.endpoint_id WHERE e.normalized_path='/search'").fetchone()[0]
        conn.execute("INSERT INTO endpoint_annotations(annotation_id,observation_id,annotation_run_id,category,tag,rationale,created_at) VALUES ('source-evidence',?,'tags','source_vulnerability','sqli','Fixture source evidence',CURRENT_TIMESTAMP)", (observation,))
    plan_recon_attack(path, 'scan', agent=Planner())
    snapshot = DashboardProjector(tmp_path, database=path).attack_tasks('scan')['coverage']
    assert snapshot['planning_unresolved'] == 0
    assert not any(gap['status'] == 'planning_rejected' for gap in snapshot['gaps'])
