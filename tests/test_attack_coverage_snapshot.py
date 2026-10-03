"""Read-only coverage distinguishes endpoint review, execution and Validation."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aidast.attack.coverage_snapshot import attack_work_unfinished, read_coverage_snapshot
from aidast.pipeline.lifecycle import start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


@pytest.fixture
def pipeline(tmp_path: Path):
    path = tmp_path / 'Pipeline.db'
    conn = db.init_db(path)
    migrate_live_pipeline_schema(conn)
    conn.row_factory = sqlite3.Row
    for scan in ('scan', 'other'):
        db.insert_scan(conn, scan_id=scan, scope_type='test', scope_value='fixture')
        asset = db.insert_asset(conn, scan_id=scan, identifier=scan, asset_type='DOMAIN')
        origin = db.upsert_origin(conn, asset_id=asset, scheme='https', host=scan + '.test',
                                 port=443, base_url='https://' + scan + '.test')
        conn.execute('''INSERT INTO annotation_runs
            (annotation_run_id,scan_id,model,prompt_version,taxonomy_version,status)
            VALUES (?,?,'fixture','1','1','completed')''', (scan, scan))
        endpoints = ('first', 'second', 'excluded') if scan == 'scan' else ('foreign',)
        for endpoint in endpoints:
            conn.execute('''INSERT INTO endpoints(endpoint_id,origin_id,normalized_path,is_excluded)
                VALUES (?,?,?,?)''', (endpoint, origin, '/' + endpoint, endpoint == 'excluded'))
            conn.execute('''INSERT INTO endpoint_observations
                (observation_id,endpoint_id,source_tool,discovery_kind,association_method,observed_at)
                VALUES (?,?,'fixture','tool_report','direct',CURRENT_TIMESTAMP)''', (endpoint, endpoint))
            conn.execute('''INSERT INTO endpoint_annotations
                (annotation_id,observation_id,annotation_run_id,category,tag,rationale,created_at)
                VALUES (?,?,?,'function','unknown','fixture',CURRENT_TIMESTAMP)''', (endpoint, endpoint, scan))
    conn.commit()
    yield path, conn
    conn.close()


def review(conn: sqlite3.Connection, endpoint: str) -> None:
    conn.execute('''INSERT INTO attack_endpoint_reviews
        (scan_id,endpoint_id,evidence_sha256,status,reason,hypothesis_count)
        VALUES ('scan',?,?,'not_applicable','fixture review',0)''', (endpoint, 'a' * 64))


def coverage(conn: sqlite3.Connection, index: int, endpoint: str, status: str,
             *, vuln_class: str = 'sqli', finding: str | None = None) -> None:
    annotation = 'hypothesis-' + str(index)
    conn.execute('''INSERT INTO endpoint_annotations
        (annotation_id,observation_id,annotation_run_id,category,tag,rationale,created_at)
        VALUES (?,?,'scan','attack_hypothesis',?,'fixture',CURRENT_TIMESTAMP)''',
        (annotation, endpoint, vuln_class + '-' + str(index)))
    conn.execute('''INSERT INTO attack_coverage_items
        (coverage_id,coverage_key,scan_id,endpoint_id,annotation_id,vuln_class,
         skill_name,status,finding_id)
        VALUES (?,?,'scan',?,?,?, ?,?,?)''',
        (str(index), f'{index:064x}', endpoint, annotation, vuln_class, 'hunt-' + vuln_class, status, finding))


def test_stale_and_foreign_reviews_cannot_cover_an_unreviewed_endpoint(pipeline) -> None:
    path, conn = pipeline
    for endpoint in ('first', 'excluded', 'foreign'):
        review(conn, endpoint)
    conn.commit()
    before = path.read_bytes()

    snapshot = read_coverage_snapshot(conn, 'scan')

    assert snapshot['endpoints_total'] == 2
    assert snapshot['endpoints_reviewed'] == 1
    assert snapshot['endpoints_unreviewed'] == 1
    assert snapshot['not_applicable_endpoints'] == 1
    assert [gap['url'] for gap in snapshot['gaps']] == ['https://scan.test/first']
    assert attack_work_unfinished(conn, 'scan')
    assert path.read_bytes() == before
    review(conn, 'second')
    assert not attack_work_unfinished(conn, 'scan')


def test_excluded_reviews_alone_still_expose_missing_included_reviews(pipeline) -> None:
    _, conn = pipeline
    review(conn, 'excluded')

    snapshot = read_coverage_snapshot(conn, 'scan', include_gaps=False)

    assert snapshot['endpoints_reviewed'] == 0
    assert snapshot['endpoints_unreviewed'] == 2
    assert attack_work_unfinished(conn, 'scan')


def test_duplicate_hypotheses_and_attempts_do_not_multiply_endpoint_coverage(pipeline) -> None:
    _, conn = pipeline
    coverage(conn, 1, 'first', 'tested_negative')
    coverage(conn, 2, 'first', 'tested_negative', vuln_class='xss')
    coverage(conn, 3, 'second', 'unsupported')
    coverage(conn, 4, 'second', 'blocked_auth', vuln_class='idor')
    coverage(conn, 5, 'excluded', 'tested_negative')
    for index, endpoint in enumerate(('first', 'first', 'second', 'excluded', 'foreign')):
        conn.execute('''INSERT INTO attack_attempts
            (attempt_id,scan_id,endpoint_id,skill_name,request_fingerprint,outcome)
            VALUES (?,?,?,'hunt-sqli',?,'inconclusive')''',
            (str(index), 'other' if endpoint == 'foreign' else 'scan', endpoint, f'{index:064x}'))

    snapshot = read_coverage_snapshot(conn, 'scan', include_gaps=False)

    assert snapshot['tested'] == 3  # Historical hypotheses retain their dispositions.
    assert snapshot['endpoints_attempted'] == 2
    assert snapshot['endpoints_tested'] == 1
    assert snapshot['by_vulnerability'] == {
        'idor': {'blocked_auth': 1},
        'sqli': {'tested_negative': 2, 'unsupported': 1},
        'xss': {'tested_negative': 1},
    }
    assert snapshot['candidate_findings'] == 0
    assert snapshot['independently_confirmed_findings'] == 0


def test_confirmation_comes_from_distinct_independent_validation_cases(pipeline) -> None:
    path, conn = pipeline
    stage = start_stage_run(conn, scan_id='scan', stage='validation')
    for finding in ('confirmed', 'underpowered', 'pending', 'queued', 'unbound'):
        conn.execute('''INSERT INTO findings
            (finding_id,scan_id,endpoint_id,vuln_type,severity,title)
            VALUES (?,'scan','first','sqli','LOW','fixture')''', (finding,))
    for index, finding in enumerate(('confirmed', 'confirmed', 'underpowered', 'pending', 'queued')):
        coverage(conn, index, 'first', 'candidate', finding=finding)
    for finding, status in (('confirmed', 'CONFIRMED'), ('underpowered', 'UNDERPOWERED'),
                            ('queued', None), ('unbound', 'CONFIRMED')):
        conn.execute('''INSERT INTO validation_cases
            (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,processing_phase,
             current_status,decision_json,decision_sha256)
            VALUES (?,'scan','finding',?,?,'queued',?,?,?)''',
            (finding, finding, stage, status, '{}' if status else None, 'b' * 64 if status else None))
    conn.commit()
    before = path.read_bytes()

    snapshot = read_coverage_snapshot(conn, 'scan')

    assert snapshot['by_status'] == {'candidate': 5}
    assert snapshot['candidate_findings'] == 4
    assert snapshot['independently_confirmed_findings'] == 1
    assert snapshot['validation_by_status'] == {'CONFIRMED': 1, 'PENDING': 2, 'UNDERPOWERED': 1}
    assert snapshot['endpoints_tested'] == 1
    assert path.read_bytes() == before


def test_source_coverage_without_endpoint_reviews_keeps_legacy_resume_behavior(pipeline) -> None:
    _, conn = pipeline
    assert read_coverage_snapshot(conn, 'scan') is None
    coverage(conn, 1, 'first', 'tested_negative')
    assert not attack_work_unfinished(conn, 'scan')
