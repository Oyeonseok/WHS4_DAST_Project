import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder, AnnotationBatch, safe_url
from aidast.recon.surface import export_surface
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture


class FakeAgent:
    def __init__(self, invalid=False):
        self.invalid = invalid

    def _run_structured(self, **kwargs):
        self.prompt = kwargs['prompt']
        payload = json.loads(self.prompt.split('\n', 1)[1])
        return AnnotationBatch(annotations=[{
            'observation_id': 'invented' if self.invalid else o['observation_id'],
            'category': 'function', 'tag': 'unknown',
            'rationale': '기능을 판단할 근거가 부족함', 'confidence': None,
        } for o in payload['observations']])


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'recon.db'
        self.conn = db.init_db(self.path)
        db.insert_scan(self.conn, scan_id='scan', scope_type='test', scope_value='example')
        asset = db.insert_asset(self.conn, scan_id='scan', identifier='example.com', asset_type='DOMAIN')
        self.origin = db.upsert_origin(self.conn, asset_id=asset, scheme='https', host='example.com', port=443, base_url='https://example.com')

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def items(self):
        return [{'method': 'POST', 'path': '/api/session', 'source': 'playwright_login',
                 'context': {'context_key': key, 'page_url': page,
                             'action_type': 'click', 'action_target': 'Login'}}
                for key, page in [('one', '/login'), ('two', '/reauth')]]

    def test_preserves_multiple_contexts_and_exports_evidence(self):
        agent = FakeAgent()
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan', agent=agent)
        recorder.record('login', self.items())
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoints').fetchone()[0], 1)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM discovery_contexts').fetchone()[0], 2)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_annotations').fetchone()[0], 2)
        target = Path(self.temp.name) / 'surface.json'
        export_surface(self.conn, scan_id='scan', output_path=target)
        output = json.loads(target.read_text())
        endpoint = output['origins'][0]['endpoints'][0]
        self.assertEqual(endpoint['path'], '/api/session')
        self.assertEqual(len(endpoint['observations']), 2)
        self.assertEqual(len(endpoint['annotations']), 2)
        self.assertEqual(output['annotation_runs'][0]['status'], 'completed')

    def test_unverified_api_candidate_is_recorded_outside_surface_endpoints(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan')
        recorder.record('api_secondary', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'zap_openapi', 'discovery_kind': 'api_spec_candidate',
            'verification_status': 'candidate',
        }])

        surface = json.loads(export_surface(
            self.conn, scan_id='scan', output_path=Path(self.temp.name) / 'surface.json',
        ).read_text())
        origin = surface['origins'][0]
        self.assertEqual(origin['endpoints'], [])
        self.assertEqual([item['path'] for item in origin['candidate_endpoints']], ['/b2b'])
        self.assertEqual(origin['candidate_endpoints'][0]['observations'][0]['source_tool'], 'zap_openapi')
        self.assertEqual(self.conn.execute(
            "SELECT is_excluded, exclude_reason FROM endpoints WHERE normalized_path='/b2b'"
        ).fetchone(), (1, 'unverified_candidate'))

    def test_static_asset_report_is_not_exported_as_api_candidate(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record(
            'api_secondary', [{
                'method': 'GET', 'path': '/main.js', 'url': 'https://example.com/main.js',
                'source': 'zap_openapi', 'verification_status': 'candidate',
            }],
        )

        surface = json.loads(export_surface(
            self.conn, scan_id='scan', output_path=Path(self.temp.name) / 'surface.json',
        ).read_text())
        self.assertEqual(surface['origins'][0]['candidate_endpoints'], [])

    def test_verified_observation_promotes_existing_api_candidate(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan')
        candidate = {
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'zap_openapi', 'verification_status': 'candidate',
        }
        recorder.record('api_secondary', [candidate])
        recorder.record('browser', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'playwright_http', 'evidence': {'response_status': 200},
        }])

        surface = json.loads(export_surface(
            self.conn, scan_id='scan', output_path=Path(self.temp.name) / 'surface.json',
        ).read_text())
        origin = surface['origins'][0]
        self.assertEqual([item['path'] for item in origin['endpoints']], ['/b2b'])
        self.assertEqual(origin['candidate_endpoints'], [])
        self.assertEqual(len(origin['endpoints'][0]['observations']), 2)
        self.assertEqual(origin['endpoints'][0]['verification_status'], 'verified')

    def test_unproven_observation_does_not_promote_api_candidate(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan')
        recorder.record('api_secondary', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'zap_openapi', 'verification_status': 'candidate',
        }])
        recorder.record('crawler', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'katana_standard',
        }])

        surface = json.loads(export_surface(
            self.conn, scan_id='scan', output_path=Path(self.temp.name) / 'surface.json',
        ).read_text())
        origin = surface['origins'][0]
        self.assertEqual(origin['endpoints'], [])
        self.assertEqual(origin['candidate_endpoints'][0]['verification_status'], 'candidate')
        self.assertEqual(len(origin['candidate_endpoints'][0]['observations']), 2)

    def test_candidate_observation_does_not_demote_verified_endpoint(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan')
        recorder.record('browser', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'playwright_http', 'evidence': {'response_status': 200},
        }])
        recorder.record('api_secondary', [{
            'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
            'source': 'zap_openapi', 'verification_status': 'candidate',
        }])

        self.assertEqual(self.conn.execute(
            "SELECT is_excluded, exclude_reason FROM endpoints WHERE normalized_path='/b2b'"
        ).fetchone(), (0, None))

    def test_failed_http_probe_does_not_promote_api_candidate(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record(
            'api_secondary', [{
                'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
                'source': 'zap_openapi', 'verification_status': 'candidate',
            }],
        )
        capture = Path(self.temp.name) / 'capture.jsonl'
        capture.write_text(json.dumps({
            'method': 'GET', 'url': 'https://example.com/b2b', 'response_status': 404,
        }) + '\n')
        self.assertEqual(ingest_mitm_capture(self.conn, capture, origin_id=self.origin), (1, 0))

        self.assertEqual(self.conn.execute(
            "SELECT is_excluded, exclude_reason FROM endpoints WHERE normalized_path='/b2b'"
        ).fetchone(), (1, 'unverified_candidate'))

    def test_successful_proxy_capture_alone_does_not_promote_spec_candidate(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record(
            'api_secondary', [{
                'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
                'source': 'zap_openapi', 'verification_status': 'candidate',
            }],
        )
        capture = Path(self.temp.name) / 'capture.jsonl'
        capture.write_text(json.dumps({
            'method': 'GET', 'url': 'https://example.com/b2b', 'response_status': 200,
        }) + '\n')
        self.assertEqual(ingest_mitm_capture(self.conn, capture, origin_id=self.origin), (1, 0))

        self.assertEqual(self.conn.execute(
            "SELECT is_excluded, exclude_reason FROM endpoints WHERE normalized_path='/b2b'"
        ).fetchone(), (1, 'unverified_candidate'))

    def test_rejected_candidate_get_capture_does_not_promote_on_http_200(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record(
            'api_secondary', [{
                'method': 'GET', 'path': '/b2b', 'url': 'https://example.com/b2b',
                'source': 'zap_openapi', 'verification_status': 'candidate',
                'evidence': {'response_status': 200, 'verification_reason': 'non_positive_json'},
            }],
        )
        capture = Path(self.temp.name) / 'capture.jsonl'
        capture.write_text(json.dumps({
            'method': 'GET', 'url': 'https://example.com/b2b',
            'response_status': 200, 'candidate_probe': True,
        }) + '\n')
        self.assertEqual(ingest_mitm_capture(self.conn, capture, origin_id=self.origin), (1, 0))

        surface = json.loads(export_surface(
            self.conn, scan_id='scan', output_path=Path(self.temp.name) / 'surface.json',
        ).read_text())
        self.assertEqual(surface['origins'][0]['endpoints'], [])
        candidate = surface['origins'][0]['candidate_endpoints'][0]
        self.assertEqual(candidate['observations'][0]['evidence']['verification_reason'],
                         'non_positive_json')

    def test_invalid_llm_output_keeps_observations_without_partial_tags(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan', agent=FakeAgent(True))
        recorder.record('login', self.items())
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_observations').fetchone()[0], 2)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_annotations').fetchone()[0], 0)
        self.assertEqual(self.conn.execute('SELECT status FROM annotation_runs').fetchone()[0], 'failed')

    def test_tagging_records_bounded_batch_progress(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan', agent=FakeAgent()).record(
            'login', self.items(),
        )
        events = [
            json.loads(row[0])
            for row in self.conn.execute(
                "SELECT details_json FROM audit_events WHERE event_type='recon.activity' ORDER BY rowid"
            )
        ]
        self.assertEqual(events, [
            {'phase': 'observation_tagging', 'state': 'started', 'index': 1, 'total': 1, 'count': 2},
            {'phase': 'observation_tagging', 'state': 'finished', 'index': 1, 'total': 1,
             'count': 2, 'processed_count': 2, 'failed_count': 0},
        ])

    def test_proxy_links_endpoint_and_scan_without_guessing_page(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record('login', self.items())
        capture = Path(self.temp.name) / 'capture.jsonl'
        capture.write_text(json.dumps({'method': 'POST', 'url': 'https://example.com/api/session', 'response_status': 200}) + '\n')
        self.assertEqual(ingest_mitm_capture(self.conn, capture, origin_id=self.origin), (1, 0))
        row = self.conn.execute('SELECT endpoint_id, origin_id FROM http_transactions').fetchone()
        self.assertIsNotNone(row[0])
        self.assertEqual(row[1], self.origin)
        self.assertEqual(self.conn.execute("SELECT context_id FROM endpoint_observations WHERE source_tool='mitmproxy'").fetchone(), (None,))

    def test_url_sanitization(self):
        self.assertEqual(safe_url('https://user:password@example.com/login?token=secret#secret'), 'https://example.com/login')

    def test_legacy_migration_is_idempotent_and_preserves_rows(self):
        legacy = Path(self.temp.name) / 'legacy.db'
        conn = sqlite3.connect(legacy)
        conn.executescript(db.SCHEMA)
        conn.execute("INSERT INTO http_transactions(http_transaction_id,method,url) VALUES ('old','GET','https://example.com')")
        conn.commit()
        conn.close()
        for _ in range(2):
            conn = db.init_db(legacy)
            self.assertEqual(conn.execute('SELECT http_transaction_id, origin_id FROM http_transactions').fetchall(), [('old', None)])
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0], db.RECON_SCHEMA_VERSION)
            self.assertEqual(conn.execute('PRAGMA foreign_key_check').fetchall(), [])
            conn.close()


if __name__ == '__main__':
    unittest.main()
