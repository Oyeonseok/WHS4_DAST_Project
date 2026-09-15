"""Shared Pipeline.db v9 Validation storage constraints."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.recon import db
from aidast.pipeline.schema import migrate_pipeline_schema


class ValidationSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.conn = db.init_db(Path(self.temp.name) / "Pipeline.db")
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')", (origin,))
        self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES ('finding','scan','endpoint','idor','LOW','fixture')")
        self.conn.execute("INSERT INTO stage_runs(stage_run_id,scan_id,stage,status) VALUES ('validation_run','scan','validation','running')")
        self.conn.commit()

    def test_schema_version_and_tables(self):
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], 9)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(validation_cases)")}
        self.assertNotIn("known_similarity", columns)
        binding_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(chain_execution_bindings)")
        }
        self.assertTrue({
            "source_kind", "source_path_json", "target_kind", "target_path_json",
        }.issubset(binding_columns))
        expected = {"validation_cases", "validation_attempts", "validation_evidence",
                    "validation_development_actions", "validation_impact_hypotheses",
                    "validation_http_requests", "finding_reproduction_specs"}
        names = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual(expected, names)
        reproduction_columns = {
            row[1] for row in self.conn.execute(
                "PRAGMA table_info(finding_reproduction_specs)"
            )
        }
        self.assertTrue({
            "development_contract_json", "development_contract_sha256",
        }.issubset(reproduction_columns))

    def test_target_and_active_stage_uniqueness(self):
        self.conn.execute("""INSERT INTO validation_cases
            (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,processing_phase)
            VALUES ('case','scan','finding','finding','validation_run','queued')""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""INSERT INTO validation_cases
                (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,processing_phase)
                VALUES ('duplicate','scan','finding','finding','validation_run','queued')""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO stage_runs(stage_run_id,scan_id,stage,status) VALUES ('other','scan','validation','running')")

    def test_completed_evidence_is_append_only(self):
        self.conn.execute("""INSERT INTO validation_cases
            (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,processing_phase)
            VALUES ('case','scan','finding','finding','validation_run','queued')""")
        self.conn.execute("""INSERT INTO validation_attempts
            (attempt_id,case_id,stage_run_id,batch_no,attempt_kind,ordinal,signal_type,outcome,finished_at)
            VALUES ('attempt','case','validation_run',1,'target',1,'response_diff','observed','done')""")
        self.conn.execute("""INSERT INTO validation_evidence
            (evidence_id,case_id,stage_run_id,attempt_id,evidence_kind,details_json,content_sha256,content_length)
            VALUES ('evidence','case','validation_run','attempt','observation','{}',?,0)""", ('a' * 64,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE validation_evidence SET details_json='{}'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE validation_attempts SET outcome='error'")

    def test_reproduction_spec_is_immutable(self):
        self.conn.execute("""INSERT INTO finding_reproduction_specs
            (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
             injection_location,parameter_name,payload_template_json,
             required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,
             payload_structure_sha256,source_policy_sha256,spec_sha256)
             VALUES ('finding','hunt-idor','endpoint','GET','/','query','id','{}','[]',
                     '["attempt"]','["request"]',?,?,?)""",
            ("a" * 64, "b" * 64, "c" * 64))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE finding_reproduction_specs SET method='POST'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM finding_reproduction_specs")

    def test_real_v8_request_shape_migrates_without_backfilling_policy_digest(self):
        path = Path(self.temp.name) / "v8.db"
        with sqlite3.connect(path) as connection:
            connection.executescript(db.SCHEMA)
            connection.executescript("""
                CREATE TABLE stage_runs (
                    stage_run_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, stage TEXT NOT NULL,
                    status TEXT NOT NULL, manifest_path TEXT, error_message TEXT, started_at TEXT,
                    finished_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(stage_run_id,scan_id));
                CREATE TABLE attack_tasks (
                    task_id TEXT PRIMARY KEY, stage_run_id TEXT NOT NULL, scan_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL, endpoint_id TEXT, status TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}', error_message TEXT, started_at TEXT,
                    finished_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(task_id,scan_id));
                CREATE TABLE attack_http_requests (
                    request_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, stage_run_id TEXT NOT NULL,
                    task_id TEXT NOT NULL, policy_id TEXT NOT NULL, method TEXT NOT NULL,
                    url TEXT NOT NULL, request_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
                    response_status INTEGER, response_bytes INTEGER, error_message TEXT,
                    scheduled_at REAL NOT NULL, dispatched_at REAL, finished_at REAL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                INSERT INTO scans(scan_id,scope_type,scope_value) VALUES ('scan','test','local');
                INSERT INTO stage_runs(stage_run_id,scan_id,stage,status) VALUES ('run','scan','attack','completed');
                INSERT INTO attack_tasks(task_id,stage_run_id,scan_id,skill_name,status)
                    VALUES ('task','run','scan','fixture','completed');
                INSERT INTO attack_http_requests
                    (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                     request_fingerprint,status,scheduled_at)
                    VALUES ('request','scan','run','task','policy','GET','https://test',
                            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                            'completed',0);
                PRAGMA user_version=8;
            """)
            migrate_pipeline_schema(connection)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 9)
            self.assertEqual(connection.execute(
                "SELECT request_id,policy_sha256,result_json FROM attack_http_requests"
            ).fetchone(), ("request", None, "{}"))
            before = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
            migrate_pipeline_schema(connection)
            self.assertEqual(connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], before)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_v9_known_similarity_column_is_removed_without_losing_cases(self):
        self.conn.execute("ALTER TABLE validation_cases ADD COLUMN known_similarity REAL")
        self.conn.execute("""INSERT INTO validation_cases
            (case_id,scan_id,target_kind,finding_id,latest_stage_run_id,processing_phase,
             known_similarity) VALUES ('case','scan','finding','finding','validation_run','queued',0.9)""")
        self.conn.execute("""INSERT INTO validation_attempts
            (attempt_id,case_id,stage_run_id,batch_no,attempt_kind,ordinal,signal_type,outcome)
            VALUES ('attempt','case','validation_run',1,'target',1,'response_diff','not_observed')""")
        self.conn.execute("PRAGMA user_version=9")
        self.conn.commit()

        migrate_pipeline_schema(self.conn)

        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(validation_cases)")}
        self.assertNotIn("known_similarity", columns)
        self.assertEqual(self.conn.execute(
            "SELECT case_id,processing_phase FROM validation_cases"
        ).fetchall(), [("case", "queued")])
        self.assertEqual(self.conn.execute(
            "SELECT attempt_id,case_id FROM validation_attempts"
        ).fetchall(), [("attempt", "case")])
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], 9)
        self.assertEqual(self.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
