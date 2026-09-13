from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from aidast.attack.db_cli import transition_task
from aidast.attack.request_cli import RequestGuardError, guarded_request
from aidast.pipeline.lifecycle import create_task, start_stage_run
from aidast.recon import db


class FakeResponse:
    status = 200
    code = 200

    def __init__(self, url: str, *, body: bytes = b'{"ok":true}') -> None:
        self._url = url
        self._body = body
        self.headers = {"Content-Type": "application/json", "Set-Cookie": "secret"}

    def read(self, maximum: int) -> bytes:
        return self._body[:maximum]

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        pass


class FakeOpener:
    def __init__(self, bodies: list[bytes] | None = None) -> None:
        self.calls = []
        self.bodies = list(bodies or [])

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        body = self.bodies.pop(0) if self.bodies else b'{"ok":true}'
        return FakeResponse(request.full_url, body=body)


def fixture(root: Path, *, max_requests: int = 1) -> tuple[Path, Path, Path, str, str]:
    database = root / "Pipeline.db"
    conn = db.init_db(database)
    db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    db.upsert_endpoint(
        conn, origin_id=origin, method="GET", path="/api/profile",
        normalized_path="/api/profile", source_tool="fixture",
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
    )
    conn.commit()
    stage = start_stage_run(conn, scan_id="scan", stage="attack")
    task = create_task(conn, stage_run_id=stage, skill_name="hunt-cors")
    conn.close()
    transition_task(database, "scan", stage, task, "running")
    policy = root / "TargetPolicy.json"
    policy.write_text(json.dumps({
        "schema_version": "1.0", "scope_id": "scope", "policies": [{
            "schema_version": "1.0", "scope_id": "scope", "policy_id": "policy",
            "asset_type": "URL", "asset": "https://example.test/api",
            "allowed_schemes": ["https"], "allowed_hosts": ["example.test"],
            "include_subdomains": False, "allowed_ports": [443],
            "allowed_path_prefixes": ["/api"], "excluded_path_prefixes": ["/api/admin"],
            "allowed_methods": ["GET"],
            "limits": {"requests_per_second": 50, "concurrency": 1,
                       "timeout_seconds": 5, "max_depth": 1,
                       "max_requests": max_requests},
            "tools": {}, "policy_notes": [], "restriction_evidence": [],
        }],
    }), encoding="utf-8")
    payload = root / "request.json"
    return database, policy, payload, stage, task


class AttackRequestGuardTests(unittest.TestCase):
    def test_response_capture_is_cryptographically_bound_to_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root, max_requests=3)
            opener = FakeOpener([
                b'{"account_id":"victim-42"}',
                b'{"owner":"victim","private":true}',
            ])
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://example.test/api/profile",
                    "captures": [{"name": "account_id", "source": "json_body",
                                  "path": ["account_id"]}],
                }), encoding="utf-8")
                first = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                payload.write_text(json.dumps({
                    "method": "GET",
                    "url": "https://example.test/api/account/victim-42",
                    "bindings": [{
                        "name": "object_id", "source_request_id": first["request_id"],
                        "capture_name": "account_id", "value": first["captures"]["account_id"],
                        "target_kind": "path_parameter", "target_path": ["account_id"],
                    }],
                    "assertions": [{
                        "name": "private_record_disclosed", "kind": "json_equals",
                        "path": ["private"], "expected": True, "terminal": True,
                    }],
                }), encoding="utf-8")
                second = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertTrue(second["assertions"][0]["passed"])
            with closing(sqlite3.connect(database)) as conn:
                metadata = conn.execute(
                    "SELECT result_json FROM attack_http_requests WHERE request_id=?",
                    (second["request_id"],),
                ).fetchone()[0]
            self.assertNotIn("victim-42", metadata)
            self.assertIn("consumed_binding_hashes", metadata)
            parsed = json.loads(metadata)
            self.assertEqual(parsed["consumed_binding_contracts"]["object_id"], {
                "target_kind": "path_parameter", "target_path": ["account_id"],
            })

            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/account/forged",
                "bindings": [{
                    "name": "object_id", "source_request_id": first["request_id"],
                    "capture_name": "account_id", "value": "forged",
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "does not match"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(len(opener.calls), 2)

    def test_allowed_request_is_sent_once_and_durably_charged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile?token=secret",
                "headers": {"Cookie": "session=secret"},
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(result["response_headers"]["Set-Cookie"], "[REDACTED]")
            self.assertEqual(len(opener.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                stored = conn.execute(
                    "SELECT status,url,response_status FROM attack_http_requests"
                ).fetchone()
            self.assertEqual(stored[0], "completed")
            self.assertNotIn("secret", stored[1])
            self.assertEqual(stored[2], 200)

    def test_scope_and_budget_are_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://outside.test/api/profile",
                }), encoding="utf-8")
                with self.assertRaisesRegex(RequestGuardError, "exactly one TargetPolicy"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://example.test/api/profile",
                }), encoding="utf-8")
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                with self.assertRaisesRegex(RequestGuardError, "budget exhausted"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(len(opener.calls), 1)

    def test_request_requires_running_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            transition_task(database, "scan", stage, task, "completed")
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "running Attack task"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )


if __name__ == "__main__":
    unittest.main()
