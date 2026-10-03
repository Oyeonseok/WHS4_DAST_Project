from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from aidast.attack.db_cli import transition_task
from aidast.attack.request_cli import RequestGuardError, guarded_request, _credential_headers
from aidast.core.request_governor import RequestGovernor
from aidast.pipeline.lifecycle import create_task, register_credential_reference, start_stage_run
from aidast.pipeline.browser_credentials import register_browser_session_credentials
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
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


def fixture(
    root: Path,
    *,
    max_requests: int = 1,
    attack_methods: list[str] | None = None,
    observed_post: bool = False,
    observed_post_path: str = "/api/profile",
    observed_post_source: str = "playwright_login",
    hackerone_username: str | None = None,
) -> tuple[Path, Path, Path, str, str]:
    database = root / "Pipeline.db"
    conn = db.init_db(database)
    migrate_live_pipeline_schema(conn)
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
    if observed_post:
        post_endpoint = db.upsert_endpoint(
            conn, origin_id=origin, method="POST", path=observed_post_path,
            normalized_path=observed_post_path, source_tool=observed_post_source,
        )
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,
                association_method,observed_at)
               VALUES (?,?,?,?,?,?)""",
            (
                db.new_id("observation"), post_endpoint, observed_post_source,
                "passive_login_observation", "session_bundle", db.now(),
            ),
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
            "attack_allowed_methods": attack_methods or ["GET"],
            "attack_authorization_mode": (
                "active_non_destructive"
                if any(method not in {"GET", "HEAD", "OPTIONS"}
                       for method in (attack_methods or []))
                else "read_only"
            ),
            "attack_authorization_evidence": (
                "Non-destructive active security testing is allowed."
                if any(method not in {"GET", "HEAD", "OPTIONS"}
                       for method in (attack_methods or []))
                else None
            ),
            "hackerone_username": hackerone_username,
            "limits": {"requests_per_second": 50, "concurrency": 1,
                       "timeout_seconds": 5, "max_depth": 1,
                       "max_requests": max_requests},
            "tools": {}, "policy_notes": [], "restriction_evidence": [],
        }],
    }), encoding="utf-8")
    payload = root / "request.json"
    return database, policy, payload, stage, task


class AttackRequestGuardTests(unittest.TestCase):
    def test_slow_shared_queue_preserves_network_timeout_and_dispatch_guards(self) -> None:
        # Four already authorized requests hold shared capacity for eight
        # fake seconds at 0.5 RPS, beyond this helper's five-second network
        # timeout. No real HTTP request or wall-clock wait is used.
        for scan_seconds, stopped in ((30, False), (7, False), (30, True)):
            with self.subTest(scan_seconds=scan_seconds, stopped=stopped):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    database, policy_path, payload, stage, task = fixture(root)
                    document = json.loads(policy_path.read_text())
                    policy = document["policies"][0]
                    policy["limits"]["requests_per_second"] = 0.5
                    binding = {
                        "ledger_path": str(root / "governor.db"), "scan_id": "scan",
                        "program_id": "program", "scan_max_requests": 5,
                        "scan_max_seconds": scan_seconds, "requests_per_second": 0.5,
                        "concurrency": 1, "request_limits": [],
                    }
                    policy["request_governor"] = binding
                    policy_path.write_text(json.dumps(document))
                    payload.write_text(json.dumps({
                        "method": "GET", "url": "https://example.test/api/profile",
                    }))
                    now = [1000.0]
                    pending = [3]
                    next_release = [1002.0]
                    current = []

                    def advance(delay):
                        now[0] += delay
                        if now[0] + 1e-8 < next_release[0]:
                            return
                        now[0] = max(now[0], next_release[0])
                        current[0].complete()
                        if stopped and pending[0] == 3:
                            transition_task(database, "scan", stage, task, "completed")
                        if pending[0]:
                            pending[0] -= 1
                            next_release[0] = now[0] + 2
                            current[0] = governor.reserve("https://example.test")
                            current[0].wait()
                        else:
                            next_release[0] = float("inf")

                    governor = RequestGovernor(binding, clock=lambda: now[0], sleeper=advance)
                    current.append(governor.reserve("https://example.test"))
                    current[0].wait()
                    opener = FakeOpener()
                    with (
                        patch("aidast.attack.request_cli.RequestGovernor", return_value=governor),
                        patch("aidast.attack.request_cli.build_opener", return_value=opener),
                    ):
                        if scan_seconds == 7 or stopped:
                            with self.assertRaisesRegex(
                                RequestGuardError, "deadline" if scan_seconds == 7 else "stopped",
                            ):
                                guarded_request(
                                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                                    policy_path=policy_path, payload_path=payload,
                                )
                            self.assertEqual(opener.calls, [])
                        else:
                            result = guarded_request(
                                database, scan_id="scan", stage_run_id=stage, task_id=task,
                                policy_path=policy_path, payload_path=payload,
                            )
                            self.assertEqual(result["status"], 200)
                            self.assertGreaterEqual(now[0], 1008.0)
                            self.assertEqual(len(opener.calls), 1)
                            self.assertEqual(opener.calls[0][1], 5)
                    with sqlite3.connect(database) as conn:
                        row = conn.execute(
                            "SELECT status,dispatched_at FROM attack_http_requests"
                        ).fetchone()
                    self.assertEqual(row[0], "failed" if scan_seconds == 7 or stopped else "completed")
                    if scan_seconds == 7 or stopped:
                        self.assertIsNone(row[1])
                    with sqlite3.connect(root / "governor.db") as conn:
                        rows = conn.execute(
                            "SELECT charged FROM governor_requests ORDER BY charged"
                        ).fetchall()
                    self.assertLessEqual(len(rows), 5)
                    self.assertTrue(all(
                        after[0] - before[0] >= 2 - 1e-8
                        for before, after in zip(rows, rows[1:])
                    ))

    def test_registered_recon_browser_session_reaches_attack_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _policy, _payload, _stage, task = fixture(root)
            snapshot = root / "browser.json"
            snapshot.write_text(json.dumps({
                "cookies": [], "origins": [{"origin": "https://example.test",
                    "localStorage": [{"name": "token", "value": "header.payload.signature"}]}
                ],
            }), encoding="utf-8")
            with sqlite3.connect(database) as conn:
                refs = register_browser_session_credentials(
                    conn, scan_id="scan", result_root=root / "result",
                    sessions=[("https://example.test/", snapshot, True)],
                )
                reference = refs[0]["credential_reference_id"]
                conn.execute("UPDATE attack_tasks SET payload_json=? WHERE task_id=?", (
                    json.dumps({"credential_references": refs}), task,
                ))
            with patch("aidast.validation.execution.credentials.RESULT_ROOT", root / "result"):
                selected, headers = _credential_headers(
                    database, scan_id="scan", task_id=task,
                    url="https://example.test/api/profile",
                    item={"credential_reference_id": reference},
                )
            self.assertEqual(selected, reference)
            self.assertEqual(headers, {"Authorization": "Bearer header.payload.signature"})

    def test_session_credential_is_rejected_for_another_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _policy, _payload, _stage, task = fixture(Path(temporary))
            with sqlite3.connect(database) as conn:
                origin_id = conn.execute("SELECT origin_id FROM origins").fetchone()[0]
                conn.execute("INSERT INTO sessions(session_id,origin_id,auth_state) VALUES ('session_auth',?,'authenticated')", (origin_id,))
                reference = register_credential_reference(
                    conn, scan_id="scan", session_id="session_auth", label="browser",
                    reference_uri="env://AIDAST_TEST_AUTH_HEADERS", identity_role="authenticated",
                )
                conn.execute("UPDATE attack_tasks SET payload_json=? WHERE task_id=?", (
                    json.dumps({"credential_references": [{"credential_reference_id": reference}]}), task,
                ))
            with self.assertRaisesRegex(RequestGuardError, "origin"):
                _credential_headers(
                    database, scan_id="scan", task_id=task,
                    url="https://another.example.test/api/profile",
                    item={"credential_reference_id": reference},
                )

    def test_opaque_task_bound_credential_is_resolved_without_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            with closing(sqlite3.connect(database)) as conn:
                reference = register_credential_reference(
                    conn, scan_id="scan", label="user-a",
                    reference_uri="env://AIDAST_TEST_USER_A", identity_role="user-a",
                )
                conn.execute(
                    "UPDATE attack_tasks SET payload_json=? WHERE task_id=?",
                    (json.dumps({
                        "required_identity_role": "authenticated",
                        "credential_references": [{
                            "credential_reference_id": reference,
                            "label": "user-a", "identity_role": "user-a",
                        }],
                    }), task),
                )
                conn.commit()
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile",
                "credential_reference_id": reference,
            }), encoding="utf-8")
            opener = FakeOpener()
            secret = "Bearer secret-must-not-be-persisted"
            with patch.dict(os.environ, {
                "AIDAST_TEST_USER_A": json.dumps({"Authorization": secret}),
            }), patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            request, _ = opener.calls[0]
            self.assertEqual(request.get_header("Authorization"), secret)
            self.assertNotIn(secret, json.dumps(result))
            with closing(sqlite3.connect(database)) as conn:
                persisted = " ".join(str(value) for value in conn.execute(
                    "SELECT result_json,error_message FROM attack_http_requests"
                ).fetchone())
            self.assertNotIn(secret, persisted)
            self.assertIn(reference, persisted)

    def test_credential_must_be_listed_on_exact_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            with closing(sqlite3.connect(database)) as conn:
                reference = register_credential_reference(
                    conn, scan_id="scan", label="user-a",
                    reference_uri="env://AIDAST_TEST_USER_A", identity_role="user-a",
                )
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile",
                "credential_reference_id": reference,
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "not authorized for this task"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

    def test_hackerone_identity_header_overrides_untrusted_payload_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, hackerone_username="trusted_hacker",
            )
            payload.write_text(json.dumps({
                "method": "GET",
                "url": "https://example.test/api/profile",
                "headers": {"x-hackerone": "attacker-controlled"},
            }), encoding="utf-8")
            opener = FakeOpener()

            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            request, _ = opener.calls[0]
            self.assertEqual(request.get_header("X-hackerone"), "trusted_hacker")

    def test_restored_authentication_endpoint_is_network_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root,
                attack_methods=["GET", "POST"],
                observed_post=True,
                observed_post_path="/rest/user/login",
                observed_post_source="auth_bootstrap",
            )
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["policies"][0]["allowed_path_prefixes"] = ["/api", "/rest"]
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/rest/user/login",
                "body": '{"email":"probe","password":"redacted"}',
                "risk_class": "application_mutation",
            }), encoding="utf-8")

            with patch(
                "aidast.attack.request_cli.build_opener", return_value=FakeOpener()
            ):
                result = guarded_request(
                    database,
                    scan_id="scan",
                    stage_run_id=stage,
                    task_id=task,
                    policy_path=policy,
                    payload_path=payload,
                )

            with closing(sqlite3.connect(database)) as conn:
                request_row = conn.execute(
                    """SELECT endpoint_provenance,endpoint_reference_id
                       FROM attack_http_requests WHERE request_id=?""",
                    (result["request_id"],),
                ).fetchone()
                endpoint_id = conn.execute(
                    """SELECT endpoint_id FROM endpoints
                       WHERE method='POST' AND normalized_path='/rest/user/login'"""
                ).fetchone()[0]

            self.assertEqual(request_row, ("network_observed", endpoint_id))

    def test_coverage_task_endpoint_wins_equivalent_template_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            with closing(sqlite3.connect(database)) as conn, conn:
                conn.row_factory = sqlite3.Row
                origin = conn.execute("SELECT origin_id FROM origins").fetchone()[0]
                observed = db.upsert_endpoint(
                    conn, origin_id=origin, method="GET", path="/api/Items/1",
                    normalized_path="/api/Items/:id", source_tool="browser",
                )
                conn.execute("""INSERT INTO endpoint_observations
                    (observation_id,endpoint_id,source_tool,discovery_kind,
                     observed_url,association_method,observed_at)
                    VALUES (?,?,?,?,?,?,?)""", (
                    db.new_id("observation"), observed, "browser", "http_response",
                    "https://example.test/api/Items/1", "exact", db.now(),
                ))
                selected = db.upsert_endpoint(
                    conn, origin_id=origin, method="GET", path="/api/Items/{e}",
                    normalized_path="/api/Items/{e}", source_tool="adaptive_js",
                    verification_status="candidate", is_excluded=True,
                    exclude_reason="unverified_candidate",
                )
                conn.execute("""INSERT INTO endpoint_observations
                    (observation_id,endpoint_id,source_tool,discovery_kind,
                     observed_url,association_method,observed_at)
                    VALUES (?,?,?,?,?,?,?)""", (
                    db.new_id("observation"), selected, "adaptive_js", "js_http_call",
                    "https://example.test/api/Items/{e}", "document_declaration", db.now(),
                ))
                conn.execute(
                    "UPDATE attack_tasks SET endpoint_id=? WHERE task_id=?",
                    (selected, task),
                )
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/Items/1",
            }), encoding="utf-8")

            with patch("aidast.attack.request_cli.build_opener", return_value=FakeOpener()):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            with closing(sqlite3.connect(database)) as conn:
                provenance = conn.execute(
                    """SELECT endpoint_provenance,endpoint_reference_id
                       FROM attack_http_requests WHERE request_id=?""",
                    (result["request_id"],),
                ).fetchone()
            self.assertEqual(provenance, ("recon_candidate", selected))

    def test_observed_attack_post_is_allowed_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"], observed_post=True,
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/profile",
                "body": '{"probe":"bounded"}',
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            self.assertEqual(result["status"], 200)
            with closing(sqlite3.connect(database)) as conn:
                source, reference, provenance = conn.execute(
                    """SELECT authorization_source,authorization_reference_id,
                              endpoint_provenance
                       FROM attack_http_requests"""
                ).fetchone()
            self.assertEqual(source, "scope_active_mutation")
            self.assertEqual(reference, "policy")
            self.assertEqual(provenance, "network_observed")

    def test_unobserved_normal_post_is_automatically_allowed_and_traced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(len(opener.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                request_auth = conn.execute(
                    """SELECT authorization_source,authorization_reference_id,
                              endpoint_provenance,risk_class
                       FROM attack_http_requests"""
                ).fetchone()
                envelopes = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(request_auth, (
                "scope_active_mutation", "policy", "agent_proposed",
                "application_mutation",
            ))
            self.assertEqual(envelopes, 0)

    def test_denied_unobserved_post_is_not_dispatched_or_reprompted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/new-action",
                "risk_class": "external_side_effect",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        guarded_request,
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                    deadline = time.monotonic() + 3
                    row = None
                    while time.monotonic() < deadline and row is None:
                        with closing(sqlite3.connect(database)) as conn:
                            row = conn.execute(
                                """SELECT envelope_id FROM attack_authorization_envelopes
                                   WHERE status='pending'"""
                            ).fetchone()
                        if row is None:
                            time.sleep(0.02)
                    self.assertIsNotNone(row)
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute(
                            """UPDATE attack_authorization_envelopes
                               SET status='denied',decided_at=? WHERE envelope_id=?""",
                            (time.time(), row[0]),
                        )
                    with self.assertRaisesRegex(RequestGuardError, "denied by the user"):
                        future.result(timeout=3)
                with self.assertRaisesRegex(RequestGuardError, "denied by the user"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])

    def test_unobserved_mutation_body_over_16_kib_is_rejected_before_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=20, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/new-action",
                "body": "x" * (16_384 + 1),
                "risk_class": "external_side_effect",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with self.assertRaisesRegex(RequestGuardError, "16 KiB"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])
            with closing(sqlite3.connect(database)) as conn:
                count = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(count, 0)

    def test_mutation_requires_active_scope_and_explicit_risk_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST"],
            )
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["policies"][0]["attack_authorization_mode"] = "read_only"
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "active non-destructive"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            document["policies"][0]["attack_authorization_mode"] = (
                "active_non_destructive"
            )
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "risk_class"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

    def test_destructive_or_bulk_request_is_always_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/profile",
                "risk_class": "destructive_or_bulk",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with self.assertRaisesRegex(RequestGuardError, "prohibited"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])

    def test_delete_of_resource_created_by_same_task_is_automatically_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST", "DELETE"],
            )
            opener = FakeOpener([b'{"id":"42"}', b'{"deleted":true}'])
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "POST",
                    "url": "https://example.test/api/items",
                    "risk_class": "test_resource_create",
                    "captures": [{
                        "name": "created_id", "source": "json_body", "path": ["id"],
                    }],
                }), encoding="utf-8")
                created = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                payload.write_text(json.dumps({
                    "method": "DELETE",
                    "url": "https://example.test/api/items/42",
                    "risk_class": "test_resource_delete",
                    "bindings": [{
                        "name": "created_id",
                        "source_request_id": created["request_id"],
                        "capture_name": "created_id",
                        "value": "42",
                        "target_kind": "path_parameter",
                        "target_path": ["id"],
                    }],
                }), encoding="utf-8")
                deleted = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(deleted["status"], 200)
            self.assertEqual(len(opener.calls), 2)
            with closing(sqlite3.connect(database)) as conn:
                authorization = conn.execute(
                    """SELECT authorization_source,risk_class
                       FROM attack_http_requests WHERE method='DELETE'"""
                ).fetchone()
                envelopes = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(
                authorization, ("scope_active_mutation", "test_resource_delete")
            )
            self.assertEqual(envelopes, 0)

    def test_unproven_delete_requires_an_approval_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "DELETE"],
            )
            payload.write_text(json.dumps({
                "method": "DELETE",
                "url": "https://example.test/api/items/42",
                "risk_class": "test_resource_delete",
            }), encoding="utf-8")
            opener = FakeOpener()
            with (
                patch("aidast.attack.request_cli.build_opener", return_value=opener),
                patch(
                    "aidast.attack.request_cli._await_approved_envelope",
                    return_value="envelope_test",
                ) as approve,
            ):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(
                approve.call_args.kwargs["approval_reason"],
                "unproven_delete_ownership",
            )
            with closing(sqlite3.connect(database)) as conn:
                authorization = conn.execute(
                    """SELECT authorization_source,authorization_reference_id
                       FROM attack_http_requests"""
                ).fetchone()
            self.assertEqual(authorization, ("approved_envelope", "envelope_test"))

    def test_high_impact_path_requires_approval_despite_lower_risk_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/notifications/broadcast",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            with (
                patch("aidast.attack.request_cli.build_opener", return_value=FakeOpener()),
                patch(
                    "aidast.attack.request_cli._await_approved_envelope",
                    return_value="envelope_test",
                ) as approve,
            ):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(
                approve.call_args.kwargs["approval_reason"], "high_impact_path"
            )

    def test_mutation_budget_is_bounded_per_task_and_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=20, attack_methods=["GET", "POST"],
            )
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                for identifier in range(10):
                    payload.write_text(json.dumps({
                        "method": "POST",
                        "url": f"https://example.test/api/items/{identifier}",
                        "risk_class": "application_mutation",
                    }), encoding="utf-8")
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                payload.write_text(json.dumps({
                    "method": "POST",
                    "url": "https://example.test/api/items/999",
                    "risk_class": "application_mutation",
                }), encoding="utf-8")
                with self.assertRaisesRegex(RequestGuardError, "mutation budget"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(len(opener.calls), 10)

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
