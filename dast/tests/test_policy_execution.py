from __future__ import annotations

import json
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mitmproxy.http import Headers

from aidast.recon.policy import PolicyError, ReconPolicy, ScopeGuard, load_policy
from aidast.recon.policy_plan import build_execution_plan
from aidast.recon.policy_runner import PolicyToolRunner, _redact_arguments
from aidast.recon.policy_store import PolicyRunStore
from aidast.recon.tools.mitm_addon import PolicyEnforcer


def policy_payload(*, traffic_class: str = "target_http") -> dict:
    return {
        "schema_version": "1.0",
        "source": {"scope_md_path": "/approved/scope.md"},
        "policy_status": "ready",
        "default_execution_decision": "block",
        "target_rules": {
            "allow": [
                {
                    "asset_type": "url",
                    "value": "https://example.com/api",
                    "schemes": ["https"],
                    "ports": [443],
                    "path_prefixes": ["/api"],
                    "source_section": "In Scope",
                }
            ],
            "deny": [
                {
                    "asset_type": "url",
                    "value": "https://example.com/api/admin",
                    "reason": "admin path excluded",
                    "source_section": "Out of Scope",
                }
            ],
        },
        "global_controls": {
            "proxy_required_for_http": True,
            "maximum_requests_per_second": 5,
            "maximum_concurrency": 2,
            "maximum_duration_seconds": 60,
            "follow_off_scope_redirects": False,
            "revalidate_each_redirect": True,
            "required_headers": [
                {
                    "name": "X-Bug-Bounty",
                    "value": None,
                    "value_source": "runtime_input",
                    "required": True,
                }
            ],
        },
        "tools": {
            "katana": {
                "program_permission": "conditional",
                "execution_decision": "allow",
                "traffic_class": traffic_class,
                "proxy": {"mode": "required", "coverage": "full"},
                "enforced_controls": {
                    "maximum_requests_per_second": 3,
                    "maximum_concurrency": 1,
                    "maximum_duration_seconds": 30,
                    "required_arguments": ["-proxy"],
                    "forbidden_arguments": ["-ns"],
                },
                "conditions": ["required header"],
                "evidence": [
                    {
                        "source_section": "Testing Restrictions",
                        "rule": "Automated tools are allowed at 3 requests per second.",
                    }
                ],
                "reason": "Automation is explicitly allowed with controls.",
            },
            "nuclei": {
                "program_permission": "prohibited",
                "execution_decision": "block",
                "traffic_class": "target_http",
                "proxy": {"mode": "required", "coverage": "full"},
                "enforced_controls": {
                    "maximum_requests_per_second": None,
                    "maximum_concurrency": None,
                    "maximum_duration_seconds": None,
                    "required_arguments": [],
                    "forbidden_arguments": [],
                },
                "conditions": [],
                "evidence": [
                    {
                        "source_section": "Prohibited Actions",
                        "rule": "Automated vulnerability scanning is prohibited.",
                    }
                ],
                "reason": "The program prohibits this behavior.",
            },
        },
        "runtime_inputs": [],
        "review_items": [],
    }


class ScopeGuardTests(unittest.TestCase):
    def test_deny_rule_wins_and_path_scope_is_not_broadened(self) -> None:
        guard = ScopeGuard(ReconPolicy.model_validate(policy_payload()))

        self.assertTrue(guard.evaluate_url("https://example.com/api/users")[0])
        self.assertFalse(guard.evaluate_url("https://example.com/api/admin/1")[0])
        self.assertFalse(guard.evaluate_url("https://example.com/")[0])
        self.assertFalse(guard.evaluate_url("https://example.com/apix")[0])
        self.assertFalse(guard.evaluate_url("https://other.example/api")[0])

    def test_policy_blocks_every_decision_other_than_allow(self) -> None:
        policy = ReconPolicy.model_validate(policy_payload())

        with self.assertRaisesRegex(PolicyError, "not executable"):
            policy.require_executable_tool("nuclei")
        with self.assertRaisesRegex(PolicyError, "does not contain"):
            policy.require_executable_tool("unknown")

    def test_legacy_policy_has_a_clear_regeneration_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            policy_path = Path(temporary_dir) / "recon-policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "exact_allowlist": ["https://example.com"],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PolicyError, "regenerate.*aidast-recon-policy"
            ):
                load_policy(policy_path)


class PolicyExecutionPlanTests(unittest.TestCase):
    def test_automatically_selects_allowed_adapter_and_all_concrete_targets(
        self,
    ) -> None:
        payload = policy_payload()
        payload["target_rules"]["allow"].extend(
            [
                {
                    "asset_type": "host",
                    "value": "api.example.org",
                    "schemes": ["https"],
                    "ports": [443, 8443],
                    "path_prefixes": ["/v1"],
                    "source_section": "In Scope",
                },
                {
                    "asset_type": "ip",
                    "value": "192.0.2.8",
                    "schemes": ["http"],
                    "ports": [8080],
                    "path_prefixes": ["/"],
                    "source_section": "In Scope",
                },
                {
                    "asset_type": "wildcard_host",
                    "value": "*.example.net",
                    "schemes": ["https"],
                    "ports": [443],
                    "path_prefixes": ["/"],
                    "source_section": "In Scope",
                },
            ]
        )
        plan = build_execution_plan(
            ReconPolicy.model_validate(payload),
            supported_tool_ids={"katana", "nuclei"},
        )

        self.assertEqual(plan.tool_ids, ("katana",))
        self.assertIn("https://example.com/api", plan.targets)
        self.assertIn("https://api.example.org/v1", plan.targets)
        self.assertIn("https://api.example.org:8443/v1", plan.targets)
        self.assertIn("http://192.0.2.8:8080/", plan.targets)
        self.assertEqual(plan.skipped_tools[0].item_id, "nuclei")
        self.assertIn("wildcard_host", plan.skipped_targets[0].item_id)

    def test_explicit_target_and_tool_must_both_be_policy_approved(self) -> None:
        policy = ReconPolicy.model_validate(policy_payload())

        with self.assertRaisesRegex(PolicyError, "outside policy"):
            build_execution_plan(
                policy,
                supported_tool_ids={"katana"},
                requested_targets=["https://outside.example/api"],
                requested_tool_ids=["katana"],
            )
        with self.assertRaisesRegex(PolicyError, "cannot execute"):
            build_execution_plan(
                policy,
                supported_tool_ids={"katana", "nuclei"},
                requested_targets=["https://example.com/api"],
                requested_tool_ids=["nuclei"],
            )


class FakeRequest:
    def __init__(self, url: str, *, headers: dict[str, str] | None = None):
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        self.pretty_url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.method = "GET"
        self.path = parsed.path or "/"
        self.headers = Headers(**(headers or {}))


class FakeFlow:
    def __init__(self, request: FakeRequest):
        self.request = request
        self.response = None
        self.metadata: dict = {}


class MitmAddonTests(unittest.TestCase):
    def _addon(self) -> PolicyEnforcer:
        policy = ReconPolicy.model_validate(policy_payload())
        addon = PolicyEnforcer()
        addon._policy = policy
        addon._guard = ScopeGuard(policy)
        addon._fp = io.StringIO()
        return addon

    def test_blocks_out_of_scope_request_before_forwarding(self) -> None:
        addon = self._addon()
        flow = FakeFlow(
            FakeRequest(
                "https://outside.example/api",
                headers={"X-AIDAST-Execution": "exec-1", "X-Bug-Bounty": "user"},
            )
        )

        addon.request(flow)

        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.metadata["aidast_decision"], "block")
        self.assertNotIn("X-AIDAST-Execution", flow.request.headers)

    def test_records_allowed_flow_with_sensitive_headers_redacted(self) -> None:
        addon = self._addon()
        flow = FakeFlow(
            FakeRequest(
                "https://example.com/api/users",
                headers={
                    "X-AIDAST-Execution": "exec-1",
                    "X-Bug-Bounty": "researcher",
                    "Authorization": "secret",
                },
            )
        )
        flow.response = SimpleNamespace(
            status_code=200,
            headers=Headers(content_type="application/json", content_length="2"),
        )

        with patch(
            "aidast.recon.tools.mitm_addon.ctx",
            SimpleNamespace(options=SimpleNamespace(run_id="run-1")),
        ):
            addon.request(flow)
            addon.response(flow)

        record = json.loads(addon._fp.getvalue())
        self.assertEqual(record["decision"], "allow")
        self.assertEqual(record["execution_id"], "exec-1")
        self.assertEqual(record["request_headers"]["Authorization"], "<redacted>")
        self.assertEqual(record["request_headers"]["X-Bug-Bounty"], "<redacted>")


class PolicyToolRunnerTests(unittest.TestCase):
    def test_missing_required_header_blocks_before_proxy_or_run_creation(self) -> None:
        policy = ReconPolicy.model_validate(policy_payload())
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
            )
            try:
                with self.assertRaisesRegex(PolicyError, "missing required header"):
                    runner.run(["katana"])
                run_count = runner.store.conn.execute(
                    "SELECT COUNT(*) FROM policy_runs"
                ).fetchone()[0]
            finally:
                runner.close()

        self.assertEqual(run_count, 0)

    def test_all_tool_prerequisites_are_checked_before_a_run_is_created(self) -> None:
        payload = policy_payload()
        payload["tools"]["ffuf"] = payload["tools"]["katana"].copy()
        policy = ReconPolicy.model_validate(payload)
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={"X-Bug-Bounty": "researcher"},
            )
            try:
                with patch(
                    "aidast.recon.policy_runner.shutil.which",
                    return_value="/bin/tool",
                ):
                    with self.assertRaisesRegex(PolicyError, "wordlist"):
                        runner.run(["katana", "ffuf"])
                row = runner.store.conn.execute(
                    "SELECT COUNT(*) FROM policy_runs"
                ).fetchone()
            finally:
                runner.close()

        self.assertEqual(row[0], 0)

    def test_policy_fixed_header_and_internal_execution_id_cannot_be_overridden(
        self,
    ) -> None:
        payload = policy_payload()
        payload["global_controls"]["required_headers"] = [
            {
                "name": "X-Bug-Bounty",
                "value": "fixed-policy-value",
                "value_source": "fixed_from_scope",
                "required": True,
            }
        ]
        policy = ReconPolicy.model_validate(payload)
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={
                    "x-bug-bounty": "user-override",
                    "x-aidast-execution": "spoofed-execution",
                },
            )
            try:
                headers = runner._resolved_headers("trusted-execution")
            finally:
                runner.close()

        self.assertEqual(headers["X-Bug-Bounty"], "fixed-policy-value")
        self.assertEqual(headers["X-AIDAST-Execution"], "trusted-execution")
        self.assertNotIn("x-bug-bounty", headers)
        self.assertNotIn("x-aidast-execution", headers)

    def test_katana_command_forces_proxy_controls_and_required_header(self) -> None:
        policy = ReconPolicy.model_validate(policy_payload())
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={"X-Bug-Bounty": "researcher"},
            )
            try:
                tool = runner._validate_tool("katana")
                command, timeout = runner._build_command(
                    "katana", tool, "http://127.0.0.1:18080", execution_id="exec-1"
                )
            finally:
                runner.close()

        self.assertEqual(timeout, 30)
        self.assertIn("http://127.0.0.1:18080", command)
        self.assertEqual(command[command.index("-rl") + 1], "3")
        self.assertEqual(command[command.index("-c") + 1], "1")
        self.assertIn("X-Bug-Bounty: researcher", command)
        self.assertIn("X-AIDAST-Execution: exec-1", command)

    def test_runner_rejects_provider_traffic_without_provider_allowlist(self) -> None:
        policy = ReconPolicy.model_validate(policy_payload(traffic_class="provider_http"))
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={"X-Bug-Bounty": "researcher"},
            )
            try:
                with self.assertRaisesRegex(PolicyError, "cannot be safely constrained"):
                    runner._validate_tool("katana")
            finally:
                runner.close()

    def test_curl_command_trusts_only_the_ephemeral_mitm_ca(self) -> None:
        payload = policy_payload()
        payload["tools"]["curl"] = payload["tools"].pop("katana")
        payload["tools"]["curl"]["enforced_controls"]["required_arguments"] = [
            "--proxy"
        ]
        policy = ReconPolicy.model_validate(payload)
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            ca_path = root / "mitmproxy-ca-cert.pem"
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={"X-Bug-Bounty": "researcher"},
            )
            try:
                command, _ = runner._build_command(
                    "curl",
                    runner._validate_tool("curl"),
                    "http://127.0.0.1:18080",
                    execution_id="exec-1",
                    ca_cert_path=ca_path,
                )
            finally:
                runner.close()

        self.assertEqual(command[command.index("--cacert") + 1], str(ca_path))
        self.assertNotIn("--insecure", command)

    def test_playwright_adapter_uses_proxy_and_execution_header(self) -> None:
        payload = policy_payload()
        payload["tools"]["playwright"] = payload["tools"].pop("katana")
        payload["tools"]["playwright"]["enforced_controls"][
            "required_arguments"
        ] = ["--proxy"]
        policy = ReconPolicy.model_validate(payload)
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            runner = PolicyToolRunner(
                policy=policy,
                policy_path=root / "policy.json",
                target="https://example.com/api",
                db_path=root / "audit.sqlite3",
                flow_log_path=root / "flows.jsonl",
                headers={"X-Bug-Bounty": "researcher"},
            )
            run_id = runner.store.start_run(
                policy_path=root / "policy.json", target="https://example.com/api"
            )
            browser = MagicMock()
            browser.is_connected.return_value = False
            page = browser.new_context.return_value.new_page.return_value
            page.url = "https://example.com/api"
            page.title.return_value = "Example"
            page.goto.return_value.status = 200
            playwright = MagicMock()
            playwright.chromium.launch.return_value = browser
            manager = MagicMock()
            manager.__enter__.return_value = playwright
            manager.__exit__.return_value = False
            try:
                with patch(
                    "aidast.recon.policy_runner.sync_playwright", return_value=manager
                ):
                    result = runner._run_playwright(
                        runner._validate_tool("playwright"),
                        "http://127.0.0.1:18080",
                        run_id,
                        execution_id="exec-playwright",
                    )
            finally:
                runner.close()

        launch = playwright.chromium.launch.call_args.kwargs
        context = browser.new_context.call_args.kwargs
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(launch["proxy"]["server"], "http://127.0.0.1:18080")
        self.assertEqual(
            context["extra_http_headers"]["X-AIDAST-Execution"],
            "exec-playwright",
        )

    def test_persisted_command_redacts_header_values(self) -> None:
        redacted = _redact_arguments(
            ["katana", "-H", "Authorization: secret", "-u", "https://example.com"]
        )
        self.assertEqual(redacted[2], "Authorization: <redacted>")
        self.assertNotIn("secret", " ".join(redacted))


class PolicyStoreTests(unittest.TestCase):
    def test_ingests_only_matching_run_and_keeps_redacted_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            store = PolicyRunStore(root / "audit.sqlite3")
            run_id = store.start_run(
                policy_path=root / "policy.json", target="https://example.com/api"
            )
            execution_id = store.start_execution(
                run_id=run_id,
                tool_id="katana",
                redacted_arguments=["katana", "-H", "Authorization: <redacted>"],
            )
            flow_log = root / "flows.jsonl"
            records = [
                {
                    "run_id": run_id,
                    "execution_id": execution_id,
                    "timestamp": 1.0,
                    "scheme": "https",
                    "host": "example.com",
                    "port": 443,
                    "method": "GET",
                    "path": "/api/users",
                    "query_string": None,
                    "request_headers": {"Authorization": "<redacted>"},
                    "status_code": 200,
                    "content_type": "application/json",
                    "response_size": 12,
                    "decision": "allow",
                    "reason": "matched allow rule",
                },
                {"run_id": "other-run", "decision": "block", "reason": "other"},
            ]
            flow_log.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )

            self.assertEqual(store.ingest_flow_log(flow_log, run_id=run_id), 1)
            self.assertEqual(store.count_execution_flows(execution_id), 1)
            store.close()

            conn = sqlite3.connect(root / "audit.sqlite3")
            row = conn.execute(
                "SELECT host, path, decision, request_headers_json FROM proxy_flows"
            ).fetchone()
            conn.close()

        self.assertEqual(row[:3], ("example.com", "/api/users", "allow"))
        self.assertNotIn("secret", row[3])


if __name__ == "__main__":
    unittest.main()
