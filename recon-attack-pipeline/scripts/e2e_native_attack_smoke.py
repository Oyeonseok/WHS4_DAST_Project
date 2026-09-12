"""Local-only native Recon -> Attack -> Chaining end-to-end smoke test."""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from aidast.agents.main import CodexMainAgent
from aidast.orchestration.attack import AttackCoordinator
from aidast.orchestration.chaining import ChainingCoordinator
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.recon import db
from aidast.recon.executor import ReconExecutor
from aidast.recon.models import ReconStep, ReconTask, ReconTaskTarget
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


class CorsLabHandler(BaseHTTPRequestHandler):
    server_version = "AI-DAST-E2E/1.0"

    def _headers(self, status: int, length: int = 0) -> None:
        self.send_response(status)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._headers(204)

    def do_HEAD(self) -> None:  # noqa: N802
        body = b'{"profile":"private"}'
        self._headers(200 if "session=e2e-local" in self.headers.get("Cookie", "") else 401, len(body))

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/api/account/victim-42":
            body = b'{"account_id":"victim-42","owner":"victim","private":true,"record":"local-chain-proof"}'
            self._headers(200, len(body))
            self.wfile.write(body)
            return
        if path.startswith("/api/account/"):
            body = b'{"error":"not found"}'
            self._headers(404, len(body))
            self.wfile.write(body)
            return
        if path != "/api/profile":
            self._headers(404)
            return
        if "session=e2e-local" not in self.headers.get("Cookie", ""):
            body = b'{"error":"authentication required"}'
            self._headers(401, len(body))
            self.wfile.write(body)
            return
        body = b'{"user":"e2e-user","email":"local@example.test","account_id":"victim-42"}'
        self._headers(200, len(body))
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def prepare_fixture(root: Path, port: int) -> tuple[Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=False)
    database = root / "Pipeline.db"
    scope = root / "Scope.md"
    policy = root / "TargetPolicy.json"
    base_url = f"http://127.0.0.1:{port}"
    scope.write_text(
        """# Local AI-DAST E2E Scope

Only `http://127.0.0.1` on the port in TargetPolicy.json is in scope.
Non-destructive GET, HEAD, OPTIONS, CORS and authorization testing is allowed.
Denial of service, destructive writes, persistence and other hosts are prohibited.
""",
        encoding="utf-8",
    )
    policy_document = {
        "schema_version": "1.0",
        "scope_id": "scope_e2e_local",
        "policies": [{
            "schema_version": "1.0", "scope_id": "scope_e2e_local",
            "policy_id": "policy_e2e_local", "asset_type": "URL",
            "asset": base_url + "/api/profile", "allowed_schemes": ["http"],
            "allowed_hosts": ["127.0.0.1"], "include_subdomains": False,
            "allowed_ports": [port], "allowed_path_prefixes": ["/api"],
            "excluded_path_prefixes": [], "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "limits": {"requests_per_second": 1.0, "concurrency": 1,
                       "timeout_seconds": 5, "max_depth": 1, "max_requests": 30},
            "tools": {"playwright_interaction": False, "form_submission": False,
                      "katana_headless": False, "ffuf_enabled": False,
                      "ffuf_recursion": False, "mitm_capture_bodies": True},
            "policy_notes": ["Local E2E fixture only"], "restriction_evidence": [],
        }],
    }
    policy.write_text(json.dumps(policy_document, indent=2), encoding="utf-8")
    target_policy = TargetPolicy.model_validate(policy_document["policies"][0])
    target = base_url + "/api/profile"
    executor = ReconExecutor(
        scan_id="scan_e2e_local", scope_type="approved_scope",
        scope_value="scope_e2e_local", db_path=database,
        target_policies={(AssetType.URL.value, target): target_policy},
        require_policy_enforcement=True,
        execution_start_urls={(AssetType.URL.value, target): target},
    )
    tasks = [
        ReconTask(
            task_id="recon_probe", plan_id="plan_e2e", scope_id="scope_e2e_local",
            task_type=ReconStep.HTTP_PROBE, sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.URL, asset=target),
            depends_on_task_ids=[], constraints=["local-only"],
        ),
        ReconTask(
            task_id="recon_origin", plan_id="plan_e2e", scope_id="scope_e2e_local",
            task_type=ReconStep.ORIGIN_DISCOVERY, sequence=2,
            target=ReconTaskTarget(asset_type=AssetType.URL, asset=target),
            depends_on_task_ids=["recon_probe"], constraints=["local-only"],
        ),
    ]
    conn = executor.conn
    recon_stage = start_stage_run(conn, scan_id="scan_e2e_local", stage="recon")
    try:
        executor.run(tasks)
        origin, endpoint = conn.execute(
            """SELECT o.origin_id,e.endpoint_id FROM endpoints e
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id='scan_e2e_local' AND e.path='/api/profile'"""
        ).fetchone()
        conn.execute(
            """INSERT INTO sessions
               (session_id,origin_id,target,auth_state,isolation_scope)
               VALUES ('session_e2e',?,?,?,'origin')""",
            (origin, base_url, json.dumps({"cookie": "session=e2e-local"})),
        )
        conn.execute("UPDATE endpoints SET session_id='session_e2e' WHERE endpoint_id=?", (endpoint,))
        conn.execute(
            "INSERT INTO observations VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
            ("observation_e2e", origin, "response_header", "vary", "Origin", "e2e-fixture"),
        )
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
                association_method,observed_at,evidence_json)
               VALUES ('endpoint_observation_e2e',?,'e2e-fixture','http_transaction',?,
                       'direct',CURRENT_TIMESTAMP,'{}')""",
            (endpoint, base_url + "/api/profile"),
        )
        conn.execute(
            """INSERT INTO annotation_runs
               (annotation_run_id,scan_id,model,prompt_version,taxonomy_version,status,
                started_at,finished_at) VALUES
               ('annotation_e2e','scan_e2e_local','fixture','1','1','completed',
                CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"""
        )
        for identifier, category, tag in (
            ("annotation_profile", "function", "profile_read"),
            ("annotation_personal", "data_role", "personal_data"),
        ):
            conn.execute(
                """INSERT INTO endpoint_annotations
                   (annotation_id,observation_id,annotation_run_id,category,tag,rationale,
                    confidence,created_at) VALUES (?,?, 'annotation_e2e',?,?,?,1.0,CURRENT_TIMESTAMP)""",
                (identifier, "endpoint_observation_e2e", category, tag, "local E2E fixture"),
            )
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan_e2e_local'"
        )
        conn.commit()
        finish_stage_run(conn, recon_stage, status="completed")
    finally:
        conn.close()
    return database, scope, policy


def seed_completed_attack(
    database: Path, *, port: int, include_chain_pair: bool = False,
) -> None:
    """Seed Attack-proven findings for a faster Chaining-only smoke run."""
    with closing(sqlite3.connect(database)) as conn:
        origin, endpoint = conn.execute(
            """SELECT e.origin_id,e.endpoint_id FROM endpoints e
               WHERE e.path='/api/profile'"""
        ).fetchone()
        account_endpoint = db.upsert_endpoint(
            conn, origin_id=origin, method="GET", path="/api/account/victim-42",
            normalized_path="/api/account/{id}", source_tool="e2e-fixture",
        )
        stage = start_stage_run(conn, scan_id="scan_e2e_local", stage="attack")
        cors_task = create_task(
            conn, stage_run_id=stage, skill_name="hunt-cors", endpoint_id=endpoint
        )
        transition_task(conn, cors_task, status="running")
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
               VALUES ('finding_e2e_seed','scan_e2e_local',?,'CORS','MEDIUM',
                       'Credentialed arbitrary-origin CORS','Local smoke seed')""",
            (endpoint,),
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                method,url,outcome,finding_id,resolved_at)
               VALUES ('attempt_e2e_seed','scan_e2e_local',?,'hunt-cors',?,?,'GET',
                       'http://127.0.0.1/api/profile','confirmed','finding_e2e_seed',
                       CURRENT_TIMESTAMP)""",
            (cors_task, endpoint, "f" * 64),
        )
        base_url = f"http://127.0.0.1:{port}"
        conn.execute(
            """INSERT INTO attack_requests
               (request_id,finding_id,role,method,url,request_headers,response_status,
                response_headers,response_body,response_time_ms)
               VALUES ('seed_request_cors','finding_e2e_seed','authenticated','GET',?,
                       'Origin: https://attacker.invalid\nCookie: [REDACTED]',200,
                       'Access-Control-Allow-Origin: https://attacker.invalid\nAccess-Control-Allow-Credentials: true',
                       ?,1)""",
            (base_url + "/api/profile", b'{"account_id":"victim-42"}'),
        )
        transition_task(conn, cors_task, status="completed")
        if include_chain_pair:
            idor_task = create_task(
                conn, stage_run_id=stage, skill_name="hunt-idor",
                endpoint_id=account_endpoint,
            )
            transition_task(conn, idor_task, status="running")
            conn.execute(
                """INSERT INTO findings
                   (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                   VALUES ('finding_e2e_idor','scan_e2e_local',?,'IDOR','HIGH',
                           'Unauthenticated account record access by identifier',
                           'The account endpoint accepts an externally obtained account ID.')""",
                (account_endpoint,),
            )
            conn.execute(
                """INSERT INTO attack_attempts
                   (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                    method,url,outcome,finding_id,resolved_at)
                   VALUES ('attempt_e2e_idor','scan_e2e_local',?,'hunt-idor',?,?,'GET',?,
                           'confirmed','finding_e2e_idor',CURRENT_TIMESTAMP)""",
                (idor_task, account_endpoint, "e" * 64,
                 base_url + "/api/account/victim-42"),
            )
            conn.execute(
                """INSERT INTO attack_requests
                   (request_id,finding_id,role,method,url,response_status,response_headers,
                    response_body,response_time_ms)
                   VALUES ('seed_request_idor','finding_e2e_idor','unauthenticated','GET',?,
                           200,'Content-Type: application/json',?,1)""",
                (base_url + "/api/account/victim-42",
                 b'{"account_id":"victim-42","owner":"victim","private":true,"record":"local-chain-proof"}'),
            )
            transition_task(conn, idor_task, status="completed")
        finish_stage_run(conn, stage, status="completed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--chaining-only", action="store_true")
    parser.add_argument("--successful-chain", action="store_true")
    args = parser.parse_args()
    temporary = None
    if args.output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="aidast-native-e2e-")
        output = Path(temporary.name) / "run"
    else:
        output = args.output_dir.resolve()
        if output.exists():
            raise SystemExit(f"output already exists: {output}")
    server = ThreadingHTTPServer(("127.0.0.1", 0), CorsLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        database, scope, policy = prepare_fixture(output, server.server_port)
        agent = CodexMainAgent(timeout_seconds=300)
        if args.chaining_only or args.successful_chain:
            seed_completed_attack(
                database, port=server.server_port,
                include_chain_pair=args.successful_chain,
            )
            seeded_findings = ["finding_e2e_seed"]
            if args.successful_chain:
                seeded_findings.append("finding_e2e_idor")
            attack_output = {"status": "SEEDED", "finding_ids": seeded_findings}
        else:
            result = AttackCoordinator(
                agent=agent, db_path=database,
                scope_path=scope, policy_path=policy,
            ).run("scan_e2e_local")
            attack_output = result.model_dump()
        chaining_result = ChainingCoordinator(
            agent=agent, db_path=database, scope_path=scope, policy_path=policy,
        ).run("scan_e2e_local")
        with closing(sqlite3.connect(database)) as conn:
            counts = {
                table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "endpoints", "http_transactions", "attack_tasks",
                    "attack_http_requests", "attack_attempts", "attack_requests", "findings",
                    "chain_candidates", "finding_chains", "chain_evidence",
                    "chain_executions", "chain_execution_steps",
                    "chain_execution_bindings",
                )
            }
        print(json.dumps({"attack_result": attack_output,
                          "chaining_result": chaining_result.model_dump(), "counts": counts,
                          "output_dir": str(output)}, ensure_ascii=False, indent=2))
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
