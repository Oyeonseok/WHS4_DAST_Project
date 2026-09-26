"""Stage seven isolated, explicitly synthetic claims for live Validation replay.

The claims model false positives for testing. Attack outcomes are set to
``confirmed`` only to exercise the existing Validation integrity contract; they
must never be reported as demonstrated exploits. HTTP observations are real GET
response metadata from the local pinned lab. The answer key is not copied into
the staged Pipeline.db or candidate-to-finding map.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (
    ImpactDevelopmentRuntimeContract, canonical_reproduction_spec, canonical_sha256,
    validate_runtime_contract,
)
from aidast.validation.contracts.eligibility import ScopePolicySource
from aidast.validation.contracts.impact_development import impact_contract_document
from aidast.validation.contracts.runtime_contract import HttpRequestTemplate, render_http_request
from aidast.validation.core.integrity import CandidateIntegrityGate
from aidast.validation.persistence.repository import ValidationRepository
try:
    from scripts.probe_validation_controls import fetch_status_and_digest, verify_runtime_identity
except ModuleNotFoundError:  # Direct `python scripts/prepare_validation_lab.py`.
    from probe_validation_controls import fetch_status_and_digest, verify_runtime_identity


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / "result/test-runs/validation-candidates"
DEFAULT_SCOPE_ROOT = ROOT / "result/Scope/lab-aidast-invalid"
BASES = {"juice-shop": "http://127.0.0.1:3001", "vuln-bank": "http://127.0.0.1:5001"}
SKILLS = {"sql_injection": "hunt-sqli", "unauthenticated_disclosure": "hunt-auth-bypass",
          "excessive_data_exposure": "hunt-source-leak"}
IMPACT_CANDIDATE = "vuln-bank:curated:GET:/debug/users:excessive_data_exposure"
SEED_SOURCE_SHA256 = "071e9a655508f6c6790cc01620a8a680681165defa5a141c017729e3280b793b"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def probe_impact_markers(url: str) -> tuple[set[str], str]:
    """Check only non-secret JSON field names in one bounded local GET response."""
    if url != BASES["vuln-bank"] + "/debug/users":
        raise ValueError("impact marker probe URL is not the pinned debug route")
    with build_opener(_NoRedirect).open(Request(url, method="GET"), timeout=15) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("impact marker probe response changed")
        body = response.read(1_048_577)
    if len(body) > 1_048_576:
        raise ValueError("impact marker probe response exceeded bounded size")
    return impact_marker_names(body), hashlib.sha256(body).hexdigest()


def impact_marker_names(body: bytes) -> set[str]:
    """Extract declared JSON keys and the pinned first demo admin record."""
    document = json.loads(body)
    if not isinstance(document, dict) or "users" not in document:
        return set()
    names = {"users"}
    users = document["users"]
    if isinstance(users, list) and any(
        isinstance(user, dict) and "password" in user for user in users
    ):
        names.add("password")
    admin = users[0] if isinstance(users, list) and users and isinstance(users[0], dict) else {}
    if admin.get("username") == "admin" and "password" in admin:
        names.add("seeded_admin")
    if (admin.get("username") == "admin" and admin.get("account_number") == "ADMIN001"
            and "password" in admin):
        names.add("seeded_admin_account")
    return names


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _contract(candidate: dict) -> tuple[str, str, str, dict, str]:
    """Return endpoint, slot, location, bounded HTTP contract, and Hunt skill."""
    path = candidate["endpoint_template"]
    project = candidate["project"]
    vuln = candidate["vuln_class"]
    if project == "juice-shop" and path == "/api/Feedbacks/:id":
        endpoint, slot, location = "/api/Feedbacks/1", "probe", "query"
        target, positive, negative = None, "healthy", "inert"
        marker, positive_status = '"comment"', 401
    elif project == "juice-shop" and path in {
        "/api/Users", "/api/PrivacyRequests", "/api/Complaints"
    }:
        endpoint, slot, location = path, "probe", "query"
        target, positive, negative = None, "healthy", "inert"
        marker, positive_status = '"data"', 401
    elif path == "/api/billers/by-category/<int:category_id>":
        endpoint, slot, location = "/api/billers/by-category/{category_id}", "category_id", "path"
        target, positive, negative = "1' OR 1=1", "1", "not-an-int"
        marker, positive_status = '"billers"', 200
    elif path == "/api/virtual-cards/<int:card_id>/transactions":
        endpoint, slot, location = "/api/virtual-cards/{card_id}/transactions", "card_id", "path"
        target, positive, negative = "1' OR 1=1", "1", "not-an-int"
        marker, positive_status = '"transactions"', 401
    elif project == "vuln-bank" and path == "/debug/users":
        endpoint, slot, location = "/debug/{resource}", "resource", "path"
        target, positive, negative = "users", "users", "missing"
        marker, positive_status = '"password":', 200
    else:
        raise ValueError(f"no read-only replay plan for {candidate['candidate_id']}")
    proof = {"assertion_id": "bounded-signal", "kind": "body_contains", "expected": marker}
    def request(value):
        if location == "query":
            return {} if value is None else {"query_parameters": {slot: value}}
        return {"path_parameters": {slot: value}}
    runtime = validate_runtime_contract({
        "schema_version": 1,
        "target": {"request": request(target), "assertions": [proof]},
        "positive_control": {
            "request": request(positive),
            "assertions": [{"assertion_id": "channel-healthy", "kind": "status_equals",
                            "expected": positive_status}],
        },
        "negative_control": {
            "request": request(negative), "assertions": [proof],
        },
    }).model_dump(mode="json")
    return endpoint, slot, location, runtime, SKILLS[vuln]


def _load_inputs(inventory: Path, answers: Path, observations: Path,
                 live_probe: Callable[[str], tuple[int, str, int]],
                 identity_probe: Callable[[], dict]) -> list[tuple[dict, dict]]:
    with sqlite3.connect(answers) as key_db:
        linked = key_db.execute(
            "SELECT value FROM answer_metadata WHERE key='inventory_sha256'"
        ).fetchone()
        if linked is None or linked[0] != hashlib.sha256(inventory.read_bytes()).hexdigest():
            raise ValueError("answer key is not bound to this candidate inventory")
        ready = [row[0] for row in key_db.execute(
            "SELECT candidate_id FROM answer_key WHERE readiness='GET_REPLAY_READY' ORDER BY candidate_id"
        )]
        expected = {row[0]: row[1] for row in key_db.execute(
            "SELECT candidate_id,observed_http_status FROM answer_key WHERE readiness='GET_REPLAY_READY'"
        )}
    with sqlite3.connect(inventory) as candidate_db:
        candidate_db.row_factory = sqlite3.Row
        candidates = {row["candidate_id"]: dict(row) for row in candidate_db.execute(
            "SELECT * FROM attack_candidates WHERE candidate_id IN ("
            + ",".join("?" for _ in ready) + ")", ready
        )}
    report = json.loads(observations.read_text(encoding="utf-8"))
    if report.get("runtime_identity") != identity_probe():
        raise ValueError("runtime identity differs from saved observations")
    items = report["observations"]
    observed = {item["candidate_id"]: item for item in items}
    if len(observed) != len(items) or set(observed) != set(ready) or set(candidates) != set(ready):
        raise ValueError("observation candidate set differs from the adjudicated GET subset")
    result = []
    for candidate_id in ready:
        item = observed[candidate_id]
        candidate = candidates[candidate_id]
        expected_base = BASES[candidate["project"]]
        endpoint, _, _, runtime, _ = _contract(candidate)
        expected_url, _, _ = render_http_request(
            expected_base + endpoint,
            HttpRequestTemplate.model_validate(runtime["target"]["request"]),
        )
        if (item["method"] != "GET" or item["authorization"] != "none"
                or item["observed_http_status"] != expected[candidate_id]
                or not item["matches_answer_key"]
                or item["url"] != expected_url
                or not re.fullmatch(r"[0-9a-f]{64}", item.get("response_body_sha256", ""))
                or type(item.get("response_bytes")) is not int or item["response_bytes"] < 0):
            raise ValueError(f"invalid or changed observation for {candidate_id}")
        live_status, live_hash, live_length = live_probe(expected_url)
        if (live_status, live_hash, live_length) != (
            item["observed_http_status"], item["response_body_sha256"], item["response_bytes"]
        ):
            raise ValueError(f"live observation differs from saved report for {candidate_id}")
        result.append((candidate, item))
    return result


def prepare_validation_lab(inventory: Path, answers: Path, observations: Path,
                           output: Path, *,
                           scope_root: Path = DEFAULT_SCOPE_ROOT,
                           live_probe: Callable[[str], tuple[int, str, int]] = fetch_status_and_digest,
                           identity_probe: Callable[[], dict] = verify_runtime_identity,
                           impact_probe: bool = False,
                           impact_marker_probe: Callable[[str], tuple[set[str], str]] = probe_impact_markers) -> dict:
    """Build an isolated Pipeline.db and mapping; existing output is never replaced."""
    cases = _load_inputs(inventory, answers, observations, live_probe, identity_probe)
    if impact_probe:
        selected = next((observation for candidate, observation in cases
                         if candidate["candidate_id"] == IMPACT_CANDIDATE), None)
        if selected is None:
            raise ValueError("impact marker is missing from the pinned local response")
        names, response_sha = impact_marker_probe(selected["url"])
        if (not {"users", "password", "seeded_admin", "seeded_admin_account"} <= names
                or response_sha != selected["response_body_sha256"]):
            raise ValueError("impact marker or response digest changed")
        source_file = ROOT / "result/lab/vuln-bank/database.py"
        if (not source_file.is_file()
                or hashlib.sha256(source_file.read_bytes()).hexdigest() != SEED_SOURCE_SHA256):
            raise ValueError("impact marker seed source changed")
    scopes = {}
    for project, base in BASES.items():
        source = ScopePolicySource.from_path(scope_root / project / "Scope.md")
        if source.approval_digest is None or base + "/" not in source.scope_markdown:
            raise ValueError(f"approved local Scope does not cover {project}")
        scopes[project] = source
    output = Path(output)
    if output.exists():
        raise ValueError(f"fixture output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="validation-lab-", dir=output.parent) as directory:
        bundle = Path(directory) / "bundle"
        bundle.mkdir()
        database = bundle / "Pipeline.db"
        conn = db.init_db(database)
        migrate_live_pipeline_schema(conn)
        policy_by_project = {}
        for project in BASES:
            base = BASES[project]
            policy = TargetPolicy(
                asset_type=AssetType.URL, asset=base,
                allowed_schemes=["http"], allowed_hosts=["127.0.0.1"],
                allowed_ports=[int(base.rsplit(":", 1)[1])],
                allowed_path_prefixes=(
                    ["/api/Users", "/api/Feedbacks/1", "/api/PrivacyRequests", "/api/Complaints"]
                    if project == "juice-shop" else
                    ["/api/billers/by-category", "/api/virtual-cards", "/debug"]
                ),
                allowed_methods=["GET"],
                limits=PolicyLimits(requests_per_second=0.5, concurrency=1,
                                    timeout_seconds=15, max_depth=2, max_requests=100),
                tools=ToolPolicy(), scope_id=(
                    "scope_local_lab_juice_shop" if project == "juice-shop"
                    else "scope_local_lab_vuln_bank"
                ),
                policy_id=f"validation-lab-policy-{project}",
            )
            policy_by_project[project] = policy
        (bundle / "TargetPolicy.json").write_text(json.dumps({
            "policies": [policy.model_dump(mode="json") for policy in policy_by_project.values()]
        }, indent=2) + "\n", encoding="utf-8")
        mapping = {"fixture_kind": "synthetic_attack_claims_for_validation_only",
                   "observation_report_sha256": hashlib.sha256(observations.read_bytes()).hexdigest(),
                   "cases": []}
        endpoint_ids: dict[tuple[str, str], str] = {}
        for project, base in BASES.items():
            scan_id = f"validation-lab-{project}"
            db.insert_scan(conn, scan_id=scan_id, scope_type="test", scope_value="local-validation-lab")
            conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                         (scan_id,))
            ValidationRepository(conn).bind_scope(scan_id, scopes[project], commit=False)
            asset_id = db.insert_asset(conn, scan_id=scan_id, identifier=base, asset_type="URL")
            origin_id = db.upsert_origin(conn, asset_id=asset_id, scheme="http", host="127.0.0.1",
                                         port=int(base.rsplit(":", 1)[1]), base_url=base)
            stage = start_stage_run(conn, scan_id=scan_id, stage="attack",
                                    stage_run_id=f"{scan_id}-attack")
            policy = policy_by_project[project]
            policy_sha = canonical_sha256(policy.model_dump(mode="json"))
            for candidate, observation in cases:
                if candidate["project"] != project:
                    continue
                candidate_id = candidate["candidate_id"]
                short = _digest(candidate_id)[:16]
                task_id = f"lab-task-{short}"
                finding_id, attempt_id = f"lab-finding-{short}", f"lab-attempt-{short}"
                source_id, evidence_id = f"lab-source-{short}", f"lab-evidence-{short}"
                endpoint, parameter, location, runtime, skill = _contract(candidate)
                impact_contract = None
                if impact_probe and candidate_id == IMPACT_CANDIDATE:
                    impact_contract = ImpactDevelopmentRuntimeContract.model_validate({
                        "schema_version": 1,
                        "actions": [{
                            "contract_id": "debug-users-password-field",
                            "path_id": "bounded-impact-confirmation",
                            "endpoint_template": endpoint,
                            "method": "GET",
                            "request": runtime["target"]["request"],
                            "assertions": [{
                                "assertion_id": "password-field-name",
                                "kind": "body_contains",
                                "expected": '"password":',
                            }, {
                                "assertion_id": "seeded-admin-account",
                                "kind": "json_equals",
                                "path": ["users", 0, "account_number"],
                                "expected": "ADMIN001",
                            }],
                            "credential_roles": [],
                            "precondition_observation": {
                                "source_request_id": source_id,
                                "response_sha256": observation["response_body_sha256"],
                                "response_status": observation["observed_http_status"],
                                "marker_json_path": ["users", 0, "account_number"],
                                "marker_assertion_id": "seeded-admin-account",
                                "marker_source": {
                                    "url": "https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/database.py#L255",
                                    "file_sha256": SEED_SOURCE_SHA256,
                                    "line": 255,
                                },
                            },
                        }],
                    })
                    impact_contract = impact_contract_document(impact_contract)
                endpoint_key = (project, endpoint)
                if endpoint_key not in endpoint_ids:
                    endpoint_ids[endpoint_key] = "lab-endpoint-" + _digest(project + endpoint)[:16]
                    conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                                 "VALUES (?,?,?,?)", (endpoint_ids[endpoint_key], origin_id, "GET", endpoint))
                endpoint_id = endpoint_ids[endpoint_key]
                create_task(conn, stage_run_id=stage, skill_name=skill,
                            endpoint_id=endpoint_id, task_id=task_id)
                transition_task(conn, task_id, status="running")
                fingerprint = _digest(candidate_id + observation["url"])
                conn.execute(
                    "INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title,description) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (finding_id, scan_id, endpoint_id, candidate["vuln_class"], "LOW",
                     "Synthetic Validation claim: " + candidate["title"],
                     "Deliberately synthetic Attack claim for an isolated Validation test."),
                )
                # The confirmed Attack attempt is intentionally synthetic. The real GET
                # response code is preserved, including 401/404 for false-positive claims.
                conn.execute(
                    """INSERT INTO attack_attempts
                       (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                        method,url,response_status,response_signature,outcome,finding_id,
                        resolution_reason,resolved_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,'confirmed',?,'synthetic_validation_claim',CURRENT_TIMESTAMP)""",
                    (attempt_id, scan_id, task_id, skill, endpoint_id, fingerprint,
                     "GET", observation["url"], observation["observed_http_status"],
                     observation["response_body_sha256"], finding_id),
                )
                conn.execute(
                    """INSERT INTO attack_http_requests
                       (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,
                        method,url,request_fingerprint,status,response_status,response_bytes,
                        scheduled_at,authorization_source)
                       VALUES (?,?,?,?,?,?,?,?,?,'completed',?,?,0,'scope_safe_method')""",
                    (source_id, scan_id, stage, task_id, policy.policy_id, policy_sha,
                     "GET", observation["url"], fingerprint,
                     observation["observed_http_status"], observation["response_bytes"]),
                )
                conn.execute(
                    """INSERT INTO attack_requests
                       (request_id,finding_id,role,method,url,response_status)
                       VALUES (?,?,?,'GET',?,?)""",
                    (evidence_id, finding_id, "synthetic_claim_source",
                     observation["url"], observation["observed_http_status"]),
                )
                spec = canonical_reproduction_spec(
                    finding_id=finding_id, attack_skill_name=skill,
                    endpoint_id=endpoint_id, method="GET", endpoint_template=endpoint,
                    injection_location=location, parameter_name=parameter,
                    payload_template={parameter: "<slot:string>"},
                    required_identity_roles=[], source_attempt_ids=[attempt_id],
                    source_request_ids=[source_id], source_policy_sha256=policy_sha,
                    runtime_contract=runtime, runtime_contract_sha256=canonical_sha256(runtime),
                )
                conn.execute(
                    """INSERT INTO finding_reproduction_specs
                       (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
                        injection_location,parameter_name,payload_template_json,
                        required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,
                        payload_structure_sha256,source_policy_sha256,runtime_contract_json,
                        runtime_contract_sha256,impact_development_contract_json,
                        impact_development_contract_sha256,spec_sha256)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (finding_id, skill, endpoint_id, "GET", endpoint, location, parameter,
                     json.dumps(spec["payload_template"]), "[]", json.dumps([attempt_id]),
                     json.dumps([source_id]), spec["payload_structure_sha256"], policy_sha,
                     json.dumps(runtime, sort_keys=True), spec["runtime_contract_sha256"],
                     json.dumps(impact_contract, sort_keys=True) if impact_contract else None,
                     canonical_sha256(impact_contract) if impact_contract else None,
                     spec["spec_sha256"]),
                )
                transition_task(conn, task_id, status="completed")
                mapping["cases"].append({"candidate_id": candidate_id, "scan_id": scan_id,
                                         "finding_id": finding_id,
                                         "source_http_status": observation["observed_http_status"]})
                if impact_contract is not None:
                    mapping["impact_lab"] = {"candidate_id": candidate_id,
                                             "scan_id": scan_id, "finding_id": finding_id}
            finish_stage_run(conn, stage)
            chain = start_stage_run(conn, scan_id=scan_id, stage="chaining",
                                    stage_run_id=f"{scan_id}-chaining")
            finish_stage_run(conn, chain, status="skipped")
        conn.commit()
        for case in mapping["cases"]:
            CandidateIntegrityGate(conn).validate_finding(
                case_id="preflight-" + case["finding_id"],
                scan_id=case["scan_id"], finding_id=case["finding_id"],
            )
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("staged Pipeline.db integrity check failed")
        conn.close()
        (bundle / "CandidateFindingMap.json").write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(bundle, output)
    return mapping


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-db", type=Path, default=DEFAULT_ROOT / "CandidateInventory.db")
    parser.add_argument("--answer-db", type=Path, default=DEFAULT_ROOT / "CandidateAnswerKey.db")
    parser.add_argument("--observations", type=Path, default=DEFAULT_ROOT / "LocalControlObservations.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_ROOT / "validation-lab")
    parser.add_argument("--scope-root", type=Path, default=DEFAULT_SCOPE_ROOT)
    parser.add_argument("--impact-probe", action="store_true",
                        help="stage a separate weak-impact /debug/users case")
    args = parser.parse_args()
    result = prepare_validation_lab(args.candidate_db, args.answer_db, args.observations,
                                    args.output, scope_root=args.scope_root,
                                    impact_probe=args.impact_probe)
    print(json.dumps({"output": str(args.output), "staged_cases": len(result["cases"]),
                      "fixture_kind": result["fixture_kind"]}))


if __name__ == "__main__":
    main()
