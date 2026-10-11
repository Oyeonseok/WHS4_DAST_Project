"""Isolated authenticated BOLA Validation experiment for the pinned VulnBank lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.recon import db
from aidast.recon.policy import TargetPolicy
from aidast.validation import canonical_reproduction_spec, canonical_sha256
from aidast.validation.contracts.runtime_contract import validate_runtime_contract
from aidast.validation.core.integrity import CandidateIntegrityGate

try:
    from scripts.prepare_validation_lab import BASES, DEFAULT_ROOT, ROOT
    from scripts.probe_validation_controls import verify_runtime_identity
except ModuleNotFoundError:
    from prepare_validation_lab import BASES, DEFAULT_ROOT, ROOT
    from probe_validation_controls import verify_runtime_identity


AUTH_CASES = ("detail", "own_list", "cross_list")
ORDER_A = "VALIDATION-AUTH-20260926-A"
ORDER_B = "VALIDATION-AUTH-20260926-B"
_ROUTES = {
    "detail": "/api/v1/payments/<int:payment_id>",
    "own_list": "/api/v1/payments",
    "cross_list": "/api/v1/payments/merchant_id/<int:merchant_id>",
}
_CASE_IDS = {
    "detail": "vuln-bank:case:GET:/api/v1/payments/<int:payment_id>:bola",
    "own_list": "vuln-bank:case:GET:/api/v1/payments:bola",
    "cross_list": "vuln-bank:curated:GET:/api/v1/payments/merchant_id/<int:merchant_id>:bola",
}
_SOURCE = ROOT / "result/lab/vuln-bank/merchant_payments.py"
_SOURCE_SHA = "fb67c5ff54dd94b1e747444a79fc75ce91b71820ae5aedc8a091625e2fa0064e"
_BASE = BASES["vuln-bank"]


def ensure_fixture(roles: dict[str, dict]) -> None:
    """Create one declined local payment per merchant when absent."""
    verify_runtime_identity()
    if not verify_source_guards(_SOURCE) or hashlib.sha256(_SOURCE.read_bytes()).hexdigest() != _SOURCE_SHA:
        raise ValueError("pinned VulnBank payment source changed")
    for role, order in (("a", ORDER_A), ("b", ORDER_B)):
        merchant = roles[role]
        status, body, _, _ = _fetch("/api/v1/payments", api_key=merchant["key"])
        matches = [item for item in body.get("payments", [])
                   if item.get("merchant_order_id") == order]
        if status != 200 or len(matches) > 1:
            raise ValueError("owned payment fixture is ambiguous")
        if matches:
            continue
        status, body, _, _ = _fetch(
            "/api/v1/payments/charge", api_key=merchant["key"],
            payload={"amount": 1.0, "currency": "USD", "card_number": "0000000000000000",
                     "cvv": "000", "expiry_date": "01/30", "merchant_order_id": order},
        )
        if (status != 400 or body.get("failure_reason") != "invalid_card_number"
                or type(body.get("payment_id")) is not int):
            raise ValueError("declined payment fixture creation failed")
        status, listing, _, _ = _fetch("/api/v1/payments", api_key=merchant["key"])
        created = [item for item in listing.get("payments", [])
                   if item.get("id") == body["payment_id"]]
        if (status != 200 or len(created) != 1
                or created[0].get("merchant_id") != merchant["id"]
                or created[0].get("merchant_order_id") != order
                or created[0].get("payment_status") != "failed"):
            raise ValueError("declined payment fixture ownership check failed")


def control_response_matches(details: dict, expected: dict) -> bool:
    expected_url = _BASE + expected["path"]
    return (
        details.get("response_status") == expected["status"]
        and details.get("response_url") in {
            expected_url, expected_url.split("?", 1)[0]}
        and details.get("response_body_sha256") == expected["sha256"]
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def _fetch(path: str, *, api_key: str | None = None,
           payload: dict | None = None) -> tuple[int, dict, str, int]:
    if not path.startswith("/api/v1/"):
        raise ValueError("auth lab permits only local API paths")
    if payload is not None and path not in {
        "/api/v1/merchants/login", "/api/v1/payments/charge",
    }:
        raise ValueError("auth lab permits POST only for login or declined fixture setup")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if api_key is not None:
        headers["X-Merchant-Api-Key"] = api_key
    request = Request(_BASE + path, headers=headers,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      method="POST" if payload is not None else "GET")
    opener = build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(200_001)
        status = response.status
    if len(body) > 200_000:
        raise ValueError("auth lab response exceeded bounded size")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("auth lab response was not a JSON object")
    return status, document, hashlib.sha256(body).hexdigest(), len(body)


def _roles() -> dict[str, dict]:
    verify_runtime_identity()
    accounts = {
        "a": ("bookstore@vulnbank.org", "bookstore123"),
        "b": ("pwnshop@vulnbank.org", "pwnshop123"),
    }
    roles = {}
    for role, (email, password) in accounts.items():
        status, document, _, _ = _fetch(
            "/api/v1/merchants/login", payload={"email": email, "password": password})
        if status != 200 or document.get("status") != "success":
            raise ValueError("seeded merchant login failed")
        roles[role] = {"id": document["merchant"]["id"], "key": document["api_key"]}
        status, me, _, _ = _fetch("/api/v1/merchants/me", api_key=roles[role]["key"])
        if status != 200 or me.get("merchant", {}).get("id") != roles[role]["id"]:
            raise ValueError("merchant session identity mismatch")
    if roles["a"]["id"] == roles["b"]["id"]:
        raise ValueError("auth lab requires distinct merchants")
    return roles


def observe_fixture(roles: dict[str, dict]) -> dict:
    """Check both owners and all three routes without exposing response bodies."""
    if not verify_source_guards(_SOURCE) or hashlib.sha256(_SOURCE.read_bytes()).hexdigest() != _SOURCE_SHA:
        raise ValueError("pinned VulnBank payment source changed")
    lists = {}
    for role, order in (("a", ORDER_A), ("b", ORDER_B)):
        status, body, _, _ = _fetch("/api/v1/payments", api_key=roles[role]["key"])
        matches = [item for item in body.get("payments", [])
                   if item.get("merchant_order_id") == order]
        if status != 200 or len(matches) != 1 or matches[0].get("merchant_id") != roles[role]["id"]:
            raise ValueError("owned fixture payment is unavailable")
        if body["payments"][0].get("merchant_order_id") != order:
            raise ValueError("owned fixture must be first for bounded JSON assertion")
        lists[role] = matches[0]["id"]
    a, b = roles["a"], roles["b"]
    if lists["a"] == lists["b"]:
        raise ValueError("fixture payments must differ")
    status, body, b_sha, _ = _fetch(f"/api/v1/payments/{lists['b']}", api_key=b["key"])
    if (status != 200 or body.get("payment", {}).get("merchant_id") != b["id"]
            or body.get("payment", {}).get("id") != lists["b"]):
        raise ValueError("B ownership detail control failed")
    observed = {"a_id": a["id"], "b_id": b["id"],
                "a_payment": lists["a"], "b_payment": lists["b"],
                "b_ownership_sha256": b_sha, "targets": {}}
    paths = {
        "detail": f"/api/v1/payments/{lists['b']}",
        "own_list": "/api/v1/payments",
        "cross_list": f"/api/v1/payments/merchant_id/{b['id']}",
    }
    for case, path in paths.items():
        status, body, digest, size = _fetch(path, api_key=a["key"])
        if case == "detail":
            valid = status == 404 and body.get("status") == "error"
        elif case == "own_list":
            valid = status == 200 and all(item.get("merchant_id") == a["id"]
                                          for item in body.get("payments", []))
        else:
            valid = (status == 200 and body.get("merchant_id") == b["id"]
                     and any(item.get("id") == lists["b"] for item in body.get("payments", [])))
        if not valid:
            raise ValueError(f"auth lab ownership expectation failed: {case}")
        observed["targets"][case] = {"path": path, "status": status,
                                     "sha256": digest, "bytes": size}
    controls = {
        "detail": {
            "positive_control": f"/api/v1/payments/{lists['a']}",
            "negative_control": "/api/v1/payments/999999",
        },
        "own_list": {
            "positive_control": "/api/v1/payments",
            "negative_control": "/api/v1/payments?probe=inert",
        },
        "cross_list": {
            "positive_control": f"/api/v1/payments/merchant_id/{a['id']}",
            "negative_control": "/api/v1/payments/merchant_id/999999",
        },
    }
    observed["controls"] = {}
    for case, pair in controls.items():
        observed["controls"][case] = {}
        for kind, path in pair.items():
            status, body, digest, size = _fetch(path, api_key=a["key"])
            if case == "detail":
                valid = (status == 200 and body.get("payment", {}).get("id") == lists["a"]
                         and body.get("payment", {}).get("merchant_id") == a["id"])
                if kind == "negative_control":
                    valid = status == 404 and body.get("status") == "error"
            elif kind == "positive_control":
                valid = (status == 200 and any(
                    item.get("id") == lists["a"] and item.get("merchant_id") == a["id"]
                    for item in body.get("payments", [])))
            elif case == "own_list":
                valid = (status == 200 and all(item.get("merchant_id") == a["id"]
                                                 for item in body.get("payments", [])))
            else:
                valid = status == 200 and body.get("payments") == []
            if not valid:
                raise ValueError(f"auth lab control failed: {case}/{kind}")
            observed["controls"][case][kind] = {
                "path": path, "status": status, "sha256": digest, "bytes": size,
            }
    return observed


def auth_contract(case: str, *, a_id: int, b_id: int,
                  a_payment: int, b_payment: int):
    if case not in AUTH_CASES or min(a_id, b_id, a_payment, b_payment) < 1 or a_id == b_id:
        raise ValueError("invalid authenticated lab identities or case")
    if case == "detail":
        endpoint = "/api/v1/payments/{payment_id}"
        target = {"path_parameters": {"payment_id": b_payment}}
        positive = {"path_parameters": {"payment_id": a_payment}}
        negative = {"path_parameters": {"payment_id": 999999}}
        marker = {"kind": "json_equals", "path": ["payment", "id"], "expected": b_payment}
        own_marker = {"kind": "json_equals", "path": ["payment", "id"], "expected": a_payment}
    elif case == "own_list":
        endpoint = "/api/v1/payments"
        target = {}
        positive = {}
        negative = {"query_parameters": {"probe": "inert"}}
        marker = {"kind": "json_equals", "path": ["payments", 0, "merchant_order_id"],
                  "expected": ORDER_B}
        own_marker = {"kind": "json_equals", "path": ["payments", 0, "merchant_order_id"],
                      "expected": ORDER_A}
    else:
        endpoint = "/api/v1/payments/merchant_id/{merchant_id}"
        target = {"path_parameters": {"merchant_id": b_id}}
        positive = {"path_parameters": {"merchant_id": a_id}}
        negative = {"path_parameters": {"merchant_id": 999999}}
        marker = {"kind": "json_equals", "path": ["payments", 0, "merchant_order_id"],
                  "expected": ORDER_B}
        own_marker = {"kind": "json_equals", "path": ["payments", 0, "merchant_order_id"],
                      "expected": ORDER_A}
    runtime = validate_runtime_contract({
        "schema_version": 1,
        "target": {"request": target, "assertions": [{"assertion_id": "foreign-object", **marker}]},
        "positive_control": {"request": positive,
                             "assertions": [{"assertion_id": "owned-object", **own_marker}]},
        "negative_control": {"request": negative,
                             "assertions": [{"assertion_id": "foreign-object", **marker}]},
    }).model_dump(mode="json")
    return endpoint, runtime


def verify_source_guards(source):
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    if not isinstance(text, str):
        return False
    for case, route in _ROUTES.items():
        anchor = f"@app.route('{route}', methods=['GET'])"
        if text.count(anchor) != 1:
            return False
        block = text.split(anchor, 1)[1].split("@app.route(", 1)[0]
        if "@merchant_required" not in block:
            return False
        guard = ("AND mp.merchant_id = {current_merchant['id']}" if case == "detail"
                 else "WHERE mp.merchant_id = {current_merchant['id']}" if case == "own_list"
                 else "WHERE mp.merchant_id = {merchant_id}")
        if guard not in block:
            return False
    return True


def stage_auth_cases(base_bundle: Path, output: Path, observed: dict,
                     inventory_path: Path = DEFAULT_ROOT / "CandidateInventory.db") -> dict:
    """Clone a completed seven-case fixture and add only the three auth claims."""
    if output.exists():
        raise ValueError("auth lab output already exists")
    if not (base_bundle / "Pipeline.db").is_file():
        raise ValueError("base Validation bundle is missing")
    shutil.copytree(base_bundle, output)
    mapping_path = output / "CandidateFindingMap.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if mapping.get("fixture_kind") != "synthetic_attack_claims_for_validation_only" or mapping.get("auth_lab"):
        raise ValueError("base bundle is not the isolated seven-case fixture")
    with sqlite3.connect(inventory_path) as inventory:
        inventory.row_factory = sqlite3.Row
        rows = {}
        for case, candidate_id in _CASE_IDS.items():
            candidate = inventory.execute(
                "SELECT * FROM attack_candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if candidate is None or candidate["project"] != "vuln-bank":
                raise ValueError("official BOLA candidate missing")
            rows[case] = dict(candidate)
    for case in ("detail", "own_list"):
        if rows[case]["source_sha256"] != _SOURCE_SHA:
            raise ValueError("candidate does not match pinned payment source")
    policy_path = output / "TargetPolicy.json"
    policy_doc = json.loads(policy_path.read_text(encoding="utf-8"))
    for index, item in enumerate(policy_doc["policies"]):
        if item["policy_id"] != "validation-lab-policy-vuln-bank":
            continue
        item["allowed_path_prefixes"] = sorted(set(item["allowed_path_prefixes"]) | {
            "/api/v1/payments"})
        policy_doc["policies"][index] = TargetPolicy.model_validate(item).model_dump(mode="json")
        policy = TargetPolicy.model_validate(policy_doc["policies"][index])
        break
    else:
        raise ValueError("VulnBank local TargetPolicy missing")
    policy_path.write_text(json.dumps(policy_doc, indent=2) + "\n", encoding="utf-8")
    policy_sha = canonical_sha256(policy.model_dump(mode="json"))
    scan_id = "validation-lab-vuln-bank"
    with sqlite3.connect(output / "Pipeline.db") as conn:
        origin = conn.execute(
            """SELECT o.origin_id FROM origins o JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND o.base_url=?""", (scan_id, _BASE)
        ).fetchone()
        if origin is None:
            raise ValueError("VulnBank scan origin missing")
        stage = start_stage_run(conn, scan_id=scan_id, stage="attack",
                                stage_run_id="validation-lab-vuln-bank-auth-attack")
        conn.execute(
            """INSERT INTO credential_references
               (credential_reference_id,scan_id,label,reference_uri,identity_role)
               VALUES (?,?,?,?,?)""",
            ("validation-auth-merchant-a", scan_id, "validation merchant A",
             "keyring://aidast-validation-auth/merchant-a", "merchant_a"),
        )
        auth_mapping = []
        for case in AUTH_CASES:
            candidate = rows[case]
            candidate_id = _CASE_IDS[case]
            short = hashlib.sha256(candidate_id.encode()).hexdigest()[:16]
            endpoint, runtime = auth_contract(case, **{
                name: observed[name] for name in ("a_id", "b_id", "a_payment", "b_payment")})
            parameter = "probe" if case == "own_list" else (
                "payment_id" if case == "detail" else "merchant_id")
            location = "query" if case == "own_list" else "path"
            finding_id, attempt_id = f"auth-finding-{short}", f"auth-attempt-{short}"
            task_id, source_id = f"auth-task-{short}", f"auth-source-{short}"
            evidence_id, endpoint_id = f"auth-evidence-{short}", f"auth-endpoint-{short}"
            target = observed["targets"][case]
            url = _BASE + target["path"]
            fingerprint = hashlib.sha256((candidate_id + url).encode()).hexdigest()
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                         "VALUES (?,?,?,?)", (endpoint_id, origin[0], "GET", endpoint))
            create_task(conn, stage_run_id=stage, skill_name="hunt-idor",
                        endpoint_id=endpoint_id, task_id=task_id)
            transition_task(conn, task_id, status="running")
            conn.execute(
                """INSERT INTO findings
                   (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                   VALUES (?,?,?,?,?,?,?)""",
                (finding_id, scan_id, endpoint_id, "bola", "LOW",
                 "Synthetic Validation claim: " + candidate["title"],
                 "Deliberately synthetic Attack claim for an authenticated BOLA lab test."),
            )
            conn.execute(
                """INSERT INTO attack_attempts
                   (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                    method,url,response_status,response_signature,outcome,finding_id,
                    resolution_reason,resolved_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'confirmed',?,'synthetic_validation_claim',CURRENT_TIMESTAMP)""",
                (attempt_id, scan_id, task_id, "hunt-idor", endpoint_id, fingerprint,
                 "GET", url, target["status"], target["sha256"], finding_id),
            )
            conn.execute(
                """INSERT INTO attack_http_requests
                   (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,
                    method,url,request_fingerprint,status,response_status,response_bytes,
                    scheduled_at,authorization_source)
                   VALUES (?,?,?,?,?,?,?,?,?,'completed',?,?,0,'scope_safe_method')""",
                (source_id, scan_id, stage, task_id, policy.policy_id, policy_sha,
                 "GET", url, fingerprint, target["status"], target["bytes"]),
            )
            conn.execute(
                """INSERT INTO attack_requests
                   (request_id,finding_id,role,method,url,response_status)
                   VALUES (?,?,?,'GET',?,?)""",
                (evidence_id, finding_id, "synthetic_claim_source", url, target["status"]),
            )
            spec = canonical_reproduction_spec(
                finding_id=finding_id, attack_skill_name="hunt-idor",
                endpoint_id=endpoint_id, method="GET", endpoint_template=endpoint,
                injection_location=location, parameter_name=parameter,
                payload_template={parameter: "<slot:string>"},
                required_identity_roles=["merchant_a"], source_attempt_ids=[attempt_id],
                source_request_ids=[source_id], source_policy_sha256=policy_sha,
                runtime_contract=runtime, runtime_contract_sha256=canonical_sha256(runtime),
            )
            conn.execute(
                """INSERT INTO finding_reproduction_specs
                   (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
                    injection_location,parameter_name,payload_template_json,
                    required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,
                    payload_structure_sha256,source_policy_sha256,runtime_contract_json,
                    runtime_contract_sha256,spec_sha256)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding_id, "hunt-idor", endpoint_id, "GET", endpoint, location,
                 parameter, json.dumps(spec["payload_template"]), json.dumps(["merchant_a"]),
                 json.dumps([attempt_id]), json.dumps([source_id]),
                 spec["payload_structure_sha256"], policy_sha,
                 json.dumps(runtime, sort_keys=True), spec["runtime_contract_sha256"],
                 spec["spec_sha256"]),
            )
            transition_task(conn, task_id, status="completed")
            mapped = {"candidate_id": candidate_id, "scan_id": scan_id,
                      "finding_id": finding_id, "source_http_status": target["status"]}
            mapping["cases"].append(mapped)
            auth_mapping.append(mapped)
        finish_stage_run(conn, stage)
        conn.commit()
        for item in auth_mapping:
            CandidateIntegrityGate(conn).validate_finding(
                case_id="preflight-" + item["finding_id"],
                scan_id=item["scan_id"], finding_id=item["finding_id"])
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("auth lab Pipeline.db integrity check failed")
    mapping["auth_lab"] = auth_mapping
    mapping_path.write_text(json.dumps(mapping, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
    (output / "AuthFixture.json").write_text(json.dumps(observed, indent=2) + "\n",
                                               encoding="utf-8")
    return mapping


def run_auth_cases(bundle: Path) -> list[dict]:
    """Run real Validation agents; keep merchant API keys only in process memory."""
    from aidast.validation import NativePrerequisiteResolver, ValidationCoordinator
    from aidast.validation.core.policy import TargetPolicyProvider
    from aidast.validation.execution.credentials import PipelineCredentialResolver
    from aidast.validation.execution.native_impact import NativeImpactDevelopmentPort
    try:
        from scripts.validation_lab_negative_proof import (
            LabNegativeProofHttpPort, load_lab_negative_proofs,
        )
    except ModuleNotFoundError:
        from validation_lab_negative_proof import (
            LabNegativeProofHttpPort, load_lab_negative_proofs,
        )

    mapping_path = bundle / "CandidateFindingMap.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    auth_cases = mapping.get("auth_lab")
    if (not isinstance(auth_cases, list) or len(auth_cases) != len(AUTH_CASES)
            or any(not isinstance(x, dict) for x in auth_cases)
            or {x.get("candidate_id") for x in auth_cases} != set(_CASE_IDS.values())):
        raise ValueError("bundle does not contain exactly three auth candidates")
    saved = json.loads((bundle / "AuthFixture.json").read_text(encoding="utf-8"))
    roles = _roles()
    live = observe_fixture(roles)
    if live != saved:
        raise ValueError("auth fixture changed since staging")
    policy_provider = TargetPolicyProvider(bundle / "TargetPolicy.json")
    def auth_backend(uri: str) -> dict[str, str]:
        if uri != "keyring://aidast-validation-auth/merchant-a":
            raise ValueError("unexpected auth lab credential reference")
        return {"X-Merchant-Api-Key": roles["a"]["key"]}

    resolver = PipelineCredentialResolver(
        bundle / "Pipeline.db", backends={"keyring": auth_backend})
    proofs = load_lab_negative_proofs(
        inventory_path=DEFAULT_ROOT / "CandidateInventory.db",
        mapping_path=mapping_path, pipeline_path=bundle / "Pipeline.db",
        observations_path=DEFAULT_ROOT / "LocalControlObservations.json",
    )

    class AuthProofPort(LabNegativeProofHttpPort):
        def __init__(self):
            super().__init__(proofs, credential_resolver=resolver)
            self.controls = {}

        def execute(self, blind_case, *, attempt_kind, batch_no, ordinal,
                    attempt_id, db_path, scan_id, stage_run_id, case_id, policy):
            observation = super().execute(
                blind_case, attempt_kind=attempt_kind, batch_no=batch_no,
                ordinal=ordinal, attempt_id=attempt_id, db_path=db_path,
                scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
                policy=policy,
            )
            case = next((name for name in AUTH_CASES
                         if blind_case.endpoint == _BASE + auth_contract(
                             name, **{key: saved[key] for key in (
                                 "a_id", "b_id", "a_payment", "b_payment")})[0]), None)
            if case not in {"detail", "own_list"}:
                return observation
            _, expected_runtime = auth_contract(
                case, **{key: saved[key] for key in (
                    "a_id", "b_id", "a_payment", "b_payment")})
            if (scan_id != "validation-lab-vuln-bank"
                    or blind_case.attack_skill_name != "hunt-idor"
                    or blind_case.required_identity_roles != ("merchant_a",)
                    or canonical_sha256(blind_case.runtime_contract) != canonical_sha256(expected_runtime)):
                return observation
            key = (stage_run_id, case_id, batch_no)
            if attempt_kind in {"positive_control", "negative_control"}:
                expected = saved["controls"][case][attempt_kind]
                if control_response_matches(observation.details, expected):
                    self.controls.setdefault(key, {})[attempt_kind] = (
                        observation.outcome, observation.signal_observed)
                return observation
            if attempt_kind != "target" or self.controls.get(key) != {
                "positive_control": ("observed", True),
                "negative_control": ("not_observed", False),
            }:
                return observation
            expected = saved["targets"][case]
            if (observation.outcome != "not_observed" or observation.signal_observed is not False
                    or observation.details.get("response_status") != expected["status"]
                    or observation.details.get("response_url") != _BASE + expected["path"]
                    or observation.details.get("response_body_sha256") != expected["sha256"]):
                return observation
            return observation.model_copy(update={
                "explicit_non_exploit": True,
                "details": {**observation.details, "auth_negative_proof": {
                    "case": case, "source_sha256": _SOURCE_SHA,
                    "merchant_a_id": saved["a_id"], "merchant_b_id": saved["b_id"],
                    "merchant_b_payment_id": saved["b_payment"],
                    "merchant_b_ownership_sha256": saved["b_ownership_sha256"],
                    "target_sha256": expected["sha256"],
                }},
            })

    coordinator = ValidationCoordinator(
        db_path=bundle / "Pipeline.db", agent=None, reproduction=AuthProofPort(),
        policy_provider=policy_provider,
        prerequisite_resolver=NativePrerequisiteResolver(
            credential_resolver=resolver, policy_provider=policy_provider),
        impact_development_port=NativeImpactDevelopmentPort(
            credential_resolver=resolver, policy_provider=policy_provider),
    )
    results = []
    for item in auth_cases:
        result = coordinator.run(item["scan_id"], finding_id=item["finding_id"])
        results.append({"candidate_id": item["candidate_id"],
                        "finding_id": item["finding_id"],
                        "stage_run_id": result.stage_run_id,
                        "statuses": result.summary["statuses"]})
    return results


def score_auth_cases(bundle: Path, *, live_check: bool = True) -> dict:
    """Score persisted Agent decisions against the separate official answer DB."""
    from aidast.validation.core.decision import evaluate_impact
    from aidast.validation.execution.request_broker import _safe_url

    mapping = json.loads((bundle / "CandidateFindingMap.json").read_text(encoding="utf-8"))
    mapped = {item["candidate_id"]: item for item in mapping.get("auth_lab", [])}
    if set(mapped) != set(_CASE_IDS.values()):
        raise ValueError("auth case mapping is incomplete")
    saved = json.loads((bundle / "AuthFixture.json").read_text(encoding="utf-8"))
    if live_check and observe_fixture(_roles()) != saved:
        raise ValueError("live auth fixture no longer matches staged observations")
    inventory = DEFAULT_ROOT / "CandidateInventory.db"
    with sqlite3.connect(DEFAULT_ROOT / "CandidateAnswerKey.db") as answers:
        bound = answers.execute("SELECT value FROM answer_metadata WHERE key='inventory_sha256'").fetchone()
        if bound is None or bound[0] != hashlib.sha256(inventory.read_bytes()).hexdigest():
            raise ValueError("official answer DB is not bound to candidate inventory")
        expected = dict(answers.execute(
            "SELECT candidate_id,target_validation_status FROM answer_key WHERE readiness='NEEDS_TWO_MERCHANT_IDENTITIES'"
        ).fetchall())
    if set(expected) != set(mapped):
        raise ValueError("auth mapping does not match official prerequisite candidates")
    rows = []
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        for case in AUTH_CASES:
            candidate_id = _CASE_IDS[case]
            item = mapped[candidate_id]
            stored = conn.execute(
                """SELECT * FROM validation_cases WHERE scan_id=? AND finding_id=?""",
                (item["scan_id"], item["finding_id"]),
            ).fetchone()
            if stored is None:
                rows.append({"candidate_id": candidate_id, "result": "PENDING"})
                continue
            actual = stored["current_status"]
            verdict = ("PASS" if actual == expected[candidate_id]
                       else "WRONG_VERDICT" if actual in {"CONFIRMED", "DISPROVEN"}
                       else "UNRESOLVED")
            supported = False
            attempts = conn.execute(
                """SELECT attempt_id,attempt_kind,ordinal,outcome,signal_observed,
                          observation_json,finished_at FROM validation_attempts
                   WHERE case_id=? AND stage_run_id=?""",
                (stored["case_id"], stored["decision_stage_run_id"]),
            ).fetchall()
            try:
                decision = json.loads(stored["decision_json"])
                citations = set(decision["evidence_ids"])
                observed = {(row["attempt_kind"], row["ordinal"]): row for row in attempts}
                required = {("positive_control", 1), ("negative_control", 1)} | {
                    ("target", ordinal) for ordinal in (1, 2, 3)}
                evidence_by_attempt = {}
                for key, row in observed.items():
                    evidence_by_attempt[key] = [e for e in conn.execute(
                        """SELECT evidence_id,content_sha256 FROM validation_evidence
                           WHERE case_id=? AND stage_run_id=? AND attempt_id=?
                             AND evidence_kind='observation'""",
                        (stored["case_id"], stored["decision_stage_run_id"], row["attempt_id"]),
                    ) if e["evidence_id"] in citations]
                evidence_ok = all(
                    observed[key]["finished_at"] is not None
                    and len(evidence_by_attempt[key]) == 1
                    for key in required
                )
                def attempt_matches(key, expected_response, outcome, signal):
                    row = observed[key]
                    proof = json.loads(row["observation_json"])
                    ids = proof.get("request_ids")
                    if not isinstance(ids, list) or len(ids) != 1:
                        return False
                    ledger = conn.execute(
                        """SELECT method,url,status,response_status,
                                  dispatched_at,finished_at FROM validation_http_requests
                           WHERE request_id=? AND scan_id=? AND stage_run_id=?
                             AND case_id=? AND attempt_id=?""",
                        (ids[0], item["scan_id"], stored["decision_stage_run_id"],
                         stored["case_id"], row["attempt_id"]),
                    ).fetchone()
                    expected_url = _BASE + expected_response["path"]
                    return (
                        row["outcome"] == outcome
                        and row["signal_observed"] == int(signal)
                        and proof.get("response_status") == expected_response["status"]
                        and proof.get("response_url") == expected_url.split("?", 1)[0]
                        and proof.get("response_bytes") == expected_response["bytes"]
                        and proof.get("validation_runtime", {}).get("policy_allowed") is True
                        and len(evidence_by_attempt[key]) == 1
                        and evidence_by_attempt[key][0]["content_sha256"] == expected_response["sha256"]
                        and ledger is not None
                        and ledger["method"] == "GET"
                        and ledger["url"] == _safe_url(expected_url)
                        and ledger["status"] == "completed"
                        and ledger["response_status"] == expected_response["status"]
                        and ledger["dispatched_at"] is not None
                        and ledger["finished_at"] is not None
                    )

                controls_ok = (
                    attempt_matches(("positive_control", 1),
                                    saved["controls"][case]["positive_control"], "observed", True)
                    and attempt_matches(("negative_control", 1),
                                        saved["controls"][case]["negative_control"],
                                        "not_observed", False)
                )
                target = saved["targets"][case]
                target_is_positive = case == "cross_list"
                targets_ok = all(
                    attempt_matches(("target", ordinal), target,
                                    "observed" if target_is_positive else "not_observed",
                                    target_is_positive)
                    for ordinal in (1, 2, 3)
                )
                if not target_is_positive:
                    for ordinal in (1, 2, 3):
                        proof = json.loads(observed[("target", ordinal)]["observation_json"])
                        auth_proof = proof.get("auth_negative_proof", {})
                        targets_ok &= (
                            proof.get("validation_runtime", {}).get("explicit_non_exploit") is True
                            and auth_proof.get("merchant_b_ownership_sha256") == saved["b_ownership_sha256"]
                            and auth_proof.get("source_sha256") == _SOURCE_SHA
                            and auth_proof.get("target_sha256") == target["sha256"]
                        )
                impact_ok = (case != "cross_list" or not evaluate_impact(
                    stored["impact_boundary"], stored["impact_sensitivity"],
                    stored["impact_actor_requirements"]).underpowered)
                supported = (canonical_sha256(decision) == stored["decision_sha256"]
                             and required <= set(observed) and len(attempts) == 5
                             and evidence_ok and controls_ok and targets_ok and impact_ok)
            except (IndexError, KeyError, TypeError, ValueError, sqlite3.Error):
                supported = False
            rows.append({"candidate_id": candidate_id,
                         "target_validation_status": expected[candidate_id],
                         "actual_validation_status": actual,
                         "result": verdict if supported else "UNSUPPORTED_EVIDENCE",
                         "evidence_supported": supported,
                         "attempt_count": len(attempts)})
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    return {"rows": rows, "counts": {status: sum(row["result"] == status for row in rows)
                                      for status in {row["result"] for row in rows}},
            "database_integrity": integrity}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--base", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("bundle", type=Path)
    score = sub.add_parser("score")
    score.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        roles = _roles()
        ensure_fixture(roles)
        observed = observe_fixture(roles)
        mapping = stage_auth_cases(args.base, args.output, observed)
        print(json.dumps({"bundle": str(args.output), "auth_cases": len(mapping["auth_lab"])}))
    elif args.command == "run":
        print(json.dumps({"results": run_auth_cases(args.bundle)}, ensure_ascii=False))
    else:
        print(json.dumps(score_auth_cases(args.bundle), ensure_ascii=False))


if __name__ == "__main__":
    main()
