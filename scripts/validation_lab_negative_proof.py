"""Source-pinned negative proof for the isolated, read-only Validation lab.

This module is deliberately a lab adapter. Ordinary native Validation does not
infer a negative verdict from an HTTP status or from Attack's runtime contract.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from aidast.validation import BlindCase, ReproductionObservation, canonical_sha256
from aidast.validation.contracts.runtime_contract import HttpRequestTemplate, render_http_request
from aidast.validation.execution.http_adapter import HttpReproductionPort

try:
    from scripts.prepare_validation_lab import BASES, ROOT, _contract
    from scripts.probe_validation_controls import verify_runtime_identity
except ModuleNotFoundError:  # Direct `python scripts/run_validation_lab.py`.
    from prepare_validation_lab import BASES, ROOT, _contract
    from probe_validation_controls import verify_runtime_identity


@dataclass(frozen=True)
class LabNegativeProof:
    candidate_id: str
    scan_id: str
    endpoint: str
    attack_skill_name: str
    runtime_sha256: str
    target_url: str
    expected_status: int
    proof_kind: str
    source_sha256: str
    source_line: int
    source_anchor: str


def verify_route_source(source: str, line_number: int, anchor: str,
                        proof_kind: str, route: str) -> bool:
    """Check the literal route/guard at a pinned line, never a loose file match."""
    lines = source.splitlines()
    if not 1 <= line_number <= len(lines):
        return False
    line = lines[line_number - 1].strip()
    if proof_kind == "auth_denial":
        return (line == anchor and
                ("security.isAuthorized()" in line or "security.denyAll()" in line)
                and (f"app.get('{route}'" in line or f"app.use('{route}'" in line))
    if proof_kind == "integer_route":
        if not re.search(r"<int:[A-Za-z_][A-Za-z_0-9]*>", route):
            return False
        expected = f"@app.route('{route}', methods=['GET'])"
        if line != expected:
            return False
        following = lines[line_number:line_number + 80]
        next_route = next((index for index, value in enumerate(following)
                           if value.lstrip().startswith("@app.route(")), len(following))
        return any(anchor in value for value in following[:next_route])
    return False


def is_bounded_negative_response(proof: LabNegativeProof, blind: BlindCase,
                                 observation: ReproductionObservation,
                                 negative_control_hash: str | None,
                                 scan_id: str) -> bool:
    """Accept only a source-verified exact request matching a live inert control."""
    runtime = blind.runtime_contract or {}
    request = runtime.get("target", {}).get("request", {})
    if (scan_id != proof.scan_id or blind.endpoint != proof.endpoint
            or blind.attack_skill_name != proof.attack_skill_name
            or blind.method != "GET" or blind.required_identity_roles
            or blind.credential_references
            or canonical_sha256(runtime) != proof.runtime_sha256
            or request.get("headers") or request.get("json_body")
            or request.get("text_body")
            or observation.outcome != "not_observed"
            or observation.signal_observed is not False
            or observation.details.get("response_status") != proof.expected_status
            or observation.details.get("response_url") != proof.target_url
            or observation.details.get("response_body_sha256") != negative_control_hash
            or negative_control_hash is None):
        return False
    if proof.proof_kind == "auth_denial":
        return (blind.injection_location == "query"
                and not request.get("path_parameters"))
    if proof.proof_kind == "integer_route":
        value = request.get("path_parameters", {}).get(blind.parameter_name)
        return (blind.injection_location == "path" and isinstance(value, str)
                and re.fullmatch(r"[0-9]+", value) is None)
    return False


def load_lab_negative_proofs(
    *, inventory_path: Path, mapping_path: Path, pipeline_path: Path,
    observations_path: Path,
    source_files: Mapping[str, Path] | None = None,
    identity_probe: Callable[[], dict] = verify_runtime_identity,
) -> dict[tuple[str, str], LabNegativeProof]:
    """Build proofs from the candidate inventory and pinned source, not the answer key."""
    if source_files is None:
        source_files = {
            "juice-shop": ROOT / "resources/lab/juice-shop-v20.2.0-server.ts",
            "vuln-bank": ROOT / "result/lab/vuln-bank/app.py",
        }
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    if observations["runtime_identity"] != identity_probe():
        raise ValueError("Validation lab runtime identity changed")
    observed = {item["candidate_id"]: item for item in observations["observations"]}
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if mapping.get("fixture_kind") != "synthetic_attack_claims_for_validation_only":
        raise ValueError("not an isolated Validation lab fixture")
    control_candidates = {
        item["candidate_id"]: item for item in json.loads(
            (ROOT / "resources/lab/validation-control-candidates.json").read_text(encoding="utf-8")
        )
    }
    proofs: dict[tuple[str, str], LabNegativeProof] = {}
    with (sqlite3.connect(inventory_path) as inventory,
          sqlite3.connect(pipeline_path) as pipeline):
        inventory.row_factory = sqlite3.Row
        pipeline.row_factory = sqlite3.Row
        for mapped in mapping["cases"]:
            candidate_id = mapped["candidate_id"]
            definition = control_candidates.get(candidate_id)
            if definition is None or definition["vuln_class"] not in {
                "unauthenticated_disclosure", "sql_injection",
            }:
                continue
            candidate = inventory.execute(
                "SELECT * FROM attack_candidates WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            spec = pipeline.execute(
                "SELECT * FROM finding_reproduction_specs WHERE finding_id=?",
                (mapped["finding_id"],),
            ).fetchone()
            if candidate is None or spec is None or candidate["project"] != definition["project"]:
                raise ValueError(f"missing bounded proof input: {candidate_id}")
            source_path = source_files[candidate["project"]]
            source_bytes = source_path.read_bytes()
            source_sha = hashlib.sha256(source_bytes).hexdigest()
            if source_sha != candidate["source_sha256"]:
                raise ValueError(f"source digest mismatch: {candidate_id}")
            kind = ("auth_denial" if candidate["project"] == "juice-shop"
                    else "integer_route")
            route_line = (candidate["source_line"] if kind == "auth_denial" else
                          int(candidate["route_source_url"].rsplit("#L", 1)[1]))
            if not verify_route_source(
                source_bytes.decode("utf-8"), route_line, definition["anchor"],
                kind, definition["path"],
            ):
                raise ValueError(f"route guard mismatch: {candidate_id}")
            endpoint, _, _, runtime, skill = _contract(dict(candidate))
            runtime_sha = canonical_sha256(runtime)
            if (spec["attack_skill_name"] != skill or
                    spec["runtime_contract_sha256"] != runtime_sha):
                raise ValueError(f"staged runtime mismatch: {candidate_id}")
            target_url, target_headers, target_body = render_http_request(
                BASES[candidate["project"]] + endpoint,
                HttpRequestTemplate.model_validate(runtime["target"]["request"]),
            )
            if target_headers or target_body is not None:
                raise ValueError(f"unexpected target identity or body: {candidate_id}")
            expected_status = 401 if kind == "auth_denial" else 404
            if (observed[candidate_id]["observed_http_status"] != expected_status
                    or observed[candidate_id]["url"] != target_url):
                raise ValueError(f"saved target observation mismatch: {candidate_id}")
            proof = LabNegativeProof(
                candidate_id=candidate_id, scan_id=mapped["scan_id"],
                endpoint=BASES[candidate["project"]] + endpoint,
                attack_skill_name=skill, runtime_sha256=runtime_sha,
                target_url=target_url, expected_status=expected_status,
                proof_kind=kind, source_sha256=source_sha,
                source_line=route_line, source_anchor=(
                    definition["anchor"] if kind == "auth_denial"
                    else f"@app.route('{definition['path']}', methods=['GET'])"
                ),
            )
            key = (proof.scan_id, proof.endpoint)
            if key in proofs:
                raise ValueError("duplicate bounded negative proof endpoint")
            proofs[key] = proof
    if len(proofs) != 6:
        raise ValueError("expected six source-backed negative proof cases")
    return proofs


class LabNegativeProofHttpPort(HttpReproductionPort):
    """Mark explicit negative proof only after source, request and control checks."""

    def __init__(self, proofs: Mapping[tuple[str, str], LabNegativeProof], *,
                 transport=None, credential_resolver=None):
        super().__init__(transport=transport, credential_resolver=credential_resolver)
        self.proofs = dict(proofs)
        self._negative_hashes: dict[tuple[str, str, int], str] = {}

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy):
        observation = super().execute(
            blind_case, attempt_kind=attempt_kind, batch_no=batch_no,
            ordinal=ordinal, attempt_id=attempt_id, db_path=db_path,
            scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            policy=policy,
        )
        proof = self.proofs.get((scan_id, blind_case.endpoint))
        if proof is None:
            return observation
        batch = (stage_run_id, case_id, batch_no)
        if attempt_kind == "negative_control":
            if observation.outcome == "not_observed":
                self._negative_hashes[batch] = observation.details.get("response_body_sha256", "")
            return observation
        if attempt_kind != "target" or not is_bounded_negative_response(
            proof, blind_case, observation, self._negative_hashes.get(batch), scan_id,
        ):
            return observation
        return observation.model_copy(update={
            "explicit_non_exploit": True,
            "details": {**observation.details, "bounded_negative_proof": {
                "candidate_id": proof.candidate_id,
                "proof_kind": proof.proof_kind,
                "source_sha256": proof.source_sha256,
                "source_line": proof.source_line,
                "source_anchor": proof.source_anchor,
                "negative_control_digest": self._negative_hashes[batch],
            }},
        })
