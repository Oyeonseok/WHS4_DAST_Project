"""Build a source-backed candidate inventory for the two local training apps.

This database is deliberately separate from Attack.db: an upstream challenge or
source comment is a lead, not a performed Attack attempt or a Validation finding.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import yaml


JUICE_VERSION = "v20.2.0"
JUICE_IMAGE_DIGEST = "sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
JUICE_SHA256 = "8efa070380ab8f39783eb92cbaaf9df67bcee0f1715eee98a06fb1176051c2b7"
JUICE_SERVER_SHA256 = "1774fac7f05f9f78fad0b4f82a10eaf0d2ef5b2522ddbe75133e65e423c0a90b"
VULN_BANK_COMMIT = "5e5ea5425fcf309373a0655dd111ecfb45037cbf"
VULN_BANK_FILE_SHA256 = {
    "README.md": "224774baba70c371b939434167098e1431ecf39aa38b0bb903ccb174c545ed88",
    "app.py": "b17c2b597d119dc433922719446afde3aae474b13035cf413fd4e732a68f5be6",
    "auth.py": "07041ed39dbd26370234ee73702b405d2d7da78bc19ee69207f9d168f779b70d",
    "merchant_payments.py": "fb67c5ff54dd94b1e747444a79fc75ce91b71820ae5aedc8a091625e2fa0064e",
    "transaction_graphql.py": "19245273eade5f394b9e5e9fd1ddebedf156fcfeeb29fa532d105d08e1d3101f",
}
JUICE_URL = f"https://github.com/juice-shop/juice-shop/blob/{JUICE_VERSION}/data/static/challenges.yml"
BANK_URL = f"https://github.com/Commando-X/vuln-bank/blob/{VULN_BANK_COMMIT}/"
ROOT = Path(__file__).resolve().parents[1]


VULN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in (
        ("sql_injection", r"sql\s+injection|sql\s+inject"),
        ("bola", r"\bBOLA\b|\bIDOR\b|no (?:additional )?authorization check|no verification if .* belongs"),
        ("mass_assignment", r"mass assignment|no whitelist of allowed fields|direct field name injection"),
        ("xss", r"\bXSS\b|cross.site scripting"),
        ("ssrf", r"\bSSRF\b|server.side request forgery"),
        ("information_disclosure", r"information disclosure|debug information|debug info|detailed error|query exposure|path disclosure|system information exposure"),
        ("excessive_data_exposure", r"excessive data exposure|sensitive data exposure|exposed sensitive data|exposing account number"),
        ("weak_jwt", r"weak JWT|weak secret key|no token expiration|accepts any algorithm"),
        ("weak_password_reset", r"weak reset pin|guessable pin|predictable pin"),
        ("race_condition", r"race condition|no transaction atomicity|transaction locking"),
        ("csrf", r"\bCSRF\b|cross.site request forgery"),
        ("unrestricted_file_upload", r"no file type validation|no content.type validation|no file size check"),
        ("path_traversal", r"path traversal|directory traversal|user.controlled filename"),
        ("missing_rate_limit", r"no rate limiting|no rate limit"),
        ("negative_amount", r"negative amount|negative transfer"),
        ("input_validation", r"no input validation|no amount validation|no validation on (?:card limit|recipient|account|payment method)"),
        ("weak_password_policy", r"no password complexity|no password history"),
        ("predictable_identifier", r"predictable (?:card|cvv|reference|authorization code)"),
        ("missing_idempotency", r"no idempotency|replay protection"),
        ("plaintext_secret", r"plaintext password|plaintext storage|api keys? returned"),
        ("prompt_injection", r"prompt injection|role override|context injection"),
    )
)

# At this pinned commit these comments describe SQL built only from Flask's
# <int:...> converter values. The adjacent BOLA claims remain in the inventory.
EXCLUDED_SOURCE_CLAIMS = {
    ("/api/billers/by-category/<int:category_id>", "GET", "sql_injection"),
    ("/api/virtual-cards/<int:card_id>/transactions", "GET", "sql_injection"),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def juice_candidates(source: Path) -> list[dict]:
    raw = source.read_bytes()
    records = yaml.safe_load(raw)
    if not isinstance(records, list):
        raise ValueError("Juice Shop source must be a challenge list")
    key_lines = {}
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        match = re.match(r"\s*(?:-\s*)?key:\s*['\"]?([A-Za-z0-9_]+)", line)
        if match:
            key_lines[match.group(1)] = line_number
    seen: set[str] = set()
    result = []
    for item in records:
        if not isinstance(item, dict) or any(not isinstance(item.get(key), str) or not item[key]
                                              for key in ("key", "name", "category", "description")):
            raise ValueError("invalid official Juice Shop challenge")
        key = item["key"]
        if key in seen:
            raise ValueError(f"duplicate Juice Shop challenge key: {key}")
        seen.add(key)
        if key not in key_lines:
            raise ValueError(f"challenge key lacks source line: {key}")
        disabled = "Docker" in (item.get("disabledEnv") or [])
        manual_only = item["category"] == "Miscellaneous"
        category = re.sub(r"[^a-z0-9]+", "_", item["category"].lower()).strip("_")
        line = key_lines[key]
        result.append({
            "candidate_id": f"juice-shop:{key}", "project": "juice-shop",
            "external_id": key, "title": item["name"], "vuln_class": category,
            "description": item["description"], "endpoint_template": None, "method": None,
            "source_url": f"{JUICE_URL}#L{line}", "source_path": "data/static/challenges.yml",
            "route_source_url": None,
            "source_line": line, "source_sha256": _sha(raw), "source_version": JUICE_VERSION,
            "claim_basis": "official_challenge", "readiness": "needs_route_mapping",
            "availability": "disabled_in_docker" if disabled else "enabled_in_docker",
            "evaluation_status": "OUT_OF_TEST_SCOPE" if disabled else (
                "MANUAL_ONLY" if manual_only else "UNASSESSED"
            ),
            "metadata_json": _json({
                "difficulty": item.get("difficulty"), "tags": item.get("tags") or [],
                "disabled_env": item.get("disabledEnv") or [],
            }),
        })
    return result


def _route_definitions(text: str) -> list[tuple[str, str, int, int, bool, int]]:
    tree = ast.parse(text)
    routes = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr != "route" or not decorator.args:
                continue
            try:
                path = ast.literal_eval(decorator.args[0])
                methods = next((ast.literal_eval(kw.value) for kw in decorator.keywords
                                if kw.arg == "methods"), ["GET"])
            except (ValueError, TypeError, SyntaxError):
                continue
            if not isinstance(path, str) or not isinstance(methods, (list, tuple)):
                continue
            # The mixed GET/POST routes render forms on GET and process input on POST.
            selected = ["POST"] if set(methods) == {"GET", "POST"} else methods
            rate_limited = any(isinstance(item, ast.Name) and item.id == "ai_rate_limit"
                               for item in node.decorator_list)
            routes.extend((path, method, node.lineno, node.end_lineno or node.lineno,
                           rate_limited, decorator.lineno)
                          for method in selected if isinstance(method, str))
    return routes


def vuln_bank_candidates(sources: dict[str, str], *, commit: str) -> list[dict]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("VulnBank commit must be a full SHA-1")
    candidates: dict[str, dict] = {}
    for filename, text in sorted(sources.items()):
        if Path(filename).name != filename or not filename.endswith(".py"):
            raise ValueError("VulnBank source paths must be top-level Python files")
        lines = text.splitlines()
        source_hash = _sha(text.encode("utf-8"))
        for path, method, first, last, rate_limited, route_line in _route_definitions(text):
            for line_number in range(first, last + 1):
                line = lines[line_number - 1].strip()
                if "#" not in line:
                    continue
                comment = line.split("#", 1)[1].strip()
                if re.search(r"\bfixed\b|no longer|\bremoved\b|mitigat", comment, re.IGNORECASE):
                    continue
                for vuln_class, pattern in VULN_PATTERNS:
                    if not pattern.search(comment):
                        continue
                    if vuln_class == "missing_rate_limit" and rate_limited:
                        continue
                    if (path, method.upper(), vuln_class) in EXCLUDED_SOURCE_CLAIMS:
                        continue
                    candidate_id = f"vuln-bank:{filename}:{method.upper()}:{path}:{vuln_class}"
                    if candidate_id in candidates:
                        continue
                    excluded = vuln_class in {"race_condition", "missing_rate_limit"}
                    candidates[candidate_id] = {
                        "candidate_id": candidate_id, "project": "vuln-bank",
                        "external_id": f"{filename}:{method.upper()}:{path}:{vuln_class}",
                        "title": f"{vuln_class.replace('_', ' ').title()} at {method.upper()} {path}",
                        "vuln_class": vuln_class, "description": comment,
                        "endpoint_template": path, "method": method.upper(),
                        "source_url": f"https://github.com/Commando-X/vuln-bank/blob/{commit}/{filename}#L{line_number}",
                        "route_source_url": f"https://github.com/Commando-X/vuln-bank/blob/{commit}/{filename}#L{route_line}",
                        "source_path": filename, "source_line": line_number,
                        "source_sha256": source_hash, "source_version": commit,
                        "claim_basis": "source_comment", "readiness": "needs_reproduction_evidence",
                        "availability": "source_present",
                        "evaluation_status": "OUT_OF_TEST_SCOPE" if excluded else "UNASSESSED",
                        "metadata_json": _json({"source_function_line": first}),
                    }
    return sorted(candidates.values(), key=lambda row: row["candidate_id"])


def curated_vuln_bank_candidates(sources: dict[str, str], specs: list[dict],
                                 *, commit: str) -> list[dict]:
    """Include source claims whose evidence is code or README rather than a comment."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("VulnBank commit must be a full SHA-1")
    routes = {(path, method.upper()): (name, first, last, route_line)
              for name, text in sources.items() if name.endswith(".py")
              for path, method, first, last, _, route_line in _route_definitions(text)}
    result = []
    for spec in specs:
        path, method = spec["path"], spec["method"].upper()
        if (path, method) not in routes:
            raise ValueError(f"curated claim references an unregistered route: {method} {path}")
        filename = spec["source_path"]
        if filename not in sources:
            raise ValueError(f"curated claim source is missing: {filename}")
        matches = [(number, line) for number, line in enumerate(sources[filename].splitlines(), start=1)
                   if spec["anchor"] in line]
        if len(matches) != 1:
            raise ValueError(f"curated claim source anchor is missing or ambiguous: {filename}")
        line_number = matches[0][0]
        route_filename, route_first, route_last, route_line = routes[(path, method)]
        if filename.endswith(".py"):
            if filename != route_filename:
                raise ValueError("curated code anchor is outside route source")
            helper = spec.get("shared_helper")
            if helper:
                tree = ast.parse(sources[filename])
                functions = {node.name: node for node in ast.walk(tree)
                             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                helper_node = functions.get(helper)
                route_node = next((node for node in functions.values()
                                   if node.lineno == route_first), None)
                if (helper_node is None or route_node is None
                        or not helper_node.lineno <= line_number <= (helper_node.end_lineno or 0)):
                    raise ValueError("curated code anchor is outside named shared helper")
                visited = set()
                pending = [route_node.name]
                while pending:
                    name = pending.pop()
                    if name in visited:
                        continue
                    visited.add(name)
                    node = functions.get(name)
                    if node is None:
                        continue
                    pending.extend(call.func.id for call in ast.walk(node)
                                   if isinstance(call, ast.Call) and isinstance(call.func, ast.Name))
                    pending.extend(dec.id for dec in node.decorator_list if isinstance(dec, ast.Name))
                if helper not in visited:
                    raise ValueError("curated shared helper is not reachable from route")
            elif not route_first <= line_number <= route_last:
                raise ValueError("curated code anchor is outside route")
        vuln_class = spec["vuln_class"]
        result.append({
            "candidate_id": f"vuln-bank:curated:{method}:{path}:{vuln_class}",
            "project": "vuln-bank", "external_id": f"curated:{method}:{path}:{vuln_class}",
            "title": f"{vuln_class.replace('_', ' ').title()} at {method} {path}",
            "vuln_class": vuln_class, "description": spec["description"],
            "endpoint_template": path, "method": method,
            "source_url": f"https://github.com/Commando-X/vuln-bank/blob/{commit}/{filename}#L{line_number}",
            "route_source_url": f"https://github.com/Commando-X/vuln-bank/blob/{commit}/{route_filename}#L{route_line}",
            "source_path": filename, "source_line": line_number,
            "source_sha256": _sha(sources[filename].encode("utf-8")), "source_version": commit,
            "claim_basis": "official_readme" if filename == "README.md" else "source_code",
            "readiness": "needs_reproduction_evidence", "availability": "source_present",
            "evaluation_status": spec.get("evaluation_status", "UNASSESSED"),
            "metadata_json": _json({"anchor": spec["anchor"]}),
        })
    return result


def control_candidates(specs: list[dict], juice_server: str,
                       bank_sources: dict[str, str], *, vuln_commit: str) -> list[dict]:
    """Add scoped test hypotheses without embedding their expected verdicts."""
    if not re.fullmatch(r"[0-9a-f]{40}", vuln_commit):
        raise ValueError("VulnBank commit must be a full SHA-1")
    routes = {(path, method.upper()): (name, first, last, route_line)
              for name, source in bank_sources.items() if name.endswith(".py")
              for path, method, first, last, _, route_line in _route_definitions(source)}
    result = []
    seen = set()
    for spec in specs:
        if "verdict" in _json(spec).lower():
            raise ValueError("control candidate must not contain a verdict")
        candidate_id = spec["candidate_id"]
        if candidate_id in seen:
            raise ValueError(f"duplicate control candidate: {candidate_id}")
        seen.add(candidate_id)
        project, path, method = spec["project"], spec["path"], spec["method"].upper()
        filename = spec["source_path"]
        if project == "juice-shop":
            if filename != "server.ts" or path not in spec["anchor"]:
                raise ValueError("Juice Shop control route and anchor do not match")
            source = juice_server
            version = JUICE_VERSION
            base_url = f"https://github.com/juice-shop/juice-shop/blob/{version}/"
            route_line = None
        elif project == "vuln-bank":
            if (path, method) not in routes:
                raise ValueError(f"control references an unregistered route: {method} {path}")
            route_filename, first, last, route_line = routes[(path, method)]
            if filename != route_filename:
                raise ValueError("control anchor is outside route source")
            source = bank_sources[filename]
            version = vuln_commit
            base_url = f"https://github.com/Commando-X/vuln-bank/blob/{version}/"
        else:
            raise ValueError(f"unknown control project: {project}")
        matches = [number for number, line in enumerate(source.splitlines(), start=1)
                   if spec["anchor"] in line]
        if len(matches) != 1:
            raise ValueError(f"control source anchor is missing or ambiguous: {candidate_id}")
        line_number = matches[0]
        if project == "juice-shop":
            route_line_text = source.splitlines()[line_number - 1].strip()
            route_method = re.match(r"app\.(get|post|put|delete|patch)\(", route_line_text)
            if route_method and route_method.group(1).upper() != method:
                raise ValueError(f"control method does not match Juice Shop route: {candidate_id}")
            if not route_method and not route_line_text.startswith("app.use("):
                raise ValueError(f"control method cannot be checked against Juice Shop route: {candidate_id}")
        if project == "vuln-bank" and not first <= line_number <= last:
            raise ValueError("control anchor is outside route")
        result.append({
            "candidate_id": candidate_id, "project": project,
            "external_id": candidate_id.split(":", 1)[1],
            "title": spec["title"], "vuln_class": spec["vuln_class"],
            "description": spec["description"], "endpoint_template": path,
            "method": method, "source_url": f"{base_url}{filename}#L{line_number}",
            "route_source_url": f"{base_url}{filename}#L{route_line}" if route_line else None,
            "source_path": filename, "source_line": line_number,
            "source_sha256": _sha(source.encode("utf-8")), "source_version": version,
            "claim_basis": "source_code", "readiness": "needs_reproduction_evidence",
            "availability": "source_present", "evaluation_status": "UNASSESSED",
            "metadata_json": _json({"probe": spec["probe"]}),
        })
    return result


SCHEMA = """
PRAGMA user_version=1;
CREATE TABLE inventory_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE attack_candidates (
  candidate_id TEXT PRIMARY KEY,
  project TEXT NOT NULL CHECK(project IN ('juice-shop','vuln-bank')),
  external_id TEXT NOT NULL,
  title TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  description TEXT NOT NULL,
  endpoint_template TEXT,
  method TEXT,
  source_url TEXT NOT NULL,
  route_source_url TEXT,
  source_path TEXT NOT NULL,
  source_line INTEGER NOT NULL CHECK(source_line > 0),
  source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),
  source_version TEXT NOT NULL,
  claim_basis TEXT NOT NULL CHECK(claim_basis IN ('official_challenge','source_comment','source_code','official_readme')),
  readiness TEXT NOT NULL CHECK(readiness IN ('needs_route_mapping','needs_reproduction_evidence')),
  availability TEXT NOT NULL,
  evaluation_status TEXT NOT NULL CHECK(evaluation_status IN ('UNASSESSED','OUT_OF_TEST_SCOPE','MANUAL_ONLY')),
  metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
  UNIQUE(project,external_id),
  CHECK((endpoint_template IS NULL)=(method IS NULL))
);
CREATE INDEX idx_attack_candidates_project ON attack_candidates(project,vuln_class);
"""


def build_inventory(output: Path, juice_source: Path, bank_sources: dict[str, str],
                    *, vuln_commit: str, curated_specs: list[dict] | None = None,
                    control_specs: list[dict] | None = None,
                    juice_server_source: Path | None = None) -> dict[str, int]:
    bank_rows = vuln_bank_candidates(
        {name: text for name, text in bank_sources.items() if name.endswith(".py")},
        commit=vuln_commit,
    )
    if curated_specs:
        existing = {(row["endpoint_template"], row["method"], row["vuln_class"])
                    for row in bank_rows}
        for row in curated_vuln_bank_candidates(bank_sources, curated_specs, commit=vuln_commit):
            identity = (row["endpoint_template"], row["method"], row["vuln_class"])
            if identity not in existing:
                bank_rows.append(row)
                existing.add(identity)
    rows = juice_candidates(juice_source) + bank_rows
    if control_specs:
        if juice_server_source is None:
            raise ValueError("Juice Shop server source is required for control candidates")
        rows.extend(control_candidates(control_specs, juice_server_source.read_text(encoding="utf-8"),
                                       bank_sources, vuln_commit=vuln_commit))
    counts = {project: sum(row["project"] == project for row in rows)
              for project in ("juice-shop", "vuln-bank")}
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    os.close(descriptor)
    try:
        with sqlite3.connect(temporary) as conn:
            conn.executescript(SCHEMA)
            fields = tuple(rows[0]) if rows else ()
            conn.executemany(
                f"INSERT INTO attack_candidates ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
                [tuple(row[field] for field in fields) for row in rows],
            )
            conn.executemany("INSERT INTO inventory_metadata VALUES (?,?)", [
                ("juice_shop_version", JUICE_VERSION),
                ("juice_shop_image_digest", JUICE_IMAGE_DIGEST),
                ("juice_shop_source_sha256", _sha(juice_source.read_bytes())),
                ("vuln_bank_commit", vuln_commit),
                ("inventory_kind", "source_backed_attack_candidates_not_findings"),
            ])
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("candidate database integrity check failed")
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return counts


ANSWER_SCHEMA = """
PRAGMA user_version=1;
CREATE TABLE answer_key (
  candidate_id TEXT PRIMARY KEY,
  expected_verdict TEXT NOT NULL CHECK(expected_verdict IN ('VULNERABLE','NOT_VULNERABLE')),
  target_validation_status TEXT NOT NULL CHECK(target_validation_status IN ('CONFIRMED','DISPROVEN')),
  readiness TEXT NOT NULL CHECK(readiness IN ('GET_REPLAY_READY','NEEDS_TWO_MERCHANT_IDENTITIES')),
  proof_requirement TEXT NOT NULL,
  scope TEXT NOT NULL,
  evidence_level TEXT NOT NULL CHECK(evidence_level IN ('source_review','source_and_local_http')),
  observed_http_status INTEGER,
  source_url TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  limitations TEXT NOT NULL,
  CHECK((evidence_level='source_and_local_http')=(observed_http_status IS NOT NULL)),
  CHECK((expected_verdict='VULNERABLE')=(target_validation_status='CONFIRMED'))
);
CREATE TABLE answer_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def build_answer_key(output: Path, inventory: Path, answers: list[dict]) -> dict[str, int]:
    """Build a separate scored subset. Unlisted inventory rows stay unadjudicated."""
    if output.resolve() == inventory.resolve():
        raise ValueError("inventory and answer key must use separate files")
    with sqlite3.connect(inventory) as conn:
        source_rows = {row[0]: (row[1], row[2]) for row in conn.execute(
            "SELECT candidate_id,source_url,source_sha256 FROM attack_candidates"
        )}
    seen = set()
    rows = []
    for answer in answers:
        candidate_id = answer["candidate_id"]
        if candidate_id not in source_rows:
            raise ValueError(f"missing candidate in inventory: {candidate_id}")
        if candidate_id in seen:
            raise ValueError(f"duplicate answer: {candidate_id}")
        seen.add(candidate_id)
        verdict = answer["expected_verdict"]
        if verdict not in {"VULNERABLE", "NOT_VULNERABLE"}:
            raise ValueError(f"invalid verdict: {verdict}")
        target_status = answer["target_validation_status"]
        if target_status != ("CONFIRMED" if verdict == "VULNERABLE" else "DISPROVEN"):
            raise ValueError(f"invalid target Validation status: {candidate_id}")
        readiness = answer["readiness"]
        if readiness not in {"GET_REPLAY_READY", "NEEDS_TWO_MERCHANT_IDENTITIES"}:
            raise ValueError(f"invalid Validation readiness: {candidate_id}")
        proof_requirement = answer["proof_requirement"]
        if not isinstance(proof_requirement, str) or not proof_requirement.strip():
            raise ValueError(f"missing Validation proof requirement: {candidate_id}")
        level = answer["evidence_level"]
        status = answer["observed_http_status"]
        if (level == "source_and_local_http") != (status is not None):
            raise ValueError(f"observation mismatch: {candidate_id}")
        source_url, source_hash = source_rows[candidate_id]
        rows.append((candidate_id, verdict, target_status, readiness, proof_requirement,
                     answer["scope"], level, status,
                     source_url, source_hash, answer["limitations"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    os.close(descriptor)
    try:
        with sqlite3.connect(temporary) as conn:
            conn.executescript(ANSWER_SCHEMA)
            conn.executemany("INSERT INTO answer_key VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            conn.executemany("INSERT INTO answer_metadata VALUES (?,?)", [
                ("answer_scope", "adjudicated_subset_only"),
                ("inventory_sha256", _sha(inventory.read_bytes())),
            ])
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("answer database integrity check failed")
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {verdict: sum(row[1] == verdict for row in rows)
            for verdict in ("VULNERABLE", "NOT_VULNERABLE")}


def build_inventory_pair(output: Path, answer_output: Path, juice_source: Path,
                         bank_sources: dict[str, str], answers: list[dict],
                         *, vuln_commit: str, curated_specs: list[dict],
                         control_specs: list[dict], juice_server_source: Path) -> tuple[dict[str, int], dict[str, int]]:
    """Validate both outputs before replacing either existing database."""
    if output.resolve() == answer_output.resolve():
        raise ValueError("inventory and answer key must use separate files")
    output.parent.mkdir(parents=True, exist_ok=True)
    answer_output.parent.mkdir(parents=True, exist_ok=True)
    with (tempfile.TemporaryDirectory(prefix="candidate-build-", dir=output.parent) as staging,
          tempfile.TemporaryDirectory(prefix="answer-build-", dir=answer_output.parent) as answer_staging):
        staged_inventory = Path(staging) / "CandidateInventory.db"
        staged_answer = Path(answer_staging) / "CandidateAnswerKey.db"
        counts = build_inventory(staged_inventory, juice_source, bank_sources,
                                 vuln_commit=vuln_commit, curated_specs=curated_specs,
                                 control_specs=control_specs,
                                 juice_server_source=juice_server_source)
        answer_counts = build_answer_key(staged_answer, staged_inventory, answers)
        os.replace(staged_inventory, output)
        os.replace(staged_answer, answer_output)
    return counts, answer_counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--juice-source", type=Path,
                        default=ROOT / "resources/lab/juice-shop-v20.2.0-challenges.yml")
    parser.add_argument("--vuln-bank-root", type=Path, default=ROOT / "result/lab/vuln-bank")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "result/test-runs/validation-candidates/CandidateInventory.db")
    parser.add_argument("--challenge-api-snapshot", type=Path)
    parser.add_argument("--curated-bank", type=Path,
                        default=ROOT / "resources/lab/vuln-bank-curated.json")
    parser.add_argument("--juice-server-source", type=Path,
                        default=ROOT / "resources/lab/juice-shop-v20.2.0-server.ts")
    parser.add_argument("--control-candidates", type=Path,
                        default=ROOT / "resources/lab/validation-control-candidates.json")
    parser.add_argument("--answers", type=Path,
                        default=ROOT / "resources/lab/validation-answer-key.json")
    parser.add_argument("--answer-output", type=Path,
                        default=ROOT / "result/test-runs/validation-candidates/CandidateAnswerKey.db")
    args = parser.parse_args()

    if _sha(args.juice_source.read_bytes()) != JUICE_SHA256:
        parser.error("Juice Shop source differs from the pinned v20.2.0 definition")
    if _sha(args.juice_server_source.read_bytes()) != JUICE_SERVER_SHA256:
        parser.error("Juice Shop server differs from the pinned v20.2.0 source")
    if args.output.resolve() == args.answer_output.resolve():
        parser.error("inventory and answer key outputs must be separate files")
    revision = subprocess.run(
        ["git", "-C", str(args.vuln_bank_root), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if revision != VULN_BANK_COMMIT:
        parser.error("VulnBank checkout differs from the pinned source commit")
    names = ("app.py", "auth.py", "merchant_payments.py", "transaction_graphql.py", "README.md")
    for name in names:
        if _sha((args.vuln_bank_root / name).read_bytes()) != VULN_BANK_FILE_SHA256[name]:
            parser.error(f"VulnBank {name} differs from the pinned source file")
    sources = {name: (args.vuln_bank_root / name).read_text(encoding="utf-8") for name in names}
    if args.challenge_api_snapshot:
        remote = json.loads(args.challenge_api_snapshot.read_text(encoding="utf-8"))["data"]
        expected = {(row["external_id"], row["title"]) for row in juice_candidates(args.juice_source)}
        observed = {(item["key"], item["name"]) for item in remote}
        if expected != observed:
            parser.error("running Juice Shop challenge keys/names differ from pinned source")
    curated_specs = json.loads(args.curated_bank.read_text(encoding="utf-8"))
    control_specs = json.loads(args.control_candidates.read_text(encoding="utf-8"))
    answers = json.loads(args.answers.read_text(encoding="utf-8"))
    counts, answer_counts = build_inventory_pair(
        args.output, args.answer_output, args.juice_source, sources, answers,
        vuln_commit=revision, curated_specs=curated_specs,
        control_specs=control_specs, juice_server_source=args.juice_server_source,
    )
    print(_json({"database": str(args.output), "counts": counts,
                 "answer_database": str(args.answer_output), "answer_counts": answer_counts,
                 "kind": "source_backed_candidates_not_attack_findings"}))


if __name__ == "__main__":
    main()
