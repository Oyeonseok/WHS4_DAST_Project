"""Build a verified post-Recon handoff from operator-supplied Flask source.

The importer is deliberately passive: it reads local source, records route and
parameter metadata, and never sends HTTP requests.  It exists for controlled
DAST benchmarks where the operator already has a trusted source inventory and
wants to exercise Attack, Validation, and Report without repeating Recon.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import re
import shutil
import tokenize
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from aidast.benchmarks.catalog import parse_implemented_vulnerabilities
from aidast.orchestration.scope import ScopeCoordinator
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder, _parameter_role
from aidast.recon.judgment import normalize_path
from aidast.recon.policy import (
    ApiProbePolicy,
    PolicyLimits,
    TargetPolicy,
    ToolPolicy,
    validate_policy_for_target,
)
from aidast.recon.surface import export_surface
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeDocument,
    SourceEvidence,
)


class SourceImportError(RuntimeError):
    """The supplied source cannot safely form a Recon handoff."""


@dataclass(frozen=True, slots=True)
class SourceParameter:
    name: str
    location: str
    data_type: str = "string"


@dataclass(frozen=True, slots=True)
class SourceEndpoint:
    source_file: str
    source_line: int
    function_name: str
    method: str
    path: str
    parameters: tuple[SourceParameter, ...]
    vulnerability_tags: tuple[str, ...]
    vulnerability_evidence: tuple[tuple[str, str], ...]
    auth_required: bool


@dataclass(frozen=True, slots=True)
class SourceImportResult:
    scan_id: str
    recon_database: Path
    pipeline_database: Path
    handoff: Path
    inventory: Path
    endpoint_count: int
    parameter_count: int
    vulnerability_signal_count: int
    benchmark_catalog_count: int
    benchmark_catalog: Path | None


_PATH_PARAMETER = re.compile(r"<(?:(?P<type>[A-Za-z_][\w]*):)?(?P<name>[A-Za-z_][\w]*)>")
_VULNERABILITY_PATTERNS = (
    ("sqli", re.compile(r"sql\s*injection", re.I)),
    ("xss", re.compile(r"\bxss\b|cross[- ]site scripting", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|server[- ]side request forgery", re.I)),
    ("idor", re.compile(r"\bidor\b|\bbola\b|object reference", re.I)),
    ("csrf", re.compile(r"\bcsrf\b|cross[- ]site request forgery", re.I)),
    ("jwt_crypto", re.compile(r"\bjwt\b|token (?:never|does not) expire|weak token", re.I)),
    ("file_upload", re.compile(r"file upload|upload.*(?:type|extension|size)", re.I)),
    ("lfi", re.compile(r"path traversal|local file inclusion|\blfi\b", re.I)),
    ("brute_force", re.compile(r"rate limit|brute force", re.I)),
    ("source_leak", re.compile(r"information disclosure|sensitive data|error exposure|debug", re.I)),
    ("auth_bypass", re.compile(r"broken auth|no auth|authorization (?:check|validation)|privilege", re.I)),
    ("race_condition", re.compile(r"race condition|atomicity", re.I)),
    ("api_misconfig", re.compile(r"mass assignment|field name injection|no input validation", re.I)),
    ("llm_ai", re.compile(r"prompt injection|context injection|system prompt", re.I)),
)


def _attribute_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _constant_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _request_location(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.BoolOp):
        return next((location for value in node.values
                     if (location := _request_location(value, aliases))), None)
    if isinstance(node, ast.IfExp):
        return (_request_location(node.body, aliases)
                or _request_location(node.orelse, aliases))
    name = _attribute_name(node)
    if name in {"request.args", "request.query_params"}:
        return "query"
    if name == "request.form" or name == "request.files":
        return "form"
    if name in {"request.json", "request.get_json"}:
        return "json"
    if isinstance(node, ast.Call) and _attribute_name(node.func) == "request.get_json":
        return "json"
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    return None


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[SourceParameter, ...]:
    aliases: dict[str, str] = {}
    for item in ast.walk(node):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        value = item.value
        location = _request_location(value, aliases) if value is not None else None
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        if location:
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = location

    found: set[SourceParameter] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr == "get":
            location = _request_location(item.func.value, aliases)
            name = _constant_string(item.args[0]) if item.args else None
            if location and name:
                found.add(SourceParameter(name=name, location=location))
        elif isinstance(item, ast.Subscript):
            location = _request_location(item.value, aliases)
            name = _constant_string(item.slice)
            if location and name:
                found.add(SourceParameter(name=name, location=location))
    return tuple(sorted(found, key=lambda item: (item.location, item.name)))


def _function_comments(path: Path) -> dict[int, str]:
    comments: dict[int, str] = {}
    try:
        with path.open("rb") as stream:
            for token in tokenize.tokenize(stream.readline):
                if token.type == tokenize.COMMENT:
                    comments[token.start[0]] = token.string.removeprefix("#").strip()
    except (OSError, tokenize.TokenError):
        return {}
    return comments


def _vulnerability_tags(text: str) -> tuple[str, ...]:
    return tuple(tag for tag, pattern in _VULNERABILITY_PATTERNS if pattern.search(text))


def _vulnerability_evidence(text: str) -> tuple[tuple[str, str], ...]:
    """Keep a bounded source-provided explanation for each imported signal."""
    normalized = [re.sub(r"\s+", " ", line).strip(" -\t") for line in text.splitlines()]
    evidence = []
    for tag, pattern in _VULNERABILITY_PATTERNS:
        matches = [line for line in normalized if line and pattern.search(line)]
        if matches:
            evidence.append((tag, "; ".join(dict.fromkeys(matches))[:500]))
    return tuple(evidence)


def _request_method_guard(node: ast.If) -> str | None:
    """Return the HTTP method selected by a simple request.method equality."""
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    if not isinstance(test.ops[0], ast.Eq):
        return None
    pairs = ((test.left, test.comparators[0]), (test.comparators[0], test.left))
    for attribute, constant in pairs:
        if _attribute_name(attribute) == "request.method":
            value = _constant_string(constant)
            if value:
                return value.upper()
    return None


def _method_comment_text(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    comments: dict[int, str],
    method: str,
) -> str:
    """Select source-marker comments reachable for one declared HTTP method."""
    guarded_ranges: list[tuple[int, int, str, bool]] = []
    for branch in ast.walk(node):
        if not isinstance(branch, ast.If):
            continue
        guarded_method = _request_method_guard(branch)
        if guarded_method is None:
            continue
        if branch.body:
            guarded_ranges.append((
                branch.lineno + 1,
                max(item.end_lineno or item.lineno for item in branch.body),
                guarded_method,
                True,
            ))
        if branch.orelse:
            guarded_ranges.append((
                branch.orelse[0].lineno,
                max(item.end_lineno or item.lineno for item in branch.orelse),
                guarded_method,
                False,
            ))

    selected = []
    for line, value in comments.items():
        if not node.lineno <= line <= (node.end_lineno or node.lineno):
            continue
        allowed = True
        for start, end, guarded_method, positive_branch in guarded_ranges:
            if start <= line <= end:
                matches = method == guarded_method
                if matches != positive_branch:
                    allowed = False
                    break
        if allowed:
            selected.append(value)
    return "\n".join(selected)


def _requires_authentication(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Detect executable authentication guards without matching prose/docstrings."""
    guard_names = {
        "admin_required", "auth_required", "jwt_required", "login_required",
        "merchant_required", "token_required",
    }
    for decorator in node.decorator_list:
        callable_node = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _attribute_name(callable_node).split(".")[-1].casefold() in guard_names:
            return True
    # Reading or optionally accepting an Authorization header does not make a
    # route authentication-required. Flask authentication is represented by an
    # explicit guard decorator in the supported source-import contract.
    return False


def _route_methods(decorator: ast.Call) -> tuple[str, ...]:
    for keyword in decorator.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            methods = tuple(
                value.upper() for item in keyword.value.elts
                if (value := _constant_string(item)) is not None
            )
            return methods or ("GET",)
    return ("GET",)


def extract_flask_endpoints(source_root: Path) -> tuple[SourceEndpoint, ...]:
    """Extract Flask route decorators and request parameter names without imports."""
    root = source_root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise SourceImportError("source root must be a directory")
    endpoints: list[SourceEndpoint] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", ".venv", "venv", "__pycache__"} for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise SourceImportError(f"cannot parse Python source: {path}: {exc}") from exc
        comments = _function_comments(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators: list[ast.Call] = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr == "route" and decorator.args:
                        decorators.append(decorator)
            if not decorators:
                continue
            auth_required = _requires_authentication(node)
            parameters = list(_function_parameters(node))
            for decorator in decorators:
                route = _constant_string(decorator.args[0])
                if not route or not route.startswith("/"):
                    continue
                path_parameters = [
                    SourceParameter(
                        name=match.group("name"), location="path",
                        data_type="integer" if match.group("type") == "int" else "string",
                    )
                    for match in _PATH_PARAMETER.finditer(route)
                ]
                combined = tuple(sorted(set(parameters + path_parameters), key=lambda item: (item.location, item.name)))
                normalized = _PATH_PARAMETER.sub(lambda match: "{" + match.group("name") + "}", route)
                for method in _route_methods(decorator):
                    # Source comments are the explicit benchmark contract. Do
                    # not turn incidental identifiers or unreachable branches
                    # for another HTTP method into vulnerability assertions.
                    vulnerability_text = _method_comment_text(
                        node, comments, method,
                    )
                    tags = _vulnerability_tags(vulnerability_text)
                    evidence = _vulnerability_evidence(vulnerability_text)
                    endpoints.append(SourceEndpoint(
                        source_file=path.relative_to(root).as_posix(),
                        source_line=decorator.lineno,
                        function_name=node.name,
                        method=method,
                        path=normalized,
                        parameters=combined,
                        vulnerability_tags=tags,
                        vulnerability_evidence=evidence,
                        auth_required=auth_required,
                    ))
    unique = {
        (item.method, item.path): item
        for item in sorted(endpoints, key=lambda item: (item.path, item.method, item.source_file, item.source_line))
    }
    if not unique:
        raise SourceImportError("no Flask route decorators were found")
    return tuple(unique.values())


def _source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        if ".git" in path.parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _scope_document(
    target_url: str, *, scope_id: str, source_ref: str,
    lab_benchmark: bool = False,
) -> ScopeDocument:
    statement = (
        "This is an intentionally vulnerable application, built to practice and teach "
        "application security testing, and to help security professionals, and tooling "
        "companies benchmark traditional SAST/DAST tools and offensive security AI agents."
    )
    active = "Non-destructive active security testing with GET, HEAD, OPTIONS, and POST is authorized."
    benchmark_active = (
        "Bounded active security testing with PUT, PATCH, and DELETE against disposable "
        "local lab fixtures is authorized; state may be reset between cases."
    )
    benchmark_concurrency = (
        "Bounded race-condition testing with concurrency up to 8 and bounded rate-limit "
        "testing with at most 20 guesses per case are authorized."
    )
    prohibited = (
        "Denial of service, unbounded brute force, external OOB, external SSRF, and "
        "requests to non-loopback targets are prohibited."
        if lab_benchmark else
        "PUT, PATCH, DELETE, denial of service, brute force, destructive state changes, "
        "external OOB, and external SSRF are prohibited."
    )
    operational = (
        "Rate limit: 5 requests per second; concurrency: 8; maximum requests: 5000; "
        "timeout: 15 seconds."
        if lab_benchmark else
        "Rate limit: 0.5 requests per second; concurrency: 1; maximum requests: 500; "
        "timeout: 15 seconds."
    )
    allowed = [active]
    if lab_benchmark:
        allowed.extend((benchmark_active, benchmark_concurrency))
    source_text = "\n".join((
        statement, f"Canonical asset: {target_url}", f"Source reference: {source_ref}", active,
        *(allowed[1:]), prohibited, operational,
    ))
    captured_at = datetime.now(timezone.utc)
    return ScopeDocument(
        scope_id=scope_id,
        created_at=captured_at,
        source=ProgramPage(
            requested_url=target_url,
            final_url=target_url,
            title="Operator-provided intentionally vulnerable application source",
            captured_at=captured_at,
            capture_status=CaptureStatus.COMPLETE,
            capture_reason=CaptureReason.NONE,
            content_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            text=source_text,
        ),
        analysis=ScopeAnalysis(
            program_name="Source-imported authorized lab",
            program_description=statement,
            in_scope_assets=[ScopeAsset(
                asset_type=AssetType.URL, asset=target_url,
                description="Operator-provided intentionally vulnerable benchmark target",
                eligibility="eligible", maximum_severity="critical",
            )],
            out_of_scope_assets=[],
            allowed_activities=allowed,
            prohibited_activities=[prohibited],
            submission_requirements=["Keep evidence local and redact credentials or unrelated user data."],
            operational_constraints=(
                ["Rate limit: 5 requests per second.", "Concurrency: 8.",
                 "Maximum requests: 5000.", "Timeout: 15 seconds."]
                if lab_benchmark else
                ["Rate limit: 0.5 requests per second.", "Concurrency: 1.",
                 "Maximum requests: 500.", "Timeout: 15 seconds."]
            ),
            safe_harbor="Authorization is limited to this intentionally vulnerable training target.",
            ambiguities=[],
            source_evidence=[
                SourceEvidence(section="Purpose", quote=statement),
                SourceEvidence(section="Canonical asset", quote=target_url),
                SourceEvidence(section="Active testing", quote=active),
            ],
        ),
    )


def _function_tag(endpoint: SourceEndpoint) -> str:
    value = f"{endpoint.function_name} {endpoint.path}".casefold()
    if any(token in value for token in ("login", "signin", "auth")):
        return "authentication"
    if any(token in value for token in ("forgot", "reset-password", "reset_password")):
        return "password_reset"
    if "upload" in value:
        return "file_upload"
    if any(token in value for token in ("transfer", "payment", "charge", "loan", "card")):
        return "payment"
    if any(token in value for token in ("user", "admin", "account")):
        return "authorization"
    if any(token in value for token in ("search", "billers", "transactions")):
        return "search"
    return "unknown"


def import_flask_source(
    source_root: Path, *, target_url: str, result_root: Path,
    approved_by: str, source_ref: str = "operator-provided-source",
    lab_benchmark: bool = False,
) -> SourceImportResult:
    """Create Recon.db, immutable handoff, and Pipeline.db without network Recon."""
    root = source_root.expanduser().resolve(strict=True)
    result = result_root.expanduser().resolve()
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise SourceImportError("target URL must be an absolute credential-free HTTP(S) URL")
    if parsed.scheme == "http":
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise SourceImportError("plain HTTP source imports are limited to loopback targets")
    if parsed.query or parsed.fragment:
        raise SourceImportError("target URL must not contain a query string or fragment")
    if not approved_by.strip():
        raise SourceImportError("approved_by must not be blank")

    endpoints = extract_flask_endpoints(root)
    benchmark_catalog = (
        parse_implemented_vulnerabilities(root) if lab_benchmark else None
    )
    scan_id = db.new_id("scan")
    scope_id = db.new_id("scope")
    run_dir = result / "Runs" / scan_id
    attack_dir = result / "AttackRuns" / scan_id
    scope_dir = result / "ImportedScope" / scan_id
    if any(path.exists() for path in (run_dir, attack_dir, scope_dir)):
        raise SourceImportError("generated scan path already exists")

    if lab_benchmark:
        try:
            benchmark_loopback = (
                parsed.hostname == "localhost"
                or ipaddress.ip_address(parsed.hostname).is_loopback
            )
        except ValueError:
            benchmark_loopback = False
        if not benchmark_loopback:
            raise SourceImportError("lab benchmark mode is limited to loopback targets")
    document = _scope_document(
        target_url, scope_id=scope_id, source_ref=source_ref,
        lab_benchmark=lab_benchmark,
    )
    coordinator = ScopeCoordinator(scope_dir)
    staging = coordinator._create_scope_draft(document)
    try:
        coordinator._publish_scope(staging, document, approved_by.strip())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    coordinator.load_approved_scope()

    run_dir.mkdir(parents=True)
    attack_dir.mkdir(parents=True)
    recon_path = run_dir / "Recon.db"
    conn = db.init_db(recon_path)
    try:
        db.insert_scan(conn, scan_id=scan_id, scope_type="source_import", scope_value=scope_id)
        asset_id = db.insert_asset(conn, scan_id=scan_id, identifier=target_url, asset_type=AssetType.URL.value)
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        base_url = f"{parsed.scheme}://{parsed.hostname}" + (f":{port}" if port != default_port else "")
        origin_id = db.upsert_origin(
            conn, asset_id=asset_id, scheme=parsed.scheme, host=parsed.hostname,
            port=port, base_url=base_url, framework_signature="Flask (source import)",
            main_crawler_mode="source_import", spa_detected=False,
        )
        stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="recon")
        recorder = ObservationRecorder(conn, origin_id=origin_id, scan_id=scan_id)
        annotation_run = db.new_id("annotation_run")
        conn.execute(
            """INSERT INTO annotation_runs
            (annotation_run_id,scan_id,model,prompt_version,taxonomy_version,status,started_at,finished_at)
            VALUES (?,?,'deterministic-source-import','1','1','completed',?,?)""",
            (annotation_run, scan_id, db.now(), db.now()),
        )
        endpoint_rows: list[dict] = []
        vulnerability_count = 0
        parameter_count = 0
        for item in endpoints:
            recorder.record("source_import", [{
                "method": item.method,
                "path": item.path,
                "url": base_url + item.path,
                "source": "flask_source_import",
                "discovery_kind": "source_route",
                "observed_at": db.now(),
                "context": {
                    "context_key": f"source:{item.source_file}",
                    "action_type": "source_import",
                    "action_target": f"{item.source_file}:{item.source_line}",
                    "context_summary": "Static Flask route declaration; no HTTP response inferred.",
                    "auth_state": "unknown",
                },
            }])
            endpoint_id = conn.execute(
                "SELECT endpoint_id FROM endpoints WHERE origin_id=? AND method=? AND normalized_path=?",
                (origin_id, item.method, normalize_path(item.path)),
            ).fetchone()[0]
            conn.execute(
                "UPDATE endpoints SET auth_required=? WHERE endpoint_id=?",
                (int(item.auth_required), endpoint_id),
            )
            for parameter in item.parameters:
                role = _parameter_role(parameter.name)
                db.upsert_parameter(
                    conn, endpoint_id=endpoint_id, name=parameter.name,
                    location=parameter.location, data_type=parameter.data_type,
                    role=role, is_identifier=role == "identifier",
                )
                parameter_count += 1
            observation_id = conn.execute(
                """SELECT observation_id FROM endpoint_observations
                WHERE endpoint_id=? ORDER BY observed_at DESC LIMIT 1""", (endpoint_id,),
            ).fetchone()[0]
            function_tag = _function_tag(item)
            conn.execute(
                """INSERT INTO endpoint_annotations
                (annotation_id,observation_id,annotation_run_id,category,tag,rationale,confidence,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (db.new_id("annotation"), observation_id, annotation_run, "function",
                 function_tag, "Deterministic classification from route/function names.", 1.0, db.now()),
            )
            for tag in item.vulnerability_tags:
                evidence = dict(item.vulnerability_evidence).get(tag)
                rationale = f"Operator-provided source marker at {item.source_file}:{item.source_line}."
                if evidence:
                    rationale += f" Source evidence: {evidence}"
                conn.execute(
                    """INSERT INTO endpoint_annotations
                    (annotation_id,observation_id,annotation_run_id,category,tag,rationale,confidence,created_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (db.new_id("annotation"), observation_id, annotation_run,
                     "source_vulnerability", tag,
                     rationale,
                     1.0, db.now()),
                )
                db.insert_observation(
                    conn, origin_id=origin_id, obs_type="source_vulnerability",
                    key=tag, value=f"{tag} source marker at {item.source_file}:{item.source_line}",
                    source="flask_source_import",
                )
                db.insert_surface_signal(conn, origin_id=origin_id, signal_type=tag, value=item.path)
                vulnerability_count += 1
            endpoint_rows.append({
                "method": item.method, "path": item.path,
                "source_file": item.source_file, "source_line": item.source_line,
                "function_name": item.function_name, "auth_required": item.auth_required,
                "parameters": [
                    {"name": parameter.name, "location": parameter.location,
                     "data_type": parameter.data_type}
                    for parameter in item.parameters
                ],
                "vulnerability_tags": list(item.vulnerability_tags),
                "vulnerability_evidence": dict(item.vulnerability_evidence),
            })
        if benchmark_catalog is not None:
            conn.executemany(
                """INSERT INTO benchmark_catalog_items
                (catalog_item_id,scan_id,ordinal,category,title,source_path,
                 source_line,source_ref,source_sha256)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        db.new_id("catalog"), scan_id, item.ordinal, item.category,
                        item.title, item.source_path, item.source_line, source_ref,
                        benchmark_catalog.source_sha256,
                    )
                    for item in benchmark_catalog.items
                ],
            )
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
            (scan_id,),
        )
        conn.commit()
        finish_stage_run(conn, stage_run_id, status="completed")
        surface_path = export_surface(conn, scan_id=scan_id, output_path=run_dir / "Surface.json")
    finally:
        conn.close()

    inventory_path = run_dir / "SourceInventory.json"
    inventory = {
        "schema_version": "1.0", "scan_id": scan_id, "target_url": target_url,
        "source_ref": source_ref, "source_sha256": _source_digest(root),
        "endpoint_count": len(endpoint_rows), "parameter_count": parameter_count,
        "vulnerability_signal_count": vulnerability_count,
        "benchmark_catalog_count": (
            len(benchmark_catalog.items) if benchmark_catalog is not None else 0
        ),
        "vulnerability_counts": dict(sorted(Counter(
            tag for endpoint in endpoint_rows for tag in endpoint["vulnerability_tags"]
        ).items())),
        "endpoints": endpoint_rows,
    }
    inventory_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    catalog_path: Path | None = None
    if benchmark_catalog is not None:
        catalog_path = run_dir / "BenchmarkCatalog.json"
        catalog_path.write_text(json.dumps({
            "schema_version": "1.0",
            "scan_id": scan_id,
            "source_ref": source_ref,
            "source_path": benchmark_catalog.source_path,
            "source_sha256": benchmark_catalog.source_sha256,
            "count": len(benchmark_catalog.items),
            "semantics": (
                "Upstream-declared benchmark claims; each remains unassessed until "
                "independent Attack and Validation evidence exists."
            ),
            "items": [item.to_dict() for item in benchmark_catalog.items],
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    review_path = run_dir / "ReconReview.json"
    review_path.write_text(json.dumps({
        "schema_version": "1.0", "scan_id": scan_id, "status": "completed",
        "review_kind": "deterministic_source_import",
        "limitations": [
            "No endpoint was proven reachable during import.",
            "Source vulnerability markers are hypotheses, not confirmed findings.",
            "Attack and Validation must produce independent request/response evidence.",
        ],
        "counts": {
            "endpoints": len(endpoint_rows), "parameters": parameter_count,
            "vulnerability_signals": vulnerability_count,
            "benchmark_catalog_items": (
                len(benchmark_catalog.items) if benchmark_catalog is not None else 0
            ),
        },
    }, indent=2) + "\n", encoding="utf-8")

    active_evidence = (
        "Bounded active security testing with PUT, PATCH, and DELETE against disposable "
        "local lab fixtures is authorized; state may be reset between cases."
        if lab_benchmark else
        "Non-destructive active security testing with GET, HEAD, OPTIONS, and POST is authorized."
    )
    policy = TargetPolicy(
        scope_id=scope_id, policy_id=db.new_id("policy"), asset_type=AssetType.URL,
        asset=target_url, allowed_schemes=[parsed.scheme], allowed_hosts=[parsed.hostname],
        allowed_ports=[port], allowed_path_prefixes=[parsed.path or "/"],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        attack_allowed_methods=(
            ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
            if lab_benchmark else ["GET", "HEAD", "OPTIONS", "POST"]
        ),
        attack_authorization_mode="active_non_destructive",
        attack_authorization_evidence=active_evidence,
        limits=PolicyLimits(
            requests_per_second=5 if lab_benchmark else 0.5,
            concurrency=8 if lab_benchmark else 1,
            timeout_seconds=15, max_depth=2,
            max_requests=5000 if lab_benchmark else 500,
        ),
        tools=ToolPolicy(playwright_interaction=True, form_submission=False,
                         katana_headless=True, ffuf_enabled=False, ffuf_recursion=False,
                         mitm_capture_bodies=True),
        api_probe=ApiProbePolicy(graphql=True, allowed_paths=["/graphql"]),
        policy_notes=[
            "Generated from operator-provided source; import itself made no HTTP requests.",
            *(
                ["Disposable loopback lab benchmark mode; reset state between cases."]
                if lab_benchmark else []
            ),
        ],
    )
    validate_policy_for_target(
        policy, asset_type=AssetType.URL, asset=target_url,
        scope_markdown=(scope_dir / "Scope.md").read_text(encoding="utf-8"),
    )
    policy_path = run_dir / "TargetPolicy.json"
    policy_path.write_text(json.dumps({
        "schema_version": "1.0", "scope_id": scope_id,
        "policies": [policy.model_dump(mode="json")],
    }, indent=2) + "\n", encoding="utf-8")
    for name in ("Scope.md", "Scope.json", "Approval.json"):
        shutil.copy2(scope_dir / name, run_dir / name)

    artifacts = [
        hash_artifact(recon_path, root=run_dir, role="database", media_type="application/vnd.sqlite3"),
        hash_artifact(surface_path, root=run_dir, role="surface", media_type="application/json"),
        hash_artifact(review_path, root=run_dir, role="recon-review", media_type="application/json"),
        hash_artifact(inventory_path, root=run_dir, role="source-inventory", media_type="application/json"),
    ]
    if catalog_path is not None:
        artifacts.append(hash_artifact(
            catalog_path, root=run_dir, role="benchmark-catalog",
            media_type="application/json",
        ))
    for name, role, media_type in (
        ("Scope.md", "scope-markdown", "text/markdown"),
        ("Scope.json", "scope", "application/json"),
        ("Approval.json", "scope-approval", "application/json"),
        ("TargetPolicy.json", "target-policy", "application/json"),
    ):
        artifacts.append(hash_artifact(run_dir / name, root=run_dir, role=role, media_type=media_type))
    handoff = HandoffManifest(
        scan_id=scan_id, stage_run_id=stage_run_id, producer_stage="recon",
        consumer_stage="review", db_path="Recon.db", artifacts=artifacts,
        counts={
            "assets": 1, "endpoints": len(endpoint_rows),
            "parameters": parameter_count,
            "benchmark_catalog_items": (
                len(benchmark_catalog.items) if benchmark_catalog is not None else 0
            ),
        },
        metadata={"scope_id": scope_id, "source_ref": source_ref,
                  "source_sha256": inventory["source_sha256"], "imported": True,
                  "benchmark_catalog_items": (
                      len(benchmark_catalog.items)
                      if benchmark_catalog is not None else 0
                  )},
    )
    handoff_path = run_dir / "Handoff.json"
    handoff_path.write_text(handoff.model_dump_json(indent=2) + "\n", encoding="utf-8")
    pipeline_path = attack_dir / "Pipeline.db"
    materialize_pipeline(handoff_path, pipeline_path)
    return SourceImportResult(
        scan_id=scan_id, recon_database=recon_path, pipeline_database=pipeline_path,
        handoff=handoff_path, inventory=inventory_path,
        endpoint_count=len(endpoint_rows), parameter_count=parameter_count,
        vulnerability_signal_count=vulnerability_count,
        benchmark_catalog_count=(
            len(benchmark_catalog.items) if benchmark_catalog is not None else 0
        ),
        benchmark_catalog=catalog_path,
    )
