"""Masked, source-bound submission packages; persisted report bytes stay immutable.

Only text metadata is supported. Pattern masking cannot identify arbitrary,
unlabelled secrets and never claims to recover raw request bodies or attachments.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import string
import tempfile
import zipfile
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from aidast.validation.models import canonical_json, canonical_sha256
from . import case_runtime
from .models import validate_draft
from .runtime import ReportError, _path

POLICY_VERSION = "text-metadata-v2"
PROFILE_VERSION = "submission-v1"
MAX_METADATA_BYTES = 65536
MAX_REQUIREMENTS_BYTES = 131072
MAX_MARKDOWN_BYTES = 2_000_000
MAX_EVIDENCE_BYTES = 2_000_000
MAX_EVIDENCE_COUNT = 2048
MAX_PACKAGE_BYTES = 8_000_000
_CANONICAL = frozenset({
    "title", "asset", "target", "weakness", "vulnerability_type", "endpoint", "severity",
    "technical_severity", "cvss_vector", "vrt_category", "summary", "description", "prerequisites",
    "steps_to_reproduce", "expected_behavior", "actual_behavior", "impact", "demonstrated_impact", "remediation",
})
Name = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
RuleText = Annotated[str, StringConstraints(max_length=8192)]


class ProgramRequirements(BaseModel):
    """Operator-identified program rules, never approval of a report."""
    model_config = ConfigDict(extra="forbid", strict=True)
    verified: bool = False
    source: RuleText = ""
    severity_required: bool = True
    required_fields: list[Name] = Field(default_factory=list, max_length=64)
    additional_fields: dict[Name, RuleText] = Field(default_factory=dict, max_length=64)
    report_template: RuleText | None = None
    impact_template: RuleText | None = None

    @model_validator(mode="after")
    def program_rules(self) -> ProgramRequirements:
        if self.verified and not self.source.strip():
            raise ValueError("verified program rules require a source")
        if len(set(self.required_fields)) != len(self.required_fields):
            raise ValueError("duplicate required fields")
        if set(self.additional_fields) & _CANONICAL:
            raise ValueError("additional fields cannot override canonical fields")
        return self


_SECRET_NAME = re.compile(r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|credential|session|email|phone|ssn|account[_-]?id|user[_-]?id)", re.I)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_HEADER = re.compile(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)(\s*[:=]\s*)([^\r\n]+)")
_ASSIGN = re.compile(r'''(?ix)(["']?(?:password|passwd|secret|(?:access|refresh|auth|id|csrf)[_-]?token|token|api[_-]?key|credential|session(?:[_-]?id)?|email|phone|ssn|account[_-]?id|user[_-]?id)["']?\s*[:=]\s*)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s&,;<>}\]"']+))''')
_BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+([^\s,;<>]+)")
_URL = re.compile(r'''https?://[^\s"'<>`]+''', re.I)
_TOKEN = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:sk-|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{8,})\b")
_LOCAL_PATH = re.compile(r"(?<![A-Za-z0-9:/])(?:/(?:Users|private|tmp|var|home|opt|workspace|srv|root)/[^\s\"'<>`]+|[A-Za-z]:\\[^\s\"'<>`]+)")
_UNSUPPORTED_KEYS = frozenset({"file", "file_path", "path", "source_path", "attachment_path", "raw_body", "body", "response_body", "request_body", "binary", "base64", "image", "video"})
_TEXT_KINDS = frozenset({"observation", "request", "response", "response_diff", "response_comparison", "http", "text", "metadata", "replay", "comparison", "control", "target", "proof", "validation", "blind_assessment", "blind_assessment_pre_impact", "claim_comparison", "blind_profile_evidence_audit", "development_observation", "impact_development_observation", "impact_precondition_verification"})


class _Masker:
    def __init__(self, values: list[Any], *, paths: tuple[str, ...] = (), seed: list[Any] | None = None):
        self.secrets: dict[str, str] = {}
        self.tokens: dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self._next_number: Counter[str] = Counter()
        self._reserved: set[str] = set()
        # Original seed literals are unmanaged. Allocate writer identities
        # before looking at derivative prose or program rules, then extend the
        # map without renumbering existing labels. Never hash private values
        # into public pseudonyms: low-entropy values could be guessed offline.
        if seed is not None:
            self._reserve(seed)
            for value in seed:
                self._discover(value)
        self._reserve(values, managed=set(self.tokens.values()))
        for value in values:
            self._discover(value)
        for path in paths:
            self._add(path, 'path')
        ordered = sorted((item for item in self.secrets if len(item) > 3), key=lambda item: (-len(item), item))
        self._replacement = re.compile("|".join(re.escape(item) for item in ordered)) if ordered else None

    def _reserve(self, value: Any, *, managed: set[str] | None = None) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._reserve(key, managed=managed)
                self._reserve(child, managed=managed)
        elif isinstance(value, list):
            for child in value:
                self._reserve(child, managed=managed)
        elif isinstance(value, str):
            for match in re.finditer(r"\[(?:EMAIL|TOKEN|PATH)_\d+\]", value):
                if managed is None or match.group() not in managed:
                    self._reserved.add(match.group())

    def _add(self, value: str, kind: str) -> None:
        if not value or value in self.secrets or re.fullmatch(r"\[(?:REDACTED|[A-Z]+_\d+)\]", value):
            return
        self.secrets[value] = kind
        while True:
            self._next_number[kind] += 1
            label = f"[{kind.upper()}_{self._next_number[kind]}]"
            if label not in self._reserved:
                self.tokens[value] = label
                break

    def _discover(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in sorted(value.items()):
                self._discover(key)
                if _SECRET_NAME.search(key):
                    self._sensitive(child, "email" if "email" in key.lower() else "token")
                self._discover(child)
        elif isinstance(value, list):
            for child in value:
                self._discover(child)
        elif isinstance(value, str):
            for match in _EMAIL.finditer(value):
                self._add(match.group(), "email")
            for match in _HEADER.finditer(value):
                raw = match[3].strip()
                self._add(raw, "token")
                if match[1].lower().endswith("authorization"):
                    self._add(re.sub(r"^(?:Bearer|Basic)\s+", "", raw, flags=re.I), "token")
                else:
                    for part in raw.split(";"):
                        if "=" in part:
                            self._add(part.split("=", 1)[1].strip(), "token")
            for match in _ASSIGN.finditer(value):
                raw = next((group for group in match.groups()[1:] if group is not None), "")
                self._add(raw, "email" if _EMAIL.fullmatch(raw) else "token")
            for match in _BEARER.finditer(value):
                self._add(match[1], "token")
            for match in _URL.finditer(value):
                try:
                    parsed = urlsplit(match.group())
                    if "@" in parsed.netloc:
                        self._add(parsed.netloc.rsplit("@", 1)[0], "token")
                    for part in parsed.query.split("&"):
                        if "=" in part:
                            key, raw = part.split("=", 1)
                            if _SECRET_NAME.search(unquote(key)) or unquote(key).lower() in {"auth", "key", "signature", "sig", "jwt", "code"}:
                                self._add(raw, "token")
                                self._add(unquote(raw), "token")
                except ValueError:
                    self._add(match.group(), "token")
            for match in _TOKEN.finditer(value):
                self._add(match.group(), "token")
            for match in _LOCAL_PATH.finditer(value):
                self._add(match.group(), "path")

    def _sensitive(self, value: Any, kind: str) -> None:
        if isinstance(value, str):
            self._add(value, kind)
        elif isinstance(value, dict):
            for child in value.values():
                self._sensitive(child, kind)
        elif isinstance(value, list):
            for child in value:
                self._sensitive(child, kind)

    def _token(self, value: str) -> str:
        kind = self.secrets[value]
        self.counts[kind] += 1
        return self.tokens[value]

    def text(self, value: str) -> str:
        cleaned = self._replacement.sub(lambda match: self._token(match.group()), value) if self._replacement else value
        # Short credentials are replaced only in labelled assignments. Global
        # replacement would corrupt numbered steps and ordinary HTTP values.
        def assignment(match):
            raw = next((group for group in match.groups()[1:] if group is not None), "")
            if raw not in self.secrets or len(raw) > 3:
                return match.group()
            quote = '"' if match[2] is not None else "'" if match[3] is not None else ""
            return match[1] + quote + self._token(raw) + quote
        cleaned = _ASSIGN.sub(assignment, cleaned)
        def header(match):
            raw = match[3].strip()
            if raw in self.secrets:
                return match[1] + match[2] + self._token(raw)
            return match.group()
        cleaned = _HEADER.sub(header, cleaned)
        cleaned = _BEARER.sub(lambda match: match.group().split()[0] + " " + self._token(match[1]) if match[1] in self.secrets else match.group(), cleaned)
        def url(match):
            try:
                parsed = urlsplit(match.group())
                netloc = parsed.netloc
                if '@' in netloc:
                    credential, host = netloc.rsplit('@', 1)
                    if credential in self.secrets:
                        netloc = self._token(credential) + '@' + host
                query = []
                for part in parsed.query.split('&'):
                    key, separator, raw = part.partition('=')
                    sensitive = _SECRET_NAME.search(unquote(key)) or unquote(key).lower() in {'auth', 'key', 'signature', 'sig', 'jwt', 'code'}
                    if separator and sensitive:
                        known = raw if raw in self.secrets else unquote(raw)
                        if known in self.secrets:
                            raw = self._token(known)
                    query.append(key + separator + raw)
                return parsed._replace(netloc=netloc, query='&'.join(query)).geturl()
            except ValueError:
                return self._token(match.group()) if match.group() in self.secrets else match.group()
        return _URL.sub(url, cleaned)

    def clean(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.clean(child) for child in value]
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                cleaned_key = self.text(key)
                if cleaned_key in result:
                    raise ReportError("metadata keys collide after masking")
                if _SECRET_NAME.search(key) and not isinstance(child, str):
                    self.counts["token"] += 1
                    result[cleaned_key] = "[REDACTED]"
                elif _SECRET_NAME.search(key) and child in self.secrets:
                    result[cleaned_key] = self._token(child)
                else:
                    result[cleaned_key] = self.clean(child)
            return result
        return value


def sanitize_preview(text: str, *, paths: tuple[str, ...] = ()) -> str:
    """Mask old/plain previews without changing immutable renderer bytes."""
    return _Masker([text], paths=paths).text(text)


def _writer_seed(context: dict) -> list[Any]:
    """Exact shared discovery inputs for writer and later submission views."""
    validation = context.get("validation", {})
    return [validation.get("decision", {}), [item.get("details", {}) for item in validation.get("evidence", [])],
            context.get("skill", ""), context.get("template", "")]


def sanitize_writer_context(context: dict) -> dict:
    """Give report writers a masked copy while retaining provenance bindings.

    The original context hash identifies the persisted snapshot. Masked prose
    is a derivative view and does not replace the source used for validation.
    """
    copy = json.loads(canonical_json(context))
    validation = copy.get("validation", {})
    for evidence in validation.get("evidence", []):
        _metadata_check(evidence.get("details", {}))
    masker = _Masker([], seed=_writer_seed(copy))
    def decision_view(value):
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key in {"evidence_ids", "validation_evidence_ids", "evidence_id", "case_id", "scan_id", "attempt_id", "operation_ids"} or key.endswith("_sha256"):
                    result[key] = child
                elif _SECRET_NAME.search(key):
                    cleaned = masker.clean({key: child})
                    result[key] = next(iter(cleaned.values()))
                else:
                    result[key] = decision_view(child)
            return result
        if isinstance(value, list):
            return [decision_view(child) for child in value]
        return masker.clean(value)
    validation["decision"] = decision_view(validation.get("decision", {}))
    for evidence in validation.get("evidence", []):
        evidence["details"] = masker.clean(evidence.get("details", {}))
    for key in ("skill", "template"):
        if key in copy:
            copy[key] = masker.text(copy[key])
    return copy


def _requirements(report_db: Path) -> ProgramRequirements:
    path = _path(report_db.parent / "ProgramRequirements.json")
    if not path.exists():
        return ProgramRequirements()
    if not path.is_file() or path.stat().st_size > MAX_REQUIREMENTS_BYTES:
        raise ReportError("program requirements cannot be safely read")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"schema_version", "requirements"} or type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ReportError("unsupported program requirements version")
    return ProgramRequirements.model_validate(document["requirements"])


def save_requirements(report_db: Path, requirements: ProgramRequirements) -> dict:
    """Atomically replace only the versioned program-rules sidecar."""
    report_db = _path(report_db, existing=True)
    requirements = ProgramRequirements.model_validate(requirements.model_dump())
    path = _path(report_db.parent / "ProgramRequirements.json")
    if path.exists():
        try:
            private = _requirements(report_db).model_dump()
            public = inspect_report(report_db)["requirements"]
        except (ValueError, OSError, UnicodeError):
            # Invalid sidecars can still be replaced by valid supplied rules.
            pass
        else:
            def retain_original(submitted: Any, masked: Any, original: Any) -> Any:
                if isinstance(submitted, str) and isinstance(original, str) and submitted == masked:
                    return original
                if isinstance(submitted, dict) and isinstance(masked, dict) and isinstance(original, dict):
                    return {key: retain_original(value, masked[key], original[key])
                            if key in masked and key in original else value for key, value in submitted.items()}
                return submitted
            requirements = ProgramRequirements.model_validate(retain_original(requirements.model_dump(), public, private))
    encoded = (canonical_json({"schema_version": 1, "requirements": requirements.model_dump()}) + "\n").encode()
    if len(encoded) > MAX_REQUIREMENTS_BYTES:
        raise ReportError("program requirements exceed the byte budget")
    handle, name = tempfile.mkstemp(prefix=".requirements-", dir=path.parent)
    staging = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        _path(path)
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)
    return inspect_report(report_db)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for candidate in (path, Path(str(path) + "-wal")):
        if candidate.is_file() and not candidate.is_symlink():
            with candidate.open("rb") as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
    return digest.hexdigest()


def _metadata_check(value: Any) -> None:
    nodes = 0

    def visit(child: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 12 or nodes > 2048:
            raise ReportError("evidence metadata exceeds structural bounds")
        if isinstance(child, dict):
            if len(child) > 128:
                raise ReportError("evidence metadata exceeds structural bounds")
            for key, item in child.items():
                if not isinstance(key, str):
                    raise ReportError("evidence metadata requires text keys")
                if key.lower() in _UNSUPPORTED_KEYS or "mime" in key.lower() or "content_type" in key.lower():
                    raise ReportError("raw bodies and file attachments are unsupported")
                visit(item, depth + 1)
        elif isinstance(child, list):
            if len(child) > 128:
                raise ReportError("evidence metadata exceeds structural bounds")
            for item in child:
                visit(item, depth + 1)
        elif child is not None and not isinstance(child, (str, int, float, bool)):
            raise ReportError("evidence metadata requires JSON values")
    visit(value, 0)
    if len(canonical_json(value).encode()) > MAX_METADATA_BYTES:
        raise ReportError("evidence metadata exceeds the byte budget")


def _fields(draft, context: dict) -> tuple[dict[str, str], dict[str, str]]:
    common = {}
    for name in ("title", "asset", "weakness", "summary", "expected_behavior", "actual_behavior", "impact", "severity", "cvss_vector", "vrt_category"):
        cited = getattr(draft, name)
        common[name] = cited.text if cited else ""
    common["prerequisites"] = "\n".join(item.text for item in draft.prerequisites)
    common["steps_to_reproduce"] = "\n".join(f"{i}. {item.text}" for i, item in enumerate(draft.steps_to_reproduce, 1))
    common["remediation"] = draft.remediation or ""
    # Endpoint must come from explicit source metadata, never guessed from an asset.
    endpoints = []
    for item in context["validation"]["evidence"]:
        details = item.get("details", {})
        if isinstance(details, dict):
            candidate = details.get("endpoint") or details.get("url")
            if isinstance(candidate, str):
                endpoints.append(candidate)
    common["endpoint"] = endpoints[0] if endpoints else ""
    aliases = {"target": "asset", "vulnerability_type": "weakness", "description": "summary", "technical_severity": "severity", "demonstrated_impact": "impact"}
    all_fields = common | {key: common[value] for key, value in aliases.items()}
    if draft.platform == "bugcrowd":
        rename = {"asset": "target", "weakness": "vulnerability_type", "summary": "description", "severity": "technical_severity", "impact": "demonstrated_impact"}
    elif draft.platform == "intigriti":
        rename = {"weakness": "vulnerability_type", "summary": "description"}
    else:
        rename = {}
    fields = {rename.get(key, key): value for key, value in common.items() if key != "vrt_category" or draft.platform == "bugcrowd"}
    return fields, all_fields


def _template(template: str, values: dict[str, str]) -> str:
    pieces = []
    size = 0
    def append(value: str) -> None:
        nonlocal size
        size += len(value.encode())
        if size > MAX_MARKDOWN_BYTES:
            raise ReportError('template exceeds the rendered byte budget')
        pieces.append(value)
    try:
        for literal, field, format_spec, conversion in string.Formatter().parse(template):
            append(literal)
            if field is not None:
                if format_spec or conversion or field not in values or not values[field].strip():
                    raise ReportError("template contains an unknown or empty placeholder")
                append(values[field])
    except ValueError:
        raise ReportError("template contains invalid placeholders") from None
    return "".join(pieces)


def _masked_template(template: str | None, masker: _Masker) -> str | None:
    if template is None:
        return None
    pieces = []
    try:
        for literal, field, format_spec, conversion in string.Formatter().parse(template):
            pieces.append(masker.text(literal).replace('{', '{{').replace('}', '}}'))
            if field is not None:
                # Placeholder identifiers belong to the typed program schema.
                # Only simple placeholders are supported by the renderer.
                if format_spec or conversion or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', field):
                    raise ReportError('template contains invalid placeholders')
                pieces.append('{' + field + '}')
    except ValueError:
        raise ReportError('template contains invalid placeholders') from None
    return ''.join(pieces)


def _markdown(fields: dict[str, str], values: dict[str, str], requirements: dict, evidence: list[dict], attachment_ids: list[str]) -> str:
    if requirements["report_template"] is not None:
        body = _template(requirements["report_template"], values)
    else:
        body = "\n\n".join("## " + name.replace("_", " ").title() + "\n\n" + value for name, value in fields.items() if name != "title" and value)
    result = "# " + fields["title"] + "\n\n" + body
    if requirements["impact_template"] is not None:
        result += "\n\n## Program impact\n\n" + _template(requirements["impact_template"], values)
    if evidence:
        result += "\n\n## Evidence metadata\n\nText metadata only; raw HTTP bodies, images and videos are not included.\n"
        for i, item in enumerate(evidence, 1):
            label = " (requested attachment; metadata only)" if item["evidence_id"] in attachment_ids else ""
            result += f"\n- Evidence/evidence-{i:03d}.json{label}"
    result += '\n'
    if len(result.encode()) > MAX_MARKDOWN_BYTES:
        raise ReportError('report exceeds the rendered byte budget')
    return result


def inspect_report(report_db: Path) -> dict:
    """Recompute safe previews, source checks and revision on every inspection."""
    path = _path(report_db, existing=True)
    checks = []

    def block(code: str, message: str, field: str | None = None) -> None:
        checks.append({"code": code, "level": "blocker", "field": field, "message": message})

    requirements = ProgramRequirements()
    try:
        requirements = _requirements(path)
    except (ValueError, OSError, UnicodeError):
        block("program_requirements", "Program requirements are invalid or cannot be safely read.")
    if not requirements.verified:
        block("program_requirements", "Program requirements have not been verified.")

    run, context, stored = {}, {}, None
    source_fingerprint = "unavailable"
    try:
        run, context, stored, stale = case_runtime._load(path)
        if stale:
            block("source_integrity", "Current Validation source or scope eligibility differs from the report.")
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
        block("source_integrity", "Report or Validation source integrity could not be verified.")
        try:
            run, context, stored, _ = case_runtime._load(path, verify_source=False)
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            run, context, stored = {}, {}, None
    if run:
        try:
            source_path = _path(path.parent / run["source_path"], existing=True)
            current_source = case_runtime.read_verified_case(source_path, run["case_id"])
            source_fingerprint = canonical_sha256(current_source)
            if case_runtime._context(current_source, context["platform"]) != context:
                block("source_integrity", "Current Validation source or scope eligibility differs from the report.")
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError):
            block("source_integrity", "Current Validation source could not be verified.")
            try:
                source_fingerprint = _file_digest(_path(path.parent / run["source_path"], existing=True))
            except (ValueError, OSError):
                pass

    fields, aliases, evidence, attachment_ids = {}, {}, [], []
    evidence_bytes = 0
    if stored:
        try:
            draft = validate_draft(json.loads(stored["draft_json"]), context)
            fields, aliases = _fields(draft, context)
            attachment_ids = draft.attachment_evidence_ids
            for item in context["validation"]["evidence"]:
                try:
                    if not re.fullmatch(r"[0-9a-f]{64}", item["content_sha256"]):
                        block("source_integrity", "Evidence content digest is invalid.")
                        continue
                    if item["evidence_kind"] not in _TEXT_KINDS:
                        raise ReportError("unsupported evidence kind")
                    _metadata_check(item["details"])
                    evidence_bytes += len(canonical_json(item['details']).encode())
                    if evidence_bytes > MAX_EVIDENCE_BYTES or len(evidence) >= MAX_EVIDENCE_COUNT:
                        block('evidence_metadata', 'Evidence metadata exceeds the aggregate budget.')
                        break
                    evidence.append({"evidence_id": item["evidence_id"], "kind": item["evidence_kind"], "details": item["details"], "content_sha256": item["content_sha256"]})
                except (ValueError, TypeError, RecursionError):
                    block("evidence_metadata", "Evidence is oversized or contains unsupported raw content or attachments.")
        except (ValueError, KeyError, TypeError):
            block("draft_integrity", "The immutable draft or its evidence citations are invalid.")
    else:
        block("draft_required", "A valid immutable report draft is required.")

    raw_requirements = requirements.model_dump()
    known_paths = [str(path), str(path.parent)]
    if run.get('source_path'):
        known_paths.extend((run['source_path'], str((path.parent / run['source_path']).resolve())))
    masker = _Masker([fields, aliases, raw_requirements], seed=_writer_seed(context), paths=tuple(known_paths))
    fields = {key: masker.text(value) for key, value in fields.items()}
    aliases = {key: masker.text(value) for key, value in aliases.items()}
    public_requirements = {**raw_requirements, 'source': masker.text(requirements.source),
                           'additional_fields': {key: masker.text(value) for key, value in requirements.additional_fields.items()}}
    for key in ('report_template', 'impact_template'):
        try:
            public_requirements[key] = _masked_template(raw_requirements[key], masker)
        except ValueError:
            public_requirements[key] = masker.text(raw_requirements[key])
            block('program_template', 'Program template contains invalid, unknown or empty placeholders.')
    for key, value in public_requirements["additional_fields"].items():
        fields[key] = value
        aliases[key] = value
    evidence = [{**item, "details": masker.clean(item["details"])} for item in evidence]
    for item in evidence:
        item["sanitized_sha256"] = canonical_sha256(item["details"])

    if fields:
        mandatory = ["title", "asset", "weakness", "summary", "steps_to_reproduce", "expected_behavior", "actual_behavior", "impact"]
        if requirements.severity_required or context["platform"] == "bugcrowd":
            mandatory.append("severity")
        if context["platform"] == "bugcrowd":
            mandatory.append("vrt_category")
        mandatory += requirements.required_fields
        for name in dict.fromkeys(mandatory):
            if not aliases.get(name, "").strip():
                field = "technical_severity" if name == "severity" and context["platform"] == "bugcrowd" else name
                block("required_field", "A required submission field is missing.", field)
    markdown = ""
    if fields:
        try:
            markdown = _markdown(fields, aliases, public_requirements, evidence, attachment_ids)
        except ValueError:
            block("program_template", "Program template contains invalid, unknown or empty placeholders, or exceeds the byte budget.")
    checks.append({"code": "metadata_only", "level": "warning", "field": None, "message": "Evidence files contain text metadata only. Raw bodies, images and videos are unavailable; pattern masking cannot identify arbitrary unlabeled secrets."})
    checks.append({"code": "claim_quality", "level": "warning", "field": None, "message": "Field presence and evidence citations do not establish every report claim."})
    view = {"report_id": run.get("report_id", ""), "platform": context.get("platform", ""), "ready": not any(c["level"] == "blocker" for c in checks),
            "requirements": public_requirements, "fields": fields, "markdown": markdown, "evidence": evidence, "checks": checks,
            "redactions": [{"kind": kind, "count": count} for kind, count in sorted(masker.counts.items())]}
    if len(canonical_json(view).encode()) > MAX_PACKAGE_BYTES:
        block('submission_size', 'Submission exceeds the aggregate byte budget.')
        view['ready'] = False
        view['markdown'] = ''
        view['evidence'] = []
    view["revision_sha256"] = canonical_sha256({"policy": POLICY_VERSION, "profile": PROFILE_VERSION, "report_digest": _file_digest(path),
                                              "source_fingerprint": source_fingerprint, "requirements": raw_requirements, "view": view})
    return view


def export_report(report_db: Path, *, expected_revision: str | None = None) -> bytes:
    """Export only freshly checked files, bound to the revision shown to the user."""
    view = inspect_report(report_db)
    if expected_revision is not None and expected_revision != view["revision_sha256"]:
        raise ReportError("submission revision changed; inspect the report again")
    if not view["ready"]:
        raise ReportError("submission export is blocked by automatic checks")
    submission = {"report_id": view["report_id"], "platform": view["platform"], "revision_sha256": view["revision_sha256"],
                  "fields": view["fields"], "requirements": view["requirements"], "evidence_files": [f"Evidence/evidence-{i:03d}.json" for i in range(1, len(view["evidence"]) + 1)]}
    files = {"Report.md": view["markdown"].encode(), "Submission.json": (canonical_json(submission) + "\n").encode()}
    for i, evidence in enumerate(view["evidence"], 1):
        files[f"Evidence/evidence-{i:03d}.json"] = (canonical_json(evidence) + "\n").encode()
    manifest = {"schema_version": 1, "report_id": view["report_id"], "platform": view["platform"], "revision_sha256": view["revision_sha256"],
                "masking_policy": POLICY_VERSION, "profile_version": PROFILE_VERSION, "evidence_format": "text metadata only",
                "files": [{"name": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)} for name, data in files.items()],
                "evidence": [{"evidence_id": item["evidence_id"], "kind": item["kind"], "content_sha256": item["content_sha256"], "sanitized_sha256": item["sanitized_sha256"], "status": "metadata_sanitized"} for item in view["evidence"]],
                "checks": view["checks"], "redactions": view["redactions"]}
    files["Manifest.json"] = (canonical_json(manifest) + "\n").encode()
    if sum(len(data) for data in files.values()) > MAX_PACKAGE_BYTES:
        raise ReportError('submission package exceeds the byte budget')
    # A second inspection catches changes during package preparation.
    current = inspect_report(report_db)
    if not current["ready"] or current["revision_sha256"] != view["revision_sha256"]:
        raise ReportError("submission revision changed during export")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, data)
    return output.getvalue()
