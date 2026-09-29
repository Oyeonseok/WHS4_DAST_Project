"""Validate AI-declared header templates and bind operator supplied input values."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable
from uuid import uuid4

from aidast.core.http_safety import validate_identity_header_value, validate_identity_headers, validate_platform_username
from aidast.scope.models import ScopeAnalysis, ScopeDocument, ScopeHeaderRequirements


def required_identity_header_names(analysis: ScopeAnalysis) -> tuple[str, ...]:
    if analysis.required_request_headers is None:
        raise ValueError('approved Scope header requirements need AI interpretation before launch')
    validated = ScopeAnalysis.model_validate(analysis.model_dump())
    return tuple(item.name for item in validated.required_request_headers or [])


def resolve_scope_identity_headers(analysis: ScopeAnalysis, *, identity_values: dict[str, str] | None = None,
                                   hackerone_username: str | None = None, intigriti_username: str | None = None,
                                   require_values: bool = True) -> dict[str, str]:
    required_identity_header_names(analysis)
    values = dict(identity_values or {})
    for key, value in [('hackerone_username', hackerone_username), ('intigriti_username', intigriti_username)]:
        if value is not None:
            if key in values and values[key] != value:
                raise ValueError(f'conflicting values for header input {key}')
            values[key] = value
    declarations = {item.key: item for spec in analysis.required_request_headers or [] for item in spec.inputs}
    unused_aliases = [value for key, value in [('hackerone_username', hackerone_username), ('intigriti_username', intigriti_username)]
                      if value is not None and key not in declarations]
    unresolved = [key for key, item in declarations.items() if item.kind == 'username' and key not in values]
    if unused_aliases and unresolved:
        if len(unused_aliases) == len(unresolved) == 1:
            values[unresolved[0]] = unused_aliases[0]
        else:
            raise ValueError('ambiguous platform username aliases; supply --header-input KEY=VALUE')
    headers = {}
    for spec in analysis.required_request_headers or []:
        bound = {}
        for item in spec.inputs:
            value = values.get(item.key)
            if value is None or not isinstance(value, str) or not value.strip():
                if require_values:
                    alias_hint = f' (or --{item.key.replace("_", "-")})' if item.key in {"hackerone_username", "intigriti_username"} else ""
                    raise ValueError(f'approved Scope requires {spec.name}; supply --header-input {item.key}=VALUE{alias_hint}')
                break
            if len(value) > 256:
                raise ValueError(f'header input {item.key} exceeds 256 characters')
            value = validate_identity_header_value(value.strip())
            if item.kind == 'username':
                value = validate_platform_username(value, item.label)
            elif item.kind == 'email' and (value.count('@') != 1 or any(c.isspace() for c in value) or not all(value.split('@'))):
                raise ValueError(f'invalid email for header input {item.key}')
            bound[item.key] = value
        else:
            headers[spec.name] = spec.value_template.format_map(bound)
    return validate_identity_headers(headers)


HEADER_INTERPRETATION_VERSION = "1"


class ScopeHeaderResolver:
    """Separate digest-bound cache for immutable approved legacy documents.

    The injectable interpreter receives only the approved captured ProgramPage;
    list/cache reads never execute it. The production adapter disables browsing
    and bounds both text and model runtime.
    """
    def __init__(self, cache_dir: Path, interpreter: Callable | None = None, *, max_page_chars: int = 120000):
        self.cache_dir = Path(cache_dir)
        self.interpreter = interpreter
        self.max_page_chars = max_page_chars

    @staticmethod
    def digest(document: ScopeDocument) -> str:
        return hashlib.sha256((HEADER_INTERPRETATION_VERSION + "\n" + document.model_dump_json()).encode()).hexdigest()

    def cache_path(self, document: ScopeDocument) -> Path:
        return self.cache_dir / f'{self.digest(document)}.json'

    def _validate(self, document: ScopeDocument, result) -> ScopeAnalysis:
        response = result if isinstance(result, ScopeHeaderRequirements) else ScopeHeaderRequirements.model_validate(result)
        data = document.analysis.model_dump()
        data['required_request_headers'] = response.model_dump()['required_request_headers']
        # Legacy source_evidence may omit operational rules. Ground new quotes
        # against the unchanged captured page, then add evidence in memory only.
        for item in response.required_request_headers:
            if item.source_quote not in document.source.evidence_text:
                raise ValueError('AI header requirement quote is absent from approved captured text')
            data['source_evidence'].append({'section': 'Required request header', 'quote': item.source_quote})
        return ScopeAnalysis.model_validate(data)

    def cached(self, document: ScopeDocument) -> ScopeAnalysis | None:
        if document.analysis.required_request_headers is not None:
            return ScopeAnalysis.model_validate(document.analysis.model_dump())
        try:
            path = self.cache_path(document)
            if path.stat().st_size > 262144:
                return None
            cached = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(cached, dict):
                return None
            if cached.get('interpretation_version') != HEADER_INTERPRETATION_VERSION or cached['approved_digest'] != self.digest(document):
                return None
            return self._validate(document, cached['requirements'])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def resolve(self, document: ScopeDocument) -> ScopeAnalysis:
        cached = self.cached(document)
        if cached is not None:
            return cached
        if len(document.source.evidence_text) > self.max_page_chars:
            raise ValueError('approved Scope text exceeds the header interpretation budget')
        try:
            interpreter = self.interpreter
            if interpreter is None:
                from aidast.agents.main import CodexMainAgent
                interpreter = CodexMainAgent().interpret_scope_header_requirements
            analysis = self._validate(document, interpreter(document.source))
        except Exception as exc:
            raise ValueError('Scope header requirements AI interpretation failed; resolve requirements before launch') from exc
        response = ScopeHeaderRequirements(required_request_headers=analysis.required_request_headers or [])
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self.cache_path(document)
        temporary = path.with_name(f'.{path.name}.{uuid4().hex}.tmp')
        try:
            temporary.write_text(json.dumps({'approved_digest': self.digest(document), 'interpretation_version': HEADER_INTERPRETATION_VERSION, 'requirements': response.model_dump()}, ensure_ascii=False), encoding='utf-8')
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        return analysis
