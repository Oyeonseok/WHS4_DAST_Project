"""Grounded execution restrictions and operator prerequisite validation."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Callable, Final
from uuid import uuid4
from aidast.scope.models import ScopeAnalysis, ScopeDocument, ScopeExecutionInterpretation, ScopeExecutionRules, MAX_POLICY_REFERENCE_EDGES
from aidast.core.http_safety import validate_platform_username

DEFAULT_SCOPE_MODEL: Final = "gpt-5.6-sol"


def validate_policy_prerequisites(rules: ScopeExecutionRules | None, selected_assets: list[str],
                                  values: dict[str, str] | None = None, confirmations: list[str] | None = None):
    if rules is None:
        raise ValueError('Scope execution requirements need AI interpretation before launch')
    rules = ScopeExecutionRules.model_validate(rules.model_dump())
    selected = set(selected_assets)
    blockers = applicable_blockers(rules, selected)
    if blockers:
        raise ValueError('unsupported mandatory requirements: ' + '; '.join(i.label for i in blockers))
    if rules.allowed_target_assets and not selected <= set(rules.allowed_target_assets.values):
        raise ValueError('selected target is prohibited by execution requirements')
    values, confirmations = dict(values or {}), list(confirmations or [])
    declared = {i.key for i in rules.required_inputs}
    known = {i.key for i in rules.required_confirmations}
    if set(values) - declared or set(confirmations) - known or len(confirmations) != len(set(confirmations)):
        raise ValueError('unknown or duplicate policy prerequisites')
    def applies(item):
        return not item.target_assets or bool(selected.intersection(item.target_assets))
    evidence = {'input_keys': [], 'confirmation_keys': []}
    for item in rules.required_inputs:
        if not applies(item):
            continue
        value = values.get(item.key)
        if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f'policy input {item.key} is required and must be bounded text')
        value = value.strip()
        if item.kind == 'username':
            validate_platform_username(value, item.label)
        if item.kind == 'email':
            if value.count('@') != 1 or any(c.isspace() for c in value) or not all(value.split('@')):
                raise ValueError(f'invalid email for policy input {item.key}')
            if item.allowed_email_domains and value.split('@')[1].casefold() not in {d.casefold() for d in item.allowed_email_domains}:
                raise ValueError(f'email domain is not allowed for policy input {item.key}')
        evidence['input_keys'].append(item.key)
    for item in rules.required_confirmations:
        if applies(item):
            if item.key not in confirmations:
                raise ValueError(f'policy confirmation {item.key} is required')
            evidence['confirmation_keys'].append(item.key)
    return evidence


def applicable_blockers(rules: ScopeExecutionRules, selected_assets):
    selected = set(selected_assets)
    return [item for item in rules.blocking_requirements
            if not item.target_assets or selected.intersection(item.target_assets)]


EXECUTION_INTERPRETATION_VERSION = "4"
MAX_FRESH_INTERPRETATION_BYTES = 262144
# Each generated edge reserves a 16k-character quote (including JSON escapes),
# bounded error/reason and static guidance. Raw model output retains its own cap.
MAX_CACHED_INTERPRETATION_BYTES = MAX_FRESH_INTERPRETATION_BYTES + MAX_POLICY_REFERENCE_EDGES * 102400


def execution_interpretation_complete(analysis: ScopeAnalysis) -> bool:
    """Structural freshness check only; does not read caches or call an agent."""
    return (analysis.required_request_headers is not None
            and analysis.execution_rules is not None
            and analysis.execution_rules.exclusions is not None)


def requires_policy_advisory_review(document: ScopeDocument) -> bool:
    """Read-only freshness check; preparation performs any required model call."""
    rules = document.analysis.execution_rules
    return bool(rules and rules.policy_review_version < 2 and
                (document.source.policy_references or rules.blocking_requirements))


def render_execution_advisories(rules: ScopeExecutionRules) -> str:
    """Render effective per-scan guidance without mutating approved Scope bytes."""
    if not rules.advisories:
        return ''
    def clean(value):
        return ' '.join(str(value).split())
    lines = ['## Policy advisories', '']
    for item in rules.advisories:
        lines.append(f'- **{clean(item.label)}:** {clean(item.reason)}')
        lines.append('  - Applies to: ' + (', '.join(clean(v) for v in item.target_assets) or 'all selected targets'))
        lines.append('  - Source: ' + clean(item.source_quote))
        lines.append('  - Guidance: ' + clean(item.guidance))
    return '\n'.join(lines) + '\n'


class ScopeExecutionResolver:
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
        return hashlib.sha256((EXECUTION_INTERPRETATION_VERSION + "\n" + document.model_dump_json()).encode()).hexdigest()

    def cache_path(self, document: ScopeDocument) -> Path:
        return self.cache_dir / f'{self.digest(document)}.json'

    def _validate(self, document: ScopeDocument, result, *, fresh: bool = False) -> ScopeAnalysis:
        response = result if isinstance(result, ScopeExecutionInterpretation) else ScopeExecutionInterpretation.model_validate(result)
        if response.execution_rules.exclusions is None:
            raise ValueError('fresh Scope execution interpretation must supply exclusions ([] when none)')
        data = document.analysis.model_dump()
        budget = MAX_FRESH_INTERPRETATION_BYTES if fresh else MAX_CACHED_INTERPRETATION_BYTES
        if len(response.model_dump_json().encode("utf-8")) > budget:
            raise ValueError('execution interpretation exceeds response budget')
        data.update(response.model_dump())
        # Legacy source_evidence may omit operational rules. Ground new quotes
        # against the unchanged captured page, then add evidence in memory only.
        for item in [*response.required_request_headers, *response.execution_rules.quoted_requirements()]:
            if item.source_quote not in document.source.evidence_text:
                raise ValueError('AI header requirement quote is absent from approved captured text')
            data['source_evidence'].append({'section': 'Required request header', 'quote': item.source_quote})
        analysis = ScopeAnalysis.model_validate(data)
        if fresh:
            from aidast.scope.policy_references import require_unresolved_testing_holds
            reviewed = require_unresolved_testing_holds(document.source, analysis)
            return self._validate(document, ScopeExecutionInterpretation(
                required_request_headers=reviewed.required_request_headers or [],
                execution_rules=reviewed.execution_rules))
        return analysis

    def cached(self, document: ScopeDocument) -> ScopeAnalysis | None:
        try:
            path = self.cache_path(document)
            if path.stat().st_size > MAX_CACHED_INTERPRETATION_BYTES:
                raise ValueError('execution cache exceeds budget')
            cached = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(cached, dict):
                raise ValueError('invalid execution cache')
            if cached.get('interpretation_version') != EXECUTION_INTERPRETATION_VERSION or cached['approved_digest'] != self.digest(document):
                raise ValueError('stale execution cache')
            requirements = ScopeExecutionInterpretation.model_validate(cached['requirements'])
            if requirements.execution_rules.policy_review_version != 2:
                raise ValueError('execution cache lacks policy advisory review')
            return self._validate(document, requirements)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        if execution_interpretation_complete(document.analysis) and not requires_policy_advisory_review(document):
            try:
                return self._validate(document, ScopeExecutionInterpretation(
                    required_request_headers=document.analysis.required_request_headers,
                    execution_rules=document.analysis.execution_rules))
            except (ValueError, TypeError):
                pass
        return None

    def resolve(self, document: ScopeDocument) -> ScopeAnalysis:
        cached = self.cached(document)
        if cached is not None:
            return cached
        if len(document.source.evidence_text) > self.max_page_chars:
            raise ValueError('approved Scope text exceeds the execution interpretation budget')
        try:
            interpreter = self.interpreter
            if interpreter is None:
                from aidast.agents.main import CodexMainAgent
                interpreter = CodexMainAgent(main_model=DEFAULT_SCOPE_MODEL).interpret_scope_execution_requirements
            analysis = self._validate(document, interpreter(document.source), fresh=True)
        except Exception as exc:
            raise ValueError('Scope execution requirements AI interpretation failed; resolve requirements before launch') from exc
        response = ScopeExecutionInterpretation(required_request_headers=analysis.required_request_headers or [], execution_rules=analysis.execution_rules)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self.cache_path(document)
        temporary = path.with_name(f'.{path.name}.{uuid4().hex}.tmp')
        try:
            temporary.write_text(json.dumps({'approved_digest': self.digest(document), 'interpretation_version': EXECUTION_INTERPRETATION_VERSION, 'requirements': response.model_dump()}, ensure_ascii=False), encoding='utf-8')
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        return analysis


def bind_execution_policies(policies, rules: ScopeExecutionRules | None, *, result_root: Path,
                            program_url: str, scan_id: str | None, prerequisite_evidence: dict):
    """Intersect verified policies and attach one application-owned scan budget."""
    from aidast.recon.policy import TargetPolicy, RequestGovernorBinding
    from aidast.scope.paths import identify_program
    if rules is None or applicable_blockers(rules, [policy.asset for policy in policies.values()]):
        raise ValueError('execution rules are unresolved or contain mandatory blockers')
    narrowed = {}
    for key, policy in policies.items():
        if rules.allowed_target_assets and policy.asset not in rules.allowed_target_assets.values:
            raise ValueError('target is prohibited by execution requirements')
        data = policy.model_dump()
        for item in rules.option_limits:
            if item.field in data['limits']:
                data['limits'][item.field] = min(data['limits'][item.field], item.value)
            elif item.field in data['tools']:
                data['tools'][item.field] = data['tools'][item.field] and item.value
        periodic = [i.maximum / i.period_seconds for i in rules.request_limits if i.period_seconds is not None]
        if periodic:
            data['limits']['requests_per_second'] = min(data['limits']['requests_per_second'], *periodic)
        if rules.allowed_methods:
            allowed = set(rules.allowed_methods.values)
            if policy.execution_allowed_methods is not None:
                allowed.intersection_update(policy.execution_allowed_methods)
            data['execution_allowed_methods'] = sorted(allowed)
            for field in ('allowed_methods', 'attack_allowed_methods'):
                data[field] = [method for method in data[field] if method in allowed]
                if not data[field]:
                    raise ValueError('execution method intersection is empty')
            if not set(data['attack_allowed_methods']) - {'GET', 'HEAD', 'OPTIONS'}:
                data['attack_authorization_mode'] = 'read_only'
                data['attack_authorization_evidence'] = None
        applicable = [item for item in rules.advisories
                      if not item.target_assets or policy.asset in item.target_assets]
        for item in applicable:
            note = render_execution_advisories(rules.model_copy(update={'advisories': [item]}))
            if note not in data['policy_notes']:
                data['policy_notes'].append(note)
        from aidast.scope.exclusion_guidance import agent_exclusion_advisories, render_agent_exclusion_note
        for item in agent_exclusion_advisories(rules, policy.asset):
            note = render_agent_exclusion_note(item)
            if note not in data['policy_notes']:
                data['policy_notes'].append(note)
        data['policy_prerequisite_evidence'] = prerequisite_evidence
        narrowed[key] = TargetPolicy.model_validate(data)
    if not narrowed:
        raise ValueError('execution requires at least one verified target policy')
    if scan_id is not None:
        # identify_program normalizes supported platform URLs, including query noise.
        program = identify_program(program_url)
        namespace = hashlib.sha256(f'{program.platform}/{program.program}'.encode()).hexdigest()
        deadline = next((i.value for i in rules.option_limits if i.field == 'max_scan_seconds'), None)
        ledger_dir = Path(result_root).resolve() / '.policy-budgets'
        ledger_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        binding = RequestGovernorBinding(
            ledger_path=str(ledger_dir / f'{namespace}.db'),
            scan_id=scan_id, program_id=namespace,
            scan_max_requests=min(p.limits.max_requests for p in narrowed.values()),
            scan_max_seconds=deadline, requests_per_second=min(p.limits.requests_per_second for p in narrowed.values()),
            concurrency=min(p.limits.concurrency for p in narrowed.values()), request_limits=rules.request_limits)
        narrowed = {key: policy.model_copy(update={'request_governor': binding}) for key, policy in narrowed.items()}
    return narrowed


def validate_shared_policy_values(analysis: ScopeAnalysis, identity_values: dict, policy_values: dict):
    """Shared declarations must describe the same operator supplied value."""
    analysis = ScopeAnalysis.model_validate(analysis.model_dump())
    headers = {item.key for header in analysis.required_request_headers or [] for item in header.inputs}
    inputs = {item.key for item in analysis.execution_rules.required_inputs} if analysis.execution_rules else set()
    for key in headers & inputs & identity_values.keys() & policy_values.keys():
        if identity_values[key].strip() != policy_values[key].strip():
            raise ValueError(f'conflicting header and policy values for shared input {key}')
