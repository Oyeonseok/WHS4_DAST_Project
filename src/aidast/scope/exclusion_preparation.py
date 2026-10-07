"""Shared offline exclusion preparation for new CLI and dashboard executions.

Only verified approved Scope/run associations and complete physical HTTP receipts
produce semantic candidates. Endpoint annotations and legacy redacted transactions
never do. This module has no network or browser capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from aidast.core.capture_receipt import prepare_http_request, validate_capture_receipt
from aidast.core.exclusion_guard import evaluate_exclusions, exclusion_applicability, _url
from aidast.scope.exclusion_binding import ExclusionBindingResolver
from aidast.scope.exclusions import ResourceCandidate, ResourceEvidence
from aidast.scope.execution_rules import execution_interpretation_complete
from aidast.scope.exclusion_guidance import (
    split_exclusion_enforcement, agent_exclusion_advisories, render_agent_exclusion_note,
)
from aidast.recon.policy import validate_start_url_for_target
from aidast.scope.models import AssetType

MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = 262144
MAX_SNAPSHOT_BYTES = 524288
MAX_CANDIDATES = 256


def approved_scope_digest(document):
    """Identity of the original approved document, never the in-memory v3 overlay."""
    return hashlib.sha256(document.model_dump_json().encode()).hexdigest()


def _safe_path(path):
    path = Path(path).absolute()
    if any(p.is_symlink() and not (p.parent == Path(p.anchor) and p.lstat().st_uid == 0)
           for p in (path, *path.parents)):
        raise ValueError('symlink capture paths are not trusted')
    return path.resolve()


def capture_databases(result_root):
    root = _safe_path(result_root)
    paths = [root / name for name in ('Recon.db','Pipeline.db') if (root / name).is_file()]
    for directory, name in [('Runs','Recon.db'),('AttackRuns','Pipeline.db')]:
        runs = root / directory
        if runs.exists():
            for path in runs.rglob(name):
                paths.append(_safe_path(path))
    # Long-lived dashboards naturally accumulate more than 64 completed runs.
    # Preparation consumes a bounded recent window; history volume must not
    # prevent a new scan from starting.  Scope and target association checks in
    # load_capture_snapshot still decide whether each selected DB is usable.
    unique = set(paths)
    return sorted(
        unique,
        key=lambda path: (path.stat().st_mtime_ns, str(path)),
        reverse=True,
    )[:64]


def _origin(url):
    parsed = urlsplit(url)
    return (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))


def validate_captured_request_for_target(url, *, target):
    """Captured requests retain queries; operator start-URL restrictions do not apply."""
    _url(url)  # Reject userinfo, fragments, malformed query escapes and ambiguous paths.
    parsed=urlsplit(url)
    scope_path=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))
    validate_start_url_for_target(scope_path,asset_type=target.asset_type,asset=target.asset)


def _public_url(url):
    from aidast.attack.store import _redact
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, _redact(parsed.path),
        urlencode([(name, '[REDACTED]') for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]), ''))


@dataclass
class CaptureSnapshot:
    candidates: list[ResourceCandidate] = field(default_factory=list)
    evidence: list[ResourceEvidence] = field(default_factory=list)
    rejected: int = 0


def load_capture_snapshot(database_paths, *, document, target):
    """Read standalone SQLite captures without schema migration or source writes."""
    if target.asset not in {item.asset for item in document.analysis.in_scope_assets}:
        raise ValueError('capture target is not in the approved Scope')
    result = CaptureSnapshot()
    seen = {}; total = 0
    if len(database_paths) > 64:
        raise ValueError('capture database count exceeds preparation budget')
    for supplied in database_paths:
        path = _safe_path(supplied)
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_DATABASE_BYTES or any(Path(str(path)+suffix).exists() for suffix in ('-wal','-journal')):
            result.rejected += 1; continue
        try:
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1', uri=True)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute('PRAGMA query_only=ON')
                columns = {r[1] for r in conn.execute('PRAGMA table_info(http_transactions)')}
                if 'request_receipt' not in columns:
                    result.rejected += 1; continue
                origin_join = 'COALESCE(t.origin_id,e.origin_id)' if 'origin_id' in columns else 'e.origin_id'
                rows=conn.execute(f'''SELECT t.*,s.scan_id,o.base_url,a.identifier,e.origin_id AS endpoint_origin,
                       o.origin_id AS actual_origin FROM http_transactions t
                    LEFT JOIN endpoints e ON e.endpoint_id=t.endpoint_id
                    JOIN origins o ON o.origin_id={origin_join}
                    JOIN assets a ON a.asset_id=o.asset_id JOIN scans s ON s.scan_id=a.scan_id
                    WHERE s.scope_type='approved_scope' AND s.scope_value=?
                      AND t.request_receipt IS NOT NULL
                      AND length(t.response_body)<=? AND length(COALESCE(t.request_body,''))<=262144
                      AND length(t.request_receipt)<=8192
                      AND length(t.url)<=16384 AND length(COALESCE(t.request_headers,''))<=65536
                    ORDER BY t.captured_at DESC LIMIT ?''',
                    (document.scope_id, MAX_CAPTURE_BYTES, MAX_CANDIDATES+1))
                for row in rows:
                    try:
                        if row['endpoint_origin'] is not None and row['endpoint_origin'] != row['actual_origin']:
                            raise ValueError('capture has conflicting origin associations')
                        # Original approved asset or discovered child bound to that exact target.
                        validate_captured_request_for_target(row['url'],target=target)
                        validate_start_url_for_target(row['base_url'],asset_type=target.asset_type,asset=target.asset)
                        if row['identifier'] != target.asset and target.asset_type is not AssetType.WILDCARD:
                            raise ValueError('capture asset association differs from target')
                        if _origin(row['url']) != _origin(row['base_url']):
                            raise ValueError('capture URL differs from recorded origin')
                        response = row['response_body']
                        if not isinstance(response, bytes) or not response:
                            raise ValueError('missing captured response bytes')
                        receipt = validate_capture_receipt(json.loads(row['request_receipt']),
                            url=row['url'],method=row['method'],response_body=response)
                        if receipt['body_bytes'] > MAX_CAPTURE_BYTES:
                            raise ValueError('captured request body exceeds preparation budget')
                        if receipt['captured_at'] > time.time():
                            raise ValueError('future capture timestamp cannot support binding')
                        previous = seen.get(receipt['request_key'])
                        if previous is not None and receipt['captured_at'] <= result.evidence[previous].captured_at:
                            continue
                        if previous is None and len(result.candidates) >= MAX_CANDIDATES:
                            raise ValueError('capture candidate count exceeds budget')
                        from aidast.attack.store import _redact
                        text = response.decode('utf-8', errors='strict')
                        try:
                            excerpt = json.dumps(_redact(json.loads(text)),ensure_ascii=False)
                        except (ValueError, TypeError):
                            excerpt = _redact(text)
                        # Treat all non-public captured header values as sensitive, including
                        # arbitrary program identity headers; redact echoes before model use.
                        stored_headers=json.loads(row['request_headers'] or '{}')
                        for name,value in stored_headers.items():
                            if name.casefold() not in {'content-type','content-length','host','accept','accept-encoding','connection','user-agent'} and isinstance(value,str) and value and value!='[REDACTED]':
                                excerpt=excerpt.replace(value,'[REDACTED]')
                        excerpt=excerpt[:16000]
                        public_url=_public_url(row['url'])
                        token=hashlib.sha256((str(path)+'\n'+row['scan_id']+'\n'+row['http_transaction_id']).encode()).hexdigest()
                        cid, eid='candidate_'+token, 'evidence_'+token
                        candidate=ResourceCandidate(candidate_id=cid,request_key=receipt['request_key'],
                            url=public_url,method=row['method'],public_headers={},
                            body_sha256=receipt['body_sha256'],body_preview=None,evidence_ids=[eid])
                        evidence=ResourceEvidence(evidence_id=eid,candidate_ids=[cid],source_url=public_url,
                            kind='captured_response',content_sha256=receipt['response_sha256'],excerpt=excerpt,
                            captured_at=float(receipt['captured_at']))
                        size=len(candidate.model_dump_json().encode())+len(evidence.model_dump_json().encode())
                        prior_size = 0 if previous is None else (
                            len(result.candidates[previous].model_dump_json().encode())
                            + len(result.evidence[previous].model_dump_json().encode()))
                        if total-prior_size+size>MAX_SNAPSHOT_BYTES:
                            raise ValueError('capture evidence exceeds preparation budget')
                        total+=size-prior_size
                        if previous is None:
                            seen[receipt['request_key']]=len(result.candidates)
                            result.candidates.append(candidate); result.evidence.append(evidence)
                        else:
                            result.candidates[previous]=candidate; result.evidence[previous]=evidence
                    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
                        result.rejected += 1
        except sqlite3.Error:
            result.rejected += 1
    return result


@dataclass(frozen=True)
class StartupOperation:
    """Application-selected essential startup capability, never model-supplied wire data."""
    capability: str
    url: str | None = None


def normalize_start_urls(start_urls, *, preserve_wildcard_starts=False):
    """Keep wildcard starts only when the selected profile intentionally narrows them."""
    return {
        key: value for key, value in (start_urls or {}).items()
        if preserve_wildcard_starts or key[0] != AssetType.WILDCARD.value
    }


def selected_startup_operations(
    targets, *, start_urls=None, plan=None, preserve_wildcard_starts=False,
):
    """Represent known startup operations; an unplanned DOMAIN/IP is not a GET.

    A completed plan proves whether DNS/port/discovery tools are required. Until
    then only a concrete URL/API probe has a known app-owned HTTP descriptor.
    Browser/endpoint-first plans have no complete startup descriptor here.
    """
    starts=normalize_start_urls(
        start_urls, preserve_wildcard_starts=preserve_wildcard_starts,
    )
    planned={} if plan is None else {(item.asset_type.value,item.asset):item for item in plan.targets}
    result={}
    for target in targets:
        key=(target.asset_type.value,target.asset)
        url=starts.get(key)
        if url is None and target.asset_type in {AssetType.URL,AssetType.API}:
            url=target.asset if target.asset.startswith(('http://','https://')) else None
        if plan is None:
            if target.asset_type is AssetType.WILDCARD and url:
                operations=[StartupOperation('HTTP_PROBE',url)]
            elif target.asset_type is AssetType.WILDCARD:
                operations=[StartupOperation('ASSET_DISCOVERY')]
            elif target.asset_type in {AssetType.URL,AssetType.API} and url:
                operations=[StartupOperation('HTTP_PROBE',url)]
            else:
                operations=[StartupOperation('UNKNOWN_STARTUP')]
        elif key not in planned:
            operations=[]
        else:
            if url is None and target.asset_type in {AssetType.DOMAIN,AssetType.IP_ADDRESS}:
                url='https://'+target.asset
            steps=[step.value for step in planned[key].steps]
            if target.asset_type in {AssetType.URL, AssetType.API}:
                # Exact web targets never execute DNS/port discovery.  Ignore
                # incompatible model-proposed steps here as a defensive policy
                # boundary as well as normalizing them in the CLI plan.
                steps=[step for step in steps if step not in {
                    'ASSET_DISCOVERY','DNS_RESOLUTION','HOST_PORT_DISCOVERY'}]
            operations=[StartupOperation(step,url if step=='HTTP_PROBE' else None)
                for step in steps if step in {'ASSET_DISCOVERY','DNS_RESOLUTION','HOST_PORT_DISCOVERY','HTTP_PROBE'}]
            if not operations and steps:
                operations=[StartupOperation(steps[0])]
        result[target.asset]=operations
    return result


def _startup_diagnostics(compiled, operations, *, headers=None, seed_identity_complete=True, policy=None, login_mode=None):
    relevant=[rule.key for rule in compiled.rules
              if exclusion_applicability(rule.model_dump(mode='json'), compiled.target_asset) != 'disjoint']
    if login_mode=='system-browser' and compiled.rules:
        return [dict(target_asset=compiled.target_asset,url=None,capability='SYSTEM_BROWSER',decision='hold',
            rule_keys=[rule.key for rule in compiled.rules],
            reason='system-browser cannot enforce exclusions; use a governed runtime browser or an existing session bundle')]
    operations=operations or [StartupOperation('MISSING_STARTUP')]
    diagnostics=[]
    for operation in operations:
        url=operation.url
        if operation.capability!='HTTP_PROBE' or not url:
            held=bool(relevant) or operation.capability=='MISSING_STARTUP' or operation.capability=='HTTP_PROBE'
            decision=dict(decision='hold' if held else 'continue',rule_keys=relevant,
                reason=f'{operation.capability} startup has no complete enforceable request descriptor' if held else 'No applicable exclusions')
        elif policy is not None and not policy.allows_url(url,method='GET'):
            decision=dict(decision='hold',rule_keys=relevant,reason='generated TargetPolicy does not authorize the selected initial request')
        else:
            final_headers={'User-Agent':'aidast-recon/0.1',**(headers or {})}
            if policy is not None:
                from aidast.core.http_safety import merge_hackerone_identity
                final_headers=merge_hackerone_identity(final_headers,policy.hackerone_username,
                    required_identity_headers=policy.required_identity_headers)
            descriptor=prepare_http_request(url,headers=final_headers)
            data=compiled.model_dump(mode='json')
            if not seed_identity_complete:
                data['semantic_bindings']=[]
            decision=evaluate_exclusions(data,**descriptor,body_available=True)
        diagnostics.append({'target_asset':compiled.target_asset,'url':_public_url(url) if url else None,
                            'capability':operation.capability,**decision})
    return diagnostics


@dataclass
class ExclusionPreparation:
    policies: dict
    diagnostics: list[dict]
    captured_candidates: int = 0
    rejected_captures: int = 0
    startup_operations: dict[str,list[StartupOperation]] = field(default_factory=dict)
    login_mode: str | None = None
    agent_guidance: dict[str, list[dict]] = field(default_factory=dict)

    def public(self):
        return {'resources':self.diagnostics, 'captured_candidates':self.captured_candidates,
                'rejected_captures':self.rejected_captures,
                'agent_guidance': [item for items in self.agent_guidance.values() for item in items],
                'held':sum(d['decision']=='hold' for d in self.diagnostics),
                'denied':sum(d['decision']=='deny' for d in self.diagnostics)}

    def require_ready(self):
        covered={item.get('target_asset') for item in self.diagnostics}
        if not self.policies or not self.diagnostics or set(self.policies)-covered:
            raise ValueError('selected startup request descriptors are missing; preparation is not ready')
        blocked=[d for d in self.diagnostics if d['decision']!='continue']
        if blocked:
            raise ValueError('Exclusion preparation requires offline review: '+ '; '.join(
                f"{item['decision']} [{', '.join(item['rule_keys'])}]: {item['reason']}" for item in blocked))

    def reconcile_startup(self, operations, *, headers=None, seed_identity_complete=True):
        """Replace provisional readiness with the actual completed plan's capabilities."""
        self.startup_operations=operations
        self.diagnostics=[item for asset,compiled in self.policies.items()
            for item in _startup_diagnostics(compiled,operations.get(asset),headers=headers,
                seed_identity_complete=seed_identity_complete,login_mode=self.login_mode)]
        return self.diagnostics

    def inspect_policy_starts(self, policies, start_urls, *, headers=None, seed_identity_complete=True):
        """Publish final policy identity diagnostics for both offline inspection and execution."""
        starts=normalize_start_urls(start_urls)
        by_asset={policy.asset:policy for policy in policies.values()}
        checked=[]
        for asset,compiled in self.policies.items():
            policy=by_asset.get(asset)
            if policy is None:
                operations=[]
            else:
                operations=self.startup_operations.get(asset,[])
                key=(policy.asset_type.value,policy.asset)
                if policy.asset_type in {AssetType.DOMAIN,AssetType.IP_ADDRESS} and key not in starts:
                    operations=[StartupOperation(op.capability,policy.allowed_schemes[0]+'://'+policy.asset)
                        if op.capability=='HTTP_PROBE' else op for op in operations]
            checked.extend(_startup_diagnostics(compiled,operations,headers=headers,
                seed_identity_complete=seed_identity_complete,policy=policy,login_mode=self.login_mode))
        self.diagnostics=checked
        return checked

    def require_policy_starts_ready(self, policies, start_urls, *, headers=None, seed_identity_complete=True):
        self.inspect_policy_starts(policies,start_urls,headers=headers,seed_identity_complete=seed_identity_complete)
        self.require_ready()

    def attach(self, policies):
        result = {}
        for key, policy in policies.items():
            notes = list(policy.policy_notes)
            for item in self.agent_guidance.get(policy.asset, []):
                note = render_agent_exclusion_note(item)
                if note not in notes:
                    notes.append(note)
            result[key] = policy.model_copy(update={
                'request_exclusions': self.policies[policy.asset], 'policy_notes': notes})
        return result


def prepare_exclusions(*, document, analysis, targets, result_root, start_urls=None, headers=None,
                       login_mode=None, seed_identity_complete=True, resolver=None,
                       database_paths=None, refresh=False, cache_only=False, startup_operations=None,
                       preserve_wildcard_starts=False):
    """Prepare captured evidence and explicitly selected startup capabilities offline.

    Keep the approved document original and pass the complete v3 analysis separately.
    Missing startup descriptors and unsupported essential capabilities remain held.
    """
    if not execution_interpretation_complete(analysis):
        raise ValueError('Scope exclusion interpretation is pending; prepare execution requirements offline')
    root=Path(result_root)
    resolver=resolver or ExclusionBindingResolver(root/'.exclusion-bindings')
    rules, _ = split_exclusion_enforcement(analysis.execution_rules)
    policies={}; count=rejected=0
    paths=database_paths if database_paths is not None else capture_databases(root)
    starts=normalize_start_urls(
        start_urls, preserve_wildcard_starts=preserve_wildcard_starts,
    )
    for target in targets:
        key=(target.asset_type.value,target.asset)
        if key in starts:
            validate_start_url_for_target(starts[key],asset_type=target.asset_type,asset=target.asset)
        snapshot=load_capture_snapshot(paths,document=document,target=target) if rules else CaptureSnapshot()
        count+=len(snapshot.candidates); rejected+=snapshot.rejected
        inputs=dict(scope_digest=approved_scope_digest(document),target_asset=target.asset,rules=rules,
                    candidates=snapshot.candidates,evidence=snapshot.evidence)
        if cache_only:
            compiled=resolver.cached(**inputs)
            if compiled is None:
                from aidast.scope.exclusions import CompiledExclusionPolicy
                from aidast.core.exclusion_guard import rule_digest
                compiled=CompiledExclusionPolicy(scope_digest=inputs['scope_digest'],target_asset=target.asset,
                    rules=rules,rule_digest=rule_digest([r.model_dump() for r in rules]),
                    evidence_digest=hashlib.sha256(b'[]').hexdigest())
        else:
            compiled=(resolver.refresh if refresh else resolver.resolve)(**inputs)
        policies[target.asset]=compiled
    operations=(selected_startup_operations(
                    targets, start_urls=starts,
                    preserve_wildcard_starts=preserve_wildcard_starts,
                )
                if startup_operations is None else startup_operations)
    prepared=ExclusionPreparation(policies,[],count,rejected,login_mode=login_mode)
    prepared.agent_guidance = {target.asset: agent_exclusion_advisories(analysis.execution_rules, target.asset)
                               for target in targets}
    prepared.reconcile_startup(operations,headers=headers,seed_identity_complete=seed_identity_complete)
    return prepared
