import type { Snapshot } from './events';

export type ExecutionProfileId = 'safe-recon' | 'focused-discovery' | 'bug-bounty-safe';

export function validStartUrl(value: string, httpsOnly = false): boolean {
  if (!value.trim()) return true;
  try {
    const parsed = new URL(value.trim());
    const supportedScheme = parsed.protocol === 'https:' || (!httpsOnly && parsed.protocol === 'http:');
    return supportedScheme && !!parsed.hostname && !parsed.username && !parsed.password
      && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

export function bugBountyTargetReady(
  profile: ExecutionProfileId,
  selectedTargets: readonly string[],
  approvedTargets: readonly { readonly asset: string; readonly asset_type: string }[],
  startUrl: string,
): boolean {
  if (profile !== 'bug-bounty-safe') return true;
  if (selectedTargets.length !== 1) return false;
  const selected = approvedTargets.find(item => item.asset === selectedTargets[0]);
  if (!selected) return false;
  return selected.asset_type !== 'WILDCARD' || (!!startUrl.trim() && validStartUrl(startUrl, true));
}

export function approvedScopeSelection(scopeId: string, targets: readonly string[]) {
  const selectedScopeId = scopeId.trim();
  if (!selectedScopeId || targets.length === 0 || targets.some(target => !target.trim())) {
    throw new Error('An approved Scope and at least one target are required.');
  }
  return { scope_id: selectedScopeId, targets: [...targets] };
}

export function isValidTagBatchSize(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 200;
}

export function scanRetryAction(scan: Pick<Snapshot, 'status' | 'stage'>): 'resume' | 'rescan' | null {
  if (scan.status === 'completed' || scan.status === 'cancelled') return 'rescan';
  if (scan.status !== 'failed') return null;
  return scan.stage === 'Attack' || scan.stage === 'Chaining' || scan.stage === 'Validation' || scan.stage === 'Report'
    ? 'resume'
    : 'rescan';
}

export type ExecutionLimits = {
  readonly requests_per_second: number;
  readonly concurrency: number;
  readonly timeout_seconds: number;
  readonly max_depth: number;
  readonly max_requests: number;
};

export type ScopeExecutionRequirements = {
  readonly execution_requirements_status?: 'ready' | 'pending';
  readonly execution_rules?: ScopeExecutionRules | null;
  readonly policy_inputs?: readonly PolicyInput[];
  readonly policy_confirmations?: readonly PolicyConfirmation[];
  readonly policy_blockers?: readonly PolicyBlocker[];
  readonly header_requirements_status: 'ready' | 'pending';
  readonly required_headers: readonly RequiredRequestHeader[];
  readonly header_inputs: readonly HeaderInput[];
  readonly scope_max_requests_per_second: number | null;
  readonly required_header: {
    readonly name: string;
    readonly input_field: string;
  } | null;
  readonly operational_constraints: readonly string[];
  readonly profiles: readonly {
    readonly id: ExecutionProfileId;
    readonly limits: ExecutionLimits;
  }[];
};

export type HeaderInput = {
  readonly key: string;
  readonly label: string;
  readonly kind: 'text' | 'username' | 'email';
};

export type RequiredRequestHeader = {
  readonly name: string;
  readonly value_template: string;
  readonly inputs: readonly HeaderInput[];
  readonly source_quote: string;
};

type HeaderRequirements = Pick<ScopeExecutionRequirements, 'header_requirements_status' | 'header_inputs'>;

export function canLaunchWithHeaderInputs(
  requirements: HeaderRequirements,
  values: Readonly<Record<string, string>>,
): boolean {
  return requirements.header_requirements_status === 'ready'
    && Array.isArray(requirements.header_inputs)
    && requirements.header_inputs.every(input => {
      const value = values[input.key];
      return typeof value === 'string' && !!value.trim() && value.length <= 256
        && !/[\x00-\x1f\x7f\u0100-\uffff]/.test(value)
        && (input.kind !== 'username' || /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.trim()))
        && (input.kind !== 'email' || /^[^\s@]+@[^\s@]+$/.test(value.trim()));
    });
}

export function headerIdentityValues(
  requirements: HeaderRequirements,
  values: Readonly<Record<string, string>>,
): Record<string, string> {
  return Object.fromEntries(requirements.header_inputs.map(input => [input.key, values[input.key]]));
}

// Preserve settled failures, too: selecting a pending Scope again must not repeatedly invoke AI.
export function createHeaderRequirementsResolver<T>(
  request: (scopeId: string) => Promise<T>,
): (scopeId: string) => Promise<T> {
  const requests = new Map<string, Promise<T>>();
  return scopeId => {
    let result = requests.get(scopeId);
    if (!result) {
      result = request(scopeId);
      requests.set(scopeId, result);
    }
    return result;
  };
}

export class MissingExecutionProfileError extends Error {
  constructor(profile: ExecutionProfileId) {
    super(`Approved Scope does not provide execution profile: ${profile}`);
    this.name = 'MissingExecutionProfileError';
  }
}

export function resolveExecutionLimits(
  requirements: ScopeExecutionRequirements,
  profile: ExecutionProfileId,
): ExecutionLimits {
  const selected = requirements.profiles.find(item => item.id === profile);
  if (!selected) throw new MissingExecutionProfileError(profile);
  const limits = { ...selected.limits };
  for (const cap of requirements.execution_rules?.option_limits ?? []) {
    if (typeof cap.value === 'number' && cap.field in limits) {
      const field = cap.field as keyof ExecutionLimits;
      Object.assign(limits, { [field]: Math.min(limits[field], cap.value) });
    }
  }
  return {
    ...limits,
    requests_per_second: profile === 'bug-bounty-safe'
      ? Math.min(requirements.scope_max_requests_per_second ?? limits.requests_per_second, limits.requests_per_second, 50)
      : Math.min(requirements.scope_max_requests_per_second ?? limits.requests_per_second, 50),
  };
}

export type PolicyInput = HeaderInput & { readonly allowed_email_domains?: readonly string[]; readonly target_assets: readonly string[]; readonly source_quote: string };
export type PolicyConfirmation = { readonly key: string; readonly label: string; readonly target_assets: readonly string[]; readonly source_quote: string };
export type PolicyBlocker = { readonly label: string; readonly reason: string; readonly source_quote: string; readonly target_assets?: readonly string[] };
export type PolicyAdvisory = PolicyBlocker & { readonly guidance: string };
export type RequestLimit = { readonly maximum: number; readonly period_seconds: number | null; readonly scope: 'scan' | 'program' | 'target'; readonly source_quote: string };
export type ExclusionExpression = {
  readonly operator: 'predicate' | 'all' | 'any' | 'not';
  readonly predicate?: { readonly key: string; readonly field: string; readonly operator: string; readonly name?: string | null; readonly value?: string | null } | null;
  readonly children?: readonly ExclusionExpression[];
};
export type ScopeExclusion = { readonly key: string; readonly label: string; readonly source_quote: string; readonly target_assets: readonly string[]; readonly condition: ExclusionExpression };
export type ExclusionPreparation = { readonly held: number; readonly denied: number; readonly captured_candidates: number; readonly rejected_captures: number; readonly agent_guidance?: readonly PolicyAdvisory[]; readonly resources: readonly { readonly target_asset: string; readonly url: string | null; readonly decision: 'continue' | 'deny' | 'hold'; readonly rule_keys: readonly string[]; readonly reason: string }[] };
export type ScopeExecutionRules = {
  readonly exclusions?: readonly ScopeExclusion[] | null;
  readonly request_limits: readonly RequestLimit[];
  readonly option_limits: readonly { field: string; value: number | boolean; source_quote: string }[];
  readonly allowed_methods?: { values: readonly string[]; source_quote: string } | null;
  readonly allowed_target_assets?: { values: readonly string[]; source_quote: string } | null;
  readonly required_inputs?: readonly PolicyInput[];
  readonly required_confirmations?: readonly PolicyConfirmation[];
  readonly blocking_requirements?: readonly PolicyBlocker[];
  readonly advisories?: readonly PolicyAdvisory[];
  readonly policy_review_version?: number;
};
type PolicyRequirements = Pick<ScopeExecutionRequirements, 'execution_requirements_status' | 'execution_rules' | 'policy_inputs' | 'policy_confirmations' | 'policy_blockers'> & Partial<Pick<ScopeExecutionRequirements, 'header_inputs'>>;
export function applicablePolicyRequirements<T extends { readonly target_assets?: readonly string[] }>(items: readonly T[] | undefined, targets: readonly string[]): T[] {
  return (items ?? []).filter(item => !item.target_assets?.length || item.target_assets.some(asset => targets.includes(asset)));
}
export function policyConfirmationKeys(requirements: PolicyRequirements, targets: readonly string[], authorizationConfirmed: boolean): string[] {
  return authorizationConfirmed && requirements.execution_requirements_status === 'ready'
    && requirements.execution_rules != null
    ? applicablePolicyRequirements(requirements.policy_confirmations, targets).map(item => item.key)
    : [];
}
export function validPolicyInput(input: PolicyInput, value: string | undefined): boolean {
  if (typeof value !== 'string' || !value.trim() || value.length > 256 || /[\x00-\x1f\x7f]/.test(value)) return false;
  if (input.kind === 'username') return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.trim());
  if (input.kind === 'email') {
    if (!/^[^\s@]+@[^\s@]+$/.test(value.trim())) return false;
    const domain = value.trim().split('@')[1].toLowerCase();
    return !input.allowed_email_domains?.length || input.allowed_email_domains.some(allowed => allowed.toLowerCase() === domain);
  }
  return input.kind === 'text';
}
export function canLaunchWithPolicyInputs(requirements: PolicyRequirements, targets: readonly string[], values: Readonly<Record<string,string>>, confirmations: readonly string[], identityValues: Readonly<Record<string, string>> = {}): boolean {
  return requirements.execution_requirements_status === 'ready' && requirements.execution_rules != null
    && Array.isArray(requirements.execution_rules.exclusions)
    && Array.isArray(requirements.policy_inputs) && Array.isArray(requirements.policy_confirmations) && Array.isArray(requirements.policy_blockers)
    && applicablePolicyRequirements(requirements.policy_blockers, targets).length === 0
    && sharedPolicyInputConflicts(requirements, targets, identityValues, values).length === 0
    && (!requirements.execution_rules.allowed_methods || requirements.execution_rules.allowed_methods.values.length > 0)
    && applicablePolicyRequirements(requirements.policy_inputs, targets).every(input => validPolicyInput(input, values[input.key]))
    && applicablePolicyRequirements(requirements.policy_confirmations, targets).every(item => confirmations.includes(item.key))
    && (!requirements.execution_rules.allowed_target_assets || targets.every(target => requirements.execution_rules!.allowed_target_assets!.values.includes(target)));
}
export function policyLaunchValues(requirements: PolicyRequirements, targets: readonly string[], values: Readonly<Record<string,string>>, confirmations: readonly string[]) {
  return {
    policy_values: Object.fromEntries(applicablePolicyRequirements(requirements.policy_inputs, targets).map(input => [input.key, values[input.key]])),
    policy_confirmations: applicablePolicyRequirements(requirements.policy_confirmations, targets).filter(item => confirmations.includes(item.key)).map(item => item.key),
  };
}
export function requestLimitLabel(limit: RequestLimit): string {
  return `${limit.maximum} requests ${limit.period_seconds === null ? 'total' : `per ${limit.period_seconds} seconds`} · ${limit.scope}`;
}

export function sharedPolicyInputConflicts(requirements: PolicyRequirements, targets: readonly string[], identityValues: Readonly<Record<string, string>>, policyValues: Readonly<Record<string, string>>): string[] {
  const sharedKeys = new Set((requirements.header_inputs ?? []).map(input => input.key));
  return applicablePolicyRequirements(requirements.policy_inputs, targets)
    .filter(input => sharedKeys.has(input.key) && (identityValues[input.key] ?? '').trim() !== (policyValues[input.key] ?? '').trim())
    .map(input => input.label);
}
