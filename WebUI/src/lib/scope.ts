export const scopeCollectionRequest = {
  login_mode: 'runtime-browser',
  identity: 'primary',
} as const;

export function programRegistrationUrlError(programUrl: string): string | null {
  return /^http:\/\//i.test(programUrl.trim())
    ? 'HTTP URLs cannot be registered. Enter a URL starting with https://.'
    : null;
}

export function isValidScopeModel(model: string): boolean {
  return model === model.trim() && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/.test(model) && !model.includes('://');
}

export function scopeRequestForStatus(status: string, model = 'gpt-5.6-sol') {
  return { ...scopeCollectionRequest, refresh: status !== 'scope_required', model };
}

export function selectApprovedScope(scopes: readonly { scope_id: string }[], current: string): string {
  if (scopes.some(scope => scope.scope_id === current)) return current;
  return scopes[0]?.scope_id ?? '';
}

export function createScopeResponseGuard() {
  let selection = 0;
  return {
    invalidate: () => { selection += 1; },
    capture: () => {
      const started = selection;
      return () => started === selection;
    },
  };
}

export type PolicyReferenceSummary = {
  requested_url: string;
  final_url: string | null;
  status: 'captured' | 'unresolved';
  applicability: 'testing' | 'reporting' | 'disclosure' | 'mixed' | 'unknown';
  relationship?: 'required' | 'supporting' | 'uncertain';
  source_quote: string;
  error: string | null;
};
