export type ModelCallEvent = {
  event_id: number;
  call_id: string;
  state: 'started' | 'success' | 'error';
  occurred_at: string;
  scan_id: string | null;
  stage: string | null;
  stage_run_id: string | null;
  task_id: string | null;
  case_id: string | null;
  scope_job_id: string | null;
  operation_code: string;
  invocation_kind: 'structured' | 'session' | 'attack_orchestrator' | 'chaining_orchestrator';
  requested_model: string | null;
  elapsed_ms: number | null;
  error_code: string | null;
  input_tokens: number | null;
  cached_input_tokens: number | null;
  output_tokens: number | null;
  usage_status: 'not_captured' | 'absent' | 'reported' | 'partial' | 'invalid' | 'ambiguous';
};

export type ModelCallPage = { events: ModelCallEvent[]; next_before: number | null };
export const tokenStages = ['Recon', 'Attack', 'Chaining', 'Validation', 'Report'] as const;
export type TokenBucket = {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  measured_calls: number;
  unreported_calls: number;
};
export type ScanTokenUsage = {
  scan_id: string;
  total: TokenBucket;
  stages: Record<string, TokenBucket>;
  unattributed: TokenBucket;
};

function text(value: unknown, max = 128): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function optionalText(value: unknown): value is string | null {
  return value === null || text(value);
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function optionalCount(value: unknown): value is number | null {
  return value === null || count(value);
}

function parseTokenBucket(value: unknown): TokenBucket | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (!count(row.input_tokens) || !count(row.output_tokens)
    || !count(row.total_tokens) || !count(row.measured_calls) || !count(row.unreported_calls)
    || row.total_tokens !== row.input_tokens + row.output_tokens) return null;
  return {
    input_tokens: row.input_tokens, output_tokens: row.output_tokens,
    total_tokens: row.total_tokens, measured_calls: row.measured_calls,
    unreported_calls: row.unreported_calls,
  };
}

export function parseScanTokenUsage(value: unknown, scanId: string): ScanTokenUsage | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (row.scan_id !== scanId || !row.stages || typeof row.stages !== 'object'
    || Array.isArray(row.stages)) return null;
  const total = parseTokenBucket(row.total);
  const unattributed = parseTokenBucket(row.unattributed);
  if (!total || !unattributed) return null;
  const stages: Record<string, TokenBucket> = {};
  for (const stage of tokenStages) {
    const bucket = parseTokenBucket((row.stages as Record<string, unknown>)[stage]);
    if (!bucket) return null;
    stages[stage] = bucket;
  }
  for (const field of ['input_tokens', 'output_tokens', 'total_tokens', 'measured_calls', 'unreported_calls'] as const) {
    if (total[field] !== unattributed[field] + tokenStages.reduce(
      (sum, stage) => sum + stages[stage][field], 0,
    )) return null;
  }
  return { scan_id: scanId, total, stages, unattributed };
}

function parseEvent(value: unknown): ModelCallEvent | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (!count(row.event_id) || row.event_id === 0 || !text(row.call_id)
    || !text(row.state) || !['started', 'success', 'error'].includes(row.state)
    || !text(row.occurred_at) || !Number.isFinite(Date.parse(row.occurred_at))
    || !optionalText(row.scan_id) || !optionalText(row.stage) || !optionalText(row.stage_run_id)
    || !optionalText(row.task_id) || !optionalText(row.case_id) || !optionalText(row.scope_job_id)
    || !text(row.operation_code) || !text(row.invocation_kind)
    || !['structured', 'session', 'attack_orchestrator', 'chaining_orchestrator'].includes(row.invocation_kind)
    || !optionalText(row.requested_model) || !optionalCount(row.elapsed_ms) || !optionalText(row.error_code)
    || !optionalCount(row.input_tokens) || !optionalCount(row.cached_input_tokens) || !optionalCount(row.output_tokens)
    || !text(row.usage_status)
    || !['not_captured', 'absent', 'reported', 'partial', 'invalid', 'ambiguous'].includes(row.usage_status)) return null;
  return {
    event_id: row.event_id,
    call_id: row.call_id,
    state: row.state as ModelCallEvent['state'],
    occurred_at: row.occurred_at,
    scan_id: row.scan_id,
    stage: row.stage,
    stage_run_id: row.stage_run_id,
    task_id: row.task_id,
    case_id: row.case_id,
    scope_job_id: row.scope_job_id,
    operation_code: row.operation_code,
    invocation_kind: row.invocation_kind as ModelCallEvent['invocation_kind'],
    requested_model: row.requested_model,
    elapsed_ms: row.elapsed_ms,
    error_code: row.error_code,
    input_tokens: row.input_tokens,
    cached_input_tokens: row.cached_input_tokens,
    output_tokens: row.output_tokens,
    usage_status: row.usage_status as ModelCallEvent['usage_status'],
  };
}

export function parseModelCallPage(value: unknown): ModelCallPage | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const page = value as Record<string, unknown>;
  if (!Array.isArray(page.events)
    || (page.next_before !== null && (!count(page.next_before) || page.next_before === 0))) return null;
  return {
    events: page.events.map(parseEvent).filter((event): event is ModelCallEvent => event !== null),
    next_before: page.next_before,
  };
}
