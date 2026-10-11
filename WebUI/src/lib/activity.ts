import type { Level, Log, Stage } from './events';

export type ScopeActivityEvent = {
  job_id: string;
  event_id: number;
  occurred_at: string;
  level: string;
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
};

export type ActivityLog = {
  key: string;
  source: 'scope' | 'scan';
  stream: string;
  sequence: number;
  time: string;
  stage: Stage;
  level: Level;
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
  audit_id?: string;
};

export type ScopeActivityStatus =
  | 'scope_required'
  | 'collecting'
  | 'awaiting_browser'
  | 'paused'
  | 'cancelling'
  | 'cancelled'
  | 'review_required'
  | 'approved'
  | 'rejected'
  | 'failed';

export type ScopeActivityState = {
  polling: boolean;
  events: ScopeActivityEvent[];
};

export type ScopeActivityAction =
  | { type: 'job-selected'; status: ScopeActivityStatus }
  | { type: 'collection-started' }
  | { type: 'external-mutation' }
  | { type: 'dialog-closed' }
  | { type: 'program-status'; status: ScopeActivityStatus | undefined }
  | { type: 'job-response'; status: ScopeActivityStatus | undefined; events: ScopeActivityEvent[] }
  | { type: 'reset' };

export const initialScopeActivityState: ScopeActivityState = { polling: false, events: [] };

const activityLevel = (value: string): Level =>
  value === 'success' || value === 'warning' || value === 'error' ? value : 'info';

export function isScopeActivityActive(status: ScopeActivityStatus | undefined): boolean {
  return status === 'collecting' || status === 'awaiting_browser'
    || status === 'paused' || status === 'cancelling';
}

export function scopeCollectionProgress(status: ScopeActivityStatus | undefined, events: readonly ScopeActivityEvent[]): number {
  if (status === 'review_required' || status === 'approved' || status === 'rejected') return 100;
  const milestones: Record<string, number> = {
    'scope.started': 2,
    'scope.page_read_started': 10,
    'scope.collection_started': 10,
    'scope.page_read_completed': 25,
    'scope.analysis_started': 40,
    'scope.analysis_completed': 55,
    'scope.collection_completed': 55,
    'scope.verification_started': 65,
    'scope.verification_completed': 80,
    'scope.draft_started': 90,
    'scope.draft_completed': 95,
  };
  return events.reduce((progress, event) => {
    if (event.message_code === 'scope.browser_progress' && progress < 25) {
      return Math.min(24, Math.max(10, progress) + 1);
    }
    return Math.max(progress, milestones[event.message_code ?? ''] ?? 0);
  }, 0);
}

export function reconCollectionProgress(actual: number, logs: readonly Log[]): number {
  const groups = [
    { start: 0, end: 12, phases: ['asset_discovery', 'subfinder'] },
    { start: 12, end: 24, phases: ['dns_resolution', 'dnsx'] },
    { start: 24, end: 36, phases: ['host_port_discovery', 'naabu', 'nmap'] },
    { start: 36, end: 48, phases: ['http_probe'] },
    { start: 48, end: 55, phases: ['origin_discovery'] },
    { start: 55, end: 75, phases: ['endpoint_discovery', 'playwright_bootstrap', 'playwright_priority',
      'katana_standard', 'katana_headless', 'playwright_interaction', 'ffuf', 'api_secondary',
      'openapi_detection', 'graphql_detection', 'zap_openapi', 'zap_graphql', 'mitm_capture'] },
    { start: 75, end: 90, phases: ['observation_tagging'] },
  ] as const;
  const activity = new Map<number, Set<string>>();
  return logs.reduce((progress, log) => {
    const params = log.message_params;
    if (log.stage !== 'Recon') return progress;
    if (log.message_code === 'agent.work' && typeof params?.progress === 'number') {
      return Math.max(progress, Math.min(98, params.progress));
    }
    if (log.message_code !== 'recon.activity' || !params
      || (params.state !== 'started' && params.state !== 'finished'
        && params.state !== 'skipped' && params.state !== 'found')) return progress;
    const group = groups.find(item => item.phases.some(phase => phase === params.phase));
    if (!group) return progress;
    const recorded = activity.get(group.start) ?? new Set<string>();
    recorded.add(`${params.phase}:${params.state}:${params.method ?? ''}:${params.url ?? ''}`);
    activity.set(group.start, recorded);
    const finished = params.phase === group.phases[0]
      && (params.state === 'finished' || params.state === 'skipped');
    return Math.max(progress, finished ? group.end : Math.min(group.end - 1, group.start + recorded.size));
  }, actual);
}

export function initialEstimatedProgress(actual: number, status: string): number {
  return status === 'completed' ? 100 : actual;
}

export function currentStageProgressStatus(scanStatus: string | undefined, stageStatus: string | undefined): string {
  return stageStatus === 'completed' || stageStatus === 'skipped' ? 'completed' : scanStatus ?? 'pending';
}

export function advanceEstimatedProgress(value: number, mode: 'running' | 'paused' | 'completed'): number {
  if (mode === 'paused') return value;
  return Math.min(mode === 'completed' ? 100 : 99, value + 1);
}

export function estimatedProgressDelay(shown: number, actual: number, mode: 'running' | 'paused' | 'completed'): number | null {
  if (mode === 'paused' || (mode === 'running' && shown >= actual)) return null;
  if (advanceEstimatedProgress(shown, mode) === shown) return null;
  return mode === 'completed' ? 80 : 200;
}

export function scopePollingAfterJobResponse(status: ScopeActivityStatus | undefined): boolean {
  return isScopeActivityActive(status);
}

export function shouldPollScopeJob({
  hasJob,
  polling,
  dialogOpen,
}: {
  hasJob: boolean;
  polling: boolean;
  dialogOpen: boolean;
}): boolean {
  return hasJob && (polling || dialogOpen);
}

export function reduceScopeActivity(
  state: ScopeActivityState,
  action: ScopeActivityAction,
): ScopeActivityState {
  switch (action.type) {
    case 'job-selected':
      return { polling: scopePollingAfterJobResponse(action.status), events: [] };
    case 'collection-started':
      return { polling: true, events: [] };
    case 'external-mutation':
      return { ...state, polling: true };
    case 'job-response':
      return {
        polling: scopePollingAfterJobResponse(action.status),
        events: action.events,
      };
    case 'dialog-closed':
    case 'program-status':
      return state;
    case 'reset':
      return initialScopeActivityState;
  }
}

export type ScopeJobPollResult<T> = {
  status: ScopeActivityStatus | undefined;
  payload: T;
};

export type ScopeJobPoller = {
  first: Promise<void>;
  stop: () => void;
};

export function startScopeJobPolling<T>({
  repeat,
  load,
  onResponse,
  onError,
  intervalMs = 1000,
  schedule = (callback, delay) => window.setInterval(callback, delay),
  cancel = handle => window.clearInterval(handle),
}: {
  repeat: boolean;
  load: (signal: AbortSignal) => Promise<ScopeJobPollResult<T>>;
  onResponse: (result: ScopeJobPollResult<T>) => void;
  onError: (error: unknown) => void;
  intervalMs?: number;
  schedule?: (callback: () => void, delay: number) => number;
  cancel?: (handle: number) => void;
}): ScopeJobPoller {
  const abort = new AbortController();
  let timer: number | undefined;
  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    abort.abort();
    if (timer !== undefined) {
      cancel(timer);
      timer = undefined;
    }
  };
  const poll = async () => {
    try {
      const result = await load(abort.signal);
      if (stopped) return;
      onResponse(result);
      if (!scopePollingAfterJobResponse(result.status)) stop();
    } catch (error) {
      if (!stopped && !abort.signal.aborted) onError(error);
    }
  };
  if (repeat) timer = schedule(() => void poll(), intervalMs);
  const first = poll();
  return { first, stop };
}

export function startScopeElapsedClock({
  onTick,
  now = () => Date.now(),
  schedule = (callback, delay) => window.setInterval(callback, delay),
  cancel = handle => window.clearInterval(handle),
}: {
  onTick: (now: number) => void;
  now?: () => number;
  schedule?: (callback: () => void, delay: number) => number;
  cancel?: (handle: number) => void;
}): { stop: () => void } {
  let stopped = false;
  const timer = schedule(() => {
    if (!stopped) onTick(now());
  }, 1000);
  onTick(now());
  return {
    stop: () => {
      if (stopped) return;
      stopped = true;
      cancel(timer);
    },
  };
}

export function formatActivityElapsed(seconds: number, language: 'ko' | 'en' = 'ko'): string {
  const wholeSeconds = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(wholeSeconds / 60);
  const remainder = wholeSeconds % 60;
  if (language === 'en') return minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`;
  return minutes > 0 ? `${minutes}분 ${remainder}초` : `${remainder}초`;
}

export function mergeActivityLogs(
  scanLogs: readonly Log[],
  scopeEvents: readonly ScopeActivityEvent[],
): ActivityLog[] {
  const scopeLogs: ActivityLog[] = scopeEvents.map(event => ({
    key: `scope:${event.job_id}:${event.event_id}`,
    source: 'scope',
    stream: `scope:${event.job_id}`,
    sequence: event.event_id,
    time: event.occurred_at,
    stage: 'Scope',
    level: activityLevel(event.level),
    message: event.message,
    message_code: event.message_code,
    message_params: event.message_params,
  }));
  const normalizedScanLogs: ActivityLog[] = scanLogs.map(log => ({
    key: `scan:${log.id}`,
    source: 'scan',
    stream: 'scan',
    sequence: log.id,
    time: log.time,
    stage: log.stage,
    level: log.level,
    message: log.message,
    message_code: log.message_code,
    message_params: log.message_params,
    audit_id: log.audit_id,
  }));
  return [...scopeLogs, ...normalizedScanLogs]
    .sort((left, right) => {
      const millisecondOrder = Date.parse(left.time) - Date.parse(right.time);
      if (millisecondOrder !== 0) return millisecondOrder;
      const preciseTimeOrder = left.time.localeCompare(right.time);
      if (preciseTimeOrder !== 0) return preciseTimeOrder;
      if (left.stream === right.stream) return left.sequence - right.sequence;
      return left.stream.localeCompare(right.stream);
    })
    .slice(-500);
}

export function hideAcknowledgedActivity(logs: readonly ActivityLog[], acknowledgedIds: ReadonlySet<string>): ActivityLog[] {
  return logs.filter(log => !log.audit_id || !acknowledgedIds.has(log.audit_id));
}
