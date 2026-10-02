import { apiErrorMessage } from './transport.ts';

export type ReportSummary = {
  report_id: string; scan_id: string; case_id: string; platform: string;
  language?: 'ko' | 'en'; title: string; created_at: string;
};
export type ScanExecutionSummary = {
  scan_id: string; execution_status: 'completed' | 'partial' | 'in_progress';
  inventory: Record<string, number>;
  validation: { current_confirmed: number; statuses: Record<string, number>; phases: Record<string, number> };
  reports: { report_id?: string; case_id?: string; status?: string; platform?: string }[];
  errors: Record<string, string>[]; markdown: string;
};

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === 'string';
const counts = (value: unknown): value is Record<string, number> =>
  record(value) && Object.values(value).every(item => Number.isSafeInteger(item) && (item as number) >= 0);

export function parseReportSummaries(value: unknown, scanId: string): ReportSummary[] | null {
  if (!record(value) || !Array.isArray(value.reports)) return null;
  if (!value.reports.every(item => record(item)
    && text(item.report_id) && /^report_[0-9a-f]{32}$/.test(item.report_id)
    && item.scan_id === scanId && text(item.case_id) && text(item.platform)
    && text(item.title) && text(item.created_at)
    && (item.language === undefined || item.language === 'ko' || item.language === 'en'))) return null;
  return value.reports as ReportSummary[];
}

export function parseScanExecutionSummary(value: unknown, scanId: string): ScanExecutionSummary | null {
  if (!record(value) || value.scan_id !== scanId
    || typeof value.execution_status !== 'string' || !['completed', 'partial', 'in_progress'].includes(value.execution_status)
    || !counts(value.inventory) || !record(value.validation)
    || !Number.isSafeInteger(value.validation.current_confirmed) || (value.validation.current_confirmed as number) < 0
    || !counts(value.validation.statuses) || !counts(value.validation.phases)
    || !Array.isArray(value.reports) || !value.reports.every(item => record(item)
      && ['report_id', 'case_id', 'status', 'platform'].every(key => item[key] === undefined || text(item[key])))
    || !Array.isArray(value.errors) || !value.errors.every(item => record(item) && Object.values(item).every(text))
    || !text(value.markdown)) return null;
  return value as ScanExecutionSummary;
}

export function confirmedReportSummaries(
  reports: readonly ReportSummary[],
  validations: readonly { case_id: string; processing_phase: string; current_status: string | null }[],
  scanId: string,
): ReportSummary[] {
  const confirmed = new Set(validations.filter(item =>
    item.processing_phase === 'completed' && item.current_status === 'CONFIRMED').map(item => item.case_id));
  return reports.filter(item => item.scan_id === scanId && confirmed.has(item.case_id));
}

export async function requestReportSummaries(
  base: string, scanId: string, signal: AbortSignal, request: typeof fetch = fetch,
): Promise<ReportSummary[]> {
  const url = new URL('/api/v1/reports', base);
  url.searchParams.set('scan_id', scanId);
  const response = await request(url, { signal, credentials: 'same-origin', cache: 'no-store' });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(apiErrorMessage(record(body) ? body.detail : undefined,
    `Report request returned ${response.status}`));
  const parsed = parseReportSummaries(body, scanId);
  if (!parsed) throw new Error('The backend returned invalid report drafts.');
  return parsed;
}

export async function requestScanExecutionSummary(
  base: string, scanId: string, signal: AbortSignal, request: typeof fetch = fetch,
): Promise<ScanExecutionSummary | null> {
  const response = await request(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}/summary`, base),
    { signal, credentials: 'same-origin', cache: 'no-store' });
  if (response.status === 404) return null;
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(apiErrorMessage(record(body) ? body.detail : undefined,
    `Scan summary returned ${response.status}`));
  const parsed = parseScanExecutionSummary(body, scanId);
  if (!parsed) throw new Error('The backend returned an invalid scan summary.');
  return parsed;
}
