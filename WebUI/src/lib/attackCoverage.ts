export type HypothesisCoverage = { vuln_class: string; injection_location: string; parameter_name: string; required_identity_role: string; status: string; disposition_reason: string };
export type AttackCoverage = {
  total: number; resolved: number; unfinished: number; tested: number; budget_limited: number;
  by_status: Record<string, number>; endpoints_total: number; endpoints_reviewed: number;
  planning_unresolved?: number; planning_rejected?: number; planning_resolved?: number;
  insufficient_evidence_endpoints: number; not_applicable_endpoints: number;
  gaps: { method: string; url: string; status: string; reason: string; vuln_class: string | null }[];
  gaps_total: number; gaps_truncated: boolean;
};
export const coverageStatusLabels: Record<string, [string, string]> = {
  pending: ['대기', 'Pending'], running: ['진행 중', 'Running'],
  tested_negative: ['검증했으나 취약점 미확인', 'Tested without a finding'],
  candidate: ['후보 발견', 'Candidate'], confirmed: ['취약점 확인', 'Confirmed'],
  blocked_auth: ['인증 부족', 'Missing authentication'], policy_excluded: ['정책 제외', 'Policy excluded'],
  unsupported: ['검증 미실행', 'Not tested'], error_retryable: ['재시도 대기', 'Retry pending'],
  error_terminal: ['실행 오류', 'Execution error'], insufficient_evidence: ['근거 부족', 'Insufficient evidence'],
  not_applicable: ['적용 대상 없음', 'Not applicable'],
  planning_rejected: ['가설 근거 불일치 · 미실행', 'Ungrounded hypothesis · not tested'],
};
export function coverageMetrics(coverage: Pick<AttackCoverage, 'total' | 'resolved' | 'tested' | 'unfinished' | 'by_status' | 'budget_limited' | 'endpoints_total' | 'endpoints_reviewed' | 'insufficient_evidence_endpoints' | 'not_applicable_endpoints' | 'planning_unresolved'>) {
  return [
    {key: 'total', ko: '전체 검증 가설', en: 'Total hypotheses', value: coverage.total},
    {key: 'tested', ko: '실제 검증', en: 'Actually tested', value: coverage.tested},
    {key: 'unfinished', ko: '미처리 가설', en: 'Unfinished hypotheses', value: coverage.unfinished},
    {key: 'blocked_auth', ko: '인증 부족', en: 'Missing authentication', value: coverage.by_status.blocked_auth ?? 0},
    {key: 'policy_excluded', ko: '정책 제외', en: 'Policy excluded', value: coverage.by_status.policy_excluded ?? 0},
    {key: 'budget_limited', ko: '예산·시간 제한', en: 'Budget or time limit', value: coverage.budget_limited},
    {key: 'unsupported', ko: '검증 방식 미지원', en: 'Unsupported test', value: Math.max(0, (coverage.by_status.unsupported ?? 0) - coverage.budget_limited)},
    {key: 'insufficient_evidence', ko: '근거 부족 URL', en: 'URLs lacking evidence', value: coverage.insufficient_evidence_endpoints},
    {key: 'planning_unresolved', ko: '근거 불일치 가설', en: 'Ungrounded hypotheses', value: coverage.planning_unresolved ?? 0},
    {key: 'errors', ko: '실행 오류', en: 'Execution errors', value: (coverage.by_status.error_terminal ?? 0) + (coverage.by_status.error_retryable ?? 0)},
  ];
}
