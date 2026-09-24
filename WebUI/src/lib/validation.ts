import type { Finding } from './events';

export type ValidationStatus =
  | 'CONFIRMED' | 'DISPROVEN' | 'KNOWN' | 'OUT_OF_SCOPE'
  | 'UNDERPOWERED' | 'BLOCKED' | 'INCONCLUSIVE' | 'CONTESTED';

export type ValidationCase = {
  readonly case_id: string;
  readonly target_kind: 'finding' | 'chain';
  readonly target_id: string;
  readonly processing_phase: string;
  readonly current_status: ValidationStatus | null;
  readonly updated_at: string;
  readonly decision?: {
    readonly reason?: string;
    readonly match_kind?: string;
    readonly failed_check?: string;
    readonly known_source_case_id?: string;
    readonly severity?: string;
    readonly impact_score?: number;
  };
  readonly evidence?: {
    readonly attempts: Readonly<Record<string, Readonly<Record<string, number>>>>;
    readonly evidence_count?: number;
  };
};

export type FindingVerdict = 'tp' | 'fp' | 'duplicate' | 'pending' | 'inconclusive';

export function knownSourceCase(validation: ValidationCase, cases: readonly ValidationCase[]): ValidationCase | undefined {
  if (validation.processing_phase !== 'completed' || validation.current_status !== 'KNOWN') return undefined;
  const source = cases.find(item => item.case_id === validation.decision?.known_source_case_id);
  return source?.processing_phase === 'completed' && source.current_status === 'CONFIRMED' ? source : undefined;
}

export function findingVerdict(finding: Finding, cases: readonly ValidationCase[]): FindingVerdict {
  const validation = cases.find(item => item.target_kind === 'finding' && item.target_id === finding.id);
  switch (validation?.processing_phase === 'completed' ? validation.current_status : null) {
    case 'CONFIRMED': return 'tp';
    case 'DISPROVEN': return 'fp';
    case 'KNOWN': return validation && knownSourceCase(validation, cases) ? 'duplicate' : 'inconclusive';
    case null:
    case undefined: return 'pending';
    case 'OUT_OF_SCOPE':
    case 'UNDERPOWERED':
    case 'BLOCKED':
    case 'INCONCLUSIVE':
    case 'CONTESTED': return 'inconclusive';
  }
}

export function filterFindings(findings: readonly Finding[], cases: readonly ValidationCase[], verdict: FindingVerdict | 'all'): Finding[] {
  return findings.filter(finding => verdict === 'all' || findingVerdict(finding, cases) === verdict);
}

export function reportCaseForFinding(finding: Finding, cases: readonly ValidationCase[]): string | null {
  const validation = cases.find(item => item.target_kind === 'finding' && item.target_id === finding.id);
  if (validation?.processing_phase !== 'completed') return null;
  if (validation.current_status === 'CONFIRMED') return validation.case_id;
  if (validation.current_status !== 'KNOWN') return null;
  return knownSourceCase(validation, cases)?.case_id ?? null;
}

export function parseValidationCases(value: unknown, scanId: string): ValidationCase[] | null {
  if (!value || typeof value !== 'object' || !('scan_id' in value) || value.scan_id !== scanId
    || !('cases' in value) || !Array.isArray(value.cases)) return null;
  const statuses: readonly string[] = ['CONFIRMED', 'DISPROVEN', 'KNOWN', 'OUT_OF_SCOPE', 'UNDERPOWERED', 'BLOCKED', 'INCONCLUSIVE', 'CONTESTED'];
  if (!value.cases.every((item: unknown) => item !== null && typeof item === 'object'
    && 'case_id' in item && typeof item.case_id === 'string'
    && 'target_kind' in item && (item.target_kind === 'finding' || item.target_kind === 'chain')
    && 'target_id' in item && typeof item.target_id === 'string'
    && 'processing_phase' in item && typeof item.processing_phase === 'string'
    && 'updated_at' in item && typeof item.updated_at === 'string'
    && 'current_status' in item && (item.current_status === null || typeof item.current_status === 'string' && statuses.includes(item.current_status))
    && (!('decision' in item) || item.decision !== null && typeof item.decision === 'object'
      && (!('known_source_case_id' in item.decision) || typeof item.decision.known_source_case_id === 'string')
      && (!('reason' in item.decision) || typeof item.decision.reason === 'string'))
    && (!('evidence' in item) || item.evidence !== null && typeof item.evidence === 'object'
      && 'attempts' in item.evidence && item.evidence.attempts !== null && typeof item.evidence.attempts === 'object'
      && Object.values(item.evidence.attempts).every(counts => counts !== null && typeof counts === 'object'
        && Object.values(counts).every(count => typeof count === 'number' && Number.isSafeInteger(count) && count >= 0))
      && (!('evidence_count' in item.evidence) || typeof item.evidence.evidence_count === 'number'
        && Number.isSafeInteger(item.evidence.evidence_count) && item.evidence.evidence_count >= 0))
  )) return null;
  return value.cases;
}
