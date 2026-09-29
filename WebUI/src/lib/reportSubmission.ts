export type ProgramRequirements = {
  verified: boolean; source: string; severity_required: boolean;
  required_fields: string[]; additional_fields: Record<string, string>;
  report_template: string | null; impact_template: string | null;
};

export type ReportSubmissionView = {
  report_id: string; platform: 'hackerone' | 'intigriti' | 'bugcrowd'; ready: boolean;
  revision_sha256: string; requirements: ProgramRequirements;
  fields: Record<string, string>; markdown: string;
  evidence: { evidence_id: string; kind: string; details: unknown; content_sha256: string; sanitized_sha256: string }[];
  checks: { code: string; level: 'pass' | 'warning' | 'blocker'; field: string | null; message: string }[];
  redactions: { kind: string; count: number }[];
};

const digest = /^[a-f0-9]{64}$/;
const identifier = /^[A-Za-z0-9_.:-]{1,256}$/;
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === 'string';
const textMap = (value: unknown): value is Record<string, string> => record(value) && Object.keys(value).length <= 128 && Object.values(value).every(text);
const nullableText = (value: unknown) => value === null || text(value);

export function parseReportSubmission(value: unknown, reportId: string): ReportSubmissionView | null {
  if (!record(value) || !/^report_[a-f0-9]{32}$/.test(reportId) || value.report_id !== reportId
    || !['hackerone', 'intigriti', 'bugcrowd'].includes(String(value.platform))
    || typeof value.ready !== 'boolean' || !text(value.revision_sha256) || !digest.test(value.revision_sha256)
    || !textMap(value.fields) || !text(value.markdown)) return null;
  const rules = value.requirements;
  if (!record(rules) || typeof rules.verified !== 'boolean' || !text(rules.source)
    || typeof rules.severity_required !== 'boolean' || !Array.isArray(rules.required_fields)
    || rules.required_fields.length > 64 || !rules.required_fields.every(text)
    || !textMap(rules.additional_fields) || !nullableText(rules.report_template) || !nullableText(rules.impact_template)) return null;
  if (!Array.isArray(value.checks) || value.checks.length > 256 || !value.checks.every(check => record(check)
    && text(check.code) && ['pass', 'warning', 'blocker'].includes(String(check.level))
    && nullableText(check.field) && text(check.message))) return null;
  if (value.ready && (!rules.verified || !rules.source.trim() || value.checks.some(check => check.level === 'blocker'))) return null;
  if (!Array.isArray(value.evidence) || value.evidence.length > 2048 || !value.evidence.every(item => record(item)
    && text(item.evidence_id) && identifier.test(item.evidence_id) && text(item.kind)
    && Object.hasOwn(item, 'details') && text(item.content_sha256) && digest.test(item.content_sha256)
    && text(item.sanitized_sha256) && digest.test(item.sanitized_sha256))) return null;
  if (!Array.isArray(value.redactions) || value.redactions.length > 128 || !value.redactions.every(item => record(item)
    && text(item.kind) && typeof item.count === 'number' && Number.isSafeInteger(item.count) && item.count >= 0)) return null;
  return value as unknown as ReportSubmissionView;
}

export function canExportSubmission(value: ReportSubmissionView | null, reportId: string, dirty = false, busy = false): boolean {
  return !dirty && !busy && !!value && value.report_id === reportId && value.ready && digest.test(value.revision_sha256)
    && value.requirements.verified && !value.checks.some(check => check.level === 'blocker');
}

export type PocInfo = {
  status: 'missing' | 'ready' | 'stale' | 'blocked'; mode: 'evidence_replay';
  source_revision: string | null; filename: string | null; sha256: string | null;
  byte_size: number | null; duration_seconds: number | null; width: number | null;
  height: number | null; chapters: number | null;
};

export function parsePocInfo(value: unknown): PocInfo | null {
  if (!record(value) || value.mode !== 'evidence_replay' || !text(value.status)
    || !['missing', 'ready', 'stale', 'blocked'].includes(value.status)) return null;
  if (value.status !== 'ready') {
    return ['source_revision', 'filename', 'sha256', 'byte_size', 'duration_seconds', 'width', 'height', 'chapters']
      .every(key => value[key] === null) ? value as PocInfo : null;
  }
  if (!text(value.source_revision) || !digest.test(value.source_revision) || value.filename !== 'Video.webm'
    || !text(value.sha256) || !digest.test(value.sha256) || typeof value.byte_size !== 'number'
    || !Number.isSafeInteger(value.byte_size) || value.byte_size < 1 || value.byte_size > 10000000
    || value.width !== 1280 || value.height !== 720 || typeof value.chapters !== 'number'
    || !Number.isSafeInteger(value.chapters) || value.chapters < 1 || value.chapters > 12
    || value.duration_seconds !== value.chapters * 5) return null;
  return value as PocInfo;
}

export function canPreviewPoc(info: PocInfo | null, view: ReportSubmissionView | null, reportId: string, dirty = false, busy = false): boolean {
  return canExportSubmission(view, reportId, dirty, busy) && !!info && !!parsePocInfo(info)
    && info.status === 'ready' && info.source_revision === view?.revision_sha256;
}

export type RequirementsForm = {
  source: string; verified: boolean; severityRequired: boolean; requiredFields: string;
  additionalFields: string; reportTemplate: string; impactTemplate: string;
};

const fieldName = /^[a-z][a-z0-9_]{0,63}$/;
const canonicalFields = new Set(['title', 'asset', 'target', 'weakness', 'vulnerability_type', 'endpoint', 'severity',
  'technical_severity', 'cvss_vector', 'vrt_category', 'summary', 'description', 'prerequisites',
  'steps_to_reproduce', 'expected_behavior', 'actual_behavior', 'impact', 'demonstrated_impact', 'remediation']);

export function parseRequirementsForm(form: RequirementsForm): ProgramRequirements | null {
  try {
    const required: unknown = JSON.parse(form.requiredFields);
    const additional: unknown = JSON.parse(form.additionalFields);
    if ((form.verified && !form.source.trim()) || [form.source, form.reportTemplate, form.impactTemplate].some(value => [...value].length > 8192)
      || !Array.isArray(required) || required.length > 64 || !required.every(value => text(value) && fieldName.test(value))
      || new Set(required).size !== required.length || !textMap(additional) || Object.keys(additional).length > 64
      || !Object.entries(additional).every(([key, value]) => fieldName.test(key) && !canonicalFields.has(key) && [...value].length <= 8192)) return null;
    const rules = { source: form.source, verified: form.verified, severity_required: form.severityRequired,
      required_fields: required, additional_fields: additional, report_template: form.reportTemplate || null,
      impact_template: form.impactTemplate || null };
    return new TextEncoder().encode(JSON.stringify(rules)).length <= 131072 ? rules : null;
  } catch { return null; }
}
