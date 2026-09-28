import { test } from 'node:test';
import assert from 'node:assert/strict';

const submission = await import('../src/lib/reportSubmission.ts').catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {};
  throw error;
});

const reportId = 'report_' + 'a'.repeat(32);
const response = {
  report_id: reportId, platform: 'hackerone', ready: true, revision_sha256: 'b'.repeat(64),
  requirements: { verified: true, source: 'https://example.invalid/program', severity_required: false,
    required_fields: [], additional_fields: {}, report_template: null, impact_template: null },
  fields: { title: 'Fixture report', summary: 'Bounded evidence' }, markdown: '# Fixture report',
  evidence: [{ evidence_id: 'evidence_case', kind: 'observation', details: { summary: 'Bounded' },
    content_sha256: 'c'.repeat(64), sanitized_sha256: 'd'.repeat(64) }],
  checks: [{ code: 'source', level: 'pass', field: null, message: 'Source is current.' }],
  redactions: [{ kind: 'token', count: 1 }],
};

test('submission response belongs to the selected report and preserves safe export revision', () => {
  assert.equal(typeof submission.parseReportSubmission, 'function');
  const parsed = submission.parseReportSubmission?.(response, reportId);
  assert.equal(parsed?.revision_sha256, 'b'.repeat(64));
  assert.equal(submission.canExportSubmission?.(parsed, reportId), true);
  assert.equal(submission.parseReportSubmission?.(response, 'report_' + 'e'.repeat(32)), null);
});

test('malformed and contradictory checks never enable submission export', () => {
  assert.equal(typeof submission.parseReportSubmission, 'function');
  for (const value of [null, {}, { ...response, ready: 'true' },
    { ...response, revision_sha256: '' }, { ...response, evidence: 'untrusted' },
    { ...response, fields: { title: {} } }, { ...response, platform: 'unknown' },
    { ...response, checks: [{ code: 'source', level: 'blocker', field: null, message: 'Stale source' }] },
    { ...response, checks: [{ code: 'source', level: 'unknown', field: null, message: 'Unknown' }] },
    { ...response, requirements: { ...response.requirements, verified: false } },
    { ...response, evidence: [{ ...response.evidence[0], sanitized_sha256: '../file' }] },
    { ...response, redactions: [{ kind: 'token', count: -1 }] },
  ]) assert.equal(submission.parseReportSubmission?.(value, reportId), null);
});

test('blocked reports remain inspectable but cannot be exported', () => {
  assert.equal(typeof submission.parseReportSubmission, 'function');
  const parsed = submission.parseReportSubmission?.({ ...response, ready: false,
    checks: [{ code: 'severity', level: 'blocker', field: 'severity', message: 'Severity required' }] }, reportId);
  assert.equal(parsed?.ready, false);
  assert.equal(submission.canExportSubmission?.(parsed, reportId), false);
  assert.equal(submission.canExportSubmission?.(response, 'report_' + 'e'.repeat(32)), false);
});

const form = { source: response.requirements.source, verified: true, severityRequired: false,
  requiredFields: '["researcher_ip"]', additionalFields: '{"researcher_ip":"192.0.2.1"}',
  reportTemplate: '', impactTemplate: 'Impact: {impact}' };

test('program form parses snake case rules and optional templates', () => {
  assert.equal(typeof submission.parseRequirementsForm, 'function');
  assert.deepEqual(submission.parseRequirementsForm?.(form), {
    verified: true, source: form.source, severity_required: false,
    required_fields: ['researcher_ip'], additional_fields: { researcher_ip: '192.0.2.1' },
    report_template: null, impact_template: 'Impact: {impact}',
  });
});

test('invalid rules fail before saving and edited rules disable export', () => {
  assert.equal(typeof submission.parseRequirementsForm, 'function');
  for (const changes of [
    { source: '   ' }, { requiredFields: '{}' }, { requiredFields: '["title","title"]' },
    { requiredFields: '["Title"]' }, { additionalFields: '[]' },
    { additionalFields: '{"custom":2}' }, { additionalFields: '{"title":"override"}' },
    { reportTemplate: 'a'.repeat(8193) }, { additionalFields: '{broken' },
  ]) assert.equal(submission.parseRequirementsForm?.({ ...form, ...changes }), null);
  assert.equal(submission.canExportSubmission?.(response, reportId, true), false);
});
