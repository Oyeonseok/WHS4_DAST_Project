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

test('report content locale is preserved independently of the UI and invalid locales are rejected', () => {
  assert.equal(submission.parseReportSubmission({ ...response, platform: 'generic', language: 'en' }, reportId)?.language, 'en');
  assert.equal(submission.parseReportSubmission({ ...response, language: 'unknown' }, reportId), null);
  assert.equal(submission.parseReportSubmission({ ...response, language: null }, reportId), null);
  assert.notEqual(submission.parseReportSubmission(response, reportId), null);
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

test('reader-facing evidence summaries remain text and cannot accept malformed display data', () => {
  const evidence = { ...response.evidence[0], display: { label: '재현 요청', response: 'HTTP 200', result: '판별 조건 충족' } };
  const value = { ...response, evidence: [evidence] };
  assert.deepEqual(submission.parseReportSubmission(value, reportId)?.evidence[0].display, evidence.display);
  assert.equal(submission.parseReportSubmission({ ...value, evidence: [{ ...evidence, display: { ...evidence.display, result: 200 } }] }, reportId), null);
});

test('generic reports export without platform rules and still respect source blockers', () => {
  const generic = { ...response, platform: 'generic', requirements: {
    ...response.requirements, verified: false, source: '', severity_required: false,
  } };
  const parsed = submission.parseReportSubmission(generic, reportId);
  assert.equal(parsed?.platform, 'generic');
  assert.equal(submission.canExportSubmission(parsed, reportId), true);
  const blocked = submission.parseReportSubmission({ ...generic, ready: false, checks: [
    { code: 'source_integrity', level: 'blocker', field: null, message: 'Stale source' },
  ] }, reportId);
  assert.equal(blocked?.ready, false);
  assert.equal(submission.canExportSubmission(blocked, reportId), false);
  assert.equal(submission.parseReportSubmission({ ...generic, checks: blocked.checks }, reportId), null);
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

const poc = { status: 'ready', mode: 'evidence_replay', source_revision: response.revision_sha256,
  filename: 'Video.webm', sha256: 'e'.repeat(64), byte_size: 500000, duration_seconds: 10,
  width: 1280, height: 720, chapters: 2 };

test('PoC metadata accepts bounded evidence replay and empty cache states', () => {
  assert.equal(typeof submission.parsePocInfo, 'function');
  assert.deepEqual(submission.parsePocInfo?.(poc), poc);
  for (const status of ['missing', 'stale', 'blocked']) {
    const info = { status, mode: 'evidence_replay', source_revision: null, filename: null,
      sha256: null, byte_size: null, duration_seconds: null, width: null, height: null, chapters: null };
    assert.deepEqual(submission.parsePocInfo?.(info), info);
  }
});

test('PoC status must be a string even for an empty cache', () => {
  const empty = { mode: 'evidence_replay', source_revision: null, filename: null,
    sha256: null, byte_size: null, duration_seconds: null, width: null, height: null, chapters: null };
  for (const status of [['missing'], { status: 'missing' }, null, 0, true]) {
    assert.equal(submission.parsePocInfo({ ...empty, status }), null);
  }
});

test('malformed ready PoC metadata never produces a preview', () => {
  assert.equal(typeof submission.parsePocInfo, 'function');
  for (const changes of [{ status: 'unknown' }, { mode: 'live' }, { source_revision: null },
    { source_revision: 'x'.repeat(64) }, { filename: '../Video.webm' }, { sha256: null },
    { byte_size: 0 }, { byte_size: 10000001 }, { byte_size: 2.5 }, { duration_seconds: NaN },
    { duration_seconds: 61 }, { duration_seconds: 5 }, { width: 1920 }, { height: 1080 },
    { chapters: 0 }, { chapters: 13 }, { chapters: 1.5 }, { width: null },
  ]) assert.equal(submission.parsePocInfo?.({ ...poc, ...changes }), null);
  assert.equal(submission.parsePocInfo?.({ ...poc, status: 'missing' }), null);
});

test('preview and export reject stale report, dirty rules and pending actions', () => {
  assert.equal(typeof submission.canPreviewPoc, 'function');
  assert.equal(submission.canPreviewPoc?.(poc, response, reportId), true);
  for (const info of [null, { ...poc, status: 'stale' }, { ...poc, source_revision: 'f'.repeat(64) },
    { ...poc, byte_size: 10000001 }]) assert.equal(submission.canPreviewPoc?.(info, response, reportId), false);
  assert.equal(submission.canPreviewPoc?.(poc, response, 'report_' + 'f'.repeat(32)), false);
  assert.equal(submission.canPreviewPoc?.(poc, response, reportId, true), false);
  assert.equal(submission.canPreviewPoc?.(poc, response, reportId, false, true), false);
  assert.equal(submission.canPreviewPoc?.(poc, { ...response, ready: false }, reportId), false);
  assert.equal(submission.canExportSubmission?.(response, reportId, false, true), false);
  // Missing cache does not require users to manually prepare a video before export.
  assert.equal(submission.canExportSubmission?.(response, reportId, false, false), true);
});
