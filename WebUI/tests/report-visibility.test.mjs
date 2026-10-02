import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  confirmedReportSummaries, parseReportSummaries, parseScanExecutionSummary,
  requestReportSummaries, requestScanExecutionSummary,
} from '../src/lib/reports.ts';

const report = { report_id: 'report_' + 'a'.repeat(32), scan_id: 'scan_a', case_id: 'case_a',
  platform: 'generic', language: 'en', title: 'Verified fixture', created_at: '2026-10-01T00:00:00Z' };
const summary = { scan_id: 'scan_a', execution_status: 'partial', inventory: { endpoints: 4 },
  validation: { current_confirmed: 1, statuses: { CONFIRMED: 1 }, phases: { completed: 1 } },
  reports: [{ report_id: report.report_id, case_id: report.case_id, status: 'drafted', platform: 'generic' }],
  errors: [{ stage: 'report', error_type: 'TimeoutError' }], markdown: '# Execution summary' };
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

test('a missing optional summary does not prevent report drafts from loading', async () => {
  const signal = new AbortController().signal;
  const fetch = async url => url.pathname.endsWith('/summary') ? response(null, 404) : response({ reports: [report] });
  const [reports, execution] = await Promise.all([
    requestReportSummaries('http://fixture', 'scan_a', signal, fetch),
    requestScanExecutionSummary('http://fixture', 'scan_a', signal, fetch),
  ]);
  assert.deepEqual(reports, [report]);
  assert.equal(execution, null);
});

test('summary network, HTTP and malformed-data failures leave report loading independent', async () => {
  for (const failure of [new Error('Summary disconnected'), response({ detail: 'Summary unavailable' }, 503), response({ scan_id: 'scan_a', markdown: 'Incomplete artifact' })]) {
    const fetch = async url => {
      if (!url.pathname.endsWith('/summary')) return response({ reports: [report] });
      if (failure instanceof Error) throw failure;
      return failure;
    };
    const results = await Promise.allSettled([
      requestReportSummaries('http://fixture', 'scan_a', new AbortController().signal, fetch),
      requestScanExecutionSummary('http://fixture', 'scan_a', new AbortController().signal, fetch),
    ]);
    assert.deepEqual(results[0], { status: 'fulfilled', value: [report] });
    assert.equal(results[1].status, 'rejected');
  }
});

test('report failures do not hide an available execution summary', async () => {
  const fetch = async url => url.pathname.endsWith('/summary') ? response(summary) : response({ detail: [{ msg: 'Draft service unavailable' }] }, 503);
  const results = await Promise.allSettled([
    requestReportSummaries('http://fixture', 'scan_a', new AbortController().signal, fetch),
    requestScanExecutionSummary('http://fixture', 'scan_a', new AbortController().signal, fetch),
  ]);
  assert.equal(results[0].reason.message, 'Draft service unavailable');
  assert.deepEqual(results[1], { status: 'fulfilled', value: summary });
});

test('summary fields used by the screen must be present and valid before rendering', () => {
  assert.deepEqual(parseScanExecutionSummary(summary, 'scan_a'), summary);
  for (const changes of [
    { scan_id: 'scan_b' }, { execution_status: ['completed'] }, { inventory: null }, { inventory: { endpoints: -1 } },
    { validation: {} }, { validation: { ...summary.validation, current_confirmed: '1' } },
    { validation: { ...summary.validation, phases: null } }, { reports: null }, { reports: [{ status: {} }] },
    { errors: null }, { errors: [{ error_type: {} }] }, { markdown: null },
  ]) assert.equal(parseScanExecutionSummary({ ...summary, ...changes }, 'scan_a'), null);
});

test('a report response for another scan or malformed draft is rejected', () => {
  assert.deepEqual(parseReportSummaries({ reports: [report] }, 'scan_a'), [report]);
  assert.deepEqual(parseReportSummaries({ reports: [] }, 'scan_a'), []);
  for (const changes of [{ scan_id: 'scan_b' }, { report_id: '../private' }, { language: 'unknown' }, { title: {} }]) {
    assert.equal(parseReportSummaries({ reports: [{ ...report, ...changes }] }, 'scan_a'), null);
  }
});

test('visibility requires the selected scan and a current completed confirmed case', () => {
  const cases = [{ case_id: 'case_a', processing_phase: 'completed', current_status: 'CONFIRMED' }];
  const foreign = { ...report, scan_id: 'scan_b' };
  assert.deepEqual(confirmedReportSummaries([report, foreign], cases, 'scan_a'), [report]);
  for (const current_status of [null, 'PENDING', 'REJECTED', 'KNOWN']) {
    assert.deepEqual(confirmedReportSummaries([report], [{ ...cases[0], current_status }], 'scan_a'), []);
  }
  assert.deepEqual(confirmedReportSummaries([report], [{ ...cases[0], processing_phase: 'reviewing' }], 'scan_a'), []);
  assert.deepEqual(confirmedReportSummaries([report], [], 'scan_a'), []);
});
