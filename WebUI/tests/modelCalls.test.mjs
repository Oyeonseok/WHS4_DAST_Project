import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseModelCallPage, parseScanTokenUsage, tokenStages } from '../src/lib/modelCalls.ts';

const event = {
  event_id: 12,
  call_id: 'call-1',
  state: 'success',
  occurred_at: '2026-09-27T00:00:00Z',
  scan_id: 'scan-1',
  stage: 'Recon',
  stage_run_id: null,
  task_id: null,
  case_id: null,
  scope_job_id: null,
  operation_code: 'recon_plan',
  invocation_kind: 'structured',
  requested_model: null,
  elapsed_ms: 125,
  error_code: null,
  input_tokens: null,
  cached_input_tokens: null,
  output_tokens: null,
  usage_status: 'not_captured',
};

test('model call pages keep only typed metadata and pagination', () => {
  const page = parseModelCallPage({
    events: [{ ...event, prompt: 'secret prompt', stderr: 'secret stderr' }],
    next_before: 12,
  });
  assert.deepEqual(page, { events: [event], next_before: 12 });
});

test('model call pages reject malformed data without inventing usage', () => {
  assert.equal(parseModelCallPage({ events: [], next_before: -1 }), null);
  assert.equal(parseModelCallPage({ events: 'bad', next_before: null }), null);
  assert.deepEqual(parseModelCallPage({
    events: [{ ...event, event_id: 0 }, { ...event, state: 'invalid' }, { ...event, state: { toString: () => 'success' } }, { ...event, output_tokens: '0' }],
    next_before: null,
  }), { events: [], next_before: null });
  assert.deepEqual(parseModelCallPage({ events: [{ ...event, output_tokens: 0 }], next_before: null }), {
    events: [{ ...event, output_tokens: 0 }], next_before: null,
  });
});

test('scan token totals exclude cached input and retain unreported calls', () => {
  const zero = { input_tokens: 0, output_tokens: 0, total_tokens: 0, measured_calls: 0, unreported_calls: 0 };
  const recon = { input_tokens: 8, output_tokens: 2, total_tokens: 10, measured_calls: 1, unreported_calls: 1 };
  const data = {
    scan_id: 'scan-1', total: recon,
    stages: Object.fromEntries(tokenStages.map(stage => [stage, stage === 'Recon' ? recon : zero])),
    unattributed: zero,
  };
  assert.deepEqual(parseScanTokenUsage(data, 'scan-1'), data);
  assert.equal(parseScanTokenUsage(data, 'scan-2'), null);
  assert.equal(parseScanTokenUsage({ ...data, total: { ...recon, total_tokens: 13 } }, 'scan-1'), null);
  assert.equal(parseScanTokenUsage({ ...data, stages: { Recon: recon } }, 'scan-1'), null);
  assert.equal(parseScanTokenUsage({ ...data, total: { ...recon, unreported_calls: -1 } }, 'scan-1'), null);
});
