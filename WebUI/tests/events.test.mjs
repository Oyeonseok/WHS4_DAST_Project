import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEvent, parseSnapshot, applyEvent, applyOrderedEvent, stages } from '../src/lib/events.ts';
import { demoSnapshot, DEMO_SCAN } from '../src/data/demo.ts';
import { translate } from '../src/lib/i18n.ts';

const event = (id = 8, overrides = {}) => ({ version: 1, event_id: id, scan_id: DEMO_SCAN, occurred_at: '2026-09-20T06:00:00Z', type: 'log.appended', payload: { stage: 'Attack', level: 'info', message: 'Redacted fixture event' }, ...overrides });
test('dashboard labels support Korean and preserve English', () => {
  assert.equal(translate('ko', 'Scopes / Programs'), '스코프 / 프로그램');
  assert.equal(translate('ko', 'Yes · Approve Scope'), 'Yes · Scope 승인');
  assert.equal(translate('en', 'Scopes / Programs'), 'Scopes / Programs');
});
test('pipeline includes report and preserves the real stage order', () => assert.deepEqual(stages, ['Scope','Recon','Attack','Chaining','Validation','Report']));
test('snapshot validates the synthetic scan independently', () => {
  const data = demoSnapshot();
  assert.deepEqual(parseSnapshot(data, DEMO_SCAN), data);
});
test('invalid snapshots do not fall back to fixture data', () => {
  for (const patch of [{ version: 2 }, { last_event_id: -1 }, { stage: 'unknown' }, { progress: 101 }, { budget: -1 }, { findings: [{}] }, { logs: [{}] }, { logs: [{ ...demoSnapshot().logs[0], id: 900 }] }]) assert.equal(parseSnapshot({ ...demoSnapshot(), ...patch }, DEMO_SCAN), null);
  assert.equal(parseSnapshot(demoSnapshot(), 'other-scan'), null);
});
test('snapshot log history is sorted and deduplicated', () => {
  const data = demoSnapshot(); data.logs = [data.logs[3], data.logs[0], data.logs[3]];
  assert.deepEqual(parseSnapshot(data, DEMO_SCAN).logs.map(l => l.id), [1, 4]);
});
test('malformed JSON, foreign scans, versions, and unknown events are rejected', () => {
  for (const raw of ['{', 'null', '[]', event(8,{version:2}), event(8,{scan_id:'other'}), event(-1), event(8,{type:'something.new'}), event(8,{occurred_at:'not-a-date'}), event(8,{payload:{}})]) assert.equal(parseEvent(raw, DEMO_SCAN), null);
});
test('valid event payload is preserved', () => assert.deepEqual(parseEvent(JSON.stringify(event()), DEMO_SCAN), event()));
test('progress payloads reject NaN, negative requests and values beyond 100', () => {
  for (const payload of [{progress:NaN,requests:1},{progress:101,requests:1},{progress:20,requests:-1}]) assert.equal(parseEvent(event(8,{type:'task.progress.updated',payload}), DEMO_SCAN), null);
});
test('duplicate or old events never duplicate logs or regress the cursor', () => {
  const next = applyEvent(demoSnapshot(), event());
  assert.equal(next.last_event_id,8); assert.equal(next.logs.length,8);
  assert.equal(applyEvent(next,event()),next);
  assert.equal(applyEvent(next,event(3)),next);
});
test('out-of-order events buffer until the missing event arrives', () => {
  const pending = new Map(); const start = demoSnapshot();
  const waiting = applyOrderedEvent(start,event(10),pending);
  assert.equal(waiting,start);
  const partial = applyOrderedEvent(waiting,event(8),pending);
  assert.equal(partial.last_event_id,8);
  const complete = applyOrderedEvent(partial,event(9),pending);
  assert.equal(complete.last_event_id,10);
  assert.deepEqual(complete.logs.slice(-3).map(l=>l.id),[8,9,10]); assert.equal(pending.size,0);
});
test('a large event gap fails explicitly and does not grow the buffer', () => {
  const pending = new Map(); assert.throws(() => applyOrderedEvent(demoSnapshot(),event(500),pending), /replay buffer/); assert.equal(pending.size,0);
});
test('heartbeats never consume durable event IDs', () => {
  const start = demoSnapshot(); const heartbeat = event(99,{type:'heartbeat',payload:{}});
  assert.equal(applyOrderedEvent(start,heartbeat,new Map()),start);
});
test('stage, scan status, and finding changes update the snapshot', () => {
  let next = applyEvent(demoSnapshot(),event(8,{type:'stage.status.changed',payload:{stage:'Chaining'}}));
  assert.equal(next.stage,'Chaining'); assert.equal(next.progress,0);
  next = applyEvent(next,event(9,{type:'scan.status.changed',payload:{status:'completed'}})); assert.equal(next.status,'completed');
  next = applyEvent(next,event(10,{type:'finding.updated',payload:{...next.findings[0],status:'confirmed'}}));
  assert.equal(next.findings.length,4); assert.equal(next.findings.find(f=>f.id==='F-0042').status,'confirmed');
});
test('log retention is bounded while event cursor keeps advancing', () => {
  let next = demoSnapshot();
  for (let i=8;i<=700;i++) next=applyEvent(next,event(i));
  assert.equal(next.logs.length,500); assert.equal(next.last_event_id,700); assert.equal(next.logs[0].id,201);
});
