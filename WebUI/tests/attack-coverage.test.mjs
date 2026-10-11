import assert from 'node:assert/strict';
import test from 'node:test';
import { coverageMetrics } from '../src/lib/attackCoverage.ts';
import { agentWorkLabel } from '../src/lib/activityMessages.ts';

test('a resolved auth/policy/budget blocker never counts as a tested hypothesis', () => {
  const metrics = coverageMetrics({ total: 12, resolved: 9, tested: 2, unfinished: 3,
    by_status: { tested_negative: 2, blocked_auth: 3, policy_excluded: 2, unsupported: 2, pending: 3 },
    budget_limited: 1, endpoints_total: 20, endpoints_reviewed: 20,
    insufficient_evidence_endpoints: 7, not_applicable_endpoints: 1 });
  assert.equal(metrics.find(item => item.key === 'tested').value, 2);
  assert.equal(metrics.find(item => item.key === 'unfinished').value, 3);
  assert.equal(metrics.find(item => item.key === 'blocked_auth').value, 3);
  assert.equal(metrics.find(item => item.key === 'budget_limited').value, 1);
  assert.equal(metrics.find(item => item.key === 'insufficient_evidence').value, 7);
});

test('planning activity exposes reviewed endpoint counts in both languages', () => {
  const params = {agent: 'attack', step: 'planning', state: 'progress', processed: 16, endpoint_total: 65};
  assert.match(agentWorkLabel('ko', params), /16\/65/);
  assert.match(agentWorkLabel('en', params), /16\/65/);
});

test('ungrounded proposals are shown separately from completed tests', () => {
  const metrics=coverageMetrics({total:1,resolved:0,tested:0,unfinished:1,by_status:{pending:1},budget_limited:0,
    endpoints_total:2,endpoints_reviewed:2,insufficient_evidence_endpoints:1,not_applicable_endpoints:0,planning_unresolved:3});
  assert.equal(metrics.find(item=>item.key==='planning_unresolved').value,3);
  assert.equal(metrics.find(item=>item.key==='tested').value,0);
});

test('planning repair activity shows the bounded correction round', () => {
  const params={agent:'attack',step:'planning',state:'progress',processed:0,endpoint_total:15,repair_attempt:1,repair_limit:2,validation_issue_count:3};
  assert.match(agentWorkLabel('ko',params),/보정 1\/2/);
  assert.match(agentWorkLabel('en',params),/correction 1\/2/);
});
