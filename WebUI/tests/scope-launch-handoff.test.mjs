import { test } from 'node:test';
import assert from 'node:assert/strict';
import { approvedScopeSelection } from '../src/lib/scan.ts';

test('approved Scope selection is preserved in the scan launch contract', () => {
  const targets = ['app.example.test', 'api.example.test'];
  const payload = approvedScopeSelection(' scope_approved ', targets);

  assert.deepEqual(payload, {
    scope_id: 'scope_approved',
    targets: ['app.example.test', 'api.example.test'],
  });
  targets[0] = 'outside.example.test';
  assert.equal(payload.targets[0], 'app.example.test');
});

test('scan launch selection rejects missing Scope or targets', () => {
  assert.throws(() => approvedScopeSelection('', ['app.example.test']), /approved Scope/);
  assert.throws(() => approvedScopeSelection('scope_approved', []), /at least one target/);
  assert.throws(() => approvedScopeSelection('scope_approved', ['']), /at least one target/);
});
