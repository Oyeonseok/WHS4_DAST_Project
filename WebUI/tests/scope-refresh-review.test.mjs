import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as scope from '../src/lib/scope.ts';

// A broken request builder would turn Collect again into an idempotent lookup.
test('initial collection is ordinary and Collect again explicitly requests refresh', () => {
  assert.equal(typeof scope.scopeRequestForStatus, 'function');
  assert.deepEqual(scope.scopeRequestForStatus('scope_required'), {login_mode:'runtime-browser',identity:'primary',refresh:false,model:'gpt-5.6-sol'});
  for (const status of ['approved','failed','rejected','cancelled']) {
    assert.equal(scope.scopeRequestForStatus(status).refresh, true);
  }
});

test('Scope request preserves a selected model distinct from the default', () => {
  assert.equal(scope.scopeRequestForStatus('approved', 'gpt-6-astra').model, 'gpt-6-astra');
  for (const model of ['gpt-6-astra', 'provider/custom']) assert.equal(scope.isValidScopeModel(model), true);
  for (const model of ['', 'https://example.test/model', 'gpt model', 'gpt\nmodel', 'gpt-6\n', 'x'.repeat(129)]) {
    assert.equal(scope.isValidScopeModel(model), false);
  }
});

test('new approval selection uses exact scope ID when multiple versions share one program', () => {
  assert.equal(typeof scope.selectApprovedScope, 'function');
  const versions = [{scope_id:'scope_old',program_id:'one'}, {scope_id:'scope_new',program_id:'one'}];
  assert.equal(scope.selectApprovedScope(versions, 'scope_new'), 'scope_new');
  assert.equal(scope.selectApprovedScope(versions, 'scope_old'), 'scope_old');
  assert.equal(scope.selectApprovedScope([], 'missing'), '');
});

test('late responses cannot change a closed or replaced Scope workflow', async () => {
  const guard = scope.createScopeResponseGuard();
  let applyOldResponse;
  const delayed = new Promise(resolve => { applyOldResponse = resolve; });
  const oldCurrent = guard.capture();
  const applied = delayed.then(() => oldCurrent() ? 'old program' : 'ignored');
  guard.invalidate();
  const newCurrent = guard.capture();
  applyOldResponse();
  assert.equal(await applied, 'ignored');
  assert.equal(newCurrent(), true);
  guard.invalidate();
  assert.equal(newCurrent(), false);
});

test('responses remain usable while the same Scope workflow stays selected', () => {
  const guard = scope.createScopeResponseGuard();
  const current = guard.capture();
  assert.equal(current(), true);
  assert.equal(current(), true);
});

test('reference review exposes URL, status, applicability, provenance and failures compactly', async () => {
  const {ScopePolicyReferences} = await import('../src/components/ScopePolicyReferences.ts');
  const refs = [{requested_url:'https://docs.example.test/testing',final_url:'https://docs.example.test/v2',status:'captured',applicability:'testing',source_quote:'Read our testing guide.',error:null},
    {requested_url:'https://docs.example.test/disclosure',final_url:null,status:'unresolved',applicability:'disclosure',source_quote:'Follow the disclosure guide.',error:'Unsupported document format'}];
  const html = renderToStaticMarkup(createElement(ScopePolicyReferences,{references:refs,open:true,language:'en'}));
  for (const text of ['https://docs.example.test/testing','https://docs.example.test/v2','Captured','Testing','Unresolved','Disclosure','Read our testing guide.','Unsupported document format']) {
    assert.ok(html.includes(text), `Missing reference detail: ${text}`);
  }
  assert.ok(!html.includes('<input'), 'Review must keep aggregate authorization only');
});
