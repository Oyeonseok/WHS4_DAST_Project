import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { canLaunchWithPolicyInputs } from '../src/lib/scan.ts';
import * as components from '../src/components/ScopeExecutionRules.ts';
import { ScopePolicyReferences } from '../src/components/ScopePolicyReferences.ts';

const advisory = {label:'Unclear applicability',reason:'The reference context is incomplete.',source_quote:'See the policy for context.',guidance:'Proceed within explicit authorization.',target_assets:['app.example']};
const rules = {exclusions:[],request_limits:[],option_limits:[],advisories:[advisory]};
const warningOnly = {execution_requirements_status:'ready',execution_rules:rules,policy_inputs:[],policy_confirmations:[],policy_blockers:[]};

test('reviewed warnings permit launch while applicable hard blockers still prevent it', () => {
  assert.equal(canLaunchWithPolicyInputs(warningOnly,['app.example'],{},[]),true);
  assert.equal(canLaunchWithPolicyInputs({...warningOnly,policy_blockers:[{...advisory,label:'Mandatory control'}]},['app.example'],{},[]),false);
  assert.equal(canLaunchWithPolicyInputs({...warningOnly,execution_requirements_status:'pending'},['app.example'],{},[]),false);
});

test('compact warnings expand reason, source and guidance without adding consent', () => {
  assert.equal(typeof components.ScopePolicyAdvisories,'function');
  const html=renderToStaticMarkup(createElement(components.ScopePolicyAdvisories,{advisories:rules.advisories,selectedAssets:['app.example']}));
  assert.match(html,/<details/); assert.match(html,/<summary/);
  for(const text of [advisory.label,advisory.reason,advisory.source_quote,advisory.guidance]) assert.ok(html.includes(text),text);
  assert.ok(!html.includes('checkbox')); assert.ok(!html.includes('role="alert"')); assert.ok(!html.includes(' open=""'));
});

test('scan warnings filter exact selected targets and draft rules show all advisories', () => {
  assert.equal(typeof components.ScopePolicyAdvisories,'function');
  const advisories=[advisory,{...advisory,label:'Global guidance',target_assets:[]}];
  const html=renderToStaticMarkup(createElement(components.ScopePolicyAdvisories,{advisories,selectedAssets:['other.example']}));
  assert.ok(!html.includes(advisory.label)); assert.ok(html.includes('Global guidance'));
  const draft=renderToStaticMarkup(createElement(components.ScopeExecutionRules,{rules:{...rules,advisories}}));
  assert.ok(draft.includes(advisory.label)); assert.ok(draft.includes('Global guidance'));
  assert.equal(renderToStaticMarkup(createElement(components.ScopePolicyAdvisories,{advisories:[]})),'');
});

test('reference review displays semantic relationship and legacy uncertainty', () => {
  const reference={requested_url:'https://example.com/policy',final_url:null,status:'unresolved',applicability:'unknown',source_quote:'Context link',error:'Not captured'};
  const html=renderToStaticMarkup(createElement(ScopePolicyReferences,{references:[{...reference,relationship:'supporting'},reference],language:'en'}));
  assert.ok(html.includes('Supporting')); assert.ok(html.includes('Uncertain'));
});

test('prepared Agent conditions remain visible when request guards are ready', () => {
  const preparation={held:0,denied:0,captured_candidates:0,rejected_captures:0,resources:[],agent_guidance:[advisory]};
  const html=renderToStaticMarkup(createElement(components.ScopeExclusionStatus,{count:1,preparation}));
  assert.ok(html.includes('0 held, 0 denied'));
  assert.ok(html.includes(advisory.label));
  assert.ok(html.includes(advisory.source_quote));
  assert.ok(html.includes(advisory.guidance));
});
