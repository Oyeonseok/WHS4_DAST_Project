import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as scan from '../src/lib/scan.ts';
const input = { key:'email',label:'Testing email',kind:'email',allowed_email_domains:['example.com'],target_assets:['https://prod/'],source_quote:'Use example.com.' };
const confirmation = {key:'contact',label:'Contacted production',target_assets:['https://prod/'],source_quote:'Contact production.'};
const requirements = { execution_requirements_status:'ready', execution_rules:{request_limits:[],option_limits:[],exclusions:[]},policy_inputs:[input],policy_confirmations:[confirmation],policy_blockers:[] };
test('only exact selected assets activate prerequisites and stale payload values are omitted',()=>{
 assert.equal(scan.canLaunchWithPolicyInputs?.(requirements,['https://dev/'],{},[]),true);
 assert.equal(scan.canLaunchWithPolicyInputs?.(requirements,['https://prod/'],{email:'a@other.com'},['contact']),false);
 assert.equal(scan.canLaunchWithPolicyInputs?.(requirements,['https://prod/'],{email:'a@EXAMPLE.com'},['contact']),true);
 assert.deepEqual(scan.policyLaunchValues?.(requirements,['https://dev/'],{email:'a@example.com'},['contact']),{policy_values:{},policy_confirmations:[]});
});
test('pending, absent rules and unsupported blockers fail closed',()=>{
 for(const r of [{...requirements,execution_requirements_status:'pending'},{...requirements,execution_rules:null},{...requirements,policy_blockers:[{label:'Unsupported',reason:'Unknown',source_quote:'Unknown control.'}]}]) assert.equal(scan.canLaunchWithPolicyInputs?.(r,[],{},[]),false);
});
test('window quota labels preserve declared units and scope',()=>{
 assert.equal(scan.requestLimitLabel?.({maximum:10,period_seconds:60,scope:'program'}),'10 requests per 60 seconds · program');
 assert.equal(scan.requestLimitLabel?.({maximum:100,period_seconds:null,scope:'target'}),'100 requests total · target');
});
test('structured option caps narrow existing profile limits',()=>{
 const r={profiles:[{id:'safe-recon',limits:{concurrency:5,max_requests:500,timeout_seconds:30,max_depth:3,requests_per_second:2}}],scope_max_requests_per_second:null,execution_rules:{option_limits:[{field:'concurrency',value:1},{field:'max_requests',value:20}]}};
 assert.equal(scan.resolveExecutionLimits(r,'safe-recon').concurrency,1);
 assert.equal(scan.resolveExecutionLimits(r,'safe-recon').max_requests,20);
});
test('approval renders structured restrictions and complete prerequisite evidence',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');
 let component;try { component=(await import('../src/components/ScopeExecutionRules.ts')).ScopeExecutionRules; }catch {}
 assert.equal(typeof component,'function');
 const html=renderToStaticMarkup(createElement(component,{rules:{request_limits:[{maximum:10,period_seconds:60,scope:'program',source_quote:'Ten per minute.'}],option_limits:[{field:'concurrency',value:1,source_quote:'One worker.'}],required_inputs:[input],required_confirmations:[confirmation],blocking_requirements:[{label:'Unknown control',reason:'Unsupported',source_quote:'Mandatory unknown.'}]}}));
 for(const text of ['10 requests per 60 seconds · program','Ten per minute.','concurrency','One worker.','Testing email','example.com','https://prod/','Contacted production','Contact production.','Unsupported','Mandatory unknown.']) assert.ok(html.includes(text),text);
});
test('missing confirmation, all-target requirements and empty permissions block launch',()=>{
 assert.equal(scan.canLaunchWithPolicyInputs(requirements,['https://prod/'],{email:'a@example.com'},[]),false);
 assert.equal(scan.canLaunchWithPolicyInputs({...requirements,policy_inputs:[{...input,target_assets:[]}]},['https://dev/'],{},[]),false);
 assert.equal(scan.canLaunchWithPolicyInputs({...requirements,execution_rules:{...requirements.execution_rules,allowed_methods:{values:[],source_quote:'No permitted methods.'}}},['https://dev/'],{},[]),false);
});
test('pending approval rules display Pending and explicit empty rules render without invented obligations',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');const {ScopeExecutionRules}=await import('../src/components/ScopeExecutionRules.ts');
 for (const rules of [null,undefined]) assert.match(renderToStaticMarkup(createElement(ScopeExecutionRules,{rules})),/Pending/);
 const html=renderToStaticMarkup(createElement(ScopeExecutionRules,{rules:{request_limits:[],option_limits:[],exclusions:[]}}));
 assert.ok(!html.includes('Pending'));assert.ok(!html.includes('Testing email'));
});
test('applicable shared header and policy inputs must have equal trimmed values',()=>{
 const shared={...requirements,header_inputs:[{key:'email',label:'Header email',kind:'email'}]};
 const policyValues={email:'policy@example.com'};
 assert.equal(scan.canLaunchWithPolicyInputs(shared,['https://prod/'],policyValues,['contact'],{email:'header@example.com'}),false);
 assert.equal(scan.canLaunchWithPolicyInputs(shared,['https://prod/'],policyValues,['contact'],{email:'policy@example.com'}),true);
 assert.equal(scan.canLaunchWithPolicyInputs(shared,['https://prod/'],{email:' policy@example.com '},['contact'],{email:'policy@example.com  '}),true);
 assert.equal(scan.canLaunchWithPolicyInputs(shared,['https://dev/'],policyValues,[],{email:'header@example.com'}),true);
 assert.deepEqual(scan.policyLaunchValues(shared,['https://dev/'],policyValues,['contact']),{policy_values:{},policy_confirmations:[]});
});
test('shared input conflict explanation identifies only applicable mismatched labels',()=>{
 const shared={...requirements,header_inputs:[{key:'email',label:'Header email',kind:'email'}]};
 assert.deepEqual(scan.sharedPolicyInputConflicts?.(shared,['https://prod/'],{email:'header@example.com'},{email:'policy@example.com'}),['Testing email']);
 assert.deepEqual(scan.sharedPolicyInputConflicts?.(shared,['https://prod/'],{email:' policy@example.com '},{email:'policy@example.com'}),[]);
 assert.deepEqual(scan.sharedPolicyInputConflicts?.(shared,['https://dev/'],{email:'header@example.com'},{email:'policy@example.com'}),[]);
});
test('conditional production and OTHER blockers apply only to their exact selected assets',()=>{
 const blockers=[{label:'Production control',reason:'Unsupported',source_quote:'Production requires VPN.',target_assets:['https://prod/']},{label:'Extension control',reason:'Unsupported',source_quote:'Extension requires review.',target_assets:['OTHER: browser extension']}];
 const conditional={...requirements,policy_inputs:[],policy_confirmations:[],policy_blockers:blockers};
 assert.equal(scan.canLaunchWithPolicyInputs(conditional,['https://stage/'],{},[]),true);
 assert.equal(scan.canLaunchWithPolicyInputs(conditional,['https://prod/'],{},[]),false);
 assert.equal(scan.canLaunchWithPolicyInputs(conditional,['OTHER: browser extension'],{},[]),false);
 assert.equal(scan.canLaunchWithPolicyInputs({...conditional,policy_blockers:[{...blockers[0],target_assets:[]}]},['https://stage/'],{},[]),false);
 assert.equal(scan.canLaunchWithPolicyInputs({...conditional,policy_blockers:[{label:'Global',reason:'Unsupported',source_quote:'Always required.'}]},['https://stage/'],{},[]),false);
 assert.deepEqual(scan.applicablePolicyRequirements(blockers,['https://stage/']),[]);
});
test('approval displays conditional blocker target alongside evidence',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');const {ScopeExecutionRules}=await import('../src/components/ScopeExecutionRules.ts');
 const html=renderToStaticMarkup(createElement(ScopeExecutionRules,{rules:{request_limits:[],option_limits:[],blocking_requirements:[{label:'Conditional',reason:'Unsupported',source_quote:'Production VPN.',target_assets:['https://conditional-prod/']}]}}));
 assert.ok(html.includes('https://conditional-prod/'));assert.ok(html.includes('Production VPN.'));
});
test('launch rules panel filters conditional blockers while approval retains complete evidence',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');const {ScopeExecutionRules}=await import('../src/components/ScopeExecutionRules.ts');
 const rules={request_limits:[],option_limits:[],blocking_requirements:[
  {label:'Production only',reason:'Unsupported',source_quote:'Production evidence.',target_assets:['https://prod/']},
  {label:'OTHER only',reason:'Unsupported',source_quote:'Extension evidence.',target_assets:['OTHER: extension']},
  {label:'Global empty',reason:'Unsupported',source_quote:'Empty global evidence.',target_assets:[]},
  {label:'Global legacy',reason:'Unsupported',source_quote:'Legacy global evidence.'},
 ]};
 const render=selectedAssets=>renderToStaticMarkup(createElement(ScopeExecutionRules,{rules,selectedAssets}));
 const staging=render(['https://stage/']);
 for(const label of ['Production only','OTHER only','Production evidence.','Extension evidence.']) assert.ok(!staging.includes(label),label);
 for(const label of ['Global empty','Global legacy']) assert.ok(staging.includes(label),label);
 const production=render(['https://prod/']);assert.ok(production.includes('Production only'));assert.ok(!production.includes('OTHER only'));
 const other=render(['OTHER: extension']);assert.ok(other.includes('OTHER only'));assert.ok(!other.includes('Production only'));
 const approval=render(undefined);for(const label of ['Production only','OTHER only','Production evidence.','Extension evidence.','https://prod/','OTHER: extension']) assert.ok(approval.includes(label),label);
});

test('policy rate fills the scan option even when a profile contains fallback defaults',()=>{
 const base={profiles:[{id:'safe-recon',limits:{concurrency:2,max_requests:500,timeout_seconds:15,max_depth:2,requests_per_second:0.5}}],execution_rules:{option_limits:[]}};
 for(const [rate,expected] of [[10,10],[0.1,0.1],[100,50],[null,0.5]]) {
  assert.equal(scan.resolveExecutionLimits({...base,scope_max_requests_per_second:rate},'safe-recon').requests_per_second,expected);
 }
});
test('one explicit authorization supplies only applicable policy acknowledgements',()=>{
 const r={...requirements,policy_confirmations:[confirmation,{key:'general',target_assets:[],label:'General',source_quote:'General obligation.'}]};
 assert.equal(typeof scan.policyConfirmationKeys,'function');
 assert.deepEqual(scan.policyConfirmationKeys(r,['https://prod/'],false),[]);
 assert.deepEqual(scan.policyConfirmationKeys({...r,execution_requirements_status:'pending'},['https://prod/'],true),[]);
 const acknowledged=scan.policyConfirmationKeys(r,['https://prod/'],true);
 assert.deepEqual(acknowledged,['contact','general']);
 assert.equal(scan.canLaunchWithPolicyInputs(r,['https://prod/'],{email:'a@example.com'},acknowledged),true);
 assert.deepEqual(scan.policyLaunchValues(r,['https://prod/'],{email:'a@example.com'},acknowledged),{policy_values:{email:'a@example.com'},policy_confirmations:['contact','general']});
 assert.deepEqual(scan.policyConfirmationKeys(r,['https://dev/'],true),['general']);
});
test('legacy exclusions remain pending even with ready status and review prints full condition tree',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');const {ScopeExecutionRules}=await import('../src/components/ScopeExecutionRules.ts');
 assert.equal(scan.canLaunchWithPolicyInputs({...requirements,execution_rules:{...requirements.execution_rules,exclusions:null}},['https://dev/'],{},[]),false);
 const exclusion={key:'conditional',label:'Restricted resources',source_quote:'Do not test managed resources unless public.',target_assets:['https://prod/'],condition:{operator:'all',children:[{operator:'predicate',predicate:{key:'kind',field:'semantic',operator:'equals',value:'managed resources'}},{operator:'not',children:[{operator:'predicate',predicate:{key:'public',field:'query',operator:'present',name:'public'}}]}]}};
 const html=renderToStaticMarkup(createElement(ScopeExecutionRules,{rules:{request_limits:[],option_limits:[],exclusions:[exclusion]}}));
 for(const text of ['conditional','Restricted resources','Do not test managed resources unless public.','https://prod/','all','not','semantic','managed resources','public']) assert.ok(html.includes(text),text);
 assert.ok(!html.includes('checkbox'));
});
test('compact exclusion status reports held reasons and no additional consent controls',async()=>{
 const {createElement}=await import('react');const {renderToStaticMarkup}=await import('react-dom/server');const module=await import('../src/components/ScopeExecutionRules.ts');
 assert.equal(typeof module.ScopeExclusionStatus,'function');
 const html=renderToStaticMarkup(createElement(module.ScopeExclusionStatus,{count:2,preparation:{held:1,denied:0,captured_candidates:0,rejected_captures:1,resources:[{decision:'hold',rule_keys:['restricted'],reason:'Missing captured evidence'}]}}));
 for(const text of ['2','1','restricted','Missing captured evidence']) assert.ok(html.includes(text));
 assert.ok(!html.includes('checkbox'));
});
