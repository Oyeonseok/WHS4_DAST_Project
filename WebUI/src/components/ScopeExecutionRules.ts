import { createElement as h } from 'react';
import { applicablePolicyRequirements, requestLimitLabel } from '../lib/scan.ts';
import type { ScopeExecutionRules as Rules, ExclusionPreparation, PolicyAdvisory } from '../lib/scan';

export function ScopePolicyAdvisories({ advisories, selectedAssets, language = 'en' }: { advisories?: readonly PolicyAdvisory[]; selectedAssets?: readonly string[]; language?: 'ko' | 'en' }) {
  const applicable = selectedAssets === undefined ? advisories ?? [] : applicablePolicyRequirements(advisories, selectedAssets);
  if (!applicable.length) return null;
  const ko = language === 'ko';
  return h('details', {className:'scope-evidence policy-advisories'},
    h('summary', null, `${ko ? '정책 안내' : 'Policy advisories'} · ${applicable.length}`),
    applicable.map((item, index) => h('details', {className:'scope-evidence-section', key:index},
      h('summary', null, item.label),
      h('p', null, item.reason),
      h('p', {className:'requirements-note'}, `${ko ? '대상' : 'Targets'}: ${item.target_assets?.length ? item.target_assets.join(', ') : ko ? '선택한 모든 대상' : 'All selected targets'}`),
      h('blockquote', null, item.source_quote),
      h('p', null, item.guidance))));
}

export function ScopeExecutionRules({ rules, open = false, selectedAssets }: { rules?: Rules | null; open?: boolean; selectedAssets?: readonly string[] }) {
  const evidence = (label: string, quote: string, key: string) => h('div', {className:'scope-evidence-section',key}, h('strong',null,label),h('blockquote',null,quote));
  return h('details',{className:'scope-evidence',open},h('summary',null,'Policy execution rules'),
    rules == null ? h('p',{className:'requirements-note'},'Pending') : h('div',null,
      rules.exclusions == null ? h('p',{className:'requirements-note'},'Exclusion interpretation pending') : rules.exclusions.map(rule => h('div',{className:'scope-evidence-section',key:`exclusion-${rule.key}`},
        h('strong',null,`${rule.label} [${rule.key}] · Targets: ${rule.target_assets.length ? rule.target_assets.join(', ') : 'All selected targets'}`),
        h('pre',null,JSON.stringify(rule.condition,null,2)),h('blockquote',null,rule.source_quote))),
      rules.request_limits.map((limit,index)=>evidence(requestLimitLabel(limit),limit.source_quote,`quota-${index}`)),
      rules.option_limits.map((limit,index)=>evidence(`Automatically applied: ${limit.field} ${typeof limit.value === 'boolean' ? `= ${limit.value}` : `≤ ${limit.value}`}`,limit.source_quote,`option-${index}`)),
      [rules.allowed_methods,rules.allowed_target_assets].map((restriction,index)=>restriction && evidence(`${index === 0 ? 'Allowed methods' : 'Allowed target assets'}: ${restriction.values.join(', ')}`,restriction.source_quote,`allowed-${index}`)),
      (rules.required_inputs ?? []).map(input=>evidence(`${input.label} (${input.kind})${input.allowed_email_domains?.length ? ` · Allowed email domains: ${input.allowed_email_domains.join(', ')}` : ''} · Targets: ${input.target_assets.length ? input.target_assets.join(', ') : 'All selected targets'}`,input.source_quote,`input-${input.key}`)),
      (rules.required_confirmations ?? []).map(item=>evidence(`${item.label} · Targets: ${item.target_assets.length ? item.target_assets.join(', ') : 'All selected targets'}`,item.source_quote,`confirmation-${item.key}`)),
      (selectedAssets === undefined ? rules.blocking_requirements ?? [] : applicablePolicyRequirements(rules.blocking_requirements, selectedAssets)).map((item,index)=>evidence(`Blocked: ${item.label} · ${item.reason} · Targets: ${item.target_assets?.length ? item.target_assets.join(', ') : 'All selected targets'}`,item.source_quote,`blocker-${index}`)),
      h(ScopePolicyAdvisories, {advisories:rules.advisories, selectedAssets}),
    ));
}

export function ScopeExclusionStatus({ count, preparation }: { count: number; preparation?: ExclusionPreparation | null }) {
  return h('div',{className:'requirements-note','aria-live':'polite'},
    h('span',null,`${count} exclusions · ${preparation ? `${preparation.held} held, ${preparation.denied} denied` : 'Checked before launch'}`),
    h(ScopePolicyAdvisories,{advisories:preparation?.agent_guidance}),
    preparation && preparation.resources.filter(item=>item.decision!=='continue').map((item,index)=>h('div',{key:index},`${item.decision} [${item.rule_keys.join(', ')}]: ${item.reason}`)));
}
