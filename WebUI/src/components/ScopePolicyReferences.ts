import { createElement as h } from 'react';
import type { PolicyReferenceSummary } from '../lib/scope';

export function ScopePolicyReferences({ references, open = false, language }: {
  references?: readonly PolicyReferenceSummary[];
  open?: boolean;
  language: 'ko' | 'en';
}) {
  const ko = language === 'ko';
  const phases = ko
    ? { testing:'테스트', reporting:'보고', disclosure:'공개', mixed:'혼합', unknown:'미확인' }
    : { testing:'Testing', reporting:'Reporting', disclosure:'Disclosure', mixed:'Mixed', unknown:'Unknown' };
  const relationships = ko
    ? {required:'필수', supporting:'보조', uncertain:'불확실'}
    : {required:'Required', supporting:'Supporting', uncertain:'Uncertain'};
  return h('details', { className:'scope-evidence', open },
    h('summary', null, ko ? '참조 정책 문서' : 'Policy reference documents', ' ', h('span', null, references?.length ?? 0)),
    references?.length ? references.map((reference, index) => h('div', {className:'scope-evidence-section',key:index},
      h('strong', null, `${reference.status === 'captured' ? (ko ? '수집 완료' : 'Captured') : (ko ? '미해결' : 'Unresolved')} · ${phases[reference.applicability]} · ${relationships[reference.relationship ?? 'uncertain']}`),
      h('p', null, reference.requested_url),
      reference.final_url && reference.final_url !== reference.requested_url ? h('p', null, reference.final_url) : null,
      reference.error ? h('p', {className:'form-error'}, reference.error) : null,
      h('blockquote', null, reference.source_quote)))
      : h('p', {className:'requirements-note'}, ko ? '수집된 참조 문서가 없습니다.' : 'No captured reference documents.'));
}
