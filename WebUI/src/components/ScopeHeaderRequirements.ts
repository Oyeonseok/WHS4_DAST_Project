import { createElement as h } from 'react';
import type { RequiredRequestHeader } from '../lib/scan';

export function ScopeHeaderRequirements({ headers, open = false, tr }: {
  headers?: readonly RequiredRequestHeader[] | null;
  open?: boolean;
  tr: (label: string) => string;
}) {
  return h('details', { className: 'scope-evidence', open },
    h('summary', null, tr('Required request header'), ' ',
      h('span', null, headers?.length ?? tr('Pending'))),
    headers == null
      ? h('p', { className: 'requirements-note' }, tr('Pending'))
      : headers.length === 0
        ? h('p', { className: 'requirements-note' }, tr('None'))
        : headers.map(header => h('div', { className: 'scope-evidence-section', key: header.name },
          h('strong', { className: 'mono' }, `${header.name}: ${header.value_template}`),
          header.inputs.length > 0 && h('ul', null, header.inputs.map(input =>
            h('li', { key: input.key }, input.label, ' ', h('code', null, `{${input.key}}`)))),
          h('strong', null, tr('Source evidence')),
          h('blockquote', null, header.source_quote))),
  );
}
