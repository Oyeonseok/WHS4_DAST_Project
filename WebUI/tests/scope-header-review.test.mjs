import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { translate } from '../src/lib/i18n.ts';
import { ScopeHeaderRequirements } from '../src/components/ScopeHeaderRequirements.ts';

function render(headers, open = true) {
  assert.equal(typeof ScopeHeaderRequirements, 'function');
  return renderToStaticMarkup(createElement(ScopeHeaderRequirements, { headers, open, tr: label => translate('en', label) }));
}

test('approval review exposes arbitrary names, templates, input labels and exact source quotes', () => {
  const html = render([
    { name: 'Research-ID', value_template: 'team-{name}', inputs: [{ key: 'name', label: 'Researcher name', kind: 'text' }], source_quote: 'You must send Research-ID: team-{name} on every request.' },
    { name: 'Traffic-Category', value_template: 'approved-research', inputs: [], source_quote: 'Include Traffic-Category: approved-research.' },
  ]);
  for (const text of ['Research-ID: team-{name}', 'Researcher name', 'Traffic-Category: approved-research', 'You must send Research-ID: team-{name} on every request.', 'Include Traffic-Category: approved-research.']) {
    assert.ok(html.includes(text), `Missing review detail: ${text}`);
  }
  assert.match(html, /<details[^>]*open=""/);
});

test('older draft payloads remain visibly pending instead of implying no required headers', () => {
  for (const headers of [null, undefined]) {
    const html = render(headers, false);
    assert.ok(html.includes('Pending'));
    assert.ok(!html.includes('None'));
  }
});

test('an interpreted empty header list displays no required headers', () => {
  assert.ok(render([]).includes('None'));
});
