import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { transformWithOxc } from 'vite';
import { canConfirmManualLogin, parseManualLogin } from '../src/lib/manualLogin.ts';
import { apiErrorMessage } from '../src/lib/transport.ts';

const hookSource = await readFile(new URL('../src/hooks/useManualLogin.ts', import.meta.url), 'utf8');
const hookCode = stripTypeScriptTypes(hookSource)
  .replace(/^import .*;$/gm, '').replace('export function', 'function')
  .replaceAll('import.meta.env', 'env');
const makeHook = new Function('useState', 'useEffect', 'canConfirmManualLogin', 'parseManualLogin',
  'apiErrorMessage', 'fetch', 'window', 'location', 'env', `${hookCode}\nreturn useManualLogin;`);

const pending = {
  scan_id: 'scan_one', request_id: 'a'.repeat(32), target_origin: 'https://example.test',
  status: 'waiting', expires_at: Date.now() / 1000 + 120, problem: null, auth_state: null,
};
const response = manual_login => ({ ok: true, json: async () => ({ manual_login }) });
const settle = () => new Promise(resolve => setImmediate(resolve));

function harness(fetch, env = { VITE_API_BASE_URL: 'http://api.fixture:8000' }) {
  const states = [], effects = [], timers = new Map();
  let stateIndex, effectIndex, scheduled, timerId = 0;
  const hook = makeHook(initial => {
    const index = stateIndex++;
    if (!(index in states)) states[index] = initial;
    return [states[index], value => { states[index] = value; }];
  }, (run, dependencies) => {
    const index = effectIndex++, previous = effects[index];
    if (previous && dependencies.every((value, i) => Object.is(value, previous.dependencies[i]))) return;
    scheduled.push(() => {
      previous?.cleanup?.();
      effects[index] = { dependencies, cleanup: run() };
    });
  }, canConfirmManualLogin, parseManualLogin, apiErrorMessage, fetch, {
    setInterval: callback => { timers.set(++timerId, callback); return timerId; },
    clearInterval: id => timers.delete(id),
  }, { origin: 'http://ui.fixture:4173' }, env);
  return {
    render(scanId = 'scan_one', status = 'running', enabled = true) {
      stateIndex = effectIndex = 0; scheduled = [];
      const value = hook(scanId, status, enabled);
      scheduled.forEach(run => run());
      return value;
    },
    tick: async () => { for (const callback of timers.values()) callback(); await settle(); },
    timerCount: () => timers.size,
    close: () => effects.forEach(effect => effect?.cleanup?.()),
  };
}

test('manual-login polling and confirmation use the configured backend when UI has a different origin', async () => {
  const calls = [];
  const app = harness(async (url, options) => {
    calls.push({ url: url.href, options });
    return response(options.method === 'POST' ? { ...pending, status: 'confirmed' } : pending);
  });
  try {
    app.render(); await settle();
    const login = app.render();
    assert.equal(login.canConfirm, true);
    await login.confirm();
    assert.deepEqual(calls.map(call => call.url), [
      'http://api.fixture:8000/api/v1/scans/scan_one/manual-login',
      'http://api.fixture:8000/api/v1/scans/scan_one/manual-login/confirm',
    ]);
    assert.deepEqual(JSON.parse(calls[1].options.body), { request_id: pending.request_id });
    assert.equal(app.render().request.status, 'confirmed');
  } finally { app.close(); }
});

test('a request created after the first response appears on the next polling tick', async () => {
  let calls = 0;
  const app = harness(async () => response(++calls === 1 ? null : pending), {});
  try {
    app.render(); await settle();
    assert.equal(app.render().request, null);
    await app.tick();
    assert.equal(app.render().canConfirm, true);
    assert.equal(calls, 2);
    app.render('scan_one', 'completed'); await settle();
    assert.equal(app.timerCount(), 0);
    assert.equal(app.render('scan_one', 'completed').canConfirm, false);
  } finally { app.close(); }
});

test('changing selected scan hides its previous request and ignores an aborted polling response', async () => {
  const deferred = [];
  const app = harness(url => new Promise(resolve => deferred.push({ url, resolve })));
  try {
    app.render('scan_one');
    assert.equal(app.render('scan_two').request, null);
    deferred[1].resolve(response({ ...pending, scan_id: 'scan_two' })); await settle();
    deferred[0].resolve(response(pending)); await settle();
    const login = app.render('scan_two');
    assert.equal(login.request.scan_id, 'scan_two');
    assert.equal(login.canConfirm, true);
    assert.equal(app.render('scan_two', 'running', false).request, null);
    assert.equal(app.timerCount(), 0);
  } finally { app.close(); }
});

const noticeSource = await readFile(new URL('../src/components/ManualLoginNotice.tsx', import.meta.url), 'utf8');
const noticeCode = (await transformWithOxc(noticeSource, 'ManualLoginNotice.tsx')).code
  .replace('"../lib/manualLogin"', JSON.stringify(new URL('../src/lib/manualLogin.ts', import.meta.url).href))
  .replace('import "./ManualLoginNotice.css";', '')
  .replace('"react/jsx-runtime"', JSON.stringify(import.meta.resolve('react/jsx-runtime')));
const { ManualLoginNotice } = await import(`data:text/javascript;base64,${Buffer.from(noticeCode).toString('base64')}`);
const markup = request => renderToStaticMarkup(createElement(ManualLoginNotice, {
  request, busy: false, error: '', canConfirm: true, confirm: async () => {}, language: 'ko',
}));

test('waiting login displays an enabled completion button and accepted login removes it', () => {
  const html = markup(pending);
  assert.match(html, /<button[^>]*>로그인 완료<\/button>/);
  assert.doesNotMatch(html, /disabled/);
  assert.equal(markup({ ...pending, status: 'accepted' }), '');
  assert.match(markup({ ...pending, status: 'confirmed' }), /브라우저 확인 중/);
});

test('login notice is above page content and outside the collapsible activity panel, with another copy inside scan progress', async () => {
  const app = await readFile(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /<main id="main-content"[^>]*>\s*\{manualLoginNotice\}/);
  const aside = app.slice(app.indexOf('<aside id="activity-panel"'), app.indexOf('</aside>', app.indexOf('<aside id="activity-panel"')));
  assert.doesNotMatch(aside, /\{manualLoginNotice\}/);
  assert.match(app, /const scanProgressContent = <div className="scan-progress-dialog">\s*\{manualLoginNotice\}/);
});
