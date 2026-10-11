import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as login from '../src/lib/manualLogin.ts';

const pending = {
  scan_id: 'scan_one', request_id: 'a'.repeat(32), target_origin: 'https://example.com',
  status: 'waiting', expires_at: 100, problem: null, auth_state: null,
};

test('login button is limited to the current running scan and unexpired waiting request', () => {
  assert.equal(login.canConfirmManualLogin?.(pending, 'scan_one', 'running', 99), true);
  for (const [request, scan, status, now] of [
    [pending, 'scan_two', 'running', 99], [pending, 'scan_one', 'failed', 99],
    [pending, 'scan_one', 'paused', 99], [pending, 'scan_one', 'running', 100],
    [{ ...pending, status: 'confirmed' }, 'scan_one', 'running', 99],
    [{ ...pending, status: 'accepted' }, 'scan_one', 'running', 99],
  ]) assert.equal(login.canConfirmManualLogin?.(request, scan, status, now), false);
});

test('confirmation records operator attestation and never synthesizes server verification', () => {
  const value = login.parseManualLogin?.({ manual_login: { ...pending, status: 'accepted', auth_state: 'operator_confirmed' } });
  assert.equal(value?.auth_state, 'operator_confirmed');
  assert.equal(value?.status, 'accepted');
});

test('malformed responses cannot enable a login confirmation', () => {
  for (const value of [null, {}, { manual_login: {} }, { manual_login: { ...pending, expires_at: '100' } },
    { manual_login: { ...pending, status: 'unknown' } }, { manual_login: { ...pending, request_id: '../other' } }]) {
    assert.equal(login.parseManualLogin?.(value), null);
  }
});

test('runtime user action kinds are parsed and labelled without inventing an AI decision', () => {
  const request = login.parseManualLogin({ manual_login: { ...pending, action_kind: 'captcha', problem: 'captcha_required' } });
  assert.equal(request.action_kind, 'captcha');
  assert.equal(login.manualActionLabel(request, 'en'), 'CAPTCHA verification');
  assert.equal(login.manualActionLabel({ ...pending, action_kind: 'recon_login' }, 'ko'), '정찰 중 로그인');
  assert.equal(login.parseManualLogin({ manual_login: { ...pending, action_kind: 'unknown' } }), null);
});
