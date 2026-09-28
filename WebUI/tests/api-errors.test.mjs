import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as transport from '../src/lib/transport.ts';
import { translate } from '../src/lib/i18n.ts';

test('registration validation responses display the HTTPS requirement in Korean', () => {
  const detail = [{
    type: 'value_error',
    loc: ['body', 'program_url'],
    msg: 'Value error, program URL must be an absolute HTTPS URL',
    input: 'http://hackerone.com/neon_bbp?type=team',
    ctx: { error: {} },
  }];
  const message = transport.apiErrorMessage?.(detail, 'Registration failed');
  assert.equal(message, 'program URL must be an absolute HTTPS URL');
  assert.equal(translate('ko', message), 'HTTP 주소는 등록할 수 없습니다. https://로 시작하는 URL을 입력하세요.');
});

test('multiple validation errors preserve each explanation without echoing input', () => {
  assert.equal(transport.apiErrorMessage?.([
    { type: 'string_too_short', loc: ['body', 'program_url'], msg: 'String should have at least 8 characters', input: 'secret' },
    { type: 'literal_error', loc: ['body', 'visibility'], msg: "Input should be 'public' or 'private'", input: 'secret' },
  ], 'Request failed'), "String should have at least 8 characters\nInput should be 'public' or 'private'");
});

test('string and structured errors retain their readable message', () => {
  for (const detail of ['Permission denied', { msg: 'Permission denied' }, { message: 'Permission denied' }]) {
    assert.equal(transport.apiErrorMessage?.(detail, 'Request failed'), 'Permission denied');
  }
});

test('missing or malformed errors use the fallback instead of object coercion', () => {
  for (const detail of [undefined, null, '', '  ', {}, [], [{ msg: {} }], { input: 'secret' }, 422]) {
    assert.equal(transport.apiErrorMessage?.(detail, 'Request failed (422)'), 'Request failed (422)');
  }
});
