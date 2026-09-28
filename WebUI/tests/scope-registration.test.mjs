import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as scope from '../src/lib/scope.ts';
import { translate } from '../src/lib/i18n.ts';

test('HTTP program URLs show an instruction to use HTTPS', () => {
  for (const url of [
    'http://hackerone.com/neon_bbp?type=team',
    '  HTTP://hackerone.com/neon_bbp?type=team  ',
  ]) {
    const error = scope.programRegistrationUrlError?.(url);
    assert.equal(error, 'HTTP URLs cannot be registered. Enter a URL starting with https://.');
    assert.equal(translate('ko', error), 'HTTP 주소는 등록할 수 없습니다. https://로 시작하는 URL을 입력하세요.');
  }
});

test('HTTPS program URLs can proceed to registration', () => {
  assert.equal(
    scope.programRegistrationUrlError?.('https://hackerone.com/neon_bbp?type=team'),
    null,
  );
});
