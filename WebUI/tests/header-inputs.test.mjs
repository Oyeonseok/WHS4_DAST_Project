import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as scan from '../src/lib/scan.ts';

const username = { key: 'researcher_username', label: 'Researcher username', kind: 'username' };
const email = { key: 'contact_email', label: 'Contact email', kind: 'email' };
const requirements = {
  header_requirements_status: 'ready',
  required_headers: [
    { name: 'X-Research-Identity', value_template: 'bounty-{researcher_username}', inputs: [username], source_quote: 'Send X-Research-Identity: bounty-<your username>.' },
    { name: 'Researcher-Contact', value_template: '{researcher_username} <{contact_email}>', inputs: [username, email], source_quote: 'Send your username and email in Researcher-Contact.' },
  ],
  header_inputs: [username, email],
};

test('unfamiliar headers can share a declared slot without requiring a platform handle', () => {
  assert.equal(scan.canLaunchWithHeaderInputs?.(requirements, {
    researcher_username: 'alice', contact_email: 'alice@example.com',
  }), true);
});

test('each required input must be present and nonblank', () => {
  for (const values of [{}, { researcher_username: 'alice' }, { researcher_username: ' ', contact_email: 'alice@example.com' }]) {
    assert.equal(scan.canLaunchWithHeaderInputs?.(requirements, values), false);
  }
});

test('literal-only headers need no identity input', () => {
  assert.equal(scan.canLaunchWithHeaderInputs?.({
    header_requirements_status: 'ready', header_inputs: [],
    required_headers: [{ name: 'Research-Traffic', value_template: 'approved-research', inputs: [], source_quote: 'Send Research-Traffic: approved-research.' }],
  }, {}), true);
});

test('pending or absent interpretation cannot be treated as no required headers', () => {
  assert.equal(scan.canLaunchWithHeaderInputs?.({ header_requirements_status: 'pending', header_inputs: [] }, {}), false);
  assert.equal(scan.canLaunchWithHeaderInputs?.({ header_inputs: [] }, {}), false);
});

test('invalid email and control characters block launch', () => {
  for (const values of [
    { researcher_username: 'alice\r\nInjected: value', contact_email: 'alice@example.com' },
    { researcher_username: 'alice', contact_email: 'invalid' },
  ]) assert.equal(scan.canLaunchWithHeaderInputs?.(requirements, values), false);
});

test('username inputs follow the declared kind rather than a header name', () => {
  for (const value of ['name with spaces', 'alice@example.com', 'x'.repeat(65)]) {
    assert.equal(scan.canLaunchWithHeaderInputs?.(requirements, {
      researcher_username: value, contact_email: 'alice@example.com',
    }), false);
  }
  assert.equal(scan.canLaunchWithHeaderInputs?.(requirements, {
    researcher_username: 'alice_1.test-name', contact_email: 'alice@research',
  }), true);
});

test('text inputs allow spaces but enforce the input length bound', () => {
  const textRequirements = { header_requirements_status: 'ready', header_inputs: [{ key: 'researcher', label: 'Researcher', kind: 'text' }] };
  assert.equal(scan.canLaunchWithHeaderInputs?.(textRequirements, { researcher: 'Alice Example' }), true);
  assert.equal(scan.canLaunchWithHeaderInputs?.(textRequirements, { researcher: 'x'.repeat(256) }), true);
  assert.equal(scan.canLaunchWithHeaderInputs?.(textRequirements, { researcher: 'x'.repeat(257) }), false);
});

test('text and email inputs require HTTP Latin1 encodable values', () => {
  for (const kind of ['text', 'email']) {
    const inputRequirements = { header_requirements_status: 'ready', header_inputs: [{ key: 'identity', label: 'Identity', kind }] };
    for (const value of ['researcher😀', '연구자']) {
      assert.equal(scan.canLaunchWithHeaderInputs?.(inputRequirements, {
        identity: kind === 'email' ? `${value}@example.com` : value,
      }), false);
    }
    assert.equal(scan.canLaunchWithHeaderInputs?.(inputRequirements, {
      identity: kind === 'email' ? 'André@example.com' : 'André ÿ',
    }), true);
  }
});

test('launch identity values preserve text and omit undeclared stale values', () => {
  assert.deepEqual(scan.headerIdentityValues?.(requirements, {
    researcher_username: 'alice', contact_email: 'alice@example.com', unrelated: 'previous scope',
  }), { researcher_username: 'alice', contact_email: 'alice@example.com' });
});

test('pending scope resolution shares one request across repeated selections', async () => {
  let requests = 0;
  const resolved = { scope_id: 'approved-one', execution_requirements: requirements };
  const resolver = scan.createHeaderRequirementsResolver?.(async scopeId => {
    requests++;
    assert.equal(scopeId, 'approved-one');
    return resolved;
  });
  assert.equal(typeof resolver, 'function');
  const first = resolver('approved-one');
  const second = resolver('approved-one');
  assert.equal(first, second);
  assert.equal(await first, resolved);
  assert.equal(await resolver('approved-one'), resolved);
  assert.equal(requests, 1);
});

test('failed interpretation stays failed and is not silently retried or launchable', async () => {
  let requests = 0;
  const resolver = scan.createHeaderRequirementsResolver?.(async () => {
    requests++;
    throw new Error('Scope header interpretation unavailable');
  });
  assert.equal(typeof resolver, 'function');
  await assert.rejects(resolver('approved-one'), /interpretation unavailable/);
  await assert.rejects(resolver('approved-one'), /interpretation unavailable/);
  assert.equal(requests, 1);
});
