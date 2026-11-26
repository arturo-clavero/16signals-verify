import assert from 'node:assert/strict';
import test from 'node:test';
import { buildCloudflareRequest, cloudflarePageQuery, CF_PAGE_PREFIX, CF_PAGE_INFIX } from './request.mjs';

const token = 'T'.repeat(40), userId = 'a'.repeat(32), accountId = 'b'.repeat(32);
const page = { userId, since: '2026-08-27T00:00:00.000Z', before: '2026-11-25T00:00:00.000Z', limit: 25 };

test('identity, accounts and page requests', () => {
  assert.equal(buildCloudflareRequest({ kind: 'identity', token }).url, 'https://api.cloudflare.com/client/v4/user');
  assert.equal(buildCloudflareRequest({ kind: 'accounts', token }).url, 'https://api.cloudflare.com/client/v4/accounts');
  const r = buildCloudflareRequest({ kind: 'page', token, accountId, ...page });
  assert.equal(r.method, 'GET');
  assert.equal(r.headers.Authorization, `Bearer ${token}`);
  assert.equal(r.headers['Accept-Encoding'], 'identity');
  const url = new URL(r.url);
  assert.ok(url.pathname.startsWith(CF_PAGE_PREFIX + accountId + CF_PAGE_INFIX.slice(0, -1)));
  assert.deepEqual([...url.searchParams.keys()], ['since', 'before', 'limit', 'direction', 'actor_id', 'actor_type', 'action_result', 'action_type.not']);
  assert.equal(url.searchParams.get('action_type.not'), 'view');
  assert.equal(new URLSearchParams(cloudflarePageQuery({ ...page, cursor: 'abc_-=' })).get('cursor'), 'abc_-=');
});

test('since == before is allowed (one-instant window)', () => {
  assert.ok(cloudflarePageQuery({ ...page, since: page.before }));
});

test('refuses bad inputs', () => {
  const bad = input => assert.throws(() => buildCloudflareRequest(input), /CF_REQUEST_INVALID/);
  bad({ kind: 'page', token, accountId: 'x', ...page });
  bad({ kind: 'page', token, accountId, ...page, userId: 'nope' });
  bad({ kind: 'page', token, accountId, ...page, since: page.before, before: page.since });
  bad({ kind: 'page', token, accountId, ...page, limit: 0 });
  bad({ kind: 'page', token, accountId, ...page, limit: 1001 });
  bad({ kind: 'page', token, accountId, ...page, cursor: 'a b' });
  bad({ kind: 'page', token, accountId, ...page, since: '2026-11-25' });
  bad({ kind: 'other', token });
  bad({ kind: 'identity', token: 'short' });
  bad({ kind: 'identity', token: `${'x'.repeat(30)}\r\nX: y` });
});
