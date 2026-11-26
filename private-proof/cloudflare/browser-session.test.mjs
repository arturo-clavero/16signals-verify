import assert from 'node:assert/strict';
import test from 'node:test';
import { createCloudflareLocalSession } from './browser-session.mjs';

const issuedAt = Date.now() - 1000, attempt = { issuedAt, expiresAt: issuedAt + 900000 }, token = 't'.repeat(40);
const json = body => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });

test('identity only (fast check): one identity request, no account lookup or discovery', async () => {
  const urls = [];
  const fetchCf = async url => { urls.push(new URL(url).pathname); return json({ result: { id: 'a'.repeat(32) } }); };
  const requests = await createCloudflareLocalSession({ attempt, fetchCf, identityOnly: true }).prepare(token);
  assert.deepEqual(requests.map(r => new URL(r.url).pathname), ['/client/v4/user']);
  assert.deepEqual(urls, ['/client/v4/user']);
  await assert.rejects(createCloudflareLocalSession({ attempt, identityOnly: true, fetchCf: async () => json({ result: {} }) }).prepare(token), /CF_PRIVATE_COLLECTION_FAILED/);
});
