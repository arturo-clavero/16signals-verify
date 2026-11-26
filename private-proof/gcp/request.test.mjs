import assert from 'node:assert/strict';
import test from 'node:test';
import catalog from './generated/catalog.json' with { type: 'json' };
import { localBatchBody, matchBatchBody } from './policy.mjs';
import { BATCHES, GCP_MAX_SENT, gcpBatchRequest, gcpSessionRequest } from './request.mjs';

const policy = { cutoff: Date.parse('2026-03-01T12:00:00.000Z'), windowDays: 90 };
const key = 'AIza' + 'b'.repeat(35);

test('identity request: one account digit, the body the identity circuit expects', () => {
  assert.deepEqual(gcpSessionRequest('3'), { url: 'https://accounts.google.com/ListAccounts?json=standard&authuser=3', method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: ' ' });
  for (const bad of ['10', '', 'a', 3, undefined]) assert.throws(() => gcpSessionRequest(bad), /GCP_REQUEST_INVALID/);
});

test('batch requests: catalog bodies that the policy matcher accepts, within the transcript limit', () => {
  assert.deepEqual(BATCHES.map(batch => batch.step), catalog.batches.map(batch => batch.step));
  const email = 'x'.repeat(242) + '@example.com', project = 'a'.repeat(30);
  for (const { step } of BATCHES) {
    const request = gcpBatchRequest(step, policy, project, email, key);
    assert.equal(request.url, `https://logging.clients6.google.com/batch?key=${key}`);
    assert.equal(request.headers['Content-Type'], 'multipart/mixed; boundary=gcp_groups_v1');
    const { text, privateRanges } = localBatchBody(step, policy, project, email);
    assert.equal(request.body, text);
    assert.ok(request.body.length + 2048 < GCP_MAX_SENT);
    // The verifier side sees the private ranges zeroed; the constant bytes must still match the catalog.
    const bytes = Uint8Array.from(text, char => char.charCodeAt(0));
    for (const range of privateRanges) bytes.fill(0, range.start, range.end);
    matchBatchBody({ bytes, privateRanges: privateRanges.map(range => ({ ...range, hash: '0'.repeat(64) })) }, step, policy);
  }
});

test('batch requests refuse bad keys, steps, scopes and service accounts', () => {
  const ok = ['groups:0', policy, 'my-project-1', 'dev@example.com', key];
  assert.ok(gcpBatchRequest(...ok));
  for (const [index, value] of [[4, 'AIzaShort'], [0, 'groups:9'], [1, { ...policy, windowDays: 14 }], [2, 'Bad_Project'],
    [3, 'bot@p.iam.gserviceaccount.com'], [3, 'not-an-email']]) {
    const args = [...ok]; args[index] = value;
    assert.throws(() => gcpBatchRequest(...args), /GCP_(REQUEST|PRIVATE_POLICY)_INVALID/);
  }
});
