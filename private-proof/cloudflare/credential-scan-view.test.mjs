import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { cloudflareCredentialScanView } from './credential-scan-view.mjs';
import { planCloudflareSession, cloudflarePageRows } from './session.mjs';
import { requestBytes, responseBytes, identityBody, pageBody } from './session-fixture.mjs';
import { receiptFor } from './receipt-fixture.mjs';

const issuedAt = Date.parse('2026-11-25T08:00:00Z'), now = issuedAt + 60000;
const base = { proofId: randomUUID(), pluginSha256: 'c'.repeat(64), nonceMac: 'n'.repeat(43), issuedAt, expiresAt: issuedAt + 900000 };
// The shared scanner's header rule, as in the GCP and AWS scan views.
const CREDENTIAL_HEADER = /(?:^|[\r\n\0])[ \t]*(?:proxy-authorization|authorization|set-cookie|cookie|x-amz-security-token)[ \t]*:/i;
const reveals = view => CREDENTIAL_HEADER.test(view.transcript.sent) || CREDENTIAL_HEADER.test(view.transcript.recv) ||
  view.results.some(result => CREDENTIAL_HEADER.test(result.value));

function identity() {
  const expected = { ...base, sessionId: randomUUID(), step: 'identity' };
  const recv = responseBytes(identityBody());
  return { expected, ...receiptFor({ sent: requestBytes('identity'), recv, plan: planCloudflareSession('identity', requestBytes('identity'), recv), expected }) };
}
function page() {
  const body = pageBody([{}, { product: 'queues', type: null }, { product: 'workers', type: 'scripts', action: 'update', context: 'dash' }]);
  const starts = cloudflarePageRows(body).map(r => r.start);
  const recv = responseBytes(body, starts.slice(1).map((s, i) => s - (i ? starts[i] : 0)));
  const expected = { ...base, sessionId: randomUUID(), step: 'P0' };
  return { expected, ...receiptFor({ sent: requestBytes('page'), recv, plan: planCloudflareSession('P0', requestBytes('page'), recv, [0, 2]), expected }) };
}

function revealHeader(receipt, name, partial) {
  const offset = receipt.transcript.sent.indexOf(`${name}: `) + name.length + 2;
  const index = receipt.config.sent.findIndex(range => range.start === offset);
  const range = receipt.config.sent[index];
  assert.equal(range?.handler.action.kind, 'HASH');
  const result = receipt.results.filter(r => r.type === 'SENT')[index];
  const end = partial ? range.start + 1 : range.end;
  const reveal = { type: 'SENT', part: range.handler.part, action: { kind: 'REVEAL' } };
  const ranges = [{ start: range.start, end, handler: reveal }], results = [{ ...reveal, value: 'x'.repeat(end - range.start) }];
  if (partial) { ranges.push({ ...range, start: end }); results.push({ ...result, value: 'e'.repeat(64) }); }
  receipt.config.sent.splice(index, 1, ...ranges);
  receipt.results.splice(receipt.results.indexOf(result), 1, ...results);
  receipt.transcript.sent = receipt.transcript.sent.slice(0, range.start) + results[0].value + receipt.transcript.sent.slice(end);
}

for (const fixture of [identity, page]) {
  test(`${fixture.name}: masks only hidden credential header names, both directions, without changing the receipt`, () => {
    const { receipt, expected } = fixture(), before = structuredClone(receipt);
    assert.ok(reveals(receipt));
    const view = cloudflareCredentialScanView(receipt, expected, now);
    assert.deepEqual(receipt, before);
    assert.equal(reveals(view), false);
    assert.equal(view.transcript.sent, receipt.transcript.sent.replace(/Authorization/gi, name => '\0'.repeat(name.length)));
    assert.equal(view.transcript.recv, receipt.transcript.recv.replace(/Set-Cookie/g, name => '\0'.repeat(name.length)));
    assert.deepEqual(view.results.filter(r => r.action.kind === 'HASH'), receipt.results.filter(r => r.action.kind === 'HASH'));
  });

  for (const partial of [false, true]) test(`${fixture.name}: keeps a ${partial ? 'partly' : 'fully'} revealed Authorization for rejection`, () => {
    const { receipt, expected } = fixture();
    revealHeader(receipt, 'authorization', partial);
    const view = cloudflareCredentialScanView(receipt, expected, now);
    assert.ok(view.transcript.sent.includes('authorization: x'));
    assert.ok(reveals(view));
  });

  test(`${fixture.name}: rejects stale and foreign receipts before masking`, () => {
    const { receipt, expected } = fixture();
    assert.throws(() => cloudflareCredentialScanView(receipt, expected, expected.expiresAt), { message: 'CF_PRIVATE_TRANSCRIPT_INVALID' });
    receipt.session.method = 'AWS_ACCOUNT';
    assert.throws(() => cloudflareCredentialScanView(receipt, expected, now), { message: 'CF_PRIVATE_TRANSCRIPT_INVALID' });
  });
}
