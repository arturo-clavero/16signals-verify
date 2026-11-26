// Building proof packages: from the verifier's receipt v2 test vector (as its webhook would carry it) and from the
// providers' fixture packages; every built package must pass checkPackage.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { buildPackage, buildRun, checkPackage, transcriptBytes, webhookRun } from './index.mjs';
import cloudflare from '../../private-proof/cloudflare/descriptor.mjs';
import gcp from '../../private-proof/gcp/descriptor.mjs';
import aws from '../../private-proof/aws/descriptor.mjs';

const json = url => JSON.parse(readFileSync(new URL(url, import.meta.url), 'utf8'));
const V2 = json('../../servers/verifier/src/tests/receipt-v2-vectors.json');
const providers = [gcp, aws, cloudflare];
const noBb = { loadBb: async () => { throw new Error('not installed'); } };
const byId = result => Object.fromEntries(result.checks.map(c => [c.id, c]));
const didDocument = { id: V2.kid.split('#')[0], verificationMethod: [{ id: V2.kid, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: V2.publicJwk.x } }],
  assertionMethod: [V2.kid] };
const sent = Uint8Array.from(Buffer.from(V2.sentHex, 'hex'));
const recv = Uint8Array.from(Buffer.from(V2.recvHex, 'hex'));
/** The vector as the verifier's webhook carries it: receipt, salted leaves, transcript as text with its lengths. */
const webhook = { receipt: V2.receipt, leaves: V2.publishedLeaves,
  transcript: { sent: Buffer.from(sent).toString('utf8'), recv: Buffer.from(recv).toString('utf8'), sent_length: sent.length, recv_length: recv.length } };
const check = pkg => checkPackage(pkg, { providers, keys: { dids: [didDocument] }, zk: noBb });

test('a run from the v2 vector: reveal leaves as hashes, commit leaves with their digests', async () => {
  const run = await buildRun({ receipt: V2.receipt, leaves: V2.publishedLeaves, sent, recv });
  assert.deepEqual(run.leaves, V2.publishedLeaves.map(({ direction, start, end, kind }) => ({ direction, start, end, kind })));
  assert.deepEqual(run.disclosed, []);
  assert.deepEqual(run.hidden, V2.publishedLeaves.flatMap((leaf, i) => (leaf.kind === 'reveal' ? [{ leaf: i, hash: V2.leaves[i].leafHash }] : [])));
  assert.deepEqual(run.commitments, V2.publishedLeaves.flatMap((leaf, i) => (leaf.kind === 'commit' ? [{ leaf: i, salt: leaf.salt, alg: leaf.alg, digest: leaf.digest }] : [])));
  assert.equal('zk' in run, false);
  const pkg = await buildPackage({ descriptor: cloudflare, runs: [run] });
  assert.deepEqual(pkg, { v: 1, provider: 'cloudflare', runs: [run], pins: {} });
  const checks = byId(await check(pkg));
  for (const id of ['receipt-signature', 'server-name', 'signed-root']) assert.equal(checks[id].ok, true, `${id}: ${checks[id].detail}`);
});

test('a run from the webhook payload equals the run from bytes; disclose publishes chosen reveal leaves', async () => {
  assert.deepEqual(await webhookRun(webhook), await buildRun({ receipt: V2.receipt, leaves: V2.publishedLeaves, sent, recv }));
  const run = await webhookRun(webhook, { disclose: leaf => leaf.direction === 'recv' });
  assert.deepEqual(run.disclosed.map(d => d.leaf), V2.publishedLeaves.flatMap((l, i) => (l.kind === 'reveal' && l.direction === 'recv' ? [i] : [])));
  assert.equal(Buffer.from(run.disclosed[0].bytes, 'base64').toString('hex'), V2.leaves[run.disclosed[0].leaf].bytesHex);
  const checks = byId(await check(await buildPackage({ provider: 'cloudflare', runs: [run], pins: {} })));
  assert.equal(checks['signed-root'].ok, true, checks['signed-root'].detail);
  assert.equal(checks['receipt-signature'].ok, true);
});

test('a run that does not rebuild its signed root is refused', async () => {
  const salted = V2.publishedLeaves.map((leaf, i) => (i === 0 ? { ...leaf, salt: '00'.repeat(32) } : leaf));
  await assert.rejects(buildRun({ receipt: V2.receipt, leaves: salted, sent, recv }), /signed root/);
  await assert.rejects(buildRun({ receipt: V2.receipt, leaves: V2.publishedLeaves.slice(1), sent, recv }), /signs 5 leaves/);
  await assert.rejects(buildRun({ receipt: V2.receipt, leaves: V2.publishedLeaves, sent: null, recv }), /no transcript bytes/);
  await assert.rejects(webhookRun({ ...webhook, receipt: undefined }), /no receipt/);
  await assert.rejects(webhookRun({ ...webhook, transcript: { ...webhook.transcript, sent: `${webhook.transcript.sent.slice(1)}�` } }), /no transcript bytes/);
});

test('transcriptBytes: exact UTF-8 bytes or null', () => {
  assert.deepEqual(transcriptBytes('ab\0c', 4), Uint8Array.of(0x61, 0x62, 0, 0x63));
  assert.deepEqual(transcriptBytes('é', 2), Uint8Array.of(0xc3, 0xa9));
  assert.equal(transcriptBytes('é', 1), null);
  assert.equal(transcriptBytes('a�', 4), null);
  assert.equal(transcriptBytes(undefined, 0), null);
});

test('buildPackage takes the pins of the circuits a run uses from the descriptor (the fixture packages)', async () => {
  for (const [name, descriptor] of [['cloudflare-package.json', cloudflare], ['gcp-package.json', gcp], ['aws-package.json', aws]]) {
    const fixture = json(`./test-fixtures/proof-package/${name}`);
    const pkg = await buildPackage({ descriptor, claim: fixture.claim, runs: fixture.runs, vks: {} });
    assert.deepEqual(pkg, fixture, name);
  }
  const fixture = json('./test-fixtures/proof-package/gcp-zk-package.json');
  const vk = Buffer.from(fixture.vks['timestamps-v1'], 'base64');
  assert.deepEqual(await buildPackage({ descriptor: gcp, runs: fixture.runs, vks: { 'timestamps-v1': vk, 'unused-v1': 'AA==' } }), fixture);
  await assert.rejects(buildPackage({ descriptor: { id: 'gcp' }, runs: fixture.runs }), /pins no key for timestamps-v1/);
  await assert.rejects(buildPackage({ descriptor: gcp, runs: [] }), /no runs/);
});
