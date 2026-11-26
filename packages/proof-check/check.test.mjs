import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { bundleCommitment, createAttestation, describeClaim, evaluate, proofHash, signAttestation, verifierKeyId,
  verifyCommitment } from './index.mjs';
import example from './test-fixtures/example-descriptor.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
const keys = { keys: [{ id: await verifierKeyId(pem.publicKey), label: 'test verifier', publicKeyPem: pem.publicKey }] };
const NOW = Date.parse('2026-11-06T12:00:00.000Z');
const bundle = { kind: 'EXAMPLE_RESULT', version: 1, proofs: [{ circuitId: 'example-v1', proof: 'AAAA', publicInputs: ['7'] }] };

async function sign(overrides = {}) {
  const fields = { provider: 'example', claim: 'example:value-7', window: 30, proofHash: await proofHash(bundle),
    vkHashes: { 'example-v1': 'e'.repeat(64) }, ...overrides };
  const commitment = await bundleCommitment(fields);
  return signAttestation(createAttestation({ ...fields, commitment, issuedAt: NOW - 1000, expiresAt: NOW + 86400000 }), pem.privateKey);
}
const check = (signed, extra = {}) => evaluate({ commitment: signed.commitment, attestations: [signed], bundle, keys,
  providers: [example], now: NOW, ...extra });

test('a plugged-in provider verifies end to end with stable check ids', async () => {
  const result = await check(await sign());
  assert.equal(result.status, 'verified');
  assert.deepEqual(result.checks.map(item => [item.id, item.ok]),
    [['signature', true], ['proof-hash', true], ['verification-keys', true], ['claim', true]]);
  assert.equal(result.verifier, 'test verifier');
  assert.equal(describeClaim(result, [example]), 'Example: value-7.');
  assert.equal(describeClaim(result, []), 'example: example:value-7 in the last 30 days.');
});

test('the provider descriptor decides the pins and the claim', async () => {
  const wrongClaim = await check(await sign({ claim: 'example:value-8' }));
  assert.equal(wrongClaim.status, 'failed');
  assert.deepEqual(wrongClaim.checks.filter(item => !item.ok).map(item => item.id), ['claim']);
  const wrongKey = await check(await sign({ vkHashes: { 'example-v1': 'f'.repeat(64) } }));
  assert.deepEqual(wrongKey.checks.filter(item => !item.ok).map(item => item.id), ['verification-keys']);
  const loader = await check(await sign(), { providers: [{ ...example, pins: async () => example.pins }] });
  assert.equal(loader.status, 'verified');
  const unpinned = await check(await sign(), { providers: [{ id: 'example', pins: () => { throw new Error('offline'); } }] });
  assert.equal(unpinned.status, 'verified');
  assert.equal(unpinned.checks.at(-1).label, 'Verification keys cover exactly the circuits used');
});

test('an attestation for a provider without a descriptor fails closed', async () => {
  const signed = await sign();
  for (const providers of [[], undefined, [{ id: 'other' }]]) {
    const result = await check(signed, { providers });
    assert.equal(result.status, 'failed');
    assert.deepEqual(result.checks.map(item => [item.id, item.ok, item.detail]), [['signature', true, undefined], ['provider', false, 'example']]);
  }
});

test('signature failures carry a reason', async () => {
  const signed = await sign();
  assert.equal((await check(signed, { keys: { keys: [] } })).checks[0].detail, 'unknown-key');
  assert.equal((await check(signed, { now: NOW + 2 * 86400000 })).checks[0].detail, 'expired');
  const missing = await evaluate({ commitment: signed.commitment, attestations: [], keys, providers: [example], now: NOW });
  assert.deepEqual([missing.status, missing.checks[0].detail], ['not-found', 'no-attestation']);
});

test('custom registries are searched for attestations and the bundle', async () => {
  const signed = await sign();
  const queries = [];
  const empty = { findAttestations: async query => { queries.push(['a', query]); return []; }, findBundle: async () => null };
  const store = { findAttestations: async () => [signed],
    findBundle: async query => { queries.push(['b', query]); return { json: JSON.stringify(bundle) }; } };
  const result = await verifyCommitment({ commitment: signed.commitment, keys, providers: [example], registries: [empty, store], now: NOW });
  assert.equal(result.status, 'verified');
  assert.deepEqual(queries, [['a', { commitment: signed.commitment }], ['b', { commitment: signed.commitment, proofHash: signed.proofHash }]]);
  const none = await verifyCommitment({ commitment: signed.commitment, keys, providers: [example], registries: [empty], now: NOW });
  assert.equal(none.status, 'not-found');
  await assert.rejects(verifyCommitment({ commitment: signed.commitment, keys, providers: [example] }), /Drop an attestation/);
});

test('the cli prints one line per check and exits 0, 1 or 2', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'proof-check-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const descriptor = fileURLToPath(new URL('./test-fixtures/example-descriptor.mjs', import.meta.url));
  const file = async (name, value) => { const path = join(dir, name); await writeFile(path, JSON.stringify(value)); return path; };
  const config = await file('config.json', { providers: [descriptor], keys: './keys.json' });
  await file('keys.json', keys);
  const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const run = (...args) => new Promise(resolve => execFile(process.execPath, [cli, ...args, '--config', config,
    '--now', new Date(NOW).toISOString()], (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr })));

  const signed = await sign();
  const ok = await run(await file('both.json', { attestation: signed, bundle }));
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(ok.stdout.trim().split('\n').length, 5);
  assert.match(ok.stdout, /^ok {3}Signed by a listed verifier key/);
  assert.match(ok.stdout, /\nverified [0-9a-f]{64} example:value-7\n$/);
  const bundleFile = await file('bundle.json', bundle);
  assert.equal((await run(await file('signed.json', signed), '--bundle', bundleFile)).code, 0);
  const signatureOnly = await run(await file('signed.json', signed));
  assert.equal(signatureOnly.code, 1);
  assert.match(signatureOnly.stdout, /FAIL Public proof bundle not found/);
  assert.equal((await run(await file('bad-claim.json', { attestation: await sign({ claim: 'example:value-8' }), bundle }))).code, 1);
  assert.equal((await run(await file('signed.json', signed), '--keys', await file('none.json', { keys: [] }))).code, 1);
  assert.equal((await run(await file('notes.json', { hello: 1 }))).code, 2);
  assert.equal((await run(bundleFile)).code, 2);
  assert.equal((await run(join(dir, 'missing.json'))).code, 2);
  assert.equal((await run()).code, 2);
  assert.equal((await run(bundleFile, '--verbose')).code, 2);
});
