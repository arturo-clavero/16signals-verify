// The verify page's built-in providers, loaded through verify.config.json as the page and the CLI load them.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { BATCHES } from '../private-proof/gcp/policy.mjs';
import { bundleCommitment, createAttestation, describeClaim, fromVerifiedBundle, loadConfig, parseDropped, signAttestation,
  verifierKeyId, verifyCommitment } from '../packages/proof-check/index.mjs';

const readJson = async url => JSON.parse(await readFile(url, 'utf8'));
const { providers } = await loadConfig(new URL('./verify.config.json', import.meta.url), { readJson });
const gcp = providers.find(descriptor => descriptor.id === 'gcp');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
const keys = { keys: [{ id: await verifierKeyId(pem.publicKey), label: 'test verifier', publicKeyPem: pem.publicKey }] };
const NOW = Date.parse('2026-11-06T12:00:00.000Z');

// One timestamps-v1 proof per batch; group slot 1 of batch 0 is observed. Proof bytes are placeholders.
const timestamps = batch => Array.from({ length: 200 }, (_, index) =>
  index === 192 + 1 && batch === 0 ? '24' : index === 198 ? '1793900000000' : index === 199 ? '30' : '0');
const bundle = { kind: 'GCP_PRIVATE_RESULT', version: 1, proofs: [
  { circuitId: 'identity-scope-v1', proof: 'AAAA', publicInputs: ['1'] },
  ...BATCHES.map((_, batch) => ({ circuitId: 'timestamps-v1', proof: 'AAAA', publicInputs: timestamps(batch) }))] };
const groups = BATCHES.flatMap(batch => batch.groupIds.map(id => ({ id, status: 'empty' })));
groups.find(group => group.id === BATCHES[0].groupIds[1]).status = 'observed';

async function published(claimOverride) {
  const fields = await fromVerifiedBundle(gcp, bundle, { policy: { windowDays: 30 }, groups });
  if (claimOverride) fields.claim = claimOverride;
  const commitment = await bundleCommitment(fields);
  const signed = await signAttestation(createAttestation({ ...fields, commitment, issuedAt: NOW - 1000, expiresAt: NOW + 86400000 }), pem.privateKey);
  return { commitment, signed };
}
const registry = (attestations, bundleJson) => ({
  findAttestations: async () => attestations,
  findBundle: async () => bundleJson ? { json: bundleJson, proofHash: 'x' } : null,
});
const run = (commitment, attestations, bundleJson, extra = {}) => verifyCommitment({ commitment, keys, providers,
  now: NOW, registries: [registry(attestations, bundleJson)], ...extra });

test('the config lists the three built-in providers and the BNB registry', async () => {
  const config = await loadConfig(new URL('./verify.config.json', import.meta.url), { readJson });
  assert.deepEqual(config.providers.map(descriptor => descriptor.id), ['gcp', 'aws', 'cloudflare']);
  assert.deepEqual(config.keys, await readJson(new URL('./keys.json', import.meta.url)));
  assert.equal(config.registries[0].type, 'bnb');
  assert.equal(config.registries[0].module, new URL('../packages/bnb-anchor/anchor.mjs', import.meta.url).href);
});

test('a published attestation and bundle verify end to end and the claim is recomputed from public inputs', async () => {
  const { commitment, signed } = await published();
  const result = await run(commitment, [signed], JSON.stringify(bundle));
  assert.equal(result.status, 'verified');
  assert.ok(result.checks.every(check => check.ok), JSON.stringify(result.checks));
  assert.equal(result.checks.length, 4);
  assert.equal(describeClaim(result, providers), 'Google Cloud: activity observed in 1 skill group(s) in the last 30 days.');
});

test('a signature over a claim the public inputs do not support fails', async () => {
  const { commitment, signed } = await published(`gcp:observed:${BATCHES[0].groupIds[1]},${BATCHES[1].groupIds[0]}`);
  const result = await run(commitment, [signed], JSON.stringify(bundle));
  assert.equal(result.status, 'failed');
  assert.deepEqual(result.checks.filter(check => !check.ok).map(check => check.label), ['Claim matches the proven public inputs']);
});

test('a swapped bundle, unknown key or missing data never shows verified', async () => {
  const { commitment, signed } = await published();
  const other = { ...bundle, proofs: bundle.proofs.slice(0, -1) };
  assert.equal((await run(commitment, [signed], JSON.stringify(other))).status, 'failed');
  assert.equal((await run(commitment, [signed], null)).status, 'signature-only');
  assert.equal((await run(commitment, [], null)).status, 'not-found');
  assert.equal((await run(commitment, [signed], null, { keys: { keys: [] } })).status, 'failed');
  assert.equal((await run('f'.repeat(64), [signed], JSON.stringify(bundle))).status, 'failed');
  await assert.rejects(run('nope', [signed], null), /64-character/);
});

test('a dropped attestation plus bundle file verifies without a network lookup', async () => {
  const { commitment, signed } = await published();
  const dropped = parseDropped(JSON.stringify({ attestation: signed, bundle }));
  const result = await run(undefined, [], null, { dropped, registries: [] });
  assert.equal(result.commitment, commitment);
  assert.equal(result.status, 'verified');
  assert.throws(() => parseDropped('{"hello":1}'), /Unrecognised/);
});

test('the cli checks with the built-in providers from the default config', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'verify-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const { signed } = await published();
  const file = join(dir, 'evidence.json'), keyFile = join(dir, 'keys.json');
  await writeFile(file, JSON.stringify({ attestation: signed, bundle }));
  await writeFile(keyFile, JSON.stringify(keys));
  const cli = fileURLToPath(new URL('../packages/proof-check/cli.mjs', import.meta.url));
  const run = (...args) => new Promise(resolve => execFile(process.execPath, [cli, file, '--now', new Date(NOW).toISOString(), ...args],
    (error, stdout) => resolve({ code: error?.code ?? 0, stdout })));
  const ok = await run('--keys', keyFile);
  assert.equal(ok.code, 0, ok.stdout);
  assert.match(ok.stdout, /Claim matches the proven public inputs/);
  assert.equal((await run()).code, 1);
});
