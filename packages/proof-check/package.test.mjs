// Proof packages: the verifier's receipt vectors, packages built from the providers' own fixtures
// (test-fixtures/make-packages.mjs), a real UltraHonk proof when @aztec/bb.js is installed, and the CLI.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { bundleCommitment, checkPackage, closeZk, createAttestation, didWebUrl, packageHash, packageLines, parseDropped,
  signAttestation, verifierKeyId } from './index.mjs';
import { commitLeafHash, merkleRoot, revealLeafHash } from './package/leaves.mjs';
import { toHex } from './package/bytes.mjs';
import gcp from '../../private-proof/gcp/descriptor.mjs';
import aws from '../../private-proof/aws/descriptor.mjs';
import cloudflare from '../../private-proof/cloudflare/descriptor.mjs';

const json = url => JSON.parse(readFileSync(new URL(url, import.meta.url), 'utf8'));
const load = name => json(`./test-fixtures/proof-package/${name}`);
const MERKLE = json('../../servers/verifier/src/tests/receipt-merkle-vectors.json');
const V2 = json('../../servers/verifier/src/tests/receipt-v2-vectors.json');
const did = load('did.json');
const providers = [gcp, aws, cloudflare];
const keys = { dids: [did] };
const noBb = { loadBb: async () => { throw new Error('not installed'); } };
const byId = result => Object.fromEntries(result.checks.map(c => [c.id, c]));
const run = (pkg, options = {}) => checkPackage(pkg, { providers, keys, zk: noBb, ...options });
const hex = value => Uint8Array.from(Buffer.from(value, 'hex'));

// ── the verifier's receipt vectors ──────────────────────────────────────────────────────────────────────────────

test('receipt Merkle vectors (v1): leaf hashes and roots', async () => {
  for (const vector of MERKLE.vectors) {
    const hashes = [];
    for (const leaf of vector.leaves) {
      const hash = toHex(await revealLeafHash(leaf, hex(leaf.salt), hex(leaf.bytesHex)));
      assert.equal(hash, leaf.leafHash, `${vector.name} leaf ${leaf.index}`);
      hashes.push(hex(hash));
    }
    assert.equal(toHex(await merkleRoot(hashes)), vector.root, vector.name);
  }
});

test('receipt v2 vector: reveal and commit leaf hashes', async () => {
  for (const leaf of V2.leaves) {
    const hash = leaf.kind === 'commit' ? await commitLeafHash(leaf, hex(leaf.salt), hex(leaf.digest)) : await revealLeafHash(leaf, hex(leaf.salt), hex(leaf.bytesHex));
    assert.equal(toHex(hash), leaf.leafHash, `leaf ${leaf.index}`);
  }
});

/** The v2 vector as a package: reveal leaves published as hashes, commit leaves with their digests. */
function vectorPackage() {
  const r = { receipt: V2.receipt, leaves: V2.publishedLeaves.map(({ direction, start, end, kind }) => ({ direction, start, end, kind })),
    commitments: [], hidden: [], zk: null };
  V2.publishedLeaves.forEach((leaf, i) => {
    if (leaf.kind === 'reveal') r.hidden.push({ leaf: i, hash: V2.leaves[i].leafHash });
    else r.commitments.push({ leaf: i, salt: leaf.salt, alg: leaf.alg, digest: leaf.digest });
  });
  const didDocument = { id: V2.kid.split('#')[0], verificationMethod: [{ id: V2.kid, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: V2.publicJwk.x } }],
    assertionMethod: [V2.kid] };
  return { pkg: { v: 1, provider: 'cloudflare', runs: [r], pins: {} }, didDocument };
}

test('receipt v2 vector: signature, server name and root check', async () => {
  const { pkg, didDocument } = vectorPackage();
  const c = byId(await run(pkg, { keys: { dids: [didDocument] } }));
  assert.equal(c['receipt-signature'].ok, true, c['receipt-signature'].detail);
  assert.equal(c['server-name'].ok, true, c['server-name'].detail);
  assert.equal(c['signed-root'].ok, true, c['signed-root'].detail);
  // A Cloudflare package without its ZK bundle cannot pass the ZK check (the provider pins circuits).
  assert.equal(c['zk-proofs'].ok, false);
  assert.match(c['zk-proofs'].detail, /carries no ZK proofs/);
});

test('receipt v2 vector: a missing leaf, a tampered hash, a hidden commit leaf, another key or a non-assertion key fail', async () => {
  const { pkg, didDocument } = vectorPackage();
  const options = { keys: { dids: [didDocument] } };
  const missing = structuredClone(pkg);
  missing.runs[0].hidden = missing.runs[0].hidden.filter(h => h.leaf !== 4);
  assert.match(byId(await run(missing, options))['signed-root'].detail, /leaf 4 is neither disclosed, committed nor hidden/);

  const tampered = structuredClone(pkg);
  const hash = tampered.runs[0].hidden[0].hash;
  tampered.runs[0].hidden[0].hash = (hash[0] === '0' ? '1' : '0') + hash.slice(1);
  assert.equal(byId(await run(tampered, options))['signed-root'].ok, false);

  const hiddenCommit = structuredClone(pkg);
  hiddenCommit.runs[0].commitments = hiddenCommit.runs[0].commitments.filter(c => c.leaf !== 1);
  hiddenCommit.runs[0].hidden.push({ leaf: 1, hash: V2.leaves[1].leafHash });
  assert.match(byId(await run(hiddenCommit, options))['signed-root'].detail, /digest must be published/);

  const other = structuredClone(didDocument);
  other.verificationMethod[0].publicKeyJwk.x = V2.publicJwk.x.replace(/^./, ch => (ch === 'A' ? 'B' : 'A'));
  assert.equal(byId(await run(pkg, { keys: { dids: [other] } }))['receipt-signature'].ok, false);

  const unlisted = { ...didDocument, assertionMethod: [] };
  assert.match(byId(await run(pkg, { keys: { dids: [unlisted] } }))['receipt-signature'].detail, /not an assertion key/);
});

test('without the issuer\'s DID document the signature check is not run, never passed; a resolver supplies it', async () => {
  const { pkg, didDocument } = vectorPackage();
  const c1 = byId(await run(pkg, { keys: {} }))['receipt-signature'];
  assert.equal(c1.ok, null);
  assert.match(c1.detail, /no DID document for did:web:verifier.test.invalid/);
  const asked = [];
  const resolved = byId(await run(pkg, { keys: {}, resolveDid: async id => { asked.push(id); return didDocument; } }))['receipt-signature'];
  assert.equal(resolved.ok, true);
  assert.deepEqual(asked, ['did:web:verifier.test.invalid']);
  assert.equal(didWebUrl('did:web:verifier.example.com'), 'https://verifier.example.com/.well-known/did.json');
  assert.equal(didWebUrl('did:web:localhost%3A7047'), 'https://localhost:7047/.well-known/did.json');
});

// ── packages from the providers' fixtures ───────────────────────────────────────────────────────────────────────

test('Cloudflare: 1-3 pass, the claim is attested, ZK binds but needs bb.js, no registry: partial', async () => {
  const pkg = load('cloudflare-package.json');
  assert.ok(pkg.runs.every(r => !r.disclosed?.length && r.hidden.length > 0));
  const r = await run(pkg);
  const c = byId(r);
  for (const id of ['receipt-signature', 'server-name', 'signed-root']) assert.equal(c[id].ok, true, `${id}: ${c[id].detail}`);
  assert.equal(c['claim-from-data'].ok, null);
  assert.equal(c['claim-from-data'].reason, 'attested');
  assert.equal(c['zk-proofs'].ok, null);
  assert.match(c['zk-proofs'].detail, /open the \d+ signed commitments/);
  assert.equal(c['on-chain'].ok, null);
  assert.equal(c['on-chain'].reason, 'not-applicable');
  assert.equal(r.status, 'partial'); // ZK cannot run without verification keys
  assert.equal(r.proofHash, await packageHash(pkg));
  assert.equal(r.claim, 'cloudflare:groups:1,4,5:user');
  assert.equal(packageLines(r).length, 7);
});

test('the claim check fails when the package backs another claim', async () => {
  const c4 = byId(await run(load('cloudflare-package.json'), { claim: 'cloudflare:groups:3:user' }))['claim-from-data'];
  assert.equal(c4.ok, false);
  assert.equal(c4.reason, undefined);
});

test('a proof that does not open a signed commitment, or a foreign pin, fails the ZK check', async () => {
  const pkg = load('cloudflare-package.json');
  const bytes = pkg.runs[1].commitments[0].digest.match(/../g).map(h => BigInt(`0x${h}`));
  for (const p of pkg.runs[0].zk.proofs) {
    for (let i = 0; i + 32 <= p.publicInputs.length; i++) {
      if (bytes.every((b, j) => BigInt(p.publicInputs[i + j]) === b)) p.publicInputs[i] = String((bytes[0] + 1n) % 256n);
    }
  }
  const c5 = byId(await run(pkg))['zk-proofs'];
  assert.equal(c5.ok, false);
  assert.match(c5.detail, /opened by no proof/);

  const pinned = load('cloudflare-package.json');
  pinned.pins[Object.keys(pinned.pins)[0]] = 'f'.repeat(64);
  assert.equal(byId(await run(pinned))['zk-proofs'].ok, false);
});

test('a commit leaf relabelled reveal and hidden still rebuilds the root, but fails the ZK check', async () => {
  const pkg = load('cloudflare-package.json');
  const r = pkg.runs[1];
  for (const c of r.commitments) {
    const leaf = r.leaves[c.leaf];
    const hash = await commitLeafHash(leaf, hex(c.salt), hex(c.digest));
    leaf.kind = 'reveal';
    r.hidden.push({ leaf: c.leaf, hash: toHex(hash) });
  }
  r.commitments = [];
  const c = byId(await run(pkg));
  assert.equal(c['signed-root'].ok, true, c['signed-root'].detail);
  assert.equal(c['zk-proofs'].ok, false);
  assert.match(c['zk-proofs'].detail, /commits no values/);
});

test('a package without its ZK bundle fails the ZK check', async () => {
  const pkg = load('cloudflare-package.json');
  pkg.runs[0].zk = null;
  assert.match(byId(await run(pkg))['zk-proofs'].detail, /carries no ZK proofs/);
});

test('a receipt for another host fails the server-name check; a descriptor without hosts leaves it open', async () => {
  const c2 = byId(await run(load('gcp-package.json'), { providers: [{ ...gcp, hosts: () => ['example.com'] }] }))['server-name'];
  assert.equal(c2.ok, false);
  assert.match(c2.detail, /run 1 names "accounts.google.com"/);
  assert.equal(byId(await run(load('gcp-package.json'), { providers: [{ ...gcp, hosts: undefined }] }))['server-name'].ok, null);
});

for (const name of ['gcp', 'aws']) {
  test(`${name.toUpperCase()}: hidden leaves and commitments rebuild the roots; ZK binds every signed commitment`, async () => {
    const c = byId(await run(load(`${name}-package.json`)));
    for (const id of ['receipt-signature', 'server-name', 'signed-root']) assert.equal(c[id].ok, true, `${id}: ${c[id].detail}`);
    // GCP: the claim is checked against the public inputs only once the proofs verify (not run, never passed). AWS page
    // runs: the public inputs do not determine the groups, so without a signed attestation the claim is attested.
    assert.equal(c['claim-from-data'].ok, null);
    if (name === 'gcp') {
      assert.equal(c['claim-from-data'].reason, undefined);
      assert.match(c['claim-from-data'].detail, /once the proofs verify/);
    } else assert.equal(c['claim-from-data'].reason, 'attested');
    assert.equal(c['zk-proofs'].ok, null, c['zk-proofs'].detail);
    assert.match(c['zk-proofs'].detail, /open the \d+ signed commitments/);
  });
}

test('the descriptors\' hosts follow the session position', () => {
  assert.deepEqual(aws.hosts(0), ['iam.amazonaws.com']);
  assert.ok(aws.hosts(1).includes('cloudtrail.eu-west-1.amazonaws.com') && !aws.hosts(1).includes('iam.amazonaws.com'));
  assert.deepEqual(gcp.hosts(0), ['accounts.google.com']);
  assert.deepEqual(gcp.hosts(2), ['logging.clients6.google.com']);
  assert.deepEqual([...cloudflare.hosts], ['api.cloudflare.com']);
});

test('proofHash is sha256 of the canonical JSON, so key order does not matter', async () => {
  const pkg = load('cloudflare-package.json');
  assert.equal(await packageHash(Object.fromEntries(Object.entries(pkg).reverse())), await packageHash(pkg));
});

test('a malformed package or an unknown provider fails every check with the reason', async () => {
  const r = await run({ v: 2 });
  assert.equal(r.status, 'failed');
  assert.ok(r.checks.every(c => c.ok === false && /v1/.test(c.detail)));
  const unknown = await run({ ...load('gcp-zk-package.json'), provider: 'other' });
  assert.ok(unknown.checks.every(c => c.ok === false && /no descriptor for provider other/.test(c.detail)));
});

test('a dropped proof package is recognised', () => {
  const pkg = load('gcp-zk-package.json');
  assert.deepEqual(parseDropped(JSON.stringify(pkg)), { package: pkg });
});

// ── claims checked against the proofs' public inputs ───────────────────────────────────────────────────────────

/**
 * The fixture packages carry placeholder proofs: here a stand-in verifier accepts (or rejects) every proof, under a
 * test key pinned by a copy of the descriptor. The binding to the signed commitments is still checked for real.
 */
const TEST_KEY = Buffer.from('test verification key');
const TEST_SHA = createHash('sha256').update(TEST_KEY).digest('hex');
const fakeBb = verdict => async () => ({
  BackendType: { Wasm: 'wasm' },
  Barretenberg: class { static async new() { return { destroy: async () => {} }; } async initSRSChonk() {} },
  UltraHonkVerifierBackend: class { async verifyProof() { return verdict; } },
});
async function withProofs(name, { verdict = true, edit = pkg => pkg, ...options } = {}) {
  const pkg = load(name);
  const descriptor = providers.find(p => p.id === pkg.provider);
  pkg.pins = Object.fromEntries(Object.keys(pkg.pins).map(id => [id, TEST_SHA]));
  edit(pkg);
  try {
    return await run(pkg, { providers: [{ ...descriptor, pins: { circuits: Object.fromEntries(Object.keys(pkg.pins).map(id => [id, { sha256: TEST_SHA }])) } }],
      zk: { loadBb: fakeBb(verdict), verificationKey: async () => TEST_KEY }, ...options });
  } finally {
    await closeZk();
  }
}

test('GCP: once the proofs verify, the claim is rebuilt from their public inputs', async () => {
  const r = await withProofs('gcp-package.json');
  const c = byId(r);
  assert.equal(c['zk-proofs'].ok, true, c['zk-proofs'].detail);
  assert.equal(c['claim-from-data'].ok, true, c['claim-from-data'].detail);
  assert.match(c['claim-from-data'].detail, /from the proofs' public inputs$/);
  assert.equal(r.status, 'verified');
});

test('GCP: a claim the public inputs do not give fails, even when signed; proofs that do not verify leave it unchecked', async () => {
  const tampered = await withProofs('gcp-package.json', { edit: pkg => { pkg.claim = 'gcp:observed:g1'; } });
  assert.equal(byId(tampered)['claim-from-data'].ok, false);
  assert.match(byId(tampered)['claim-from-data'].detail, /the proofs' public inputs give "gcp:observed:g0,/);

  const rejected = await withProofs('gcp-package.json', { verdict: false });
  assert.equal(byId(rejected)['zk-proofs'].ok, false);
  assert.equal(byId(rejected)['claim-from-data'].ok, null);
  assert.match(byId(rejected)['claim-from-data'].detail, /do not verify/);
  assert.equal(rejected.status, 'failed');

  const skipped = byId(await withProofs('gcp-package.json', { zk: { skip: 'skipped here' } }))['claim-from-data'];
  assert.equal(skipped.ok, null);
  assert.equal(skipped.reason, undefined);
});

for (const name of ['aws', 'cloudflare']) {
  test(`${name}: the public inputs do not determine the claim, so it is attested even when the proofs verify`, async () => {
    const c = byId(await withProofs(`${name}-package.json`));
    assert.equal(c['zk-proofs'].ok, true, c['zk-proofs'].detail);
    assert.equal(c['claim-from-data'].ok, null);
    assert.equal(c['claim-from-data'].reason, 'attested');
  });
}

// ── claims signed by a trusted issuer ───────────────────────────────────────────────────────────────────────────

const NOW = Date.now();
async function newIssuer(label = 'test issuer') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), key: { id: await verifierKeyId(publicKeyPem), label, publicKeyPem } };
}
async function attest(pkg, issuer, overrides = {}) {
  const fields = { provider: pkg.provider, claim: pkg.claim, proofHash: await packageHash(pkg), ...overrides };
  return signAttestation(createAttestation({ ...fields, commitment: await bundleCommitment(fields),
    issuedAt: new Date(NOW - 60000).toISOString(), expiresAt: new Date(NOW + 86400000).toISOString() }), issuer.privateKeyPem);
}

test('a claim signed by a listed issuer key over the package hash passes; another key, claim or package does not', async () => {
  const pkg = load('cloudflare-package.json');
  const issuer = await newIssuer();
  const signedBy = async (attestation, trusted = [issuer.key]) => byId(await run(pkg, { attestation, keys: { dids: [did], keys: trusted }, now: NOW }))['claim-from-data'];

  const ok = await signedBy(await attest(pkg, issuer));
  assert.equal(ok.ok, true, ok.detail);
  assert.equal(ok.detail, `${pkg.claim}, signed by test issuer`);

  const unlisted = await signedBy(await attest(pkg, await newIssuer('other')));
  assert.equal(unlisted.ok, null);
  assert.equal(unlisted.reason, 'attested');
  assert.match(unlisted.detail, /not signed by a listed key/);

  const otherClaim = await signedBy(await attest(pkg, issuer, { claim: 'cloudflare:groups:3:user' }));
  assert.equal(otherClaim.ok, false);
  assert.match(otherClaim.detail, /backs "cloudflare:groups:3:user"/);

  const otherPackage = await signedBy(await attest(pkg, issuer, { proofHash: 'a'.repeat(64) }));
  assert.equal(otherPackage.ok, false);
  assert.match(otherPackage.detail, /names package a{64}/);

  const forged = { ...(await attest(pkg, issuer)), claim: 'cloudflare:groups:3:user' };
  assert.equal((await signedBy(forged)).reason, 'attested');
});

test('AWS: a signed claim passes once nothing in the proofs contradicts it; the on-chain record is reused', async () => {
  const pkg = load('aws-package.json');
  const issuer = await newIssuer();
  const attestation = await attest(pkg, issuer);
  let lookups = 0;
  const registry = { findByProofHash: async () => { lookups += 1; return [attestation]; } };
  const r = await run(pkg, { registries: [registry], keys: { dids: [did], keys: [issuer.key] }, now: NOW });
  const c = byId(r);
  assert.equal(c['on-chain'].ok, true, c['on-chain'].detail);
  assert.equal(c['claim-from-data'].ok, true, c['claim-from-data'].detail);
  assert.match(c['claim-from-data'].detail, /signed by test issuer$/);
  assert.equal(lookups, 1);
});

test('a package with its attestation in one file is recognised', async () => {
  const pkg = load('cloudflare-package.json');
  const attestation = await attest(pkg, await newIssuer());
  assert.deepEqual(parseDropped(JSON.stringify({ package: pkg, attestation })), { package: pkg, attestation });
  assert.deepEqual(parseDropped(JSON.stringify({ package: pkg })), { package: pkg });
});

test('a package that names no claim: the claim check is not applicable', async () => {
  const c4 = byId(await run(load('gcp-zk-package.json')))['claim-from-data'];
  assert.equal(c4.ok, null);
  assert.equal(c4.reason, 'not-applicable');
});

// ── on chain ────────────────────────────────────────────────────────────────────────────────────────────────────

test('on-chain: an attestation naming the package hash, signed by a listed key, in a registry', async () => {
  const pkg = load('gcp-zk-package.json');
  const proofHash = await packageHash(pkg);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
  const listed = { id: await verifierKeyId(pem.publicKey), label: 'test', publicKeyPem: pem.publicKey };
  const now = Date.now();
  const fields = { provider: 'gcp', claim: 'gcp:observed:none', proofHash };
  const signed = await signAttestation(createAttestation({ ...fields, commitment: await bundleCommitment(fields),
    issuedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 86400000).toISOString() }), pem.privateKey);
  const registry = { findByProofHash: async query => (query.proofHash === signed.proofHash ? [signed] : []) };
  const onChain = async options => byId(await run(pkg, { registries: [registry], keys: { dids: [did], keys: [listed] }, now, ...options }))['on-chain'];

  assert.equal((await onChain()).ok, true);
  assert.equal((await onChain({ keys: { dids: [did], keys: [] } })).detail, 'unknown-key');
  assert.equal((await onChain({ registries: [{ findByProofHash: async () => [] }] })).detail, 'not-found');
  assert.equal((await onChain({ proofHash: 'a'.repeat(64) })).ok, false);
});

// ── claims rebuilt from disclosed bytes ─────────────────────────────────────────────────────────────────────────

const SIGNER = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const sha = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };

/** One signed v1 run over `[{ direction, start, text, disclose }]` reveal leaves (fixed test salts). */
function signedRun(specs, { serverName, sessionId = 's0' }) {
  const r = { leaves: [], disclosed: [], hidden: [] };
  const hashes = specs.map((spec, i) => {
    const bytes = Buffer.from(spec.text, 'latin1'), leaf = { direction: spec.direction, start: spec.start, end: spec.start + bytes.length };
    const salt = sha(Buffer.from(`salt-${i}`));
    const head = Buffer.alloc(18); head[1] = leaf.direction === 'sent' ? 0 : 1;
    head.writeBigUInt64BE(BigInt(leaf.start), 2); head.writeBigUInt64BE(BigInt(bytes.length), 10);
    const hash = sha(head, salt, bytes);
    r.leaves.push(leaf);
    if (spec.disclose) r.disclosed.push({ leaf: i, salt: salt.toString('hex'), bytes: bytes.toString('base64') });
    else r.hidden.push({ leaf: i, hash: hash.toString('hex') });
    return hash;
  });
  let level = hashes;
  while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? sha(Buffer.from([1]), level[i], level[i + 1]) : level[i]); level = next; }
  const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${enc({ alg: 'EdDSA', kid: did.verificationMethod[0].id, typ: 'tlsn-receipt+jws' })}.${enc({ v: 1, serverName, sessionId,
    verifiedAt: '2026-11-26T10:00:00.000Z', tlsnVersion: '0.1.0-alpha.15', root: level[0].toString('hex'), leafCount: specs.length })}`;
  r.receipt = `${input}.${sign(null, Buffer.from(input), SIGNER).toString('base64url')}`;
  return r;
}

test('a provider without circuits: the claim is rebuilt from the disclosed bytes, ZK is not applicable', async () => {
  const example = { id: 'example', hosts: ['example.com'],
    claimFromData: ({ runs }) => `example:status-${new TextDecoder().decode(runs[0].disclosed[0].bytes).split(' ')[1]}` };
  const r0 = signedRun([{ direction: 'sent', start: 0, text: 'GET / HTTP/1.1\r\n' }, { direction: 'recv', start: 0, text: 'HTTP/1.1 200 OK\r\n', disclose: true }],
    { serverName: 'example.com' });
  const pkg = { v: 1, provider: 'example', claim: 'example:status-200', runs: [r0], pins: {} };
  const result = await run(pkg, { providers: [example] });
  const c = byId(result);
  for (const id of ['receipt-signature', 'server-name', 'signed-root', 'claim-from-data']) assert.equal(c[id].ok, true, `${id}: ${c[id].detail}`);
  assert.equal(c['zk-proofs'].reason, 'not-applicable');
  assert.equal(result.status, 'verified'); // no registry: on-chain is not applicable

  const wrong = await run({ ...pkg, claim: 'example:status-404' }, { providers: [example] });
  assert.equal(byId(wrong)['claim-from-data'].ok, false);
  const altered = structuredClone(pkg);
  altered.runs[0].disclosed[0].bytes = Buffer.from('HTTP/1.1 404 OK\r\n').toString('base64');
  assert.equal(byId(await run(altered, { providers: [example] }))['signed-root'].ok, false);
});

// ── a real UltraHonk proof ──────────────────────────────────────────────────────────────────────────────────────

let bbInstalled = true;
try { await import('@aztec/bb.js'); } catch { bbInstalled = false; }

test('a real UltraHonk proof verifies with the 192-byte setup and the pinned key; a changed input or another key does not',
  { skip: !bbInstalled && '@aztec/bb.js not installed' }, async () => {
    try {
      const pkg = load('gcp-zk-package.json');
      const check = async (value, options) => byId(await checkPackage(value, { providers, keys, ...options }))['zk-proofs'];
      const good = await check(pkg);
      assert.equal(good.ok, true, good.detail);

      const changed = structuredClone(pkg);
      const inputs = changed.runs[0].zk.proofs[0].publicInputs;
      inputs[198] = `0x${(BigInt(inputs[198]) + 1n).toString(16)}`;
      assert.equal((await check(changed)).ok, false);

      assert.equal((await check(pkg, { zk: { verificationKey: async () => new Uint8Array(3680) } })).ok, false);
      const swapped = structuredClone(pkg);
      swapped.vks['timestamps-v1'] = Buffer.alloc(3680).toString('base64');
      assert.equal((await check(swapped)).ok, false);
    } finally {
      await closeZk();
    }
  });

// ── CLI ─────────────────────────────────────────────────────────────────────────────────────────────────────────

const cli = (...args) => {
  try {
    return { out: execFileSync(process.execPath, [new URL('./cli.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8', stdio: 'pipe' }), code: 0 };
  } catch (error) { return { out: error.stdout, err: error.stderr, code: error.status }; }
};
const fixture = name => new URL(`./test-fixtures/proof-package/${name}`, import.meta.url).pathname;

test('CLI --proof prints one line per check; exits 2 when a check could not run, 1 when one fails, 2 on bad input', () => {
  const partial = cli('--proof', fixture('cloudflare-package.json'), '--did', fixture('did.json'));
  const lines = partial.out.trim().split('\n');
  assert.equal(lines.length, 7, partial.out);
  assert.match(lines[0], /^ok {3}receipt-signature: /);
  assert.match(lines[3], /^att {2}claim-from-data: /);
  assert.match(lines[6], /^partial [0-9a-f]{64} cloudflare:groups:1,4,5:user$/);
  assert.equal(partial.code, 2);

  assert.equal(cli('--proof', fixture('cloudflare-package.json'), '--did', fixture('did.json'), '--claim', 'cloudflare:groups:3:user').code, 1);
  assert.equal(cli('--proof', fixture('did.json')).code, 2);
  assert.equal(cli('--proof').code, 2);
});

test('CLI --proof with { package, attestation } and --keys: the signed claim passes; --attestation gives it separately', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'proof-check-'));
  try {
    const pkg = load('cloudflare-package.json');
    const issuer = await newIssuer();
    const attestation = await attest(pkg, issuer);
    const file = name => join(dir, name);
    writeFileSync(file('keys.json'), JSON.stringify({ keys: [issuer.key], dids: [did] }));
    writeFileSync(file('both.json'), JSON.stringify({ package: pkg, attestation }));
    writeFileSync(file('attestation.json'), JSON.stringify(attestation));
    const both = cli('--proof', file('both.json'), '--keys', file('keys.json'));
    assert.match(both.out.split('\n')[3], /^ok {3}claim-from-data: .*signed by test issuer\)$/, both.out);
    const apart = cli('--proof', fixture('cloudflare-package.json'), '--keys', file('keys.json'), '--attestation', file('attestation.json'));
    assert.match(apart.out.split('\n')[3], /^ok {3}claim-from-data: /, apart.out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
