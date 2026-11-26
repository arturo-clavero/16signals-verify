#!/usr/bin/env node
// Builds the proof-package test fixtures in ./proof-package from the providers' own synthetic test fixtures. A
// development tool, not part of the checker (it imports private-proof; the checker does not).
//
//   - cloudflare-package.json  identity + one audit-log page (private-proof/cloudflare session fixtures)
//   - gcp-package.json         identity + five log batches (private-proof/gcp gcp-fixtures.mjs)
//   - aws-package.json         identity + page sessions (private-proof/aws page-run-fixture.mjs); needs the built AWS
//                              circuit artifacts for their ABIs
//   - gcp-zk-package.json      one real timestamps-v1 UltraHonk proof over six synthetic commitments, with its key
//   - did.json                 the issuer's DID document
//
// Receipts are v2, signed with the fake test key of servers/verifier/src/tests/receipt-v2-vectors.json (seed 0x07 x
// 32). Every reveal leaf is hidden (leaf hash only); commit leaves carry their digests. The replay packages' proofs are
// placeholders (the binding is real, the UltraHonk proofs are not); the provider verifiers run here to make sure each
// bundle is one they accept.
//
//   node packages/proof-check/test-fixtures/make-packages.mjs <aws dist/artifacts dir>
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pinnedKeyHash } from '../bundle.mjs';
import { planCloudflareSession, cloudflarePageRows, inspectCloudflareSession } from '../../../private-proof/cloudflare/session.mjs';
import { requestBytes, responseBytes, identityBody, pageBody } from '../../../private-proof/cloudflare/session-fixture.mjs';
import { receiptFor } from '../../../private-proof/cloudflare/receipt-fixture.mjs';
import { authenticatedCloudflareTranscript, cloudflareTargets, verifyCloudflareBundle } from '../../../private-proof/cloudflare/verify-bundle.mjs';
import { verifyBundle as verifyGcpBundle, assembleBundleExpectations } from '../../../private-proof/gcp/verify-bundle.mjs';
import { inspectGcpSession } from '../../../private-proof/gcp/gcp-structure.mjs';
import { BATCHES } from '../../../private-proof/gcp/policy.mjs';
import { gcpFixture, fixtureNonce, fixturePolicy, identityRow, secret, fragments } from '../../../private-proof/gcp/gcp-fixtures.mjs';
import { verifyAwsBundle } from '../../../private-proof/aws/verify-bundle.mjs';
import { fixtureExpected, fixtureNow } from '../../../private-proof/aws/event-fixture.mjs';
import { pageActivity, pageRun } from '../../../private-proof/aws/page-run-fixture.mjs';
import { loadAwsArtifacts } from '../../../private-proof/aws/artifact-registry.mjs';
import { awsToolClass } from '../../../private-proof/aws/tool-class.mjs';
import gcp from '../../../private-proof/gcp/descriptor.mjs';
import aws from '../../../private-proof/aws/descriptor.mjs';
import cloudflare from '../../../private-proof/cloudflare/descriptor.mjs';

const HERE = import.meta.dirname;
const OUT = resolve(HERE, 'proof-package');
const vector = JSON.parse(readFileSync(resolve(HERE, '../../../servers/verifier/src/tests/receipt-v2-vectors.json'), 'utf8'));
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const KID = vector.kid;
const DID = KID.split('#')[0];
const b64url = bytes => Buffer.from(bytes).toString('base64url');
const sha = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
let saltCounter = 0;
const nextSalt = () => sha(Buffer.from(`fixture-salt-${saltCounter++}`));

function u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
const leafHead = (tag, l) => Buffer.concat([Buffer.from([tag, l.direction === 'sent' ? 0 : 1]), u64(l.start), u64(l.end - l.start)]);
function root(hashes) {
  let level = hashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? sha(Buffer.from([1]), level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}

/** A verifier result (webhook shape) -> one package run: v2 leaves, every reveal leaf hidden. */
function packageRun(receipt, { serverName, sessionId, proofId, verifiedAt, zk = null }) {
  const bytesOf = { sent: Buffer.from(receipt.transcript.sent, 'latin1'), recv: Buffer.from(receipt.transcript.recv, 'latin1') };
  const leaves = [], commitments = [], hidden = [], hashes = [];
  const results = { sent: receipt.results.filter(r => r.type === 'SENT'), recv: receipt.results.filter(r => r.type === 'RECV') };
  for (const direction of ['sent', 'recv']) {
    receipt.config[direction].forEach((range, i) => {
      const result = results[direction][i];
      const leaf = { direction, start: range.start, end: range.end, kind: result.action.kind === 'HASH' ? 'commit' : 'reveal' };
      const index = leaves.push(leaf) - 1, salt = nextSalt();
      if (leaf.kind === 'commit') {
        hashes.push(sha(leafHead(2, leaf), salt, Buffer.from(result.value, 'hex')));
        commitments.push({ leaf: index, salt: salt.toString('hex'), alg: 'sha256', digest: result.value });
      } else {
        const hash = sha(leafHead(0, leaf), salt, bytesOf[direction].subarray(range.start, range.end));
        hashes.push(hash);
        hidden.push({ leaf: index, hash: hash.toString('hex') });
      }
    });
  }
  const header = JSON.stringify({ alg: 'EdDSA', kid: KID, typ: 'tlsn-receipt+jws' });
  const payload = JSON.stringify({ v: 2, serverName, sessionId, proofId, verifiedAt, tlsnVersion: '0.1.0-alpha.15', root: root(hashes).toString('hex'), leafCount: leaves.length });
  const input = `${b64url(header)}.${b64url(payload)}`;
  return { receipt: `${input}.${b64url(sign(null, Buffer.from(input), key))}`, leaves, commitments, hidden, zk };
}

const pinsFor = (descriptor, proofs) => Object.fromEntries([...new Set(proofs.map(p => p.circuitId))].map(id => [id, pinnedKeyHash(descriptor.pins.circuits[id])]));
const write = (name, value) => writeFileSync(resolve(OUT, name), `${JSON.stringify(value, null, 2)}\n`);
const accept = { verify: async (entry, expected) => entry.publicInputs.every((v, i) => BigInt(v) === BigInt(expected[i])) };
const placeholder = proofs => proofs.map(p => ({ ...p, proof: Buffer.alloc(16).toString('base64'), publicInputs: p.publicInputs.map(v => `0x${BigInt(v).toString(16)}`) }));

write('did.json', {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'], id: DID,
  verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: vector.publicJwk.x, alg: 'EdDSA', use: 'sig' } }],
  assertionMethod: [KID],
});

// Cloudflare: identity + one page of three rows.
{
  const issuedAt = Date.parse('2026-11-25T08:00:00Z');
  const proofId = '3f2b8c1e-5d4a-4c3b-9a1f-0000000000c1';
  const base = { proofId, pluginSha256: 'c'.repeat(64), nonceMac: 'n'.repeat(43), issuedAt, expiresAt: issuedAt + 900000 };
  const sessions = [];
  const idExpected = { ...base, sessionId: '0b8e8f0e-0000-4000-8000-0000000000c1', step: 'identity' };
  const idPlan = planCloudflareSession('identity', requestBytes('identity'), responseBytes(identityBody()));
  sessions.push({ expected: idExpected, ...receiptFor({ sent: requestBytes('identity'), recv: responseBytes(identityBody()), plan: idPlan, expected: idExpected }) });
  const rows = [{}, { product: 'queues', type: null }, { product: 'workers', type: 'scripts', action: 'update', context: 'dash' }];
  const body = pageBody(rows), starts = cloudflarePageRows(body).map(r => r.start);
  const recv = responseBytes(body, starts.slice(1).map((s, i) => s - (i ? starts[i] : 0)));
  const plan = planCloudflareSession('P0', requestBytes('page'), recv, [0, 1, 2]);
  const expected = { ...base, sessionId: '0b8e8f0e-0000-4000-8000-0000000000c2', step: 'P0' };
  sessions.push({ expected, ...receiptFor({ sent: requestBytes('page'), recv, plan, expected }) });
  const inspected = sessions.map(s => inspectCloudflareSession(authenticatedCloudflareTranscript(s.receipt, s.expected, issuedAt + 60000), s.expected.step));
  const targets = cloudflareTargets(inspected[0], inspected.slice(1));
  const zk = { kind: cloudflare.kind, version: 1, sessionIds: sessions.map(s => s.expected.sessionId),
    proofs: targets.map(t => ({ circuitId: t.circuitId, proof: Buffer.alloc(16).toString('base64'), publicInputs: t.publicInputs.map(String) })) };
  const runs = sessions.map((s, i) => packageRun(s.receipt, { serverName: 'api.cloudflare.com', sessionId: s.expected.sessionId, proofId,
    verifiedAt: new Date(issuedAt + 60000 * (i + 1)).toISOString(), zk: i === 0 ? zk : null }));
  const result = await verifyCloudflareBundle({ sessions, bundle: zk, runtime: accept, now: issuedAt + 60000 });
  const pkg = { v: 1, provider: 'cloudflare', claim: cloudflare.claimFromResult(result).claim, runs, pins: pinsFor(cloudflare, zk.proofs), vks: {} };
  write('cloudflare-package.json', pkg);
}

// GCP: one real timestamps-v1 proof over six signed commitments.
{
  const real = JSON.parse(readFileSync(resolve(OUT, 'gcp-timestamps-proof.json'), 'utf8'));
  const vk = Buffer.from(real.vk, 'base64');
  const vkSha = createHash('sha256').update(vk).digest('hex');
  if (vkSha !== pinnedKeyHash(gcp.pins.circuits['timestamps-v1'])) throw new Error('the key is not the pinned timestamps-v1 key');
  const fields = real.publicInputs.map(v => BigInt(v));
  const digests = Array.from({ length: 6 }, (_, i) => Buffer.from(fields.slice(i * 32, i * 32 + 32).map(Number)).toString('hex'));
  const lengths = fields.slice(192, 198).map(Number);
  // A synthetic transcript: a public request line, then six hash-committed values.
  const line = 'GET /synthetic HTTP/1.1\r\n';
  let at = 0;
  const config = { sent: [{ start: 0, end: line.length }], recv: [] };
  const results = [{ type: 'SENT', action: { kind: 'REVEAL' }, value: line }];
  digests.forEach((digest, i) => {
    config.recv.push({ start: at, end: at + lengths[i] });
    results.push({ type: 'RECV', action: { kind: 'HASH', algorithm: 'SHA256' }, value: digest });
    at += lengths[i];
  });
  const receipt = { config, results, transcript: { sent: line, recv: '\0'.repeat(at) } };
  const zk = { kind: gcp.kind, version: 1, sessionIds: ['0b8e8f0e-0000-4000-8000-0000000000d1'],
    proofs: [{ circuitId: 'timestamps-v1', proof: real.proof, publicInputs: real.publicInputs }] };
  const run = packageRun(receipt, { serverName: 'accounts.google.com', sessionId: zk.sessionIds[0], proofId: '3f2b8c1e-5d4a-4c3b-9a1f-0000000000d1',
    verifiedAt: '2026-11-26T12:00:00.000Z', zk });
  const pkg = { v: 1, provider: 'gcp', runs: [run], pins: { 'timestamps-v1': vkSha }, vks: { 'timestamps-v1': real.vk } };
  write('gcp-zk-package.json', pkg);
}

// GCP replay: identity + five batch sessions.
{
  const steps = ['identity', ...BATCHES.map(b => b.step)];
  const proofId = '22222222-2222-4222-8222-2222222222e1';
  const fixtures = steps.map((step, index) => {
    const options = index === 0 ? { rows: [identityRow(0, '1', secret(`"${'x'.repeat(100)}"`, 1)), identityRow(1, '0')],
      responseHeaders: fragments('X-Transport: ', secret('first synthetic value'), '\r\nX-Transport: ', secret('second synthetic value'), '\r\n') } : {};
    const fixture = gcpFixture(step, options), replacements = new Map();
    for (const direction of Object.values(fixture.directions)) {
      for (const slot of direction.privateRanges) {
        const hash = ((BigInt(index + 1) << 32n) + BigInt(`0x${slot.hash}`)).toString(16).padStart(64, '0');
        replacements.set(slot.hash, hash); slot.hash = hash;
      }
    }
    for (const claim of fixture.atomicClaims) claim.hash = replacements.get(claim.hash);
    return fixture;
  });
  const sessions = fixtures.map((fixture, index) => {
    const expected = { sessionId: `11111111-1111-4111-8111-${String(index + 1).padStart(12, '0')}`, proofId, pluginSha256: 'ab'.repeat(32), nonceMac: fixtureNonce, step: fixture.meta.step };
    const receipt = { server_name: index === 0 ? 'accounts.google.com' : 'logging.clients6.google.com',
      session: { id: expected.sessionId, proofId, pluginSha256: expected.pluginSha256, nonceMac: fixtureNonce, step: expected.step, method: 'GCP_WORK', mode: 'Proxy' },
      config: {}, results: [], transcript: {} };
    for (const [name, value] of Object.entries(fixture.directions)) {
      const ranges = [], type = name.toUpperCase();
      const append = (start, end, hash) => {
        const action = hash ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' };
        ranges.push({ start, end, handler: { type, part: 'BODY', action } });
        receipt.results.push({ type, part: 'BODY', action, value: hash ?? new TextDecoder().decode(value.bytes.slice(start, end)) });
      };
      let cursor = 0;
      for (const slot of value.privateRanges) { if (cursor < slot.start) append(cursor, slot.start); append(slot.start, slot.end, slot.hash); cursor = slot.end; }
      if (cursor < value.bytes.length) append(cursor, value.bytes.length);
      receipt.config[name] = ranges;
      receipt.transcript[name] = String.fromCharCode(...value.bytes);
      receipt.transcript[`${name}_length`] = value.bytes.length;
    }
    return { receipt, expected };
  });
  const inspections = fixtures.map(f => inspectGcpSession(f.directions, f.meta, f.policy, f.atomicClaims));
  const expectations = assembleBundleExpectations(inspections, Array(32).fill(7), fixturePolicy, fixtureNonce);
  const zk = { kind: gcp.kind, version: 1, sessionIds: sessions.map(x => x.expected.sessionId),
    proofs: placeholder(expectations.map(e => ({ circuitId: e.circuitId, publicInputs: e.publicInputs }))) };
  const result = await verifyGcpBundle({ sessions, policy: fixturePolicy, bundle: zk, runtime: accept });
  if (!result.groups.some(g => g.status === 'observed')) throw new Error('the GCP fixture bundle observes no group');
  const runs = sessions.map((x, i) => packageRun(x.receipt, { serverName: x.receipt.server_name, sessionId: x.expected.sessionId, proofId,
    verifiedAt: new Date(fixturePolicy.cutoff + 60000 * (i + 1)).toISOString(), zk: i === 0 ? zk : null }));
  const pkg = { v: 1, provider: 'gcp', claim: gcp.claimFromResult(result).claim, runs, pins: pinsFor(gcp, zk.proofs), vks: {} };
  write('gcp-package.json', pkg);
}

// AWS replay: identity + page sessions.
{
  const dir = process.argv[2];
  if (!dir) throw new Error('usage: make-packages.mjs <aws dist/artifacts dir>');
  const artifacts = await loadAwsArtifacts(file => readFileSync(resolve(dir, file)));
  const proveCircuit = async (id, inputs) => {
    const values = artifacts[id].abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity));
    if (id.startsWith('aws-event-batch')) {
      for (const [row, body] of inputs.row_body.entries()) values.push(awsToolClass(`"${Buffer.from(body.slice(2, inputs.ua_lengths[row] - 2)).toString()}"`));
    } else if (artifacts[id].abi.return_type) values.push(1);
    return { circuitId: id, proof: 'AA==', publicInputs: values.map(String) };
  };
  const { bundle, sessions } = await pageRun(pageActivity(), proveCircuit);
  const result = await verifyAwsBundle({ sessions, bundle, runtime: accept, now: fixtureNow });
  if (!result.observations.length) throw new Error('the AWS fixture bundle observes no row');
  const zk = { ...bundle, proofs: placeholder(bundle.proofs) };
  const runs = sessions.map((x, i) => packageRun(x.receipt, { serverName: x.receipt.server_name, sessionId: x.expected.sessionId, proofId: x.expected.proofId,
    verifiedAt: new Date(fixtureExpected.issuedAt + 1000 * (i + 1)).toISOString(), zk: i === 0 ? zk : null }));
  const pkg = { v: 1, provider: 'aws', claim: aws.claimFromResult(result).claim, runs, pins: pinsFor(aws, zk.proofs), vks: {} };
  write('aws-package.json', pkg);
}

process.stdout.write(`wrote ${OUT}\n`);
