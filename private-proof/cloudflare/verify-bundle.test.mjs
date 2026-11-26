import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { planCloudflareSession, cloudflarePageRows } from './session.mjs';
import { requestBytes, responseBytes, identityBody, pageBody } from './session-fixture.mjs';
import { receiptFor } from './receipt-fixture.mjs';
import {
  authenticatedCloudflareTranscript, cloudflareTargets, verifyCloudflareBundle, validateCloudflareBundleShape, CF_CIRCUITS,
} from './verify-bundle.mjs';
import { inspectCloudflareSession } from './session.mjs';

const issuedAt = Date.parse('2026-11-25T08:00:00Z'), now = issuedAt + 60000;
const base = { proofId: randomUUID(), pluginSha256: 'c'.repeat(64), nonceMac: 'n'.repeat(43), issuedAt, expiresAt: issuedAt + 900000 };

function run(pageRows = [{}, { product: 'queues', type: null }, { product: 'workers', type: 'scripts', action: 'update', context: 'dash' }], select = [0, 1, 2]) {
  const sessions = [];
  const idPlan = planCloudflareSession('identity', requestBytes('identity'), responseBytes(identityBody()));
  const idExpected = { ...base, sessionId: randomUUID(), step: 'identity' };
  sessions.push({ expected: idExpected, ...receiptFor({ sent: requestBytes('identity'), recv: responseBytes(identityBody()), plan: idPlan, expected: idExpected }) });
  const body = pageBody(pageRows), starts = cloudflarePageRows(body).map(r => r.start);
  const recv = responseBytes(body, starts.slice(1).map((s, i) => s - (i ? starts[i] : 0)));
  const plan = planCloudflareSession('P0', requestBytes('page'), recv, select);
  const expected = { ...base, sessionId: randomUUID(), step: 'P0' };
  sessions.push({ expected, ...receiptFor({ sent: requestBytes('page'), recv, plan, expected }) });
  const results = sessions.map(s => inspectCloudflareSession(authenticatedCloudflareTranscript(s.receipt, s.expected, now), s.expected.step));
  const targets = cloudflareTargets(results[0], results.slice(1));
  const bundle = { kind: 'CLOUDFLARE_PRIVATE_RESULT', version: 1, sessionIds: sessions.map(s => s.expected.sessionId),
    proofs: targets.map(t => ({ circuitId: t.circuitId, proof: 'AAAA', publicInputs: t.publicInputs.map(String) })) };
  return { sessions: sessions.map(({ receipt, expected }) => ({ receipt, expected })), openings: sessions.map(s => s.openings), targets, bundle };
}
const accept = { verify: async () => true };

test('a full synthetic run verifies into observations', async () => {
  const { sessions, bundle, targets } = run();
  validateCloudflareBundleShape(bundle);
  const out = await verifyCloudflareBundle({ sessions, bundle, runtime: accept, now });
  assert.equal(out.attribution, 'cloudflare-user');
  assert.deepEqual(out.observations.map(o => `${o.group} ${o.tool} ${o.day}`), ['d1 cli 2026-11-25', 'queues cli 2026-11-25', 'workers-deploy console 2026-11-25']);
  const kinds = targets.reduce((m, t) => ({ ...m, [t.circuitId]: (m[t.circuitId] ?? 0) + 1 }), {});
  assert.equal(kinds['cf-actor-v1'], 1);
  for (const t of targets) assert.equal(t.publicInputs.length, CF_CIRCUITS[t.circuitId][2]);
});

test('every hidden piece is covered by exactly one target slot', () => {
  const { targets, openings } = run();
  const covered = targets.flatMap(t => t.slots.map(s => s.hash));
  const all = openings.flatMap(o => [...o.keys()]);
  assert.equal(new Set(covered).size, covered.length);
  assert.deepEqual([...covered].sort(), [...all].sort());
});

test('forged bundles and receipts are refused', async () => {
  const bad = async (mutate, code = '') => {
    const r = run(); mutate(r);
    await assert.rejects(verifyCloudflareBundle({ sessions: r.sessions, bundle: r.bundle, runtime: r.runtime ?? accept, now }), new RegExp(`CF_PRIVATE_BUNDLE_INVALID${code}`));
  };
  await bad(r => { r.bundle.proofs.pop(); }, ':proof-count');
  await bad(r => { r.bundle.proofs[0].publicInputs[0] = '7'; }, ':inputs');
  await bad(r => { r.bundle.proofs.reverse(); });
  await bad(r => { r.runtime = { verify: async () => false }; }, ':verify');
  await bad(r => { r.sessions[1].receipt.session.method = 'AWS_ACCOUNT'; }, ':receipt');
  await bad(r => { r.sessions[1].receipt.server_name = 'evil.example'; }, ':receipt');
  await bad(r => { r.sessions[1].expected.pluginSha256 = 'd'.repeat(64); r.sessions[1].receipt.session.pluginSha256 = 'd'.repeat(64); }, '');
  await bad(r => { r.sessions.reverse(); r.bundle.sessionIds.reverse(); }, ':steps');
  await bad(r => { r.bundle.kind = 'AWS_PRIVATE_RESULT'; }, ':shape');
});

test('rows outside the window or the catalog fail the run', async () => {
  const old = run([{ time: '2026-08-01T00:00:00Z' }], [0]);
  await assert.rejects(verifyCloudflareBundle({ ...old, runtime: accept, now }), /:row/);
  const future = run([{ time: '2026-11-26T00:00:00Z' }], [0]);
  await assert.rejects(verifyCloudflareBundle({ ...future, runtime: accept, now }), /:row/);
  const other = run([{ product: 'dns', type: 'record' }], [0]);
  await assert.rejects(verifyCloudflareBundle({ ...other, runtime: accept, now }), /:row/);
});
