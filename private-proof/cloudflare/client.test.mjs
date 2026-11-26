import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createCloudflarePrivateClient } from './client.mjs';
import { requestBytes, responseBytes, identityBody, pageBody } from './session-fixture.mjs';
import { cloudflarePageRows } from './session.mjs';
import { verifyCloudflareBundle, verifyCloudflareFastBundle, cloudflareFastSource } from './verify-bundle.mjs';

const issuedAt = Date.now() - 1000;
const attempt = { proofId: randomUUID(), pluginSha256: 'c'.repeat(64), nonceMac: 'n'.repeat(43), issuedAt, expiresAt: issuedAt + 900000 };
const baseAttempt = attempt;
const today = new Date(issuedAt).toISOString().slice(0, 10);

// What the native verifier would do with a plan: commitments + openings, and the matching receipt.
function session(step, sent, recv, plan, attempt = baseAttempt) {
  const sessionId = randomUUID(), openings = { sent: [], recv: [] }, results = [];
  const visible = { sent: new Uint8Array(sent.length), recv: new Uint8Array(recv.length) };
  for (const [direction, bytes, ranges, type] of [['sent', sent, plan.sentRangesWithHandlers, 'SENT'], ['recv', recv, plan.recvRangesWithHandlers, 'RECV']]) {
    for (const r of ranges) {
      const slice = bytes.subarray(r.start, r.end);
      if (r.handler.action.kind === 'REVEAL') { visible[direction].set(slice, r.start); results.push({ type, part: r.handler.part, action: { kind: 'REVEAL' }, value: String.fromCharCode(...slice) }); continue; }
      const blinder = randomBytes(16), hash = createHash('sha256').update(slice).update(blinder).digest();
      openings[direction].push({ start: r.start, end: r.end, hash: new Uint8Array(hash), blinder: new Uint8Array(blinder) });
      results.push({ type, part: r.handler.part, action: { kind: 'HASH', algorithm: 'SHA256' }, value: hash.toString('hex') });
    }
  }
  const expected = { ...attempt, sessionId, step };
  const receipt = { session: { id: sessionId, proofId: attempt.proofId, pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac, step, method: 'CLOUDFLARE_ACCOUNT', mode: 'Proxy' },
    server_name: 'api.cloudflare.com', config: { sent: plan.sentRangesWithHandlers, recv: plan.recvRangesWithHandlers }, results,
    transcript: { sent: String.fromCharCode(...visible.sent), recv: String.fromCharCode(...visible.recv), sent_length: sent.length, recv_length: recv.length } };
  const witness = { sessionId, serverName: 'api.cloudflare.com', step, proofId: attempt.proofId, nonceMac: attempt.nonceMac, sent, recv,
    selections: { sent: plan.sentRangesWithHandlers, recv: plan.recvRangesWithHandlers }, openings };
  return { witness, receipt, expected };
}

// A fake worker: echoes the public inputs the circuit would expose.
const echo = async (circuitId, inputs) => {
  const flat = v => Array.isArray(v) ? v.flatMap(flat) : [v];
  const publicInputs = circuitId === 'cf-actor-v1'
    ? [...inputs.identity_hash, inputs.identity_length, ...flat(inputs.hashes), ...inputs.lengths]
    : 'preimage' in inputs ? [...(inputs.commitment ?? inputs.hash), inputs.length, ...(inputs.kind === undefined ? [] : [inputs.kind])]
      : [...flat(inputs.hashes), ...inputs.lengths, ...(inputs.kinds ?? [])];
  return { circuitId, proof: 'AAAA', publicInputs: publicInputs.map(String) };
};

test('client: plans from the received bytes, proves every target, and the bundle verifies', async () => {
  const client = createCloudflarePrivateClient({ attempt, proveCircuit: echo });
  const time = `${today}T00:00:01.000Z`;
  const rows = [{ time }, { time, actorId: 'f'.repeat(32) }, { time, product: 'queues', type: null }];
  const body = pageBody(rows), starts = cloudflarePageRows(body).map(r => r.start);
  const pageRecv = responseBytes(body, [starts[1], starts[2] - starts[1]]);
  const sessions = [];
  for (const [step, sent, recv] of [['identity', requestBytes('identity'), responseBytes(identityBody())], ['P0', requestBytes('page'), pageRecv]]) {
    const meta = { sessionId: randomUUID(), serverName: 'api.cloudflare.com', step, proofId: attempt.proofId, nonceMac: attempt.nonceMac };
    const plan = client.getRevealPlan(meta, { sent, recv });
    sessions.push(session(step, sent, recv, plan));
  }
  const bundle = await client.prove(sessions.map(s => s.witness), new AbortController().signal);
  const out = await verifyCloudflareBundle({ sessions: sessions.map(({ receipt, expected }) => ({ receipt, expected })), bundle, runtime: { verify: async () => true } });
  // The other actor's row is not proven.
  assert.deepEqual(out.observations.map(o => o.group), ['d1', 'queues']);
});

test('client: refuses a page before the identity, other proof ids, and reuse', async () => {
  const client = createCloudflarePrivateClient({ attempt, proveCircuit: echo });
  const meta = step => ({ sessionId: randomUUID(), serverName: 'api.cloudflare.com', step, proofId: attempt.proofId, nonceMac: attempt.nonceMac });
  assert.throws(() => client.getRevealPlan(meta('P0'), { sent: requestBytes('page'), recv: responseBytes(pageBody([{}])) }), /CF_PRIVATE_CLIENT_INVALID/);
  assert.throws(() => client.getRevealPlan({ ...meta('identity'), proofId: randomUUID() }, { sent: requestBytes('identity'), recv: responseBytes(identityBody()) }), /CF_PRIVATE_CLIENT_INVALID/);
  await assert.rejects(client.prove([], new AbortController().signal), /CF_PRIVATE_CLIENT_INVALID/);
  await assert.rejects(client.prove([], new AbortController().signal), /CF_PRIVATE_CLIENT_INVALID/);
});

// A full run on this browser, then a fast check on a new attempt: identity only, bound to the recorded id.
async function fullRun(saveLink) {
  const client = createCloudflarePrivateClient({ attempt, proveCircuit: echo, saveLink });
  const body = pageBody([{ time: `${today}T00:00:01.000Z` }]);
  const sessions = [];
  for (const [step, sent, recv] of [['identity', requestBytes('identity'), responseBytes(identityBody())], ['P0', requestBytes('page'), responseBytes(body)]]) {
    const meta = { sessionId: randomUUID(), serverName: 'api.cloudflare.com', step, proofId: attempt.proofId, nonceMac: attempt.nonceMac };
    sessions.push(session(step, sent, recv, client.getRevealPlan(meta, { sent, recv })));
  }
  const bundle = await client.prove(sessions.map(s => s.witness), new AbortController().signal);
  return { sessions: sessions.map(({ receipt, expected }) => ({ receipt, expected })), bundle, policy: { issuedAt: attempt.issuedAt, expiresAt: attempt.expiresAt } };
}
async function fastRun(recording, linkSecret) {
  const now = Date.now() - 500;
  const live = { ...attempt, proofId: randomUUID(), issuedAt: now, expiresAt: now + 900000 };
  const client = createCloudflarePrivateClient({ attempt: live, proveCircuit: echo, fastSource: cloudflareFastSource(recording), linkSecret });
  const meta = { sessionId: randomUUID(), serverName: 'api.cloudflare.com', step: 'identity', proofId: live.proofId, nonceMac: live.nonceMac };
  const sent = requestBytes('identity'), recv = responseBytes(identityBody());
  assert.throws(() => client.getRevealPlan({ ...meta, step: 'P0' }, { sent: requestBytes('page'), recv: responseBytes(pageBody([{}])) }), /CF_PRIVATE_CLIENT_INVALID/);
  const one = session('identity', sent, recv, client.getRevealPlan(meta, { sent, recv }), live);
  const bundle = await client.prove([one.witness], new AbortController().signal);
  return { sessions: [{ receipt: one.receipt, expected: one.expected }], bundle };
}

test('fast check: a full run saves the id blinder; a fast run proves the same user and the recording verifies', async () => {
  let saved;
  const recording = await fullRun((binding, secret) => { saved = { binding, secret: new Uint8Array(secret) }; });
  assert.equal(saved.secret.length, 16);
  assert.equal(saved.binding, cloudflareFastSource(recording).identityHash);
  const live = await fastRun(recording, new Uint8Array(saved.secret));
  assert.equal(live.bundle.sessionIds.length, 1);
  assert.equal(live.bundle.proofs.at(-1).circuitId, 'cf-identity-refresh-v1');
  const out = await verifyCloudflareFastBundle({ ...live, runtime: { verify: async () => true }, recording });
  assert.deepEqual(out.observations.map(o => o.group), ['d1']);
  // The fast bundle alone is not a full result, and a full verifier refuses it.
  await assert.rejects(verifyCloudflareBundle({ ...live, runtime: { verify: async () => true } }), /CF_PRIVATE_BUNDLE_INVALID/);
});

test('fast check: another saved blinder (another run or user) is refused before proving', async () => {
  const recording = await fullRun(() => {});
  await assert.rejects(fastRun(recording, new Uint8Array(16).fill(7)), /CF_PRIVATE_CLIENT_INVALID/);
  assert.throws(() => createCloudflarePrivateClient({ attempt, proveCircuit: echo, fastSource: cloudflareFastSource(recording) }), /CF_PRIVATE_CLIENT_INVALID/);
});
