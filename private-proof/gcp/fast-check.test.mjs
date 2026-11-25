import test from 'node:test';
import assert from 'node:assert/strict';
import { createGcpPrivateClient } from './client-plan.mjs';
import { gcpFastSource, verifyBundle, verifyFastBundle } from './verify-bundle.mjs';
import { fixture, committed, policy, projectId, mockPublicInputs } from './client-fixture.mjs';

// Synthetic native-shaped receipts exercise binding; they do not establish TLS provenance.
function session(witness) {
  const expected = { sessionId: witness.sessionId, proofId: witness.proofId, pluginSha256: 'ab'.repeat(32), nonceMac: witness.nonceMac, step: witness.step };
  const receipt = { server_name: witness.serverName, session: { ...expected, id: expected.sessionId, method: 'GCP_WORK', mode: 'Proxy' },
    config: structuredClone(witness.selections), results: [], transcript: {} };
  delete receipt.session.sessionId;
  for (const direction of ['sent', 'recv']) {
    const visible = new Uint8Array(witness[direction].length);
    for (const range of witness.selections[direction]) {
      let value;
      if (range.handler.action.kind === 'HASH') value = Buffer.from(witness.openings[direction].find(slot => slot.start === range.start && slot.end === range.end).hash).toString('hex');
      else { const bytes = witness[direction].subarray(range.start, range.end); visible.set(bytes, range.start); value = new TextDecoder().decode(bytes); }
      receipt.results.push({ ...structuredClone(range.handler), value });
    }
    receipt.transcript[direction] = String.fromCharCode(...visible);
    receipt.transcript[direction + '_length'] = visible.length;
  }
  return { receipt, expected };
}
const proveCircuit = async (circuitId, inputs) => ({ circuitId, proof: 'YQ==', publicInputs: mockPublicInputs(circuitId, inputs) });
const runtime = { verify: async entry => entry.proof === 'YQ==' };
const bundle = (witnesses, result) => ({ kind: 'GCP_PRIVATE_RESULT', version: 1, sessionIds: witnesses.map(w => w.sessionId), ...result });

test('Fast rechecks saved activity and binds only a fresh identity; missing/wrong openings fail closed', async () => {
  let secret, binding;
  const old = fixture().map(raw => committed({ ...raw, proofId: '22222222-2222-4222-8222-222222222222' }));
  const full = createGcpPrivateClient({ projectId, policy, proveCircuit, saveLink: (key, value) => { binding = key; secret = new Uint8Array(value); } });
  full.identityEmail(old[0]);
  const recording = { policy, sessions: old.map(session), bundle: bundle(old, await full.prove(old, new AbortController().signal)) };
  const fastSource = gcpFastSource(recording); assert.equal(binding, fastSource.scopeHash);
  const raw = fixture()[0]; raw.proofId = '33333333-3333-4333-8333-333333333333'; raw.sessionId = '99999999-9999-4999-8999-999999999999';
  raw.nonceMac = 'B'.repeat(43); raw.sent = new TextEncoder().encode(new TextDecoder().decode(raw.sent).replace('A'.repeat(43), raw.nonceMac));
  const fresh = [committed(raw)], sessions = fresh.map(session);
  const client = createGcpPrivateClient({ projectId, policy, proveCircuit, fastSource, linkSecret: new Uint8Array(secret) });
  client.identityEmail(fresh[0]);
  const fast = bundle(fresh, await client.prove(fresh, new AbortController().signal));
  assert(fast.proofs.length < recording.bundle.proofs.length);
  assert(!fast.proofs.some(p => ['query-scope-v1', 'timestamps-v1'].includes(p.circuitId)));
  assert.deepEqual(await verifyFastBundle({ sessions, policy, bundle: fast, runtime, recording }), await verifyBundle({ ...recording, runtime }));
  await assert.rejects(verifyBundle({ sessions, policy, bundle: fast, runtime }));
  await assert.rejects(verifyFastBundle({ sessions, policy: { ...policy, windowDays: 30 }, bundle: fast, runtime, recording }));
  assert.throws(() => createGcpPrivateClient({ projectId, policy, proveCircuit, fastSource }));
  for (const settings of [{ projectId: 'wrong-project' }, { linkSecret: new Uint8Array(32) }]) {
    const wrong = createGcpPrivateClient({ projectId, policy, proveCircuit, fastSource, linkSecret: new Uint8Array(secret), ...settings });
    wrong.identityEmail(fresh[0]); await assert.rejects(wrong.prove(fresh, new AbortController().signal));
  }
  const otherRaw = { ...raw, recv: new TextEncoder().encode(new TextDecoder().decode(raw.recv).replace('12345', '67890')) };
  const otherIdentity = committed(otherRaw);
  const wrongAccount = createGcpPrivateClient({ projectId, policy, proveCircuit, fastSource, linkSecret: new Uint8Array(secret) });
  wrongAccount.identityEmail(otherIdentity); await assert.rejects(wrongAccount.prove([otherIdentity], new AbortController().signal));
  const other = structuredClone(recording); other.bundle.proofs[0].proof = 'Yg==';
  await assert.rejects(verifyFastBundle({ sessions, policy, bundle: fast, runtime, recording: other }));
  const changed = structuredClone(fast); changed.proofs[0].publicInputs[43] = String((Number(changed.proofs[0].publicInputs[43]) + 1) % 256);
  await assert.rejects(verifyFastBundle({ sessions, policy, bundle: changed, runtime, recording }));
});
