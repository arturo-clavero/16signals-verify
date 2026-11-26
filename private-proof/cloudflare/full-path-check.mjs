// Real proofs end to end in Node on synthetic sessions: plan -> receipts -> targets -> prove every target -> verify the
// bundle with the pinned keys. Prints timings per circuit. Heavy: run alone (flock /tmp/16s-heavy.lock).
// Usage: node private-proof/cloudflare/full-path-check.mjs [rows=3] [threads=4]
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { planCloudflareSession, cloudflarePageRows, inspectCloudflareSession } from './session.mjs';
import { requestBytes, responseBytes, identityBody, pageBody } from './session-fixture.mjs';
import { receiptFor } from './receipt-fixture.mjs';
import { authenticatedCloudflareTranscript, cloudflareTargets, verifyCloudflareBundle, verifyCloudflareFastBundle, cloudflareFastSource } from './verify-bundle.mjs';
import { cloudflareCircuitInputs } from './circuit-inputs.mjs';
import { loadCloudflareArtifacts, loadCloudflareVerificationKeys } from './artifact-registry.mjs';
import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { pinnedCloudflareKey } from './artifact-registry.mjs';

const rowCount = Number(process.argv[2] ?? 3), threads = Number(process.argv[3] ?? 4);
const load = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)).then(b => new Uint8Array(b));
const artifacts = await loadCloudflareArtifacts(load), keys = await loadCloudflareVerificationKeys(load);
const ids = Object.keys(artifacts);
const factory = t => proofRuntimeFactory({ ids, invalidCode: 'CF_PRIVATE_PROOF_INVALID', provingCode: 'CF_PRIVATE_PROVING_FAILED', keyForCircuit: pinnedCloudflareKey, threads: t });

const issuedAt = Date.parse('2026-11-25T08:00:00Z'), now = issuedAt + 60000;
const base = { proofId: randomUUID(), pluginSha256: 'c'.repeat(64), nonceMac: 'n'.repeat(43), issuedAt, expiresAt: issuedAt + 900000 };
const kinds = [{}, { product: 'queues', type: null }, { product: 'workers', type: 'scripts', action: 'update', request: { script: 'x'.repeat(600) } },
  { product: 'storage', type: 'kv.namespaces', action: 'create', context: 'dash' }, { product: 'vectorize', type: 'indexes' }];
const rows = Array.from({ length: rowCount }, (_, i) => kinds[i % kinds.length]);
const sessions = [], openings = new Map();
const add = (step, sent, recv, select, into = sessions, attempt = base) => {
  const plan = planCloudflareSession(step, sent, recv, select), expected = { ...attempt, sessionId: randomUUID(), step };
  const r = receiptFor({ sent, recv, plan, expected });
  for (const [hash, o] of r.openings) { const pre = new Uint8Array(o.bytes.length + 16); pre.set(o.bytes); pre.set(o.blinder, o.bytes.length); openings.set(hash, pre); }
  into.push({ receipt: r.receipt, expected });
};
add('identity', requestBytes('identity'), responseBytes(identityBody()));
const body = pageBody(rows), starts = cloudflarePageRows(body).map(r => r.start);
add('P0', requestBytes('page'), responseBytes(body, starts.slice(1).map((s, i) => s - (i ? starts[i] : 0))), rows.map((_, i) => i));
const results = sessions.map(s => inspectCloudflareSession(authenticatedCloudflareTranscript(s.receipt, s.expected, now), s.expected.step));
const targets = cloudflareTargets(results[0], results.slice(1));
console.log(JSON.stringify({ rows: rowCount, targets: targets.length, byCircuit: targets.reduce((m, t) => ({ ...m, [t.circuitId]: (m[t.circuitId] ?? 0) + 1 }), {}) }));

const prover = await factory(threads)(artifacts, keys);
const proofs = [], times = {};
const started = performance.now();
try {
  for (const target of targets) {
    const t0 = performance.now();
    proofs.push(await prover.prove(target.circuitId, cloudflareCircuitInputs(target, openings)));
    (times[target.circuitId] ??= []).push(Math.round(performance.now() - t0));
  }
} finally { await prover.close(); }
const proveMs = Math.round(performance.now() - started);
const verifier = await factory(1)(artifacts, keys);
const bundle = { kind: 'CLOUDFLARE_PRIVATE_RESULT', version: 1, sessionIds: sessions.map(s => s.expected.sessionId), proofs };
const v0 = performance.now();
try {
  const out = await verifyCloudflareBundle({ sessions, bundle, runtime: verifier, now });
  console.log(JSON.stringify({ ok: true, observations: out.observations.length, groups: [...new Set(out.observations.map(o => o.group))],
    proveMs, verifyMs: Math.round(performance.now() - v0), bundleBytes: JSON.stringify(bundle).length,
    msPerCircuit: Object.fromEntries(Object.entries(times).map(([k, v]) => [k, Math.round(v.reduce((a, b) => a + b, 0) / v.length)])) }));
  // A tampered proof must fail.
  const forged = structuredClone(bundle); forged.proofs[0].proof = forged.proofs[1].proof;
  await verifyCloudflareBundle({ sessions, bundle: forged, runtime: verifier, now }).then(() => console.log('FORGED ACCEPTED'), e => console.log('forged refused:', e.message));
  // Fast check: a new attempt proves only a fresh identity session, bound to the recorded run's id. The recorded
  // opening (same id, the first run's blinder) is what the extension rebuilds from its saved link.
  const recording = { sessions, bundle, policy: { issuedAt: base.issuedAt, expiresAt: base.expiresAt } };
  const fastAttempt = { ...base, proofId: randomUUID() }, fastSessions = [];
  add('identity', requestBytes('identity'), responseBytes(identityBody()), undefined, fastSessions, fastAttempt);
  const fresh = inspectCloudflareSession(authenticatedCloudflareTranscript(fastSessions[0].receipt, fastSessions[0].expected, now), 'identity');
  const fastTargets = cloudflareTargets(fresh, [], cloudflareFastSource(recording));
  const fastProver = await factory(threads)(artifacts, keys), fastProofs = [];
  const f0 = performance.now();
  try { for (const target of fastTargets) fastProofs.push(await fastProver.prove(target.circuitId, cloudflareCircuitInputs(target, openings))); }
  finally { await fastProver.close(); }
  const fastBundle = { kind: 'CLOUDFLARE_PRIVATE_RESULT', version: 1, sessionIds: [fastSessions[0].expected.sessionId], proofs: fastProofs };
  const fast = await verifyCloudflareFastBundle({ sessions: fastSessions, bundle: fastBundle, runtime: verifier, now, recording });
  console.log(JSON.stringify({ fastOk: true, fastTargets: fastTargets.map(t => t.circuitId), fastProveMs: Math.round(performance.now() - f0), observations: fast.observations.length }));
} finally { await verifier.close(); }
