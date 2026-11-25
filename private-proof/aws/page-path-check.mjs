// Synthetic page run with real proofs: `node page-path-check.mjs` after build-artifacts.mjs. Heavy (one
// 2^20 batch proof peaks at about 3.5 GB): run alone, under the shared lock. Proofs are made one at a time.
// No AWS, no TLS: receipts are native-shaped fixtures, so this measures planning, proving and verification only.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadAwsArtifacts, loadAwsVerificationKeys } from './artifact-registry.mjs';
import { createAwsProofRuntime } from './proof-runtime.mjs';
import { verifyAwsBundle } from './verify-bundle.mjs';
import { fixtureNow } from './event-fixture.mjs';
import { pageActivity, pageRun } from './page-run-fixture.mjs';

const read = file => readFileSync(new URL(`./dist/artifacts/${file}`, import.meta.url));
const artifacts = await loadAwsArtifacts(read), keys = await loadAwsVerificationKeys(read);
const prover = await createAwsProofRuntime(artifacts, keys, { forProving: true });
const measurements = [];
const started = performance.now();
let run;
try {
  run = await pageRun(pageActivity(), async (circuitId, inputs) => {
    const began = performance.now(), proof = await prover.prove(circuitId, inputs);
    measurements.push({ circuitId, ms: Math.round(performance.now() - began) });
    console.log(JSON.stringify({ phase: 'proved', ...measurements.at(-1), completed: measurements.length }));
    return proof;
  });
} finally { await prover.close(); }
const provedMs = Math.round(performance.now() - started);
const verifier = await createAwsProofRuntime(artifacts, keys);
try {
  const began = performance.now();
  const result = await verifyAwsBundle({ sessions: run.sessions, bundle: run.bundle, runtime: verifier, now: fixtureNow });
  const verifyMs = Math.round(performance.now() - began);
  assert.ok(result.observations.length >= 25);
  // A changed proof or public input fails.
  const changed = structuredClone(run.bundle), batch = changed.proofs.find(proof => proof.circuitId.startsWith('aws-event-batch'));
  batch.publicInputs[0] = String((BigInt(batch.publicInputs[0]) + 1n) % 256n);
  await assert.rejects(verifyAwsBundle({ sessions: run.sessions, bundle: changed, runtime: verifier, now: fixtureNow }));
  const byCircuit = {};
  for (const { circuitId, ms } of measurements) (byCircuit[circuitId] ??= []).push(ms);
  console.log(JSON.stringify({ synthetic: true, observations: result.observations.length,
    groups: new Set(result.observations.map(o => o.group)).size, days: new Set(result.observations.map(o => o.day)).size,
    sessions: run.sessions.length - 1, proofs: run.bundle.proofs.length, provedMs, verifyMs,
    perCircuit: Object.fromEntries(Object.entries(byCircuit).map(([id, list]) => [id, { count: list.length, totalMs: list.reduce((a, b) => a + b, 0) }])),
    bundleBytes: JSON.stringify(run.bundle).length, peakRssKiB: process.resourceUsage().maxRSS }));
} finally { await verifier.close(); }
