// Synthetic check of one event run at another event-session cap: `node --experimental-test-module-mocks
// sessions-cap-check.mjs <cap>` (run by sessions.test.mjs). It swaps in that cap and, when the catalog has fewer skill
// areas, IAM-shaped synthetic operations in new areas; then runs the client planner and prover (an ABI-derived proof
// double, as in client.test.mjs) and the bundle verifier end to end. No AWS, no real proofs.
import assert from 'node:assert/strict';
import { mock } from 'node:test';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { awsToolClass } from './tool-class.mjs';

const cap = Number(process.argv[2]);
const real = await import('./operation-catalog.mjs?real'), steps = await import('./sessions.mjs?real');
const iam = real.AWS_OPERATIONS[0];
// Areas that only skill groups roll up to have no operation to select.
const realAreas = real.AWS_SKILL_AREAS.filter(area => real.AWS_OPERATIONS.some(entry => entry.skillArea === area.id));
const synthetic = Array.from({ length: Math.max(0, cap - realAreas.length) }, (_, index) => ({
  ...structuredClone(iam), id: `synthetic-operation-${index}`, skillArea: `synthetic-${index}`, eventNames: [`SyntheticOperation${index}`] }));
const operations = [...real.AWS_OPERATIONS, ...synthetic];
mock.module(new URL('./operation-catalog.mjs', import.meta.url).href, { namedExports: { ...real,
  AWS_SKILL_AREAS: [...real.AWS_SKILL_AREAS, ...synthetic.map(entry => ({ id: entry.skillArea, label: entry.skillArea }))],
  AWS_OPERATIONS: operations,
  awsOperation: (source, name) => operations.find(entry => entry.eventSource === source && entry.eventNames.includes(name)) } });
mock.module(new URL('./sessions.mjs', import.meta.url).href, { namedExports: { ...steps,
  AWS_MAX_EVENT_SESSIONS: cap, AWS_SESSION_STEPS: steps.awsSessionSteps(cap), AWS_EVENT_STEPS: steps.awsSessionSteps(cap).slice(1) } });

const { createAwsPrivateClient } = await import('./client.mjs');
const { verifyAwsBundle } = await import('./verify-bundle.mjs');
const { groupedFixture } = await import('./grouped-fixture.mjs');
const { fixtureNow, syntheticWitness, OPERATION_FAMILIES } = await import('./event-fixture.mjs');
const { loadAwsArtifacts } = await import('./artifact-registry.mjs');

// Every operation of the (possibly extended) catalog. The first operation of each skill area, in area order, is
// what a run proves; the catalog may have more areas than the cap.
const families = operations.map(entry => OPERATION_FAMILIES[entry.id] ?? entry.eventNames[0]);
const areas = [...realAreas, ...synthetic.map(entry => ({ id: entry.skillArea }))].map(area => area.id);
const firsts = areas.map(area => operations.findIndex(entry => entry.skillArea === area));

// 1. Client and verifier: the selected areas as E0..E(cap-1).
const artifacts = await loadAwsArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
const proveCircuit = async (id, inputs) => {
  const abi = artifacts[id].abi;
  const values = abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity));
  if (abi.return_type) {
    const bytes = inputs.decoded_preimage ?? inputs.preimage, length = inputs.decoded_length ?? inputs.length;
    const text = Buffer.from(bytes.slice(0, length)).toString(), value = JSON.parse(text);
    values.push(id === 'aws-user-agent-class-v1' ? awsToolClass(text)
      : value === null ? 5 : value === false ? 4 : value === true ? 3 : typeof value === 'number' ? 2 : 1);
  }
  return { circuitId: id, proof: 'AA==', publicInputs: values.map(String) };
};
async function run(list) {
  const fixtures = groupedFixture(list);
  const client = createAwsPrivateClient({ attempt: { ...fixtures[0].expected }, now: () => fixtureNow, proveCircuit, crypto: webcrypto });
  const bundle = await client.prove(fixtures.map(syntheticWitness), new AbortController().signal);
  return { sessions: fixtures.map(({ receipt, expected }) => ({ receipt, expected })), bundle };
}
const selected = firsts.slice(0, cap);
const { sessions, bundle } = await run(selected.map(index => families[index]));
const runtime = { verify: async () => true };
const accepted = await verifyAwsBundle({ sessions, bundle, runtime, now: fixtureNow });
assert.deepEqual(accepted.activities, operations.filter((_, index) => selected.includes(index)).map(entry => entry.id));

// 2. Adversarial at this cap: a repeated area, an out-of-order step and one session past the cap.
const reject = value => assert.rejects(verifyAwsBundle({ runtime, now: fixtureNow, ...value }), /AWS_PRIVATE_BUNDLE_INVALID/);
await reject(await run([...selected.slice(0, cap - 1).map(index => families[index]), families[0]]));
await reject({ sessions: [sessions[0], ...sessions.slice(1).reverse()], bundle: { ...bundle, sessionIds: [bundle.sessionIds[0], ...bundle.sessionIds.slice(1).reverse()] } });
const extraId = '44444444-4444-4444-8444-444444444444';
await reject({ sessions: [...sessions, { ...sessions[1], expected: { ...sessions[1].expected, sessionId: extraId, step: `E${cap}` } }],
  bundle: { ...bundle, sessionIds: [...bundle.sessionIds, extraId] } });
console.log(JSON.stringify({ cap, eventSessions: accepted.activities.length, proofs: bundle.proofs.length,
  bundleBytes: JSON.stringify(bundle).length }));
