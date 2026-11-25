// Synthetic check of one run at another event-session cap: `node --experimental-test-module-mocks
// sessions-cap-check.mjs <cap>` (run by sessions.test.mjs). It swaps in that cap and, when the catalog has fewer skill
// areas, IAM-shaped synthetic operations in new areas; then runs local discovery, the client planner and prover
// (an ABI-derived proof double, as in client.test.mjs) and the bundle verifier end to end. No AWS, no real proofs.
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

const { createAwsLocalSession } = await import('./browser-session.mjs');
const { createAwsPrivateClient } = await import('./client.mjs');
const { verifyAwsBundle } = await import('./verify-bundle.mjs');
const { groupedFixture } = await import('./grouped-fixture.mjs');
const { identityFixture } = await import('./identity-fixture.mjs');
const { eventFixture, activityEventFixture, fixtureNow, syntheticWitness, ACTIVITY_EVENTS, OPERATION_FAMILIES } = await import('./event-fixture.mjs');
const { loadAwsArtifacts } = await import('./artifact-registry.mjs');

// Every operation of the (possibly extended) catalog. The first operation of each skill area, in area order, is
// what a run selects; the catalog may have more areas than the cap.
const families = operations.map(entry => OPERATION_FAMILIES[entry.id] ?? entry.eventNames[0]);
const ids = families.map((_, index) => `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa${String(index).padStart(2, '0')}`);
const areas = [...realAreas, ...synthetic.map(entry => ({ id: entry.skillArea }))].map(area => area.id);
const firsts = areas.map(area => operations.findIndex(entry => entry.skillArea === area));

// 1. Discovery: one page in reverse catalog order (later operations of an area first) selects the first operation of
// each area, areas in catalog order, up to the cap.
const now = Date.UTC(2026, 9, 29, 8, 0, 0);
const body = fixture => new TextDecoder().decode(syntheticWitness(fixture).recv).split('\r\n\r\n')[1];
const row = (family, eventId) => JSON.parse(body(family === 'iam' ? eventFixture({ eventId }) :
  Object.hasOwn(ACTIVITY_EVENTS, family) ? activityEventFixture(family, { eventId }) :
    eventFixture({ eventId, mutateEvent: event => { event.eventName = family; }, mutateRow: value => { value.EventName = family; } }))).Events[0];
const identity = body(identityFixture({ fields: { Path: '/', UserName: 'synthetic', Arn: 'arn:aws:iam::111122223333:user/synthetic' } }));
const page = JSON.stringify({ Events: families.map((family, index) => row(family, ids[index])).reverse() });
const local = createAwsLocalSession({ pages: false, now: () => now, attempt: { proofId: '22222222-2222-4222-8222-222222222222', pluginSha256: 'a'.repeat(64),
  nonceMac: 'n'.repeat(43), identityService: 'iam', region: 'us-east-1', issuedAt: now, expiresAt: now + 300000 },
fetchAws: async url => new Response(url === 'https://iam.amazonaws.com/' ? identity : page) });
const requests = await local.prepare({ credentials: { accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
  sessionToken: 't'.repeat(100), expiration: new Date(now + 3600000).toISOString() }, accountId: '111122223333' });
assert.deepEqual(requests.slice(1).map(request => JSON.parse(request.body).LookupAttributes[0].AttributeValue), firsts.slice(0, cap).map(index => ids[index]));

// 2. Client and verifier: the selected areas as E0..E(cap-1).
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

// 3. Adversarial at this cap: a repeated area, an out-of-order step and one session past the cap.
const reject = value => assert.rejects(verifyAwsBundle({ runtime, now: fixtureNow, ...value }), /AWS_PRIVATE_BUNDLE_INVALID/);
await reject(await run([...selected.slice(0, cap - 1).map(index => families[index]), families[0]]));
await reject({ sessions: [sessions[0], ...sessions.slice(1).reverse()], bundle: { ...bundle, sessionIds: [bundle.sessionIds[0], ...bundle.sessionIds.slice(1).reverse()] } });
const extraId = '44444444-4444-4444-8444-444444444444';
await reject({ sessions: [...sessions, { ...sessions[1], expected: { ...sessions[1].expected, sessionId: extraId, step: `E${cap}` } }],
  bundle: { ...bundle, sessionIds: [...bundle.sessionIds, extraId] } });
console.log(JSON.stringify({ cap, eventSessions: accepted.activities.length, proofs: bundle.proofs.length,
  bundleBytes: JSON.stringify(bundle).length }));
