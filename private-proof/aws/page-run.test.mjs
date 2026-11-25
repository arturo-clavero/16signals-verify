import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createAwsPrivateClient } from './client.mjs';
import { awsFastSource, verifyAwsBundle, verifyAwsFastBundle } from './verify-bundle.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { fixtureExpected, fixtureNow, syntheticWitness } from './event-fixture.mjs';
import { pageSessionFixture, pageWitness } from './page-fixture.mjs';
import { pageActivity as activity, pageRun } from './page-run-fixture.mjs';
import { loadAwsArtifacts } from './artifact-registry.mjs';
import { awsToolClass } from './tool-class.mjs';
import { awsCatalogOperation } from './skill-groups.mjs';

// A synthetic run end to end without AWS or real proofs (page-run-fixture.mjs) with an ABI-derived proof double, then
// the bundle verifier. page-path-check.mjs runs the same with real proofs.
const artifacts = await loadAwsArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
/** ABI-derived public fields; batch outputs are the userAgent classes. Not a cryptographic proof. */
async function proveCircuit(id, inputs) {
  const abi = artifacts[id].abi;
  const values = abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity));
  if (id.startsWith('aws-event-batch')) {
    for (const [row, body] of inputs.row_body.entries()) {
      values.push(awsToolClass(`"${Buffer.from(body.slice(2, inputs.ua_lengths[row] - 2)).toString()}"`));
    }
  } else if (abi.return_type) values.push(1);
  return { circuitId: id, proof: 'AA==', publicInputs: values.map(String) };
}

const runtime = { verify: async () => true };

test('25 proven rows over several groups and days: discovery to bundle verification', async () => {
  const events = activity(), started = performance.now();
  const { steps, rows, bundle, sessions, pages } = await pageRun(events, proveCircuit);
  const result = await verifyAwsBundle({ sessions, bundle, runtime, now: fixtureNow });
  const groups = new Set(result.observations.map(o => o.group)), days = new Set(result.observations.map(o => o.day));
  assert.equal(steps.slice(0, sessions.length).join(), ['identity', 'P0', 'P1', 'P2', 'P3', 'P4'].slice(0, sessions.length).join());
  assert.equal(result.observations.length, Object.values(rows).flat().length);
  assert.ok(result.observations.length >= 25, String(result.observations.length));
  assert.ok(groups.size >= 8 && days.size >= 3, `${groups.size} groups, ${days.size} days`);
  assert.ok(result.observations.every(o => ['terraform', 'cli', 'console'].includes(o.tool)));
  // Nothing private reaches the verifier: account, user, resource names, bucket host, userAgent text, time of day.
  const seen = JSON.stringify({ sessions, bundle });
  for (const secret of ['111122223333', 'AIDAEXAMPLESYNTHETIC01', 'AWS_PRIVATE_USER_SENTINEL', 'synthetic-resource', 'private-bucket', 'aws-cli/']) {
    assert.ok(!seen.includes(secret), secret);
  }
  assert.doesNotMatch(pages.map(page => page.receipt.transcript.recv).join(), /T\d\d:\d\d:\d\dZ/);
  console.log(JSON.stringify({ synthetic: true, observations: result.observations.length, groups: groups.size, days: days.size,
    sessions: sessions.length - 1, proofs: bundle.proofs.length, batchProofs: bundle.proofs.filter(p => p.circuitId.startsWith('aws-event-batch')).length,
    planAndVerifyMs: Math.round(performance.now() - started) }));
});

test('the attempt\'s job groups weigh the selection: more rows of the named group, its session proven first', async () => {
  const events = activity(), byId = new Map(events.map(event => [event.eventID, event]));
  const groupsOf = rows => Object.fromEntries(Object.entries(rows).map(([step, ids]) =>
    [step, ids.map(id => awsCatalogOperation(byId.get(id).eventSource, byId.get(id).eventName).group)]));
  const count = (groups, id) => Object.values(groups).flat().filter(group => group === id).length;
  const plain = groupsOf((await pageRun(events, proveCircuit)).rows);
  const { rows, bundle, sessions } = await pageRun(events, proveCircuit, () => {}, { jobGroups: ['ecr', 'not-a-group'] });
  const named = groupsOf(rows);
  assert.ok(count(named, 'ecr') > count(plain, 'ecr'), `${count(named, 'ecr')} vs ${count(plain, 'ecr')}`);
  assert.ok(named.P0.includes('ecr') && !plain.P0.includes('ecr'));
  // Weight only: every group the plain run proves is still proven, and the bundle verifies the same way.
  assert.deepEqual([...new Set(Object.values(named).flat())].sort(), [...new Set(Object.values(plain).flat())].sort());
  assert.ok((await verifyAwsBundle({ sessions, bundle, runtime, now: fixtureNow })).observations.length >= 25);
});

const windowOf = page => { const request = JSON.parse(page.plaintext.sent.toString().split('\r\n\r\n')[1]); return { start: request.StartTime, end: request.EndTime }; };
const within = (events, { start, end: stop }) => events.filter(event => { const t = Date.parse(event.eventTime) / 1000; return t >= start && t <= stop; });
/** Proof entries straight from the verifier's own targets (outputs set to 1): only the session rules can fail. */
async function targetBundle(sessions) {
  const { inspectAwsIdentitySession } = await import('./identity-structure.mjs');
  const { inspectAwsPageSession } = await import('./page-session.mjs');
  const { assembleAwsPageExpectations } = await import('./verify-bundle.mjs');
  const { pageClaims } = await import('./page-fixture.mjs');
  const identity = inspectAwsIdentitySession(sessions[0].receipt, sessions[0].expected, fixtureNow);
  const length = identity.bindings.UserName.end - identity.bindings.UserName.start;
  const pages = sessions.slice(1).map(session => inspectAwsPageSession(session.receipt, session.expected, pageClaims(session), length, fixtureNow));
  return { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: sessions.map(session => session.expected.sessionId),
    proofs: assembleAwsPageExpectations(identity, pages, sessions[0].expected.issuedAt).map(target => ({ circuitId: target.circuitId,
      proof: 'AA==', publicInputs: target.publicInputs.map(value => (value === null ? '1' : String(value))) })) };
}

test('rejects overlapping windows, a missing proof and a row counted twice', async () => {
  const events = activity();
  const { bundle, sessions, pages, rows } = await pageRun(events, proveCircuit);
  const fewer = structuredClone(bundle); fewer.proofs.splice(0, 1);
  await assert.rejects(verifyAwsBundle({ sessions, bundle: fewer, runtime, now: fixtureNow }), { message: 'AWS_PRIVATE_BUNDLE_INVALID' });
  assert.equal((await verifyAwsBundle({ sessions, bundle: await targetBundle(sessions), runtime, now: fixtureNow })).observations.length,
    Object.values(rows).flat().length);
  // The first window proven again as another session would count its rows twice: client and verifier refuse it.
  const again = pageSessionFixture({ step: 'P1', sessionId: '33333333-3333-4333-8333-333333333339', events: within(events, windowOf(pages[0])),
    ...windowOf(pages[0]), select: rows.P0 });
  const twice = [sessions[0], sessions[1], { receipt: again.receipt, expected: again.expected }];
  await assert.rejects(verifyAwsBundle({ sessions: twice, bundle: await targetBundle(twice), runtime, now: fixtureNow }), { message: 'AWS_PRIVATE_BUNDLE_INVALID' });
  const client = createAwsPrivateClient({ attempt: { ...fixtureExpected }, now: () => fixtureNow, proveCircuit, crypto: webcrypto });
  client.selectPages({ P0: rows.P0, P1: rows.P0 });
  await assert.rejects(client.prove([syntheticWitness(identityFixture()), pageWitness(pages[0]), pageWitness(again)], new AbortController().signal),
    { message: 'AWS_PRIVATE_CLIENT_INVALID' });
});

test('Fast replay of a page run: fresh IAM identity, the recorded observations re-verified, wrong links refused', async () => {
  let secret;
  const { bundle, sessions } = await pageRun(activity(), proveCircuit, () => {}, {}, { saveLink: (_, value) => { secret = new Uint8Array(value); } });
  const recording = { policy: { ...sessions[0].expected }, sessions, bundle };
  const fastSource = awsFastSource(recording);
  assert.ok(bundle.proofs[0].circuitId.startsWith('aws-event-batch'));
  const fresh = identityFixture({ blinderSeed: 'fresh' }), old = sessions[0].expected.nonceMac;
  fresh.expected.sessionId = fresh.receipt.session.id = '99999999-9999-4999-8999-999999999999';
  fresh.expected.nonceMac = fresh.receipt.session.nonceMac = 'B'.repeat(43);
  fresh.receipt.transcript.sent = fresh.receipt.transcript.sent.replace(old, fresh.expected.nonceMac);
  for (const item of fresh.receipt.results) if (item.action.kind === 'REVEAL') item.value = item.value.replace(old, fresh.expected.nonceMac);
  const make = (linkSecret = new Uint8Array(secret)) => createAwsPrivateClient({ attempt: fresh.expected, now: () => fixtureNow, proveCircuit,
    crypto: webcrypto, fastSource, linkSecret });
  const live = await make().prove([syntheticWitness(fresh)], new AbortController().signal);
  assert.equal(live.proofs[0].circuitId, 'aws-identity-refresh-v1'); assert.equal(live.sessionIds.length, 1);
  const freshSessions = [{ receipt: fresh.receipt, expected: fresh.expected }];
  const replayed = await verifyAwsFastBundle({ sessions: freshSessions, bundle: live, runtime, recording, now: fixtureNow });
  assert.deepEqual(replayed, await verifyAwsBundle({ sessions, bundle, runtime, now: fixtureNow }));
  assert.ok(replayed.observations.length >= 25);
  await assert.rejects(make(new Uint8Array(16)).prove([syntheticWitness(fresh)], new AbortController().signal));
  // Another recorded UserId commitment than the one the fresh proof opened is refused.
  const other = structuredClone(recording); other.bundle.proofs[0].publicInputs[0] = String((Number(other.bundle.proofs[0].publicInputs[0]) + 1) % 256);
  await assert.rejects(verifyAwsFastBundle({ sessions: freshSessions, bundle: live, runtime, recording: other, now: fixtureNow }));
  assert.throws(() => awsFastSource({ ...recording, bundle: { ...bundle, proofs: [bundle.proofs.at(-1), ...bundle.proofs.slice(1)] } }));
});
