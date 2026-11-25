import assert from 'node:assert/strict';
import test from 'node:test';
import { groupedFixture } from './grouped-fixture.mjs';
import { fixtureNow } from './event-fixture.mjs';
import { AWS_MAX_EVENT_SESSIONS } from './sessions.mjs';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { inspectAwsEventSession } from './event-structure.mjs';
import { assembleAwsBundleExpectations, verifyAwsBundle } from './verify-bundle.mjs';

function fixture(families, eventIds) {
  const fixtures = groupedFixture(families, eventIds), [identity, ...events] = fixtures;
  const targets = assembleAwsBundleExpectations(inspectAwsIdentitySession(identity.receipt, identity.expected, fixtureNow),
    events.map(event => inspectAwsEventSession(event.receipt, event.expected, event.claims, fixtureNow)), identity.expected.issuedAt);
  return { sessions: fixtures.map(({ receipt, expected }) => ({ receipt, expected })), now: fixtureNow,
    bundle: { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: fixtures.map(f => f.expected.sessionId),
      proofs: targets.map(({ circuitId, publicInputs }) => ({ circuitId, publicInputs: publicInputs.map(value => String(value ?? 0)), proof: 'AA==' })) },
    runtime: { verify: async () => true } };
}

test('groups only individually bound positive events; sparse collections make no absence claim', async () => {
  assert.deepEqual(await verifyAwsBundle(fixture()), { activities: ['iam-role-trust-update', 'lambda-configuration-update', 'security-group-ingress'],
    attribution: 'iam-user', windowDays: 90, tools: {} });
  assert.deepEqual(await verifyAwsBundle(fixture(['network'])), { activities: ['security-group-ingress'], attribution: 'iam-user', windowDays: 90, tools: {} });
});

test('does not count repeated-family events as additional breadth', async () => {
  await assert.rejects(verifyAwsBundle(fixture(['iam', 'iam'])), /AWS_PRIVATE_BUNDLE_INVALID/);
  await assert.rejects(verifyAwsBundle(fixture(['iam', 'iam'], Array(2).fill('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'))), /AWS_PRIVATE_BUNDLE_INVALID/);
});

test('accepts at most the session cap, in step order', async () => {
  // Synthetic sessions past the cap: the shape check refuses them before any receipt is read.
  const extra = fixture();
  while (extra.sessions.length <= AWS_MAX_EVENT_SESSIONS + 1) {
    const sessionId = `44444444-4444-4444-8444-44444444444${extra.sessions.length}`;
    extra.sessions.push({ ...extra.sessions[1], expected: { ...extra.sessions[1].expected, sessionId, step: `E${extra.sessions.length - 1}` } });
    extra.bundle.sessionIds.push(sessionId);
  }
  await assert.rejects(verifyAwsBundle(extra), /AWS_PRIVATE_BUNDLE_INVALID/);
  const swapped = fixture();
  [swapped.sessions[1], swapped.sessions[2]] = [swapped.sessions[2], swapped.sessions[1]];
  [swapped.bundle.sessionIds[1], swapped.bundle.sessionIds[2]] = [swapped.bundle.sessionIds[2], swapped.bundle.sessionIds[1]];
  await assert.rejects(verifyAwsBundle(swapped), /AWS_PRIVATE_BUNDLE_INVALID/);
});

test('each group requires its own native receipt, actor relation, cutoff and proof', async () => {
  for (const mutate of [
    value => { value.sessions.pop(); },
    value => { value.sessions[2].receipt = value.sessions[1].receipt; },
    value => { value.sessions[2].expected.step = 'E0'; },
    value => { value.sessions[3].expected.nonceMac = 'X'.repeat(43); },
    value => { value.bundle.proofs.splice(2, 1); },
    value => { value.bundle.proofs[3].publicInputs[128] = String(BigInt(value.bundle.proofs[3].publicInputs[128]) ^ 1n); },
    value => { value.bundle.proofs[7].publicInputs[198] = String(fixtureNow); },
    value => { value.runtime.verify = async proof => proof !== value.bundle.proofs[3]; },
  ]) {
    const value = fixture(); mutate(value);
    await assert.rejects(verifyAwsBundle(value), /AWS_PRIVATE_BUNDLE_INVALID/);
  }
});

test('each operation needs its actor and time-window relations to verify', async () => {
  for (const family of ['iam', 'lambda', 'network']) {
    assert.equal((await verifyAwsBundle(fixture([family]))).activities.length, 1);
    // A wrong actor cannot satisfy identity-link and an out-of-window event cannot satisfy event-link.
    for (const circuitId of ['aws-identity-link-v1', 'aws-event-link-v1']) {
      const value = fixture([family]);
      value.runtime.verify = async proof => proof.circuitId !== circuitId;
      await assert.rejects(verifyAwsBundle(value), /AWS_PRIVATE_BUNDLE_INVALID/);
    }
    const value = fixture([family]), link = value.bundle.proofs.find(proof => proof.circuitId === 'aws-event-link-v1');
    link.publicInputs[198] = String(fixtureNow - 365 * 86400_000);
    await assert.rejects(verifyAwsBundle(value), /AWS_PRIVATE_BUNDLE_INVALID/);
  }
});
