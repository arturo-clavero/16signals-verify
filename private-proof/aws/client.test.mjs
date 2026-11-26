import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { identityFixture } from './identity-fixture.mjs';
import { groupedFixture } from './grouped-fixture.mjs';
import { eventFixture, fixtureNow, syntheticWitness } from './event-fixture.mjs';
import { createAwsPrivateClient } from './client.mjs';
import { loadAwsArtifacts } from './artifact-registry.mjs';
import { verifyAwsBundle, verifyAwsFastBundle, awsFastSource } from './verify-bundle.mjs';
import { awsToolClass } from './tool-class.mjs';

const artifacts = await loadAwsArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
const error = { message: 'AWS_PRIVATE_CLIENT_INVALID' };
const flat = value => Array.isArray(value) ? value.flat(Infinity) : [value];
const zero = value => value && typeof value === 'object' ? Object.values(value).every(zero) : value === 0;
function fixture(options = {}, families, { eventIds, mutateRequest, userAgent } = {}) {
  let fixtures;
  if (families) fixtures = groupedFixture(families, eventIds);
  else {
    const event = eventFixture({ mutateRequest, mutateEvent: value => {
      value.userIdentity.arn = 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL';
      if (userAgent !== undefined) value.userAgent = userAgent;
    } });
    event.expected.sessionId = '33333333-3333-4333-8333-333333333333'; event.receipt.session.id = event.expected.sessionId;
    fixtures = [identityFixture(), event];
  }
  const [identity] = fixtures;
  const witnesses = fixtures.map(syntheticWitness), inputsHeld = [], randomHeld = [];
  const calls = [];
  // ABI-derived public fields with a controlled proof/verifier double, not cryptographic acceptance.
  const proveCircuit = async (id, inputs, signal) => {
    assert.equal(signal.aborted, false); inputsHeld.push(inputs); calls.push(id);
    const abi = artifacts[id].abi;
    assert.deepEqual(Object.keys(inputs).sort(), abi.parameters.map(p => p.name).sort());
    const values = abi.parameters.filter(p => p.visibility === 'public').flatMap(p => flat(inputs[p.name]));
    if (abi.return_type) {
      const bytes = inputs.decoded_preimage ?? inputs.preimage, length = inputs.decoded_length ?? inputs.length;
      const text = Buffer.from(bytes.slice(0, length)).toString(), value = JSON.parse(text);
      values.push(id === 'aws-user-agent-class-v1' ? awsToolClass(text)
        : value === null ? 5 : value === false ? 4 : value === true ? 3 : typeof value === 'number' ? 2 : 1);
    }
    return { circuitId: id, proof: 'AA==', publicInputs: values.map(String) };
  };
  const crypto = { subtle: webcrypto.subtle, getRandomValues: bytes => { randomHeld.push(bytes); return webcrypto.getRandomValues(bytes); } };
  const attempt = { ...identity.expected }, abort = new AbortController();
  const client = createAwsPrivateClient({ attempt, now: () => fixtureNow, proveCircuit, crypto, ...options });
  return { witnesses, client, abort, attempt, inputsHeld, randomHeld, calls, proveCircuit,
    sessions: fixtures.map(({ receipt, expected }) => ({ receipt, expected })) };
}
const prove = value => value.client.prove(value.witnesses, value.abort.signal);

test('matches native openings by range, builds a closed bundle, and erases owned inputs/blinders', async () => {
  const value = fixture();
  for (const witness of value.witnesses) {
    assert.deepEqual(value.client.getRevealPlan(witness, witness), {
      sentRangesWithHandlers: witness.selections.sent, recvRangesWithHandlers: witness.selections.recv });
    witness.openings.sent.reverse(); witness.openings.recv.reverse();
  }
  const bundle = await prove(value);
  assert.equal(bundle.proofs.length, 11);
  assert.deepEqual(await verifyAwsBundle({ sessions: value.sessions, bundle, runtime: { verify: async () => true }, now: fixtureNow }),
    { activities: ['iam-role-trust-update'], attribution: 'iam-user', windowDays: 90, tools: {} });
  assert.ok(value.inputsHeld.every(zero) && value.randomHeld.every(bytes => bytes.every(byte => byte === 0)));
  assert.doesNotMatch(JSON.stringify(bundle), /AWS_PRIVATE_[A-Z_]+_SENTINEL|111122223333|AIDAEXAMPLESYNTHETIC01|openings|witness|preimage/);
  await assert.rejects(prove(value), error);
  assert.throws(() => value.client.getRevealPlan(value.witnesses[0], value.witnesses[0]), error);
});

test('proves the tool class of each event without putting the userAgent in the bundle', async () => {
  for (const [userAgent, tools] of [
    ['APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 AWS_PRIVATE_AGENT_SENTINEL', { 'iam-role-trust-update': 'terraform' }],
    ['aws-cli/2.22.4 md/command#iam.update-assume-role-policy', { 'iam-role-trust-update': 'cli' }],
    ['[aws-cli/2.42.1 md/command#s3api.put-bucket-versioning]', { 'iam-role-trust-update': 'cli' }],
    ['curl/8.5.0 AWS_PRIVATE_AGENT_SENTINEL', {}],
  ]) {
    const value = fixture({}, undefined, { userAgent }), bundle = await prove(value);
    assert.equal(value.calls.filter(id => id === 'aws-user-agent-class-v1').length, 1);
    assert.deepEqual((await verifyAwsBundle({ sessions: value.sessions, bundle, runtime: { verify: async () => true }, now: fixtureNow })).tools, tools);
    assert.doesNotMatch(JSON.stringify(bundle), /AWS_PRIVATE_AGENT_SENTINEL|aws-cli|Terraform|curl/);
  }
});

test('grouped client binds every family, clears all owned inputs, and rejects a forged last witness before proving', async () => {
  const families = ['iam', 'lambda', 'network'], value = fixture({}, families);
  const bundle = await prove(value);
  assert.equal(bundle.sessionIds.length, 4);
  assert.deepEqual(await verifyAwsBundle({ sessions: value.sessions, bundle, runtime: { verify: async () => true }, now: fixtureNow }),
    { activities: ['iam-role-trust-update', 'lambda-configuration-update', 'security-group-ingress'], attribution: 'iam-user', windowDays: 90, tools: {} });
  assert.ok(value.inputsHeld.every(zero) && value.randomHeld.every(bytes => bytes.every(byte => byte === 0)));
  assert.doesNotMatch(JSON.stringify(bundle), /AWS_PRIVATE_[A-Z_]+_SENTINEL|111122223333|sg-0123456789abcdef0|192\.0\.2\.0|openings|witness|preimage/);
  const forged = fixture({}, families);
  forged.witnesses[3].openings.recv[0].hash[0] ^= 1;
  await assert.rejects(prove(forged), error);
  assert.equal(forged.calls.length, 0);
  assert.ok(forged.randomHeld.every(bytes => bytes.every(byte => byte === 0)));
});

test('an event session must return the event its request named, and no event twice, before any proof', async () => {
  const other = { mutateRequest: request => { request.LookupAttributes[0].AttributeValue = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'; } };
  const same = { eventIds: Array(2).fill('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') };
  for (const value of [fixture({}, undefined, other), fixture({}, ['iam', 'lambda'], same)]) {
    await assert.rejects(prove(value), error);
    assert.equal(value.calls.length, 0);
  }
  assert.equal((await prove(fixture({}, ['iam', 'lambda']))).sessionIds.length, 3);
});

test('rejects changed, duplicate, missing or relocated native openings before proving', async () => {
  for (const mutate of [w => { w.openings.recv[0].hash[0] ^= 1; }, w => { w.openings.recv[0].blinder[0] ^= 1; },
    w => { w.openings.recv[0].start++; }, w => { w.openings.recv.pop(); }, w => { w.openings.recv.push(w.openings.recv[0]); },
    w => { w.openings.recv[1] = w.openings.recv[0]; }, w => { w.openings.recv[0].extra = 'private'; },
    w => { w.recv[w.openings.recv[0].start] ^= 1; }]) {
    const value = fixture(); mutate(value.witnesses[1]); await assert.rejects(prove(value), error); assert.equal(value.calls.length, 0);
    assert.ok(value.randomHeld.every(bytes => bytes.every(byte => byte === 0)));
  }
});

test('rejects disclosure-plan substitutions, extra handlers and transcript changes', async () => {
  for (const mutate of [w => { w.selections.recv[0].end++; }, w => { w.selections.recv.pop(); },
    w => { w.selections.recv.reverse(); }, w => { w.selections.recv.find(r => r.handler.action.kind === 'HASH').handler.action.kind = 'REVEAL'; },
    w => { w.selections.sent[0].handler.part = 'ALL'; }, w => { w.selections.sent[0].handler.params = {}; }]) {
    const value = fixture(); mutate(value.witnesses[1]); await assert.rejects(prove(value), error); assert.equal(value.calls.length, 0);
  }
});

test('binds witness order, unique sessions, attempt, nonce, host and lifetime', async () => {
  for (const mutate of [v => v.witnesses.reverse(), v => { v.witnesses[1].sessionId = v.witnesses[0].sessionId; },
    v => { v.witnesses[1].proofId = '44444444-4444-4444-8444-444444444444'; }, v => { v.witnesses[1].nonceMac = 'X'.repeat(43); },
    v => { v.witnesses[1].serverName = 'other.amazonaws.com'; }]) {
    const value = fixture(); mutate(value); await assert.rejects(prove(value), error); assert.equal(value.calls.length, 0);
  }
  assert.throws(() => fixture({ now: () => fixtureNow + 1001 }), error);
  assert.throws(() => fixture({ now: () => fixtureNow - 1001 }), error);
  const value = fixture(); value.attempt.nonceMac = 'X'.repeat(43); await prove(value);
});

test('owns snapshots across async hashing and derives fresh decoded commitments', async () => {
  let value, called = false;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest: async (...args) => {
    if (!called) { called = true; value.witnesses[1].recv.fill(0); value.witnesses[1].openings.recv[0].blinder.fill(0); }
    return webcrypto.subtle.digest(...args);
  } } };
  value = fixture({ crypto }); const first = await prove(value), second = await prove(fixture());
  assert.deepEqual(first.proofs.map(proof => proof.circuitId), second.proofs.map(proof => proof.circuitId));
  assert.notEqual(first.proofs[0].publicInputs.slice(128, 160).join(','), second.proofs[0].publicInputs.slice(128, 160).join(','));
});

test('serializes validated padded hexadecimal public fields as equivalent canonical decimal values', async () => {
  const base = fixture(), emitted = [];
  const value = fixture({ proveCircuit: async (...args) => {
    const entry = await base.proveCircuit(...args);
    entry.publicInputs = entry.publicInputs.map(field => `0x${BigInt(field).toString(16).padStart(64, '0')}`);
    emitted.push(entry); return entry;
  } });
  const bundle = await prove(value);
  bundle.proofs.forEach((entry, index) => {
    assert.deepEqual(entry.publicInputs, emitted[index].publicInputs.map(field => BigInt(field).toString()));
    assert.ok(entry.publicInputs.every(field => /^(0|[1-9][0-9]*)$/.test(field)));
    assert.ok(emitted[index].publicInputs.every(field => /^0x[0-9a-f]{64}$/.test(field)));
    assert.equal(entry.proof, emitted[index].proof);
  });
  assert.deepEqual(await verifyAwsBundle({ sessions: value.sessions, bundle, runtime: { verify: async () => true }, now: fixtureNow }),
    { activities: ['iam-role-trust-update'], attribution: 'iam-user', windowDays: 90, tools: {} });
});

test('rejects proof-output substitutions and private extras, clearing inputs on every failure', async () => {
  for (const mutate of [entry => { entry.publicInputs[0] = '256'; }, entry => { entry.circuitId = 'other'; },
    ...['-1', '1.0', '0x', '18446744073709551616'].map(invalid => entry => { entry.publicInputs[0] = invalid; }),
    entry => { entry.witness = 'private sentinel'; }, entry => { entry.proof = 'not-base64'; }]) {
    const base = fixture(), value = fixture({ proveCircuit: async (...args) => { const entry = await base.proveCircuit(...args); mutate(entry); return entry; } });
    await assert.rejects(prove(value), error); assert.ok(base.inputsHeld.every(zero)); assert.equal(base.calls.length, 1);
  }
  let held;
  const value = fixture({ proveCircuit: async (_, inputs) => { held = inputs; throw new Error('PRIVATE_ERROR_SENTINEL'); } });
  await assert.rejects(prove(value), error); assert.ok(zero(held));
});

test('cancellation, expiry and clearing prevent any final bundle after a worker settles', async () => {
  const before = fixture(); before.abort.abort(); await assert.rejects(prove(before), error); assert.equal(before.calls.length, 0);
  for (const stop of ['abort', 'clear', 'expire']) {
    let value, time = fixtureNow; const base = fixture();
    value = fixture({ now: () => time, proveCircuit: async (...args) => {
      const entry = await base.proveCircuit(...args);
      if (stop === 'abort') value.abort.abort(); else if (stop === 'clear') value.client.clear(); else time = fixtureNow + 1001;
      return entry;
    } });
    await assert.rejects(prove(value), error); assert.ok(base.inputsHeld.every(zero));
    assert.ok(value.randomHeld.every(bytes => bytes.every(byte => byte === 0)));
  }
});


test('Fast proves fresh IAM identity equality, rechecks old activity, and refuses absent or wrong links', async () => {
  let secret;
  const full = fixture({ saveLink: (_, value) => { secret = new Uint8Array(value); } });
  const recording = { policy: full.attempt, sessions: full.sessions, bundle: await prove(full) };
  const fastSource = awsFastSource(recording);
  const fresh = identityFixture({ blinderSeed: 'fresh' });
  fresh.expected.sessionId = fresh.receipt.session.id = '99999999-9999-4999-8999-999999999999';
  fresh.expected.nonceMac = fresh.receipt.session.nonceMac = 'B'.repeat(43);
  fresh.receipt.transcript.sent = fresh.receipt.transcript.sent.replace(full.attempt.nonceMac, fresh.expected.nonceMac);
  for (const item of fresh.receipt.results) if (item.action.kind === 'REVEAL') item.value = item.value.replace(full.attempt.nonceMac, fresh.expected.nonceMac);
  const witnesses = [syntheticWitness(fresh)], sessions = [{ receipt: fresh.receipt, expected: fresh.expected }];
  const make = (extra = {}) => createAwsPrivateClient({ attempt: fresh.expected, now: () => fixtureNow,
    proveCircuit: full.proveCircuit, fastSource, linkSecret: new Uint8Array(secret), ...extra });
  const bundle = await make().prove(witnesses, new AbortController().signal);
  assert.equal(bundle.sessionIds.length, 1); assert.equal(bundle.proofs[0].circuitId, 'aws-identity-refresh-v1');
  assert(bundle.proofs.length < recording.bundle.proofs.length);
  const runtime = { verify: async entry => entry.proof === 'AA==' };
  assert.deepEqual(await verifyAwsFastBundle({ sessions, bundle, runtime, recording, now: fixtureNow }),
    { activities: ['iam-role-trust-update'], attribution: 'iam-user', windowDays: 90, tools: {} });
  await assert.rejects(verifyAwsBundle({ sessions, bundle, runtime, now: fixtureNow }));
  await assert.rejects(verifyAwsFastBundle({ sessions, bundle, runtime, recording, now: fixtureNow + 15 * 60 * 1000 }));
  assert.throws(() => make({ linkSecret: undefined }));
  await assert.rejects(make({ linkSecret: new Uint8Array(16) }).prove(witnesses, new AbortController().signal));
  const wrongIdentity = syntheticWitness(identityFixture({ fields: { UserId: 'AIDAOTHERUSER000000001' } }));
  await assert.rejects(make({ attempt: full.attempt }).prove([wrongIdentity], new AbortController().signal));
  const tampered = structuredClone(recording); tampered.bundle.proofs[0].proof = 'AQ==';
  await assert.rejects(verifyAwsFastBundle({ sessions, bundle, runtime, recording: tampered, now: fixtureNow }));
});
