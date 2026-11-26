import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalize } from './commitment.mjs';
import { fromVerifiedBundle, proofHash, publicBundle, vkHashesFor } from './bundle.mjs';

const h = (c) => c.repeat(64);
const entry = (circuitId, inputs = ['1', '0x2']) => ({
  circuitId,
  proof: 'AAAA',
  publicInputs: inputs,
});
const SESSIONS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
const gcp = {
  kind: 'GCP_PRIVATE_RESULT',
  version: 1,
  sessionIds: SESSIONS,
  proofs: [entry('identity-scope-v1'), entry('timestamps-v1'), entry('timestamps-v1', ['3'])],
};
// The two pin formats: a key-only manifest ({ sha256 }) and one that also pins the circuit artifact ({ keyFile, keySha256 }).
const keyPins = {
  circuits: { 'identity-scope-v1': { sha256: h('a') }, 'timestamps-v1': { sha256: h('b') } },
};
const artifactPins = {
  circuits: {
    'identity-scope-v1': { sha256: h('0'), keyFile: 'k1', keySha256: h('c') },
    'timestamps-v1': { sha256: h('0'), keyFile: 'k2', keySha256: h('d') },
  },
};
const example = {
  id: 'example',
  kind: 'EXAMPLE_RESULT',
  pins: async () => ({ circuits: { 'example-v1': { sha256: h('e') } } }),
  claimFromResult: (result) => ({ claim: `example:${result.level}`, window: 30 }),
};

test('proof hash covers exactly the proofs and public inputs, not session routing ids', async () => {
  const expected = createHash('sha256')
    .update(canonicalize({ kind: gcp.kind, version: 1, proofs: gcp.proofs }))
    .digest('hex');
  assert.equal(await proofHash(gcp), expected);
  assert.equal(await proofHash({ ...gcp, sessionIds: [] }), expected);
  assert.notEqual(await proofHash({ ...gcp, proofs: [...gcp.proofs].reverse() }), expected);
  assert.equal('sessionIds' in publicBundle(gcp), false);
  for (const bad of [
    { ...gcp, kind: 'X' },
    { ...gcp, kind: 'gcp result' },
    { ...gcp, proofs: [] },
    { ...gcp, proofs: [entry('atom-v1', [1])] },
    { ...gcp, proofs: [{ ...entry('atom-v1'), proof: 'not base64!' }] },
  ])
    await assert.rejects(proofHash(bad), /PROOF_BUNDLE_INVALID/);
});

test('vk hashes come from the pinned key manifests, not the circuit artifacts', () => {
  assert.deepEqual(vkHashesFor(gcp, keyPins), {
    'identity-scope-v1': h('a'),
    'timestamps-v1': h('b'),
  });
  assert.deepEqual(vkHashesFor(gcp, artifactPins), {
    'identity-scope-v1': h('c'),
    'timestamps-v1': h('d'),
  });
  assert.throws(
    () => vkHashesFor(gcp, { circuits: { 'timestamps-v1': { sha256: h('b') } } }),
    /no pinned key/,
  );
  assert.throws(() => vkHashesFor(gcp, undefined), /pins/);
});

test('commitment fields come from the provider descriptor: its kind, claim and pins', async () => {
  const bundle = { kind: 'EXAMPLE_RESULT', version: 1, proofs: [entry('example-v1')] };
  const fields = await fromVerifiedBundle(
    example,
    bundle,
    { level: 'two' },
    { pluginSha256: h('f') },
  );
  assert.deepEqual(fields, {
    provider: 'example',
    claim: 'example:two',
    proofHash: await proofHash(bundle),
    window: 30,
    vkHashes: { 'example-v1': h('e') },
    pluginSha256: h('f'),
  });
  assert.deepEqual(
    (
      await fromVerifiedBundle(
        example,
        bundle,
        { level: 'two' },
        { pins: { circuits: { 'example-v1': { sha256: h('1') } } } },
      )
    ).vkHashes,
    { 'example-v1': h('1') },
  );
  await assert.rejects(fromVerifiedBundle(example, gcp, { level: 'two' }), /does not match/);
  await assert.rejects(fromVerifiedBundle({ id: 'example' }, bundle, {}), /provider/);
  await assert.rejects(fromVerifiedBundle(example, bundle, { level: 'Two Words' }), /claim/);
});
