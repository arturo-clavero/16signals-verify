import assert from 'node:assert/strict';
import test from 'node:test';
import { fromVerifiedBundle, vkHashesFor } from '../../packages/proof-check/index.mjs';
import gcpDescriptor from './descriptor.mjs';
import gcpPins from './generated/verification-keys.json' with { type: 'json' };
import awsPins from '../aws/generated/pins.json' with { type: 'json' };

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
const aws = {
  kind: 'AWS_PRIVATE_RESULT',
  version: 1,
  proofs: [entry('aws-identity-link-v1'), entry('aws-event-link-v1')],
};

test('vk hashes come from the pinned key manifest, not the circuit artifacts', () => {
  assert.deepEqual(vkHashesFor(gcp, gcpDescriptor.pins), {
    'identity-scope-v1': gcpPins.circuits['identity-scope-v1'].sha256,
    'timestamps-v1': gcpPins.circuits['timestamps-v1'].sha256,
  });
  assert.throws(() => vkHashesFor(aws, gcpPins), /no pinned key/);
  assert.equal(
    vkHashesFor(aws, awsPins)['aws-event-link-v1'],
    awsPins.circuits['aws-event-link-v1'].keySha256,
  );
});

test('gcp claim lists observed groups only', async () => {
  const groups = [
    { id: 'g10', status: 'observed' },
    { id: 'g2', status: 'observed' },
    { id: 'g3', status: 'empty' },
    { id: 'g4', status: 'denied' },
  ];
  const fields = await fromVerifiedBundle(
    gcpDescriptor,
    gcp,
    { catalogDigest: 'x', policy: { cutoff: 1, windowDays: 30 }, groups },
    { pluginSha256: 'e'.repeat(64) },
  );
  assert.equal(fields.claim, 'gcp:observed:g2,g10');
  assert.equal(fields.window, 30);
  assert.equal(fields.pluginSha256, 'e'.repeat(64));
  assert.equal(
    (await fromVerifiedBundle(gcpDescriptor, gcp, { policy: { windowDays: 7 }, groups: [] })).claim,
    'gcp:observed:none',
  );
  await assert.rejects(fromVerifiedBundle(gcpDescriptor, aws, {}), /does not match/);
  await assert.rejects(
    fromVerifiedBundle(gcpDescriptor, gcp, {
      policy: { windowDays: 30 },
      groups: [{ id: 'my-project', status: 'observed' }],
    }),
    /gcp group/,
  );
});

test('gcp headline counts observed groups', () => {
  assert.equal(
    gcpDescriptor.describe({ claim: 'gcp:observed:g1,g4', window: 30 }),
    'Google Cloud: activity observed in 2 skill group(s) in the last 30 days.',
  );
  assert.equal(
    gcpDescriptor.describe({ claim: 'gcp:observed:none', window: 7 }),
    'Google Cloud: no activity observed in the last 7 days.',
  );
  assert.equal(gcpDescriptor.describe({ claim: 'gcp:other' }), null);
});
