import assert from 'node:assert/strict';
import test from 'node:test';
import { fromVerifiedBundle } from '../../packages/proof-check/index.mjs';
import cfDescriptor from './descriptor.mjs';
import { CLOUDFLARE_SKILL_GROUPS } from './skill-groups.mjs';

const entry = (circuitId, inputs = ['1', '0x2']) => ({
  circuitId,
  proof: 'AAAA',
  publicInputs: inputs,
});
const SESSIONS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
const aws = {
  kind: 'AWS_PRIVATE_RESULT',
  version: 1,
  proofs: [entry('aws-identity-link-v1'), entry('aws-event-link-v1')],
};

test('cloudflare claim lists the proven skill groups by catalog position', async () => {
  const id = Object.keys(cfDescriptor.pins.circuits)[0];
  const cf = {
    kind: 'CLOUDFLARE_PRIVATE_RESULT',
    version: 1,
    sessionIds: SESSIONS,
    proofs: [entry(id)],
  };
  const fields = await fromVerifiedBundle(cfDescriptor, cf, {
    attribution: 'cloudflare-user',
    windowDays: 90,
    observations: [{ group: 'kv' }, { group: 'workers-deploy' }, { group: 'kv' }],
  });
  assert.equal(fields.claim, 'cloudflare:groups:1,3:user');
  await assert.rejects(
    fromVerifiedBundle(cfDescriptor, cf, {
      attribution: 'cloudflare-user',
      windowDays: 90,
      observations: [{ group: 'x' }],
    }),
    /cloudflare result/,
  );
  await assert.rejects(fromVerifiedBundle(cfDescriptor, aws, {}), /does not match/);
});

test('cloudflare headline shows the group labels, and only known positions', () => {
  const labels = [CLOUDFLARE_SKILL_GROUPS[0].label, CLOUDFLARE_SKILL_GROUPS[2].label].join(', ');
  assert.equal(
    cfDescriptor.describe({ claim: 'cloudflare:groups:1,3:user', window: 90 }),
    `Cloudflare: account activity verified in ${labels} in the last 90 days.`,
  );
  assert.equal(cfDescriptor.describe({ claim: 'cloudflare:groups:999:user', window: 90 }), null);
});
