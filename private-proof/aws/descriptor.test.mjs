import assert from 'node:assert/strict';
import test from 'node:test';
import { fromVerifiedBundle } from '../../packages/proof-check/index.mjs';
import awsDescriptor from './descriptor.mjs';

const entry = (circuitId, inputs = ['1', '0x2']) => ({ circuitId, proof: 'AAAA', publicInputs: inputs });
const SESSIONS = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
const aws = { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: SESSIONS,
  proofs: [entry('aws-identity-link-v1'), entry('aws-event-link-v1')] };
const gcp = { kind: 'GCP_PRIVATE_RESULT', version: 1, proofs: [entry('timestamps-v1')] };

test('aws claim names the proved activity families', async () => {
  const awsFields = await fromVerifiedBundle(awsDescriptor, aws, { taskType: 'iam-role-trust-update', attribution: 'iam-user', windowDays: 90 });
  assert.equal(awsFields.claim, 'aws:iam-role-trust-update:iam-user');
  assert.equal(awsFields.vkHashes['aws-event-link-v1'], awsDescriptor.pins.circuits['aws-event-link-v1'].keySha256);
  const grouped = await fromVerifiedBundle(awsDescriptor, aws,
    { activities: ['iam-role-trust-update', 'security-group-ingress'], attribution: 'iam-user', windowDays: 90 });
  assert.equal(grouped.claim, 'aws:activity:iam-role-trust-update,security-group-ingress:iam-user');
  for (const activities of [[], ['security-group-ingress', 'iam-role-trust-update'], ['iam-role-trust-update', 'iam-role-trust-update'], ['s3-put']])
    await assert.rejects(fromVerifiedBundle(awsDescriptor, aws, { activities, attribution: 'iam-user', windowDays: 90 }), /aws activities/);
  const pages = await fromVerifiedBundle(awsDescriptor, aws, { attribution: 'iam-user', windowDays: 90,
    observations: [{ group: 's3' }, { group: 'iam-access' }, { group: 's3' }] });
  assert.match(pages.claim, /^aws:groups:1,[0-9]+:iam-user$/);
  await assert.rejects(fromVerifiedBundle(awsDescriptor, aws, { attribution: 'iam-user', windowDays: 90, observations: [{ group: 'mine' }] }),
    /aws observations/);
  await assert.rejects(fromVerifiedBundle(awsDescriptor, gcp, {}), /does not match/);
});

test('aws claims must list one known family per proven event, in policy order', () => {
  const claim = (bundle, signed) => awsDescriptor.claim(bundle, { claim: signed });
  const proofs = n => Array.from({ length: n }, () => [{ circuitId: 'aws-identity-link-v1' }, { circuitId: 'aws-event-link-v1' }]).flat();
  const two = 'aws:activity:iam-role-trust-update,security-group-ingress:iam-user';
  assert.equal(claim({ proofs: proofs(2) }, two).claim, two);
  assert.notEqual(claim({ proofs: proofs(1) }, two).claim, two);
  const reversed = 'aws:activity:security-group-ingress,iam-role-trust-update:iam-user';
  assert.notEqual(claim({ proofs: proofs(2) }, reversed).claim, reversed);
  assert.equal(claim({ proofs: proofs(1) }, 'aws:iam-role-trust-update:iam-user').claim, 'aws:iam-role-trust-update:iam-user');
  assert.equal(claim({ proofs: [{ circuitId: 'aws-event-link-v1' }] }, two), null);
});

test('aws headline names the operations, areas or groups', () => {
  assert.equal(awsDescriptor.describe({ claim: 'aws:iam-role-trust-update:iam-user', window: 90 }),
    'AWS: an IAM user updated a role trust policy in the last 90 days.');
  assert.match(awsDescriptor.describe({ claim: 'aws:groups:1:iam-user', window: 90 }), /^AWS: an IAM user's activity verified in .+ in the last 90 days\.$/);
  assert.equal(awsDescriptor.describe({ claim: 'aws:groups:999:iam-user', window: 90 }), null);
});
