import assert from 'node:assert/strict';
import test from 'node:test';
import { AWS_OPERATIONS, AWS_SKILL_AREAS } from './operation-catalog.mjs';
import { AWS_CATALOG_OPERATIONS, AWS_OPERATION_TIERS, AWS_SKILL_GROUPS, assertAwsSkillCatalog, awsCatalogOperation } from './skill-groups.mjs';

const clone = value => structuredClone(value);

test('one entry per CloudTrail event, each in a known group with a tier and an auto flag', () => {
  const keys = AWS_CATALOG_OPERATIONS.map(op => `${op.eventSource} ${op.eventName}`);
  assert.equal(new Set(keys).size, keys.length);
  for (const op of AWS_CATALOG_OPERATIONS) {
    assert.deepEqual(Object.keys(op).sort(), ['auto', 'eventName', 'eventSource', 'group', 'tier']);
    assert.ok(AWS_SKILL_GROUPS.some(g => g.id === op.group));
    assert.ok(AWS_OPERATION_TIERS.includes(op.tier));
    assert.equal(typeof op.auto, 'boolean');
    assert.equal(awsCatalogOperation(op.eventSource, op.eventName), op);
  }
  // Same names under different sources stay apart.
  assert.equal(awsCatalogOperation('iam.amazonaws.com', 'CreatePolicy').group, 'iam-access');
  assert.equal(awsCatalogOperation('organizations.amazonaws.com', 'CreatePolicy').group, 'org-governance');
  assert.equal(awsCatalogOperation('ec2.amazonaws.com', 'CreateRoute').group, 'vpc-routing');
  assert.equal(awsCatalogOperation('apigateway.amazonaws.com', 'CreateRoute').group, 'api-gateway');
  assert.equal(awsCatalogOperation('lambda.amazonaws.com', 'CreateFunction'), undefined);
  assert.equal(awsCatalogOperation('iam.amazonaws.com', 'GetRole'), undefined);
  assert.ok(Object.isFrozen(AWS_CATALOG_OPERATIONS) && Object.isFrozen(AWS_CATALOG_OPERATIONS[0]) && Object.isFrozen(AWS_SKILL_GROUPS[0].jobTags));
});

test('every group is reachable, rolls up to a skill area and has its own job tags', () => {
  const ids = AWS_SKILL_GROUPS.map(g => g.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const g of AWS_SKILL_GROUPS) {
    assert.ok(AWS_CATALOG_OPERATIONS.some(op => op.group === g.id), `${g.id} has no operation`);
    assert.ok(AWS_SKILL_AREAS.some(area => area.id === g.area), `${g.id} has no area`);
    assert.ok(g.jobTags.length > 0 && g.label);
  }
  for (const area of AWS_SKILL_AREAS) assert.ok(AWS_SKILL_GROUPS.some(g => g.area === area.id), `${area.id} has no group`);
  const tags = AWS_SKILL_GROUPS.flatMap(g => g.jobTags);
  assert.equal(new Set(tags).size, tags.length);
  for (const tag of tags) assert.match(tag, /^[a-z0-9]+(-[a-z0-9]+)*$/);
});

test('every provable operation is in a group of its own skill area', () => {
  for (const entry of AWS_OPERATIONS) for (const name of entry.eventNames) {
    const op = awsCatalogOperation(entry.eventSource, name);
    assert.ok(op, entry.id);
    assert.equal(AWS_SKILL_GROUPS.find(g => g.id === op.group).area, entry.skillArea, entry.id);
  }
});

test('rejects a catalog that breaks the rules', () => {
  const groups = clone(AWS_SKILL_GROUPS), ops = clone(AWS_CATALOG_OPERATIONS);
  assert.doesNotThrow(() => assertAwsSkillCatalog(groups, ops));
  const bad = [
    [groups, [...ops, ops[0]]],                                                         // duplicate event
    [groups, ops.map((op, i) => i ? op : { ...op, tier: 'expert' })],                   // unknown tier
    [groups, ops.map((op, i) => i ? op : { ...op, auto: 'no' })],                      // auto not a boolean
    [groups, ops.map((op, i) => i ? op : { ...op, group: 'nowhere' })],                 // unknown group
    [groups, ops.map((op, i) => i ? op : { ...op, eventSource: 'iam.example.com' })],   // not an AWS source
    [groups, ops.filter(op => op.eventName !== 'UpdateAssumeRolePolicy')],              // provable op missing
    [groups, ops.filter(op => op.group !== 'dns')],                                     // empty group
    [groups.map((g, i) => i ? g : { ...g, area: 'elsewhere' }), ops],                   // unknown area
    [groups.map((g, i) => i ? g : { ...g, jobTags: [] }), ops],                          // no job tags
    [groups.map((g, i) => i !== 1 ? g : { ...g, jobTags: [...g.jobTags, 'aws-iam'] }), ops], // tag names two groups
    [groups.map((g, i) => i ? g : { ...g, id: groups[1].id }), ops],                     // duplicate group id
    [groups.filter(g => g.area !== 'compute'), ops.filter(op => op.group !== 'compute')], // area without a group
    [groups.map(g => g.id === 'iac' ? { ...g, area: 'storage' } : g), ops],             // provable op in another area
  ];
  for (const [g, o] of bad) assert.throws(() => assertAwsSkillCatalog(g, o), /AWS_SKILL_CATALOG_INVALID/);
});
