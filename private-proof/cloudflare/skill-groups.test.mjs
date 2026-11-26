import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CLOUDFLARE_CATALOG_OPERATIONS, CLOUDFLARE_OPERATION_TIERS, CLOUDFLARE_SKILL_AREAS, CLOUDFLARE_SKILL_GROUPS,
  assertCloudflareSkillCatalog, cloudflareCatalogOperation, countsAsEvidence,
} from './skill-groups.mjs';

const clone = value => structuredClone(value);
const USER = 'u'.repeat(32);
const row = (product, type, action, over = {}) => ({
  action: { type: action, result: 'success' }, actor: { id: USER, type: 'user', context: 'oauth' },
  resource: { product, ...(type ? { type } : {}) }, ...over,
});

test('one entry per (product, type, action), each in a known group with a tier and an auto flag', () => {
  const keys = CLOUDFLARE_CATALOG_OPERATIONS.map(op => `${op.product}/${op.type} ${op.action}`);
  assert.equal(new Set(keys).size, keys.length);
  for (const op of CLOUDFLARE_CATALOG_OPERATIONS) {
    assert.deepEqual(Object.keys(op).sort(), ['action', 'auto', 'group', 'product', 'tier', 'type']);
    assert.ok(CLOUDFLARE_SKILL_GROUPS.some(g => g.id === op.group));
    assert.ok(CLOUDFLARE_OPERATION_TIERS.includes(op.tier));
    assert.equal(cloudflareCatalogOperation(op.product, op.type, op.action), op);
  }
  assert.ok(Object.isFrozen(CLOUDFLARE_CATALOG_OPERATIONS[0]) && Object.isFrozen(CLOUDFLARE_SKILL_GROUPS[0].jobTags));
});

test('a missing resource.type matches the empty type (queues rows have none)', () => {
  assert.equal(cloudflareCatalogOperation('queues', undefined, 'create').group, 'queues');
  assert.equal(cloudflareCatalogOperation('queues', 'consumers', 'create').tier, 'intermediate');
  assert.equal(cloudflareCatalogOperation('queues', 'producers', 'create'), undefined);
  assert.equal(cloudflareCatalogOperation('d1', 'database', 'view'), undefined);
});

test('evidence: own successful catalog change through a known tool only', () => {
  assert.equal(countsAsEvidence(row('d1', 'database', 'create'), USER), true);
  assert.equal(countsAsEvidence(row('queues', '', 'create'), USER), true);
  assert.equal(countsAsEvidence(row('d1', 'database', 'view'), USER), false);
  assert.equal(countsAsEvidence(row('d1', 'database', 'create'), 'v'.repeat(32)), false);
  assert.equal(countsAsEvidence(row('d1', 'database', 'create', { actor: { id: USER, type: 'system', context: 'oauth' } }), USER), false);
  assert.equal(countsAsEvidence(row('d1', 'database', 'create', { actor: { id: USER, type: 'user' } }), USER), false);
  assert.equal(countsAsEvidence(row('d1', 'database', 'create', { action: { type: 'create', result: 'failure' } }), USER), false);
  assert.equal(countsAsEvidence(row('dns', 'record', 'create'), USER), false);
  assert.equal(countsAsEvidence(null, USER), false);
});

test('the catalog check rejects broken entries', () => {
  const ok = () => assertCloudflareSkillCatalog(CLOUDFLARE_SKILL_AREAS, CLOUDFLARE_SKILL_GROUPS, CLOUDFLARE_CATALOG_OPERATIONS);
  ok();
  const bad = (areas, groups, ops) => assert.throws(() => assertCloudflareSkillCatalog(areas, groups, ops), /CLOUDFLARE_SKILL_CATALOG_INVALID/);
  const ops = clone(CLOUDFLARE_CATALOG_OPERATIONS), groups = clone(CLOUDFLARE_SKILL_GROUPS);
  bad(CLOUDFLARE_SKILL_AREAS, groups, [...ops, ops[0]]);
  bad(CLOUDFLARE_SKILL_AREAS, groups, ops.map((o, i) => i ? o : { ...o, action: 'view' }));
  bad(CLOUDFLARE_SKILL_AREAS, groups, ops.map((o, i) => i ? o : { ...o, tier: 'expert' }));
  bad(CLOUDFLARE_SKILL_AREAS, groups, ops.map((o, i) => i ? o : { ...o, group: 'nope' }));
  bad(CLOUDFLARE_SKILL_AREAS, groups, ops.map((o, i) => i ? o : { ...o, product: '', type: '' }));
  bad(CLOUDFLARE_SKILL_AREAS, groups.map((g, i) => i ? g : { ...g, jobTags: [...g.jobTags, groups[1].jobTags[0]] }), ops);
  bad(CLOUDFLARE_SKILL_AREAS, groups, ops.filter(o => o.group !== 'queues'));
  bad([...CLOUDFLARE_SKILL_AREAS, { id: 'zones', label: 'Zones' }], groups, ops);
});
