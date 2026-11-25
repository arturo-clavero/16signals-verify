import assert from 'node:assert/strict';
import test from 'node:test';
import { AWS_OPERATIONS, AWS_SKILL_AREAS, AWS_RESOURCE_NAME, awsOperation, assertAwsOperationCatalog } from './operation-catalog.mjs';

// Shipped ids and their skill areas. Stored results are read back against the catalog's area for each id, so this
// list only grows: never rename an id, move it to another area or reorder these entries.
const SHIPPED = [
  ['iam-role-trust-update', 'iam-security'], ['lambda-configuration-update', 'serverless'], ['security-group-ingress', 'networking'],
  ['iam-role-policy-attach', 'iam-security'], ['lambda-code-update', 'serverless'], ['s3-bucket-versioning', 'storage'],
  ['s3-bucket-lifecycle', 'storage'], ['cloudformation-change-set', 'infrastructure-as-code'], ['ecs-task-definition', 'containers'],
  ['dynamodb-ttl-update', 'database'], ['cloudwatch-metric-alarm', 'monitoring'],
];
const SHIPPED_AREAS = ['iam-security', 'serverless', 'networking', 'storage', 'infrastructure-as-code', 'containers', 'database', 'monitoring'];

test('exposes stable ids, skill areas and one lookup per CloudTrail event', () => {
  assert.deepEqual(AWS_OPERATIONS.slice(0, SHIPPED.length).map(entry => [entry.id, entry.skillArea]), SHIPPED);
  assert.deepEqual(AWS_SKILL_AREAS.slice(0, SHIPPED_AREAS.length).map(area => area.id), SHIPPED_AREAS);
  // Every area is reachable: through a provable operation or a skill group (skill-groups.test.mjs checks the groups).
  assert.ok(AWS_OPERATIONS.every(entry => AWS_SKILL_AREAS.some(area => area.id === entry.skillArea)));
  for (const entry of AWS_OPERATIONS) for (const name of entry.eventNames) assert.equal(awsOperation(entry.eventSource, name), entry);
  assert.equal(awsOperation('iam.amazonaws.com', 'UpdateFunctionConfiguration20150331v2'), undefined);
  assert.equal(awsOperation('lambda.amazonaws.com', 'UpdateAssumeRolePolicy'), undefined);
  assert.ok(Object.isFrozen(AWS_OPERATIONS) && Object.isFrozen(AWS_OPERATIONS[2].request.object.ipPermissions.list.object));
  assert.throws(() => { AWS_OPERATIONS[0].request.object.extra = { atom: 1 }; }, TypeError);
});

test('resource names use the event-link circuit grammar', () => {
  assert.deepEqual([AWS_RESOURCE_NAME.minBytes, AWS_RESOURCE_NAME.maxBytes], [3, 66]);
  for (const name of ['my-role', 'sg-0123456789abcdef0', 'fn_name.v2', 'a@b+c=d,e']) assert.match(name, AWS_RESOURCE_NAME.pattern);
  for (const name of ['with space', 'arn:aws:iam::1:role/x', 'q"uote', 'naïve']) assert.doesNotMatch(name, AWS_RESOURCE_NAME.pattern);
});

test('rejects catalog entries that would weaken the verifier', () => {
  const base = () => structuredClone(AWS_OPERATIONS.map(entry => ({ ...entry })));
  assert.doesNotThrow(() => assertAwsOperationCatalog(base()));
  for (const mutate of [
    entries => { entries[1].id = entries[0].id; },
    entries => { entries[1].eventNames = [...entries[0].eventNames]; entries[1].eventSource = entries[0].eventSource; },
    entries => { entries[0].skillArea = 'unknown'; },
    entries => { entries[0].eventSource = 'iam.example.com'; },
    entries => { entries[0].eventNames = []; },
    entries => { entries[0].readOnly = true; },
    entries => { entries[0].resource = 'missing'; },
    entries => { entries[0].request.object.roleName = { atom: 2 }; },
    entries => { entries[0].request.object.roleName = { literal: null }; },
    entries => { entries[0].request.required = ['policyDocument']; },
    entries => { entries[0].request.object.dryRun = { literal: true }; },
    entries => { entries[0].request.object.dryRun = { atom: 4 }; },
    entries => { entries[0].request.object.policyDocument = { literal: 'public' }; },
    entries => { entries[0].request.object.policyDocument = { atom: 6 }; },
    entries => { entries[0].request.object.policyDocument = { atom: 1, extra: true }; },
    entries => { entries[0].request.object.policyDocument = {}; },
    entries => { entries[0].request.required.push('unknown'); },
    entries => { entries[1].request.atLeastOne = ['functionName']; },
    entries => { entries[2].request.object.ipPermissions.nonEmpty = 'yes'; },
    entries => { entries[2].response = { atom: 1 }; delete entries[2].response.atom; },
    entries => { entries[0].request = { literal: null }; },
    entries => { entries[0].request.nullable = true; },
    entries => { entries[0].request.object = {}; entries[0].request.required = []; },
    entries => { entries[1].response.nullable = false; },
    entries => { entries[4].request.object.publish = { atom: [3] }; },
    entries => { entries[4].request.object.publish = { atom: [3, 3] }; },
    entries => { entries[4].request.object.publish = { atom: [3, 6] }; },
    entries => { entries[4].request.object.publish = { atom: [1, 2], minBytes: 3 }; },
    entries => { entries[8].request.object.containerDefinitions.nonEmpty = false; },
    entries => { entries[8].response.object.taskDefinition.object.volumes = { array: null, nonEmpty: true }; },
    entries => { entries[8].response.object.taskDefinition.object.volumes = { array: undefined }; },
    entries => { entries[9].event = { object: { apiVersion: { atom: 1 } }, required: ['apiVersion'] }; },
    entries => { entries[9].event = { object: {}, required: [] }; },
    entries => { entries[9].event = { literal: null }; },
    entries => { entries[5].event.nullable = true; },
  ]) {
    const entries = base(); mutate(entries);
    assert.throws(() => assertAwsOperationCatalog(entries), /AWS_OPERATION_CATALOG_INVALID/);
  }
});
