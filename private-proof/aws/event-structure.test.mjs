import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectAwsEventSession } from './event-structure.mjs';
import { AWS_OPERATIONS } from './operation-catalog.mjs';
import { eventFixture, activityEventFixture, fixtureNow, ACTIVITY_EVENTS } from './event-fixture.mjs';

const inspect = fixture => inspectAwsEventSession(fixture.receipt, fixture.expected, fixture.claims, fixtureNow);
const rejects = fixture => assert.throws(() => inspect(fixture), { message: 'AWS_PRIVATE_EVENT_INVALID' });

test('maps every native range to one proof obligation and retains private joins', () => {
  const fixture = eventFixture(), result = inspect(fixture);
  const hashes = fixture.receipt.results.filter(row => row.action.kind === 'HASH').map(row => row.value);
  assert.equal(result.obligations.length, hashes.length);
  assert.deepEqual(new Set(result.obligations.map(slot => slot.hash)), new Set(hashes));
  assert.equal(result.obligations.filter(slot => slot.circuitId === 'header-v1').length, 5);
  assert.ok(result.obligations.some(slot => slot.circuitId === 'atom-v1'));
  assert.ok(result.obligations.some(slot => slot.circuitId === 'aws-escaped-atom-v1'));
  assert.equal(Object.keys(result.bindings).length, 11);
  assert.match(result.bindings.userAgent.hash, /^[a-f0-9]{64}$/);
  assert.equal(result.accepted, undefined);
  for (const sentinel of ['AWS_PRIVATE', 'SYNTHETIC_PRIVATE', '111122223333', 'AIDAEXAMPLE', 'aaaaaaaa-aaaa']) {
    assert.ok(!JSON.stringify(result).includes(sentinel));
    assert.ok(!JSON.stringify(fixture.receipt).includes(sentinel));
  }
});

test('maps intact atom ranges through chunk framing and rejects split atoms', () => {
  const result = inspect(eventFixture({ chunked: true }));
  assert.equal(Object.keys(result.bindings).length, 11);
  rejects(eventFixture({ crossChunk: true }));
});

test('an event without a userAgent binds no tool class', () => {
  const result = inspect(eventFixture({ mutateEvent: event => { delete event.userAgent; } }));
  assert.equal(result.bindings.userAgent, undefined);
  assert.equal(Object.keys(result.bindings).length, 10);
});

test('requires exact read-only lookup request shape and private event selection', () => {
  for (const mutateRequest of [request => { request.MaxResults = 2; }, request => { request.NextToken = 'page'; },
    request => { request.LookupAttributes[0].AttributeKey = 'EventSource'; },
    request => { request.LookupAttributes.push(request.LookupAttributes[0]); }]) rejects(eventFixture({ mutateRequest }));
  for (const startLine of ['GET / HTTP/1.1', 'POST /other HTTP/1.1']) rejects(eventFixture({ startLine }));
});

test('requires the authenticated HTTP request to carry the intended host, operation and nonce', () => {
  for (const [name, value] of [['host', 'attacker.invalid'], ['x-16signals-nonce', 'X'.repeat(43)],
    ['x-amz-target', 'DifferentOperation'], ['accept-encoding', 'gzip']]) {
    rejects(eventFixture({ mutateHeaders: headers => { headers.find(row => row[0] === name)[1] = value; } }));
  }
});

test('rejects visible, empty or missing credentials and duplicate request headers', () => {
  for (const mutateHeaders of [headers => { headers.find(row => row[0] === 'authorization')[2] = false; },
    headers => { headers.find(row => row[0] === 'authorization')[1] = ''; },
    headers => { headers.splice(headers.findIndex(row => row[0] === 'x-amz-security-token'), 1); },
    headers => { headers.push([...headers[0]]); }]) rejects(eventFixture({ mutateHeaders }));
});

test('hides each unknown response header, including duplicate private metadata', () => {
  assert.ok(inspect(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['x-private', 'FIRST', true], ['x-private', 'SECOND', true]); } })));
  rejects(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['x-private', 'EMPLOYER_PRIVATE', false]); } }));
  rejects(eventFixture({ mutateHeaders: (_, headers) => { headers.push(['content-type', 'application/x-amz-json-1.1']); } }));
});

test('a successful lookup cannot hide recorded errors, dry runs or addenda', () => {
  for (const mutateEvent of [event => { event.errorCode = 'AccessDenied'; }, event => { event.errorMessage = 'private'; },
    event => { event.errorCode = null; }, event => { event.addendum = {}; },
    event => { event.requestParameters.dryRun = true; }, event => { event.responseElements = {}; }]) rejects(eventFixture({ mutateEvent }));
  rejects(eventFixture({ statusLine: 'HTTP/1.1 403 Forbidden' }));
});

test('rejects wrong event semantics, absent required fields and mismatched outer metadata', () => {
  for (const mutateEvent of [event => { event.eventName = 'AttachRolePolicy'; }, event => { event.eventSource = 'ec2.amazonaws.com'; },
    event => { event.readOnly = true; }, event => { event.managementEvent = false; }, event => { event.awsRegion = 'us-west-2'; },
    event => { delete event.eventID; }, event => { delete event.responseElements; }, event => { event.eventVersion = '2.00'; },
    event => { event.eventVersion = 1.11; },
    event => { event.requestParameters.policyDocument = ''; }, event => { event.requestParameters.roleName = ''; }]) rejects(eventFixture({ mutateEvent }));
  rejects(eventFixture({ mutateRow: row => { row.EventName = 'AttachRolePolicy'; } }));
  rejects(eventFixture({ mutateRow: row => { row.ReadOnly = 'true'; } }));
});

test('rejects unsupported actor classes and delegation fields', () => {
  for (const mutateEvent of [event => { event.userIdentity.type = 'AssumedRole'; }, event => { event.userIdentity.type = 'Root'; },
    event => { event.userIdentity.invokedBy = 'service.amazonaws.com'; }, event => { event.userIdentity.onBehalfOf = {}; },
    event => { delete event.userIdentity.principalId; }]) rejects(eventFixture({ mutateEvent }));
});

test('does not release private actor, account, time or resource values as public literals', () => {
  for (const path of ['userIdentity.principalId', 'userIdentity.arn', 'recipientAccountId', 'eventTime', 'requestParameters.roleName']) {
    rejects(eventFixture({ publicEvent: [path] }));
  }
});

test('binds provisional atom claims to exact native direction, range, digest and consumption', () => {
  for (const mutate of [fixture => { fixture.claims[0].start++; }, fixture => { fixture.claims[0].hash = 'ef'.repeat(32); },
    fixture => { fixture.claims[0].direction = 'RECV'; }, fixture => { fixture.claims.pop(); },
    fixture => { fixture.claims.push({ ...fixture.claims[0] }); }, fixture => { fixture.claims[0].extra = 'private'; }]) {
    const fixture = eventFixture(); mutate(fixture); rejects(fixture);
  }
});

test('keeps wrong private actor/account values provisional until equality proofs verify', () => {
  const result = inspect(eventFixture({ mutateEvent: event => { event.userIdentity.accountId = '999988887777'; } }));
  assert.notEqual(result.bindings.actorAccount.hash, result.bindings.recipientAccount.hash);
  assert.equal(result.accepted, undefined);
});

test('additional activity predicates keep all private fields behind proof obligations', () => {
  for (const [activity, id] of [['lambda', 'lambda-configuration-update'], ['network', 'security-group-ingress']]) {
    const fixture = activityEventFixture(activity), result = inspect(fixture);
    assert.equal(result.activity, id);
    assert.equal(result.obligations.length, fixture.receipt.results.filter(row => row.action.kind === 'HASH').length);
    for (const sentinel of ['AWS_PRIVATE', 'sg-0123456789abcdef0', '192.0.2.0/24', '111122223333']) {
      assert.ok(!JSON.stringify(fixture.receipt).includes(sentinel));
      assert.ok(!JSON.stringify(result).includes(sentinel));
    }
  }
});

test('additional families reject failures, other actors, unknown fields and leaked configuration', () => {
  for (const activity of ['lambda', 'network']) for (const mutate of [
    event => { event.errorCode = 'AccessDenied'; }, event => { event.errorMessage = 'failed'; },
    event => { event.requestParameters.dryRun = true; }, event => { event.userIdentity.type = 'AssumedRole'; },
    event => { event.requestParameters.unreviewedField = 'private'; }, event => { event.readOnly = true; },
    event => { event.eventSource = 'iam.amazonaws.com'; },
  ]) rejects(activityEventFixture(activity, { mutateEvent: mutate }));
  rejects(activityEventFixture('network', { mutateEvent: event => { event.responseElements._return = false; } }));
  rejects(activityEventFixture('network', { mutateEvent: event => { event.requestParameters.ipPermissions.items = []; } }));
  rejects(activityEventFixture('lambda', { mutateEvent: event => { delete event.requestParameters.timeout; } }));
  rejects(activityEventFixture('lambda', { mutateEvent: event => { event.requestParameters.environment = { SECRET: 'private' }; } }));
  for (const path of ['requestParameters.functionName', 'requestParameters.timeout']) {
    rejects(activityEventFixture('lambda', { publicEvent: [path] }));
  }
  for (const path of ['requestParameters.groupId', 'requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp',
    'responseElements.securityGroupRuleSet.items.0.cidrIpv4']) {
    rejects(activityEventFixture('network', { publicEvent: [path] }));
  }
});

// dryRun: whether the reviewed sample allowed a requestParameters.dryRun key.
const operationCases = {
  iam: { id: 'iam-role-trust-update', resource: 'roleName', secret: 'requestParameters.policyDocument', other: 'lambda', dryRun: true },
  lambda: { id: 'lambda-configuration-update', resource: 'functionName', secret: 'requestParameters.timeout', other: 'network', dryRun: true },
  network: { id: 'security-group-ingress', resource: 'groupId', secret: 'requestParameters.ipPermissions.items.0.ipProtocol', other: 'iam', dryRun: true },
  'iam-attach': { id: 'iam-role-policy-attach', resource: 'roleName', secret: 'requestParameters.policyArn', other: 'iam' },
  'lambda-code': { id: 'lambda-code-update', resource: 'functionName', secret: 'responseElements.codeSha256', other: 'lambda', dryRun: true },
  's3-versioning': { id: 's3-bucket-versioning', resource: 'bucketName', secret: 'requestParameters.VersioningConfiguration.Status', other: 's3-lifecycle' },
  's3-lifecycle': { id: 's3-bucket-lifecycle', resource: 'bucketName', secret: 'requestParameters.LifecycleConfiguration.Rule.ID', other: 's3-versioning' },
  changeset: { id: 'cloudformation-change-set', resource: 'stackName', secret: 'responseElements.id', other: 'ecs' },
  ecs: { id: 'ecs-task-definition', resource: 'family', secret: 'requestParameters.containerDefinitions.0.image', other: 'changeset' },
  ttl: { id: 'dynamodb-ttl-update', resource: 'tableName', secret: 'requestParameters.timeToLiveSpecification.attributeName', other: 'alarm' },
  alarm: { id: 'cloudwatch-metric-alarm', resource: 'alarmName', secret: 'requestParameters.threshold', other: 'ttl' },
};
const sources = Object.fromEntries(Object.keys(operationCases).map(family => {
  const event = family === 'iam' ? { eventSource: 'iam.amazonaws.com', eventName: 'UpdateAssumeRolePolicy' } : ACTIVITY_EVENTS[family]({});
  return [family, [event.eventSource, event.eventName]];
}));
// The row mirrors the event so each case tests the event's own structure, not an outer metadata mismatch.
const operationFixture = (family, mutateEvent, publicEvent, changeRow) => {
  const mutateRow = row => {
    const event = JSON.parse(row.CloudTrailEvent); row.EventName = event.eventName; row.EventSource = event.eventSource; changeRow?.(row);
  };
  return family === 'iam' ? eventFixture({ mutateEvent, mutateRow, publicEvent }) :
    activityEventFixture(family, { mutateEvent, publicEvent, mutateRow: changeRow });
};

test('every catalog operation accepts its reviewed shape, including an explicit dryRun false where reviewed', () => {
  assert.deepEqual(Object.values(operationCases).map(entry => entry.id), AWS_OPERATIONS.map(entry => entry.id));
  for (const [family, { id, dryRun }] of Object.entries(operationCases)) {
    assert.equal(inspect(operationFixture(family)).activity, id);
    const explicit = operationFixture(family, event => { event.requestParameters.dryRun = false; });
    if (dryRun) assert.equal(inspect(explicit).activity, id); else rejects(explicit);
  }
});

test('every catalog operation rejects unknown keys, exposed private values and wrong event identity', () => {
  for (const [family, { resource, secret, other }] of Object.entries(operationCases)) {
    for (const mutate of [
      event => { event.requestParameters.unreviewedField = 'private'; },
      event => { event.responseElements = { unreviewed: 'private' }; },
      event => { event.unreviewedTopLevel = 'private'; },
      event => { event.eventName = `${event.eventName}Extra`; },
      event => { event.eventSource = 'sqs.amazonaws.com'; },
      event => { [event.eventSource, event.eventName] = sources[other]; },
    ]) rejects(operationFixture(family, mutate));
    for (const path of [`requestParameters.${resource}`, secret]) rejects(operationFixture(family, undefined, [path]));
  }
});

test('every catalog operation rejects failed, read-only and dry-run events', () => {
  for (const family of Object.keys(operationCases)) for (const mutate of [
    event => { event.errorCode = 'AccessDenied'; }, event => { event.errorMessage = 'denied'; },
    event => { event.readOnly = true; }, event => { event.requestParameters.dryRun = true; },
    event => { event.requestParameters.dryRun = 'false'; },
  ]) rejects(operationFixture(family, mutate));
  for (const family of Object.keys(operationCases)) rejects(operationFixture(family, undefined, [], row => { row.ReadOnly = 'true'; }));
});

test('every catalog operation bounds its resource name to the event-link circuit length', () => {
  for (const [family, { resource }] of Object.entries(operationCases)) {
    const named = name => operationFixture(family, event => { event.requestParameters[resource] = name; });
    for (const name of ['a', 'a'.repeat(64)]) assert.ok(inspect(named(name)).bindings.roleName);
    for (const name of ['', 'a'.repeat(65), 'a'.repeat(400)]) rejects(named(name));
    rejects(operationFixture(family, event => { event.requestParameters[resource] = 42; }));
    rejects(operationFixture(family, event => { delete event.requestParameters[resource]; }));
  }
});

test('every catalog operation rejects other actor classes; actor and time joins stay proof obligations', () => {
  for (const family of Object.keys(operationCases)) {
    for (const mutate of [event => { event.userIdentity.type = 'AssumedRole'; }, event => { event.userIdentity.type = 'Root'; },
      event => { event.userIdentity.invokedBy = 'service.amazonaws.com'; }]) rejects(operationFixture(family, mutate));
    // A different principal or an old event is still structurally valid; identity-link and event-link proofs reject it.
    const result = inspect(operationFixture(family, event => { event.userIdentity.principalId = 'AIDAOTHERUSER0000000'; event.eventTime = '2020-01-01T00:00:00Z'; }));
    for (const name of ['actorId', 'actorArn', 'actorAccount', 'eventTime', 'outerTime']) assert.match(result.bindings[name].hash, /^[a-f0-9]{64}$/);
  }
});

test('existing operations accept the shapes real CloudTrail samples record', () => {
  const lambda = activityEventFixture('lambda', { mutateEvent: event => {
    event.requestParameters = { functionName: 'synthetic-function', timeout: 15, memorySize: 256, environment: {} };
    event.responseElements = ACTIVITY_EVENTS['lambda-code']({}).responseElements;
  } });
  assert.equal(inspect(lambda).activity, 'lambda-configuration-update');
  assert.equal(inspect(activityEventFixture('lambda', { mutateEvent: event => { event.requestParameters = { functionName: 'fn', environment: {} }; } })).activity,
    'lambda-configuration-update');
  const network = mutateEvent => activityEventFixture('network', { mutateEvent: event => {
    Object.assign(event.requestParameters.ipPermissions.items[0], { groups: {}, ipv6Ranges: {}, prefixListIds: {} });
    event.responseElements.securityGroupRuleSet.items[0].securityGroupRuleArn = 'arn:aws:ec2:us-east-1:111122223333:security-group-rule/sgr-0123456789abcdef0';
    mutateEvent?.(event);
  } });
  assert.equal(inspect(network()).activity, 'security-group-ingress');
  for (const mutate of [event => { event.requestParameters.ipPermissions = {}; },
    event => { event.requestParameters.ipPermissions.items[0].groups = { other: [] }; },
    event => { event.requestParameters.ipPermissions.items[0].groups = { items: {} }; },
    event => { event.responseElements = null; }]) rejects(network(mutate));
  for (const mutate of [event => { event.responseElements = { ...ACTIVITY_EVENTS['lambda-code']({}).responseElements, kmsKeyArn: 'private' }; },
    event => { event.responseElements = { ...ACTIVITY_EVENTS['lambda-code']({}).responseElements, environment: { variables: 'private' } }; },
    event => { event.responseElements = { timeout: 3 }; }]) rejects(activityEventFixture('lambda', { mutateEvent: mutate }));
});

test('new operations: reviewed variations pass, service-specific traps are rejected', () => {
  const accepts = (family, mutateEvent) => assert.equal(inspect(activityEventFixture(family, { mutateEvent })).activity, operationCases[family].id);
  const refuses = (family, mutateEvent) => rejects(activityEventFixture(family, { mutateEvent }));
  // Values stay private whatever their content: booleans may be either, S3 user agents come in brackets.
  accepts('lambda-code', event => { event.requestParameters.publish = true; });
  accepts('ttl', event => { event.requestParameters.timeToLiveSpecification.enabled = false; event.responseElements.timeToLiveSpecification.enabled = false; });
  accepts('s3-versioning', event => { event.userAgent = '[aws-cli/2.0 synthetic]'; event.tlsDetails.keyExchange = 'X25519'; });
  accepts('ecs', event => { delete event.requestParameters.dryrun; });
  for (const [family, mutate] of [
    ['iam-attach', event => { delete event.requestParameters.policyArn; }],
    ['lambda-code', event => { event.requestParameters.publish = 'false'; }],
    ['lambda-code', event => { event.requestParameters.zipFile = 'private'; }],
    ['lambda-code', event => { event.responseElements = null; }],
    ['lambda-code', event => { delete event.responseElements.functionName; }],
    ['lambda-code', event => { event.responseElements.architectures = 'x86_64'; }],
    ['s3-versioning', event => { event.additionalEventData.unreviewed = 'private'; }],
    ['s3-versioning', event => { event.apiVersion = '2006-03-01'; }],
    ['s3-versioning', event => { delete event.requestParameters.VersioningConfiguration; }],
    ['s3-versioning', event => { event.requestParameters.VersioningConfiguration.MfaDelete = 'Disabled'; }],
    ['s3-lifecycle', event => { const rule = event.requestParameters.LifecycleConfiguration.Rule; event.requestParameters.LifecycleConfiguration.Rule = [rule, rule]; }],
    ['s3-lifecycle', event => { event.requestParameters.LifecycleConfiguration.Rule.Expiration = { Days: 1 }; }],
    ['changeset', event => { event.requestParameters.stackName = 'arn:aws:cloudformation:us-east-1:111122223333:stack/synthetic-stack/id'; }],
    ['changeset', event => { event.responseElements = null; }],
    ['ecs', event => { event.requestParameters.dryrun = true; }],
    ['ecs', event => { event.requestParameters.containerDefinitions = []; }],
    ['ecs', event => { event.requestParameters.containerDefinitions = { name: 'app' }; }],
    ['ecs', event => { event.responseElements.taskDefinition.volumes = [{ name: 'private' }]; }],
    ['ecs', event => { event.responseElements.taskDefinition.containerDefinitions[0].portMappings = [{ containerPort: 80 }]; }],
    ['ttl', event => { event.requestParameters.timeToLiveSpecification.enabled = 'true'; }],
    ['ttl', event => { delete event.apiVersion; event.errorCode = 'ValidationException'; event.errorMessage = 'private'; }],
    ['alarm', event => { event.requestParameters.dimensions = { name: 'FunctionName' }; }],
    ['alarm', event => { event.responseElements = {}; }],
  ]) refuses(family, mutate);
  // A name outside the resource grammar (an alarm name with spaces) passes this structural check; discovery never
  // selects it and the event-link proof would fail on it.
  // Service-specific top-level keys are allowed only on their own operation.
  rejects(eventFixture({ mutateEvent: event => { event.additionalEventData = { ...ACTIVITY_EVENTS['s3-versioning']({}).additionalEventData }; } }));
  rejects(eventFixture({ mutateEvent: event => { event.apiVersion = '2012-08-10'; } }));
  accepts('ttl', event => { delete event.apiVersion; });
});
