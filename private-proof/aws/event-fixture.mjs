import { createHash } from 'node:crypto';
import { parseJsonStructure } from '../gcp/json-structure.mjs';

// Synthetic receipts only: these helpers make no AWS requests and authenticate no TLS.
export const fixtureNow = 1_800_000_000_000;
export const fixtureExpected = { sessionId: '11111111-1111-4111-8111-111111111111', proofId: '22222222-2222-4222-8222-222222222222',
  pluginSha256: 'ab'.repeat(32), nonceMac: 'N'.repeat(43), step: 'E0', identityService: 'iam', region: 'us-east-1',
  issuedAt: fixtureNow - 1000, expiresAt: fixtureNow + 1000 };

/** Reconstruct local plaintext/openings for tests only; never native authentication. */
export function syntheticWitness({ receipt, openings }) {
  const witness = { sessionId: receipt.session.id, serverName: receipt.server_name, step: receipt.session.step,
    proofId: receipt.session.proofId, nonceMac: receipt.session.nonceMac, selections: {}, openings: {} };
  for (const direction of ['sent', 'recv']) {
    const bytes = Uint8Array.from(Buffer.from(receipt.transcript[direction]));
    const results = receipt.results.filter(row => row.type === direction.toUpperCase());
    witness.selections[direction] = structuredClone(receipt.config[direction]); witness.openings[direction] = [];
    receipt.config[direction].forEach((range, index) => {
      if (range.handler.action.kind !== 'HASH') return;
      const hash = results[index].value, preimage = openings.get(hash), length = range.end - range.start;
      if (preimage?.length !== length + 16) throw new Error('SYNTHETIC_OPENING_INVALID');
      bytes.set(preimage.subarray(0, length), range.start);
      witness.openings[direction].push({ start: range.start, end: range.end,
        hash: Uint8Array.from(Buffer.from(hash, 'hex')), blinder: Uint8Array.from(preimage.subarray(length)) });
    });
    witness[direction] = bytes;
  }
  return witness;
}
export function eventFixture(options = {}) {
  const eventId = options.eventId ?? 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const event = { eventVersion: '1.11', eventTime: '2026-10-29T08:00:00Z', eventID: eventId,
    eventName: 'UpdateAssumeRolePolicy', eventSource: 'iam.amazonaws.com', awsRegion: 'us-east-1',
    eventType: 'AwsApiCall', eventCategory: 'Management', managementEvent: true, readOnly: false,
    recipientAccountId: '111122223333', userIdentity: { type: 'IAMUser', principalId: 'AIDAEXAMPLESYNTHETIC01',
      arn: 'arn:aws:iam::111122223333:user/synthetic', accountId: '111122223333', userName: 'AWS_PRIVATE_USER_SENTINEL',
      accessKeyId: 'AWS_PRIVATE_KEY_SENTINEL', sessionContext: { attributes: { creationDate: '2026-10-29T07:00:00Z', mfaAuthenticated: 'true' } } },
    requestParameters: { roleName: 'AWS_PRIVATE_ROLE_SENTINEL', policyDocument: '{"Version":"2012-10-17","Statement":[]}' },
    responseElements: null, sourceIPAddress: '192.0.2.1', userAgent: 'AWS_PRIVATE_AGENT_SENTINEL', requestID: eventId,
    tlsDetails: { tlsVersion: 'TLSv1.2', cipherSuite: 'SYNTHETIC', clientProvidedHostHeader: 'iam.amazonaws.com' } };
  options.mutateEvent?.(event);
  const request = { LookupAttributes: [{ AttributeKey: 'EventId', AttributeValue: eventId }], MaxResults: 1 };
  options.mutateRequest?.(request);
  const row = { EventId: eventId, EventName: 'UpdateAssumeRolePolicy', EventSource: 'iam.amazonaws.com',
    EventTime: Date.parse('2026-10-29T08:00:00Z') / 1000, ReadOnly: 'false', Username: 'AWS_PRIVATE_USER_SENTINEL',
    CloudTrailEvent: JSON.stringify(event), Resources: [{ ResourceName: 'AWS_PRIVATE_RESOURCE_SENTINEL', ResourceType: 'AWS::IAM::Role' }] };
  options.mutateRow?.(row);
  const requestBody = Buffer.from(JSON.stringify(request)), responseBody = Buffer.from(JSON.stringify({ Events: [row] }));
  const eventBody = Buffer.from(row.CloudTrailEvent);
  let sequence = 0;
  const openings = new Map();
  const digest = bytes => {
    const blinder = options.blinderSeed === undefined ? Buffer.alloc(16, ++sequence) :
      createHash('sha256').update(`${options.blinderSeed}:${++sequence}`).digest().subarray(0, 16);
    const preimage = Buffer.concat([bytes, blinder]);
    const hash = createHash('sha256').update(preimage).digest('hex');
    openings.set(hash, preimage);
    return hash;
  };
  const slots = (bytes, publicPaths) => {
    const output = [];
    const visit = (node, path) => {
      if (publicPaths.has(path)) return;
      if (node.type === 'object') for (const entry of node.entries) visit(entry.value, path ? `${path}.${entry.key.value}` : entry.key.value);
      else if (node.type === 'array') node.items.forEach((item, index) => visit(item, `${path}.${index}`));
      else output.push({ start: node.start, end: node.end, kind: node.kind, hash: digest(bytes.subarray(node.start, node.end)), layer: 'outer' });
    };
    visit(parseJsonStructure(bytes).root, '');
    return output;
  };
  const requestSlots = slots(requestBody, new Set(['LookupAttributes.0.AttributeKey', 'MaxResults']));
  const responseSlots = slots(responseBody, new Set(['Events.0.EventName', 'Events.0.EventSource', 'Events.0.ReadOnly', 'Events.0.CloudTrailEvent']));
  const publicEvent = new Set(['eventVersion', 'eventName', 'eventSource', 'awsRegion', 'eventType', 'eventCategory',
    'managementEvent', 'readOnly', ...(event.responseElements === null ? ['responseElements'] : []),
    ...(event.eventSource === 'ec2.amazonaws.com' ? ['responseElements._return'] : []),
    'userIdentity.type', 'requestParameters.dryRun', ...(options.publicEvent ?? [])]);
  const eventStart = responseBody.indexOf(Buffer.from('"CloudTrailEvent":"')) + Buffer.byteLength('"CloudTrailEvent":"');
  for (const slot of slots(eventBody, publicEvent)) {
    const prefix = JSON.stringify(eventBody.subarray(0, slot.start).toString()).slice(1, -1);
    const atom = JSON.stringify(eventBody.subarray(slot.start, slot.end).toString()).slice(1, -1);
    const start = eventStart + Buffer.byteLength(prefix);
    responseSlots.push({ start, end: start + Buffer.byteLength(atom), layer: 'event', kind: slot.kind,
      hash: digest(Buffer.from(atom)), decodedHash: slot.hash, decodedLength: slot.end - slot.start });
  }
  responseSlots.sort((a, b) => a.start - b.start);
  const requestHeaders = [
    ['host', 'cloudtrail.us-east-1.amazonaws.com'], ['connection', 'close'], ['accept-encoding', 'identity'],
    ['content-type', 'application/x-amz-json-1.1'], ['x-tlsn-nonce', fixtureExpected.nonceMac],
    ['x-amz-target', 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents'],
    ['authorization', 'SYNTHETIC_PRIVATE_AUTHORIZATION', true], ['x-amz-date', '20261029T080000Z', true],
    ['x-amz-security-token', 'SYNTHETIC_PRIVATE_SESSION_TOKEN', true],
  ];
  const responseHeaders = [['content-type', 'application/x-amz-json-1.1'], ['connection', 'close'],
    ['x-amzn-requestid', 'SYNTHETIC_PRIVATE_REQUEST_ID', true], ['date', 'Thu, 29 Oct 2026 08:00:00 GMT', true]];
  options.mutateHeaders?.(requestHeaders, responseHeaders);
  const receipt = { server_name: 'cloudtrail.us-east-1.amazonaws.com', session: {
    id: fixtureExpected.sessionId, proofId: fixtureExpected.proofId, pluginSha256: fixtureExpected.pluginSha256,
    nonceMac: fixtureExpected.nonceMac, step: 'E0', method: 'AWS_ACCOUNT', mode: 'Proxy' }, config: {}, results: [], transcript: {} };
  const claims = [];
  function direction(name, body, bodySlots, headers, startLine, chunkAt) {
    let text = startLine + '\r\n';
    const ranges = [];
    for (const [name, value, hidden] of headers) {
      const start = Buffer.byteLength(text + name + ': ');
      text += `${name}: ${value}\r\n`;
      if (hidden) ranges.push({ start, end: start + Buffer.byteLength(value), hash: digest(Buffer.from(value)) });
    }
    text += chunkAt === undefined ? `content-length: ${body.length}\r\n\r\n` : 'transfer-encoding: chunked\r\n\r\n';
    const prefix = Buffer.from(text), parts = [prefix], indices = [];
    let position = prefix.length;
    if (chunkAt === undefined) {
      parts.push(body);
      for (let i = 0; i < body.length; i++) indices.push(position + i);
    } else {
      let start = 0;
      for (const end of [chunkAt, body.length]) {
        const line = Buffer.from((end - start).toString(16) + '\r\n');
        parts.push(line, body.subarray(start, end), Buffer.from('\r\n'));
        position += line.length;
        for (let i = start; i < end; i++) indices.push(position + i - start);
        position += end - start + 2; start = end;
      }
      parts.push(Buffer.from('0\r\n\r\n'));
    }
    for (const slot of bodySlots) {
      const mapped = { ...slot, direction: name.toUpperCase(), start: indices[slot.start], end: indices[slot.end - 1] + 1 };
      claims.push(mapped); ranges.push(mapped);
    }
    const bytes = Buffer.concat(parts);
    ranges.sort((a, b) => a.start - b.start);
    for (const range of ranges) bytes.fill(0, range.start, range.end);
    const config = [];
    const append = (start, end, hash) => {
      const handler = { type: name.toUpperCase(), part: 'BODY', action: hash ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } };
      config.push({ start, end, handler });
      receipt.results.push({ ...handler, value: hash ?? bytes.subarray(start, end).toString() });
    };
    let cursor = 0;
    for (const range of ranges) {
      if (cursor < range.start) append(cursor, range.start);
      append(range.start, range.end, range.hash); cursor = range.end;
    }
    if (cursor < bytes.length) append(cursor, bytes.length);
    receipt.config[name] = config;
    receipt.transcript[name] = bytes.toString(); receipt.transcript[`${name}_length`] = bytes.length;
  }
  direction('sent', requestBody, requestSlots, requestHeaders, options.startLine ?? 'POST / HTTP/1.1');
  const split = options.crossChunk ? responseSlots[0].start + 1 : options.chunked ? 10 : undefined;
  direction('recv', responseBody, responseSlots, responseHeaders, options.statusLine ?? 'HTTP/1.1 200 OK', split);
  return { receipt, expected: { ...fixtureExpected }, claims, openings };
}

// Synthetic events shaped like reviewed CloudTrail samples of each catalog operation; every value is made up.
const lambdaResponse = name => ({ functionName: name, functionArn: `arn:aws:lambda:us-east-1:111122223333:function:${name}`,
  runtime: 'nodejs20.x', role: 'arn:aws:iam::111122223333:role/synthetic-role', handler: 'index.handler', codeSize: 300,
  description: '', timeout: 15, memorySize: 256, lastModified: '2026-10-29T08:00:00.000+0000', codeSha256: 'c3ludGhldGljLWNvZGUtc2hhMjU2LXZhbHVl',
  version: '$LATEST', environment: {}, tracingConfig: { mode: 'PassThrough' }, revisionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  state: 'Active', lastUpdateStatus: 'InProgress', lastUpdateStatusReason: 'The function is being created.',
  lastUpdateStatusReasonCode: 'Creating', packageType: 'Zip', architectures: ['x86_64'], ephemeralStorage: { size: 512 },
  snapStart: { applyOn: 'None', optimizationStatus: 'Off' },
  runtimeVersionConfig: { runtimeVersionArn: 'arn:aws:lambda:us-east-1::runtime:synthetic' },
  loggingConfig: { logFormat: 'Text', logGroup: `/aws/lambda/${name}` } });
const s3Data = { SignatureVersion: 'SigV4', CipherSuite: 'TLS_AES_128_GCM_SHA256', bytesTransferredIn: 100, startTime: 1800000000000,
  AuthenticationMethod: 'AuthHeader', endTime: 1800000000080, 'x-amz-id-2': 'c3ludGhldGljLWFtei1pZC0y', httpStatusCode: 200,
  bytesTransferredOut: 0 };
const s3Host = 'synthetic-bucket.s3.us-east-1.amazonaws.com';
export const ACTIVITY_EVENTS = Object.freeze({
  lambda: () => ({ eventName: 'UpdateFunctionConfiguration20150331v2', eventSource: 'lambda.amazonaws.com',
    requestParameters: { functionName: 'AWS_PRIVATE_FUNCTION_SENTINEL', timeout: 10 } }),
  network: event => ({ eventName: 'AuthorizeSecurityGroupIngress', eventSource: 'ec2.amazonaws.com',
    requestParameters: { groupId: 'sg-0123456789abcdef0', ipPermissions: { items: [
      { ipProtocol: 'tcp', fromPort: 443, toPort: 443, ipRanges: { items: [{ cidrIp: '192.0.2.0/24' }] } },
    ] } },
    responseElements: { _return: true, requestId: event.eventID, securityGroupRuleSet: { items: [
      { securityGroupRuleId: 'sgr-0123456789abcdef0', groupId: 'sg-0123456789abcdef0', isEgress: false,
        ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIpv4: '192.0.2.0/24' },
    ] } } }),
  'iam-attach': () => ({ eventName: 'AttachRolePolicy', eventSource: 'iam.amazonaws.com',
    requestParameters: { roleName: 'synthetic-role', policyArn: 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole' } }),
  'lambda-code': () => ({ eventName: 'UpdateFunctionCode20150331v2', eventSource: 'lambda.amazonaws.com',
    requestParameters: { functionName: 'synthetic-function', publish: false, dryRun: false },
    responseElements: lambdaResponse('synthetic-function') }),
  's3-versioning': () => ({ eventName: 'PutBucketVersioning', eventSource: 's3.amazonaws.com',
    requestParameters: { bucketName: 'synthetic-bucket', Host: s3Host, versioning: '',
      VersioningConfiguration: { Status: 'Enabled', xmlns: 'http://s3.amazonaws.com/doc/2006-03-01/' } },
    additionalEventData: { ...s3Data } }),
  's3-lifecycle': () => ({ eventName: 'PutBucketLifecycle', eventSource: 's3.amazonaws.com',
    requestParameters: { lifecycle: '', bucketName: 'synthetic-bucket', LifecycleConfiguration: {
      xmlns: 'http://s3.amazonaws.com/doc/2006-03-01/', Rule: { Status: 'Enabled', Filter: { Prefix: '' },
        NoncurrentVersionExpiration: { NoncurrentDays: 7 }, ID: 'expire-old' } }, Host: s3Host },
    additionalEventData: { ...s3Data, turnAroundTime: 80 } }),
  changeset: () => ({ eventName: 'CreateChangeSet', eventSource: 'cloudformation.amazonaws.com',
    requestParameters: { changeSetName: 'synthetic-change-set', stackName: 'synthetic-stack' },
    responseElements: { id: 'arn:aws:cloudformation:us-east-1:111122223333:changeSet/synthetic-change-set/cccccccc-cccc-4ccc-8ccc-cccccccccccc' } }),
  ecs: () => ({ eventName: 'RegisterTaskDefinition', eventSource: 'ecs.amazonaws.com',
    requestParameters: { family: 'synthetic-family', networkMode: 'awsvpc',
      containerDefinitions: [{ name: 'app', image: 'public.ecr.aws/docker/library/busybox:latest', cpu: 0, essential: true }],
      requiresCompatibilities: ['FARGATE'], cpu: '256', memory: '512', dryrun: false },
    responseElements: { taskDefinition: { taskDefinitionArn: 'arn:aws:ecs:us-east-1:111122223333:task-definition/synthetic-family:2',
      containerDefinitions: [{ name: 'app', image: 'public.ecr.aws/docker/library/busybox:latest', cpu: 0, portMappings: [],
        essential: true, environment: 'HIDDEN_DUE_TO_SECURITY_REASONS', mountPoints: [], volumesFrom: [], systemControls: [] }],
      family: 'synthetic-family', networkMode: 'awsvpc', revision: 2, volumes: [], status: 'ACTIVE',
      requiresAttributes: [{ name: 'com.amazonaws.ecs.capability.docker-remote-api.1.18' }, { name: 'ecs.capability.task-eni' }],
      placementConstraints: [], compatibilities: ['EC2', 'FARGATE', 'MANAGED_INSTANCES'], requiresCompatibilities: ['FARGATE'],
      cpu: '256', memory: '512', registeredAt: 'Oct 29, 2026, 8:00 AM', registeredBy: 'arn:aws:iam::111122223333:user/synthetic' } } }),
  ttl: () => ({ eventName: 'UpdateTimeToLive', eventSource: 'dynamodb.amazonaws.com', apiVersion: '2012-08-10',
    requestParameters: { tableName: 'synthetic-table', timeToLiveSpecification: { attributeName: 'expiresAt', enabled: true } },
    responseElements: { timeToLiveSpecification: { attributeName: 'expiresAt', enabled: true } } }),
  alarm: () => ({ eventName: 'PutMetricAlarm', eventSource: 'monitoring.amazonaws.com',
    requestParameters: { alarmName: 'synthetic-alarm', metricName: 'Errors', namespace: 'AWS/Lambda', statistic: 'Sum',
      dimensions: [{ name: 'FunctionName', value: 'synthetic-function' }], period: 300, evaluationPeriods: 1, threshold: 100.5,
      comparisonOperator: 'GreaterThanThreshold' } }),
});

/** Fixture family of each catalog operation id: 'iam' is eventFixture() itself, the rest are ACTIVITY_EVENTS keys. */
export const OPERATION_FAMILIES = Object.freeze({ 'iam-role-trust-update': 'iam', 'lambda-configuration-update': 'lambda',
  'security-group-ingress': 'network', 'iam-role-policy-attach': 'iam-attach', 'lambda-code-update': 'lambda-code',
  's3-bucket-versioning': 's3-versioning', 's3-bucket-lifecycle': 's3-lifecycle', 'cloudformation-change-set': 'changeset',
  'ecs-task-definition': 'ecs', 'dynamodb-ttl-update': 'ttl', 'cloudwatch-metric-alarm': 'alarm' });

export function activityEventFixture(activity, options = {}) {
  if (!Object.hasOwn(ACTIVITY_EVENTS, activity)) throw new Error('SYNTHETIC_ACTIVITY_UNKNOWN');
  return eventFixture({ ...options, mutateEvent(event) {
    Object.assign(event, ACTIVITY_EVENTS[activity](event));
    options.mutateEvent?.(event);
  }, mutateRow(row) { const event = JSON.parse(row.CloudTrailEvent); row.EventName = event.eventName; row.EventSource = event.eventSource; options.mutateRow?.(row); } });
}
