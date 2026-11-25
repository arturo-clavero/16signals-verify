/**
 * The AWS operations accepted as activity evidence. Activity evidence only: neither configuration
 * correctness nor downstream outcomes.
 *
 * Exports:
 *   AWS_SKILL_AREAS    [{ id, label }]; ids are stable. Their order is the selection order: a run proves one
 *                      event per area, areas in this order, up to the event-session cap (sessions.mjs). An area may
 *                      have no operation yet when only skill groups (skill-groups.mjs) roll up to it.
 *   AWS_OPERATIONS     one frozen entry per operation; within an area, earlier entries are preferred:
 *     id               stable id carried in verified results; never rename.
 *     skillArea        an AWS_SKILL_AREAS id. Never change it once shipped: stored results are read back
 *                      against the area this catalog gives their id, so a move would invalidate them.
 *     label            short human label.
 *     eventSource      CloudTrail eventSource.
 *     eventNames       accepted CloudTrail eventName values (the first one is used for discovery).
 *     resource         requestParameters key holding the resource name. It must be a required private
 *                      string, and its JSON value must fit AWS_RESOURCE_NAME (the event-link circuit grammar).
 *     readOnly         always false: only mutating calls count. A dryRun key, when allowed, must be literal false.
 *     request          allowed requestParameters tree.
 *     response         allowed responseElements shape.
 *     event            optional: extra top-level event keys this service records (an object node, none required).
 *   awsOperation(eventSource, eventName)  the matching entry or undefined.
 *
 * Tree nodes: { atom: kind | [kinds], minBytes? } is a private value committed by a proof (kinds: 1 string,
 * 2 number, 3 true, 4 false, 5 null; minBytes counts the JSON bytes incl. quotes); { literal: value } is a
 * public JSON literal; { object: { key: node }, required?, atLeastOne?, nullable? } is an object with only
 * those keys (no keys: must be empty; nullable: a public null is accepted too); { array: node | null, nonEmpty? }
 * is a JSON array of node (null: must be empty); { list: node, nonEmpty? } is the EC2 `{ "items": [node, ...] }`
 * wrapper, which EC2 records as `{}` when empty. Any key not listed is rejected. The verifier walks this tree,
 * so every new entry must be reviewed against a real CloudTrail sample, and only keys seen there are allowed.
 * Only values the session planner publishes can be literals (requestParameters.dryRun, a null responseElements,
 * EC2 `_return`); everything else is a private atom.
 */
export const AWS_RESOURCE_NAME = Object.freeze({ minBytes: 3, maxBytes: 66, pattern: /^[A-Za-z0-9_+=,.@-]+$/ });

const text = Object.freeze({ atom: 1 }), number = Object.freeze({ atom: 2 }), flag = Object.freeze({ atom: [3, 4] });
const hiddenFalse = Object.freeze({ atom: 4 }), empty = Object.freeze({ array: null });
const literal = value => ({ literal: value });
const object = (keys, required = [], atLeastOne) => ({ object: keys, required, ...(atLeastOne ? { atLeastOne } : {}) });
const list = (node, nonEmpty = false) => ({ list: node, nonEmpty });
const array = node => ({ array: node });
const texts = keys => Object.fromEntries(keys.map(name => [name, text]));
const numbers = keys => Object.fromEntries(keys.map(name => [name, number]));

export const AWS_SKILL_AREAS = Object.freeze([
  Object.freeze({ id: 'iam-security', label: 'IAM and security' }),
  Object.freeze({ id: 'serverless', label: 'Serverless' }),
  Object.freeze({ id: 'networking', label: 'Networking' }),
  Object.freeze({ id: 'storage', label: 'Storage' }),
  Object.freeze({ id: 'infrastructure-as-code', label: 'Infrastructure as code' }),
  Object.freeze({ id: 'containers', label: 'Containers' }),
  Object.freeze({ id: 'database', label: 'Database' }),
  Object.freeze({ id: 'monitoring', label: 'Monitoring' }),
  // No operation here yet: the skill groups of skill-groups.mjs roll up to it.
  Object.freeze({ id: 'compute', label: 'Compute' }),
]);

// Lambda returns the function configuration after a configuration or code update.
const lambdaFunction = () => object({
  ...texts(['functionName', 'functionArn', 'runtime', 'role', 'handler', 'description', 'lastModified', 'codeSha256', 'version',
    'revisionId', 'state', 'lastUpdateStatus', 'lastUpdateStatusReason', 'lastUpdateStatusReasonCode', 'packageType']),
  ...numbers(['codeSize', 'timeout', 'memorySize']), environment: object({}), tracingConfig: object({ mode: text }),
  architectures: array(text), ephemeralStorage: object({ size: number }), snapStart: object(texts(['applyOn', 'optimizationStatus'])),
  runtimeVersionConfig: object({ runtimeVersionArn: text }), loggingConfig: object(texts(['logFormat', 'logGroup'])),
}, ['functionName']);
// S3 records the request host, the empty subresource query key and transfer details next to the parsed XML body.
const s3Event = object({ additionalEventData: object({
  ...texts(['SignatureVersion', 'CipherSuite', 'AuthenticationMethod', 'x-amz-id-2']),
  ...numbers(['bytesTransferredIn', 'bytesTransferredOut', 'startTime', 'endTime', 'turnAroundTime', 'httpStatusCode']),
}) });

const operations = [
  { id: 'iam-role-trust-update', skillArea: 'iam-security', label: 'IAM role trust-policy updates',
    eventSource: 'iam.amazonaws.com', eventNames: ['UpdateAssumeRolePolicy'], resource: 'roleName', readOnly: false,
    request: object({ roleName: text, policyDocument: { atom: 1, minBytes: 3 }, dryRun: literal(false) }, ['roleName', 'policyDocument']),
    response: literal(null) },
  { id: 'lambda-configuration-update', skillArea: 'serverless', label: 'Lambda configuration updates',
    eventSource: 'lambda.amazonaws.com', eventNames: ['UpdateFunctionConfiguration20150331v2'], resource: 'functionName', readOnly: false,
    request: object({ functionName: text, ...texts(['description', 'handler', 'runtime', 'role', 'revisionId']),
      timeout: number, memorySize: number, environment: object({}), dryRun: literal(false) }, ['functionName'],
    ['description', 'timeout', 'memorySize', 'handler', 'runtime', 'role', 'environment']),
    response: { ...lambdaFunction(), nullable: true } },
  { id: 'security-group-ingress', skillArea: 'networking', label: 'Security-group ingress authorizations',
    eventSource: 'ec2.amazonaws.com', eventNames: ['AuthorizeSecurityGroupIngress'], resource: 'groupId', readOnly: false,
    request: object({ groupId: text, dryRun: literal(false), ipPermissions: list(object({
      ipProtocol: text, fromPort: number, toPort: number,
      ipRanges: list(object(texts(['cidrIp', 'description']))),
      ipv6Ranges: list(object(texts(['cidrIpv6', 'description']))),
      groups: list(object(texts(['groupId', 'userId', 'vpcId', 'vpcPeeringConnectionId', 'description']))),
      prefixListIds: list(object(texts(['prefixListId', 'description']))),
    }, ['ipProtocol']), true) }, ['groupId', 'ipPermissions']),
    response: object({ requestId: text, _return: literal(true), securityGroupRuleSet: list(object({
      ...texts(['securityGroupRuleId', 'securityGroupRuleArn', 'groupId', 'groupOwnerId', 'ipProtocol', 'cidrIpv4', 'cidrIpv6',
        'description', 'prefixListId']),
      isEgress: hiddenFalse, fromPort: number, toPort: number,
    })) }, ['_return']) },
  { id: 'iam-role-policy-attach', skillArea: 'iam-security', label: 'IAM role policy attachments',
    eventSource: 'iam.amazonaws.com', eventNames: ['AttachRolePolicy'], resource: 'roleName', readOnly: false,
    request: object(texts(['roleName', 'policyArn']), ['roleName', 'policyArn']),
    response: literal(null) },
  { id: 'lambda-code-update', skillArea: 'serverless', label: 'Lambda code updates',
    eventSource: 'lambda.amazonaws.com', eventNames: ['UpdateFunctionCode20150331v2'], resource: 'functionName', readOnly: false,
    request: object({ functionName: text, publish: flag, dryRun: literal(false) }, ['functionName']),
    response: lambdaFunction() },
  { id: 's3-bucket-versioning', skillArea: 'storage', label: 'S3 bucket versioning changes',
    eventSource: 's3.amazonaws.com', eventNames: ['PutBucketVersioning'], resource: 'bucketName', readOnly: false,
    request: object({ ...texts(['bucketName', 'Host', 'versioning']),
      VersioningConfiguration: object(texts(['Status', 'xmlns']), ['Status']) }, ['bucketName', 'VersioningConfiguration']),
    response: literal(null), event: s3Event },
  { id: 's3-bucket-lifecycle', skillArea: 'storage', label: 'S3 bucket lifecycle rules',
    eventSource: 's3.amazonaws.com', eventNames: ['PutBucketLifecycle'], resource: 'bucketName', readOnly: false,
    request: object({ ...texts(['bucketName', 'Host', 'lifecycle']), LifecycleConfiguration: object({ xmlns: text,
      Rule: object({ ...texts(['ID', 'Status']), Filter: object({ Prefix: text }),
        NoncurrentVersionExpiration: object({ NoncurrentDays: number }, ['NoncurrentDays']) }, ['Status']),
    }, ['Rule']) }, ['bucketName', 'LifecycleConfiguration']),
    response: literal(null), event: s3Event },
  { id: 'cloudformation-change-set', skillArea: 'infrastructure-as-code', label: 'CloudFormation change sets',
    eventSource: 'cloudformation.amazonaws.com', eventNames: ['CreateChangeSet'], resource: 'stackName', readOnly: false,
    request: object(texts(['stackName', 'changeSetName']), ['stackName', 'changeSetName']),
    response: object({ id: text }, ['id']) },
  { id: 'ecs-task-definition', skillArea: 'containers', label: 'ECS task-definition registrations',
    eventSource: 'ecs.amazonaws.com', eventNames: ['RegisterTaskDefinition'], resource: 'family', readOnly: false,
    request: object({ ...texts(['family', 'networkMode', 'cpu', 'memory']), requiresCompatibilities: array(text),
      containerDefinitions: { ...array(object({ ...texts(['name', 'image']), cpu: number, essential: flag }, ['name', 'image'])), nonEmpty: true },
      dryrun: hiddenFalse }, ['family', 'containerDefinitions']),
    response: object({ taskDefinition: object({
      ...texts(['taskDefinitionArn', 'family', 'networkMode', 'status', 'cpu', 'memory', 'registeredAt', 'registeredBy']),
      revision: number, containerDefinitions: array(object({ ...texts(['name', 'image', 'environment']), cpu: number, essential: flag,
        portMappings: empty, mountPoints: empty, volumesFrom: empty, systemControls: empty })),
      volumes: empty, placementConstraints: empty, requiresAttributes: array(object({ name: text }, ['name'])),
      compatibilities: array(text), requiresCompatibilities: array(text),
    }, ['taskDefinitionArn', 'family']) }, ['taskDefinition']) },
  { id: 'dynamodb-ttl-update', skillArea: 'database', label: 'DynamoDB time-to-live updates',
    eventSource: 'dynamodb.amazonaws.com', eventNames: ['UpdateTimeToLive'], resource: 'tableName', readOnly: false,
    request: object({ tableName: text, timeToLiveSpecification: object({ attributeName: text, enabled: flag }, ['attributeName', 'enabled']) },
      ['tableName', 'timeToLiveSpecification']),
    response: object({ timeToLiveSpecification: object({ attributeName: text, enabled: flag }, ['attributeName', 'enabled']) },
      ['timeToLiveSpecification']),
    event: object({ apiVersion: text }) },
  // Alarm names with spaces or other characters outside AWS_RESOURCE_NAME are not accepted. SQS SetQueueAttributes
  // is not listed: its only resource field, queueUrl, does not fit AWS_RESOURCE_NAME.
  { id: 'cloudwatch-metric-alarm', skillArea: 'monitoring', label: 'CloudWatch metric alarms',
    eventSource: 'monitoring.amazonaws.com', eventNames: ['PutMetricAlarm'], resource: 'alarmName', readOnly: false,
    request: object({ ...texts(['alarmName', 'metricName', 'namespace', 'statistic', 'comparisonOperator']),
      ...numbers(['period', 'evaluationPeriods', 'threshold']), dimensions: array(object(texts(['name', 'value']), ['name', 'value'])) },
    ['alarmName', 'evaluationPeriods', 'comparisonOperator']),
    response: literal(null) },
];

function checkNode(node) {
  const keys = Object.keys(node ?? {});
  const only = (...names) => keys.every(name => names.includes(name));
  const kind = value => Number.isInteger(value) && value >= 1 && value <= 5;
  if (Object.hasOwn(node ?? {}, 'atom')) {
    const kinds = Array.isArray(node.atom) ? node.atom : [node.atom];
    if (!only('atom', 'minBytes') || !kinds.length || !kinds.every(kind) || new Set(kinds).size !== kinds.length ||
        (Array.isArray(node.atom) && kinds.length < 2) ||
        (node.minBytes !== undefined && (node.atom !== 1 || !Number.isInteger(node.minBytes)))) return false;
  } else if (Object.hasOwn(node ?? {}, 'literal')) {
    if (!only('literal') || ![null, true, false].includes(node.literal)) return false;
  } else if (Object.hasOwn(node ?? {}, 'object')) {
    const names = Object.keys(node.object ?? {});
    if (!only('object', 'required', 'atLeastOne', 'nullable') || !node.object || typeof node.object !== 'object' ||
        !names.every(name => checkNode(node.object[name])) ||
        !Array.isArray(node.required) || !node.required.every(name => names.includes(name)) ||
        (node.nullable !== undefined && node.nullable !== true) ||
        (node.atLeastOne !== undefined && (!node.atLeastOne.length ||
          !node.atLeastOne.every(name => names.includes(name) && !node.required.includes(name))))) return false;
  } else if (Object.hasOwn(node ?? {}, 'array')) {
    if (!only('array', 'nonEmpty') || (node.nonEmpty !== undefined && node.nonEmpty !== true) ||
        (node.array === null ? node.nonEmpty !== undefined : !checkNode(node.array))) return false;
  } else if (Object.hasOwn(node ?? {}, 'list')) {
    if (!only('list', 'nonEmpty') || typeof node.nonEmpty !== 'boolean' || !checkNode(node.list)) return false;
  } else return false;
  return true;
}

const deepFreeze = value => {
  if (value && typeof value === 'object' && !(value instanceof RegExp)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
};

/** Throws unless every entry follows the rules above; run on the catalog when this module loads. */
export function assertAwsOperationCatalog(entries) {
  const ids = new Set(), events = new Set();
  for (const entry of entries) {
    const resource = entry?.request?.object?.[entry.resource];
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(entry?.id) || ids.has(entry.id) ||
        !AWS_SKILL_AREAS.some(area => area.id === entry.skillArea) ||
        !/^[a-z0-9-]+\.amazonaws\.com$/.test(entry.eventSource) || !Array.isArray(entry.eventNames) || !entry.eventNames.length ||
        entry.eventNames.some(name => !/^[A-Za-z0-9]+$/.test(name) || events.has(`${entry.eventSource} ${name}`)) ||
        entry.readOnly !== false || !checkNode(entry.request) || !entry.request.object || !checkNode(entry.response) ||
        entry.request.nullable || Object.keys(entry.request.object).length === 0 ||
        (entry.event !== undefined && (!checkNode(entry.event) || !entry.event.object || entry.event.required.length ||
          entry.event.atLeastOne || entry.event.nullable || !Object.keys(entry.event.object).length)) ||
        resource?.atom !== 1 || resource.minBytes !== undefined || !entry.request.required.includes(entry.resource) ||
        (entry.request.object.dryRun !== undefined && entry.request.object.dryRun.literal !== false)) {
      throw new Error(`AWS_OPERATION_CATALOG_INVALID:${entry?.id}`);
    }
    ids.add(entry.id);
    for (const name of entry.eventNames) events.add(`${entry.eventSource} ${name}`);
  }
}

assertAwsOperationCatalog(operations);
export const AWS_OPERATIONS = deepFreeze(operations);

export function awsOperation(eventSource, eventName) {
  return AWS_OPERATIONS.find(entry => entry.eventSource === eventSource && entry.eventNames.includes(eventName));
}
