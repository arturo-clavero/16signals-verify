/**
 * Catalog v2: the AWS skill groups and the CloudTrail operations that count as evidence for each, by name only.
 * Activity evidence only: neither configuration correctness nor downstream outcomes.
 *
 * Exports:
 *   AWS_SKILL_GROUPS   [{ id, label, area, jobTags }], in display order. `area` is the AWS_SKILL_AREAS id the group
 *                      rolls up to (job match by area); `jobTags` are the job tags that name this group, compared after
 *                      normalising (lowercase, spaces and underscores to hyphens). A tag names one group only.
 *   AWS_CATALOG_OPERATIONS  one frozen entry per (eventSource, eventName):
 *     eventSource, eventName  as CloudTrail records them (each confirmed by an AWS doc or a live sample, see README).
 *     group            an AWS_SKILL_GROUPS id.
 *     tier             'basic' (creates or toggles one resource), 'intermediate' (configuration whose effect has to be
 *                      understood) or 'advanced' (cross-resource or security-critical design). The kind of work, never
 *                      its quality.
 *     auto             true when the call is usually made by CI or scripts rather than by hand.
 *   awsCatalogOperation(eventSource, eventName)  the matching entry or undefined.
 *
 * These entries match events by name. Proving an event still needs a full entry in operation-catalog.mjs (allowed
 * request and response trees reviewed from a real sample); every one of those is listed here too, in the group
 * that rolls up to its skill area.
 */
import { AWS_OPERATIONS, AWS_SKILL_AREAS } from './operation-catalog.mjs';

export const AWS_OPERATION_TIERS = Object.freeze(['basic', 'intermediate', 'advanced']);
const B = 'basic', I = 'intermediate', A = 'advanced', AUTO = true;

// [id, label, area, jobTags, operations: [eventSource prefix, eventName, tier, auto?]]
const groups = [
  ['iam-access', 'IAM roles and policies', 'iam-security', ['aws-iam', 'iam', 'iam-policies'], [
    ['iam', 'CreateRole', B], ['iam', 'AttachRolePolicy', B], ['iam', 'UpdateAssumeRolePolicy', I], ['iam', 'PutRolePolicy', I],
    ['iam', 'CreatePolicy', I], ['iam', 'CreatePolicyVersion', A], ['iam', 'PutRolePermissionsBoundary', A]]],
  ['identity-federation', 'Identity federation and SSO', 'iam-security',
    ['aws-iam-identity-center', 'aws-sso', 'sso', 'identity-federation', 'saml', 'oidc'], [
      ['sso', 'CreatePermissionSet', A], ['sso', 'PutInlinePolicyToPermissionSet', A], ['sso', 'AttachManagedPolicyToPermissionSet', I],
      ['sso', 'CreateAccountAssignment', I], ['iam', 'CreateOpenIDConnectProvider', A], ['iam', 'CreateSAMLProvider', A]]],
  ['org-governance', 'Organizations and governance', 'iam-security',
    ['aws-organizations', 'organizations', 'service-control-policies', 'scp', 'landing-zone'], [
      ['organizations', 'CreateAccount', I], ['organizations', 'CreateOrganizationalUnit', I], ['organizations', 'CreatePolicy', A],
      ['organizations', 'AttachPolicy', A]]],
  ['kms-keys', 'KMS keys', 'iam-security', ['aws-kms', 'kms', 'key-management', 'encryption'], [
    ['kms', 'CreateKey', I], ['kms', 'PutKeyPolicy', A], ['kms', 'EnableKeyRotation', I], ['kms', 'CreateAlias', B],
    ['kms', 'CreateGrant', A]]],
  ['secrets-config', 'Secrets and parameters', 'iam-security',
    ['aws-secrets-manager', 'secrets-manager', 'aws-ssm', 'parameter-store', 'secrets-management'], [
      ['secretsmanager', 'CreateSecret', B], ['secretsmanager', 'UpdateSecret', I], ['secretsmanager', 'RotateSecret', A],
      ['secretsmanager', 'PutResourcePolicy', A], ['ssm', 'PutParameter', B, AUTO]]],
  ['vpc-routing', 'VPC and routing', 'networking', ['aws-vpc', 'vpc', 'subnets', 'routing', 'nat-gateway', 'vpc-peering'], [
    ['ec2', 'CreateVpc', I], ['ec2', 'CreateSubnet', I], ['ec2', 'CreateRouteTable', I], ['ec2', 'CreateRoute', A],
    ['ec2', 'CreateInternetGateway', B], ['ec2', 'CreateNatGateway', A], ['ec2', 'CreateVpcEndpoint', A],
    ['ec2', 'CreateVpcPeeringConnection', A]]],
  ['network-access', 'Security groups and network ACLs', 'networking',
    ['aws-security-groups', 'security-groups', 'network-acls', 'nacl', 'network-security'], [
      ['ec2', 'AuthorizeSecurityGroupIngress', B], ['ec2', 'AuthorizeSecurityGroupEgress', I], ['ec2', 'RevokeSecurityGroupIngress', I],
      ['ec2', 'CreateSecurityGroup', B], ['ec2', 'ModifySecurityGroupRules', I], ['ec2', 'CreateNetworkAclEntry', A]]],
  ['load-balancing', 'Load balancing', 'networking', ['aws-elb', 'aws-alb', 'elb', 'alb', 'nlb', 'load-balancing'], [
    ['elasticloadbalancing', 'CreateLoadBalancer', I], ['elasticloadbalancing', 'CreateTargetGroup', I],
    ['elasticloadbalancing', 'CreateListener', A], ['elasticloadbalancing', 'ModifyListener', A],
    ['elasticloadbalancing', 'CreateRule', A], ['elasticloadbalancing', 'RegisterTargets', B, AUTO]]],
  ['dns', 'DNS (Route 53)', 'networking', ['aws-route53', 'route53', 'route-53', 'dns'], [
    ['route53', 'CreateHostedZone', I], ['route53', 'ChangeResourceRecordSets', I], ['route53', 'CreateHealthCheck', A],
    ['route53', 'AssociateVPCWithHostedZone', A]]],
  ['edge', 'CDN and edge security', 'networking', ['aws-cloudfront', 'cloudfront', 'cdn', 'aws-waf', 'waf'], [
    ['cloudfront', 'CreateDistribution', I], ['cloudfront', 'UpdateDistribution', I], ['cloudfront', 'CreateOriginAccessControl', A],
    ['cloudfront', 'CreateCachePolicy', A], ['cloudfront', 'CreateFunction', A], ['wafv2', 'CreateWebACL', A],
    ['wafv2', 'UpdateWebACL', A]]],
  ['compute', 'EC2 compute and scaling', 'compute', ['aws-ec2', 'ec2', 'aws-auto-scaling', 'auto-scaling', 'autoscaling'], [
    ['ec2', 'RunInstances', B], ['ec2', 'CreateLaunchTemplate', I], ['ec2', 'ModifyInstanceAttribute', I], ['ec2', 'CreateImage', I],
    ['autoscaling', 'CreateAutoScalingGroup', I], ['autoscaling', 'PutScalingPolicy', A], ['autoscaling', 'StartInstanceRefresh', A]]],
  ['lambda', 'Lambda functions', 'serverless', ['aws-lambda', 'lambda'], [
    ['lambda', 'CreateFunction20150331', B], ['lambda', 'UpdateFunctionCode20150331v2', B, AUTO],
    ['lambda', 'UpdateFunctionConfiguration20150331v2', I], ['lambda', 'PublishVersion20150331', I, AUTO],
    ['lambda', 'CreateAlias20150331', I], ['lambda', 'AddPermission20150331v2', I], ['lambda', 'CreateEventSourceMapping20150331', A],
    ['lambda', 'PutFunctionConcurrency20171031', A], ['lambda', 'PutProvisionedConcurrencyConfig', A]]],
  // REST (v1) and HTTP (v2) APIs share the event source and the CreateDeployment / CreateStage names: one entry each.
  ['api-gateway', 'API Gateway', 'serverless', ['aws-api-gateway', 'api-gateway', 'apigateway'], [
    ['apigateway', 'CreateRestApi', B], ['apigateway', 'PutIntegration', I], ['apigateway', 'CreateDeployment', I],
    ['apigateway', 'CreateStage', I], ['apigateway', 'CreateAuthorizer', A], ['apigateway', 'CreateApi', B],
    ['apigateway', 'CreateRoute', I]]],
  ['workflows', 'Step Functions workflows', 'serverless', ['aws-step-functions', 'step-functions', 'workflow-orchestration'], [
    ['states', 'CreateStateMachine', I], ['states', 'UpdateStateMachine', I], ['states', 'CreateActivity', I],
    ['states', 'PublishStateMachineVersion', A]]],
  ['event-routing', 'Event routing and schedules', 'serverless',
    ['aws-eventbridge', 'eventbridge', 'event-driven', 'aws-eventbridge-scheduler', 'eventbridge-pipes'], [
      ['events', 'PutRule', I], ['events', 'PutTargets', I], ['events', 'CreateEventBus', A], ['events', 'CreateArchive', A],
      ['scheduler', 'CreateSchedule', I], ['pipes', 'CreatePipe', A]]],
  ['messaging', 'Queues and topics', 'serverless', ['aws-sqs', 'sqs', 'aws-sns', 'sns', 'messaging', 'message-queues'], [
    ['sqs', 'CreateQueue', B], ['sqs', 'SetQueueAttributes', I], ['sns', 'CreateTopic', B], ['sns', 'Subscribe', I],
    ['sns', 'SetTopicAttributes', I], ['sns', 'SetSubscriptionAttributes', A]]],
  ['ecs', 'ECS services and tasks', 'containers', ['aws-ecs', 'ecs', 'aws-fargate', 'fargate', 'container-orchestration'], [
    ['ecs', 'CreateCluster', B], ['ecs', 'RegisterTaskDefinition', I, AUTO], ['ecs', 'CreateService', I],
    ['ecs', 'UpdateService', I, AUTO], ['ecs', 'PutClusterCapacityProviders', A]]],
  ['eks', 'EKS clusters', 'containers', ['aws-eks', 'eks', 'kubernetes'], [
    ['eks', 'CreateCluster', I], ['eks', 'CreateNodegroup', I], ['eks', 'CreateAddon', I], ['eks', 'UpdateClusterConfig', A],
    ['eks', 'CreateAccessEntry', A], ['eks', 'CreatePodIdentityAssociation', A]]],
  ['ecr', 'Container registry (ECR)', 'containers', ['aws-ecr', 'ecr', 'container-registry'], [
    ['ecr', 'CreateRepository', B], ['ecr', 'PutLifecyclePolicy', I], ['ecr', 'PutImageScanningConfiguration', I],
    ['ecr', 'SetRepositoryPolicy', A], ['ecr', 'PutReplicationConfiguration', A], ['ecr', 'PutImage', B, AUTO]]],
  ['relational-db', 'RDS and Aurora', 'database', ['aws-rds', 'rds', 'aws-aurora', 'aurora', 'relational-databases'], [
    ['rds', 'CreateDBInstance', I], ['rds', 'ModifyDBInstance', I], ['rds', 'CreateDBCluster', A], ['rds', 'CreateDBParameterGroup', A]]],
  ['dynamodb', 'DynamoDB tables', 'database', ['aws-dynamodb', 'dynamodb', 'nosql'], [
    ['dynamodb', 'CreateTable', B], ['dynamodb', 'UpdateTable', I], ['dynamodb', 'UpdateTimeToLive', I], ['dynamodb', 'CreateBackup', I],
    ['dynamodb', 'UpdateContinuousBackups', A]]],
  ['s3', 'S3 bucket configuration', 'storage', ['aws-s3', 's3', 'object-storage'], [
    ['s3', 'CreateBucket', B], ['s3', 'PutBucketVersioning', B], ['s3', 'PutBucketPolicy', I], ['s3', 'PutBucketLifecycle', I],
    ['s3', 'PutBucketEncryption', I], ['s3', 'PutBucketPublicAccessBlock', I], ['s3', 'PutBucketNotification', I],
    ['s3', 'PutBucketReplication', A]]],
  ['iac', 'CloudFormation', 'infrastructure-as-code', ['aws-cloudformation', 'cloudformation', 'infrastructure-as-code'], [
    ['cloudformation', 'CreateStack', I], ['cloudformation', 'UpdateStack', I], ['cloudformation', 'CreateChangeSet', I],
    ['cloudformation', 'ExecuteChangeSet', A], ['cloudformation', 'CreateStackSet', A]]],
  ['cicd', 'CI/CD pipelines', 'infrastructure-as-code',
    ['aws-codepipeline', 'codepipeline', 'aws-codebuild', 'codebuild', 'aws-codedeploy', 'codedeploy', 'ci-cd'], [
      ['codebuild', 'CreateProject', I], ['codebuild', 'UpdateProject', I], ['codebuild', 'StartBuild', B, AUTO],
      ['codepipeline', 'CreatePipeline', I], ['codepipeline', 'UpdatePipeline', A], ['codepipeline', 'StartPipelineExecution', B, AUTO],
      ['codedeploy', 'CreateDeploymentGroup', A]]],
  ['observability', 'Monitoring, logs and audit', 'monitoring',
    ['aws-cloudwatch', 'cloudwatch', 'aws-cloudtrail', 'cloudtrail', 'aws-guardduty', 'guardduty', 'observability', 'logging'], [
      ['monitoring', 'PutMetricAlarm', B], ['monitoring', 'PutCompositeAlarm', A], ['monitoring', 'PutDashboard', I],
      ['logs', 'PutMetricFilter', I], ['logs', 'PutRetentionPolicy', B], ['logs', 'PutSubscriptionFilter', A],
      ['cloudtrail', 'CreateTrail', I], ['cloudtrail', 'PutEventSelectors', A], ['guardduty', 'CreateDetector', I]]],
];

const deepFreeze = value => {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); }
  return value;
};

export const AWS_SKILL_GROUPS = deepFreeze(groups.map(([id, label, area, jobTags]) => ({ id, label, area, jobTags })));
export const AWS_CATALOG_OPERATIONS = deepFreeze(groups.flatMap(([group, , , , ops]) => ops.map(([source, eventName, tier, auto = false]) =>
  ({ eventSource: `${source}.amazonaws.com`, eventName, group, tier, auto }))));

/** Throws unless the groups and operations follow the rules above; run on the catalog when this module loads. */
export function assertAwsSkillCatalog(skillGroups, operations) {
  const fail = what => { throw new Error(`AWS_SKILL_CATALOG_INVALID:${what}`); };
  const ids = new Set(), tags = new Set(), events = new Set();
  for (const g of skillGroups) {
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(g?.id) || ids.has(g.id) || typeof g.label !== 'string' || !g.label ||
        !AWS_SKILL_AREAS.some(area => area.id === g.area) || !Array.isArray(g.jobTags) || !g.jobTags.length) fail(g?.id);
    for (const tag of g.jobTags) { if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(tag) || tags.has(tag)) fail(`${g.id}:${tag}`); tags.add(tag); }
    ids.add(g.id);
  }
  for (const op of operations) {
    const key = `${op?.eventSource} ${op?.eventName}`;
    if (!/^[a-z0-9-]+\.amazonaws\.com$/.test(op?.eventSource) || !/^[A-Za-z0-9]+$/.test(op.eventName) || events.has(key) ||
        !ids.has(op.group) || !AWS_OPERATION_TIERS.includes(op.tier) || typeof op.auto !== 'boolean') fail(key);
    events.add(key);
  }
  for (const id of ids) if (!operations.some(op => op.group === id)) fail(`${id}:empty`);
  for (const area of AWS_SKILL_AREAS) if (!skillGroups.some(g => g.area === area.id)) fail(`${area.id}:no-group`);
  // Every operation that can be proven today is in a group of its own skill area.
  for (const entry of AWS_OPERATIONS) for (const eventName of entry.eventNames) {
    const op = operations.find(o => o.eventSource === entry.eventSource && o.eventName === eventName);
    if (!op || skillGroups.find(g => g.id === op.group).area !== entry.skillArea) fail(entry.id);
  }
}

assertAwsSkillCatalog(AWS_SKILL_GROUPS, AWS_CATALOG_OPERATIONS);

export function awsCatalogOperation(eventSource, eventName) {
  return AWS_CATALOG_OPERATIONS.find(op => op.eventSource === eventSource && op.eventName === eventName);
}
