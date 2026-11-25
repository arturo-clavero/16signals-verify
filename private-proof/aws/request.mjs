/** Home Region: the identity request, single-event sessions and every global-service event. */
export const AWS_REGION = 'us-east-1';
/** Region names as CloudTrail writes them in awsRegion. */
export const AWS_REGION_GRAMMAR = /^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/;
/**
 * Commercial Regions (partition aws) whose CloudTrail endpoint a page run may read. Console credentials of this
 * partition cannot sign for GovCloud, China or the European Sovereign Cloud, so those are not listed. Every host here
 * must also be in the extension manifest, the plugins and the verifier's TLSN_ALLOWED_HOSTS.
 */
export const AWS_REGIONS = Object.freeze(['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1',
  'ap-east-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1',
  'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-southeast-5', 'ap-southeast-6', 'ap-southeast-7',
  'ca-central-1', 'ca-west-1', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-west-1',
  'eu-west-2', 'eu-west-3', 'il-central-1', 'me-central-1', 'me-south-1', 'mx-central-1', 'sa-east-1']);
/** Services whose events CloudTrail records in us-east-1 only. */
export const AWS_GLOBAL_SOURCES = Object.freeze(['iam.amazonaws.com', 'sts.amazonaws.com', 'cloudfront.amazonaws.com',
  'route53.amazonaws.com', 'organizations.amazonaws.com']);
export const awsCloudTrailHost = region => {
  if (!AWS_REGIONS.includes(region)) throw new Error('AWS_REGION_UNSUPPORTED');
  return `cloudtrail.${region}.amazonaws.com`;
};
/** The Region of an allowed CloudTrail host, or null. */
export const awsCloudTrailRegion = host => {
  const region = typeof host === 'string' ? /^cloudtrail\.([a-z0-9-]{1,32})\.amazonaws\.com$/.exec(host)?.[1] : undefined;
  return region !== undefined && AWS_REGIONS.includes(region) ? region : null;
};
export const AWS_CLOUDTRAIL_HOSTS = Object.freeze(AWS_REGIONS.map(awsCloudTrailHost));
/** An event of `eventSource` can be recorded in `region` (global services only in us-east-1). */
export const awsRegionHolds = (region, eventSource) => region === AWS_REGION || !AWS_GLOBAL_SOURCES.includes(eventSource);
export const AWS_HOSTS = [`sts.${AWS_REGION}.amazonaws.com`, `cloudtrail.${AWS_REGION}.amazonaws.com`, 'iam.amazonaws.com'];
export const AWS_LIMITS = Object.freeze({ attempts: 48, pageSize: 50, discoveryPages: 10, discoveryBytes: 2097152,
  selected: 6, proofs: 12, bodyBytes: 65536, deadlineMs: 300000, intervalMs: 650 });
/** Largest response a proven page session may fetch (pages of 50 rows measured 38-99 KB). */
export const AWS_PAGE_BYTES = 307200;
export const AWS_EVENT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

// A page request is a discovery request without NextToken: the first page of the user's rows in [start, end].
// Identity and single-event requests use the home Region; discovery and page requests any Region of AWS_REGIONS.
export function buildAwsRequest({ region = AWS_REGION, kind, identityService = 'sts', eventId, userName, start, end, nextToken } = {}) {
  const host = awsCloudTrailHost(region);
  if (region !== AWS_REGION && kind !== 'discovery' && kind !== 'page') throw new Error('AWS_REGION_UNSUPPORTED');
  if (!['sts', 'iam'].includes(identityService)) throw new Error('AWS_IDENTITY_INVALID');
  if (kind === 'identity') return { url: `https://${identityService === 'iam' ? AWS_HOSTS[2] : AWS_HOSTS[0]}/`, method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: identityService === 'iam' ? 'Action=GetUser&Version=2010-05-08' : 'Action=GetCallerIdentity&Version=2011-06-15' };
  let params;
  if (kind === 'event' && typeof eventId === 'string' && AWS_EVENT_ID.test(eventId)) {
    params = { LookupAttributes: [{ AttributeKey: 'EventId', AttributeValue: eventId }], MaxResults: 1 };
  } else if ((kind === 'discovery' || (kind === 'page' && nextToken === undefined)) && typeof userName === 'string' && /^[\w+=,.@-]{1,64}$/.test(userName) && Number.isSafeInteger(start) &&
      Number.isSafeInteger(end) && start >= 0 && end >= start && end - start <= 90 * 86400 &&
      (nextToken === undefined || typeof nextToken === 'string' && nextToken.length > 0 && nextToken.length <= 8192)) {
    params = { LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: userName }],
      StartTime: start, EndTime: end, MaxResults: AWS_LIMITS.pageSize, ...(nextToken ? { NextToken: nextToken } : {}) };
  } else throw new Error('AWS_REQUEST_INVALID');
  return { url: `https://${host}/`, method: 'POST',
    headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents' },
    body: JSON.stringify(params) };
}
