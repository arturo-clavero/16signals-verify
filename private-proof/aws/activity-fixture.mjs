/** Synthetic LookupEvents rows and a paging fake for the discovery and selection tests. No real AWS data. */
import { AWS_CATALOG_OPERATIONS } from './skill-groups.mjs';

export const DAY = 86400;
export const END = Date.parse('2026-11-24T00:00:00Z') / 1000;
export const IDENTITY = Object.freeze({ principalId: 'AIDAEXAMPLEPRINCIPAL1', arn: 'arn:aws:iam::111122223333:user/dev-user', accountId: '111122223333' });
export const USER_AGENTS = Object.freeze({
  cli: 'aws-cli/2.17.0 md/Botocore#1.35.0 ua/2.0 os/linux#6.8 md/arch#x86_64 lang/python#3.12.6',
  terraform: 'APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.70.0',
  console: 'AWS Internal',
});

let counter = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`;

/** One page row. `op` is "group:EventName" of a catalog operation or "read"; options change one aspect of the event. */
export function row(op, time, { tool = 'cli', actor = {}, region = 'us-east-1', error = false, id = uuid(), userAgent = USER_AGENTS[tool] } = {}) {
  const [group, name] = op.split(':');
  const catalog = op === 'read' ? { eventSource: 'ec2.amazonaws.com', eventName: 'DescribeInstances' }
    : AWS_CATALOG_OPERATIONS.find(entry => entry.group === group && entry.eventName === name);
  if (!catalog) throw new Error(`fixture op ${op}`);
  const event = {
    eventVersion: '1.10', userIdentity: { type: 'IAMUser', ...IDENTITY, accessKeyId: 'AKIAEXAMPLEEXAMPLE01', userName: 'dev-user', ...actor },
    eventTime: new Date(time * 1000).toISOString().replace('.000Z', 'Z'), eventSource: catalog.eventSource, eventName: catalog.eventName,
    awsRegion: region, sourceIPAddress: '192.0.2.10', ...(userAgent === null ? {} : { userAgent }),
    ...(error ? { errorCode: 'AccessDenied', errorMessage: 'denied' } : {}),
    requestParameters: {}, responseElements: null, requestID: 'req', eventID: id, readOnly: op === 'read', eventType: 'AwsApiCall',
    managementEvent: true, recipientAccountId: IDENTITY.accountId, eventCategory: 'Management',
  };
  return { AccessKeyId: 'AKIAEXAMPLEEXAMPLE01', CloudTrailEvent: JSON.stringify(event), EventId: id, EventName: catalog.eventName,
    EventSource: catalog.eventSource, EventTime: time, ReadOnly: String(op === 'read'), Resources: [], Username: 'dev-user' };
}

/**
 * A `read` over `rows` that behaves like LookupEvents: one Region per request (rows recorded there), inclusive bounds,
 * newest first, 50 per page. Regions in `disabled` refuse every request (an opt-in Region not enabled). Counts calls.
 */
export function fakeLookup(rows, { disabled = [] } = {}) {
  const sorted = [...rows].sort((a, b) => b.EventTime - a.EventTime);
  const read = async ({ kind, userName, start, end, nextToken, region = 'us-east-1' }) => {
    if (kind !== 'discovery' || userName !== 'dev-user') throw new Error('fake lookup input');
    read.calls.push({ start, end, region });
    if (disabled.includes(region)) throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
    const offset = nextToken ? Number(nextToken.split(':')[1]) : 0;
    const inside = sorted.filter(r => r.EventTime >= start && r.EventTime <= end && JSON.parse(r.CloudTrailEvent).awsRegion === region);
    const page = inside.slice(offset, offset + 50);
    return JSON.stringify({ Events: page, ...(offset + 50 < inside.length ? { NextToken: `${start}-${end}:${offset + 50}` } : {}) });
  };
  read.calls = [];
  return read;
}

/** A discovery candidate as discovery returns it, for selection tests. */
export function candidate(op, day, { tool = 'cli', second = 43200, region } = {}) {
  const [group, name] = op.split(':'), entry = AWS_CATALOG_OPERATIONS.find(e => e.group === group && e.eventName === name);
  if (!entry) throw new Error(`fixture op ${op}`);
  const time = END - 90 * DAY + day * DAY + second;
  return { eventId: uuid(), time, day: Math.floor(time / DAY), eventSource: entry.eventSource, eventName: name, group, tier: entry.tier,
    auto: entry.auto, tool, ...(region ? { region } : {}) };
}
