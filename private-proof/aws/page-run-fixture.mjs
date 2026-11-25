// A synthetic page run without AWS: about 60 writes over five UTC days, a LookupEvents fake, the browser session's
// discovery, ranking and packing, page plans with native-shaped receipts, and the proving client.
import { webcrypto } from 'node:crypto';
import { createAwsLocalSession } from './browser-session.mjs';
import { createAwsPrivateClient } from './client.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { fixtureExpected, fixtureNow, syntheticWitness } from './event-fixture.mjs';
import { pageEvent, pageSessionFixture, pageWitness } from './page-fixture.mjs';
import { awsCollectedSteps } from './sessions.mjs';

const DAY = 86400, end = Math.floor(fixtureExpected.issuedAt / 1000);
const OPS = [['iam.amazonaws.com', 'AttachRolePolicy'], ['iam.amazonaws.com', 'CreateRole'], ['lambda.amazonaws.com', 'UpdateFunctionConfiguration20150331v2'],
  ['lambda.amazonaws.com', 'CreateFunction20150331'], ['s3.amazonaws.com', 'PutBucketVersioning'], ['dynamodb.amazonaws.com', 'UpdateTable'],
  ['dynamodb.amazonaws.com', 'CreateTable'], ['ec2.amazonaws.com', 'AuthorizeSecurityGroupIngress'], ['ecs.amazonaws.com', 'RegisterTaskDefinition'],
  ['monitoring.amazonaws.com', 'PutMetricAlarm'], ['cloudformation.amazonaws.com', 'CreateStack'], ['kms.amazonaws.com', 'CreateKey'],
  ['sqs.amazonaws.com', 'CreateQueue'], ['logs.amazonaws.com', 'PutMetricFilter'], ['secretsmanager.amazonaws.com', 'CreateSecret'],
  ['route53.amazonaws.com', 'ChangeResourceRecordSets'], ['apigateway.amazonaws.com', 'CreateRestApi'], ['ecr.amazonaws.com', 'CreateRepository'],
  ['events.amazonaws.com', 'PutRule'], ['kms.amazonaws.com', 'PutKeyPolicy']];
const AGENTS = ['cli', 'terraform', 'console'];

/**
 * About 60 writes over five UTC days (each a burst of a few minutes), with reads, failures and delegated rows between.
 * `regionOf(eventSource)` names the Region each event is recorded in (default us-east-1).
 */
export function pageActivity({ regionOf = () => 'us-east-1' } = {}) {
  const events = [];
  let index = 0;
  for (const [dayIndex, daysAgo] of [2, 5, 9, 16, 23].entries()) {
    for (let n = 0; n < 12; n++) {
      const [eventSource, eventName] = OPS[(n + dayIndex * 3) % OPS.length], time = end - daysAgo * DAY - n * 30;
      const region = regionOf(eventSource);
      events.push(pageEvent(++index, { eventSource, eventName, time, region, agent: AGENTS[n % 3], console: n % 3 === 2,
        ...(eventSource === 's3.amazonaws.com' ? { host: `private-bucket.s3.${region}.amazonaws.com`, keyExchange: true } : {}) }));
      if (n % 4 === 1) events.push(pageEvent(++index, { eventSource: 'iam.amazonaws.com', eventName: 'GetRole', time: time - 5, readOnly: true }));
      if (n % 5 === 2) events.push(pageEvent(++index, { eventSource, eventName, time: time - 7, region, errorCode: 'AccessDenied' }));
      if (n % 6 === 3) events.push(pageEvent(++index, { eventSource, eventName, time: time - 9, region, invokedBy: 'cloudformation.amazonaws.com' }));
    }
  }
  return events.sort((a, b) => Date.parse(b.eventTime) - Date.parse(a.eventTime));
}

/** LookupEvents over `events` in one Region by Username and window: inclusive bounds, newest first, 50 rows a page. */
export function pageLookup(events, body, region = 'us-east-1') {
  const { StartTime: start, EndTime: stop, NextToken: token } = JSON.parse(body);
  const inside = events.filter(event => { const t = Date.parse(event.eventTime) / 1000; return t >= start && t <= stop && event.awsRegion === region; });
  const offset = token ? Number(token.split(':')[1]) : 0, page = inside.slice(offset, offset + 50);
  return JSON.stringify({ Events: page.map(event => ({ AccessKeyId: event.userIdentity.accessKeyId, CloudTrailEvent: JSON.stringify(event),
    EventId: event.eventID, EventName: event.eventName, EventSource: event.eventSource, EventTime: Date.parse(event.eventTime) / 1000,
    ReadOnly: String(event.readOnly), Resources: [], Username: event.userIdentity.userName })),
  ...(offset + 50 < inside.length ? { NextToken: `${start}:${offset + 50}` } : {}) });
}

/** `fields` adds server attempt state, e.g. `{ jobGroups }`. */
/** `options`: extra client options (e.g. `saveLink`, to keep the Fast link of the run). */
export async function pageRun(events, proveCircuit, edit = () => {}, fields = {}, options = {}) {
  const identity = identityFixture();
  // Discovery paces its reads (650 ms apart): give the local session a full 15-minute attempt.
  const attempt = { ...fixtureExpected, expiresAt: fixtureExpected.issuedAt + 15 * 60 * 1000, ...fields };
  const local = createAwsLocalSession({ attempt, now: () => fixtureNow, fetchAws: async (url, options) =>
    new Response(url === 'https://iam.amazonaws.com/' ? syntheticWitness(identity).recv.slice(identity.receipt.transcript.recv.indexOf('\r\n\r\n') + 4)
      : pageLookup(events, options.body, new URL(url).hostname.split('.')[1])) });
  const requests = await local.prepare({ credentials: { accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
    sessionToken: 't'.repeat(100), expiration: new Date(fixtureNow + 3600000).toISOString() }, accountId: '111122223333' });
  const steps = awsCollectedSteps(requests), rows = local.pageRows();
  const pages = requests.slice(1).map((request, index) => {
    const { StartTime: start, EndTime: stop } = JSON.parse(request.body), region = new URL(request.url).hostname.split('.')[1];
    const inside = events.filter(event => { const t = Date.parse(event.eventTime) / 1000; return t >= start && t <= stop && event.awsRegion === region; });
    return pageSessionFixture({ region, step: steps[index + 1], sessionId: `33333333-3333-4333-8333-33333333333${index}`, events: inside, start, end: stop,
      select: rows[steps[index + 1]] });
  });
  edit(pages, rows);
  const client = createAwsPrivateClient({ attempt: { ...identity.expected }, now: () => fixtureNow, proveCircuit, crypto: webcrypto, ...options });
  client.selectPages(rows);
  const bundle = await client.prove([syntheticWitness(identity), ...pages.map(pageWitness)], new AbortController().signal);
  const sessions = [identity, ...pages].map(({ receipt, expected }) => ({ receipt, expected }));
  return { requests, steps, rows, pages, bundle, sessions };
}
