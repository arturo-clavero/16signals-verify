// Region coverage: page sessions per Region, the awsRegion binding of every proven row, discovery over the enabled
// Regions and selection across them. Synthetic data only.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { AWS_REGIONS, AWS_REGION_GRAMMAR, AWS_CLOUDTRAIL_HOSTS, awsCloudTrailRegion, buildAwsRequest } from './request.mjs';
import { awsPageRows, awsPageRowPieces, matchAwsPageRows, AWS_EVENTS_OPEN } from './page-structure.mjs';
import { pageEvent, pageRow, pageSessionFixture, pageClaims, nativeReceipt, PAGE_IDENTITY } from './page-fixture.mjs';
import { inspectAwsPageSession } from './page-session.mjs';
import { fixtureNow } from './event-fixture.mjs';
import { discoverAwsRegions, AWS_DISCOVERY_REGION_CONCURRENCY } from './activity-discovery.mjs';
import { rankAwsActivity, packAwsSessions } from './activity-selection.mjs';
import { DAY, END, IDENTITY, fakeLookup, row, candidate } from './activity-fixture.mjs';
import { signAwsPrivateRequest } from './browser-session.mjs';
import { pageActivity, pageRun } from './page-run-fixture.mjs';
import { verifyAwsBundle } from './verify-bundle.mjs';
import { loadAwsArtifacts } from './artifact-registry.mjs';
import { awsToolClass } from './tool-class.mjs';

const now = Math.floor(fixtureNow / 1000), userLength = PAGE_IDENTITY.userName.length;
const lambda = (index, options = {}) => pageEvent(index, { eventSource: 'lambda.amazonaws.com', eventName: 'CreateFunction20150331',
  time: now - 2 * DAY - index, ...options });

/** The verifier's view of one row on its own page: revealed text for R pieces, positions for committed ones. */
function rowPieces(event) {
  const { text, rows } = awsPageRows(new TextEncoder().encode(JSON.stringify({ Events: [pageRow(event)] })));
  const pieces = awsPageRowPieces(text, rows[0].at);
  assert.ok(pieces, 'row has the provable layout');
  return [{ type: 'R', start: 0, end: AWS_EVENTS_OPEN.length, text: AWS_EVENTS_OPEN },
    ...pieces.map(piece => (piece.type === 'R' ? { ...piece, text: text.slice(piece.start, piece.end) } : piece))];
}
const match = (event, region) => matchAwsPageRows(rowPieces(event), { userNameLength: userLength, region });
const invalid = { message: 'AWS_PRIVATE_PAGE_INVALID' };

test('every allowed Region fits the Region grammar and maps to exactly one CloudTrail host', () => {
  assert.equal(new Set(AWS_REGIONS).size, AWS_REGIONS.length);
  for (const region of AWS_REGIONS) assert.match(region, AWS_REGION_GRAMMAR);
  assert.deepEqual(AWS_CLOUDTRAIL_HOSTS.map(awsCloudTrailRegion), AWS_REGIONS);
  for (const host of ['cloudtrail.us-gov-west-1.amazonaws.com', 'cloudtrail.cn-north-1.amazonaws.com.cn', 'cloudtrail.eu-west-9.amazonaws.com',
    'cloudtrail.eu-west-1.amazonaws.com.evil', 'iam.amazonaws.com', 'xcloudtrail.eu-west-1.amazonaws.com', undefined]) {
    assert.equal(awsCloudTrailRegion(host), null, String(host));
  }
  assert.match('us-gov-west-1', AWS_REGION_GRAMMAR);
  for (const bad of ['us-east-1a', 'US-EAST-1', 'us_east_1', 'us-east-10', 'eusc-de-east-1', '']) assert.doesNotMatch(bad, AWS_REGION_GRAMMAR);
});

test('requests: discovery and pages go to their Region, identity and single events stay in us-east-1', async () => {
  const page = buildAwsRequest({ kind: 'page', region: 'ap-southeast-2', userName: 'dev-user', start: END - DAY, end: END });
  assert.equal(page.url, 'https://cloudtrail.ap-southeast-2.amazonaws.com/');
  // A page session holding one event has a one-second window (AWS bounds are inclusive); a reversed window is refused.
  assert.equal(JSON.parse(buildAwsRequest({ kind: 'page', region: 'eu-west-1', userName: 'dev-user', start: END - 5, end: END - 5 }).body).EndTime, END - 5);
  assert.throws(() => buildAwsRequest({ kind: 'page', region: 'eu-west-1', userName: 'dev-user', start: END, end: END - 1 }));
  assert.throws(() => buildAwsRequest({ kind: 'page', region: 'us-gov-west-1', userName: 'dev-user', start: END - DAY, end: END }), /AWS_REGION_UNSUPPORTED/);
  assert.throws(() => buildAwsRequest({ kind: 'event', region: 'eu-west-1', eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }), /AWS_REGION_UNSUPPORTED/);
  // SigV4 scope names the Region; checked against an independent signer over the same canonical request.
  const signNow = Date.UTC(2026, 9, 29, 8, 0, 0), credentials = { accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
    sessionToken: 't'.repeat(100), expiration: new Date(signNow + 3600000).toISOString() };
  const options = { kind: 'page', region: 'eu-west-1', userName: 'dev-user', start: 1790000000, end: 1790003600 };
  const signed = await signAwsPrivateRequest(options, credentials, { nonceMac: 'n'.repeat(43), now: signNow });
  assert.equal(signed.url, 'https://cloudtrail.eu-west-1.amazonaws.com/');
  assert.equal(signed.headers.host, 'cloudtrail.eu-west-1.amazonaws.com');
  const headers = Object.fromEntries(Object.entries(signed.headers).filter(([name]) => !['authorization', 'accept-encoding', 'connection'].includes(name)));
  const names = Object.keys(headers).sort(), sha = text => createHash('sha256').update(text).digest('hex');
  const canonical = ['POST', '/', '', names.map(name => `${name}:${headers[name]}\n`).join(''), names.join(';'), sha(signed.body)].join('\n');
  const scope = '20261029/eu-west-1/cloudtrail/aws4_request';
  let key = Buffer.from(`AWS4${credentials.secretAccessKey}`);
  for (const part of scope.split('/')) key = createHmac('sha256', key).update(part).digest();
  const signature = createHmac('sha256', key).update(`AWS4-HMAC-SHA256\n20261029T080000Z\n${scope}\n${sha(canonical)}`).digest('hex');
  assert.equal(signed.headers.authorization, `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`);
});

test('a row is claimed only in the session of the Region it names', () => {
  assert.equal(match(lambda(1, { region: 'eu-west-1' }), 'eu-west-1')[0].eventName, 'CreateFunction20150331');
  assert.equal(match(lambda(1), 'us-east-1').length, 1);
  // A row of another Region cannot be claimed in this session.
  assert.throws(() => match(lambda(1, { region: 'eu-west-2' }), 'eu-west-1'), invalid);
  assert.throws(() => match(lambda(1), 'eu-west-1'), invalid);
  // A string of the Region grammar that is not this session's Region, or not a supported Region at all.
  for (const region of ['zz-test-1', 'us-gov-west-1', 'eu-west-9']) assert.throws(() => match(lambda(1, { region }), 'eu-west-1'), invalid);
  // A session Region outside the allowlist is refused before any row.
  assert.throws(() => match(lambda(1, { region: 'us-gov-west-1' }), 'us-gov-west-1'), invalid);
});

test('a value outside the Region grammar has no provable layout and cannot be matched', () => {
  for (const region of ['EU-WEST-1', 'eu-west-1\\"', 'eu-west-12', 'global']) {
    const { text, rows } = awsPageRows(new TextEncoder().encode(JSON.stringify({ Events: [pageRow(lambda(1, { region }))] })));
    assert.equal(awsPageRowPieces(text, rows[0].at), null, region);
  }
  // Forged into a valid chain: the verifier's matcher refuses it too.
  const pieces = rowPieces(lambda(1, { region: 'eu-west-1' }));
  const operation = pieces.find(piece => piece.type === 'R' && piece.text.includes('awsRegion'));
  operation.text = operation.text.replace('eu-west-1', 'EU-WEST-1');
  assert.throws(() => matchAwsPageRows(pieces, { userNameLength: userLength, region: 'eu-west-1' }), invalid);
});

test('global-service rows are claimed only in us-east-1', () => {
  const iam = region => pageEvent(1, { eventSource: 'iam.amazonaws.com', eventName: 'CreateRole', time: now - DAY, region });
  assert.equal(match(iam('us-east-1'), 'us-east-1').length, 1);
  assert.throws(() => match(iam('eu-west-1'), 'eu-west-1'), invalid);
  for (const [eventSource, eventName] of [['route53.amazonaws.com', 'ChangeResourceRecordSets'], ['cloudfront.amazonaws.com', 'CreateDistribution'],
    ['organizations.amazonaws.com', 'CreateAccount']]) {
    const event = pageEvent(1, { eventSource, eventName, time: now - DAY, region: 'eu-west-1' });
    assert.throws(() => match(event, 'eu-west-1'), invalid, eventSource);
  }
});

test('page sessions: the receipt host decides the Region; host header, unknown hosts and swapped rows fail', () => {
  const fixture = pageSessionFixture({ region: 'eu-west-1', events: [lambda(1, { region: 'eu-west-1' }), lambda(2, { region: 'eu-west-1' })] });
  const inspect = (receipt, value = fixture) => inspectAwsPageSession(receipt, value.expected, pageClaims({ ...value, receipt }), userLength, fixtureNow);
  const result = inspect(fixture.receipt);
  assert.equal(result.region, 'eu-west-1');
  assert.equal(result.rows.length, 2);
  // The request's host header is revealed and must be the reached host.
  assert.throws(() => inspect({ ...fixture.receipt, server_name: 'cloudtrail.us-east-1.amazonaws.com' }), invalid);
  for (const serverName of ['cloudtrail.eu-west-9.amazonaws.com', 'cloudtrail.us-gov-west-1.amazonaws.com', 'attacker.invalid']) {
    assert.throws(() => inspect({ ...fixture.receipt, server_name: serverName }), invalid, serverName);
  }
  // The planner leaves rows of another Region as gaps; a page holding only such rows has nothing to prove.
  assert.throws(() => pageSessionFixture({ region: 'eu-west-1', events: [lambda(1)] }), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
  const mixed = pageSessionFixture({ region: 'eu-west-1', events: [lambda(1, { region: 'eu-west-1' }), lambda(2, { region: 'eu-west-2' })] });
  assert.equal(inspect(mixed.receipt, mixed).rows.length, 1);
  // Rows naming another Region in the authenticated bytes (same length, same plan) are refused by the verifier.
  const recv = Buffer.from(fixture.plaintext.recv.toString('latin1').replaceAll('\\"awsRegion\\":\\"eu-west-1\\"', '\\"awsRegion\\":\\"eu-west-2\\"'), 'latin1');
  assert.notDeepEqual(recv, fixture.plaintext.recv);
  const swapped = nativeReceipt({ expected: fixture.expected, sent: fixture.plaintext.sent, recv, plan: fixture.plan, blinderSeed: 'swap',
    serverName: 'cloudtrail.eu-west-1.amazonaws.com' });
  assert.throws(() => inspect(swapped.receipt), invalid);
});

test('discovery probes every other Region once, skips disabled ones and slices only Regions with writes', async () => {
  const ago = days => END - days * DAY;
  const reads = (region, count, from) => Array.from({ length: count }, (_, i) => row('read', ago(from) - i * 60, { region }));
  const rows = [
    // us-east-1: global and regional writes behind 120 newer reads.
    ...reads('us-east-1', 120, 1), row('iam-access:CreateRole', ago(10)), row('lambda:CreateFunction20150331', ago(20)),
    // eu-west-1: a write on the first page and more behind 60 reads.
    row('lambda:CreateFunction20150331', ago(1), { region: 'eu-west-1' }), ...reads('eu-west-1', 60, 2),
    row('dynamodb:CreateTable', ago(30), { region: 'eu-west-1' }),
    // ap-southeast-2: only reads, more than one page (console browsing): not sliced.
    ...reads('ap-southeast-2', 70, 1), row('lambda:CreateFunction20150331', ago(40), { region: 'ap-southeast-2' }),
    // us-west-2: two writes, everything on the probe page.
    row('s3:PutBucketPolicy', ago(5), { region: 'us-west-2' }), row('dynamodb:CreateTable', ago(50), { region: 'us-west-2' }),
    // Global services recorded outside us-east-1 are not candidates (CloudTrail records them in us-east-1).
    row('iam-access:CreateRole', ago(3), { region: 'us-west-2' }),
  ];
  const read = fakeLookup(rows, { disabled: ['af-south-1', 'me-south-1'] });
  const found = await discoverAwsRegions({ read, identity: IDENTITY, end: END });
  const probes = read.calls.filter(call => call.start === END - 90 * DAY && call.end === END);
  // us-east-1 is read in slices from the start; every other Region gets one probe.
  assert.deepEqual(probes.map(call => call.region).sort(), AWS_REGIONS.filter(region => region !== 'us-east-1').sort());
  assert.deepEqual(found.probe, { regions: AWS_REGIONS.length, enabled: AWS_REGIONS.length - 2, sliced: ['us-east-1', 'eu-west-1'], unread: [], homeComplete: true });
  const byRegion = region => read.calls.filter(call => call.region === region).length;
  assert.equal(byRegion('ap-southeast-2'), 1);
  assert.equal(byRegion('us-west-2'), 1);
  assert.ok(byRegion('eu-west-1') > 1 && byRegion('us-east-1') > 1);
  assert.deepEqual(found.candidates.map(c => `${c.region}:${c.group}`).sort(), ['eu-west-1:dynamodb', 'eu-west-1:lambda', 'us-east-1:iam-access',
    'us-east-1:lambda', 'us-west-2:dynamodb', 'us-west-2:s3']);
  assert.equal(found.requests, read.calls.length);
  assert.equal(found.regions['us-west-2'].coverage[0].start, END - 90 * DAY);
  assert.equal(found.regions['af-south-1'], undefined);
  // us-east-1 holds the identity's home and the global services: its failure fails discovery.
  await assert.rejects(discoverAwsRegions({ read: fakeLookup(rows, { disabled: ['us-east-1'] }), identity: IDENTITY, end: END }));
});

test('discovery names a Region it could not read (failed in transit after retries) instead of dropping it silently', async () => {
  const rows = [row('iam-access:CreateRole', END - DAY), row('lambda:CreateFunction20150331', END - 2 * DAY, { region: 'eu-west-1' }),
    row('s3:PutBucketPolicy', END - 3 * DAY, { region: 'us-west-2' })];
  const lookup = fakeLookup(rows, { disabled: ['af-south-1'] });
  // eu-west-1 keeps failing in transit: the session's read returns null for it (after its own retries).
  const read = async options => (options.region === 'eu-west-1' ? (lookup.calls.push(options), null) : lookup(options));
  const found = await discoverAwsRegions({ read, identity: IDENTITY, end: END });
  assert.deepEqual(found.probe.unread, ['eu-west-1'], 'a transient failure is reported, a refused Region is not');
  assert.equal(found.probe.homeComplete, true);
  assert.deepEqual(found.candidates.map(c => `${c.region}:${c.group}`).sort(), ['us-east-1:iam-access', 'us-west-2:s3']);
});

test('discovery probes only a few Regions at a time (no burst of dozens of requests)', async () => {
  const lookup = fakeLookup([row('iam-access:CreateRole', END - DAY)]);
  let inFlight = 0, peak = 0;
  const read = async options => {
    inFlight++; peak = Math.max(peak, inFlight);
    await new Promise(resolve => setTimeout(resolve, 2));
    try { return await lookup(options); } finally { inFlight--; }
  };
  const found = await discoverAwsRegions({ read, identity: IDENTITY, end: END });
  // us-east-1's own lane plus at most AWS_DISCOVERY_REGION_CONCURRENCY probes.
  assert.ok(peak <= AWS_DISCOVERY_REGION_CONCURRENCY + 1, String(peak));
  assert.equal(found.probe.enabled, AWS_REGIONS.length);
});

test('discovery shares one time budget across Regions', async () => {
  const rows = Array.from({ length: 400 }, (_, i) => row('read', END - DAY - i * 30, { region: 'eu-west-1' }))
    .concat([row('lambda:CreateFunction20150331', END - 600, { region: 'eu-west-1' })]);
  let clock = 0;
  const read = fakeLookup(rows), timed = async options => { clock += 1000; return read(options); };
  const found = await discoverAwsRegions({ read: timed, identity: IDENTITY, end: END, timeMs: AWS_REGIONS.length * 1000 + 5000, now: () => clock });
  // The probes took the budget down to 5 s: about five more eu-west-1 pages, not the 80-page cap.
  assert.ok(found.regions['eu-west-1'].requests <= 6, String(found.regions['eu-west-1'].requests));
  assert.equal(found.candidates.length, 1);
});

/** Discovery result of several Regions, each with every row seen. */
const discoveryOf = candidates => {
  const regions = {};
  for (const c of candidates) (regions[c.region ?? 'us-east-1'] ??= []).push(c.time);
  return { candidates, regions: Object.fromEntries(Object.entries(regions).map(([region, times]) =>
    [region, { region, times: times.sort((a, b) => a - b), coverage: [{ start: END - 90 * DAY, end: END }] }])) };
};

test('mixed-Region selection: levels count across Regions, sessions never mix Regions', () => {
  const candidates = [candidate('lambda:CreateFunction20150331', 10, { region: 'eu-west-1' }),
    candidate('lambda:UpdateFunctionConfiguration20150331v2', 30), candidate('lambda:CreateFunction20150331', 50, { region: 'us-west-2' }),
    candidate('iam-access:CreateRole', 10), candidate('dynamodb:CreateTable', 10, { region: 'eu-west-1', second: 43300 })];
  const discovery = discoveryOf(candidates);
  const ranking = rankAwsActivity(candidates, { budget: 10, discovery });
  // Three Lambda days in three Regions are three distinct days of the same group.
  assert.equal(ranking.groups.find(group => group.group === 'lambda').days, 3);
  const { sessions, deferred, unplaced } = packAwsSessions(ranking.picks, discovery, { rowCap: 21, maxSessions: 10 });
  assert.deepEqual(unplaced, []);
  assert.deepEqual(deferred, []);
  const regionOf = new Map(candidates.map(c => [c.eventId, c.region ?? 'us-east-1']));
  for (const session of sessions) assert.ok(session.eventIds.every(id => regionOf.get(id) === session.region), session.region);
  assert.deepEqual(sessions.map(session => session.region).sort(), ['eu-west-1', 'us-east-1', 'us-west-2']);
  // Same day, same window: the two eu-west-1 picks share one session; us-east-1 picks of that day do not join it.
  assert.equal(sessions.find(session => session.region === 'eu-west-1').eventIds.length, 2);
});

test('budget split: maxSessions is the whole run\'s budget, best sessions first, the rest deferred', () => {
  const regions = ['us-east-1', 'eu-west-1', 'us-west-2', 'ap-southeast-2'];
  const groups = ['lambda:CreateFunction20150331', 'dynamodb:CreateTable', 's3:PutBucketPolicy', 'iam-access:CreateRole'];
  // One Region per group (IAM is global, so us-east-1); each Region's pick is a separate session.
  const candidates = groups.map((op, index) => candidate(op, 10 + index, { region: op.startsWith('iam') ? 'us-east-1' : regions[index + 1] ?? 'us-east-1' }));
  const discovery = discoveryOf(candidates);
  const ranking = rankAwsActivity(candidates, { budget: 25, discovery, jobTags: ['dynamodb'] });
  const { sessions, deferred } = packAwsSessions(ranking.picks, discovery, { rowCap: 21, maxSessions: 3, jobTags: ['dynamodb'] });
  assert.equal(sessions.length, 3);
  assert.equal(deferred.length, 1);
  assert.equal(new Set(sessions.map(session => session.region)).size, 3);
  // The job's group comes first.
  assert.deepEqual(sessions[0].groups, ['dynamodb']);
});

const artifacts = await loadAwsArtifacts(file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)));
/** ABI-derived public fields (as page-run.test.mjs); not a cryptographic proof. */
async function proveCircuit(id, inputs) {
  const abi = artifacts[id].abi;
  const values = abi.parameters.filter(p => p.visibility === 'public').flatMap(p => [inputs[p.name]].flat(Infinity));
  if (id.startsWith('aws-event-batch')) {
    for (const [index, body] of inputs.row_body.entries()) values.push(awsToolClass(`"${Buffer.from(body.slice(2, inputs.ua_lengths[index] - 2)).toString()}"`));
  } else if (abi.return_type) values.push(1);
  return { circuitId: id, proof: 'AA==', publicInputs: values.map(String) };
}

test('a run over two Regions: discovery, page sessions per Region and bundle verification', async () => {
  const away = new Set(['lambda.amazonaws.com', 'dynamodb.amazonaws.com', 'ecs.amazonaws.com', 'sqs.amazonaws.com']);
  const events = pageActivity({ regionOf: source => (away.has(source) ? 'eu-west-1' : 'us-east-1') });
  const { requests, bundle, sessions, rows } = await pageRun(events, proveCircuit);
  const hosts = requests.slice(1).map(request => new URL(request.url).hostname);
  assert.ok(hosts.includes('cloudtrail.eu-west-1.amazonaws.com') && hosts.includes('cloudtrail.us-east-1.amazonaws.com'), hosts.join());
  assert.ok(sessions.length - 1 <= 3);
  const result = await verifyAwsBundle({ sessions, bundle, runtime: { verify: async () => true }, now: fixtureNow });
  assert.equal(result.observations.length, Object.values(rows).flat().length);
  const sources = new Set(result.observations.map(o => o.eventSource));
  for (const source of ['lambda.amazonaws.com', 'iam.amazonaws.com']) assert.ok(sources.has(source), source);
  // Pages of two Regions may share a time window; one Region's pages may not.
  const euSession = sessions.findIndex(session => session.receipt.server_name === 'cloudtrail.eu-west-1.amazonaws.com');
  const forged = sessions.map((session, index) => (index === euSession ? { ...session, receipt: { ...session.receipt, server_name: 'cloudtrail.us-east-1.amazonaws.com' } } : session));
  await assert.rejects(verifyAwsBundle({ sessions: forged, bundle, runtime: { verify: async () => true }, now: fixtureNow }), { message: 'AWS_PRIVATE_BUNDLE_INVALID' });
});
