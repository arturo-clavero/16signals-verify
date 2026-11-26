import test from 'node:test';
import assert from 'node:assert/strict';
import { awsPrivateCredentials, signAwsPrivateRequest, readAwsPrivateResponse, createAwsLocalSession } from './browser-session.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, activityEventFixture, syntheticWitness } from './event-fixture.mjs';
import { AWS_MAX_EVENT_SESSIONS } from './sessions.mjs';
import { AWS_LIMITS } from './request.mjs';
import { pageActivity, pageLookup } from './page-run-fixture.mjs';
import { fixtureExpected, fixtureNow } from './event-fixture.mjs';

const now = Date.UTC(2026, 9, 29, 8, 0, 0);
const credentials = () => ({ accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
  sessionToken: 't'.repeat(100), expiration: new Date(now + 3600000).toISOString() });
const attempt = () => ({ proofId: '22222222-2222-4222-8222-222222222222', pluginSha256: 'a'.repeat(64),
  nonceMac: 'n'.repeat(43), identityService: 'iam', region: 'us-east-1', issuedAt: now, expiresAt: now + 300000 });
const capture = () => ({ credentials: credentials(), accountId: '111122223333' });
const body = fixture => new TextDecoder().decode(syntheticWitness(fixture).recv).split('\r\n\r\n')[1];
const identity = () => body(identityFixture({ fields: { Path: '/', UserName: 'synthetic', Arn: 'arn:aws:iam::111122223333:user/synthetic' } }));
const event = options => body(eventFixture(options));
const failed = operation => assert.rejects(operation, { message: 'AWS_PRIVATE_COLLECTION_FAILED' });
const collector = fetchAws => createAwsLocalSession({ attempt: attempt(), pages: false, fetchAws, now: () => now });

test('WebCrypto signatures match offline botocore IAM and CloudTrail vectors', async () => {
  // botocore SigV4Auth, frozen 2026-10-29T08:00:00Z, explicit synthetic credentials; no network.
  for (const [options, signature] of [
    [{ kind: 'identity' }, 'e1a7c3ecfa1375632f1436e5ef1a1ef060608970bd8773b5773407ca88d34deb'],
    [{ kind: 'event', eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, '4897e6c48f10b296a0859e959406f9b18905d51c3c4f9d1f9639eda88abad2ae'],
  ]) {
    const request = await signAwsPrivateRequest(options, credentials(), { nonceMac: 'n'.repeat(43), now });
    assert.ok(request.headers.authorization.endsWith(`Signature=${signature}`));
    assert.equal(request.headers['x-amz-date'], '20261029T080000Z');
    assert.equal(request.headers['x-16signals-nonce'], 'n'.repeat(43));
    assert.equal(request.headers['accept-encoding'], 'identity');
  }
});

test('fixed signer refuses arbitrary requests, permanent credentials, stale credentials and mutable inputs', async () => {
  for (const options of [{ kind: 'identity', url: 'https://sentinel.invalid/' }, { kind: 'identity', identityService: 'sts' },
    { kind: 'write' }, { kind: 'event', eventId: '../secret' }, { kind: 'discovery', start: 0, end: now / 1000 }]) {
    await assert.rejects(signAwsPrivateRequest(options, credentials(), { nonceMac: 'n'.repeat(43), now }));
  }
  for (const edit of [{ accessKeyId: 'AKIA' + 'A'.repeat(16) }, { expiration: new Date(now).toISOString() },
    { sessionToken: 'private\r\ninjected: value' }, { sessionToken: 1234567890123456 }, { secretAccessKey: '' }]) {
    assert.throws(() => awsPrivateCredentials({ ...credentials(), ...edit }, now));
  }
  const value = credentials();
  const pending = signAwsPrivateRequest({ kind: 'identity' }, value, { nonceMac: 'n'.repeat(43), now });
  value.secretAccessKey = 'x'.repeat(40); value.accessKeyId = 'ASIA' + 'B'.repeat(16);
  assert.ok((await pending).headers.authorization.endsWith('Signature=e1a7c3ecfa1375632f1436e5ef1a1ef060608970bd8773b5773407ca88d34deb'));
});

test('response reader bounds bytes, erases owned chunks and returns only fixed failures', async () => {
  for (const [status, count, succeeds] of [[200, 20, true], [200, 16385, false], [403, 20, false]]) {
    const chunk = new Uint8Array(count).fill(65);
    const fetchAws = async (_url, options) => {
      assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store');
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(chunk); controller.close(); } }), { status });
    };
    const pending = readAwsPrivateResponse('https://iam.amazonaws.com/', {}, { fetchAws });
    if (succeeds) assert.equal(await pending, 'A'.repeat(count)); else await failed(pending);
    if (status === 200) assert.ok(chunk.every(value => value === 0));
  }
  await failed(readAwsPrivateResponse('https://iam.amazonaws.com/', {}, { fetchAws: async () => { throw new Error('PRIVATE_ERROR_SENTINEL'); } }));
});

test('only a bounded CloudTrail access denial emits the fixed permission diagnostic', async () => {
  const url = 'https://cloudtrail.us-east-1.amazonaws.com/';
  const options = { headers: { 'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents' } };
  const denied = JSON.stringify({ __type: 'AccessDeniedException', message: 'PRIVATE_ARN_SENTINEL' });
  for (const status of [400, 403]) {
    const chunk = new TextEncoder().encode(denied);
    await assert.rejects(readAwsPrivateResponse(url, options, { fetchAws: async () => new Response(
      new ReadableStream({ start(controller) { controller.enqueue(chunk); controller.close(); } }), { status }),
    }), { message: 'AWS_ACTIVITY_ACCESS_REQUIRED' });
    assert.ok(chunk.every(value => value === 0));
  }
  for (const [target, request, status, body] of [
    ['https://iam.amazonaws.com/', options, 403, denied],
    [url, {}, 403, denied], [url, options, 500, denied],
    [url, options, 403, JSON.stringify({ __type: 'ExpiredTokenException', message: 'PRIVATE_ARN_SENTINEL' })],
    [url, options, 403, '{"__type":"AccessDeniedException","__type":"AccessDeniedException"}'],
    [url, options, 403, JSON.stringify({ __type: 'AccessDeniedException', message: 'X'.repeat(16384) })],
  ]) await failed(readAwsPrivateResponse(target, request, { fetchAws: async () => new Response(body, { status }) }));
  await failed(readAwsPrivateResponse(url, options, { fetchAws: async () => { throw new Error('AWS_ACTIVITY_ACCESS_REQUIRED'); } }));
});

test('discovery preserves only the fixed permission diagnostic and consumes the denied attempt', async () => {
  let calls = 0;
  const local = collector(async () => ++calls === 1 ? new Response(identity()) : new Response(
    JSON.stringify({ __type: 'AccessDeniedException', message: 'PRIVATE_ARN_SENTINEL' }), { status: 400 }));
  await assert.rejects(local.prepare(capture()), { message: 'AWS_ACTIVITY_ACCESS_REQUIRED' });
  assert.equal(calls, 2);
  await failed(local.prepare(capture()));
  assert.equal(calls, 2);
});

test('local discovery is one Username query whose signed native requests name only the selected event', async () => {
  const calls = [];
  const local = collector(async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.credentials, 'omit');
    return new Response(calls.length === 1 ? identity() : event());
  });
  const supplied = capture(), snapshot = structuredClone(supplied);
  const requests = await local.prepare(supplied);
  assert.deepEqual(supplied, snapshot, 'capture caller owns its source credentials');
  assert.deepEqual(requests.map(row => row.url), ['https://iam.amazonaws.com/', 'https://cloudtrail.us-east-1.amazonaws.com/']);
  assert.equal(JSON.parse(requests[1].body).LookupAttributes[0].AttributeKey, 'EventId');
  assert.equal(calls.length, 2);
  const query = JSON.parse(calls[1].options.body);
  assert.deepEqual(query, { LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: 'synthetic' }],
    StartTime: now / 1000 - 90 * 86400, EndTime: now / 1000, MaxResults: 50 });
  assert.doesNotMatch(JSON.stringify(requests), /AWS_PRIVATE_\w+_SENTINEL|AIDAEXAMPLESYNTHETIC01|111122223333|secretAccessKey|expiration/);
  await failed(local.prepare(capture())); assert.equal(calls.length, 2);
});

test('wrong account, wrong actor, denied, read-only, oversized and dry-run events never select evidence', async () => {
  for (const mutateEvent of [e => { e.userIdentity.principalId = 'OTHER'; }, e => { e.recipientAccountId = '999999999999'; },
    e => { e.errorCode = 'PRIVATE_ERROR_SENTINEL'; }, e => { e.requestParameters.dryRun = true; }, e => { e.readOnly = true; },
    e => { e.requestParameters.roleName = 'r'.repeat(65); }, e => { e.requestParameters.roleName = 'role name'; },
    e => { e.eventName = 'GetRole'; }]) {
    let calls = 0;
    const local = collector(async () => new Response(++calls === 1 ? identity() : event({ mutateEvent })));
    await failed(local.prepare(capture())); assert.equal(calls, 2);
  }
  let calls = 0;
  const local = collector(async () => { calls++; return new Response(identity()); });
  await failed(local.prepare({ ...capture(), accountId: '999999999999' })); assert.equal(calls, 1);
});

const rows = fixtures => fixtures.map(fixture => JSON.parse(body(fixture)).Events[0]);
const eventIds = requests => requests.slice(1).map(request => JSON.parse(request.body).LookupAttributes[0].AttributeValue);
const families = () => [eventFixture({ eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa0' }),
  activityEventFixture('lambda', { eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1' }),
  activityEventFixture('network', { eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2' }),
  activityEventFixture('s3-versioning', { eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3' })];
function pager(pages) {
  const queries = [];
  const local = collector(async (url, options) => {
    if (url === 'https://iam.amazonaws.com/') return new Response(identity());
    const query = JSON.parse(options.body); queries.push(query);
    return new Response(JSON.stringify(pages[queries.length - 1] ?? { Events: [] }));
  });
  return { local, queries };
}

test('selects one event per skill area in catalog order, whatever the page order', async () => {
  const { local, queries } = pager([{ Events: rows(families()).reverse() }]);
  const requests = await local.prepare(capture());
  assert.equal(queries.length, 1);
  assert.deepEqual(eventIds(requests), ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa0', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3'].slice(0, AWS_MAX_EVENT_SESSIONS));
  assert.doesNotMatch(JSON.stringify(requests), /AWS_PRIVATE_\w+_SENTINEL|111122223333|sg-0123456789abcdef0|192\.0\.2\.0/);
});

test('prefers an area\'s earlier catalog operation, and leaves areas past the cap out', async () => {
  const later = ['iam-attach', 'lambda-code'].map((family, index) => activityEventFixture(family, { eventId: `cccccccc-cccc-4ccc-8ccc-ccccccccccc${index}` }));
  const extra = ['changeset', 'ecs', 'ttl', 'alarm'].map((family, index) => activityEventFixture(family, { eventId: `dddddddd-dddd-4ddd-8ddd-ddddddddddd${index}` }));
  const { local } = pager([{ Events: rows([...extra, ...later, ...families()].reverse()) }]);
  const ids = eventIds(await local.prepare(capture()));
  assert.deepEqual(ids, [...families(), ...extra].map(fixture => JSON.parse(body(fixture)).Events[0].EventId).slice(0, AWS_MAX_EVENT_SESSIONS));
  const only = pager([{ Events: rows([...later].reverse()) }]);
  assert.deepEqual(eventIds(await only.local.prepare(capture())), ['cccccccc-cccc-4ccc-8ccc-ccccccccccc0', 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1']);
});

test('a repeated skill area keeps only its newest event', async () => {
  const newer = eventFixture({ eventId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb0' }), older = eventFixture({ eventId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1' });
  const { local } = pager([{ Events: rows([newer, older]) }]);
  assert.deepEqual(eventIds(await local.prepare(capture())), ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb0']);
});

test('pages past failed and differently attributed rows, and stops once every area is settled', async () => {
  const denied = activityEventFixture('network', { mutateEvent: event => { event.errorCode = 'AccessDenied'; } });
  const other = activityEventFixture('lambda', { mutateEvent: event => { event.userIdentity.principalId = 'OTHER'; } });
  const [iam, lambda, network, storage] = families();
  const first = pager([{ Events: rows([denied, other]), NextToken: 'second-page' }, { Events: rows([network]) }]);
  assert.deepEqual(eventIds(await first.local.prepare(capture())), ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2']);
  assert.deepEqual(first.queries.map(query => query.NextToken), [undefined, 'second-page']);
  const settled = pager([{ Events: rows([storage, network, lambda, iam]), NextToken: 'unused-page' }]);
  assert.equal((await settled.local.prepare(capture())).length, 1 + Math.min(AWS_MAX_EVENT_SESSIONS, families().length));
  assert.equal(settled.queries.length, 1);
});

test('discovery reads a bounded number of pages', async () => {
  const pages = Array.from({ length: 20 }, (_, index) => ({ Events: [], NextToken: `page-${index}` }));
  const { local, queries } = pager(pages);
  await failed(local.prepare(capture()));
  assert.equal(queries.length, AWS_LIMITS.discoveryPages);
});

test('discovery signer builds only the bounded Username query', async () => {
  const query = { kind: 'discovery', userName: 'synthetic', start: now / 1000 - 90 * 86400, end: now / 1000 };
  const request = await signAwsPrivateRequest(query, credentials(), { nonceMac: 'n'.repeat(43), now });
  assert.deepEqual(JSON.parse(request.body).LookupAttributes, [{ AttributeKey: 'Username', AttributeValue: 'synthetic' }]);
  for (const change of [{ userName: 'a/b' }, { userName: '' }, { userName: 'x'.repeat(65) }, { eventName: 'DeleteUser' },
    { start: query.end - 91 * 86400 }]) {
    await assert.rejects(signAwsPrivateRequest({ ...query, ...change }, credentials(), { nonceMac: 'n'.repeat(43), now }));
  }
});

test('malformed and looping pagination reject without a completed selection', async () => {
  for (const page of ['{"Events":{}}', '{"Events":[],"NextToken":"loop"}', '{"Events":[{}]}', 'not json']) {
    let calls = 0;
    const local = collector(async () => new Response(++calls === 1 ? identity() : page));
    await failed(local.prepare(capture())); assert.ok(calls <= 3);
  }
});

test('account binding is snapshotted before asynchronous identity fetch', async () => {
  const supplied = { ...capture(), accountId: '999999999999' };
  const local = collector(async () => { supplied.accountId = '111122223333'; return new Response(identity()); });
  await failed(local.prepare(supplied));
});

test('cancellation and expiry settle a pending response without follow-up requests', async () => {
  for (const expired of [false, true]) {
    let clock = now, resume, started;
    const ready = new Promise(resolve => { started = resolve; });
    const local = createAwsLocalSession({ attempt: attempt(), pages: false, now: () => clock, fetchAws: async () => {
      started(); return new Promise(resolve => { resume = resolve; });
    } });
    const pending = local.prepare(capture()); await ready;
    if (expired) clock += 300001; else local.clear();
    resume(new Response(identity())); await failed(pending);
  }
});


test('Fast collects only IAM identity and never queries CloudTrail', async () => {
  const calls = [];
  const local = createAwsLocalSession({ attempt: attempt(), pages: false, now: () => now, identityOnly: true,
    fetchAws: async (url, options) => { calls.push(url); assert.equal(url, 'https://iam.amazonaws.com/');
      assert.equal(options.body, 'Action=GetUser&Version=2010-05-08'); return new Response(identity()); } });
  const requests = await local.prepare(capture());
  assert.deepEqual(calls, ['https://iam.amazonaws.com/']);
  assert.equal(requests.length, 1); assert.equal(requests[0].url, 'https://iam.amazonaws.com/');
  assert.equal(requests[0].body, 'Action=GetUser&Version=2010-05-08');
  await failed(local.prepare(capture())); assert.equal(calls.length, 1);
});

test('collection failures carry a fixed stage code and no value', async () => {
  const stageOf = async (fetchAws, supplied = capture(), options = {}) => {
    const error = await createAwsLocalSession({ attempt: attempt(), pages: false, fetchAws, now: () => now, ...options }).prepare(supplied).then(() => null, e => e);
    assert.equal(error?.message, 'AWS_PRIVATE_COLLECTION_FAILED');
    return error.stage;
  };
  const early = { ...capture(), credentials: { ...credentials(), expiration: new Date(now + 200000).toISOString() } };
  assert.equal(await stageOf(async () => new Response(identity()), early), 'CREDENTIALS_EXPIRE_BEFORE_ATTEMPT');
  assert.equal(await stageOf(async () => new Response('{}', { status: 403 })), 'IDENTITY_FETCH_STATUS_403');
  assert.equal(await stageOf(async () => new Response('<x/>')), 'IDENTITY_PARSE');
  let calls = 0;
  assert.equal(await stageOf(async () => new Response(++calls === 1 ? identity() : JSON.stringify({ Events: [] }))), 'NO_EVENTS');
  calls = 0;
  assert.equal(await stageOf(async () => new Response(++calls === 1 ? identity() : '{"Events":[],"Other":1}')), 'DISCOVERY_PAGE');
});

test('page runs: a later discovery read that fails in transit keeps the pages read so far; a failed first read still fails', async () => {
  const fixture = identityFixture(), events = pageActivity();
  const identityBody = syntheticWitness(fixture).recv.slice(fixture.receipt.transcript.recv.indexOf('\r\n\r\n') + 4);
  const run = failAt => {
    let reads = 0;
    const local = createAwsLocalSession({ attempt: { ...fixtureExpected, expiresAt: fixtureExpected.issuedAt + 15 * 60 * 1000 },
      now: () => fixtureNow, fetchAws: async (url, options) => {
        if (url === 'https://iam.amazonaws.com/') return new Response(identityBody);
        // A dropped connection or the per-request timeout: fetch rejects before any response.
        if (++reads === failAt) throw new DOMException('signal timed out', 'TimeoutError');
        return new Response(pageLookup(events, options.body));
      } });
    const supplied = { credentials: { ...credentials(), expiration: new Date(fixtureNow + 3600000).toISOString() }, accountId: '111122223333' };
    return { local, pending: local.prepare(supplied) };
  };
  // The sixth read (the 60-90 day slice, which holds nothing) fails; every page before it was read.
  const late = run(6);
  const requests = await late.pending;
  assert.ok(requests.length >= 2);
  assert.ok(Object.keys(late.local.pageRows()).length >= 1);
  const error = await run(1).pending.then(() => null, e => e);
  assert.equal(error?.message, 'AWS_PRIVATE_COLLECTION_FAILED');
  assert.equal(error.stage, 'DISCOVERY_NETWORK');
});
