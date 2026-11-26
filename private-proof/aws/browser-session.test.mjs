import test from 'node:test';
import assert from 'node:assert/strict';
import { awsPrivateCredentials, signAwsPrivateRequest, readAwsPrivateResponse, createAwsLocalSession } from './browser-session.mjs';
import { identityFixture } from './identity-fixture.mjs';
import { syntheticWitness } from './event-fixture.mjs';
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
const failed = operation => assert.rejects(operation, { message: 'AWS_PRIVATE_COLLECTION_FAILED' });
const collector = fetchAws => createAwsLocalSession({ attempt: attempt(), fetchAws, now: () => now });

test('WebCrypto signatures match offline botocore IAM and CloudTrail vectors', async () => {
  // botocore SigV4Auth, frozen 2026-10-29T08:00:00Z, explicit synthetic credentials; no network.
  for (const [options, signature] of [
    [{ kind: 'identity' }, 'daaa7d2f390b845c781edfffe6965c8c0d9a73f53220433d104d1181d111577d'],
    [{ kind: 'event', eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, '6e768745cd93d552150b209fba4c2c12c6fa45d9a9ab9cd91c0ac8e03fa850a3'],
  ]) {
    const request = await signAwsPrivateRequest(options, credentials(), { nonceMac: 'n'.repeat(43), now });
    assert.ok(request.headers.authorization.endsWith(`Signature=${signature}`));
    assert.equal(request.headers['x-amz-date'], '20261029T080000Z');
    assert.equal(request.headers['x-tlsn-nonce'], 'n'.repeat(43));
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
  assert.ok((await pending).headers.authorization.endsWith('Signature=daaa7d2f390b845c781edfffe6965c8c0d9a73f53220433d104d1181d111577d'));
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
  const denied = calls;
  await failed(local.prepare(capture()));
  assert.equal(calls, denied);
});

test('a different account than the capture claims never collects', async () => {
  let calls = 0;
  const local = collector(async () => { calls++; return new Response(identity()); });
  await failed(local.prepare({ ...capture(), accountId: '999999999999' })); assert.equal(calls, 1);
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

test('account binding is snapshotted before asynchronous identity fetch', async () => {
  const supplied = { ...capture(), accountId: '999999999999' };
  const local = collector(async () => { supplied.accountId = '111122223333'; return new Response(identity()); });
  await failed(local.prepare(supplied));
});

test('cancellation and expiry settle a pending response without follow-up requests', async () => {
  for (const expired of [false, true]) {
    let clock = now, resume, started;
    const ready = new Promise(resolve => { started = resolve; });
    const local = createAwsLocalSession({ attempt: attempt(), now: () => clock, fetchAws: async () => {
      started(); return new Promise(resolve => { resume = resolve; });
    } });
    const pending = local.prepare(capture()); await ready;
    if (expired) clock += 300001; else local.clear();
    resume(new Response(identity())); await failed(pending);
  }
});


test('Fast collects only IAM identity and never queries CloudTrail', async () => {
  const calls = [];
  const local = createAwsLocalSession({ attempt: attempt(), now: () => now, identityOnly: true,
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
    const error = await createAwsLocalSession({ attempt: attempt(), fetchAws, now: () => now, ...options }).prepare(supplied).then(() => null, e => e);
    assert.equal(error?.message, 'AWS_PRIVATE_COLLECTION_FAILED');
    return error.stage;
  };
  const early = { ...capture(), credentials: { ...credentials(), expiration: new Date(now + 200000).toISOString() } };
  assert.equal(await stageOf(async () => new Response(identity()), early), 'CREDENTIALS_EXPIRE_BEFORE_ATTEMPT');
  assert.equal(await stageOf(async () => new Response('{}', { status: 403 })), 'IDENTITY_FETCH_STATUS_403');
  assert.equal(await stageOf(async () => new Response('<x/>')), 'IDENTITY_PARSE');
  let calls = 0;
  assert.equal(await stageOf(async () => new Response(++calls === 1 ? identity() : JSON.stringify({ Events: [] }))), 'NO_EVENTS');
});

test('page runs: a discovery read failing in transit is retried; one that keeps failing keeps the pages read so far; a failing first read still fails', async () => {
  const fixture = identityFixture(), events = pageActivity();
  const identityBody = syntheticWitness(fixture).recv.slice(fixture.receipt.transcript.recv.indexOf('\r\n\r\n') + 4);
  // `failing(n, url)`: whether the n-th CloudTrail read (retries included, any lane) fails in transit.
  const run = failing => {
    let reads = 0;
    const local = createAwsLocalSession({ attempt: { ...fixtureExpected, expiresAt: fixtureExpected.issuedAt + 15 * 60 * 1000 },
      now: () => fixtureNow, fetchAws: async (url, options) => {
        if (url === 'https://iam.amazonaws.com/') return new Response(identityBody);
        // A dropped connection or the per-request timeout: fetch rejects before any response.
        if (failing(++reads, url)) throw new DOMException('signal timed out', 'TimeoutError');
        return new Response(pageLookup(events, options.body));
      } });
    const supplied = { credentials: { ...credentials(), expiration: new Date(fixtureNow + 3600000).toISOString() }, accountId: '111122223333' };
    return { local, pending: local.prepare(supplied) };
  };
  const steady = run(() => false);
  await steady.pending;
  const expected = steady.local.pageRows();
  // One dropped read is retried: the run sees and proves exactly what a run without the failure does.
  const blip = run(n => n === 3);
  await blip.pending;
  assert.deepEqual(blip.local.pageRows(), expected);
  assert.equal(blip.local.discoveryReport().homeComplete, true);
  // eu-west-1 keeps failing through both retries: the run goes on with everything else and names the unread Region.
  const late = run((_n, url) => url.includes('eu-west-1'));
  const requests = await late.pending;
  assert.ok(requests.length >= 2);
  assert.deepEqual(late.local.pageRows(), expected);
  assert.deepEqual(late.local.discoveryReport(), { unread: ['eu-west-1'], homeComplete: true });
  // us-east-1 (identity's home, global services) failing on every try still fails the run.
  const error = await run((_n, url) => url.includes('us-east-1')).pending.then(() => null, e => e);
  assert.equal(error?.message, 'AWS_PRIVATE_COLLECTION_FAILED');
  // DISCOVERY_NETWORK when it is the run's very first read, DISCOVERY when Region probes answered first.
  assert.match(error.stage, /^DISCOVERY(?:_NETWORK)?$/);
});
