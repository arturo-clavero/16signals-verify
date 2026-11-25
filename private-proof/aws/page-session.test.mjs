import assert from 'node:assert/strict';
import test from 'node:test';
import { pageEvent, pageSessionFixture, pageClaims, nativeReceipt, PAGE_IDENTITY } from './page-fixture.mjs';
import { inspectAwsPageSession } from './page-session.mjs';
import { planAwsPageSession } from './page-plan.mjs';
import { fixtureNow } from './event-fixture.mjs';

const DAY = 86400, now = Math.floor(fixtureNow / 1000), userLength = PAGE_IDENTITY.userName.length;
const write = (index, options = {}) => pageEvent(index, { eventSource: 'iam.amazonaws.com', eventName: 'AttachRolePolicy', time: now - 2 * DAY - index, ...options });
const inspect = (fixture, length = userLength) => inspectAwsPageSession(fixture.receipt, fixture.expected, pageClaims(fixture), length, fixtureNow);
const rejects = (fixture, length) => assert.throws(() => inspect(fixture, length), { message: 'AWS_PRIVATE_PAGE_INVALID' });
/** Re-issue a receipt for a changed plan (a prover that does not follow the planner). */
const forged = (fixture, change) => {
  const plan = structuredClone(fixture.plan);
  change(plan.recvRangesWithHandlers, fixture.plaintext.recv);
  plan.recvRangesWithHandlers.sort((a, b) => a.start - b.start);
  return { ...fixture, ...nativeReceipt({ expected: fixture.expected, ...fixture.plaintext, plan, blinderSeed: 'forged' }), plan };
};
const reveal = (start, end) => ({ start, end, handler: { type: 'RECV', part: 'BODY', action: { kind: 'REVEAL' } } });

test('proves plain, console and S3 rows; failed, delegated, agentless and reordered rows stay gaps', () => {
  const events = [
    write(1), write(2, { console: true, agent: 'console' }),
    write(3, { eventSource: 's3.amazonaws.com', eventName: 'PutBucketVersioning', host: 'private-bucket-name.s3.us-east-1.amazonaws.com', keyExchange: true }),
    write(4, { errorCode: 'AccessDenied' }), write(5, { invokedBy: 'cloudformation.amazonaws.com' }), write(6, { noUserAgent: true }),
    write(7, { swapOperation: true }), write(8, { eventSource: 'iam.amazonaws.com', eventName: 'GetRole', readOnly: true }),
  ];
  const fixture = pageSessionFixture({ events });
  const result = inspect(fixture);
  assert.deepEqual(result.rows.map(row => [row.eventSource, row.eventName, row.group, row.day]), [
    ['iam.amazonaws.com', 'AttachRolePolicy', 'iam-access', Math.floor((now - 2 * DAY) / DAY)],
    ['iam.amazonaws.com', 'AttachRolePolicy', 'iam-access', Math.floor((now - 2 * DAY) / DAY)],
    ['s3.amazonaws.com', 'PutBucketVersioning', 's3', Math.floor((now - 2 * DAY) / DAY)]]);
  assert.equal(result.obligations.filter(slot => slot.circuitId === 'atom-v1').length, 1);
  const seen = fixture.receipt.transcript.recv + fixture.receipt.transcript.sent;
  for (const secret of [PAGE_IDENTITY.principalId, PAGE_IDENTITY.account, PAGE_IDENTITY.userName, 'private-bucket-name', 'aws-cli',
    'console.amazonaws.com', '192.0.2.10', 'synthetic-resource', 'AKIAEXAMPLE', 'synthetic-request-id', 'SYNTHETIC_PRIVATE']) {
    assert.ok(!seen.includes(secret), secret);
  }
  assert.doesNotMatch(seen, /T\d\d:\d\d:\d\dZ/);
});

test('rejects windows past 90 days or after the attempt', () => {
  const old = write(1, { time: now - 95 * DAY });
  rejects(pageSessionFixture({ events: [old], start: now - 96 * DAY, end: now - 94 * DAY }));
  // Issued five days ago: a window ending today is after the attempt.
  const issuedAt = fixtureNow - 5 * DAY * 1000, late = pageSessionFixture({ events: [write(1, { time: now - 7 * DAY })], issuedAt,
    start: now - 10 * DAY, end: now });
  late.expected.expiresAt = issuedAt + 1000;
  assert.throws(() => inspectAwsPageSession(late.receipt, late.expected, pageClaims(late), userLength, issuedAt + 500), { message: 'AWS_PRIVATE_PAGE_INVALID' });
  const inside = pageSessionFixture({ events: [write(1, { time: now - 7 * DAY })], issuedAt, start: now - 10 * DAY, end: now - 5 * DAY });
  inside.expected.expiresAt = issuedAt + 1000;
  assert.equal(inspectAwsPageSession(inside.receipt, inside.expected, pageClaims(inside), userLength, issuedAt + 500).rows.length, 1);
  // A row outside its request window cannot come from AWS: the planner's own check refuses the revealed day.
  assert.throws(() => pageSessionFixture({ events: [write(1, { time: now - 30 * DAY })], start: now - 10 * DAY, end: now - DAY }),
    { message: 'AWS_PRIVATE_CLIENT_INVALID' });
});

test('rejects chunked, encoded or kept-alive responses', () => {
  // The planner runs the verifier's page inspection on what it would reveal, so these fail there.
  assert.throws(() => pageSessionFixture({ events: [write(1)], chunked: true }), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
  for (const headers of [
    [['content-type', 'application/x-amz-json-1.1'], ['content-encoding', 'gzip'], ['connection', 'close']],
    [['content-type', 'application/x-amz-json-1.1'], ['connection', 'keep-alive']],
    [['content-type', 'application/x-amz-json-1.1']],
    [['content-type', 'text/html'], ['connection', 'close']]]) {
    assert.throws(() => pageSessionFixture({ events: [write(1)], headers }), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
  }
  assert.equal(inspect(pageSessionFixture({ events: [write(1)], headers: [['content-type', 'application/x-amz-json-1.1'], ['connection', 'close']] })).rows.length, 1);
});

test('rejects another user name length, extra reveals and unproven commitments', () => {
  const fixture = pageSessionFixture({ events: [write(1), write(2)] });
  assert.equal(inspect(fixture).rows.length, 2);
  rejects(fixture, userLength + 1);
  const recv = fixture.plaintext.recv.toString('latin1');
  // Revealing the time of day (the gap after the date) changes the chain.
  const time = recv.indexOf('T', recv.indexOf('\\"eventTime\\":\\"') + 16);
  rejects(forged(fixture, ranges => { ranges.push(reveal(time, time + 10)); }));
  // Revealing the source IP gap.
  const ip = recv.indexOf('\\"192.0.2.10\\"');
  rejects(forged(fixture, ranges => { ranges.push(reveal(ip, ip + 14)); }));
  // A commitment outside any row chain has no proof that consumes it.
  const id = recv.indexOf('"EventId":"') + 11;
  rejects(forged(fixture, ranges => { ranges.push({ start: id, end: id + 36, handler: { type: 'RECV', part: 'BODY', action: { kind: 'HASH', algorithm: 'SHA256' } } }); }));
  // Dropping one row's recipient commitment breaks its chain.
  rejects(forged(fixture, ranges => {
    const at = ranges.findIndex(range => range.handler.action.kind === 'HASH' && range.end - range.start === 16 && range.start > 400);
    ranges.splice(at, 1);
  }));
});

test('a failed write claimed as a success has no provable layout', () => {
  // The planner never selects it; a prover revealing the same layout must commit the errorCode inside the body,
  // which the batch circuit rejects (the userAgent must be followed by requestParameters).
  const fixture = pageSessionFixture({ events: [write(1), write(2, { errorCode: 'Client.DryRunOperation' })] });
  assert.equal(inspect(fixture).rows.length, 1);
  assert.throws(() => pageSessionFixture({ events: [write(2, { errorCode: 'AccessDenied' })] }), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
});

test('the planner stops at the row cap and the reveal ceiling', () => {
  const events = Array.from({ length: 40 }, (_, index) => write(index + 1, { padding: 600 }));
  const fixture = pageSessionFixture({ events });
  const rows = inspect(fixture).rows.length;
  assert.ok(rows <= 21 && rows >= 10, String(rows));
  const meta = { step: 'P0', serverName: 'cloudtrail.us-east-1.amazonaws.com', nonceMac: fixture.expected.nonceMac };
  assert.throws(() => planAwsPageSession(meta, fixture.plaintext, new Set(['not-on-this-page'])), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
});

test('the client host header is a committed escaped string: revealed or unproven, the row fails', () => {
  const fixture = pageSessionFixture({ events: [write(1, { host: 'private-bucket-name.s3.us-east-1.amazonaws.com' })] });
  const claims = pageClaims(fixture), host = claims.find(claim => claim.layer === 'event');
  assert.ok(host && !fixture.receipt.transcript.recv.includes('private-bucket-name'));
  assert.throws(() => inspectAwsPageSession(fixture.receipt, fixture.expected, claims.filter(claim => claim !== host), userLength, fixtureNow),
    { message: 'AWS_PRIVATE_PAGE_INVALID' });
  assert.throws(() => inspectAwsPageSession(fixture.receipt, fixture.expected, claims.map(claim => claim === host ? { ...claim, kind: 2 } : claim),
    userLength, fixtureNow), { message: 'AWS_PRIVATE_PAGE_INVALID' });
  rejects(forged(fixture, ranges => {
    const at = ranges.findIndex(range => range.start === host.start);
    ranges[at] = reveal(host.start, host.end);
  }));
});
