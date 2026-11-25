import assert from 'node:assert/strict';
import test from 'node:test';
import { awsDiscoveryCandidate, awsDiscoverySlices, awsWindowRows, discoverAwsActivity } from './activity-discovery.mjs';
import { DAY, END, IDENTITY, fakeLookup, row } from './activity-fixture.mjs';

const ago = (days, seconds = 0) => END - days * DAY - seconds;
const discover = (rows, options = {}) => discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END, ...options });

test('six newest-first slices cover the 90 days, neighbours sharing one second', () => {
  const slices = awsDiscoverySlices(END);
  assert.equal(slices.length, 6);
  assert.equal(slices[0].end, END);
  assert.equal(slices.at(-1).start, END - 90 * DAY);
  for (let i = 1; i < slices.length; i++) assert.equal(slices[i].end, slices[i - 1].start);
  assert.throws(() => awsDiscoverySlices(1.5), /AWS_DISCOVERY_INVALID/);
});

test('keeps only successful catalog writes by exactly the proven IAM user', () => {
  const window = { identity: IDENTITY, start: END - 90 * DAY, end: END };
  const check = r => awsDiscoveryCandidate(r, JSON.parse(r.CloudTrailEvent), window);
  const good = check(row('lambda:UpdateFunctionConfiguration20150331v2', ago(2), { tool: 'terraform' }));
  assert.deepEqual({ ...good, eventId: undefined }, { eventId: undefined, region: 'us-east-1', time: ago(2), day: Math.floor(ago(2) / DAY),
    eventSource: 'lambda.amazonaws.com', eventName: 'UpdateFunctionConfiguration20150331v2', group: 'lambda', tier: 'intermediate',
    auto: false, tool: 'terraform', body: good.body });
  assert.ok(good.body > 0 && good.body < 1238);
  assert.equal(check(row('iam-access:CreateRole', ago(1), { tool: 'console' })).tool, 'console');
  const rejected = [
    row('read', ago(1)),                                                              // read-only
    row('iam-access:CreateRole', ago(1), { error: true }),                                   // failed (also EC2 dry runs)
    row('iam-access:CreateRole', ago(1), { actor: { principalId: 'AIDAOTHERPRINCIPAL0001' } }), // another user
    row('iam-access:CreateRole', ago(1), { actor: { arn: 'arn:aws:iam::111122223333:user/other' } }),
    row('iam-access:CreateRole', ago(1), { actor: { accountId: '444455556666' } }),           // another account
    row('iam-access:CreateRole', ago(1), { actor: { type: 'AssumedRole' } }),                // a role session
    row('iam-access:CreateRole', ago(1), { actor: { invokedBy: 'cloudformation.amazonaws.com' } }), // a service acting for the user
    row('iam-access:CreateRole', ago(1), { region: 'eu-west-1' }),                           // another Region
    row('iam-access:CreateRole', ago(1), { userAgent: null }),                               // no userAgent: not provable
    row('iam-access:CreateRole', ago(1), { userAgent: 'aws-cli/2 "quoted"' }),               // userAgent with a quote: not provable
    row('iam-access:CreateRole', ago(91)),                                                   // outside the 90 days
  ];
  for (const r of rejected) assert.equal(check(r), null);
  const unknown = row('iam-access:CreateRole', ago(1));
  assert.equal(check({ ...unknown, CloudTrailEvent: unknown.CloudTrailEvent.replace('"CreateRole"', '"DeleteRole"') }), null); // not in the catalog
  assert.equal(check({ ...unknown, EventId: '00000000-0000-4000-8000-999999999999' }), null);                                // row and event disagree
  assert.equal(check({ ...unknown, EventTime: unknown.EventTime + 5 }), null);
});

test('a busy recent day does not hide older activity (one newest-first query would stop there)', async () => {
  const reads = Array.from({ length: 300 }, (_, i) => row('read', ago(0, 60 + i)));
  const older = [row('iam-access:CreateRole', ago(10)), row('dynamodb:CreateTable', ago(40)), row('s3:PutBucketPolicy', ago(80))];
  const found = await discover([...reads, row('lambda:CreateFunction20150331', ago(0, 30)), ...older], { maxPages: 10 });
  assert.deepEqual(found.candidates.map(c => c.group), ['lambda', 'iam-access', 'dynamodb', 's3']);
  // The same budget as a single 90-day newest-first query would have read only the 300 reads plus the newest write.
  assert.equal(found.requests, 10);
});

test('slices that come back empty leave their pages to the busy ones', async () => {
  const rows = Array.from({ length: 400 }, (_, i) => row('read', ago(1, i * 10)));
  const read = fakeLookup(rows);
  const found = await discoverAwsActivity({ read, identity: IDENTITY, end: END, maxPages: 12 });
  assert.equal(found.requests, 12);
  assert.deepEqual(found.slices.map(s => s.pages), [7, 1, 1, 1, 1, 1]);
  assert.deepEqual(found.slices.map(s => s.complete), [false, true, true, true, true, true]);
  // Round robin: the first six requests read the newest page of every slice, newest slice first.
  assert.deepEqual(read.calls.slice(0, 6).map(c => c.end), awsDiscoverySlices(END).map(s => s.end));
});

test('stops starting requests when the time budget is spent', async () => {
  const rows = Array.from({ length: 400 }, (_, i) => row('read', ago(1, i * 10)));
  let clock = 0;
  const read = fakeLookup(rows), timed = async options => { clock += 1200; return read(options); };
  const found = await discoverAwsActivity({ read: timed, identity: IDENTITY, end: END, timeMs: 10000, now: () => clock });
  assert.equal(found.requests, 9);                            // the 9th starts at 9.6 s, the 10th would start at 10.8 s
});

test('a later read that failed in transit ends discovery with the pages read so far; a failed first read fails', async () => {
  const rows = [row('iam-access:CreateRole', ago(1)), row('dynamodb:UpdateTable', ago(5)), row('lambda:CreateFunction20150331', ago(10))];
  const lookup = fakeLookup(rows);
  let calls = 0;
  const read = async options => (++calls === 3 ? null : lookup(options));
  const found = await discoverAwsActivity({ read, identity: IDENTITY, end: END });
  assert.equal(found.requests, 3);
  assert.deepEqual(found.slices.map(s => s.complete), [true, true, false, false, false, false]);
  assert.deepEqual(found.candidates.map(c => c.eventName), ['CreateRole', 'UpdateTable']);
  assert.equal(awsWindowRows(found, ago(10, 1), ago(10, -1)), null);  // the failed slice stays unknown
  await assert.rejects(discoverAwsActivity({ read: async () => null, identity: IDENTITY, end: END }), /AWS_DISCOVERY_INVALID:read/);
});

test('stops at the page budget and knows exactly which time ranges it saw in full', async () => {
  const rows = [
    ...Array.from({ length: 120 }, (_, i) => row(i % 4 ? 'read' : 'iam-access:AttachRolePolicy', ago(5, i * 60))),
    row('dynamodb:UpdateTable', ago(50)),
  ];
  const found = await discover(rows, { maxPages: 7 });
  const slice = found.slices[1];                              // 3-7 days: 120 rows in 3 pages; the budget leaves it at 2
  assert.deepEqual([slice.pages, slice.complete], [2, false]);
  const oldestSeen = ago(5, 99 * 60);
  assert.equal(awsWindowRows(found, oldestSeen + 1, ago(5)), 99);
  assert.equal(awsWindowRows(found, oldestSeen, ago(5)), null);  // rows of that second may continue on the next page
  assert.equal(awsWindowRows(found, ago(60), ago(40)), 1);      // complete older slices merge into one range
  assert.ok(found.candidates.filter(c => c.group === 'iam-access').every(c => c.time > oldestSeen));
  assert.equal(found.candidates.filter(c => c.group === 'iam-access').length, 25);
  assert.ok(found.candidates.some(c => c.group === 'dynamodb'));
});

test('an event inside a burst of more than 50 rows around its second cannot be placed and is dropped', async () => {
  const burst = Array.from({ length: 60 }, () => row('read', ago(2)));
  const found = await discover([...burst, row('iam-access:CreateRole', ago(2)), row('iam-access:PutRolePolicy', ago(20))]);
  assert.deepEqual(found.candidates.map(c => c.eventName), ['PutRolePolicy']);
});

test('dedupes rows seen in two slices and fails closed on malformed pages', async () => {
  const shared = row('iam-access:CreateRole', ago(3));               // exactly on the 0-3 / 3-7 boundary second
  const found = await discover([shared]);
  assert.equal(found.candidates.length, 1);
  assert.equal(found.times.length, 1);
  const bad = text => discoverAwsActivity({ read: async () => text, identity: IDENTITY, end: END });
  await assert.rejects(bad('not json'), /AWS_DISCOVERY_INVALID:page/);
  await assert.rejects(bad(JSON.stringify({ Events: [], Extra: 1 })), /AWS_DISCOVERY_INVALID:page/);
  await assert.rejects(bad(JSON.stringify({ Events: [{ ...shared, EventTime: 'x' }] })), /AWS_DISCOVERY_INVALID:row/);
  await assert.rejects(bad(JSON.stringify({ Events: [], NextToken: 'same' })), /AWS_DISCOVERY_INVALID:token/);
});
