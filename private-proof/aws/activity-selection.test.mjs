import assert from 'node:assert/strict';
import test from 'node:test';
import { awsGroupLevel, awsJobGroups, awsDiscoveryPreview, packAwsSessions, rankAwsActivity } from './activity-selection.mjs';
import { discoverAwsActivity } from './activity-discovery.mjs';
import { AWS_SKILL_GROUPS } from './skill-groups.mjs';
import { DAY, END, IDENTITY, candidate as c, fakeLookup, row } from './activity-fixture.mjs';

const steps = ranking => ranking.picks.map(pick => `${pick.group}:${pick.step}`);
const level = (ranking, group) => ranking.groups.find(g => g.group === group).proven.level;

test('job tags name groups; a vague "AWS" or a job without AWS names none', () => {
  assert.deepEqual([...awsJobGroups(['AWS Lambda', 'dynamodb', 'Terraform', 'api_gateway'])].sort(), ['api-gateway', 'dynamodb', 'lambda']);
  assert.equal(awsJobGroups(['AWS', 'Amazon Web Services', 'cloud']).size, 0);
  assert.equal(awsJobGroups(['react', 'typescript']).size, 0);
});

test('levels: long spans tested small (days 1, 9, 20 reach Sustained; days 1, 9, 12 stay Repeated)', () => {
  const op = 'lambda:UpdateFunctionConfiguration20150331v2';
  const wide = [c(op, 1), c(op, 9), c(op, 20)], narrow = [c(op, 1), c(op, 9), c(op, 12)];
  assert.equal(level(rankAwsActivity(wide, { budget: 3 }), 'lambda'), 'sustained');
  assert.equal(level(rankAwsActivity(narrow, { budget: 3 }), 'lambda'), 'repeated');
  // Basic-only evidence stops at Repeated; a single day is Observed however many events it has.
  assert.equal(awsGroupLevel([c('lambda:CreateFunction20150331', 1), c('lambda:CreateFunction20150331', 9), c('lambda:CreateFunction20150331', 20)]).level, 'repeated');
  assert.equal(awsGroupLevel([c(op, 5), c(op, 5, { second: 10 })]).level, 'observed');
  // With a bigger budget the ladder still stops at the fewest events for the level: no step adds anything after 3.
  assert.equal(rankAwsActivity([...wide, c(op, 30), c(op, 40)], { budget: 10 }).picks.length, 3);
});

test('the trio is chosen to reach Sustained even when the best single events sit on close days', () => {
  const op = 'dynamodb:UpdateTable';
  const events = [c('dynamodb:UpdateContinuousBackups', 10), c('dynamodb:UpdateContinuousBackups', 11), c(op, 12), c(op, 26)];
  const ranking = rankAwsActivity(events, { budget: 3 });
  assert.equal(level(ranking, 'dynamodb'), 'sustained');
  assert.ok(ranking.groups[0].proven.advanced);
  assert.match(ranking.picks[0].reason, /first observation of DynamoDB tables; advanced operation; first advanced operation/);
});

test('burst gamer: 15 groups in 10 minutes give 15 first observations on one day, and nothing more', () => {
  const groups = ['iam-access', 'kms-keys', 'secrets-config', 'vpc-routing', 'network-access', 'dns', 'compute', 'lambda', 'api-gateway',
    'messaging', 'ecs', 'ecr', 'dynamodb', 's3', 'observability'];
  const firstOp = g => { const ops = { 'iam-access': 'CreateRole', 'kms-keys': 'CreateKey', 'secrets-config': 'CreateSecret',
    'vpc-routing': 'CreateVpc', 'network-access': 'CreateSecurityGroup', dns: 'CreateHostedZone', compute: 'RunInstances',
    lambda: 'CreateFunction20150331', 'api-gateway': 'CreateRestApi', messaging: 'CreateQueue', ecs: 'CreateCluster',
    ecr: 'CreateRepository', dynamodb: 'CreateTable', s3: 'CreateBucket', observability: 'PutMetricAlarm' }; return `${g}:${ops[g]}`; };
  const events = groups.flatMap((g, i) => [c(firstOp(g), 80, { second: i * 40 }), c(firstOp(g), 80, { second: i * 40 + 5 })]);
  const ranking = rankAwsActivity(events, { budget: 40 });
  assert.equal(ranking.picks.length, 15);
  assert.ok(ranking.picks.every(pick => pick.step === 'observed'));
  assert.equal(new Set(ranking.picks.map(pick => pick.day)).size, 1);
});

test('CI user: automated ops reach Repeated at most, never Sustained', () => {
  const events = Array.from({ length: 30 }, (_, day) => c('lambda:UpdateFunctionCode20150331v2', day + 1, { tool: 'sdk-other' }));
  const ranking = rankAwsActivity([...events, c('lambda:PublishVersion20150331', 40)], { budget: 12 });
  assert.equal(level(ranking, 'lambda'), 'repeated');
  assert.equal(ranking.picks.length, 2);                      // unused budget is not spent
  assert.match(ranking.picks[0].reason, /usually automated/);
});

test('breadth floor: every group gets a first observation before any depth, job groups ranked first', () => {
  const lambdaOps = ['lambda:UpdateFunctionConfiguration20150331v2', 'lambda:CreateAlias20150331', 'lambda:AddPermission20150331v2'];
  const events = [...lambdaOps.map((op, i) => c(op, 1 + i * 10)), c('s3:CreateBucket', 3), c('s3:PutBucketPolicy', 30),
    c('observability:PutMetricAlarm', 5), c('vpc-routing:CreateVpc', 7)];
  const ranking = rankAwsActivity(events, { budget: 7, jobTags: ['AWS Lambda'] });
  assert.deepEqual(steps(ranking).slice(0, 4).map(s => s.split(':')[1]), ['observed', 'observed', 'observed', 'observed']);
  assert.equal(ranking.picks[0].group, 'lambda');
  assert.deepEqual(steps(ranking).slice(4), ['lambda:repeated', 'lambda:sustained', 's3:repeated']);
  assert.match(ranking.picks[0].reason, /named by the job/);
});

test('job with named services, vague "AWS" and no AWS: the boost changes order, never what the groups can reach', () => {
  const events = [c('s3:PutBucketPolicy', 2), c('s3:PutBucketPolicy', 9), c('dynamodb:UpdateTable', 3), c('dynamodb:UpdateTable', 12),
    c('iam-access:PutRolePolicy', 4)];
  const named = rankAwsActivity(events, { budget: 4, jobTags: ['DynamoDB'] });
  assert.equal(named.picks[0].group, 'dynamodb');
  assert.equal(named.picks[3].group, 'dynamodb');               // depth goes to the job group first
  const vague = rankAwsActivity(events, { budget: 4, jobTags: ['AWS'] }), none = rankAwsActivity(events, { budget: 4, jobTags: ['Go', 'React'] });
  const plain = rankAwsActivity(events, { budget: 4 });
  assert.deepEqual(steps(vague), steps(plain));
  assert.deepEqual(steps(none), steps(plain));
  assert.ok(vague.picks.every(pick => !/named by the job/.test(pick.reason)));
});

test('job groups from the attempt weigh like the tags that name them; unknown ids are ignored, never a scope', async () => {
  const events = [c('s3:PutBucketPolicy', 2), c('s3:PutBucketPolicy', 9), c('dynamodb:UpdateTable', 3), c('dynamodb:UpdateTable', 12),
    c('iam-access:PutRolePolicy', 4)];
  const byTag = rankAwsActivity(events, { budget: 4, jobTags: ['DynamoDB'] }), byGroup = rankAwsActivity(events, { budget: 4, jobGroups: ['dynamodb'] });
  assert.deepEqual(byGroup.picks, byTag.picks);
  assert.deepEqual(byGroup.groups.filter(g => g.job).map(g => g.group), ['dynamodb']);
  // A group the job names but the candidate never touched adds nothing; an id from another catalog is ignored.
  const plain = rankAwsActivity(events, { budget: 4 });
  assert.deepEqual(steps(rankAwsActivity(events, { budget: 4, jobGroups: ['lambda', 'not-a-group'] })), steps(plain));
  assert.throws(() => rankAwsActivity(events, { budget: 4, jobGroups: 'dynamodb' }), /AWS_SELECTION_INVALID:jobGroups/);
  // Packing puts the sessions holding the job's groups first.
  const ago = (days, s = 0) => END - days * DAY - s;
  const rows = [row('lambda:UpdateFunctionConfiguration20150331v2', ago(1)), ...Array.from({ length: 60 }, (_, i) => row('read', ago(1, 10 + i))),
    row('dynamodb:UpdateTable', ago(20))];
  const discovery = await discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END });
  const order = jobGroups => packAwsSessions(rankAwsActivity(discovery.candidates, { budget: 2, jobGroups, discovery }).picks, discovery,
    { rowCap: 21, jobGroups }).sessions.map(s => s.groups.join());
  assert.deepEqual(order(['dynamodb']), ['dynamodb', 'lambda']);
  assert.deepEqual(order(['lambda']), ['lambda', 'dynamodb']);
});

test('budget smaller than the group count: job groups first, then by tier', () => {
  const events = [c('s3:CreateBucket', 1), c('kms-keys:PutKeyPolicy', 2), c('dns:ChangeResourceRecordSets', 3), c('ecr:CreateRepository', 4)];
  const ranking = rankAwsActivity(events, { budget: 2, jobTags: ['ecr'] });
  assert.deepEqual(steps(ranking), ['ecr:observed', 'kms-keys:observed']);
  assert.deepEqual(rankAwsActivity(events, { budget: 0 }).picks, []);
});

test('an advanced operation is worth one extra event only when the level set has none', () => {
  const events = [c('iam-access:CreateRole', 1), c('iam-access:CreateRole', 2), c('iam-access:PutRolePermissionsBoundary', 2, { second: 7 })];
  const ranking = rankAwsActivity(events, { budget: 5 });
  assert.deepEqual(steps(ranking), ['iam-access:observed', 'iam-access:repeated']);
  assert.ok(ranking.groups[0].proven.advanced);               // the pair already holds the advanced op
  const deep = [c('lambda:UpdateFunctionConfiguration20150331v2', 1), c('lambda:CreateAlias20150331', 15),
    c('lambda:AddPermission20150331v2', 30), c('lambda:PutFunctionConcurrency20171031', 31, { tool: 'terraform' })];
  const picked = rankAwsActivity(deep, { budget: 5 });
  assert.equal(level(picked, 'lambda'), 'sustained');
  assert.ok(picked.groups[0].proven.advanced);
});

test('deterministic: input order does not change the picks', () => {
  const events = [c('s3:PutBucketPolicy', 2), c('s3:PutBucketLifecycle', 2), c('s3:PutBucketEncryption', 20), c('s3:PutBucketPolicy', 40),
    c('ecs:CreateService', 3), c('ecs:CreateService', 3, { second: 9 }), c('dns:CreateHostedZone', 70)];
  const first = rankAwsActivity(events, { budget: 6 });
  for (let i = 0; i < 5; i++) {
    const shuffled = [...events].sort(() => Math.random() - 0.5);
    assert.deepEqual(rankAwsActivity(shuffled, { budget: 6 }), first);
  }
  assert.ok(first.picks.every(pick => typeof pick.reason === 'string' && pick.reason && pick.value > 0));
});

test('sessions: page windows of at most 50 rows and rowCap picks, fewest sessions, job sessions first', async () => {
  const ago = (days, s = 0) => END - days * DAY - s;
  const rows = [
    row('lambda:UpdateFunctionConfiguration20150331v2', ago(1, 100)), row('lambda:CreateAlias20150331', ago(1, 200)),
    ...Array.from({ length: 60 }, (_, i) => row('read', ago(1, 300 + i))),        // a wall of reads between two writes
    row('s3:PutBucketPolicy', ago(1, 500)),
    row('dynamodb:UpdateTable', ago(20)), row('dynamodb:UpdateTable', ago(21)), row('dynamodb:UpdateTable', ago(22)),
  ];
  const discovery = await discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END });
  const ranking = rankAwsActivity(discovery.candidates, { budget: 10, jobTags: ['lambda'] });
  const packed = packAwsSessions(ranking.picks, discovery, { rowCap: 2, jobTags: ['lambda'] });
  assert.deepEqual(packed.unplaced, []);
  assert.equal(packed.sessions.reduce((n, s) => n + s.eventIds.length, 0), ranking.picks.length);
  for (const s of packed.sessions) assert.ok(s.rows <= 50 && s.eventIds.length <= 2);
  assert.deepEqual(packed.sessions[0].groups, ['lambda']);
  // Lambda has one day only (one pick); the dynamodb pair fills one session at rowCap 2, so s3 needs its own.
  assert.deepEqual(packed.sessions.map(s => s.groups.join()), ['lambda', 'dynamodb', 's3']);
  const capped = packAwsSessions(ranking.picks, discovery, { rowCap: 2, jobTags: ['lambda'], maxSessions: 1 });
  assert.equal(capped.sessions.length, 1);
  assert.deepEqual(capped.deferred.map(s => s.groups.join()), ['dynamodb', 's3']);
  const wide = packAwsSessions(ranking.picks, discovery, { rowCap: 25 });
  assert.equal(wide.sessions.length, 2);                      // dynamodb and s3 share a window; the reads keep lambda apart
});

test('preview for the candidate: counts per group and the level this run proves, no dates', async () => {
  const ago = (days, s = 0) => END - days * DAY - s;
  const rows = [row('lambda:UpdateFunctionConfiguration20150331v2', ago(1)), row('lambda:CreateAlias20150331', ago(10)),
    row('lambda:AddPermission20150331v2', ago(30)), row('s3:CreateBucket', ago(2)), row('ecs:CreateService', ago(50))];
  const discovery = await discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END });
  const ranking = rankAwsActivity(discovery.candidates, { budget: 4, jobTags: ['lambda'] });
  const preview = awsDiscoveryPreview(discovery, ranking, packAwsSessions(ranking.picks, discovery, { rowCap: 25 }));
  const lambda = preview.groups.find(g => g.group === 'lambda');
  assert.deepEqual([lambda.found, lambda.thisRun, lambda.days], ['sustained', 'repeated', 3]);
  assert.deepEqual(preview.groups.map(g => `${g.group}:${g.thisRun}`), ['lambda:repeated', 'ecs:observed', 's3:observed']);
  assert.equal(preview.activeDays, 5);
  assert.equal(preview.provenEvents, 4);
  const text = JSON.stringify(preview);
  assert.doesNotMatch(text, /20\d\d-\d\d|"time"|"day"|"start"|"end"/);
  assert.ok(AWS_SKILL_GROUPS.some(g => g.label === lambda.label));
});

test('ties prefer a body that fits the five-row batch proof, then an event sharing a window with an earlier pick', async () => {
  const op = 'lambda:UpdateFunctionConfiguration20150331v2';
  const big = { ...c(op, 5, { second: 100 }), body: 1500 }, small = { ...c(op, 5, { second: 50 }), body: 400 };
  assert.equal(rankAwsActivity([big, small], { budget: 1 }).picks[0].eventId, small.eventId);
  // Two equal S3 events on day 30: one next to the Lambda pick's window, one behind 60 reads. The near one is taken.
  const ago = (days, s = 0) => END - days * DAY - s;
  const rows = [row(op, ago(30, 100)), row('s3:PutBucketPolicy', ago(30, 200)),
    ...Array.from({ length: 60 }, (_, i) => row('read', ago(30, 300 + i))), row('s3:PutBucketPolicy', ago(30, 400))];
  const discovery = await discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END });
  const near = discovery.candidates.find(e => e.time === ago(30, 200)), far = discovery.candidates.find(e => e.time === ago(30, 400));
  const picks = rankAwsActivity(discovery.candidates.filter(e => e !== near), { budget: 2 }).picks;
  assert.ok(picks.some(pick => pick.eventId === far.eventId));
  const swapped = rankAwsActivity(discovery.candidates, { budget: 2, discovery }).picks;
  assert.ok(swapped.some(pick => pick.eventId === near.eventId));
  assert.equal(packAwsSessions(swapped, discovery, { rowCap: 21 }).sessions.length, 1);
});

test('page windows never share a second, so no row can be proven twice', async () => {
  const ago = (days, s = 0) => END - days * DAY - s;
  const op = 'dynamodb:UpdateTable';
  const rows = [row(op, ago(3, 10)), row('lambda:UpdateFunctionConfiguration20150331v2', ago(3, 10)), row('s3:PutBucketPolicy', ago(3, 11)),
    row('iam-access:CreateRole', ago(3, 12))];
  const discovery = await discoverAwsActivity({ read: fakeLookup(rows), identity: IDENTITY, end: END });
  const ranking = rankAwsActivity(discovery.candidates, { budget: 4 });
  const { sessions, unplaced } = packAwsSessions(ranking.picks, discovery, { rowCap: 1 });
  const windows = [...sessions].sort((a, b) => a.start - b.start);
  for (let i = 1; i < windows.length; i++) assert.ok(windows[i].start > windows[i - 1].end);
  // Two picks in one second cannot be split across sessions: with a cap of one row, the second one waits.
  assert.equal(unplaced.length, 1);
  assert.equal(sessions.length, 3);
});
