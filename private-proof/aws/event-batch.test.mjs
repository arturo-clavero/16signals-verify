import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { awsCircuitInputs } from './circuit-inputs.mjs';
import { AWS_BATCH_CAPACITY, AWS_EVENT_BATCH_CIRCUITS, assembleAwsBatchExpectations, awsBatchCircuitFor, awsBatchToolClasses } from './event-batch.mjs';

const issuedAt = Date.parse('2026-11-24T12:00:00Z');
let next = 0;
const slot = (bytes, start = 100) => ({ hash: createHash('sha256').update(String(next++)).digest('hex'), start, end: start + bytes });
const identity = () => ({ UserId: slot(21), Arn: slot(45), Path: slot(1), UserName: slot(15) });
const row = (body = 900, extra = {}) => ({ eventSource: 'iam.amazonaws.com', eventName: 'UpdateAssumeRolePolicy', day: '2026-11-20',
  actor: slot(120), body: slot(body), recipient: slot(16), ...extra });
const plan = (rows, id = identity(), options = {}) => assembleAwsBatchExpectations(id, rows, { issuedAt, ...options });
const invalid = { message: 'AWS_PRIVATE_BATCH_INVALID' };

test('the JavaScript capacities equal the circuits', async () => {
  const lib = await readFile(new URL('./circuits/lib/src/batch.nr', import.meta.url), 'utf8');
  const global = name => Number(lib.match(new RegExp(`^pub global ${name}: u32 = (\\d+);$`, 'm'))[1]);
  assert.deepEqual({ UserId: global('RAW_ID'), Arn: global('RAW_ARN'), Path: global('RAW_PATH'), UserName: global('RAW_USER'),
    actor: global('ACTOR'), recipient: global('RECIPIENT') }, { ...AWS_BATCH_CAPACITY });
  for (const [dir, circuit] of [['event-batch', AWS_EVENT_BATCH_CIRCUITS[0]], ['event-batch-wide', AWS_EVENT_BATCH_CIRCUITS[1]]]) {
    const main = await readFile(new URL(`./circuits/${dir}/src/main.nr`, import.meta.url), 'utf8');
    assert.equal(Number(main.match(/^global K: u32 = (\d+);$/m)[1]), circuit.rows);
    assert.equal(global('UA') + 22 + Number(main.match(/^global BODY: u32 = UA \+ 22 \+ (\d+);$/m)[1]), circuit.bodyBytes);
  }
  // One classifier: the batch and class circuits both use the shared library copy.
  assert.match(lib, /tool::classify\(decoded, ua_length - 2\)/);
  assert.doesNotMatch(await readFile(new URL('./circuits/user-agent-class/src/main.nr', import.meta.url), 'utf8'), /fn classify/);
});

test('plans one proof per five short rows and pads with a proven row', () => {
  const rows = Array.from({ length: 7 }, () => row());
  const targets = plan(rows);
  assert.deepEqual(targets.map(t => [t.circuitId, t.rows]), [['aws-event-batch-v1', [0, 1, 2, 3, 4]], ['aws-event-batch-v1', [5, 6, 6, 6, 6]]]);
  const inputs = targets[1].publicInputs;
  assert.equal(inputs.length, 632);
  assert.deepEqual(inputs.slice(128, 132), [21, 45, 1, 15]);
  // Per slot: actor, body, recipient hashes, then all lengths, then the tool classes.
  assert.deepEqual(inputs.slice(132, 164), [...Buffer.from(rows[5].actor.hash, 'hex')]);
  assert.deepEqual(inputs.slice(132 + 3 * 32, 132 + 4 * 32), [...Buffer.from(rows[6].actor.hash, 'hex')]);
  assert.deepEqual(inputs.slice(612, 618), [120, 900, 16, 120, 900, 16]);
  assert.deepEqual(inputs.slice(627), [null, null, null, null, null]);
});

test('long rows take the wide circuit and its free slots take short rows', () => {
  const rows = [row(), row(2000), row(), row(1300)];
  const targets = plan(rows);
  assert.deepEqual(targets.map(t => [t.circuitId, t.rows]), [['aws-event-batch-wide-v1', [1, 3, 0]], ['aws-event-batch-v1', [2, 2, 2, 2, 2]]]);
  assert.equal(targets[0].publicInputs.length, 432);
  assert.equal(awsBatchCircuitFor(row(1238)).circuitId, 'aws-event-batch-v1');
  assert.equal(awsBatchCircuitFor(row(1239)).circuitId, 'aws-event-batch-wide-v1');
  assert.equal(awsBatchCircuitFor(row(2391)), undefined);
});

test('rows that cannot be proven fail closed', () => {
  const cases = {
    oversizedBody: row(2391), longActor: row(900, { actor: slot(257) }), shortRecipient: row(900, { recipient: slot(15) }),
    readOnlyOperation: row(900, { eventName: 'GetRole' }), ec2ReadOnly: row(900, { eventSource: 'ec2.amazonaws.com', eventName: 'DescribeInstances' }),
    unknownSource: row(900, { eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole' }),
    outOfWindow: row(900, { day: '2026-08-25' }), futureDay: row(900, { day: '2026-11-25' }), badDay: row(900, { day: '2026-02-30' }),
    noDay: row(900, { day: undefined }), emptySlot: row(900, { body: { ...slot(1), end: 100 } }), badHash: row(900, { actor: { ...slot(120), hash: 'x' } }),
  };
  for (const [name, bad] of Object.entries(cases)) assert.throws(() => plan([row(), bad]), invalid, name);
  // The window edge is inclusive: 90 days back from the issue day.
  assert.equal(plan([row(900, { day: '2026-08-26' })]).length, 1);
  assert.throws(() => plan([]), invalid);
});

test('identity spans over the circuit capacity fail closed', () => {
  for (const [name, bytes] of [['UserId', 65], ['Arn', 129], ['Path', 65], ['UserName', 65]]) {
    assert.throws(() => plan([row()], { ...identity(), [name]: slot(bytes) }), invalid, name);
  }
});

test('a row or a span claimed twice is rejected; padding counts once', () => {
  const a = row();
  assert.throws(() => plan([a, a]), invalid);
  assert.throws(() => plan([a, row(900, { recipient: a.recipient })]), invalid);
  const targets = plan([row(), row()]);
  const proven = targets.map(t => t.publicInputs.map(value => value ?? 1n));
  const classes = awsBatchToolClasses(targets, proven);
  assert.equal(classes.size, 2);
});

test('proven inputs must equal the plan and classes must be known and consistent', () => {
  const targets = plan([row(), row()]), outputs = targets[0].publicInputs.length - 5;
  const proven = () => [targets[0].publicInputs.map(value => value ?? 2n)];
  assert.deepEqual([...awsBatchToolClasses(targets, proven())], [[0, 2], [1, 2]]);
  const moved = proven(); moved[0][140] = BigInt(moved[0][140]) ^ 1n;
  assert.throws(() => awsBatchToolClasses(targets, moved), invalid);
  const unknown = proven(); unknown[0][outputs] = 5n;
  assert.throws(() => awsBatchToolClasses(targets, unknown), invalid);
  // A padding slot repeats row 1, so it must report the same class.
  const split = proven(); split[0][outputs + 4] = 3n;
  assert.throws(() => awsBatchToolClasses(targets, split), invalid);
  assert.throws(() => awsBatchToolClasses(targets, []), invalid);
  assert.throws(() => awsBatchToolClasses(targets, [proven()[0].slice(1)]), invalid);
});

test('circuit inputs open every slot and find the userAgent end', () => {
  const openings = new Map(), commit = text => {
    const preimage = Buffer.concat([Buffer.from(text, 'latin1'), Buffer.alloc(16, 7)]);
    const hash = createHash('sha256').update(preimage).digest('hex');
    openings.set(hash, Uint8Array.from(preimage));
    return { hash, start: 10, end: 10 + text.length };
  };
  const ids = { UserId: commit('AIDAEXAMPLESYNTHETIC01'), Arn: commit('arn:aws:iam::111122223333:user/batch-candidate'), Path: commit('/'), UserName: commit('batch-candidate') };
  const body = '\\"aws-cli/2.22.4\\",\\"requestParameters\\":{}';
  const rows = [row(900, { actor: commit('\\"AIDA\\"'), body: commit(body), recipient: commit('\\"111122223333\\"') })];
  const [target] = assembleAwsBatchExpectations(ids, rows, { issuedAt });
  const inputs = awsCircuitInputs(target, openings);
  assert.deepEqual(inputs.ua_lengths, [18, 18, 18, 18, 18]);
  assert.equal(inputs.row_body[0].length, 1238 + 16);
  assert.equal(inputs.arn_preimage.length, 144);
  assert.deepEqual(inputs.row_lengths[4], [8, body.length, 16]);
  assert.throws(() => awsCircuitInputs(target, new Map()), { message: 'AWS_PRIVATE_CLIENT_INVALID' });
});
