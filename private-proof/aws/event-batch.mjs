import { awsOperation } from './operation-catalog.mjs';
import { AWS_TOOL_CLASSES } from './tool-class.mjs';

/**
 * Batch row proofs for LookupEvents page rows (circuits/lib/src/batch.nr). One proof opens the identity session's
 * raw IAM UserId, Arn, Path and UserName once and proves up to `rows` page rows against them.
 *
 * A row comes from the page transcript check, every slot an authenticated RECV commitment { hash, start, end }:
 *   actor      principalId value through accountId value (starts right after the revealed \"principalId\":)
 *   body       userAgent value through the byte before the revealed ,\"recipientAccountId\":
 *   recipient  the recipientAccountId value (16 bytes on the wire)
 * plus the revealed eventSource, eventName and UTC day (YYYY-MM-DD) of that row.
 *
 * Public inputs of one proof, in order: 4 identity hashes (32 field elements each, one per byte), 4 identity
 * lengths, then per slot 3 row hashes (actor, body, recipient) and after all hashes per slot 3 lengths, then one
 * tool class per slot (circuit output, 0 = no class). Unused slots repeat a proven row of the same proof; the
 * verifier counts each row once.
 */
export const AWS_EVENT_BATCH_CIRCUITS = Object.freeze([
  Object.freeze({ circuitId: 'aws-event-batch-v1', rows: 5, bodyBytes: 320 + 22 + 896 }),
  Object.freeze({ circuitId: 'aws-event-batch-wide-v1', rows: 3, bodyBytes: 320 + 22 + 2048 }),
]);
export const AWS_BATCH_CAPACITY = Object.freeze({ UserId: 64, Arn: 128, Path: 64, UserName: 64, actor: 256, recipient: 16 });
const IDENTITY = ['UserId', 'Arn', 'Path', 'UserName'], SLOTS = ['actor', 'body', 'recipient'];
const DAY_MS = 86400000, WINDOW_DAYS = 90;
const fail = () => { throw new Error('AWS_PRIVATE_BATCH_INVALID'); };

const length = slot => slot.end - slot.start;
const bytes = hash => {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail();
  return Array.from({ length: 32 }, (_, index) => parseInt(hash.slice(index * 2, index * 2 + 2), 16));
};
const day = ms => new Date(ms).toISOString().slice(0, 10);

/** The smallest batch circuit that can hold this row, or undefined: such a row cannot be proven. */
export function awsBatchCircuitFor(row) {
  if (length(row.actor) > AWS_BATCH_CAPACITY.actor || length(row.recipient) !== AWS_BATCH_CAPACITY.recipient) return undefined;
  return AWS_EVENT_BATCH_CIRCUITS.find(circuit => length(row.body) <= circuit.bodyBytes);
}

function checkRow(row, issuedAt, operation) {
  for (const name of SLOTS) {
    const slot = row?.[name];
    if (!slot || !Number.isSafeInteger(slot.start) || !Number.isSafeInteger(slot.end) || slot.start < 0 || slot.end <= slot.start) fail();
    bytes(slot.hash);
  }
  // Only catalog writes count; the catalog holds no read-only operation.
  const entry = operation(row.eventSource, row.eventName);
  if (!entry || entry.readOnly !== false) fail();
  if (typeof row.day !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(row.day) || day(Date.parse(`${row.day}T00:00:00Z`)) !== row.day ||
      row.day > day(issuedAt) || row.day < day(issuedAt - WINDOW_DAYS * DAY_MS)) fail();
  if (!awsBatchCircuitFor(row)) fail();
}

/**
 * Planned batch proofs for the authenticated identity bindings and page rows, shared by prover and verifier.
 * Rows that need the wide circuit go first, free wide slots take short rows, the rest go five per proof.
 * Every planned public input is fixed except the tool classes (null).
 */
export function assembleAwsBatchExpectations(identity, rows, { issuedAt, operation = awsOperation }) {
  if (!Number.isSafeInteger(issuedAt) || !Array.isArray(rows) || rows.length < 1) fail();
  IDENTITY.forEach(name => {
    const slot = identity?.[name];
    if (!slot || length(slot) < 1 || length(slot) > AWS_BATCH_CAPACITY[name]) fail();
    bytes(slot.hash);
  });
  const seen = new Set();
  for (const row of rows) {
    checkRow(row, issuedAt, operation);
    for (const name of SLOTS) {
      if (seen.has(row[name].hash)) fail();
      seen.add(row[name].hash);
    }
  }
  const [narrow, wide] = AWS_EVENT_BATCH_CIRCUITS, groups = [];
  const short = rows.flatMap((row, index) => awsBatchCircuitFor(row) === narrow ? [index] : []);
  const long = rows.flatMap((row, index) => awsBatchCircuitFor(row) === wide ? [index] : []);
  for (let start = 0; start < long.length; start += wide.rows) groups.push([wide, long.slice(start, start + wide.rows)]);
  for (const [circuit, members] of groups) while (members.length < circuit.rows && short.length) members.push(short.shift());
  for (let start = 0; start < short.length; start += narrow.rows) groups.push([narrow, short.slice(start, start + narrow.rows)]);
  return groups.map(([circuit, members]) => {
    const slots = Array.from({ length: circuit.rows }, (_, index) => members[Math.min(index, members.length - 1)]);
    const ids = IDENTITY.map(name => identity[name]), cells = slots.flatMap(index => SLOTS.map(name => rows[index][name]));
    return { circuitId: circuit.circuitId, rows: slots, publicInputs: [
      ...ids.flatMap(slot => bytes(slot.hash)), ...ids.map(length),
      ...cells.flatMap(slot => bytes(slot.hash)), ...cells.map(length), ...slots.map(() => null)] };
  });
}

/**
 * After every proof verified against its target's inputs (tool classes taken from the proof): the tool class
 * of each distinct proven row, by row index. A row repeated in padding slots counts once.
 */
export function awsBatchToolClasses(targets, provenInputs) {
  if (!Array.isArray(targets) || !Array.isArray(provenInputs) || targets.length !== provenInputs.length) fail();
  const classes = new Map();
  targets.forEach((target, index) => {
    const actual = provenInputs[index];
    if (!Array.isArray(actual) || actual.length !== target.publicInputs.length) fail();
    target.publicInputs.forEach((value, at) => {
      if (value === null) {
        const id = Number(actual[at]);
        if (!Number.isInteger(id) || id < 0 || id > AWS_TOOL_CLASSES.length) fail();
        const row = target.rows[at - (target.publicInputs.length - target.rows.length)];
        if (classes.has(row) && classes.get(row) !== id) fail();
        classes.set(row, id);
      } else if (BigInt(actual[at]) !== BigInt(value)) fail();
    });
  });
  return classes;
}
