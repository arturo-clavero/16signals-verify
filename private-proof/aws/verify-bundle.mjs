import { AWS_OPERATIONS } from './operation-catalog.mjs';
import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { inspectAwsIdentitySession } from './identity-structure.mjs';
import { inspectAwsEventSession } from './event-structure.mjs';
import { inspectAwsPageSession, awsPageWindowsOverlap } from './page-session.mjs';
import { AWS_PAGE_STEPS, AWS_PAGE_SESSION_STEPS, AWS_SESSION_STEPS } from './sessions.mjs';
import { AWS_TOOL_CLASSES, awsToolName } from './tool-class.mjs';
import { AWS_EVENT_BATCH_CIRCUITS, assembleAwsBatchExpectations, awsBatchToolClasses } from './event-batch.mjs';
import { awsCatalogOperation } from './skill-groups.mjs';

const COUNTS = Object.freeze({ 'header-v1': 33, 'atom-v1': 34, 'aws-xml-text-v1': 33,
  'aws-escaped-atom-v1': 67, 'aws-identity-refresh-v1': 66, 'aws-identity-link-v1': 264, 'aws-event-link-v1': 199,
  'headers-small-v1': 528, 'atoms-small-v1': 272, 'aws-escaped-atoms-small-v1': 536, 'aws-escaped-atom-small-v1': 67,
  'aws-user-agent-class-v1': 34, 'aws-event-batch-v1': 632, 'aws-event-batch-wide-v1': 432 });
const BATCHES = [['header-v1', 'headers-small-v1', 16], ['atom-v1', 'atoms-small-v1', 8],
  ['aws-escaped-atom-v1', 'aws-escaped-atoms-small-v1', 8]];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const fail = () => { throw new Error('AWS_PRIVATE_BUNDLE_INVALID'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const bytes = hash => {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail();
  return Array.from({ length: 32 }, (_, index) => parseInt(hash.slice(index * 2, index * 2 + 2), 16));
};
function fields(proof) {
  if (!exact(proof, ['circuitId', 'proof', 'publicInputs']) || !Object.hasOwn(COUNTS, proof.circuitId) ||
      typeof proof.proof !== 'string' || !proof.proof.length || proof.proof.length > 32768 || !BASE64.test(proof.proof) ||
      !Array.isArray(proof.publicInputs) || proof.publicInputs.length !== COUNTS[proof.circuitId]) fail();
  return Array.from(proof.publicInputs, value => {
    if (typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail();
    const number = BigInt(value);
    if (number > 0xffffffffffffffffn) fail();
    return number;
  });
}

export { fields as awsProofFields };

/** Wire preflight only; native delivery, ownership and replay gates remain caller duties. */
export function validateAwsBundleShape(bundle) {
  if (!exact(bundle, ['kind', 'version', 'sessionIds', 'proofs']) || bundle.kind !== 'AWS_PRIVATE_RESULT' || bundle.version !== 1 ||
      !Array.isArray(bundle.sessionIds) || (bundle.sessionIds.length < 1 || bundle.sessionIds.length > Math.max(AWS_SESSION_STEPS.length, AWS_PAGE_SESSION_STEPS.length)) ||
      Array.from(bundle.sessionIds).some(id => typeof id !== 'string' || !UUID.test(id)) ||
      new Set(bundle.sessionIds.map(id => id.toLowerCase())).size !== bundle.sessionIds.length ||
      !Array.isArray(bundle.proofs) || bundle.proofs.length < 2 || bundle.proofs.length > 128) fail();
  let size = JSON.stringify({ kind: bundle.kind, version: bundle.version, sessionIds: bundle.sessionIds, proofs: [] }).length;
  for (const proof of bundle.proofs) {
    fields(proof);
    size += JSON.stringify(proof).length + 1;
    if (size > 4 * 1024 * 1024) fail();
  }
}

/** Copy the closed public envelope before passing it across an extension boundary. */
export function sanitizeAwsPrivateResult(bundle) {
  validateAwsBundleShape(bundle);
  return { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...bundle.sessionIds],
    proofs: bundle.proofs.map(({ circuitId, proof, publicInputs }) => ({ circuitId, proof, publicInputs: [...publicInputs] })) };
}

/**
 * Public inputs for one planned proof. A null planned value is a circuit output (the userAgent class id),
 * taken from the proof; every other value must equal the plan.
 */
export function awsTargetInputs(target, actual) {
  if (actual.length !== target.publicInputs.length) fail();
  return target.publicInputs.map((value, index) => {
    if (value === null) {
      if (actual[index] > BigInt(AWS_TOOL_CLASSES.length)) fail();
      return Number(actual[index]);
    }
    if (actual[index] !== BigInt(value)) fail();
    return value;
  });
}

function relation(circuitId, slots, extra = []) {
  return { circuitId, publicInputs: [...slots.flatMap(slot => bytes(slot.hash)),
    ...slots.map(slot => slot.end - slot.start), ...extra] };
}

/** Shared with the local planner: every field comes from authenticated structure. */
export function assembleAwsBundleExpectations(identity, event, cutoffMs, fastSource) {
  const i = identity.bindings, events = Array.isArray(event) ? event : [event];
  const result = fastSource ? [{ circuitId: 'aws-identity-refresh-v1',
    publicInputs: [...bytes(fastSource.userIdHash), ...bytes(i.UserId.hash), fastSource.length, i.UserId.length] }] : events.flatMap(({ bindings: e }, index) => [
    relation('aws-identity-link-v1', [i.UserId, i.Arn, i.Path, i.UserName, e.actorId, e.actorArn, e.actorAccount, e.recipientAccount]),
    relation('aws-event-link-v1', [e.requestEventId, e.outerEventId, e.eventId, e.outerTime, e.eventTime, e.roleName], [cutoffMs]),
    // The decoded userAgent commitment comes from this event's escaped-atom proof; the class is the output.
    ...(e.userAgent ? [{ ...relation('aws-user-agent-class-v1', [e.userAgent], [null]), event: index }] : []),
  ]);
  result.push(...batchObligations([...identity.obligations, ...events.flatMap(event => event.obligations)],
    fastSource ? new Set() : new Set([i.UserId.hash, i.Arn.hash, i.Path.hash, i.UserName.hash])));
  return result;
}

/**
 * Single and small batched proofs for every other committed slot. `identityText`: identity slots another proof
 * (identity-link or a batch row proof) already authenticates with stricter XML-safe grammars.
 */
function batchObligations(obligations, identityText) {
  const result = [], batched = new Set();
  for (const [single, circuitId, count] of BATCHES) {
    const eligible = obligations.filter(slot => slot.circuitId === single && slot.length <= 64 &&
      (single !== 'aws-escaped-atom-v1' || slot.decodedLength <= 64));
    for (let start = 0; start < eligible.length; start += count) {
      const slots = eligible.slice(start, start + count);
      for (const slot of slots) batched.add(slot);
      if (single === 'aws-escaped-atom-v1' && slots.length < count) {
        for (const slot of slots) result.push({ circuitId: 'aws-escaped-atom-small-v1',
          publicInputs: [...bytes(slot.hash), slot.length, ...bytes(slot.decodedHash), slot.decodedLength, slot.kind] });
        continue;
      }
      while (slots.length < count) slots.push({ hash: '0'.repeat(64), length: 0, decodedHash: '0'.repeat(64), decodedLength: 0, kind: 0 });
      const publicInputs = [...slots.flatMap(slot => bytes(slot.hash)), ...slots.map(slot => slot.length)];
      if (single === 'aws-escaped-atom-v1') publicInputs.push(...slots.flatMap(slot => bytes(slot.decodedHash)), ...slots.map(slot => slot.decodedLength));
      if (single !== 'header-v1') publicInputs.push(...slots.map(slot => slot.kind));
      result.push({ circuitId, publicInputs });
    }
  }
  for (const slot of obligations) {
    if (batched.has(slot)) continue;
    if (slot.circuitId === 'aws-xml-text-v1' && identityText.has(slot.hash)) continue;
    const publicInputs = [...bytes(slot.hash), slot.length];
    if (slot.circuitId === 'atom-v1') publicInputs.push(slot.kind);
    if (slot.circuitId === 'aws-escaped-atom-v1') publicInputs.push(...bytes(slot.decodedHash), slot.decodedLength, slot.kind);
    if (publicInputs.length !== COUNTS[slot.circuitId]) fail();
    result.push({ circuitId: slot.circuitId, publicInputs });
  }
  return result;
}

// Every skill-group operation is a write: the catalog names write events only.
const catalogWrite = (eventSource, eventName) => (awsCatalogOperation(eventSource, eventName) ? { readOnly: false } : undefined);
const date = day => new Date(day * 86400000).toISOString().slice(0, 10);

/**
 * Page runs: batch row proofs over every proven row (event-batch.mjs), then the proofs of every other committed slot.
 * The batch proofs authenticate the identity session's UserId, Arn, Path and UserName with the same grammar as
 * identity-link, so those four need no XML text proof.
 */
export function assembleAwsPageExpectations(identity, pages, issuedAt) {
  const i = identity.bindings, rows = pages.flatMap(page => page.rows);
  const batch = assembleAwsBatchExpectations(i, rows.map(row => ({ ...row, day: date(row.day) })), { issuedAt, operation: catalogWrite });
  return [...batch.map(target => ({ ...target, rows: target.rows.map(index => rows[index]) })),
    ...batchObligations([...identity.obligations, ...pages.flatMap(page => page.obligations)],
      new Set([i.UserId.hash, i.Arn.hash, i.Path.hash, i.UserName.hash]))];
}

/** Only a trusted pinned-key runtime may verify; sessions must come from the authenticated attempt ledger. */
export async function verifyAwsBundle({ sessions, bundle, runtime, now = Date.now(), fastSource }) {
  try {
    validateAwsBundleShape(bundle);
    if (fastSource ? bundle.sessionIds.length !== 1 : bundle.sessionIds.length < 2) fail();
    if (!Array.isArray(sessions) || sessions.length !== bundle.sessionIds.length || typeof runtime?.verify !== 'function') fail();
    const pageRun = !fastSource && AWS_PAGE_STEPS.includes(sessions[1]?.expected?.step);
    const first = sessions[0]?.expected, native = new Map();
    for (const [index, step] of (pageRun ? AWS_PAGE_SESSION_STEPS : AWS_SESSION_STEPS).slice(0, sessions.length).entries()) {
      const session = sessions[index], expected = session?.expected;
      if (!expected || expected.step !== step || expected.sessionId !== bundle.sessionIds[index]) fail();
      for (const name of ['proofId', 'nonceMac', 'pluginSha256', 'issuedAt', 'expiresAt', 'identityService', 'region']) {
        if (expected[name] !== first[name]) fail();
      }
      const transcript = authenticatedAwsTranscript(session.receipt, expected, now);
      for (const [direction, value] of Object.entries(transcript)) {
        for (const range of value.privateRanges) {
          if (native.has(range.hash)) fail();
          native.set(range.hash, { ...range, direction: direction.toUpperCase(), index });
        }
      }
    }
    const claims = Array.from({ length: sessions.length }, () => []), claimed = new Set();
    for (const entry of bundle.proofs) {
      const values = fields(entry);
      if (!['atom-v1', 'aws-escaped-atom-v1', 'atoms-small-v1', 'aws-escaped-atoms-small-v1', 'aws-escaped-atom-small-v1'].includes(entry.circuitId)) continue;
      const bridge = entry.circuitId.startsWith('aws-escaped-'), batch = ['atoms-small-v1', 'aws-escaped-atoms-small-v1'].includes(entry.circuitId);
      const limit = entry.circuitId.includes('-small-') ? 64n : 512n;
      const fieldHash = start => values.slice(start, start + 32).map(value => {
        if (value > 255n) fail();
        return value.toString(16).padStart(2, '0');
      }).join('');
      for (let index = 0; index < (batch ? 8 : 1); index++) {
        const length = values[batch ? 256 + index : 32];
        if (batch && length === 0n) continue;
        const hash = fieldHash(batch ? index * 32 : 0), slot = native.get(hash);
        const kind = values[batch ? (bridge ? 528 : 264) + index : bridge ? 66 : 33];
        const decodedLength = bridge ? values[batch ? 520 + index : 65] : 0n;
        if (!slot || slot.index < 1 || BigInt(slot.end - slot.start) !== length || claimed.has(hash) ||
            length > limit || kind < 1n || kind > 5n) fail();
        if (bridge && (decodedLength < 1n || decodedLength > limit)) fail();
        claimed.add(hash);
        claims[slot.index].push({ direction: slot.direction, start: slot.start, end: slot.end, hash,
          layer: bridge ? 'event' : 'outer', kind: Number(kind),
          ...(bridge ? { decodedHash: fieldHash(batch ? 264 + index * 32 : 33), decodedLength: Number(decodedLength) } : {}) });
      }
    }
    const identity = inspectAwsIdentitySession(sessions[0].receipt, first, now);
    if (pageRun) return await verifyPages({ sessions, bundle, runtime, now, identity, claims });
    const events = sessions.slice(1).map((session, index) => inspectAwsEventSession(session.receipt, session.expected, claims[index + 1], now));
    // One event per skill area: a second event of an area adds no breadth.
    const areas = events.map(event => AWS_OPERATIONS.find(profile => profile.id === event.activity).skillArea);
    if (new Set(areas).size !== events.length) fail();
    const expected = assembleAwsBundleExpectations(identity, events, first.issuedAt, fastSource);
    if (expected.length !== bundle.proofs.length) fail();
    const proven = new Map();
    for (let index = 0; index < expected.length; index++) {
      const proof = bundle.proofs[index], target = expected[index];
      if (proof.circuitId !== target.circuitId) fail();
      const publicInputs = awsTargetInputs(target, fields(proof));
      if (await runtime.verify(proof, publicInputs) !== true) fail();
      const tool = target.event === undefined ? null : awsToolName(publicInputs.at(-1));
      if (tool) proven.set(events[target.event].activity, tool);
    }
    const activities = AWS_OPERATIONS.filter(profile => events.some(event => event.activity === profile.id)).map(profile => profile.id);
    // Activities without a userAgent, or whose userAgent matched no class, report no tool.
    return { activities, attribution: 'iam-user', windowDays: 90,
      tools: Object.fromEntries(activities.filter(id => proven.has(id)).map(id => [id, proven.get(id)])) };
  } catch { throw new Error('AWS_PRIVATE_BUNDLE_INVALID'); }
}

async function verifyPages({ sessions, bundle, runtime, now, identity, claims }) {
  const pages = sessions.slice(1).map((session, index) =>
    inspectAwsPageSession(session.receipt, session.expected, claims[index + 1], identity.bindings.UserName.end - identity.bindings.UserName.start, now));
  // Disjoint windows per Region: a row can then be proven in one session only.
  if (awsPageWindowsOverlap(pages)) fail();
  const expected = assembleAwsPageExpectations(identity, pages, sessions[0].expected.issuedAt);
  if (expected.length !== bundle.proofs.length) fail();
  const batches = [], proven = [];
  for (let index = 0; index < expected.length; index++) {
    const proof = bundle.proofs[index], target = expected[index];
    if (proof.circuitId !== target.circuitId) fail();
    const publicInputs = awsTargetInputs(target, fields(proof));
    if (await runtime.verify(proof, publicInputs) !== true) fail();
    if (target.rows) { batches.push(target); proven.push(publicInputs); }
  }
  // Padding repeats a row of the same proof: each row counts once, with one tool class.
  const classes = awsBatchToolClasses(batches, proven);
  const rows = pages.flatMap(page => page.rows);
  if (classes.size !== rows.length || rows.some(row => !classes.has(row))) fail();
  // Distinct rows, each once. The UTC day is for levels and distinct-day counts only; it is never shown to employers.
  return { attribution: 'iam-user', windowDays: 90, observations: rows.map(row => ({ group: row.group, eventSource: row.eventSource,
    eventName: row.eventName, tier: row.tier, auto: row.auto, day: row.day, tool: awsToolName(classes.get(row)) })) };
}

/**
 * The recorded identity session's UserId commitment: an event run's first proof (identity-link) binds it to the saved
 * actor; a page run's first proof (a batch row proof) opens it first among the four identity slots, its length after
 * the four hashes. The caller verifies the recording itself (`verifyAwsFastBundle`).
 */
export function awsFastSource(recording) {
  validateAwsBundleShape(recording.bundle);
  const entry = recording.bundle.proofs[0];
  const lengthAt = entry.circuitId === 'aws-identity-link-v1' ? 256
    : AWS_EVENT_BATCH_CIRCUITS.some(circuit => circuit.circuitId === entry.circuitId) ? 128 : -1;
  if (recording.bundle.sessionIds.length < 2 || lengthAt < 0) fail();
  const values = fields(entry), hash = values.slice(0, 32);
  if (hash.some(byte => byte > 255n) || values[lengthAt] < 1n || values[lengthAt] > 128n) fail();
  return { userIdHash: hash.map(byte => byte.toString(16).padStart(2, '0')).join(''), length: Number(values[lengthAt]) };
}

export async function verifyAwsFastBundle({ sessions, bundle, runtime, now = Date.now(), recording }) {
  const result = await verifyAwsBundle({ sessions: recording.sessions, bundle: recording.bundle, runtime, now: recording.policy.issuedAt });
  await verifyAwsBundle({ sessions, bundle, runtime, now, fastSource: awsFastSource(recording) });
  return result;
}
