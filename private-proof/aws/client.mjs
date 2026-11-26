import { validateAwsAttempt } from './authenticated-transcript.mjs';
import { planAwsSession } from './client-plan.mjs';
import { inspectAwsIdentityDirections } from './identity-structure.mjs';
import { inspectAwsEventDirections } from './event-structure.mjs';
import { assembleAwsBundleExpectations, assembleAwsPageExpectations, validateAwsBundleShape, awsProofFields, awsTargetInputs } from './verify-bundle.mjs';
import { planAwsPageSession } from './page-plan.mjs';
import { inspectAwsPageDirections, awsPageWindowsOverlap } from './page-session.mjs';
import { AWS_PAGE_BYTES, awsCloudTrailRegion } from './request.mjs';
import { awsCircuitInputs, eraseAwsInputs } from './circuit-inputs.mjs';
import { AWS_PAGE_STEPS, AWS_PAGE_SESSION_STEPS, AWS_SESSION_STEPS } from './sessions.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('AWS_PRIVATE_CLIENT_INVALID'); };
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

function matchSelections(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) fail();
  for (let index = 0; index < expected.length; index++) {
    const value = actual[index], target = expected[index], hash = target.handler.action.kind === 'HASH';
    if (!exact(value, ['start', 'end', 'handler']) || value.start !== target.start || value.end !== target.end ||
        !exact(value.handler, ['type', 'part', 'action']) || value.handler.type !== target.handler.type || value.handler.part !== 'BODY' ||
        !exact(value.handler.action, hash ? ['kind', 'algorithm'] : ['kind']) || value.handler.action.kind !== target.handler.action.kind ||
        (hash && value.handler.action.algorithm !== 'SHA256')) fail();
  }
}

async function prepare(witness, planned, openings, buffers, crypto, page) {
  const directions = {}, claims = [];
  for (const direction of ['sent', 'recv']) {
    const slots = planned.privateSlots[direction], candidates = witness.openings[direction];
    if (candidates.length !== slots.length) fail();
    const bytes = new Uint8Array(witness[direction]); buffers.push(bytes);
    // A page response keeps only its revealed bytes; the rest is a gap the verifier never sees.
    if (page && direction === 'recv') {
      bytes.fill(0);
      for (const range of planned.publicRanges) bytes.set(witness.recv.subarray(range.start, range.end), range.start);
      for (const slot of slots) bytes.set(witness.recv.subarray(slot.start, slot.end), slot.start);
    }
    const authenticated = [], used = new Set();
    for (const slot of slots) {
      const matches = candidates.filter(value => value.start === slot.start && value.end === slot.end);
      if (matches.length !== 1 || used.has(matches[0])) fail();
      const value = matches[0]; used.add(value);
      const preimage = new Uint8Array(slot.end - slot.start + 16); buffers.push(preimage);
      preimage.set(bytes.subarray(slot.start, slot.end)); preimage.set(value.blinder, preimage.length - 16);
      const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)));
      if (digest !== hex(value.hash) || openings.has(digest)) fail();
      openings.set(digest, preimage);
      const accepted = { ...slot, hash: digest };
      if (slot.layer === 'event') {
        const encoded = decoder.decode(bytes.subarray(slot.start, slot.end));
        const decoded = encoder.encode(JSON.parse(`"${encoded}"`)); buffers.push(decoded);
        if (decoded.length !== slot.decodedLength || JSON.stringify(decoder.decode(decoded)).slice(1, -1) !== encoded) fail();
        const derived = new Uint8Array(decoded.length + 16); buffers.push(derived);
        derived.set(decoded); crypto.getRandomValues(derived.subarray(decoded.length));
        accepted.decodedHash = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', derived)));
        if (openings.has(accepted.decodedHash)) fail();
        openings.set(accepted.decodedHash, derived);
      }
      if (slot.layer) claims.push({ ...accepted });
      authenticated.push(accepted); bytes.fill(0, slot.start, slot.end);
    }
    directions[direction] = { bytes, privateRanges: authenticated, ...(page && direction === 'recv' ? { publicRanges: planned.publicRanges } : {}) };
  }
  if (page) {
    return inspectAwsPageDirections(directions, { ...witness, issuedAt: page.issuedAt }, claims, page.userNameLength,
      awsCloudTrailRegion(witness.serverName) ?? fail());
  }
  return witness.step === 'identity' ? inspectAwsIdentityDirections(directions, witness) : inspectAwsEventDirections(directions, witness, claims);
}

/** Offscreen-owned client. The worker adapter must terminate CPU work on abort and settle its promise. */
export function createAwsPrivateClient({ attempt, proveCircuit, crypto = globalThis.crypto, now = Date.now, fastSource, linkSecret, saveLink }) {
  let context;
  try {
    validateAwsAttempt(attempt, now());
    if (typeof proveCircuit !== 'function' || !crypto?.subtle || !crypto?.getRandomValues) fail();
    context = Object.freeze(Object.fromEntries(['proofId', 'nonceMac', 'pluginSha256', 'identityService', 'region', 'issuedAt', 'expiresAt']
      .map(key => [key, attempt[key]])));
    attempt = undefined;
  } catch { fail(); }
  if (fastSource && (!(linkSecret instanceof Uint8Array) || linkSecret.length !== 16 ||
      !/^[0-9a-f]{64}$/.test(fastSource.userIdHash) || !Number.isInteger(fastSource.length) || fastSource.length < 1 || fastSource.length > 128)) fail();
  let consumed = false, pageRows;
  const clear = () => { consumed = true; context = undefined; pageRows = undefined; };
  // The rows each page session proves (local selection); the verifier derives everything from the transcript.
  const plan = (meta, transcripts) => AWS_PAGE_STEPS.includes(meta.step)
    ? planAwsPageSession(meta, transcripts, pageRows?.get(meta.step) ?? fail()) : planAwsSession(meta, transcripts);
  const check = meta => {
    validateAwsAttempt(context, now());
    if (!meta || !uuid(meta.sessionId) || meta.proofId !== context.proofId || meta.nonceMac !== context.nonceMac) fail();
  };
  return {
    clear,
    /** `rows`: { P0: [eventId, ...], ... } from the local selection, before the first page session. */
    selectPages(rows) {
      try {
        if (consumed || pageRows || !rows || typeof rows !== 'object') fail();
        const steps = Object.keys(rows);
        if (!steps.length || steps.some((step, index) => step !== AWS_PAGE_STEPS[index]) ||
            Object.values(rows).some(ids => !Array.isArray(ids) || !ids.length || ids.some(id => typeof id !== 'string'))) fail();
        pageRows = new Map(steps.map(step => [step, new Set(rows[step])]));
      } catch { fail(); }
    },
    getRevealPlan(meta, transcripts) {
      try { if (consumed) fail(); check(meta); return plan(meta, transcripts).plan; }
      catch { fail(); }
    },
    async prove(witnesses, signal) {
      const buffers = [], openings = new Map(), prepared = [], ids = new Set();
      try {
        const pageRun = !fastSource && AWS_PAGE_STEPS.includes(witnesses?.[1]?.step), steps = pageRun ? AWS_PAGE_SESSION_STEPS : AWS_SESSION_STEPS;
        if (consumed || !signal || signal.aborted || !Array.isArray(witnesses) || (fastSource ? witnesses.length !== 1 : (witnesses.length < 2 || witnesses.length > steps.length))) fail();
        consumed = true;
        // Snapshot all witnesses before the first asynchronous hash; caller mutations cannot alter the plan.
        for (const [index, step] of steps.slice(0, witnesses.length).entries()) {
          const value = witnesses[index]; check(value);
          if (value.step !== step || ids.has(value.sessionId) || !exact(value.selections, ['sent', 'recv']) ||
              !exact(value.openings, ['sent', 'recv'])) fail();
          ids.add(value.sessionId);
          const witness = { sessionId: value.sessionId, serverName: value.serverName, step, proofId: value.proofId,
            nonceMac: value.nonceMac, openings: {} };
          const page = pageRun && index > 0;
          for (const direction of ['sent', 'recv']) {
            const large = page && direction === 'recv';
            if (!(value[direction] instanceof Uint8Array) || !value[direction].length || value[direction].length > (large ? AWS_PAGE_BYTES : 16384) ||
                !Array.isArray(value.openings[direction]) || value.openings[direction].length > (large ? 512 : 256)) fail();
            witness[direction] = new Uint8Array(value[direction]); buffers.push(witness[direction]);
            witness.openings[direction] = value.openings[direction].map(opening => {
              if (!exact(opening, ['start', 'end', 'hash', 'blinder']) || !Number.isSafeInteger(opening.start) ||
                  !Number.isSafeInteger(opening.end) || opening.start < 0 || opening.end <= opening.start || opening.end > witness[direction].length ||
                  !(opening.hash instanceof Uint8Array) || opening.hash.length !== 32 ||
                  !(opening.blinder instanceof Uint8Array) || opening.blinder.length !== 16) fail();
              const hash = new Uint8Array(opening.hash), blinder = new Uint8Array(opening.blinder); buffers.push(hash, blinder);
              return { start: opening.start, end: opening.end, hash, blinder };
            });
          }
          const planned = plan(witness, witness);
          for (const direction of ['sent', 'recv']) matchSelections(value.selections[direction], planned.plan[`${direction}RangesWithHandlers`]);
          prepared.push({ witness, planned });
        }
        const inspections = [];
        for (const [index, item] of prepared.entries()) {
          if (signal.aborted) fail(); check(item.witness);
          const page = pageRun && index > 0 && { issuedAt: context.issuedAt,
            userNameLength: inspections[0].bindings.UserName.end - inspections[0].bindings.UserName.start };
          inspections.push(await prepare(item.witness, item.planned, openings, buffers, crypto, page));
        }
        // Page windows of one Region must be disjoint (the verifier's rule against proving one row twice).
        if (pageRun && awsPageWindowsOverlap(inspections.slice(1))) fail();
        // Fail before proving when an event session returned another event than its request named, or repeats one.
        // The event-link circuit enforces the first rule for the verifier.
        const eventIds = new Set();
        for (const { bindings } of pageRun ? [] : inspections.slice(1)) {
          const [requested, ...returned] = [bindings.requestEventId, bindings.outerEventId, bindings.eventId]
            .map(slot => decoder.decode(openings.get(slot.hash).subarray(0, slot.end - slot.start)));
          if (returned.some(value => value !== requested) || eventIds.has(requested)) fail();
          eventIds.add(requested);
        }
        const userId = inspections[0].bindings.UserId;
        if (fastSource) {
          const current = openings.get(userId.hash);
          if (userId.length !== fastSource.length || !current) fail();
          const prior = new Uint8Array(current); buffers.push(prior);
          prior.set(linkSecret, prior.length - 16);
          if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', prior))) !== fastSource.userIdHash) fail();
          openings.set(fastSource.userIdHash, prior);
        }
        const targets = pageRun ? assembleAwsPageExpectations(inspections[0], inspections.slice(1), context.issuedAt)
          : assembleAwsBundleExpectations(inspections[0], inspections.slice(1), context.issuedAt, fastSource);
        if (!targets.length || targets.length > 128) fail();
        const proofs = [];
        for (const target of targets) {
          if (signal.aborted) fail(); check(prepared[0].witness);
          const inputs = awsCircuitInputs(target, openings);
          try {
            const entry = await proveCircuit(target.circuitId, inputs, signal);
            const fields = awsProofFields(entry);
            if (signal.aborted || entry.circuitId !== target.circuitId) fail();
            awsTargetInputs(target, fields);
            // Preserve field values while fitting the existing ingress body limit.
            proofs.push({ ...entry, publicInputs: fields.map(String) });
          } finally { eraseAwsInputs(inputs); }
        }
        check(prepared[0].witness);
        const bundle = { kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...ids], proofs };
        validateAwsBundleShape(bundle);
        if (!fastSource && saveLink) await saveLink(userId.hash, openings.get(userId.hash).subarray(userId.length));
        return bundle;
      } catch { fail(); }
      finally { linkSecret?.fill(0); buffers.forEach(bytes => bytes.fill(0)); openings.clear(); clear(); }
    },
  };
}
