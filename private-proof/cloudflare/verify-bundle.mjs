/**
 * Cloudflare result bundle: receipt context checks, the deterministic proof targets (shared by prover and verifier),
 * proof matching, and the observations a verifier keeps.
 *
 * Bundle: { kind: 'CLOUDFLARE_PRIVATE_RESULT', version: 1, sessionIds, proofs: [{ circuitId, proof, publicInputs }] }.
 * Targets come only from authenticated structure (inspectCloudflareSession) and depend only on what the verifier sees
 * (hashes and lengths), so the prover computes the same list in the same order.
 */
import { authenticatedTranscriptRanges } from '../gcp/authenticated-transcript.mjs';
import { inspectCloudflareSession } from './session.mjs';
import { CF_API_HOST, CF_PAGE_BYTES, CF_PAGE_STEPS, CF_RUN_STEPS, CF_SMALL_BYTES, CF_WINDOW_DAYS } from './request.mjs';
import { CLOUDFLARE_TOOL_CONTEXTS, cloudflareCatalogOperation } from './skill-groups.mjs';

export const CF_METHOD = 'CLOUDFLARE_ACCOUNT';
export const CF_BUNDLE_KIND = 'CLOUDFLARE_PRIVATE_RESULT';
export const CF_PIECE_KINDS = Object.freeze({ value: 1, tail: 2 });
// circuit id -> [slots per proof, max bytes per slot, public input count]
export const CF_CIRCUITS = Object.freeze({
  'headers-small-v1': [16, 64, 528], 'cf-headers-v1': [4, 512, 4 * 33], 'header-v1': [1, 2048, 33],
  'cf-json-small-v1': [16, 64, 16 * 34], 'cf-json-v1': [4, 512, 4 * 34], 'cf-json-wide-v1': [1, 4096, 34],
  'cf-actor-v1': [8, 64, 33 + 8 * 33],
  // Fast check only: the recorded identity id and a fresh one open to the same bytes.
  'cf-identity-refresh-v1': [2, 64, 66],
});
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ZERO = '0'.repeat(64);
const fail = what => { throw new Error(`CF_PRIVATE_BUNDLE_INVALID${what ? `:${what}` : ''}`); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export const hashBytes = hash => {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail('hash');
  return Array.from({ length: 32 }, (_, i) => parseInt(hash.slice(i * 2, i * 2 + 2), 16));
};

// --- receipts --------------------------------------------------------------------------------------------------
/** Context validation only (trusted server attempt state). */
export function validateCloudflareAttempt(expected, now = Date.now()) {
  if (!record(expected) || !UUID.test(expected.proofId ?? '') || !/^[a-f0-9]{64}$/.test(expected.pluginSha256 ?? '') ||
      !/^[A-Za-z0-9_-]{43}$/.test(expected.nonceMac ?? '') || !Number.isSafeInteger(expected.issuedAt) ||
      !Number.isSafeInteger(expected.expiresAt) || expected.issuedAt < 0 || expected.issuedAt > now ||
      expected.expiresAt <= now || expected.expiresAt - expected.issuedAt > 15 * 60 * 1000) fail('attempt');
}

/** One receipt's ranges, after binding it to the attempt, step, plugin and host. */
export function authenticatedCloudflareTranscript(receipt, expected, now = Date.now()) {
  validateCloudflareAttempt(expected, now);
  const s = receipt?.session;
  if (!record(receipt) || !record(s) || receipt.failure !== undefined || !UUID.test(expected.sessionId ?? '') ||
      !CF_RUN_STEPS.includes(expected.step) || s.id !== expected.sessionId || s.proofId !== expected.proofId ||
      s.pluginSha256 !== expected.pluginSha256 || s.nonceMac !== expected.nonceMac || s.step !== expected.step ||
      s.method !== CF_METHOD || s.mode !== 'Proxy' || receipt.server_name !== CF_API_HOST) fail('receipt');
  const page = CF_PAGE_STEPS.includes(expected.step);
  return authenticatedTranscriptRanges(receipt, { maxLength: page ? CF_PAGE_BYTES : CF_SMALL_BYTES, maxRanges: 512, gaps: ['recv'] });
}

// --- targets -----------------------------------------------------------------------------------------------------
function pack(circuitId, slots, withKind) {
  const [count] = CF_CIRCUITS[circuitId], out = [];
  for (let at = 0; at < slots.length; at += count) {
    const group = slots.slice(at, at + count);
    while (group.length < count) group.push({ hash: ZERO, length: 0, kind: 0 });
    out.push({ circuitId, slots: group.filter(s => s.length),
      publicInputs: [...group.flatMap(s => hashBytes(s.hash)), ...group.map(s => s.length), ...(withKind ? group.map(s => s.kind) : [])] });
  }
  return out;
}

/** Deterministic proof targets for one run: identity result + page results (inspectCloudflareSession output). */
/**
 * `fastSource` (fast check, identity session only): { identityHash, length } of the recorded run's identity id. The
 * targets are then the identity's header proofs and one cf-identity-refresh-v1 proof binding the fresh id to it.
 */
export function cloudflareTargets(identity, pages, fastSource) {
  if (!identity?.identity || !Array.isArray(pages) || (fastSource ? pages.length : !pages.length)) fail('sessions');
  const obligations = [...identity.obligations, ...pages.flatMap(p => p.obligations)];
  const headers = obligations.filter(o => o.need === 'header');
  const pieces = obligations.filter(o => o.need === 'value' || o.need === 'tail').map(o => ({ ...o, kind: CF_PIECE_KINDS[o.need] }));
  const actors = obligations.filter(o => o.need === 'actor');
  if (obligations.some(o => !['header', 'value', 'tail', 'actor'].includes(o.need) || !Number.isSafeInteger(o.length) || o.length < 1)) fail('obligation');
  if (headers.some(o => o.length > 2048) || pieces.some(o => o.length > 4096) || actors.some(o => o.length > 64)) fail('size');
  const targets = [
    ...pack('headers-small-v1', headers.filter(o => o.length <= 64), false),
    ...pack('cf-headers-v1', headers.filter(o => o.length > 64 && o.length <= 512), false),
    ...headers.filter(o => o.length > 512).flatMap(o => pack('header-v1', [o], false)),
    ...pack('cf-json-small-v1', pieces.filter(o => o.length <= 64), true),
    ...pack('cf-json-v1', pieces.filter(o => o.length > 64 && o.length <= 512), true),
    ...pieces.filter(o => o.length > 512).flatMap(o => pack('cf-json-wide-v1', [o], true)),
  ];
  const id = identity.identity;
  for (let at = 0; at < actors.length; at += 8) {
    const group = actors.slice(at, at + 8);
    while (group.length < 8) group.push({ hash: ZERO, length: 0 });
    targets.push({ circuitId: 'cf-actor-v1', identity: id, slots: group.filter(s => s.length),
      publicInputs: [...hashBytes(id.hash), id.length, ...group.flatMap(s => hashBytes(s.hash)), ...group.map(s => s.length)] });
  }
  if (fastSource) {
    if (!record(fastSource) || fastSource.length !== id.length) fail('fast-source');
    targets.push({ circuitId: 'cf-identity-refresh-v1', slots: [],
      publicInputs: [...hashBytes(fastSource.identityHash), ...hashBytes(id.hash), fastSource.length, id.length] });
  }
  for (const t of targets) if (t.publicInputs.length !== CF_CIRCUITS[t.circuitId][2]) fail('count');
  return targets;
}

// --- bundle ------------------------------------------------------------------------------------------------------
export function cloudflareProofFields(proof) {
  if (!exact(proof, ['circuitId', 'proof', 'publicInputs']) || !Object.hasOwn(CF_CIRCUITS, proof.circuitId) ||
      typeof proof.proof !== 'string' || !proof.proof.length || proof.proof.length > 32768 || !BASE64.test(proof.proof) ||
      !Array.isArray(proof.publicInputs) || proof.publicInputs.length !== CF_CIRCUITS[proof.circuitId][2]) fail('proof');
  return Array.from(proof.publicInputs, value => {
    if (typeof value !== 'string' || !/^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/.test(value)) fail('field');
    const n = BigInt(value);
    if (n > 0xffffffffffffffffn) fail('field');
    return n;
  });
}

export function validateCloudflareBundleShape(bundle) {
  if (!exact(bundle, ['kind', 'version', 'sessionIds', 'proofs']) || bundle.kind !== CF_BUNDLE_KIND || bundle.version !== 1 ||
      !Array.isArray(bundle.sessionIds) || bundle.sessionIds.length < 1 || bundle.sessionIds.length > CF_RUN_STEPS.length ||
      bundle.sessionIds.some(id => typeof id !== 'string' || !UUID.test(id)) ||
      new Set(bundle.sessionIds.map(id => id.toLowerCase())).size !== bundle.sessionIds.length ||
      !Array.isArray(bundle.proofs) || bundle.proofs.length < 2 || bundle.proofs.length > 160) fail('shape');
  let size = 0;
  for (const proof of bundle.proofs) { cloudflareProofFields(proof); size += JSON.stringify(proof).length + 1; }
  if (size > 6 * 1024 * 1024) fail('size');
}

/** Copy the closed public envelope before passing it across an extension boundary. */
export function sanitizeCloudflarePrivateResult(bundle) {
  validateCloudflareBundleShape(bundle);
  return { kind: CF_BUNDLE_KIND, version: 1, sessionIds: [...bundle.sessionIds],
    proofs: bundle.proofs.map(({ circuitId, proof, publicInputs }) => ({ circuitId, proof, publicInputs: [...publicInputs] })) };
}

// --- fast check (demo replay) ------------------------------------------------------------------------------------
/**
 * The recorded run's identity id commitment (its first cf-actor-v1 proof opens it: hash, then length). The caller
 * verifies the recording itself (`verifyCloudflareFastBundle`).
 */
export function cloudflareFastSource(recording) {
  validateCloudflareBundleShape(recording?.bundle);
  const entry = recording.bundle.proofs.find(proof => proof.circuitId === 'cf-actor-v1');
  if (recording.bundle.sessionIds.length < 2 || !entry) fail('fast-source');
  const values = cloudflareProofFields(entry), hash = values.slice(0, 32);
  if (hash.some(byte => byte > 255n) || values[32] !== 34n) fail('fast-source');
  return { identityHash: hash.map(byte => byte.toString(16).padStart(2, '0')).join(''), length: 34 };
}

/** Fast check: the recording verifies at its own attempt time, and the fresh identity session proves the same user. */
export async function verifyCloudflareFastBundle({ sessions, bundle, runtime, now = Date.now(), recording }) {
  const result = await verifyCloudflareBundle({ sessions: recording.sessions, bundle: recording.bundle, runtime, now: recording.policy.issuedAt });
  await verifyCloudflareBundle({ sessions, bundle, runtime, now, fastSource: cloudflareFastSource(recording) });
  return result;
}

const DAY_MS = 864e5;
/** A proven row -> observation, or throws: own successful catalog change through a known tool, inside the window. */
export function cloudflareObservation(row, issuedAt) {
  const op = cloudflareCatalogOperation(row.product, row.type, row.action);
  const day = Date.parse(`${row.day}T00:00:00Z`), issuedDay = Math.floor(issuedAt / DAY_MS) * DAY_MS;
  if (!op || row.actorType !== 'user' || row.result !== 'success' || !Object.hasOwn(CLOUDFLARE_TOOL_CONTEXTS, row.context) ||
      !Number.isFinite(day) || day > issuedDay || day < issuedDay - CF_WINDOW_DAYS * DAY_MS) fail('row');
  return { group: op.group, product: op.product, type: op.type, action: op.action, tier: op.tier, auto: op.auto,
    day: row.day, tool: CLOUDFLARE_TOOL_CONTEXTS[row.context] };
}

/**
 * Verifier entry: sessions [{ receipt, expected }] in step order (identity first), the bundle, a proof runtime with
 * verify(proof, publicInputs) -> boolean. Returns { attribution, windowDays, observations }.
 */
export async function verifyCloudflareBundle({ sessions, bundle, runtime, now = Date.now(), fastSource }) {
  try {
    validateCloudflareBundleShape(bundle);
    if (!Array.isArray(sessions) || sessions.length !== bundle.sessionIds.length || (fastSource ? sessions.length !== 1 : sessions.length < 2)) fail('sessions');
    const steps = sessions.map(s => s.expected?.step);
    if (steps.join() !== CF_RUN_STEPS.slice(0, sessions.length).join()) fail('steps');
    const first = sessions[0].expected;
    sessions.forEach((s, i) => {
      if (s.expected.sessionId !== bundle.sessionIds[i] || ['proofId', 'pluginSha256', 'nonceMac', 'issuedAt', 'expiresAt'].some(k => s.expected[k] !== first[k])) fail('session-id');
    });
    const results = sessions.map(s => inspectCloudflareSession(authenticatedCloudflareTranscript(s.receipt, s.expected, now), s.expected.step));
    const [identity, ...pages] = results;
    const targets = cloudflareTargets(identity, pages, fastSource);
    if (targets.length !== bundle.proofs.length) fail('proof-count');
    for (let i = 0; i < targets.length; i++) {
      const proof = bundle.proofs[i], target = targets[i];
      if (proof.circuitId !== target.circuitId) fail('circuit');
      const actual = cloudflareProofFields(proof);
      if (actual.some((v, j) => v !== BigInt(target.publicInputs[j]))) fail('inputs');
      if (await runtime.verify(proof, target.publicInputs) !== true) fail('verify');
    }
    const observations = pages.flatMap(p => p.rows).map(row => cloudflareObservation(row, sessions[0].expected.issuedAt));
    return { attribution: 'cloudflare-user', windowDays: CF_WINDOW_DAYS, observations };
  } catch (error) {
    throw new Error(String(error?.message ?? '').startsWith('CF_') ? error.message.replace(/^CF_(SESSION_INVALID|ROW_STRUCTURE)/, 'CF_PRIVATE_BUNDLE_INVALID:$1') : 'CF_PRIVATE_BUNDLE_INVALID');
  }
}
