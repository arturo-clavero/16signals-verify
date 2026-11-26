/**
 * Offscreen-owned prover client. getRevealPlan decides what each session reveals once its transcript is known (page
 * rows are chosen here, from the bytes actually received); prove() re-reads every witness exactly as the verifier
 * will (inspectCloudflareSession), builds the shared targets and asks the worker for one proof per target.
 *
 * Fast check (`fastSource` + `linkSecret`, demo replay): the identity session only, plus one proof that its id is the
 * one a recorded run proved (the saved blinder of that run's id opening, kept by the extension). After a full run the
 * id's blinder is handed to `saveLink`, so the next check from this browser can be a fast one.
 */
import { planCloudflareSession, inspectCloudflareSession, cloudflarePageRows } from './session.mjs';
import { parseHttpResponse, transcriptRange } from './http-chunked.mjs';
import { selectCloudflareRows } from './discovery.mjs';
import { cloudflareTargets, cloudflareProofFields, validateCloudflareAttempt, CF_BUNDLE_KIND } from './verify-bundle.mjs';
import { cloudflareCircuitInputs, eraseCloudflareInputs } from './circuit-inputs.mjs';
import { CF_RUN_STEPS } from './request.mjs';

const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('CF_PRIVATE_CLIENT_INVALID'); };
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
/** One fixed diagnostic code for the offscreen console (reason names only, never a value). */
const stage = (prefix, error) => {
  const reason = String(error?.message ?? '').replace(/^CF_/, '').replace(/@\d+/g, '').replace(/[^A-Za-z0-9]+/g, '_').toUpperCase().slice(0, 80);
  try { console.warn(`CF_${prefix}_${reason || 'UNSPECIFIED'}`); } catch { /* Diagnostics must not affect the run. */ }
};
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

export function createCloudflarePrivateClient({ attempt, proveCircuit, crypto = globalThis.crypto, now = Date.now, fastSource, linkSecret, saveLink }) {
  let context;
  try {
    validateCloudflareAttempt(attempt, now());
    if (typeof proveCircuit !== 'function' || !crypto?.subtle || (saveLink !== undefined && typeof saveLink !== 'function')) fail();
    if (fastSource !== undefined && (!(linkSecret instanceof Uint8Array) || linkSecret.length !== 16 ||
        !/^[0-9a-f]{64}$/.test(fastSource?.identityHash ?? '') || fastSource.length !== 34)) fail();
    context = Object.freeze({ proofId: attempt.proofId, nonceMac: attempt.nonceMac, pluginSha256: attempt.pluginSha256,
      issuedAt: attempt.issuedAt, expiresAt: attempt.expiresAt });
  } catch { fail(); }
  let consumed = false, userId;
  const check = meta => {
    validateCloudflareAttempt(context, now());
    if (!meta || !uuid(meta.sessionId) || meta.proofId !== context.proofId || meta.nonceMac !== context.nonceMac || !CF_RUN_STEPS.includes(meta.step)) fail();
  };
  const plan = (meta, { sent, recv }) => {
    if (meta.step === 'identity') {
      const response = parseHttpResponse(recv), id = JSON.parse(decoder.decode(response.body))?.result?.id;
      if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) fail();
      const planned = planCloudflareSession('identity', sent, recv);
      userId = id;
      return planned;
    }
    if (!userId || fastSource) fail();
    const response = parseHttpResponse(recv), body = decoder.decode(response.body);
    const spans = cloudflarePageRows(body), rows = JSON.parse(body).result;
    const select = selectCloudflareRows(rows, i => !!spans[i] && !!transcriptRange(response.chunks, spans[i].start, spans[i].end), userId, context.issuedAt);
    if (!select.length) fail();
    return planCloudflareSession(meta.step, sent, recv, select);
  };
  return {
    clear() { consumed = true; context = undefined; userId = undefined; linkSecret?.fill(0); },
    getRevealPlan(meta, transcripts) {
      try {
        if (consumed) fail(); check(meta);
        const { sentRangesWithHandlers, recvRangesWithHandlers } = plan(meta, transcripts);
        return { sentRangesWithHandlers, recvRangesWithHandlers };
      } catch (error) { stage('PLAN', error); fail(); }
    },
    async prove(witnesses, signal) {
      const buffers = [], openings = new Map();
      try {
        if (consumed || !signal || signal.aborted || !Array.isArray(witnesses) ||
            (fastSource ? witnesses.length !== 1 : witnesses.length < 2 || witnesses.length > CF_RUN_STEPS.length)) fail();
        consumed = true;
        const results = [];
        for (const [index, witness] of witnesses.entries()) {
          check(witness);
          if (witness.step !== CF_RUN_STEPS[index]) fail();
          const directions = {};
          for (const direction of ['sent', 'recv']) {
            const source = witness[direction], selections = witness.selections[direction], held = witness.openings[direction];
            const bytes = new Uint8Array(source.length); buffers.push(bytes);
            const privateRanges = [], publicRanges = [];
            for (const range of selections) {
              if (range.handler.action.kind === 'REVEAL') { bytes.set(source.subarray(range.start, range.end), range.start); publicRanges.push({ start: range.start, end: range.end }); continue; }
              const match = held.filter(o => o.start === range.start && o.end === range.end);
              if (match.length !== 1) fail();
              const preimage = new Uint8Array(range.end - range.start + 16); buffers.push(preimage);
              preimage.set(source.subarray(range.start, range.end)); preimage.set(match[0].blinder, range.end - range.start);
              const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)));
              if (digest !== hex(match[0].hash) || openings.has(digest)) fail();
              openings.set(digest, preimage);
              privateRanges.push({ start: range.start, end: range.end, hash: digest });
            }
            directions[direction] = { bytes, privateRanges, ...(direction === 'recv' ? { publicRanges } : {}) };
          }
          results.push(inspectCloudflareSession(directions, witness.step));
        }
        const identity = results[0].identity;
        if (!identity || !openings.has(identity.hash)) fail();
        if (fastSource) {
          // The recorded opening is this id with the saved blinder: check it locally before proving.
          const prior = new Uint8Array(openings.get(identity.hash)); buffers.push(prior);
          prior.set(linkSecret, identity.length);
          if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', prior))) !== fastSource.identityHash) fail();
          openings.set(fastSource.identityHash, prior);
        }
        const targets = cloudflareTargets(results[0], results.slice(1), fastSource), proofs = [];
        for (const target of targets) {
          if (signal.aborted) fail();
          const inputs = cloudflareCircuitInputs(target, openings);
          try {
            const entry = await proveCircuit(target.circuitId, inputs, signal);
            const fields = cloudflareProofFields(entry);
            if (entry.circuitId !== target.circuitId || fields.some((v, i) => v !== BigInt(target.publicInputs[i]))) fail();
            proofs.push(entry);
          } finally { eraseCloudflareInputs(inputs); }
        }
        // Storage failure only means the next check from this browser must be a full one.
        if (!fastSource && saveLink) await Promise.resolve(saveLink(identity.hash, openings.get(identity.hash).subarray(identity.length))).catch(() => undefined);
        return { kind: CF_BUNDLE_KIND, version: 1, sessionIds: witnesses.map(w => w.sessionId), proofs };
      } catch (error) { stage('PROVE', error); fail(); }
      finally { linkSecret?.fill(0); for (const b of buffers) b.fill(0); for (const v of openings.values()) v.fill(0); openings.clear(); }
    },
  };
}
