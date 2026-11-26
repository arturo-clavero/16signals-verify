// Re-checks a proof package: the receipts the verifier signed, the transcript pieces behind them, the claim, the
// zero-knowledge proofs and the on-chain record. No DOM, no network: providers, DID documents and registries are
// passed in. Only the ZK step loads a library (@aztec/bb.js, lazily).
import { verifyAttestation } from '../attestation.mjs';
import { publicBundle } from '../bundle.mjs';
import { canonicalize } from '../commitment.mjs';
import { isRecord, sha256Hex, utf8 } from './bytes.mjs';
import { LeafError, resolveLeaves } from './leaves.mjs';
import { didOf, splitReceipt, unverifiedReceipt, verifyReceipt } from './receipt.mjs';
import { checkZk } from './zk.mjs';

/**
 * A proof package, format v1. `proofHash` is sha256 over its canonical JSON.
 * @typedef {object} ProofPackage
 * @property {1} v
 * @property {string} provider Descriptor id.
 * @property {string} [claim] The claim the package backs.
 * @property {PackageRun[]} runs One per verified TLS session, in order; consecutive runs sharing a `proofId` are one proof.
 * @property {Record<string, string>} pins Circuit id -> verification key sha256 (must equal the provider's pins).
 * @property {Record<string, string>} [vks] Circuit id -> verification key, base64.
 * @typedef {object} PackageRun
 * @property {string} receipt The verifier's signed receipt (compact JWS, v1 or v2).
 * @property {{ direction: 'sent' | 'recv', start: number, end: number, kind?: 'reveal' | 'commit' }[]} leaves
 * @property {{ leaf: number, salt: string, bytes: string }[]} [disclosed] Revealed bytes (base64) and salt.
 * @property {{ leaf: number, salt: string, alg: string, digest: string }[]} [commitments] Commit leaves.
 * @property {{ leaf: number, hash: string }[]} [hidden] Every other leaf, as its hash.
 * @property {object | null} [zk] The proof's ZK bundle `{ kind, version: 1, proofs }`, on its first run.
 */

/** Reasons a check is `ok: null` without being a gap; they never make the result partial. */
export const SETTLED_REASONS = Object.freeze({ ATTESTED: 'attested', NOT_APPLICABLE: 'not-applicable' });

const LABELS = Object.freeze({
  'receipt-signature': 'Every receipt is signed by the key in the issuer\'s DID document',
  'server-name': 'Every receipt names a host of the provider',
  'signed-root': 'The published pieces rebuild the signed Merkle root',
  'claim-from-data': 'The claim follows from the proofs or the disclosed data, or is signed by a listed issuer key',
  'zk-proofs': 'The zero-knowledge proofs verify and open every signed commitment',
  'on-chain': 'The package hash is in an on-chain record signed by a listed key',
});
export const PACKAGE_CHECKS = Object.freeze(Object.keys(LABELS));

const MAX_RUNS = 64;
const check = (id, ok, detail, reason) => Object.freeze({ id, ok, label: LABELS[id], ...(detail ? { detail } : {}), ...(reason ? { reason } : {}) });
const combine = oks => (oks.some(ok => ok === false) ? false : oks.some(ok => ok === null) ? null : true);
const settled = c => c.ok === null && Object.values(SETTLED_REASONS).includes(c.reason);

/** `proofHash = sha256(canonical JSON of the package)`. */
export const packageHash = async pkg => sha256Hex(utf8(canonicalize(pkg)));

/** Whether a parsed JSON value looks like a proof package (for file drops). */
export const isProofPackage = value => isRecord(value) && value.v === 1 && typeof value.provider === 'string' && Array.isArray(value.runs);

function shapeError(pkg, descriptor) {
  if (!isProofPackage(pkg)) return 'not a proof package v1';
  if (!descriptor) return `no descriptor for provider ${pkg.provider}`;
  if (pkg.claim !== undefined && typeof pkg.claim !== 'string') return 'the package claim is not a string';
  if (!pkg.runs.length || pkg.runs.length > MAX_RUNS) return 'the package has no runs';
  if (pkg.runs.some(run => !isRecord(run) || typeof run.receipt !== 'string' || !Array.isArray(run.leaves))) return 'a run has no receipt or leaf table';
  if (!isRecord(pkg.pins)) return 'the package has no pins';
  if (pkg.vks !== undefined && !isRecord(pkg.vks)) return 'the package vks is not an object';
  return null;
}

/**
 * The claim as signed by a trusted issuer: the given attestation, else the on-chain one. ok true when it is signed by a
 * key in `keys.keys`, unexpired, and names this package hash, provider and claim; false when a trusted signature names
 * another package or claim; null (with why) when there is no attestation from a listed key.
 */
async function signedClaim({ attestation, anchored, known, pkg, proofHash, now }) {
  let trusted = anchored;
  if (attestation !== undefined && attestation !== null) {
    const key = known.get(attestation?.verifierKeyId);
    if (!key) return { ok: null, detail: 'the attestation given is not signed by a listed key' };
    const verdict = await verifyAttestation(attestation, key.publicKeyPem, { now });
    if (!verdict.ok) return { ok: null, detail: `the attestation given does not verify (${verdict.reason})` };
    trusted = { attestation, key };
  }
  if (!trusted) return { ok: null, detail: 'no attestation from a listed key' };
  const { attestation: signed, key } = trusted, by = key.label ?? key.id;
  if (signed.proofHash !== proofHash) return { ok: false, detail: `the attestation signed by ${by} names package ${signed.proofHash}, not ${proofHash}` };
  if (signed.provider !== pkg.provider || signed.claim !== pkg.claim) return { ok: false, detail: `the attestation signed by ${by} backs ${JSON.stringify(signed.claim)}, not ${JSON.stringify(pkg.claim)}` };
  return { ok: true, detail: `${signed.claim}, signed by ${by}` };
}

const allowedHosts = (descriptor, index) => {
  const hosts = typeof descriptor.hosts === 'function' ? descriptor.hosts(index) : descriptor.hosts;
  return Array.isArray(hosts) ? hosts : null;
};

/**
 * Runs the package checks in order: receipt-signature, server-name, signed-root, on-chain, zk-proofs (the slow one),
 * then claim-from-data unless settled earlier (`checks` lists them in the canonical order). Each check is
 * `{ id, ok, label, detail?, reason? }` with ok true, false, or null (not run here; `detail` says why). `reason` 'attested' or 'not-applicable' marks a null
 * that is settled rather than missing.
 *
 * @param {ProofPackage} pkg
 * @param {object} options
 * @param {object[]} options.providers Provider descriptors; `pkg.provider` picks one (its `hosts`, `pins`, `kind`,
 *   `claimFromData`, `claim`).
 * @param {{ dids?: object[], keys?: object[] }} [options.keys] Trusted keys: `dids` are DID documents whose receipt keys
 *   are accepted, `keys` the attestation keys an on-chain record or a signed claim must be signed with.
 * @param {(did: string) => Promise<object | null>} [options.resolveDid] Fetches a DID document not in `keys.dids`.
 * @param {object[]} [options.registries] Registries with `findByProofHash({ proofHash })` (on-chain).
 * @param {string} [options.claim] The claim as published elsewhere; it must be the package's.
 * @param {string} [options.proofHash] The package hash a published claim names; it must match.
 * @param {object} [options.attestation] A signed attestation (attestation.mjs) over the package's hash, provider and
 *   claim; signed by a key in `keys.keys`, it backs the claim when the proofs do not determine it.
 * @param {{ loadBb?: Function, verificationKey?: Function, skip?: string }} [options.zk]
 * @param {Uint8Array} [options.body] The package file's bytes: proofHash is then their sha256.
 * @param {(check: object) => void} [options.onCheck] Called with each check as soon as it is decided.
 * @param {number} [options.now]
 */
export async function checkPackage(pkg, { providers = [], keys, resolveDid, registries = [], claim, proofHash: expectedHash,
  attestation, zk = {}, body, onCheck, now = Date.now() } = {}) {
  const proofHash = body instanceof Uint8Array ? await sha256Hex(body) : isRecord(pkg) ? await packageHash(pkg).catch(() => null) : null;
  const descriptor = isRecord(pkg) ? providers.find(entry => entry?.id === pkg.provider) : undefined;
  const base = { proofHash, provider: isRecord(pkg) ? pkg.provider ?? null : null, claim: isRecord(pkg) ? pkg.claim ?? null : null };
  const malformed = shapeError(pkg, descriptor);
  if (malformed) return { status: 'failed', ...base, checks: PACKAGE_CHECKS.map(id => check(id, false, malformed)) };
  const decided = c => { onCheck?.(c); return c; };

  // receipt-signature: each receipt under the key its kid names, from a trusted DID document or the resolver.
  const documents = new Map();
  for (const doc of keys?.dids ?? []) if (isRecord(doc) && typeof doc.id === 'string') documents.set(doc.id, doc);
  const documentFor = async did => {
    if (!did) return null;
    if (!documents.has(did)) documents.set(did, resolveDid ? await resolveDid(did).catch(() => null) : null);
    return documents.get(did);
  };
  const receipts = [];
  for (const run of pkg.runs) {
    let did = null;
    try { did = didOf(splitReceipt(run.receipt).header.kid); } catch { /* verifyReceipt says why */ }
    const doc = await documentFor(did);
    receipts.push(doc ? await verifyReceipt(run.receipt, doc) : did ? { ok: null, reason: `no DID document for ${did}` } : await verifyReceipt(run.receipt, null));
  }
  const payloads = pkg.runs.map((run, i) => receipts[i].payload ?? unverifiedReceipt(run.receipt)?.payload ?? null);
  const badReceipt = receipts.findIndex(r => r.ok !== true);
  const kids = [...new Set(receipts.map(r => r.kid).filter(Boolean))];
  const c1 = check('receipt-signature', combine(receipts.map(r => r.ok)),
    badReceipt < 0 ? `${receipts.length} receipt(s) signed by ${kids.join(', ')}` : `run ${badReceipt + 1}: ${receipts[badReceipt].reason}`);

  // Runs grouped by proof (consecutive runs sharing a proofId), so each run knows its position in its proof.
  const groups = [];
  pkg.runs.forEach((run, i) => {
    const proofId = payloads[i]?.proofId ?? `run-${i}`;
    const last = groups.at(-1);
    if (last && last.proofId === proofId) last.items.push(i); else groups.push({ proofId, items: [i] });
  });

  // server-name: the provider descriptor's hosts, by position in the proof.
  let c2;
  const hostRows = groups.flatMap(g => g.items.map((i, index) => ({ run: i + 1, serverName: payloads[i]?.serverName ?? null, allowed: allowedHosts(descriptor, index) })));
  if (hostRows.some(row => !row.allowed)) c2 = check('server-name', null, `the ${descriptor.id} descriptor lists no hosts`);
  else {
    const bad = hostRows.find(row => !row.allowed.includes(row.serverName));
    c2 = check('server-name', !bad, bad ? `run ${bad.run} names ${JSON.stringify(bad.serverName)}, not a ${descriptor.id} host`
      : [...new Set(hostRows.map(row => row.serverName))].join(', '));
  }

  // signed-root: disclosed bytes, commitments and hidden leaf hashes rebuild each signed root.
  const resolved = [];
  let badRoot = null;
  for (let i = 0; i < pkg.runs.length && !badRoot; i++) {
    const payload = payloads[i];
    try {
      if (!payload) throw new LeafError('the receipt payload is unreadable');
      const r = await resolveLeaves(pkg.runs[i], payload.v);
      if (r.hashes.length !== payload.leafCount) throw new LeafError(`the receipt signs ${payload.leafCount} leaves, the package has ${r.hashes.length}`);
      if (r.root !== payload.root) throw new LeafError(`rebuilt root ${r.root} is not the signed ${payload.root}`);
      resolved.push(r);
    } catch (error) {
      if (!(error instanceof LeafError)) throw error;
      badRoot = `run ${i + 1}: ${error.message}`;
    }
  }
  const count = key => resolved.reduce((n, r) => n + (typeof r[key] === 'number' ? r[key] : r[key].length), 0);
  const c3 = check('signed-root', !badRoot, badRoot ?? `${pkg.runs.length} run(s): ${count('disclosed')} disclosed, ${count('committed')} committed and ${count('hiddenCount')} hidden leaves`);
  [c1, c2, c3].forEach(decided);
  const proofGroups = badRoot ? null : groups.map(g => g.items.map(i => ({ run: pkg.runs[i], payload: payloads[i], resolved: resolved[i] })));

  // claim-from-data: settled now when it can be (another claim asked for, roots not rebuilt, no claim, or the disclosed
  // bytes give it); otherwise after zk-proofs and on-chain, from the proofs or a trusted signature.
  let c4;
  if (claim !== undefined && claim !== pkg.claim) c4 = check('claim-from-data', false, `the package backs ${JSON.stringify(pkg.claim ?? null)}, not ${JSON.stringify(claim)}`);
  else if (!proofGroups) c4 = check('claim-from-data', null, 'not run: the pieces do not rebuild the signed roots');
  else if (pkg.claim === undefined) c4 = check('claim-from-data', null, 'the package names no claim', SETTLED_REASONS.NOT_APPLICABLE);
  else {
    const runs = proofGroups.flat().map(({ payload, resolved: r }) => ({ serverName: payload.serverName, sessionId: payload.sessionId,
      proofId: payload.proofId, disclosed: r.disclosed.map(({ leaf, bytes }) => ({ direction: leaf.direction, start: leaf.start, end: leaf.end, bytes })) }));
    const rebuilt = runs.some(run => run.disclosed.length) && descriptor.claimFromData ? await descriptor.claimFromData({ claim: pkg.claim, runs }) : null;
    if (typeof rebuilt === 'string') c4 = check('claim-from-data', rebuilt === pkg.claim, rebuilt === pkg.claim ? `${rebuilt}, from the disclosed data` : `the disclosed data gives ${JSON.stringify(rebuilt)}`);
  }
  if (c4) decided(c4);

  // on-chain: an attestation naming this package hash, signed by a listed key, in a registry.
  let c6, anchored = null;
  const known = new Map((keys?.keys ?? []).map(key => [key.id, key]));
  const lookups = registries.filter(registry => typeof registry?.findByProofHash === 'function');
  if (expectedHash !== undefined && expectedHash !== proofHash) c6 = check('on-chain', false, `the published claim names ${String(expectedHash)}, the package hashes to ${proofHash}`);
  else if (!lookups.length) c6 = check('on-chain', null, 'no registry configured: on-chain anchoring is optional', SETTLED_REASONS.NOT_APPLICABLE);
  else {
    const found = (await Promise.all(lookups.map(registry => registry.findByProofHash({ proofHash }).catch(() => [])))).flat();
    let detail = 'not-found';
    for (const candidate of found) {
      const key = known.get(candidate?.verifierKeyId);
      if (!key) { detail = 'unknown-key'; continue; }
      if (candidate.proofHash !== proofHash) { detail = 'proof-hash-mismatch'; continue; }
      const verdict = await verifyAttestation(candidate, key.publicKeyPem, { now });
      if (verdict.ok) { anchored = { attestation: candidate, key }; break; }
      detail = verdict.reason;
    }
    c6 = check('on-chain', Boolean(anchored), anchored ? `signed by ${anchored.key.label ?? anchored.key.id}` : detail);
  }
  decided(c6);

  // zk-proofs.
  let c5;
  if (!proofGroups) c5 = check('zk-proofs', null, 'not run: the commitments are not the signed ones');
  else if (zk.skip) c5 = check('zk-proofs', null, zk.skip);
  else {
    const r = await checkZk({ descriptor, pins: pkg.pins, groups: proofGroups, loadBb: zk.loadBb, verificationKey: zk.verificationKey, vks: zk.vks ?? pkg.vks });
    c5 = check('zk-proofs', r.ok, r.detail, r.reason);
  }
  decided(c5);

  // claim-from-data, in order: rebuilt from the proofs' public inputs (the descriptor's claim; only once the proofs
  // verify, as unverified public inputs back nothing), else signed by a trusted issuer (an attestation given with the
  // package, or the on-chain one) over this package hash, provider and claim, else attested by the issuer.
  if (!c4) {
    const bundles = proofGroups.map(group => group.find(({ run }) => run.zk !== null && run.zk !== undefined)?.run.zk).filter(Boolean);
    let derived = null;
    if (typeof descriptor.claim === 'function' && bundles.length === 1) {
      try { derived = descriptor.claim(publicBundle(bundles[0]), { claim: pkg.claim })?.claim ?? null; } catch { /* undetermined */ }
    }
    const rebuildable = typeof derived === 'string';
    const rebuilt = rebuildable && c5.ok === true ? derived : null;
    const signed = typeof rebuilt === 'string' ? null : await signedClaim({ attestation, anchored, known, pkg, proofHash, now });
    if (typeof rebuilt === 'string') c4 = check('claim-from-data', rebuilt === pkg.claim, rebuilt === pkg.claim ? `${rebuilt}, from the proofs' public inputs`
      : `the proofs' public inputs give ${JSON.stringify(rebuilt)}`);
    else if (signed.ok !== null) c4 = check('claim-from-data', signed.ok, signed.detail);
    else if (rebuildable && c5.ok !== true) c4 = check('claim-from-data', null, c5.ok === false ? 'not run: the zero-knowledge proofs do not verify'
      : 'not run: the claim is checked against the proofs\' public inputs once the proofs verify');
    else c4 = check('claim-from-data', null, `attested by the issuer: the package's own claim; ${signed.detail}`, SETTLED_REASONS.ATTESTED);
    decided(c4);
  }

  const checks = [c1, c2, c3, c4, c5, c6];
  const ok = combine(checks.filter(c => !settled(c)).map(c => c.ok));
  return { status: ok === true ? 'verified' : ok === false ? 'failed' : 'partial', ...base, checks };
}

/** One line per check, as the CLI prints them. */
export function packageLines(result) {
  const mark = c => (c.ok === true ? 'ok  ' : c.ok === false ? 'FAIL' : c.reason === SETTLED_REASONS.ATTESTED ? 'att '
    : c.reason === SETTLED_REASONS.NOT_APPLICABLE ? 'n/a ' : '--  ');
  return [
    ...result.checks.map(c => `${mark(c)} ${c.id}: ${c.label}${c.detail ? ` (${c.detail})` : ''}`),
    `${result.status} ${result.proofHash ?? ''}${result.claim ? ` ${result.claim}` : ''}`.trim(),
  ];
}
