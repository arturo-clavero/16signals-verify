// Builds a proof package (format v1, see check-package.mjs) from what the TLSNotary verifier sent: one webhook per
// verified TLS session, with its signed `receipt` and the salted `leaves` the receipt's Merkle root commits to. The
// inverse of checkPackage: every run is checked to rebuild its signed root before it is put in a package.
//
// By default no transcript byte leaves: a reveal leaf is published as its hash, a commit leaf with its salt and digest
// (the digest the ZK proofs open). `disclose` picks reveal leaves to publish with their bytes and salt instead.
import { pinnedKeyHash, publicBundle, resolvePins } from '../bundle.mjs';
import { fromHex, isHex64, isRecord, toBase64, toHex } from './bytes.mjs';
import { commitLeafHash, merkleRoot, revealLeafHash } from './leaves.mjs';
import { unverifiedReceipt } from './receipt.mjs';

const REPLACEMENT = '�';
const fail = (reason) => {
  throw new Error(`PACKAGE_BUILD_FAILED: ${reason}`);
};

/**
 * The exact bytes of one webhook transcript direction. The verifier sends each direction as (lossy) UTF-8 text with
 * unrevealed bytes as 0x00, plus its byte length; null when bytes were lost on the way (an invalid UTF-8 sequence).
 */
export function transcriptBytes(text, length) {
  if (typeof text !== 'string' || !Number.isSafeInteger(length) || text.includes(REPLACEMENT))
    return null;
  const bytes = new TextEncoder().encode(text);
  return bytes.length === length ? bytes : null;
}

/**
 * One package run from a session's receipt and leaves. `leaves` are the webhook's (`{ direction, start, end, salt,
 * kind?, alg?, digest? }`), `sent` / `recv` the session's transcript bytes (needed for every reveal leaf), `zk` the
 * proof's ZK bundle (only on the first run of a proof). `disclose(leaf, index)` returns true for a reveal leaf to
 * publish with its bytes. Throws unless the leaves rebuild the receipt's signed root and leaf count.
 */
export async function buildRun({
  receipt,
  leaves,
  sent = null,
  recv = null,
  zk,
  disclose = () => false,
}) {
  const payload = unverifiedReceipt(receipt)?.payload;
  if (!payload) fail('the receipt is not a compact JWS with a readable payload');
  if (!Array.isArray(leaves) || !leaves.length || leaves.length !== payload.leafCount)
    fail(
      `the receipt signs ${payload.leafCount} leaves, ${Array.isArray(leaves) ? leaves.length : 0} were given`,
    );
  const run = { receipt, leaves: [], disclosed: [], commitments: [], hidden: [] };
  const hashes = [];
  for (const [index, leaf] of leaves.entries()) {
    if (
      !isRecord(leaf) ||
      (leaf.direction !== 'sent' && leaf.direction !== 'recv') ||
      !Number.isSafeInteger(leaf.start) ||
      !Number.isSafeInteger(leaf.end) ||
      leaf.start < 0 ||
      leaf.end < leaf.start ||
      !isHex64(leaf.salt)
    )
      fail(`leaf ${index} is malformed`);
    const range = { direction: leaf.direction, start: leaf.start, end: leaf.end };
    const salt = fromHex(leaf.salt);
    if (leaf.kind === 'commit') {
      if (!isHex64(leaf.digest) || typeof leaf.alg !== 'string')
        fail(`commit leaf ${index} has no digest`);
      hashes.push(await commitLeafHash(range, salt, fromHex(leaf.digest)));
      run.leaves.push({ ...range, kind: 'commit' });
      run.commitments.push({ leaf: index, salt: leaf.salt, alg: leaf.alg, digest: leaf.digest });
      continue;
    }
    const source = leaf.direction === 'sent' ? sent : recv;
    if (!(source instanceof Uint8Array) || leaf.end > source.length)
      fail(`no transcript bytes for reveal leaf ${index}`);
    const bytes = source.subarray(leaf.start, leaf.end);
    const hash = await revealLeafHash(range, salt, bytes);
    hashes.push(hash);
    run.leaves.push({ ...range, kind: 'reveal' });
    if (disclose(range, index))
      run.disclosed.push({ leaf: index, salt: leaf.salt, bytes: toBase64(bytes) });
    else run.hidden.push({ leaf: index, hash: toHex(hash) });
  }
  if (toHex(await merkleRoot(hashes)) !== payload.root)
    fail('the leaves and transcript do not rebuild the signed root');
  if (zk !== undefined && zk !== null) run.zk = zk;
  return run;
}

/** One package run from one verifier webhook payload (`receipt`, `leaves`, `transcript`). */
export async function webhookRun(payload, options = {}) {
  if (!isRecord(payload) || typeof payload.receipt !== 'string' || !Array.isArray(payload.leaves))
    fail('the webhook carries no receipt (is an attestor key configured?)');
  const t = isRecord(payload.transcript) ? payload.transcript : {};
  return buildRun({
    ...options,
    receipt: payload.receipt,
    leaves: payload.leaves,
    sent: transcriptBytes(t.sent, t.sent_length),
    recv: transcriptBytes(t.recv, t.recv_length),
  });
}

/**
 * A proof package from built runs. `descriptor` is the provider descriptor: its `id` names the provider and its pins
 * give `pins` for every circuit the runs' ZK bundles use (pass `pins` to set them yourself). `vks`: circuit id ->
 * verification key (base64 string or bytes), for the circuits used; lets a reader check the proofs without its own keys.
 * Runs of one proof must be consecutive, the ZK bundle on the proof's first run.
 */
export async function buildPackage({
  descriptor,
  provider = descriptor?.id,
  claim,
  runs,
  pins,
  vks,
}) {
  if (typeof provider !== 'string' || !provider) fail('no provider');
  if (!Array.isArray(runs) || !runs.length) fail('no runs');
  const used = [
    ...new Set(
      runs.flatMap((run) => (run.zk ? publicBundle(run.zk).proofs.map((p) => p.circuitId) : [])),
    ),
  ].sort();
  let packagePins = pins;
  if (packagePins === undefined) {
    const circuits = used.length ? (await resolvePins(descriptor))?.circuits : {};
    packagePins = Object.fromEntries(
      used.map((id) => {
        const sha = pinnedKeyHash(circuits?.[id]);
        if (!isHex64(sha)) fail(`the ${provider} descriptor pins no key for ${id}`);
        return [id, sha];
      }),
    );
  }
  const pkg = {
    v: 1,
    provider,
    ...(claim !== undefined && claim !== null ? { claim } : {}),
    runs,
    pins: packagePins,
  };
  if (vks)
    pkg.vks = Object.fromEntries(
      used
        .filter((id) => vks[id] !== undefined)
        .map((id) => [
          id,
          typeof vks[id] === 'string' ? vks[id] : toBase64(Uint8Array.from(vks[id])),
        ]),
    );
  return pkg;
}
