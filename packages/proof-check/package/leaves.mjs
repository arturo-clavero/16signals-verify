// The receipt Merkle tree over a run's leaves (servers/verifier README, "Signed receipts"):
//
//   reveal leaf = SHA-256(0x00 || dir || u64be(start) || u64be(len) || salt32 || bytes)    dir: 0x00 sent, 0x01 recv
//   commit leaf = SHA-256(0x02 || dir || u64be(start) || u64be(len) || salt32 || digest)   (receipt v2)
//   node        = SHA-256(0x01 || left || right), an odd last node promoted unchanged
//
// Leaves stay in receipt order (every sent range, then every recv range). A package gives each leaf one way: its
// bytes and salt (disclosed), its commitment digest and salt (a commit leaf, opened by the ZK proofs), or only its hash.
import { concat, fromHex, isHex64, sha256, strictBase64, toHex } from './bytes.mjs';

const REVEAL_TAG = 0x00;
const NODE_TAG = 0x01;
const COMMIT_TAG = 0x02;
const MAX_LEAVES = 4096;

function u64be(n) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

const leafHead = (tag, leaf) =>
  concat(
    Uint8Array.of(tag, leaf.direction === 'sent' ? 0 : 1),
    u64be(leaf.start),
    u64be(leaf.end - leaf.start),
  );

export const revealLeafHash = (leaf, salt, bytes) =>
  sha256(leafHead(REVEAL_TAG, leaf), salt, bytes);
export const commitLeafHash = (leaf, salt, digest) =>
  sha256(leafHead(COMMIT_TAG, leaf), salt, digest);

export async function merkleRoot(hashes) {
  if (!hashes.length) throw new Error('no leaves');
  let level = hashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(
        i + 1 < level.length
          ? await sha256(Uint8Array.of(NODE_TAG), level[i], level[i + 1])
          : level[i],
      );
    level = next;
  }
  return level[0];
}

export class LeafError extends Error {}

/**
 * Validates a run's leaf table and resolves every leaf to its hash. Returns
 * `{ hashes, disclosed: [{ index, leaf, bytes }], committed: [{ index, leaf, digest, alg }], hiddenCount, root }`.
 * Throws LeafError with a reader-facing reason.
 */
export async function resolveLeaves(run, receiptVersion) {
  const { leaves } = run;
  if (!Array.isArray(leaves) || !leaves.length || leaves.length > MAX_LEAVES)
    throw new LeafError('the run has no leaf table');
  let lastDirection = 'sent';
  const kinds = leaves.map((leaf, i) => {
    const kind = leaf?.kind ?? 'reveal';
    if (
      !leaf ||
      (leaf.direction !== 'sent' && leaf.direction !== 'recv') ||
      !Number.isSafeInteger(leaf.start) ||
      !Number.isSafeInteger(leaf.end) ||
      leaf.start < 0 ||
      leaf.end < leaf.start ||
      (kind !== 'reveal' && kind !== 'commit')
    )
      throw new LeafError(`leaf ${i} is malformed`);
    if (lastDirection === 'recv' && leaf.direction === 'sent')
      throw new LeafError('sent leaves must come before recv leaves');
    if (kind === 'commit' && receiptVersion !== 2)
      throw new LeafError('commit leaves need a v2 receipt');
    lastDirection = leaf.direction;
    return kind;
  });
  const hashes = new Array(leaves.length).fill(null);
  const claim = (index, what) => {
    if (!Number.isSafeInteger(index) || index < 0 || index >= leaves.length)
      throw new LeafError(`${what} names leaf ${index}, which does not exist`);
    if (hashes[index] !== null) throw new LeafError(`leaf ${index} is given twice`);
  };
  const list = (value) => (Array.isArray(value) ? value : []);

  const disclosed = [];
  for (const entry of list(run.disclosed)) {
    claim(entry?.leaf, 'a disclosed entry');
    const leaf = leaves[entry.leaf];
    if (kinds[entry.leaf] !== 'reveal')
      throw new LeafError(`leaf ${entry.leaf} is a commit leaf; it cannot be disclosed`);
    const bytes = strictBase64(entry.bytes);
    if (!isHex64(entry.salt) || !bytes || bytes.length !== leaf.end - leaf.start)
      throw new LeafError(`disclosed leaf ${entry.leaf} is malformed`);
    hashes[entry.leaf] = await revealLeafHash(leaf, fromHex(entry.salt), bytes);
    disclosed.push({ index: entry.leaf, leaf, bytes });
  }
  const committed = [];
  for (const entry of list(run.commitments)) {
    claim(entry?.leaf, 'a commitment');
    const leaf = leaves[entry.leaf];
    if (kinds[entry.leaf] !== 'commit')
      throw new LeafError(`leaf ${entry.leaf} is a reveal leaf, not a commitment`);
    if (!isHex64(entry.salt) || !isHex64(entry.digest) || typeof entry.alg !== 'string')
      throw new LeafError(`commitment ${entry.leaf} is malformed`);
    hashes[entry.leaf] = await commitLeafHash(leaf, fromHex(entry.salt), fromHex(entry.digest));
    committed.push({ index: entry.leaf, leaf, digest: entry.digest, alg: entry.alg });
  }
  let hiddenCount = 0;
  for (const entry of list(run.hidden)) {
    claim(entry?.leaf, 'a hidden entry');
    // Commitment digests are what the ZK proofs open, so a commit leaf is always published with its digest.
    if (kinds[entry.leaf] !== 'reveal')
      throw new LeafError(`commit leaf ${entry.leaf} is hidden; its digest must be published`);
    if (!isHex64(entry.hash)) throw new LeafError(`hidden leaf ${entry.leaf} has no 32-byte hash`);
    hashes[entry.leaf] = fromHex(entry.hash);
    hiddenCount += 1;
  }
  const missing = hashes.findIndex((hash) => hash === null);
  if (missing >= 0)
    throw new LeafError(`leaf ${missing} is neither disclosed, committed nor hidden`);
  return { hashes, disclosed, committed, hiddenCount, root: toHex(await merkleRoot(hashes)) };
}
