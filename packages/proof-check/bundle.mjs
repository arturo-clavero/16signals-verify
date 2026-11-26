// Public proof bundles: the part that is hashed and published, the pinned key hashes, and commitment fields for a
// bundle a provider's own verifier accepted.
import { canonicalize, commitmentFields, sha256Hex } from './commitment.mjs';

const KIND = /^[A-Z][A-Z0-9_]{1,47}$/;
const FIELD = /^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const fail = (reason) => {
  throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`);
};

/**
 * The public part of a completion bundle: exactly the proofs and public inputs a provider verifier checks, in wire
 * order. sessionIds are dropped: they only route the bundle to the verifier's own attempt records.
 */
export function publicBundle(bundle) {
  if (
    !bundle ||
    typeof bundle !== 'object' ||
    typeof bundle.kind !== 'string' ||
    !KIND.test(bundle.kind) ||
    bundle.version !== 1 ||
    !Array.isArray(bundle.proofs) ||
    !bundle.proofs.length ||
    bundle.proofs.length > 128
  )
    fail('bundle');
  return {
    kind: bundle.kind,
    version: 1,
    proofs: bundle.proofs.map((entry) => {
      if (
        !entry ||
        typeof entry.circuitId !== 'string' ||
        !/^[a-z0-9-]{1,48}$/.test(entry.circuitId) ||
        typeof entry.proof !== 'string' ||
        entry.proof.length > 32768 ||
        !BASE64.test(entry.proof) ||
        !Array.isArray(entry.publicInputs) ||
        entry.publicInputs.length > 1024 ||
        entry.publicInputs.some((value) => typeof value !== 'string' || !FIELD.test(value))
      )
        fail('proof entry');
      return {
        circuitId: entry.circuitId,
        proof: entry.proof,
        publicInputs: [...entry.publicInputs],
      };
    }),
  };
}

/** sha256 over the canonical JSON of the public bundle. */
export async function proofHash(bundle) {
  return sha256Hex(canonicalize(publicBundle(bundle)));
}

/** Key hash of one pin: `{ sha256 }`, or `{ keyFile, keySha256 }` when the pin also covers a circuit artifact. */
export function pinnedKeyHash(pin) {
  return pin && (Object.hasOwn(pin, 'keyFile') ? pin.keySha256 : pin.sha256);
}

/** A descriptor's pins, given either as an object or as a loader. */
export async function resolvePins(descriptor) {
  return typeof descriptor?.pins === 'function' ? descriptor.pins() : descriptor?.pins;
}

/** Verification-key hashes for the circuits a bundle uses, from a pins manifest `{ circuits: { [id]: pin } }`. */
export function vkHashesFor(bundle, pins) {
  const circuits = pins?.circuits;
  if (!circuits || typeof circuits !== 'object') fail('pins');
  const ids = [...new Set(publicBundle(bundle).proofs.map((entry) => entry.circuitId))].sort();
  return Object.fromEntries(
    ids.map((id) => {
      const hash = pinnedKeyHash(circuits[id]);
      if (typeof hash !== 'string' || !HEX64.test(hash)) fail(`no pinned key for ${id}`);
      return [id, hash];
    }),
  );
}

/**
 * Commitment fields for a bundle the provider's verifier accepted. `descriptor` is the provider descriptor (its
 * `kind`, `claimFromResult` and `pins` are used); `result` is that verifier's return value.
 * Options: { pins? (default: the descriptor's), coreDigest?, pluginSha256? }.
 */
export async function fromVerifiedBundle(
  descriptor,
  bundle,
  result,
  { pins, coreDigest, pluginSha256 } = {},
) {
  if (typeof descriptor?.id !== 'string' || typeof descriptor.claimFromResult !== 'function')
    fail('provider');
  if (bundle?.kind !== descriptor.kind) fail('bundle kind does not match provider');
  const fields = {
    provider: descriptor.id,
    ...descriptor.claimFromResult(result),
    proofHash: await proofHash(bundle),
    vkHashes: vkHashesFor(bundle, pins ?? (await resolvePins(descriptor))),
  };
  if (coreDigest !== undefined) fields.coreDigest = coreDigest;
  if (pluginSha256 !== undefined) fields.pluginSha256 = pluginSha256;
  return commitmentFields(fields);
}
