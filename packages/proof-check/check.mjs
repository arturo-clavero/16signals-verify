// Provider-agnostic checks of a signed attestation and its public proof bundle. No DOM, no network: providers,
// registries and trusted keys are passed in, so Node, browsers and other apps run it as is.
import { verifyAttestation } from './attestation.mjs';
import { pinnedKeyHash, proofHash, publicBundle, resolvePins } from './bundle.mjs';
import { bundleCommitment } from './commitment.mjs';
import { isProofPackage } from './package/check-package.mjs';

/**
 * One provider (evidence type) plugged into the checks. Only `id` is required.
 * @typedef {object} ProviderDescriptor
 * @property {string} id Provider name, as in `attestation.provider`.
 * @property {string} [kind] `bundle.kind` of its proof bundles.
 * @property {Pins | (() => Pins | Promise<Pins>)} [pins] Pinned verification keys, or a loader for them.
 * @property {(bundle: PublicBundle, opts: { claim?: string }) => ClaimWindow | null} [claim] Recomputes the claim from
 *   the bundle's public inputs; `opts.claim` is the signed claim. Null when the public inputs do not determine it.
 * @property {boolean} [claimFromProofs] True when `claim` fully determines the claim from the proofs' public inputs, so a
 *   proof package's claim check may rest on it (not only check it for consistency).
 * @property {(result: unknown) => ClaimWindow} [claimFromResult] Claim for a result of the provider's own bundle
 *   verifier; used by `fromVerifiedBundle` when publishing.
 * @property {(claim: { provider: string, claim: string, window?: number }) => string | null} [describe] Plain-language
 *   headline; null falls back to the claim as published.
 */
/**
 * @typedef {{ circuits: Record<string, { sha256: string } | { keyFile: string, keySha256: string }> }} Pins
 * @typedef {{ claim: string, window?: number }} ClaimWindow
 * @typedef {{ kind: string, version: 1, proofs: { circuitId: string, proof: string, publicInputs: string[] }[] }} PublicBundle
 */
/**
 * Where attestations and bundles are looked up by commitment (a chain, an indexer, a file store).
 * @typedef {object} Registry
 * @property {(query: { commitment: string }) => Promise<object[]>} findAttestations Candidate signed attestations.
 * @property {(query: { commitment: string, proofHash: string }) => Promise<{ json: string } | null>} findBundle The public
 *   bundle as JSON text, or null.
 * @property {(query: { proofHash: string }) => Promise<object[]>} [findByProofHash] Signed attestations naming a proof
 *   package's hash (the package `on-chain` check).
 */
/**
 * Trusted verifier keys (the shape of `verify/keys.json`). `id` is `verifierKeyId(publicKeyPem)`.
 * @typedef {{ keys: { id: string, label?: string, publicKeyPem: string }[] }} TrustedKeys
 */
/**
 * A check: `id` is stable (signature, provider, bundle, proof-hash, verification-keys, claim) for apps that render their
 * own text; `label` is English; `detail` is a short reason code or value when one helps.
 * @typedef {{ id: string, ok: boolean, label: string, detail?: string }} Check
 * @typedef {object} Result
 * @property {'verified' | 'signature-only' | 'failed' | 'not-found'} status
 * @property {Check[]} checks In the order they ran; stops at the first check that makes the rest meaningless.
 * @property {readonly string[]} restsOnSignature What the checks cannot establish and take from the signature.
 * @property {string} [provider] From the accepted attestation, as are `claim`, `window` and `verifier` (key label or id).
 * @property {string} [claim]
 * @property {number} [window]
 * @property {string} [verifier]
 * @property {string} [commitment] Set by `verifyCommitment`.
 */

const HEX64 = /^[0-9a-f]{64}$/;
const STOP = Symbol('stop');

/** What these checks cannot establish and therefore take from the verifier's signature. */
export const RESTS_ON_SIGNATURE = Object.freeze([
  'The proofs came from a real TLS session with the provider. The TLSNotary verifier saw that session; anyone can run their own verifier.',
  'The public inputs match that authenticated session.',
  'The zero-knowledge proofs verify against the pinned keys. This page does not re-run the ZK verifier.',
]);

/**
 * Accepts a dropped file: a public bundle, a signed attestation, { attestation, bundle }, a proof package, or
 * { package, attestation } (a package with the issuer's signed attestation of its claim).
 */
export function parseDropped(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Not a JSON file.');
  }
  if (value && typeof value.kind === 'string' && Array.isArray(value.proofs))
    return { bundle: value };
  if (isProofPackage(value)) return { package: value };
  if (isProofPackage(value?.package))
    return value.attestation
      ? { package: value.package, attestation: value.attestation }
      : { package: value.package };
  if (value?.type === 'tlsn-attestation') return { attestation: value };
  if (value && (value.attestation || value.bundle))
    return { attestation: value.attestation, bundle: value.bundle };
  throw new Error('Unrecognised file: expected a proof bundle, an attestation or a proof package.');
}

const byId = (providers, id) => (providers ?? []).find((descriptor) => descriptor?.id === id);

/** Plain-language headline for a claim, from its provider's descriptor. Otherwise the claim as published. */
export function describeClaim({ provider, claim, window }, providers) {
  const text = byId(providers, provider)?.describe?.({ provider, claim, window });
  return text || `${provider}: ${claim}${window ? ` in the last ${window} days` : ''}.`;
}

// Each step appends checks to ctx and may end the run (STOP). Later checks, such as re-checking a proof package, are
// appended to this list.
const STEPS = [
  async function signature(ctx) {
    const { commitment, attestations = [], keys, now } = ctx.input;
    const known = new Map((keys?.keys ?? []).map((key) => [key.id, key]));
    let detail = 'no-attestation';
    for (const candidate of attestations) {
      const key = known.get(candidate?.verifierKeyId);
      if (!key) {
        detail = 'unknown-key';
        continue;
      }
      if (candidate.commitment !== commitment) {
        detail = 'commitment-mismatch';
        continue;
      }
      const verdict = await verifyAttestation(candidate, key.publicKeyPem, { now });
      if (verdict.ok) {
        ctx.attestation = candidate;
        ctx.key = key;
        break;
      }
      detail = verdict.reason;
    }
    if (
      !ctx.add(
        Boolean(ctx.attestation),
        'signature',
        'Signed by a listed verifier key, unexpired, and the commitment recomputes from its fields',
        ctx.attestation ? undefined : detail,
      )
    ) {
      ctx.result.status = attestations.length ? 'failed' : 'not-found';
      return STOP;
    }
    const { attestation, key } = ctx;
    Object.assign(ctx.result, {
      provider: attestation.provider,
      claim: attestation.claim,
      window: attestation.window,
      verifier: key.label ?? key.id,
    });
  },
  async function provider(ctx) {
    ctx.descriptor = byId(ctx.input.providers, ctx.attestation.provider);
    if (ctx.descriptor) return;
    ctx.add(
      false,
      'provider',
      'The provider is one these checks support',
      ctx.attestation.provider,
    );
    ctx.result.status = 'failed';
    return STOP;
  },
  async function bundle(ctx) {
    if (!ctx.input.bundle) {
      ctx.add(
        false,
        'bundle',
        'Public proof bundle not found: proof hash and public inputs not checked',
      );
      ctx.result.status = 'signature-only';
      return STOP;
    }
    try {
      ctx.bundle = publicBundle(ctx.input.bundle);
    } catch {
      ctx.bundle = null;
    }
    if (
      !ctx.add(
        Boolean(ctx.bundle) && (await proofHash(ctx.bundle)) === ctx.attestation.proofHash,
        'proof-hash',
        'Published proof bundle hashes to the signed proof hash',
      )
    ) {
      ctx.result.status = 'failed';
      return STOP;
    }
  },
  async function verificationKeys(ctx) {
    const { vkHashes } = ctx.attestation;
    if (!vkHashes) return;
    const used = [...new Set(ctx.bundle.proofs.map((entry) => entry.circuitId))].sort();
    const pinned = (await resolvePins(ctx.descriptor).catch(() => undefined))?.circuits;
    const ok =
      used.join() === Object.keys(vkHashes).sort().join() &&
      (!pinned || used.every((id) => pinnedKeyHash(pinned[id]) === vkHashes[id]));
    if (
      !ctx.add(
        ok,
        'verification-keys',
        pinned
          ? 'Verification keys are the ones pinned in this repository'
          : 'Verification keys cover exactly the circuits used',
      )
    )
      ctx.result.status = 'failed';
  },
  async function claim(ctx) {
    const { attestation } = ctx;
    const derived = ctx.descriptor.claim?.(ctx.bundle, { claim: attestation.claim });
    if (
      derived &&
      !ctx.add(
        derived.claim === attestation.claim && derived.window === attestation.window,
        'claim',
        'Claim matches the proven public inputs',
      )
    )
      ctx.result.status = 'failed';
  },
];

/**
 * Checks one commitment against candidate attestations and an optional public bundle.
 * @param {{ commitment: string, attestations?: object[], bundle?: object | null, keys: TrustedKeys,
 *   providers: ProviderDescriptor[], now?: number }} input
 * @returns {Promise<Result>}
 */
export async function evaluate({ now = Date.now(), ...input }) {
  const checks = [];
  const ctx = {
    input: { ...input, now },
    result: { status: 'verified', checks, restsOnSignature: RESTS_ON_SIGNATURE },
    add(ok, id, label, detail) {
      checks.push(detail === undefined ? { id, ok, label } : { id, ok, label, detail });
      return ok;
    },
  };
  for (const step of STEPS) if ((await step(ctx)) === STOP) break;
  return ctx.result;
}

/**
 * Takes the attestation and bundle from a dropped file, or looks them up by commitment in `registries`, then runs
 * `evaluate`. A dropped attestation's commitment is recomputed from its fields, never taken from its label.
 * @param {{ commitment?: string, dropped?: { attestation?: object, bundle?: object }, keys: TrustedKeys,
 *   providers: ProviderDescriptor[], registries?: Registry[], now?: number }} input
 * @returns {Promise<Result & { commitment: string }>}
 */
export async function verifyCommitment({
  commitment,
  dropped = {},
  keys,
  providers,
  registries = [],
  now,
}) {
  if (!dropped.attestation && !registries.length) throw new Error('Drop an attestation file.');
  if (!dropped.attestation && !HEX64.test(commitment ?? ''))
    throw new Error('Enter a 64-character commitment or drop a file.');
  const attestations = dropped.attestation
    ? [dropped.attestation]
    : (
        await Promise.all(registries.map((registry) => registry.findAttestations({ commitment })))
      ).flat();
  const target =
    commitment ??
    (dropped.attestation
      ? await bundleCommitment(
          Object.fromEntries(
            ['provider', 'claim', 'window', 'proofHash', 'vkHashes', 'coreDigest', 'pluginSha256']
              .filter((name) => dropped.attestation[name] !== undefined)
              .map((name) => [name, dropped.attestation[name]]),
          ),
        )
      : undefined);
  let bundle = dropped.bundle ?? null;
  const hashes = [
    ...new Set(
      attestations.map((item) => item?.proofHash).filter((value) => HEX64.test(value ?? '')),
    ),
  ];
  search: for (const hash of bundle ? [] : hashes) {
    for (const registry of registries) {
      const found = await registry.findBundle({ commitment: target, proofHash: hash });
      if (found) {
        bundle = JSON.parse(found.json);
        break search;
      }
    }
  }
  return {
    commitment: target,
    ...(await evaluate({ commitment: target, attestations, keys, bundle, providers, now })),
  };
}
