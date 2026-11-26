// Pure verification logic for the static verify page. No DOM, no network: I/O is injected so Node tests run it as is.
import { bundleCommitment, proofHash, publicBundle, verifyAttestation } from '../packages/proof-check/index.mjs';
import { AWS_OPERATIONS, AWS_SKILL_AREAS } from '../private-proof/aws/operation-catalog.mjs';
import { AWS_SKILL_GROUPS } from '../private-proof/aws/skill-groups.mjs';
import { CLOUDFLARE_SKILL_GROUPS } from '../private-proof/cloudflare/skill-groups.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const VK_PINS = { gcp: '../private-proof/gcp/generated/verification-keys.json', aws: '../private-proof/aws/generated/pins.json',
  cloudflare: '../private-proof/cloudflare/generated/pins.json' };

/** What this page cannot check and therefore takes from the verifier's signature. */
export const RESTS_ON_SIGNATURE = Object.freeze([
  'The proofs came from a real TLS session with the provider. The TLSNotary verifier saw that session; anyone can run their own verifier.',
  'The public inputs match that authenticated session.',
  'The zero-knowledge proofs verify against the pinned keys. This page does not re-run the ZK verifier.',
]);

/** Accepts a dropped file: a public bundle, a signed attestation, or { attestation, bundle }. */
export function parseDropped(text) {
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('Not a JSON file.'); }
  if (value && typeof value.kind === 'string' && Array.isArray(value.proofs)) return { bundle: value };
  if (value?.type === 'tlsn-attestation') return { attestation: value };
  if (value && (value.attestation || value.bundle)) return { attestation: value.attestation, bundle: value.bundle };
  throw new Error('Unrecognised file: expected a proof bundle or an attestation.');
}

function vkPin(pin) {
  return pin && (Object.hasOwn(pin, 'keyFile') ? pin.keySha256 : pin.sha256);
}

/** Recomputes the coarse claim from the proven public inputs where the circuits make it public. */
const AWS_ACTIVITIES = AWS_OPERATIONS.map(entry => entry.id);

export function claimFromPublicInputs(provider, bundle, { gcpBatches, claim } = {}) {
  if (provider === 'gcp' && gcpBatches) {
    const timestamps = bundle.proofs.filter(entry => entry.circuitId === 'timestamps-v1');
    if (timestamps.length !== gcpBatches.length) return null;
    const observed = [], windows = new Set();
    timestamps.forEach((entry, batch) => {
      const values = entry.publicInputs.map(BigInt);
      // Layout: 6 x 32 hash bytes, 6 lengths, cutoff, windowDays. A non-zero length is an observed group.
      gcpBatches[batch].groupIds.forEach((id, slot) => { if (values[192 + slot] > 0n) observed.push(id); });
      windows.add(Number(values[199]));
    });
    if (windows.size !== 1) return null;
    observed.sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    return { claim: `gcp:observed:${observed.join(',') || 'none'}`, window: [...windows][0] };
  }
  if (provider === 'aws') {
    const count = id => bundle.proofs.filter(entry => entry.circuitId === id).length;
    const events = count('aws-event-link-v1');
    if (!events || count('aws-identity-link-v1') !== events) return null;
    // The family names come from authenticated receipts that stay private; the public inputs prove one linked event
    // per family. So a grouped claim must list known families, in policy order, one per proven event.
    // An areas claim lists one skill area per proven event, in catalog order.
    const areas = /^aws:areas:([0-9,]+):iam-user$/.exec(claim ?? '')?.[1]?.split(',').map(Number);
    if (areas) {
      const ordered = areas.every((n, i) => n >= 1 && n <= AWS_SKILL_AREAS.length && (!i || n > areas[i - 1]));
      return { claim: ordered && areas.length === events ? claim : 'aws:areas:inconsistent:iam-user', window: 90 };
    }
    const families = /^aws:activity:([a-z0-9,-]+):iam-user$/.exec(claim ?? '')?.[1]?.split(',');
    if (families) {
      const ordered = families.every((id, i) => AWS_ACTIVITIES.includes(id) && (!i || AWS_ACTIVITIES.indexOf(id) > AWS_ACTIVITIES.indexOf(families[i - 1])));
      return { claim: ordered && families.length === events ? claim : 'aws:activity:inconsistent:iam-user', window: 90 };
    }
    return events === 1 ? { claim: 'aws:iam-role-trust-update:iam-user', window: 90 } : null;
  }
  return null;
}

/** Plain-language headline for a claim. Unknown providers show the claim as published. */
export function describeClaim({ provider, claim, window }) {
  const days = window ? ` in the last ${window} days` : '';
  if (provider === 'gcp' && claim.startsWith('gcp:observed:')) {
    const groups = claim.slice('gcp:observed:'.length);
    return groups === 'none' ? `Google Cloud: no activity observed${days}.`
      : `Google Cloud: activity observed in ${groups.split(',').length} skill group(s)${days}.`;
  }
  if (claim === 'aws:iam-role-trust-update:iam-user') return `AWS: an IAM user updated a role trust policy${days}.`;
  const cf = /^cloudflare:groups:([0-9,]+):user$/.exec(claim);
  if (provider === 'cloudflare' && cf) {
    const labels = cf[1].split(',').map(n => CLOUDFLARE_SKILL_GROUPS[Number(n) - 1]?.label);
    if (labels.every(Boolean)) return `Cloudflare: account activity verified in ${labels.join(', ')}${days}.`;
  }
  const aws = /^aws:(activity|areas|groups):([a-z0-9,-]+):iam-user$/.exec(claim);
  if (provider === 'aws' && aws) {
    const items = aws[2].split(',');
    const labels = aws[1] === 'activity' ? items.map(id => AWS_OPERATIONS.find(entry => entry.id === id)?.label)
      : items.map(n => (aws[1] === 'areas' ? AWS_SKILL_AREAS : AWS_SKILL_GROUPS)[Number(n) - 1]?.label);
    if (labels.every(Boolean)) return `AWS: an IAM user's activity verified in ${labels.join(', ')}${days}.`;
  }
  return `${provider}: ${claim}${days}.`;
}

/**
 * Evaluates one commitment. `attestations` are candidates (from a dropped file or a registry), `keys` is verify/keys.json,
 * `bundle` the public bundle or null, `pins` the repo's pinned vk manifests by provider.
 */
export async function evaluate({ commitment, attestations, keys, bundle, pins = {}, gcpBatches, now = Date.now() }) {
  const checks = [];
  const add = (ok, label) => { checks.push({ ok, label }); return ok; };
  const known = new Map((keys?.keys ?? []).map(key => [key.id, key]));
  let chosen = null;
  for (const candidate of attestations ?? []) {
    const key = known.get(candidate?.verifierKeyId);
    if (!key || candidate.commitment !== commitment) continue;
    if ((await verifyAttestation(candidate, key.publicKeyPem, { now })).ok) { chosen = { attestation: candidate, key }; break; }
  }
  if (!add(Boolean(chosen), 'Signed by a listed verifier key, unexpired, and the commitment recomputes from its fields'))
    return { status: (attestations ?? []).length ? 'failed' : 'not-found', checks, restsOnSignature: RESTS_ON_SIGNATURE };
  const { attestation, key } = chosen;
  const result = { status: 'verified', provider: attestation.provider, claim: attestation.claim, window: attestation.window,
    verifier: key.label ?? key.id, checks, restsOnSignature: RESTS_ON_SIGNATURE };
  if (!bundle) {
    add(false, 'Public proof bundle not found: proof hash and public inputs not checked');
    result.status = 'signature-only';
    return result;
  }
  let clean;
  try { clean = publicBundle(bundle); } catch { clean = null; }
  if (!add(Boolean(clean) && await proofHash(clean) === attestation.proofHash, 'Published proof bundle hashes to the signed proof hash')) {
    result.status = 'failed';
    return result;
  }
  if (attestation.vkHashes) {
    const used = [...new Set(clean.proofs.map(entry => entry.circuitId))].sort();
    const pinned = pins[attestation.provider]?.circuits;
    const ok = used.join() === Object.keys(attestation.vkHashes).sort().join() &&
      (!pinned || used.every(id => vkPin(pinned[id]) === attestation.vkHashes[id]));
    if (!add(ok, pinned ? 'Verification keys are the ones pinned in this repository' : 'Verification keys cover exactly the circuits used'))
      result.status = 'failed';
  }
  const derived = claimFromPublicInputs(attestation.provider, clean, { gcpBatches, claim: attestation.claim });
  if (derived) {
    if (!add(derived.claim === attestation.claim && derived.window === attestation.window, 'Claim matches the proven public inputs'))
      result.status = 'failed';
  }
  return result;
}

/**
 * I/O wrapper used by the page: takes the attestation and bundle from a dropped file, or looks them up by commitment
 * in an optional `registry` ({ findAttestations, findBundle }).
 */
export async function verifyCommitment({ commitment, dropped = {}, keys, registry, loadJson, gcpBatches, now }) {
  if (!dropped.attestation && !registry) throw new Error('Drop an attestation file.');
  if (!dropped.attestation && !HEX64.test(commitment ?? '')) throw new Error('Enter a 64-character commitment or drop a file.');
  const attestations = dropped.attestation ? [dropped.attestation] : await registry.findAttestations({ commitment });
  // A dropped attestation names its own commitment; recompute it rather than trusting the label.
  const target = commitment ?? (dropped.attestation ? await bundleCommitment(Object.fromEntries(
    ['provider', 'claim', 'window', 'proofHash', 'vkHashes', 'coreDigest', 'pluginSha256']
      .filter(name => dropped.attestation[name] !== undefined).map(name => [name, dropped.attestation[name]]))) : undefined);
  let bundle = dropped.bundle ?? null;
  if (!bundle && registry) {
    const hashes = [...new Set(attestations.map(item => item?.proofHash).filter(value => HEX64.test(value ?? '')))];
    for (const hash of hashes) {
      const found = await registry.findBundle({ commitment: target, proofHash: hash });
      if (found) { bundle = JSON.parse(found.json); break; }
    }
  }
  const pins = {};
  for (const provider of new Set(attestations.map(item => item?.provider)))
    if (VK_PINS[provider]) pins[provider] = await loadJson(VK_PINS[provider]).catch(() => undefined);
  return { commitment: target, ...await evaluate({ commitment: target, attestations, keys, bundle, pins, gcpBatches, now }) };
}
