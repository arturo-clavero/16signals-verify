// Adapter from private-proof/{gcp,aws}/verify-bundle.mjs results to commitment fields.
import { canonicalize, commitmentFields, sha256Hex } from './commitment.mjs';
import { AWS_OPERATIONS, AWS_SKILL_AREAS } from '../../private-proof/aws/operation-catalog.mjs';
import { AWS_SKILL_GROUPS } from '../../private-proof/aws/skill-groups.mjs';

const KINDS = { gcp: 'GCP_PRIVATE_RESULT', aws: 'AWS_PRIVATE_RESULT' };
const FIELD = /^(?:0x[0-9a-f]{1,64}|0|[1-9][0-9]{0,19})$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const fail = reason => { throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`); };

/**
 * The public part of a completion bundle: exactly the proofs and public inputs verify-bundle checks, in wire order.
 * sessionIds are dropped: they only route the bundle to the verifier's own attempt records.
 */
export function publicBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || !Object.values(KINDS).includes(bundle.kind) || bundle.version !== 1 ||
      !Array.isArray(bundle.proofs) || !bundle.proofs.length || bundle.proofs.length > 128) fail('bundle');
  return { kind: bundle.kind, version: 1, proofs: bundle.proofs.map(entry => {
    if (!entry || typeof entry.circuitId !== 'string' || !/^[a-z0-9-]{1,48}$/.test(entry.circuitId) ||
        typeof entry.proof !== 'string' || entry.proof.length > 32768 || !BASE64.test(entry.proof) ||
        !Array.isArray(entry.publicInputs) || entry.publicInputs.length > 1024 ||
        entry.publicInputs.some(value => typeof value !== 'string' || !FIELD.test(value))) fail('proof entry');
    return { circuitId: entry.circuitId, proof: entry.proof, publicInputs: [...entry.publicInputs] };
  }) };
}

/** sha256 over the canonical JSON of the public bundle. */
export async function proofHash(bundle) {
  return sha256Hex(canonicalize(publicBundle(bundle)));
}

/**
 * Verification-key hashes for the circuits a bundle uses, from the repo's pinned manifests:
 * private-proof/gcp/generated/verification-keys.json (`sha256`) or private-proof/aws/generated/pins.json (`keySha256`).
 */
export function vkHashesFor(bundle, pins) {
  const circuits = pins?.circuits;
  if (!circuits || typeof circuits !== 'object') fail('pins');
  const ids = [...new Set(publicBundle(bundle).proofs.map(entry => entry.circuitId))].sort();
  return Object.fromEntries(ids.map(id => {
    const pin = circuits[id];
    const hash = pin && (Object.hasOwn(pin, 'keyFile') ? pin.keySha256 : pin.sha256);
    if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) fail(`no pinned key for ${id}`);
    return [id, hash];
  }));
}

const AWS_ACTIVITIES = AWS_OPERATIONS.map(entry => entry.id);
const AWS_GROUPS = AWS_SKILL_GROUPS.map(group => group.id);
const CLAIM_BYTES = 128;

function claimOf(provider, result) {
  if (provider === 'gcp') {
    if (!Array.isArray(result?.groups) || ![7, 30, 90].includes(result?.policy?.windowDays)) fail('gcp result');
    const observed = result.groups.filter(group => group?.status === 'observed').map(group => {
      if (typeof group.id !== 'string' || !/^g[0-9]{1,3}$/.test(group.id)) fail('gcp group');
      return group.id;
    }).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    // Only observed skill groups; empty and denied stay private.
    return { claim: `gcp:observed:${observed.join(',') || 'none'}`, window: result.policy.windowDays };
  }
  if (provider === 'aws') {
    if (result?.attribution !== 'iam-user' || result?.windowDays !== 90) fail('aws result');
    if (result.taskType === 'iam-role-trust-update' && !('activities' in result) && !('observations' in result))
      return { claim: `aws:${result.taskType}:${result.attribution}`, window: result.windowDays };
    if ('observations' in result) {
      // Page runs: the skill groups with at least one proven row, as 1-based catalog positions in display order.
      const rows = result.observations;
      if (!Array.isArray(rows) || !rows.length || rows.some(row => !AWS_GROUPS.includes(row?.group))) fail('aws observations');
      const positions = [...new Set(rows.map(row => AWS_GROUPS.indexOf(row.group) + 1))].sort((a, b) => a - b);
      return { claim: `aws:groups:${positions.join(',')}:${result.attribution}`, window: result.windowDays };
    }
    const acts = result.activities;
    if (!Array.isArray(acts) || acts.length < 1 || acts.length > AWS_ACTIVITIES.length ||
        acts.some((id, i) => !AWS_ACTIVITIES.includes(id) || (i && AWS_ACTIVITIES.indexOf(id) <= AWS_ACTIVITIES.indexOf(acts[i - 1])))) fail('aws activities');
    // Only the activities the bundle proved, in catalog order; when the names do not fit a claim, their skill areas.
    const claim = `aws:activity:${acts.join(',')}:${result.attribution}`;
    if (claim.length <= CLAIM_BYTES) return { claim, window: result.windowDays };
    const areas = AWS_SKILL_AREAS.map(area => area.id);
    const positions = acts.map(id => areas.indexOf(AWS_OPERATIONS.find(entry => entry.id === id).skillArea) + 1);
    return { claim: `aws:areas:${positions.join(',')}:${result.attribution}`, window: result.windowDays };
  }
  return fail('provider');
}

/**
 * Commitment fields for a bundle that verifyBundle / verifyAwsBundle accepted.
 * `result` is that function's return value; options: { pins, coreDigest?, pluginSha256? }.
 */
export async function fromVerifiedBundle(provider, bundle, result, { pins, coreDigest, pluginSha256 } = {}) {
  if (bundle?.kind !== KINDS[provider]) fail('bundle kind does not match provider');
  const fields = { provider, ...claimOf(provider, result), proofHash: await proofHash(bundle), vkHashes: vkHashesFor(bundle, pins) };
  if (coreDigest !== undefined) fields.coreDigest = coreDigest;
  if (pluginSha256 !== undefined) fields.pluginSha256 = pluginSha256;
  return commitmentFields(fields);
}
