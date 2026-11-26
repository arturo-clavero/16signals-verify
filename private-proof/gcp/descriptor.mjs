// Google Cloud plugged into packages/proof-check: pinned keys, the claim from a verified result or from the public
// inputs, and its headline.
import pins from './generated/verification-keys.json' with { type: 'json' };
import { BATCHES } from './policy.mjs';

const fail = reason => { throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`); };
const days = window => (window ? ` in the last ${window} days` : '');

export default Object.freeze({
  id: 'gcp',
  kind: 'GCP_PRIVATE_RESULT',
  pins,

  /** Only observed skill groups; empty and denied stay private. `result` is verifyBundle's return value. */
  claimFromResult(result) {
    if (!Array.isArray(result?.groups) || ![7, 30, 90].includes(result?.policy?.windowDays)) fail('gcp result');
    const observed = result.groups.filter(group => group?.status === 'observed').map(group => {
      if (typeof group.id !== 'string' || !/^g[0-9]{1,3}$/.test(group.id)) fail('gcp group');
      return group.id;
    }).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    return { claim: `gcp:observed:${observed.join(',') || 'none'}`, window: result.policy.windowDays };
  },

  /** The observed groups and the window, recomputed from the timestamps-v1 public inputs of each batch. */
  claim(bundle, { batches = BATCHES } = {}) {
    const timestamps = bundle.proofs.filter(entry => entry.circuitId === 'timestamps-v1');
    if (timestamps.length !== batches.length) return null;
    const observed = [], windows = new Set();
    timestamps.forEach((entry, batch) => {
      const values = entry.publicInputs.map(BigInt);
      // Layout: 6 x 32 hash bytes, 6 lengths, cutoff, windowDays. A non-zero length is an observed group.
      batches[batch].groupIds.forEach((id, slot) => { if (values[192 + slot] > 0n) observed.push(id); });
      windows.add(Number(values[199]));
    });
    if (windows.size !== 1) return null;
    observed.sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    return { claim: `gcp:observed:${observed.join(',') || 'none'}`, window: [...windows][0] };
  },

  describe({ claim, window }) {
    if (!claim.startsWith('gcp:observed:')) return null;
    const groups = claim.slice('gcp:observed:'.length);
    return groups === 'none' ? `Google Cloud: no activity observed${days(window)}.`
      : `Google Cloud: activity observed in ${groups.split(',').length} skill group(s)${days(window)}.`;
  },
});
