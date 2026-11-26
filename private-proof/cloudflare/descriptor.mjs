// Cloudflare plugged into packages/proof-check: pinned keys, TLS hosts, the claim from a verified result, and its headline.
// The public inputs do not determine the claim, so it is checked for format and known positions only.
import pins from './generated/pins.json' with { type: 'json' };
import { CLOUDFLARE_SKILL_GROUPS } from './skill-groups.mjs';
import { CF_HOSTS } from './request.mjs';

const GROUPS = CLOUDFLARE_SKILL_GROUPS.map((group) => group.id);
const fail = (reason) => {
  throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`);
};
const days = (window) => (window ? ` in the last ${window} days` : '');

export default Object.freeze({
  id: 'cloudflare',
  kind: 'CLOUDFLARE_PRIVATE_RESULT',
  pins,
  hosts: CF_HOSTS,

  /** Audit-log page runs: the skill groups with at least one proven row, as 1-based catalog positions. */
  claimFromResult(result) {
    const rows = result?.observations;
    if (
      result?.attribution !== 'cloudflare-user' ||
      !Number.isInteger(result?.windowDays) ||
      !Array.isArray(rows) ||
      !rows.length ||
      rows.some((row) => !GROUPS.includes(row?.group))
    )
      fail('cloudflare result');
    const positions = [...new Set(rows.map((row) => GROUPS.indexOf(row.group) + 1))].sort(
      (a, b) => a - b,
    );
    return { claim: `cloudflare:groups:${positions.join(',')}:user`, window: result.windowDays };
  },

  describe({ claim, window }) {
    const match = /^cloudflare:groups:([0-9,]+):user$/.exec(claim);
    const labels = match?.[1].split(',').map((n) => CLOUDFLARE_SKILL_GROUPS[Number(n) - 1]?.label);
    return labels?.every(Boolean)
      ? `Cloudflare: account activity verified in ${labels.join(', ')}${days(window)}.`
      : null;
  },
});
