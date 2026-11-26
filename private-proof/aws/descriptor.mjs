// AWS plugged into packages/proof-check: pinned keys, the claim from a verified result or checked against the public
// inputs, and its headline.
import pins from './generated/pins.json' with { type: 'json' };
import { AWS_OPERATIONS, AWS_SKILL_AREAS } from './operation-catalog.mjs';
import { AWS_SKILL_GROUPS } from './skill-groups.mjs';

const ACTIVITIES = AWS_OPERATIONS.map(entry => entry.id);
const GROUPS = AWS_SKILL_GROUPS.map(group => group.id);
const CLAIM_BYTES = 128;
const fail = reason => { throw new Error(`PROOF_BUNDLE_INVALID: ${reason}`); };
const days = window => (window ? ` in the last ${window} days` : '');

export default Object.freeze({
  id: 'aws',
  kind: 'AWS_PRIVATE_RESULT',
  pins,

  /** `result` is verifyAwsBundle's return value. */
  claimFromResult(result) {
    if (result?.attribution !== 'iam-user' || result?.windowDays !== 90) fail('aws result');
    if (result.taskType === 'iam-role-trust-update' && !('activities' in result) && !('observations' in result))
      return { claim: `aws:${result.taskType}:${result.attribution}`, window: result.windowDays };
    if ('observations' in result) {
      // Page runs: the skill groups with at least one proven row, as 1-based catalog positions in display order.
      const rows = result.observations;
      if (!Array.isArray(rows) || !rows.length || rows.some(row => !GROUPS.includes(row?.group))) fail('aws observations');
      const positions = [...new Set(rows.map(row => GROUPS.indexOf(row.group) + 1))].sort((a, b) => a - b);
      return { claim: `aws:groups:${positions.join(',')}:${result.attribution}`, window: result.windowDays };
    }
    const acts = result.activities;
    if (!Array.isArray(acts) || acts.length < 1 || acts.length > ACTIVITIES.length ||
        acts.some((id, i) => !ACTIVITIES.includes(id) || (i && ACTIVITIES.indexOf(id) <= ACTIVITIES.indexOf(acts[i - 1])))) fail('aws activities');
    // Only the activities the bundle proved, in catalog order; when the names do not fit a claim, their skill areas.
    const claim = `aws:activity:${acts.join(',')}:${result.attribution}`;
    if (claim.length <= CLAIM_BYTES) return { claim, window: result.windowDays };
    const areas = AWS_SKILL_AREAS.map(area => area.id);
    const positions = acts.map(id => areas.indexOf(AWS_OPERATIONS.find(entry => entry.id === id).skillArea) + 1);
    return { claim: `aws:areas:${positions.join(',')}:${result.attribution}`, window: result.windowDays };
  },

  /**
   * The family names come from authenticated receipts that stay private; the public inputs prove one linked event per
   * family. So a grouped claim must list known families, in policy order, one per proven event. An areas claim lists
   * one skill area per proven event, in catalog order.
   */
  claim(bundle, { claim } = {}) {
    const count = id => bundle.proofs.filter(entry => entry.circuitId === id).length;
    const events = count('aws-event-link-v1');
    if (!events || count('aws-identity-link-v1') !== events) return null;
    const areas = /^aws:areas:([0-9,]+):iam-user$/.exec(claim ?? '')?.[1]?.split(',').map(Number);
    if (areas) {
      const ordered = areas.every((n, i) => n >= 1 && n <= AWS_SKILL_AREAS.length && (!i || n > areas[i - 1]));
      return { claim: ordered && areas.length === events ? claim : 'aws:areas:inconsistent:iam-user', window: 90 };
    }
    const families = /^aws:activity:([a-z0-9,-]+):iam-user$/.exec(claim ?? '')?.[1]?.split(',');
    if (families) {
      const ordered = families.every((id, i) => ACTIVITIES.includes(id) && (!i || ACTIVITIES.indexOf(id) > ACTIVITIES.indexOf(families[i - 1])));
      return { claim: ordered && families.length === events ? claim : 'aws:activity:inconsistent:iam-user', window: 90 };
    }
    return events === 1 ? { claim: 'aws:iam-role-trust-update:iam-user', window: 90 } : null;
  },

  describe({ claim, window }) {
    if (claim === 'aws:iam-role-trust-update:iam-user') return `AWS: an IAM user updated a role trust policy${days(window)}.`;
    const match = /^aws:(activity|areas|groups):([a-z0-9,-]+):iam-user$/.exec(claim);
    if (!match) return null;
    const items = match[2].split(',');
    const labels = match[1] === 'activity' ? items.map(id => AWS_OPERATIONS.find(entry => entry.id === id)?.label)
      : items.map(n => (match[1] === 'areas' ? AWS_SKILL_AREAS : AWS_SKILL_GROUPS)[Number(n) - 1]?.label);
    return labels.every(Boolean) ? `AWS: an IAM user's activity verified in ${labels.join(', ')}${days(window)}.` : null;
  },
});
