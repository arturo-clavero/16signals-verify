// What the demo needs per provider: the built-in plugin and its params, the attempt fields the provider's bundle
// verifier checks every session against, the verifier call, and the pinned proof runtime (loaded on first use).
import { readFile } from 'node:fs/promises';
import gcp from '../../private-proof/gcp/descriptor.mjs';
import aws from '../../private-proof/aws/descriptor.mjs';
import cloudflare from '../../private-proof/cloudflare/descriptor.mjs';
import { CATALOG_DIGEST } from '../../private-proof/gcp/policy.mjs';
import { verifyBundle as verifyGcpBundle } from '../../private-proof/gcp/verify-bundle.mjs';
import { verifyAwsBundle } from '../../private-proof/aws/verify-bundle.mjs';
import { verifyCloudflareBundle } from '../../private-proof/cloudflare/verify-bundle.mjs';

const ROOT = new URL('../../private-proof/', import.meta.url);
const reader = dir => file => readFile(new URL(`${dir}/${file}`, ROOT));
const ATTEMPT_MS = 15 * 60 * 1000;

/** The pinned circuits and keys a provider's `npm run build:fork` left in private-proof/<provider>/dist. */
async function gcpRuntime() {
  const [{ loadPinnedArtifacts }, { loadPinnedVerificationKeys, pinnedVerificationKey }, { createProofRuntime }] = await Promise.all([
    import('../../private-proof/gcp/artifact-registry.mjs'), import('../../private-proof/gcp/verification-key-registry.mjs'),
    import('../../private-proof/gcp/proof-runtime.mjs')]);
  const keys = await loadPinnedVerificationKeys(reader('gcp/dist/verification-keys'));
  return { runtime: await createProofRuntime(await loadPinnedArtifacts(reader('gcp/dist/artifacts')), keys), vk: id => pinnedVerificationKey(keys, id) };
}
async function awsRuntime() {
  const [{ loadAwsArtifacts, loadAwsVerificationKeys, pinnedAwsKey }, { createAwsProofRuntime }] = await Promise.all([
    import('../../private-proof/aws/artifact-registry.mjs'), import('../../private-proof/aws/proof-runtime.mjs')]);
  const load = reader('aws/dist/artifacts');
  const keys = await loadAwsVerificationKeys(load);
  return { runtime: await createAwsProofRuntime(await loadAwsArtifacts(load), keys), vk: id => pinnedAwsKey(keys, id) };
}
async function cloudflareRuntime() {
  const [{ loadCloudflareArtifacts, loadCloudflareVerificationKeys, pinnedCloudflareKey }, { createCloudflareProofRuntime }] = await Promise.all([
    import('../../private-proof/cloudflare/artifact-registry.mjs'), import('../../private-proof/cloudflare/proof-runtime.mjs')]);
  const load = reader('cloudflare/dist/artifacts');
  const keys = await loadCloudflareVerificationKeys(load);
  return { runtime: await createCloudflareProofRuntime(await loadCloudflareArtifacts(load), keys), vk: id => pinnedCloudflareKey(keys, id) };
}

/**
 * Per provider:
 *   start({ now, windowDays }) -> { context, params(attempt) }: `context` joins every session's `expected` (with
 *     sessionId, proofId, pluginSha256, nonceMac, step); `params` is what the plugin reads as `__PLUGIN_PARAMS__`.
 *   verify({ sessions, bundle, attempt, runtime, now }) -> the provider verifier's result (throws when it refuses).
 */
export const PROVIDERS = Object.freeze({
  gcp: {
    label: 'Google Cloud', pluginId: 'gcp-work', method: 'GCP_WORK', descriptor: gcp, loadRuntime: gcpRuntime,
    start({ now, windowDays = 30 }) {
      if (![7, 30, 90].includes(windowDays)) throw new Error('windowDays must be 7, 30 or 90');
      const policy = { windowDays, cutoff: now };
      // The page adds `privateInput: { projectId }`: the project id stays in the browser.
      return { policy, context: {}, params: a => ({ ...policy, catalogDigest: CATALOG_DIGEST, proofId: a.proofId, nonceMac: a.nonceMac }) };
    },
    verify: ({ sessions, bundle, attempt, runtime }) => verifyGcpBundle({ sessions, policy: attempt.policy, bundle, runtime }),
  },
  aws: {
    label: 'AWS', pluginId: 'aws-private-work', method: 'AWS_ACCOUNT', descriptor: aws, loadRuntime: awsRuntime,
    start({ now }) {
      const context = { issuedAt: now, expiresAt: now + ATTEMPT_MS, identityService: 'iam', region: 'us-east-1' };
      return { context, params: a => ({ privateAttempt: { ...context, proofId: a.proofId, pluginSha256: a.pluginSha256, nonceMac: a.nonceMac } }) };
    },
    verify: ({ sessions, bundle, runtime, now }) => verifyAwsBundle({ sessions, bundle, runtime, now }),
  },
  cloudflare: {
    label: 'Cloudflare', pluginId: 'cloudflare-private-work', method: 'CLOUDFLARE_ACCOUNT', descriptor: cloudflare, loadRuntime: cloudflareRuntime,
    start({ now }) {
      const context = { issuedAt: now, expiresAt: now + ATTEMPT_MS };
      return { context, params: a => ({ privateAttempt: { ...context, proofId: a.proofId, pluginSha256: a.pluginSha256, nonceMac: a.nonceMac } }) };
    },
    verify: ({ sessions, bundle, runtime, now }) => verifyCloudflareBundle({ sessions, bundle, runtime, now }),
  },
});
