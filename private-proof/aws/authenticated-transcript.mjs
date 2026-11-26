import { authenticatedTranscriptRanges } from '../gcp/authenticated-transcript.mjs';
import { AWS_PAGE_STEPS, AWS_SESSION_STEPS } from './sessions.mjs';
import { AWS_PAGE_BYTES, awsCloudTrailRegion } from './request.mjs';

/** A page session's response may hold unauthenticated gaps (the rows and fields it does not prove). */
export const AWS_PAGE_TRANSCRIPT = Object.freeze({ maxLength: AWS_PAGE_BYTES, maxRanges: 512, gaps: Object.freeze(['recv']) });

const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = () => { throw new Error('AWS_PRIVATE_TRANSCRIPT_INVALID'); };

/**
 * The server a session must have reached: IAM for the identity, CloudTrail in us-east-1 for a single event, and
 * CloudTrail in any allowed Region for a page (`serverName` names which; the row layout then binds every row to it).
 */
export function awsSessionHost(step, serverName) {
  if (step === 'identity') return 'iam.amazonaws.com';
  if (AWS_PAGE_STEPS.includes(step) && awsCloudTrailRegion(serverName)) return serverName;
  return 'cloudtrail.us-east-1.amazonaws.com';
}

/** Context validation only; this does not authenticate an attempt or receipt. */
export function validateAwsAttempt(expected, now = Date.now()) {
  if (!record(expected) || !uuid(expected.proofId) ||
      typeof expected.pluginSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expected.pluginSha256) ||
      typeof expected.nonceMac !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(expected.nonceMac) ||
      expected.identityService !== 'iam' || expected.region !== 'us-east-1' ||
      !Number.isSafeInteger(now) || !Number.isSafeInteger(expected.issuedAt) || !Number.isSafeInteger(expected.expiresAt) ||
      expected.issuedAt < 0 || expected.issuedAt > now || expected.expiresAt <= now ||
      expected.expiresAt - expected.issuedAt > 15 * 60 * 1000) fail();
}

/**
 * expected is trusted server attempt state, never client input. Call only after
 * authenticating native receipt delivery and candidate ownership. The caller must
 * still enforce an atomic replay/consumption ledger; IDs and expiry alone cannot.
 * Only the private AWS_ACCOUNT method is accepted; a plaintext method cannot be promoted.
 */
export function authenticatedAwsTranscript(receipt, expected, now = Date.now()) {
  try {
    validateAwsAttempt(expected, now);
    if (!record(receipt) || !record(receipt.session) || receipt.failure !== undefined ||
        !uuid(expected.sessionId) || !(AWS_SESSION_STEPS.includes(expected.step) || AWS_PAGE_STEPS.includes(expected.step))) fail();
    const session = receipt.session;
    if (session.id !== expected.sessionId || session.proofId !== expected.proofId ||
        session.pluginSha256 !== expected.pluginSha256 || session.nonceMac !== expected.nonceMac ||
        session.step !== expected.step || session.method !== 'AWS_ACCOUNT' || session.mode !== 'Proxy' ||
        receipt.server_name !== awsSessionHost(expected.step, receipt.server_name)) fail();
    return authenticatedTranscriptRanges(receipt, AWS_PAGE_STEPS.includes(expected.step) ? AWS_PAGE_TRANSCRIPT : undefined);
  } catch { throw new Error('AWS_PRIVATE_TRANSCRIPT_INVALID'); }
}
