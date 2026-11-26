import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { privateCredentialScanView } from '../gcp/credential-scan-view.mjs';
import { AWS_PAGE_STEPS } from './sessions.mjs';

/**
 * Scanner-only view; authenticate the receipt first and never store this altered view. A page response is larger than
 * the HTTP framing parser accepts and holds unauthenticated gaps, so it is scanned as revealed, without masking.
 */
export function awsCredentialScanView(receipt, expected, now = Date.now()) {
  try {
    return privateCredentialScanView(receipt, authenticatedAwsTranscript(receipt, expected, now), false,
      AWS_PAGE_STEPS.includes(expected.step) ? ['recv'] : []);
  } catch {
    throw new Error('AWS_PRIVATE_TRANSCRIPT_INVALID');
  }
}
