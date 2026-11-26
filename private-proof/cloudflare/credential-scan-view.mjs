import { authenticatedCloudflareTranscript } from './verify-bundle.mjs';

// Same names as the shared scanner's header rule in the GCP and AWS scan views.
const CREDENTIAL_NAMES = {
  sent: new Set(['authorization', 'cookie', 'proxy-authorization', 'x-amz-security-token']),
  recv: new Set(['set-cookie']),
};
const CR = 13, LF = 10, COLON = 58, SPACE = 32, TAB = 9;
const fail = () => { throw new Error('CF_PRIVATE_TRANSCRIPT_INVALID'); };

/**
 * Masks the name of each credential header whose whole value is one or more contiguous hidden ranges. The header
 * section must be authenticated end to end (Cloudflare sessions leave gaps only in the response body); a header whose
 * value is revealed even in part keeps its name, so the scanner rejects it.
 */
function credentialNameMask(direction, { bytes, privateRanges, publicRanges }) {
  const mask = new Uint8Array(bytes.length);
  const covered = new Uint8Array(bytes.length);
  for (const range of [...privateRanges, ...(publicRanges ?? [{ start: 0, end: bytes.length }])]) covered.fill(1, range.start, range.end);
  const hidden = new Uint8Array(bytes.length);
  for (const range of privateRanges) hidden.fill(1, range.start, range.end);
  const lineEnd = from => {
    for (let at = from; at + 1 < bytes.length; at++) {
      if (!covered[at] || !covered[at + 1]) fail();
      if (bytes[at] === CR && bytes[at + 1] === LF && !hidden[at]) return at;
    }
    return fail();
  };
  let at = lineEnd(0) + 2;
  for (;;) {
    const end = lineEnd(at);
    if (end === at) break;
    const colon = bytes.indexOf(COLON, at);
    if (colon > at && colon < end && !hidden.subarray(at, colon + 1).includes(1)) {
      const name = String.fromCharCode(...bytes.subarray(at, colon)).trim().toLowerCase();
      let valueStart = colon + 1;
      while (valueStart < end && !hidden[valueStart] && (bytes[valueStart] === SPACE || bytes[valueStart] === TAB)) valueStart++;
      const ranges = privateRanges.filter(range => range.start >= valueStart && range.end <= end);
      let cursor = valueStart;
      for (const range of ranges) { if (range.start !== cursor) break; cursor = range.end; }
      if (CREDENTIAL_NAMES[direction].has(name) && valueStart < end && cursor === end) mask.fill(1, at, colon);
    }
    at = end + 2;
  }
  return mask;
}

/**
 * Scanner-only view; authenticate the receipt first and never store this altered view. Unlike the AWS page view, both
 * directions are masked: every Cloudflare API response carries Set-Cookie headers whose names are public and whose
 * values stay hidden.
 */
export function cloudflareCredentialScanView(receipt, expected, now = Date.now()) {
  try {
    const directions = authenticatedCloudflareTranscript(receipt, expected, now);
    const masks = { sent: credentialNameMask('sent', directions.sent), recv: credentialNameMask('recv', directions.recv) };
    const maskText = (text, direction, start = 0) => Array.from(text, (char, offset) => masks[direction][start + offset] ? '\0' : char).join('');
    const positions = { sent: 0, recv: 0 };
    return {
      ...receipt,
      transcript: { ...receipt.transcript, sent: maskText(receipt.transcript.sent, 'sent'), recv: maskText(receipt.transcript.recv, 'recv') },
      results: receipt.results.map(result => {
        const direction = result.type.toLowerCase(), range = receipt.config[direction][positions[direction]++];
        return { ...result, value: result.action.kind === 'REVEAL' ? maskText(result.value, direction, range.start) : result.value };
      }),
    };
  } catch {
    throw new Error('CF_PRIVATE_TRANSCRIPT_INVALID');
  }
}
