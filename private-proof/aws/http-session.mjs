import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { parseHttpStructure } from '../gcp/http-structure.mjs';

const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;
const fail = () => { throw new Error('AWS_PRIVATE_HTTP_INVALID'); };
const framing = new Set(['content-length', 'transfer-encoding', 'content-encoding']);

// Shared transport inspection for the two fixed AWS steps; obligations remain unverified.
export function inspectAwsHttpSession(receipt, expected, now) {
  return inspectAwsHttpDirections(authenticatedAwsTranscript(receipt, expected, now), expected);
}

/**
 * Header policy shared by every AWS session: approved headers carry exact public values, every other header value is
 * hash-committed in full (header-v1 obligations). Framing headers are checked by the caller.
 */
export function checkAwsHeaders(message, direction, approved, required, native, obligations) {
  const obligeHeader = header => {
    let cursor = header.value.start;
    for (const range of message.privateRanges.filter(range => range.start >= cursor && range.end <= header.value.end)) {
      if (range.start !== cursor || range.end - range.start > 2048) fail();
      obligations.push({ circuitId: 'header-v1', ...native.get(key({ ...range, direction })) });
      cursor = range.end;
    }
    if (cursor !== header.value.end) fail();
  };
  const seen = new Set();
  for (const header of message.headers) {
    if (seen.has(header.name) && (direction === 'SENT' || framing.has(header.name) || approved.has(header.name))) fail();
    seen.add(header.name);
    if (framing.has(header.name)) continue;
    if (approved.has(header.name)) {
      const value = approved.get(header.name);
      if (typeof value === 'string' ? header.value.text !== value : !value.test(header.value.text ?? '')) fail();
    } else {
      if (required.includes(header.name) && header.value.start === header.value.end) fail();
      obligeHeader(header);
    }
  }
  if (required.some(name => !seen.has(name))) fail();
}

export function addAwsNativeSlots(message, direction, native) {
  for (const range of message.privateRanges) {
    const slot = { direction, start: range.start, end: range.end, hash: range.hash, length: range.end - range.start };
    native.set(key(slot), slot);
  }
}

/** The request of a session: POST / to the step's host (a page session: its Region's) with the fixed public header set. */
export function inspectAwsRequest(direction, expected, native, obligations, host = 'cloudtrail.us-east-1.amazonaws.com') {
  const sent = parseHttpStructure(direction, { kind: 'request' });
  if (sent.startLine.method !== 'POST' || sent.startLine.target.text !== '/') fail();
  addAwsNativeSlots(sent, 'SENT', native);
  const identity = expected.step === 'identity';
  const requestHeaders = new Map([
    ['host', identity ? 'iam.amazonaws.com' : host],
    ['connection', 'close'], ['accept-encoding', 'identity'], ['x-tlsn-nonce', expected.nonceMac],
    ['content-type', identity ? 'application/x-www-form-urlencoded' : 'application/x-amz-json-1.1'],
  ]);
  if (!identity) requestHeaders.set('x-amz-target', 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents');
  checkAwsHeaders(sent, 'SENT', requestHeaders, [...requestHeaders.keys(), 'content-length', 'authorization', 'x-amz-date', 'x-amz-security-token'],
    native, obligations);
  return sent;
}

/** Structural inspection for local planning; directions alone have no native provenance. */
export function inspectAwsHttpDirections(directions, expected) {
  const native = new Map(), obligations = [];
  const sent = inspectAwsRequest(directions.sent, expected, native, obligations);
  const recv = parseHttpStructure(directions.recv, { kind: 'response' });
  if (recv.startLine.status !== 200 || recv.startLine.reason.text !== 'OK') fail();
  addAwsNativeSlots(recv, 'RECV', native);
  const identity = expected.step === 'identity';
  checkAwsHeaders(recv, 'RECV', new Map([['content-type', identity ? /^text\/xml(?:; ?charset=utf-8)?$/i : 'application/x-amz-json-1.1'],
    ['connection', 'close']]), ['content-type'], native, obligations);
  return { sent, recv, native, obligations };
}
