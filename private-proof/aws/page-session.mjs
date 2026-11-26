/**
 * Inspection of a page session: one LookupEvents request by Username and a StartTime/EndTime window, and its response
 * page, of which only the proven rows are authenticated (page-structure.mjs). Every header byte and the whole request
 * stay covered; gaps are allowed only in the response body outside the row chains.
 *
 * Returns the rows (operation, UTC day, the three committed pieces the batch circuit opens), the window and the
 * obligations of every other committed slot (header values, the Username value). Nothing here accepts a claim: the
 * caller verifies the obligations and the batch proofs.
 */
import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { addAwsNativeSlots, checkAwsHeaders, inspectAwsRequest } from './http-session.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { matchAwsPageRows } from './page-structure.mjs';
import { AWS_PAGE_STEPS } from './sessions.mjs';
import { AWS_LIMITS, AWS_REGION, awsCloudTrailHost, awsCloudTrailRegion } from './request.mjs';

/** Rows proven per page session at most; a page with more fails before any proof is checked. */
export const AWS_PAGE_ROW_CAP = 21;

const fail = () => { throw new Error('AWS_PRIVATE_PAGE_INVALID'); };
const key = slot => `${slot.direction}:${slot.start}:${slot.end}:${slot.hash}`;
const DAY = 86400;
const latin1 = bytes => { let text = ''; for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192)); return text; };

/** Response head over authenticated bytes: status line, headers, CRLF; every byte revealed or committed. */
function responseHead({ bytes, privateRanges, publicRanges }) {
  const owner = new Int32Array(bytes.length).fill(-1);
  privateRanges.forEach((range, index) => owner.fill(index, range.start, range.end));
  const revealed = new Uint8Array(bytes.length);
  for (const range of publicRanges) revealed.fill(1, range.start, range.end);
  const text = (start, end) => {
    for (let at = start; at < end; at++) if (!revealed[at]) fail();
    return latin1(bytes.subarray(start, end));
  };
  const lineEnd = start => {
    for (let at = start; at < bytes.length - 1; at++) {
      if (owner[at] >= 0) { at = privateRanges[owner[at]].end - 1; continue; }
      if (!revealed[at]) fail();
      if (bytes[at] === 13) { if (text(at, at + 2) !== '\r\n') fail(); return at; }
      if (bytes[at] === 10) fail();
    }
    fail();
  };
  if (text(0, 17) !== 'HTTP/1.1 200 OK\r\n') fail();
  const headers = [], used = new Set();
  let position = 17;
  for (;;) {
    const end = lineEnd(position);
    if (end === position) { position += 2; break; }
    if (headers.length >= 64) fail();
    const colon = bytes.indexOf(58, position);
    if (colon <= position || colon >= end || !revealed[colon]) fail();
    const name = text(position, colon);
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) fail();
    let start = colon + 1;
    while (start < end && revealed[start] && (bytes[start] === 32 || bytes[start] === 9)) start++;
    const inside = privateRanges.filter(range => range.start < end && range.end > position);
    if (inside.some(range => range.start < start || range.end > end)) fail();
    inside.forEach(range => used.add(range));
    let valueEnd = end;
    if (!inside.length) while (valueEnd > start && (bytes[valueEnd - 1] === 32 || bytes[valueEnd - 1] === 9)) valueEnd--;
    headers.push({ name: name.toLowerCase(), value: { start, end: valueEnd, ...(inside.length ? {} : { text: text(start, valueEnd) }) } });
    position = end + 2;
  }
  const headPrivate = privateRanges.filter(range => range.start < position);
  if (headPrivate.some(range => !used.has(range))) fail();
  return { headers, privateRanges: headPrivate, bodyStart: position };
}

/** Authenticated body pieces, body-relative: maximal revealed runs (with text) and committed slots. */
function bodyPieces({ bytes, privateRanges, publicRanges }, bodyStart) {
  const pieces = [];
  for (const range of publicRanges) {
    const start = Math.max(range.start, bodyStart);
    if (start >= range.end) continue;
    const last = pieces.at(-1);
    if (last && last.end === start - bodyStart) last.end = range.end - bodyStart;
    else pieces.push({ type: 'R', start: start - bodyStart, end: range.end - bodyStart });
  }
  for (const range of privateRanges) {
    if (range.start < bodyStart) continue;
    pieces.push({ type: 'H', start: range.start - bodyStart, end: range.end - bodyStart, hash: range.hash, wireStart: range.start });
  }
  pieces.sort((a, b) => a.start - b.start);
  for (const piece of pieces) if (piece.type === 'R') piece.text = latin1(bytes.subarray(piece.start + bodyStart, piece.end + bodyStart));
  return pieces;
}

const child = (node, name) => node?.entries?.find(entry => entry.key.value === name)?.value;
const integer = node => (node?.type === 'number' && node.privateSlot === undefined && /^(0|[1-9][0-9]{0,11})$/.test(node.raw) ? Number(node.raw) : fail());

function inspectPage(directions, expected, atomClaims, userNameLength, region) {
  if (!AWS_PAGE_STEPS.includes(expected?.step) || !Array.isArray(atomClaims) || atomClaims.length > 64 ||
      !Array.isArray(directions.recv?.publicRanges)) fail();
  const native = new Map(), obligations = [];
  const sent = inspectAwsRequest(directions.sent, expected, native, obligations, awsCloudTrailHost(region));
  const head = responseHead(directions.recv);
  addAwsNativeSlots(directions.recv, 'RECV', native);
  checkAwsHeaders(head, 'RECV', new Map([['content-type', 'application/x-amz-json-1.1'], ['connection', 'close']]),
    ['content-type', 'connection'], native, obligations);
  // Content-Length framing only: no chunked body (it could split a row) and no content coding.
  const length = head.headers.filter(header => header.name === 'content-length');
  if (length.length !== 1 || !/^[0-9]{1,7}$/.test(length[0].value.text ?? '') ||
      Number(length[0].value.text) !== directions.recv.bytes.length - head.bodyStart ||
      head.headers.some(header => header.name === 'transfer-encoding' || header.name === 'content-encoding')) fail();

  // Request: {"LookupAttributes":[{"AttributeKey":"Username","AttributeValue":<committed>}],"StartTime":s,"EndTime":e,"MaxResults":n}
  const claims = new Map(atomClaims.map(claim => [key(claim), claim])), used = new Set();
  if (claims.size !== atomClaims.length) fail();
  const requestSlots = sent.body.privateRanges.map(range => {
    const slot = native.get(key({ direction: 'SENT', start: range.wireStart, end: range.wireEnd, hash: range.hash }));
    const claim = claims.get(key(slot ?? {}));
    if (!claim || claim.layer !== 'outer' || claim.kind !== 1 || slot.length > 66 ||
        Reflect.ownKeys(claim).length !== 6) fail();
    used.add(claim);
    obligations.push({ circuitId: 'atom-v1', ...slot, kind: 1 });
    return { layer: 'outer', start: range.start, end: range.end, hash: range.hash, kind: 1 };
  });
  const request = parseJsonStructure(sent.body.bytes, requestSlots);
  const params = request.root;
  if (params?.type !== 'object' || params.hasPrivateKeys || params.entries.map(entry => entry.key.value).join() !==
      'LookupAttributes,StartTime,EndTime,MaxResults' || request.slots.length !== 1) fail();
  const attributes = child(params, 'LookupAttributes');
  const attribute = attributes?.type === 'array' && attributes.items.length === 1 ? attributes.items[0] : fail();
  if (attribute?.type !== 'object' || attribute.hasPrivateKeys || attribute.entries.map(entry => entry.key.value).join() !== 'AttributeKey,AttributeValue' ||
      child(attribute, 'AttributeKey')?.privateSlot !== undefined || child(attribute, 'AttributeKey')?.value !== 'Username' ||
      child(attribute, 'AttributeValue')?.privateSlot === undefined) fail();
  const start = integer(child(params, 'StartTime')), end = integer(child(params, 'EndTime')), max = integer(child(params, 'MaxResults'));
  const issued = Math.floor(expected.issuedAt / 1000);
  if (max < 1 || max > AWS_LIMITS.pageSize || start > end || end > issued || start < issued - 90 * DAY) fail();

  const rows = matchAwsPageRows(bodyPieces(directions.recv, head.bodyStart), { userNameLength, region });
  if (!rows.length || rows.length > max || rows.length > AWS_PAGE_ROW_CAP) fail();
  const slot = piece => native.get(key({ direction: 'RECV', start: piece.wireStart, end: piece.wireStart + piece.end - piece.start, hash: piece.hash })) ?? fail();
  const proven = rows.map(row => {
    if (row.day < Math.floor(start / DAY) || row.day > Math.floor(end / DAY)) fail();
    const { actor, body, recipient, host, ...rest } = row;
    if (host) {
      // The client host header: one escaped JSON string (escaped-atom proof), never revealed.
      const hostSlot = slot(host), claim = claims.get(key(hostSlot));
      if (!claim || claim.layer !== 'event' || claim.kind !== 1 || Reflect.ownKeys(claim).length !== 8 ||
          !/^[0-9a-f]{64}$/.test(claim.decodedHash) || !Number.isInteger(claim.decodedLength) || claim.decodedLength < 3 ||
          claim.decodedLength > hostSlot.length) fail();
      used.add(claim);
      obligations.push({ circuitId: 'aws-escaped-atom-v1', ...hostSlot, kind: 1, decodedHash: claim.decodedHash, decodedLength: claim.decodedLength });
    }
    return { ...rest, actor: slot(actor), body: slot(body), recipient: slot(recipient) };
  });
  if (used.size !== claims.size) fail();
  if (obligations.length + 3 * proven.length !== native.size ||
      new Set([...obligations, ...proven.flatMap(row => [row.actor, row.body, row.recipient])].map(key)).size !== native.size) fail();
  return { region, window: { start, end }, rows: proven, obligations };
}

/**
 * Authenticated page receipt. `userNameLength` is the identity session's committed IAM user name length. The Region is
 * the one of the CloudTrail host the session reached; every proven row must name it.
 */
export function inspectAwsPageSession(receipt, expected, atomClaims, userNameLength, now = Date.now()) {
  try {
    const directions = authenticatedAwsTranscript(receipt, expected, now);
    return inspectPage(directions, expected, atomClaims, userNameLength, awsCloudTrailRegion(receipt.server_name) ?? fail());
  }
  catch { fail(); }
}

/**
 * True when two inspected pages of the same Region have overlapping windows. Disjoint windows per Region mean a row
 * (one event, recorded in one Region, one eventTime) is proven in one session only.
 */
export function awsPageWindowsOverlap(pages) {
  const windows = pages.map(page => ({ region: page.region, ...page.window }))
    .sort((a, b) => (a.region < b.region ? -1 : a.region > b.region ? 1 : a.start - b.start));
  return windows.some((window, index) => index && window.region === windows[index - 1].region && window.start <= windows[index - 1].end);
}

/** Local grammar checks only (the planner's self-check); never a substitute for authenticated receipt ingestion. */
export function inspectAwsPageDirections(directions, expected, atomClaims, userNameLength, region = AWS_REGION) {
  try { return inspectPage(directions, expected, atomClaims, userNameLength, region); }
  catch { fail(); }
}
