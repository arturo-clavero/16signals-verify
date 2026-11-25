/**
 * Local reveal plan of a page session (client side). The request is covered in full (only the Username value is
 * committed), the response head in full (header values outside the public set committed), then `{"Events":[` and
 * the chain of each selected row; every other byte of the page stays an unauthenticated gap. The plan is checked by
 * the verifier's own page inspection before it is returned. Offsets and hashes are provisional.
 */
import { parseJsonStructure } from '../gcp/json-structure.mjs';
import { localHttp } from './client-plan.mjs';
import { awsPageRows, awsPageRowPieces, AWS_EVENTS_OPEN } from './page-structure.mjs';
import { inspectAwsPageDirections } from './page-session.mjs';
import { AWS_PAGE_BYTES, awsCloudTrailRegion, awsRegionHolds } from './request.mjs';
import { AWS_PAGE_STEPS } from './sessions.mjs';
import { awsCatalogOperation } from './skill-groups.mjs';

/** Rows proven per page session at most, and the verifier's reveal ceiling (AES blocks, both directions). */
export const AWS_PAGE_ROW_CAP = 21;
export const AWS_PAGE_REVEAL_BLOCKS = 2500;
const ZERO = '0'.repeat(64);
const fail = () => { throw new Error('AWS_PRIVATE_CLIENT_INVALID'); };
const decoder = new TextDecoder('utf-8', { fatal: true });

/** Distinct 16-byte blocks the ranges touch (the verifier's count). */
export function awsRevealBlocks(ranges) {
  const blocks = new Set();
  for (const { start, end } of ranges) for (let block = Math.floor(start / 16); block <= Math.floor((end - 1) / 16); block++) blocks.add(block);
  return blocks.size;
}

/**
 * `eventIds`: the rows to prove (local selection). Rows of the page that are not selected, or do not have the provable
 * layout, stay gaps; rows past AWS_PAGE_ROW_CAP or the reveal ceiling are dropped in page order.
 */
export function planAwsPageSession(meta, transcripts, eventIds) {
  const buffers = [];
  try {
    if (!meta || !AWS_PAGE_STEPS.includes(meta.step) || !/^[A-Za-z0-9_-]{43}$/.test(meta.nonceMac ?? '') ||
        !awsCloudTrailRegion(meta.serverName) || !(eventIds instanceof Set) || !eventIds.size) fail();
    const region = awsCloudTrailRegion(meta.serverName);
    const { sent: sentBytes, recv: recvBytes } = transcripts;
    if (!(recvBytes instanceof Uint8Array) || recvBytes.length < 4 || recvBytes.length > AWS_PAGE_BYTES) fail();
    const sent = localHttp(sentBytes, 'request'); buffers.push(sent.body.bytes);
    const slots = { sent: [], recv: [] }, reveals = { sent: [], recv: [] };
    const hide = (direction, start, end, attributes = {}) => slots[direction].push({ direction: direction.toUpperCase(), start, end, hash: ZERO, ...attributes });
    const hideHeader = (direction, bytes, start, end) => {
      for (let at = start; at < end; at += 2048) {
        for (const byte of bytes.subarray(at, Math.min(at + 2048, end))) if (!(byte === 9 || (byte >= 32 && byte <= 126))) fail();
        hide(direction, at, Math.min(at + 2048, end));
      }
    };
    const sentPublic = new Set(['content-length', 'content-type', 'connection', 'host', 'x-16signals-nonce', 'accept-encoding', 'x-amz-target']);
    for (const header of sent.headers) if (!sentPublic.has(header.name)) hideHeader('sent', sentBytes, header.value.start, header.value.end);
    const request = parseJsonStructure(sent.body.bytes).root;
    const value = request?.entries?.[0]?.value?.items?.[0]?.entries?.[1]?.value;
    if (value?.type !== 'string') fail();
    const endTime = request.entries.find(entry => entry.key.value === 'EndTime')?.value?.value;
    hide('sent', sent.body.wireIndices[value.start], sent.body.wireIndices[value.end - 1] + 1, { layer: 'outer', kind: 1 });

    // Response head: status line and header lines, revealed except the values of headers outside the public set.
    let bodyStart = -1;
    for (let at = 0; at + 3 < recvBytes.length && at < 16384; at++) {
      if (recvBytes[at] === 13 && recvBytes[at + 1] === 10 && recvBytes[at + 2] === 13 && recvBytes[at + 3] === 10) { bodyStart = at + 4; break; }
    }
    if (bodyStart < 0) fail();
    const head = decoder.decode(recvBytes.subarray(0, bodyStart - 4));
    let lineStart = head.indexOf('\r\n') + 2;
    for (const line of head.split('\r\n').slice(1)) {
      const colon = line.indexOf(':'), name = line.slice(0, colon).toLowerCase();
      if (colon < 1) fail();
      if (!['content-length', 'content-type', 'connection'].includes(name)) {
        let start = lineStart + colon + 1;
        while (recvBytes[start] === 32 || recvBytes[start] === 9) start++;
        if (start < lineStart + line.length) hideHeader('recv', recvBytes, start, lineStart + line.length);
      }
      lineStart += line.length + 2;
    }
    let headCursor = 0;
    for (const slot of slots.recv) { if (slot.start > headCursor) reveals.recv.push({ start: headCursor, end: slot.start }); headCursor = slot.end; }
    reveals.recv.push({ start: headCursor, end: bodyStart + AWS_EVENTS_OPEN.length });

    const body = recvBytes.subarray(bodyStart);
    const { text, rows, events } = awsPageRows(body);
    let userName, proven = 0;
    const sentBlocks = awsRevealBlocks([{ start: 0, end: sentBytes.length }]);
    for (const [index, row] of rows.entries()) {
      if (!eventIds.has(row.eventId) || proven >= AWS_PAGE_ROW_CAP) continue;
      const pieces = awsPageRowPieces(text, row.at);
      if (!pieces) continue;
      let event;
      try { event = JSON.parse(events[index].CloudTrailEvent); } catch { continue; }
      const name = event?.userIdentity?.userName;
      if (!awsCatalogOperation(event.eventSource, event.eventName) || event.awsRegion !== region ||
          !awsRegionHolds(region, event.eventSource) || typeof name !== 'string' ||
          (userName !== undefined && name !== userName)) continue;
      const wire = pieces.map(piece => ({ ...piece, start: piece.start + bodyStart, end: piece.end + bodyStart }));
      if (sentBlocks + awsRevealBlocks([...reveals.recv, ...slots.recv, ...wire]) > AWS_PAGE_REVEAL_BLOCKS) break;
      userName = name; proven++;
      for (const piece of wire) {
        if (piece.type === 'R') reveals.recv.push({ start: piece.start, end: piece.end });
        else if (!piece.host) hide('recv', piece.start, piece.end);
        else {
          // The host header becomes an escaped-atom claim: the wire \"host\" decodes to the JSON string "host".
          const encoded = decoder.decode(recvBytes.subarray(piece.start, piece.end));
          hide('recv', piece.start, piece.end, { layer: 'event', kind: 1, decodedHash: ZERO,
            decodedLength: new TextEncoder().encode(JSON.parse(`"${encoded}"`)).length });
        }
      }
    }
    if (!proven) fail();

    const selections = {}, directions = {}, claims = [];
    for (const direction of ['sent', 'recv']) {
      const source = direction === 'sent' ? sentBytes : recvBytes, bytes = new Uint8Array(source.length); buffers.push(bytes);
      const held = slots[direction].sort((a, b) => a.start - b.start);
      const ranges = [];
      const add = (start, end, action) => ranges.push({ start, end, handler: { type: direction.toUpperCase(), part: 'BODY', action } });
      if (direction === 'sent') {
        let cursor = 0;
        for (const slot of held) {
          if (slot.start < cursor) fail();
          if (slot.start > cursor) { add(cursor, slot.start, { kind: 'REVEAL' }); bytes.set(source.subarray(cursor, slot.start), cursor); }
          add(slot.start, slot.end, { kind: 'HASH', algorithm: 'SHA256' }); cursor = slot.end;
        }
        if (cursor < source.length) { add(cursor, source.length, { kind: 'REVEAL' }); bytes.set(source.subarray(cursor), cursor); }
      } else {
        const all = [...reveals.recv.map(range => ({ ...range, reveal: true })), ...held].sort((a, b) => a.start - b.start);
        let cursor = 0;
        for (const range of all) {
          if (range.start < cursor) fail();
          if (range.reveal) { add(range.start, range.end, { kind: 'REVEAL' }); bytes.set(source.subarray(range.start, range.end), range.start); }
          else add(range.start, range.end, { kind: 'HASH', algorithm: 'SHA256' });
          cursor = range.end;
        }
      }
      for (const slot of held) if (slot.layer) claims.push({ ...slot });
      if (ranges.length > (direction === 'sent' ? 256 : 512)) fail();
      selections[direction] = ranges;
      directions[direction] = { bytes, privateRanges: held, ...(direction === 'recv' ? { publicRanges: reveals.recv.map(range => ({ ...range })).sort((a, b) => a.start - b.start) } : {}) };
    }
    // The verifier's checks on what it will see; the window check uses the request's own EndTime as the cutoff.
    inspectAwsPageDirections(directions, { step: meta.step, nonceMac: meta.nonceMac, issuedAt: endTime * 1000 + 999 }, claims, userName.length, region);
    return { plan: { sentRangesWithHandlers: selections.sent, recvRangesWithHandlers: selections.recv }, privateSlots: slots, publicRanges: directions.recv.publicRanges };
  } catch { fail(); }
  finally { for (const bytes of buffers) bytes.fill(0); }
}
