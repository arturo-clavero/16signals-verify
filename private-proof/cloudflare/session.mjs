/**
 * One Cloudflare TLSNotary session: what the prover reveals (planCloudflareSession) and what the verifier reads from
 * the authenticated transcript (inspectCloudflareSession). Both sides use the same rules, so a plan the prover makes is
 * exactly what the verifier accepts.
 *
 * Request (sent, every byte revealed or hidden, no gaps):
 *   identity  GET /client/v4/user HTTP/1.1
 *   page      GET /client/v4/accounts/<hidden 32>/logs/audit?<hidden query> HTTP/1.1
 *   Header values: public when listed in CF_REQUEST_HEADERS with that exact value, otherwise hidden (header-v1).
 *   Authorization is required and always hidden.
 * Response (recv, gaps allowed in the body only): status line `HTTP/1.1 200 OK` public; header names public; values
 *   public when CF_RESPONSE_HEADERS accepts them, otherwise hidden (header-v1); framing headers public. Chunk-size
 *   lines and chunk CRLFs public, so the verifier can map wire bytes to body bytes.
 *   identity body: `{"result":{"id":` public, then the id (one hidden JSON value), the rest is a gap.
 *   page body:     `{"errors":[],"result":[` public, then every row up to the last selected one, each inside one
 *                  chunk: selected rows as rowPieces (row-structure.mjs), the others as one hidden JSON value, the
 *                  commas between rows public. Only the bytes after the last selected row are a gap, so a revealed
 *                  row is always a top-level element of the result array (never JSON nested inside another row).
 *
 * Obligations (each hidden piece must be proven by a circuit before anything counts):
 *   { hash, length, need } with need 'header' (ASCII, no CR/LF), 'value' (one JSON value), 'tail' (JSON string
 *   tail), 'actor' (one JSON value, byte-equal to the identity id).
 */
import { CF_ID, CF_PAGE_INFIX, CF_PAGE_LIMIT_MAX, CF_PAGE_PREFIX, CF_REQUEST_HEADERS, CF_RESPONSE_HEADERS, CF_USER_PATH } from './request.mjs';
import { parseHttpResponse, transcriptRange } from './http-chunked.mjs';
import { readRow, rowPieces } from './row-structure.mjs';

const fail = what => { throw new Error(`CF_SESSION_INVALID:${what}`); };
export const CF_IDENTITY_PREFIX = '{"result":{"id":';
export const CF_PAGE_BODY_PREFIX = '{"errors":[],"result":[';
export const CF_PAGE_ROW_CAP = 12;
/** A row left out of the proof is one hidden JSON value, at most the widest piece circuit's size. */
export const CF_SKIPPED_ROW_MAX = 4096;
export const CF_MAX_RANGES = 512;
const HEADER_LIMIT = 2048;
const latin = bytes => String.fromCharCode(...bytes);
const isStep = step => step === 'identity' || /^P[0-2]$/.test(step);

// ---------------------------------------------------------------------------------------------------------------
// Prover side

/** Splits a header section [start, end) into reveal/hide ranges by the header policy; returns ranges. */
function headerRanges(bytes, headStart, headEnd, approved, alwaysHidden, part) {
  const ranges = [];
  let at = headStart;
  while (at < headEnd) {
    let e = at;
    while (!(bytes[e] === 13 && bytes[e + 1] === 10)) { e++; if (e >= headEnd) fail('header-line'); }
    if (e === at) { ranges.push({ start: at, end: at + 2, hide: false, part }); at += 2; break; }
    const line = latin(bytes.subarray(at, e)), colon = line.indexOf(':');
    if (colon <= 0) fail('header-name');
    const name = line.slice(0, colon).toLowerCase();
    let valueStart = at + colon + 1;
    while (bytes[valueStart] === 32 || bytes[valueStart] === 9) valueStart++;
    const value = latin(bytes.subarray(valueStart, e)), rule = approved.get(name);
    const publicValue = !alwaysHidden.includes(name) && rule !== undefined && (typeof rule === 'string' ? value === rule : rule.test(value));
    if (publicValue || valueStart === e) ranges.push({ start: at, end: e + 2, hide: false, part });
    else {
      if (e - valueStart > HEADER_LIMIT) fail('header-size');
      ranges.push({ start: at, end: valueStart, hide: false, part }, { start: valueStart, end: e, hide: true, part, need: 'header' },
        { start: e, end: e + 2, hide: false, part });
    }
    at = e + 2;
  }
  return { ranges, end: at };
}

function requestRanges(sent, step) {
  const lineEnd = sent.indexOf(13);
  if (lineEnd < 0 || sent[lineEnd + 1] !== 10) fail('request-line');
  const line = latin(sent.subarray(0, lineEnd));
  const ranges = [];
  if (step === 'identity') {
    if (line !== `GET ${CF_USER_PATH} HTTP/1.1`) fail('request-line');
    ranges.push({ start: 0, end: lineEnd + 2, hide: false, part: 'START_LINE' });
  } else {
    const m = new RegExp(`^GET ${CF_PAGE_PREFIX.replaceAll('/', '\\/')}([0-9a-f]{32})${CF_PAGE_INFIX.replace('?', '\\?').replaceAll('/', '\\/')}(\\S+) HTTP\\/1\\.1$`).exec(line);
    if (!m) fail('request-line');
    const idStart = 4 + CF_PAGE_PREFIX.length, queryStart = idStart + 32 + CF_PAGE_INFIX.length, queryEnd = queryStart + m[2].length;
    ranges.push({ start: 0, end: idStart, hide: false, part: 'START_LINE' }, { start: idStart, end: idStart + 32, hide: true, part: 'START_LINE', need: 'header' },
      { start: idStart + 32, end: queryStart, hide: false, part: 'START_LINE' }, { start: queryStart, end: queryEnd, hide: true, part: 'START_LINE', need: 'header' },
      { start: queryEnd, end: lineEnd + 2, hide: false, part: 'START_LINE' });
  }
  const head = headerRanges(sent, lineEnd + 2, sent.length, CF_REQUEST_HEADERS, ['authorization'], 'HEADERS');
  if (head.end !== sent.length) fail('request-body');
  return [...ranges, ...head.ranges];
}

function responseRanges(recv, step, selectedRows) {
  const response = parseHttpResponse(recv);
  if (response.status !== 200) fail('status');
  const statusEnd = recv.indexOf(13) + 2;
  const ranges = [{ start: 0, end: statusEnd, hide: false, part: 'START_LINE' }];
  ranges.push(...headerRanges(recv, statusEnd, response.headEnd, CF_RESPONSE_HEADERS, [], 'HEADERS').ranges);
  // Chunk framing: every size line and chunk CRLF public.
  if (response.headers['transfer-encoding']) {
    let at = response.headEnd;
    for (const chunk of response.chunks) { ranges.push({ start: at, end: chunk.start, hide: false, part: 'BODY' }); at = chunk.end; }
    ranges.push({ start: at, end: recv.length, hide: false, part: 'BODY' });
  }
  const body = new TextDecoder().decode(response.body);
  const map = (bodyStart, bodyEnd) => transcriptRange(response.chunks, bodyStart, bodyEnd);
  const add = (bodyStart, bodyEnd, hide, need) => {
    const r = map(bodyStart, bodyEnd);
    if (!r) fail('crosses-chunk');
    ranges.push({ start: r[0], end: r[1], hide, part: 'BODY', ...(need ? { need } : {}) });
  };
  const rows = [];
  if (step === 'identity') {
    if (!body.startsWith(CF_IDENTITY_PREFIX) || body.slice(CF_IDENTITY_PREFIX.length, CF_IDENTITY_PREFIX.length + 34).search(/^"[0-9a-f]{32}"$/) !== 0) fail('identity-body');
    add(0, CF_IDENTITY_PREFIX.length, false);
    add(CF_IDENTITY_PREFIX.length, CF_IDENTITY_PREFIX.length + 34, true, 'identity');
  } else {
    if (!body.startsWith(CF_PAGE_BODY_PREFIX) || body.length !== response.body.length) fail('page-body');
    add(0, CF_PAGE_BODY_PREFIX.length, false);
    const spans = cloudflarePageRows(body);
    if (selectedRows.length > CF_PAGE_ROW_CAP || new Set(selectedRows).size !== selectedRows.length) fail('row-cap');
    // Every row up to the last selected one is covered: selected rows as rowPieces, the others as one hidden JSON
    // value, the commas between them public. Only the bytes after the last selected row stay a gap.
    const selected = new Set(selectedRows), last = Math.max(-1, ...selectedRows);
    let at = CF_PAGE_BODY_PREFIX.length;
    for (let index = 0; index <= last; index++) {
      const span = spans[index];
      if (!span || !map(span.start, span.end)) fail(`row:${index}`);
      if (span.start > at) add(at, span.start, false);
      if (selected.has(index)) {
        for (const piece of rowPieces(body.slice(span.start, span.end))) {
          const need = piece.kind === 'R' ? undefined : piece.kind === 'A' ? 'actor' : piece.kind === 'T' ? 'tail' : 'value';
          add(span.start + piece.start, span.start + piece.end, piece.kind !== 'R', need);
        }
        rows.push(index);
      } else {
        if (span.end - span.start > CF_SKIPPED_ROW_MAX) fail(`row:${index}`);
        add(span.start, span.end, true, 'value');
      }
      at = span.end;
    }
  }
  return { ranges, rows };
}

/** Row byte spans in a page body (compact JSON as served), in order. */
export function cloudflarePageRows(body) {
  const parsed = JSON.parse(body);
  if (!Array.isArray(parsed?.result)) fail('page-json');
  const spans = [];
  let from = CF_PAGE_BODY_PREFIX.length;
  for (const row of parsed.result) {
    const text = JSON.stringify(row), start = body.indexOf(text, from);
    // A row whose bytes are not exactly JSON.stringify(row) (other escaping) is skipped, not guessed.
    if (start !== from) { spans.push(null); from = skipToNextRow(body, from); continue; }
    spans.push({ start, end: start + text.length }); from = start + text.length + 1;
  }
  return spans;
}
function skipToNextRow(body, from) {
  let depth = 0, inString = false, escaped = false;
  for (let i = from; i < body.length; i++) {
    const c = body[i];
    if (inString) { if (escaped) escaped = false; else if (c === '\\') escaped = true; else if (c === '"') inString = false; continue; }
    if (c === '"') inString = true; else if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') { depth--; if (depth === 0) return i + 2; }
  }
  return body.length;
}

function mergeAndHandlers(ranges, type) {
  const sorted = [...ranges].filter(r => r.end > r.start).sort((a, b) => a.start - b.start);
  const merged = [];
  for (const r of sorted) {
    const last = merged.at(-1);
    if (last && last.end > r.start) fail('overlap');
    if (last && !last.hide && !r.hide && last.end === r.start && last.part === r.part) last.end = r.end;
    else merged.push({ ...r });
  }
  if (merged.length > CF_MAX_RANGES) fail('range-cap');
  return merged.map(r => ({ start: r.start, end: r.end,
    handler: { type, part: r.part, action: r.hide ? { kind: 'HASH', algorithm: 'SHA256' } : { kind: 'REVEAL' } } }));
}

/**
 * Prover: the reveal plan for one session. `sent`/`recv` are the full transcript bytes; `rows` lists the indexes of
 * the page rows to prove (ignored for identity). Returns { sentRangesWithHandlers, recvRangesWithHandlers, rows }.
 */
export function planCloudflareSession(step, sent, recv, rows = []) {
  if (!isStep(step) || !(sent instanceof Uint8Array) || !(recv instanceof Uint8Array)) fail('input');
  const sentRanges = requestRanges(sent, step);
  const response = responseRanges(recv, step, step === 'identity' ? [] : rows);
  const plan = { sentRangesWithHandlers: mergeAndHandlers(sentRanges, 'SENT'), recvRangesWithHandlers: mergeAndHandlers(response.ranges, 'RECV'), rows: response.rows };
  // The prover checks its own plan the way the verifier will.
  inspectCloudflareSession(planView(sent, recv, plan), step);
  return plan;
}

/** What the verifier will see for a plan (hidden bytes zeroed, fake hashes), for self-checks and tests. */
const randomHash = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
export function planView(sent, recv, plan, hashOf = randomHash) {
  const view = (bytes, ranges, direction) => {
    const out = new Uint8Array(bytes.length), privateRanges = [], publicRanges = [];
    for (const r of ranges) {
      if (r.handler.action.kind === 'REVEAL') { out.set(bytes.subarray(r.start, r.end), r.start); publicRanges.push({ start: r.start, end: r.end }); }
      else privateRanges.push({ start: r.start, end: r.end, hash: hashOf(direction, r) });
    }
    return { bytes: out, privateRanges, publicRanges };
  };
  return { sent: view(sent, plan.sentRangesWithHandlers, 'sent'), recv: view(recv, plan.recvRangesWithHandlers, 'recv') };
}

// ---------------------------------------------------------------------------------------------------------------
// Verifier side

function coverage(direction) {
  // Without publicRanges the direction has no gaps (authenticatedTranscriptRanges checked full coverage).
  const { bytes, privateRanges, publicRanges } = direction;
  const owner = new Int32Array(bytes.length).fill(publicRanges ? -2 : -1); // -2 gap, -1 public, >=0 private index
  for (const r of publicRanges ?? []) for (let i = r.start; i < r.end; i++) { if (owner[i] !== -2) fail('overlap'); owner[i] = -1; }
  privateRanges.forEach((r, index) => { for (let i = r.start; i < r.end; i++) { if (owner[i] >= 0 || (publicRanges && owner[i] !== -2)) fail('overlap'); owner[i] = index; } });
  const text = (start, end) => {
    for (let i = start; i < end; i++) if (owner[i] !== -1) fail(`not-public@${i}`);
    return latin(bytes.subarray(start, end));
  };
  // A line [start, CRLF) whose CRLF is public; returns its end (index of CR).
  const lineEnd = start => {
    for (let i = start; i < bytes.length; i++) {
      if (owner[i] === -2) fail(`gap@${i}`);
      if (owner[i] === -1 && bytes[i] === 13) { if (owner[i + 1] !== -1 || bytes[i + 1] !== 10) fail('crlf'); return i; }
    }
    fail('line');
  };
  return { owner, text, lineEnd, privateRanges, length: bytes.length };
}

function readHeaders(c, start, approved, alwaysHidden, required, obligations, repeatHidden = false) {
  const seen = new Map();
  let at = start;
  for (;;) {
    const e = c.lineEnd(at);
    if (e === at) return { end: e + 2, headers: seen };
    let colon = at;
    while (c.owner[colon] === -1 && c.text(colon, colon + 1) !== ':') colon++;
    const name = c.text(at, colon).toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || c.text(colon, colon + 1) !== ':') fail('header-name');
    // A response may repeat a header (set-cookie); only hidden values of headers outside the public policy may repeat.
    const repeated = seen.has(name);
    if (repeated && !(repeatHidden && seen.get(name) === null && !approved.has(name))) fail(`duplicate:${name}`);
    let valueStart = colon + 1;
    while (c.owner[valueStart] === -1 && /[ \t]/.test(c.text(valueStart, valueStart + 1))) valueStart++;
    const hidden = c.privateRanges.findIndex(r => r.start === valueStart);
    if (hidden >= 0) {
      const r = c.privateRanges[hidden];
      if (r.end !== e || r.end - r.start > HEADER_LIMIT || ['content-length', 'transfer-encoding', 'content-encoding'].includes(name)) fail(`hidden-header:${name}`);
      obligations.push({ hash: r.hash, length: r.end - r.start, need: 'header' });
      seen.set(name, null);
    } else {
      const value = c.text(valueStart, e), rule = approved.get(name);
      if (alwaysHidden.includes(name) || rule === undefined || !(typeof rule === 'string' ? value === rule : rule.test(value))) {
        if (value !== '' || required.includes(name)) fail(`public-header:${name}`);
      }
      if (repeated) fail(`duplicate:${name}`);
      seen.set(name, value);
    }
    at = e + 2;
  }
}

function inspectRequest(sent, step, obligations) {
  const c = coverage(sent);
  if (c.owner.some(o => o === -2)) fail('sent-gap');
  const e = c.lineEnd(0);
  if (step === 'identity') {
    if (c.text(0, e) !== `GET ${CF_USER_PATH} HTTP/1.1`) fail('request-line');
  } else {
    const idStart = 4 + CF_PAGE_PREFIX.length;
    if (c.text(0, idStart) !== `GET ${CF_PAGE_PREFIX}`) fail('request-line');
    const id = c.privateRanges.find(r => r.start === idStart), queryStart = idStart + 32 + CF_PAGE_INFIX.length;
    if (!id || id.end !== idStart + 32 || c.text(id.end, queryStart) !== CF_PAGE_INFIX) fail('request-line');
    const query = c.privateRanges.find(r => r.start === queryStart);
    if (!query || query.end >= e || c.text(query.end, e) !== ' HTTP/1.1') fail('request-line');
    obligations.push({ hash: id.hash, length: 32, need: 'header' }, { hash: query.hash, length: query.end - query.start, need: 'header' });
  }
  if (c.privateRanges.some(r => r.start < e && ![4 + CF_PAGE_PREFIX.length, 4 + CF_PAGE_PREFIX.length + 32 + CF_PAGE_INFIX.length].includes(r.start))) fail('request-line');
  const head = readHeaders(c, e + 2, CF_REQUEST_HEADERS, ['authorization'], [], obligations);
  if (head.end !== c.length || head.headers.get('authorization') !== null || head.headers.get('host') !== 'api.cloudflare.com') fail('request-headers');
}

/**
 * Verifier: reads one session from the authenticated transcript ranges ({ sent, recv } as returned by
 * authenticatedTranscriptRanges with recv gaps). Returns
 *   identity: { step, identity: { hash, length }, obligations }
 *   page:     { step, rows: [{ product, type, action, result, actorType, context, scope, day, actor: { hash, length } }], obligations }
 */
export function inspectCloudflareSession(directions, step) {
  if (!isStep(step) || !directions?.sent?.bytes || !directions?.recv?.bytes) fail('input');
  const obligations = [];
  inspectRequest(directions.sent, step, obligations);
  const c = coverage(directions.recv);
  const statusEnd = c.lineEnd(0);
  if (c.text(0, statusEnd) !== 'HTTP/1.1 200 OK') fail('status');
  const head = readHeaders(c, statusEnd + 2, CF_RESPONSE_HEADERS, [], ['content-type'], obligations, true);
  if (head.headers.has('content-encoding')) fail('content-encoding');
  const chunked = head.headers.get('transfer-encoding') !== undefined, length = head.headers.get('content-length');
  if (chunked === (length !== undefined)) fail('framing');
  // Body map: chunk data ranges in wire offsets, with their body offsets.
  const chunks = [];
  if (chunked) {
    let at = head.end, bodyAt = 0;
    for (;;) {
      const e = c.lineEnd(at), size = c.text(at, e);
      if (!/^[0-9a-fA-F]{1,8}$/.test(size)) fail('chunk-size');
      const n = parseInt(size, 16), start = e + 2;
      if (n === 0) { if (c.text(start, start + 2) !== '\r\n' || start + 2 !== c.length) fail('final-chunk'); break; }
      if (c.text(start + n, start + n + 2) !== '\r\n') fail('chunk-crlf');
      chunks.push({ start, end: start + n, bodyStart: bodyAt }); bodyAt += n; at = start + n + 2;
    }
  } else {
    if (head.end + Number(length) !== c.length) fail('content-length');
    chunks.push({ start: head.end, end: c.length, bodyStart: 0 });
  }
  // Covered runs inside the body (public and private ranges, no gap), each within one chunk.
  const runs = [];
  for (const chunk of chunks) {
    let i = chunk.start;
    while (i < chunk.end) {
      if (c.owner[i] === -2) { i++; continue; }
      const start = i; while (i < chunk.end && c.owner[i] !== -2) i++;
      runs.push({ start, end: i, bodyStart: chunk.bodyStart + start - chunk.start });
    }
  }
  const pieces = run => {
    const out = [];
    for (let i = run.start; i < run.end;) {
      if (c.owner[i] === -1) { const s = i; while (i < run.end && c.owner[i] === -1) i++; out.push({ kind: 'R', text: c.text(s, i), start: s, end: i }); }
      else { const r = c.privateRanges[c.owner[i]]; if (r.end > run.end) fail('private-crosses'); out.push({ kind: 'H', length: r.end - r.start, hash: r.hash, start: r.start, end: r.end }); i = r.end; }
    }
    return out;
  };
  if (!runs.length || runs[0].bodyStart !== 0) fail('body-start');
  const first = pieces(runs[0]);
  if (step === 'identity') {
    if (runs.length !== 1 || first.length !== 2 || first[0].kind !== 'R' || first[0].text !== CF_IDENTITY_PREFIX || first[1].kind !== 'H' || first[1].length !== 34) fail('identity-body');
    obligations.push({ hash: first[1].hash, length: 34, need: 'value' });
    return { step, identity: { hash: first[1].hash, length: 34 }, obligations };
  }
  // Page body: covered without a gap from the public prefix up to the end of the last row (a gap only after it), so
  // every row is a top-level element of the result array. Runs split only at chunk framing.
  for (let i = 1; i < runs.length; i++) if (runs[i].bodyStart !== runs[i - 1].bodyStart + runs[i - 1].end - runs[i - 1].start) fail('row-gap');
  const all = runs.flatMap(pieces).reduce((out, p) => {
    const last = out.at(-1);
    if (p.kind === 'R' && last?.kind === 'R') out[out.length - 1] = { ...last, text: last.text + p.text, end: p.end };
    else out.push(p);
    return out;
  }, []);
  if (all[0]?.kind !== 'R' || !all[0].text.startsWith(CF_PAGE_BODY_PREFIX)) fail('page-body');
  all[0] = { ...all[0], text: all[0].text.slice(CF_PAGE_BODY_PREFIX.length) };
  const elements = pageElements(all[0].text ? all : all.slice(1));
  if (!elements.length || elements.length > CF_PAGE_LIMIT_MAX) fail('rows');
  const rowRuns = [];
  for (const element of elements) {
    // A row left out is one hidden piece, proven to be exactly one JSON value; it carries no evidence.
    if (element.length === 1 && element[0].kind === 'H') obligations.push({ hash: element[0].hash, length: element[0].length, need: 'value' });
    else rowRuns.push(element);
  }
  if (!rowRuns.length || rowRuns.length > CF_PAGE_ROW_CAP) fail('rows');
  const rows = [];
  for (const run of rowRuns) {
    const row = readRow(run);
    const hidden = run.filter(p => p.kind === 'H');
    row.hidden.forEach((kind, i) => obligations.push({ hash: hidden[i].hash, length: hidden[i].length, need: kind === 'A' ? 'actor' : kind === 'T' ? 'tail' : 'value' }));
    const actor = hidden[row.hidden.indexOf('A')];
    const { hidden: _, ...fields } = row;
    rows.push({ ...fields, actor: { hash: actor.hash, length: actor.length } });
  }
  return { step, rows, obligations };
}

/**
 * Splits the covered page body after the prefix into the result array's top-level elements: each one either a row
 * (pieces from its `{` to its matching `}`) or a single hidden piece, separated by revealed commas. Hidden pieces are
 * proven to be one JSON value (or the tail of the string they close), so the depth read from the revealed bytes is the
 * real depth. The body may end mid-way only between elements (the gap after the last row).
 */
function pageElements(pieces) {
  const elements = [];
  let row = null, depth = 0, inString = false, escaped = false, comma = false;
  for (const p of pieces) {
    if (p.kind === 'H') {
      if (row) { row.push(p); inString = false; continue; }
      if (comma) fail('row-separator');
      elements.push([p]); comma = true; continue;
    }
    let from = 0;
    for (let i = 0; i < p.text.length; i++) {
      const c = p.text[i];
      if (!row) {
        if (comma) { if (c !== ',') fail('row-separator'); comma = false; continue; }
        if (c !== '{') fail('row-start');
        row = []; from = i; depth = 1; continue;
      }
      if (inString) { if (escaped) escaped = false; else if (c === '\\') escaped = true; else if (c === '"') inString = false; continue; }
      if (c === '"') inString = true;
      else if (c === '{' || c === '[') depth++;
      else if ((c === '}' || c === ']') && --depth === 0) { row.push({ ...p, text: p.text.slice(from, i + 1) }); elements.push(row); row = null; comma = true; }
    }
    if (row && from < p.text.length) row.push({ ...p, text: p.text.slice(from) });
  }
  if (row) fail('row-open');
  return elements;
}

export { CF_ID };
