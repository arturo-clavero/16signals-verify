/**
 * Audit Logs v2 row structure: which bytes of a row are revealed and which are hidden items, and the strict reader the
 * verifier runs on what was revealed.
 *
 * Cloudflare serialises rows as compact JSON with keys sorted at every level (measured on 1,227 rows, 2026-11-25), so
 * a row has one fixed grammar (ROW_GRAMMAR). The prover splits the row bytes into pieces; the verifier sees the
 * revealed pieces and, for each hidden piece, only its kind and length (plus its commitment, proven by a circuit to be
 * exactly one JSON value, a JSON string tail or the identity id). Because a hidden piece can never contain structure,
 * the revealed skeleton is the row's real structure, and the reader can take the public fields from it.
 *
 * rowPieces(text) -> [{ kind, start, end }] covering text exactly, in order. Kinds:
 *   'R' revealed bytes; 'V' hidden, one complete JSON value; 'T' hidden JSON string tail (the time after the day,
 *   e.g. `T07:00:55.123Z"`); 'A' hidden actor id (a JSON string, proven equal to the identity id).
 *   Throws CF_ROW_STRUCTURE:<reason> when the row does not fit ROW_GRAMMAR.
 * readRow(pieces) with pieces [{ kind: 'R', text } | { kind: 'H', length }] -> public fields
 *   { product, type, action, result, actorType, context, scope, day, hidden }, where `hidden` lists the kind the
 *   grammar gives each hidden piece in order ('V' | 'T' | 'A'), or throws CF_ROW_STRUCTURE:<reason>. The verifier
 *   only knows a hidden piece's length; its kind comes from its slot, and the matching proof is then required.
 */
const fail = what => { throw new Error(`CF_ROW_STRUCTURE:${what}`); };

// key -> 'V' (hidden value), 'R' (revealed short string), 'A' (actor id), 'TIME', or a nested grammar.
// `required` lists keys that must be present. Order is the key order Cloudflare serves (sorted).
export const ROW_GRAMMAR = Object.freeze({
  keys: [
    ['account', 'V'],
    ['action', { keys: [['description', 'V'], ['result', 'R'], ['time', 'TIME'], ['type', 'R']], required: ['result', 'time', 'type'] }],
    ['actor', { keys: [['context', 'R'], ['email', 'V'], ['id', 'A'], ['ip_address', 'V'], ['token', 'V'], ['type', 'R']], required: ['context', 'id', 'type'] }],
    ['id', 'V'],
    ['raw', 'V'],
    ['resource', { keys: [['id', 'V'], ['product', 'R'], ['request', 'V'], ['response', 'V'], ['scope', 'R'], ['type', 'R'], ['value', 'V']], required: [] }],
    ['zone', 'V'],
  ],
  required: ['account', 'action', 'actor', 'resource'],
});
const SHORT = /^"[a-z0-9_.-]{0,64}"$/, DAY = /^"time":"(\d{4}-\d{2}-\d{2})$/;
const TAIL = /^T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z"$/;
export const ROW_MAX_BYTES = 8192;

// --- prover side: a byte-exact scanner over compact JSON ---------------------------------------------------------
function skipString(text, i) {
  if (text[i] !== '"') fail(`string@${i}`);
  for (let j = i + 1; j < text.length; j++) {
    const c = text.charCodeAt(j);
    if (c < 32) fail(`control@${j}`);
    if (c === 92) { j++; continue; }
    if (c === 34) return j + 1;
  }
  fail('unterminated-string');
}
function skipValue(text, i) {
  const c = text[i];
  if (c === '"') return skipString(text, i);
  if (c === '{' || c === '[') {
    const close = c === '{' ? '}' : ']';
    let j = i + 1;
    if (text[j] === close) return j + 1;
    for (;;) {
      if (c === '{') { j = skipString(text, j); if (text[j] !== ':') fail(`colon@${j}`); j++; }
      j = skipValue(text, j);
      if (text[j] === ',') { j++; continue; }
      if (text[j] === close) return j + 1;
      fail(`separator@${j}`);
    }
  }
  const m = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 64));
  if (!m) fail(`value@${i}`);
  return i + m[0].length;
}

function objectPieces(text, i, grammar, out) {
  if (text[i] !== '{') fail(`object@${i}`);
  const seen = new Set();
  let j = i + 1, at = i, order = -1, first = true;
  const reveal = end => { if (end > at) out.push({ kind: 'R', start: at, end }); at = end; };
  if (text[j] === '}') { if (grammar.required.length) fail('missing-keys'); return j + 1; }
  for (;;) {
    const keyEnd = skipString(text, j), key = JSON.parse(text.slice(j, keyEnd));
    const index = grammar.keys.findIndex(([name]) => name === key);
    if (index < 0) fail(`key:${key}`);
    if (index <= order) fail(`order:${key}`);
    order = index; seen.add(key);
    if (text[keyEnd] !== ':') fail(`colon@${keyEnd}`);
    const valueStart = keyEnd + 1, rule = grammar.keys[index][1];
    if (rule === 'V' || rule === 'A') {
      const end = skipValue(text, valueStart);
      if (rule === 'A' && text[valueStart] !== '"') fail('actor-id');
      reveal(valueStart); out.push({ kind: rule, start: valueStart, end }); at = end; j = end;
    } else if (rule === 'R') {
      const end = skipValue(text, valueStart);
      if (!SHORT.test(text.slice(valueStart, end))) fail(`short:${key}`);
      j = end;
    } else if (rule === 'TIME') {
      const end = skipString(text, valueStart), dayEnd = valueStart + 11;
      if (!TAIL.test(text.slice(dayEnd, end)) || !/^"\d{4}-\d{2}-\d{2}$/.test(text.slice(valueStart, dayEnd))) fail('time');
      reveal(dayEnd); out.push({ kind: 'T', start: dayEnd, end }); at = end; j = end;
    } else {
      reveal(valueStart); j = objectPieces(text, valueStart, rule, out); at = j;
    }
    first = false;
    if (text[j] === ',') { j++; continue; }
    if (text[j] === '}') { j++; break; }
    fail(`separator@${j}`);
  }
  for (const key of grammar.required) if (!seen.has(key)) fail(`missing:${key}`);
  reveal(j);
  return j;
}

export function rowPieces(text) {
  if (typeof text !== 'string' || !text.length || text.length > ROW_MAX_BYTES) fail('size');
  const out = [];
  const end = objectPieces(text, 0, ROW_GRAMMAR, out);
  if (end !== text.length) fail('trailing');
  // Merge adjacent revealed pieces so the plan stays small.
  const merged = [];
  for (const piece of out) {
    const last = merged.at(-1);
    if (last && last.kind === 'R' && piece.kind === 'R' && last.end === piece.start) last.end = piece.end;
    else merged.push({ ...piece });
  }
  return merged;
}

// --- verifier side: read the revealed skeleton ------------------------------------------------------------------
// A hidden piece becomes one placeholder character; its kind is the kind of the slot it fills.
const HIDDEN = '\u0001';

export function readRow(pieces) {
  if (!Array.isArray(pieces) || !pieces.length) fail('pieces');
  let skeleton = '', length = 0;
  for (const piece of pieces) {
    if (piece?.kind === 'R') {
      if (typeof piece.text !== 'string' || !piece.text.length || /[\u0000-\u001f]/.test(piece.text)) fail('revealed');
      skeleton += piece.text; length += piece.text.length;
    } else if (piece?.kind === 'H') {
      if (!Number.isSafeInteger(piece.length) || piece.length < 1) fail('hidden-length');
      skeleton += HIDDEN; length += piece.length;
    } else fail('kind');
  }
  if (length > ROW_MAX_BYTES) fail('size');
  const fields = {}, hidden = [];
  const end = readObject(skeleton, 0, ROW_GRAMMAR, [], fields, hidden);
  if (end !== skeleton.length) fail('trailing');
  if (fields['actor.id'] !== 1) fail('actor-id');
  return {
    product: fields['resource.product'] ?? '', type: fields['resource.type'] ?? '', action: fields['action.type'],
    result: fields['action.result'], actorType: fields['actor.type'], context: fields['actor.context'],
    scope: fields['resource.scope'] ?? '', day: fields['action.time'], hidden,
  };
}

function readObject(s, i, grammar, path, fields, hidden) {
  if (s[i] !== '{') fail(`object@${i}`);
  let j = i + 1, order = -1;
  const seen = new Set();
  if (s[j] === '}') { if (grammar.required.length) fail('missing-keys'); return j + 1; }
  for (;;) {
    const m = /^"([a-z_]{1,32})":/.exec(s.slice(j, j + 40));
    if (!m) fail(`key@${j}`);
    const key = m[1], index = grammar.keys.findIndex(([name]) => name === key);
    if (index <= order) fail(index < 0 ? `key:${key}` : `order:${key}`);
    order = index; seen.add(key); j += m[0].length;
    const rule = grammar.keys[index][1], name = [...path, key].join('.');
    if (rule === 'V' || rule === 'A') {
      if (s[j] !== HIDDEN) fail(`hidden:${name}`);
      if (rule === 'A') fields[name] = 1;
      hidden.push(rule); j++;
    } else if (rule === 'R') {
      const r = /^"[a-z0-9_.-]{0,64}"/.exec(s.slice(j, j + 70));
      if (!r) fail(`short:${name}`);
      fields[name] = r[0].slice(1, -1); j += r[0].length;
    } else if (rule === 'TIME') {
      const d = /^"(\d{4}-\d{2}-\d{2})\u0001/.exec(s.slice(j, j + 13));
      if (!d || Number.isNaN(Date.parse(`${d[1]}T00:00:00Z`)) || new Date(`${d[1]}T00:00:00Z`).toISOString().slice(0, 10) !== d[1]) fail('time');
      fields[name] = d[1]; hidden.push('T'); j += d[0].length;
    } else {
      j = readObject(s, j, rule, [...path, key], fields, hidden);
    }
    if (s[j] === ',') { j++; continue; }
    if (s[j] === '}') { j++; break; }
    fail(`separator@${j}`);
  }
  for (const key of grammar.required) if (!seen.has(key)) fail(`missing:${[...path, key].join('.')}`);
  return j;
}
