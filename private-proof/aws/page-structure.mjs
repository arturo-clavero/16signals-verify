/**
 * Layout of one proven row of a LookupEvents page, on the wire (the outer JSON, where every quote of the embedded
 * CloudTrailEvent is escaped as \"). A row is one chain of revealed (R), hash-committed (H) and unauthenticated gap (G)
 * pieces; the verifier sees R bytes, the position and length of every piece, and nothing else.
 *
 *   R  "CloudTrailEvent":"{\"eventVersion\":\"1.NN\",\"userIdentity\":{\"type\":\"IAMUser\",\"principalId\":
 *   H  actor:      \"<principalId>\",\"arn\":\"<arn>\",\"accountId\":\"<account>\"     (== the identity session)
 *   R  ,\"accessKeyId\":                G  \"<20 chars>\" (24 B)
 *   R  ,\"userName\":                   G  \"<user name>\" (identity UserName length + 4)
 *      console sign-in only:
 *   R  ,\"sessionContext\":{\"attributes\":{\"creationDate\":   G 24 B
 *   R  ,\"mfaAuthenticated\":           G  \"true\" or \"false\" (8 or 9 B)
 *   R  }},  then for both:
 *   R  },\"eventTime\":\"YYYY-MM-DD    G  Thh:mm:ssZ (10 B; the time of day is never revealed)
 *   R  \",\"eventSource\":\"<s>\",\"eventName\":\"<n>\",\"awsRegion\":\"<r>\",\"sourceIPAddress\":
 *   G  \"<ip>\" (5-53 B)                (<r> matches the Region grammar and equals the session's endpoint Region)
 *   R  ,\"userAgent\":
 *   H  body:       \"<userAgent>\",\"requestParameters\": ... up to the byte before the next key below
 *   R  ,\"recipientAccountId\":
 *   H  recipient:  \"<account>\" (16 B)
 *   R  ,\"eventCategory\":\"Management\" [,\"tlsDetails\":{\"tlsVersion\":\"..\",\"cipherSuite\":\"..\"
 *      [,\"clientProvidedHostHeader\":  H  host: \"<host>\"  R ] [,\"keyExchange\":\"..\"] } ] [,\"sessionCredentialFromConsole\":\"true\"] }"
 *
 * The batch circuit opens the three H pieces: actor equal to the identity session's IAM user id, ARN and account;
 * the userAgent one string with no quote or backslash, immediately followed by requestParameters (so no errorCode);
 * the body never leaving the outer string (so the recipient belongs to the same event); recipient equal to the
 * account. Gaps hold AWS-generated values of a fixed or bounded length at fixed key positions.
 *
 * The client host header is the one client-chosen value in the revealed tail, and S3 writes the bucket name into it,
 * so it is neither revealed nor left as a gap: it is hash-committed and an escaped-atom proof shows it is exactly one
 * JSON string inside the event string (no unescaped quote, nothing after it). The tail is therefore fixed structure
 * around one proven string, and its closing braces and `"` still mark the end of the event at depth zero. The other
 * revealed tail values (TLS version, cipher suite, key exchange, console flag) are matched by grammars with no quote
 * or backslash. Every other layout (invokedBy, inScopeOf, roles, no userAgent, another key order, other tail keys)
 * does not match and fails closed.
 */
import { awsCatalogOperation } from './skill-groups.mjs';
import { AWS_REGION, AWS_REGIONS, awsRegionHolds } from './request.mjs';

const DAY_MS = 86400000;
const DATE = String.raw`(\d{4}-\d\d-\d\d)`;
const PREFIX = new RegExp(String.raw`^"CloudTrailEvent":"\{\\"eventVersion\\":\\"1\.\d\d\\",\\"userIdentity\\":\{\\"type\\":\\"IAMUser\\",\\"principalId\\":$`);
const ACCESS_KEY = String.raw`,\"accessKeyId\":`, USER_NAME = String.raw`,\"userName\":`;
const CONSOLE = String.raw`,\"sessionContext\":{\"attributes\":{\"creationDate\":`, MFA = String.raw`,\"mfaAuthenticated\":`;
const PLAIN_TIME = new RegExp(String.raw`^\},\\"eventTime\\":\\"${DATE}$`), CONSOLE_TIME = new RegExp(String.raw`^\}\}\},\\"eventTime\\":\\"${DATE}$`);
// awsRegion: the Region grammar (no quote or backslash can occur), then compared with the session's Region.
const REGION = String.raw`[a-z]{2}(?:-gov)?-[a-z]+-[0-9]`;
const OPERATION = new RegExp(String.raw`^\\",\\"eventSource\\":\\"([a-z0-9.-]{1,64})\\",\\"eventName\\":\\"([A-Za-z0-9]{1,64})\\",\\"awsRegion\\":\\"(${REGION})\\",\\"sourceIPAddress\\":$`);
const USER_AGENT = String.raw`,\"userAgent\":`, RECIPIENT = String.raw`,\"recipientAccountId\":`;
const TLS = String.raw`,\\"tlsDetails\\":\{\\"tlsVersion\\":\\"[A-Za-z0-9.]{1,16}\\",\\"cipherSuite\\":\\"[A-Za-z0-9_-]{1,64}\\"`;
const KEY_EXCHANGE = String.raw`(?:,\\"keyExchange\\":\\"[A-Za-z0-9_-]{1,64}\\")?`;
const CONSOLE_FLAG = String.raw`(?:,\\"sessionCredentialFromConsole\\":\\"true\\")?\}"`;
const TAIL = new RegExp(String.raw`^,\\"eventCategory\\":\\"Management\\"(?:${TLS}${KEY_EXCHANGE}\})?${CONSOLE_FLAG}$`);
const TAIL_HOST = new RegExp(String.raw`^,\\"eventCategory\\":\\"Management\\"${TLS},\\"clientProvidedHostHeader\\":$`);
const HOST_END = new RegExp(String.raw`^${KEY_EXCHANGE}\}${CONSOLE_FLAG}$`);
export const AWS_EVENTS_OPEN = '{"Events":[';
/** Wire capacities of the committed pieces (the largest batch circuit's); longer rows cannot be proven. */
export const AWS_ROW_LIMITS = Object.freeze({ actor: 256, body: 2390, userAgent: 320, recipient: 16, host: 512 });

const fail = () => { throw new Error('AWS_PRIVATE_PAGE_INVALID'); };

/** UTC day number of a revealed YYYY-MM-DD, or a failure for anything that is not a real date. */
export function awsUtcDay(date) {
  const ms = Date.parse(`${date}T00:00:00Z`);
  if (!Number.isSafeInteger(ms) || new Date(ms).toISOString().slice(0, 10) !== date) fail();
  return ms / DAY_MS;
}

/**
 * Match the row chains of a page body. `pieces` are the body's authenticated pieces in wire order:
 * { type: 'R', start, end, text } (maximal revealed runs) and { type: 'H', start, end, hash }; anything between two
 * pieces is a gap. The first piece must be the revealed `{"Events":[`. Returns one entry per row: the operation, its
 * UTC day and the three committed pieces. `region` is the session's endpoint Region: a row recorded in another Region
 * (or a global-service row outside us-east-1) fails.
 */
export function matchAwsPageRows(pieces, { userNameLength, region = AWS_REGION }) {
  if (!Number.isInteger(userNameLength) || userNameLength < 1 || userNameLength > 64 || !AWS_REGIONS.includes(region)) fail();
  let index = 0;
  const next = () => pieces[index++] ?? fail();
  const revealed = (gapMin, gapMax, previous) => {
    const piece = next();
    if (piece.type !== 'R' || piece.start - previous.end < gapMin || piece.start - previous.end > gapMax) fail();
    return piece;
  };
  const committed = (previous, max) => {
    const piece = next();
    if (piece.type !== 'H' || piece.start !== previous.end || piece.end - piece.start > max) fail();
    return piece;
  };
  const exact = (piece, text) => { if (piece.text !== text) fail(); return piece; };
  const open = next();
  if (open.type !== 'R' || open.start !== 0 || open.text !== AWS_EVENTS_OPEN) fail();
  const rows = [];
  let last = open;
  while (index < pieces.length) {
    const start = next();
    if (start.type !== 'R' || start.start <= last.end || !PREFIX.test(start.text)) fail();
    const actor = committed(start, AWS_ROW_LIMITS.actor);
    const user = exact(revealed(0, 0, actor), ACCESS_KEY);
    let time = revealed(userNameLength + 4, userNameLength + 4, exact(revealed(24, 24, user), USER_NAME));
    const console = time.text === CONSOLE;
    if (console) time = revealed(8, 9, exact(revealed(24, 24, time), MFA));
    const date = (console ? CONSOLE_TIME : PLAIN_TIME).exec(time.text)?.[1] ?? fail();
    const operation = revealed(10, 10, time), [, eventSource, eventName, rowRegion] = OPERATION.exec(operation.text) ?? fail();
    if (rowRegion !== region || !awsRegionHolds(region, eventSource)) fail();
    const body = committed(exact(revealed(5, 53, operation), USER_AGENT), AWS_ROW_LIMITS.body);
    const recipient = committed(exact(revealed(0, 0, body), RECIPIENT), AWS_ROW_LIMITS.recipient);
    if (recipient.end - recipient.start !== 16) fail();
    last = revealed(0, 0, recipient);
    let host;
    if (TAIL_HOST.test(last.text)) {
      host = committed(last, AWS_ROW_LIMITS.host);
      if (host.end - host.start < 5) fail();
      last = revealed(0, 0, host);
      if (!HOST_END.test(last.text)) fail();
    } else if (!TAIL.test(last.text)) fail();
    const operationEntry = awsCatalogOperation(eventSource, eventName) ?? fail();
    rows.push({ eventSource, eventName, group: operationEntry.group, tier: operationEntry.tier, auto: operationEntry.auto,
      day: awsUtcDay(date), actor, body, recipient, ...(host ? { host } : {}) });
  }
  return rows;
}

const latin1 = bytes => { let text = ''; for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192)); return text; };

/**
 * Client side: the pieces of the row whose `"CloudTrailEvent":"` key starts at `at` in the page body `text` (one
 * character per byte), or null when the row does not have the provable layout. Hidden pieces are only positions.
 */
export function awsPageRowPieces(text, at) {
  const pieces = [];
  let cursor = at;
  const take = (type, pattern) => {
    pattern.lastIndex = cursor;
    const match = pattern.exec(text);
    if (!match) return null;
    const end = cursor + match[0].length, last = pieces.at(-1);
    if (type === 'R' && last?.type === 'R' && last.end === cursor) last.end = end;
    else pieces.push({ type, start: cursor, end });
    cursor = end;
    return match;
  };
  const sticky = source => new RegExp(source, 'y');
  const steps = [
    ['R', String.raw`"CloudTrailEvent":"\{\\"eventVersion\\":\\"1\.\d\d\\",\\"userIdentity\\":\{\\"type\\":\\"IAMUser\\",\\"principalId\\":`],
    ['H', String.raw`\\"[A-Za-z0-9]{16,64}\\",\\"arn\\":\\"[^"\\]{1,200}\\",\\"accountId\\":\\"\d{12}\\"`],
    ['R', String.raw`,\\"accessKeyId\\":`], ['G', String.raw`\\"[A-Z0-9]{20}\\"`],
    ['R', String.raw`,\\"userName\\":`], ['G', String.raw`\\"[^"\\]{1,64}\\"`],
  ];
  for (const [type, source] of steps) if (!take(type, sticky(source))) return null;
  if (take('R', sticky(String.raw`,\\"sessionContext\\":\{\\"attributes\\":\{\\"creationDate\\":`)) &&
      !(take('G', sticky(String.raw`\\"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\\"`)) && take('R', sticky(String.raw`,\\"mfaAuthenticated\\":`)) &&
        take('G', sticky(String.raw`\\"(?:true|false)\\"`)) && take('R', sticky(String.raw`\}\}`)))) return null;
  const more = [
    ['R', String.raw`\},\\"eventTime\\":\\"\d{4}-\d\d-\d\d`], ['G', String.raw`T\d\d:\d\d:\d\dZ`],
    ['R', String.raw`\\",\\"eventSource\\":\\"[a-z0-9.-]{1,64}\\",\\"eventName\\":\\"[A-Za-z0-9]{1,64}\\",\\"awsRegion\\":\\"${REGION}\\",\\"sourceIPAddress\\":`],
    ['G', String.raw`\\"[^"\\]{1,49}\\"`], ['R', String.raw`,\\"userAgent\\":`],
  ];
  for (const [type, source] of more) if (!take(type, sticky(source))) return null;
  // The body runs to the recipient key; it must stay inside the outer string (every quote escaped).
  const bodyStart = cursor, bodyEnd = text.indexOf(RECIPIENT, cursor);
  if (bodyEnd < 0 || !sticky(String.raw`\\"[^"\\]{1,316}\\",\\"requestParameters\\":`).test(text.slice(bodyStart, bodyStart + 400))) return null;
  for (let index = bodyStart, escaped = false; index < bodyEnd; index++) {
    if (escaped) escaped = false; else if (text[index] === '"') return null; else escaped = text[index] === '\\';
  }
  pieces.push({ type: 'H', start: bodyStart, end: bodyEnd });
  cursor = bodyEnd;
  if (!take('R', sticky(String.raw`,\\"recipientAccountId\\":`)) || !take('H', sticky(String.raw`\\"\d{12}\\"`)) ||
      !take('R', sticky(String.raw`,\\"eventCategory\\":\\"Management\\"`))) return null;
  if (take('R', sticky(TLS))) {
    if (take('R', sticky(String.raw`,\\"clientProvidedHostHeader\\":`))) {
      if (!take('H', sticky(String.raw`\\"[^"\\]{1,253}\\"`))) return null;
      pieces.at(-1).host = true;
    }
    if (!take('R', sticky(`${KEY_EXCHANGE}\\}`))) return null;
  }
  if (!take('R', sticky(CONSOLE_FLAG))) return null;
  const [actor, body] = pieces.filter(piece => piece.type === 'H');
  if (actor.end - actor.start > AWS_ROW_LIMITS.actor || body.end - body.start > AWS_ROW_LIMITS.body) return null;
  return pieces.filter(piece => piece.type !== 'G');
}

/**
 * Client side: every row of a page body with its EventId and wire position of its `"CloudTrailEvent":"` key. Keys
 * inside strings are escaped, so each unescaped occurrence is one row's key, in row order.
 */
export function awsPageRows(bodyBytes) {
  const text = latin1(bodyBytes);
  let page;
  try { page = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bodyBytes)); } catch { fail(); }
  if (!text.startsWith(AWS_EVENTS_OPEN) || !Array.isArray(page?.Events) || page.Events.length > 50) fail();
  const starts = [];
  for (let at = text.indexOf('"CloudTrailEvent":"'); at >= 0; at = text.indexOf('"CloudTrailEvent":"', at + 1)) starts.push(at);
  if (starts.length !== page.Events.length) fail();
  return { text, events: page.Events, rows: page.Events.map((row, index) => ({ eventId: row?.EventId, at: starts[index] })) };
}
