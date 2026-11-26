/**
 * Cloudflare API requests of a run. All go to api.cloudflare.com with the candidate's OAuth Bearer token (scopes
 * audit-logs.read, user-details.read, account-settings.read). Every host here must also be in the extension
 * manifest, the plugin and the verifier's TLSN_ALLOWED_HOSTS.
 *
 * Steps: `identity` (GET /client/v4/user, proven), then page sessions P0..P2 (GET .../logs/audit, proven). The
 * account lookup (GET /client/v4/accounts) and discovery reads use the same builder but are never proven.
 */
export const CF_API_HOST = 'api.cloudflare.com';
export const CF_HOSTS = Object.freeze([CF_API_HOST]);
export const CF_PAGE_STEPS = Object.freeze(['P0', 'P1', 'P2']);
export const CF_RUN_STEPS = Object.freeze(['identity', ...CF_PAGE_STEPS]);
/** Largest response a page session may fetch (25 rows measured 24-35 KB; rows up to 4.3 KB). */
export const CF_PAGE_BYTES = 307200;
export const CF_SMALL_BYTES = 16384;
export const CF_SENT_BYTES = 16384;
export const CF_ID = /^[0-9a-f]{32}$/;
// Rows per page session: 12 keeps the browser prover's memory low (a 20-row session was killed by the OOM killer
// on a 15 GB machine under load, 2026-11-25); three sessions still cover 36 rows.
export const CF_PAGE_LIMIT_MAX = 12;
/** Lookback, as AWS and GCP. */
export const CF_WINDOW_DAYS = 90;

export const CF_USER_PATH = '/client/v4/user';
export const CF_ACCOUNTS_PATH = '/client/v4/accounts';
export const CF_PAGE_PREFIX = '/client/v4/accounts/';
export const CF_PAGE_INFIX = '/logs/audit?';
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const CURSOR = /^[A-Za-z0-9_=-]{1,1024}$/;

/** The fixed query of a page or discovery read: own successful non-view rows, newest first. */
export function cloudflarePageQuery({ userId, since, before, limit, cursor }) {
  if (!CF_ID.test(userId ?? '') || !ISO.test(since ?? '') || !ISO.test(before ?? '') || Date.parse(since) > Date.parse(before) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || (cursor !== undefined && !CURSOR.test(cursor))) {
    throw new Error('CF_REQUEST_INVALID');
  }
  const query = new URLSearchParams([['since', since], ['before', before], ['limit', String(limit)], ['direction', 'desc'],
    ['actor_id', userId], ['actor_type', 'user'], ['action_result', 'success'], ['action_type.not', 'view']]);
  if (cursor !== undefined) query.set('cursor', cursor);
  return query.toString();
}

/**
 * The request object handed to TLSNotary prove() (or fetch for unproven reads).
 * kind: 'identity' | 'accounts' | 'page'. A page needs accountId and the cloudflarePageQuery fields.
 */
export function buildCloudflareRequest({ kind, token, accountId, ...page } = {}) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9._~+/=-]{20,512}$/.test(token)) throw new Error('CF_REQUEST_INVALID');
  let path;
  if (kind === 'identity') path = CF_USER_PATH;
  else if (kind === 'accounts') path = CF_ACCOUNTS_PATH;
  else if (kind === 'page') {
    if (!CF_ID.test(accountId ?? '')) throw new Error('CF_REQUEST_INVALID');
    path = `${CF_PAGE_PREFIX}${accountId}${CF_PAGE_INFIX}${cloudflarePageQuery(page)}`;
  } else throw new Error('CF_REQUEST_INVALID');
  return {
    url: `https://${CF_API_HOST}${path}`, method: 'GET',
    // The extension's prover (hyper) sends exactly these headers, lower-cased, in this order; it adds no Host itself.
    headers: { Host: CF_API_HOST, Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Encoding': 'identity', Connection: 'close' },
  };
}

/** Public header values the verifier accepts on a request (every other header value must be hidden and proven ASCII). */
export const CF_REQUEST_HEADERS = Object.freeze(new Map([
  ['host', CF_API_HOST], ['accept', 'application/json'], ['accept-encoding', 'identity'], ['connection', 'close'],
]));
/** Public header values the verifier accepts on a response. */
export const CF_RESPONSE_HEADERS = Object.freeze(new Map([
  ['content-type', /^application\/json(?:; ?charset=utf-8)?$/i], ['transfer-encoding', /^chunked$/i], ['content-length', /^[0-9]{1,7}$/],
  // Fixed Cloudflare API headers (same on every response; nothing about the candidate). cf-ray, cf-auditlog-id,
  // set-cookie, ratelimit and date stay hidden.
  ['api-version', /^[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[a-z]+)?$/], ['cache-control', /^[a-z0-9=, -]{1,80}$/], ['cf-cache-status', /^[A-Z]{1,16}$/],
  ['connection', /^(keep-alive|close)$/], ['expires', /^[A-Za-z0-9 ,:]{1,40}$/], ['pragma', 'no-cache'], ['server', 'cloudflare'],
  ['strict-transport-security', /^max-age=[0-9]{1,10}(; ?[a-zA-Z]+)*$/], ['vary', /^[A-Za-z, -]{1,40}$/], ['x-content-type-options', 'nosniff'],
  ['x-frame-options', /^[A-Z]{1,16}$/],
]));
