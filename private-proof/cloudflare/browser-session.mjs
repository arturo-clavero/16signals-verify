/**
 * Local collection in the extension, with the candidate's OAuth token (held in memory only): who the candidate is,
 * which account, which rows exist, and the requests the run proves. Nothing here reaches 16signals.
 *
 * createCloudflareLocalSession({ attempt, fetchCf, identityOnly }).prepare(token) -> [identity request, page request...]
 * `identityOnly` (fast check): the identity request alone, with no account lookup or discovery.
 * Errors: CF_ACCOUNT_ACCESS_REQUIRED (no account visible to the token), CF_NO_ACTIVITY (no provable row in the
 * lookback), CF_PRIVATE_COLLECTION_FAILED (anything else).
 */
import { buildCloudflareRequest, CF_ID } from './request.mjs';
import { discoverCloudflare, selectCloudflareWindows } from './discovery.mjs';

const LIMIT = 4 * 1024 * 1024;

/** One unproven GET; JSON only, bounded size, no cookies. */
export async function readCloudflareJson(request, { fetchCf = globalThis.fetch, signal } = {}) {
  const response = await fetchCf(request.url, { method: 'GET', headers: request.headers, credentials: 'omit', redirect: 'error', cache: 'no-store', signal });
  if (response.status === 401 || response.status === 403) throw new Error('CF_ACCOUNT_ACCESS_REQUIRED');
  const text = await response.text();
  if (!response.ok || text.length > LIMIT) throw new Error('CF_PRIVATE_COLLECTION_FAILED');
  return JSON.parse(text);
}

export function createCloudflareLocalSession({ attempt, fetchCf, now = Date.now, identityOnly = false }) {
  let cleared = false;
  return {
    async prepare(token) {
      if (cleared) throw new Error('CF_PRIVATE_COLLECTION_FAILED');
      const read = request => readCloudflareJson(request, { fetchCf });
      try {
        const user = await read(buildCloudflareRequest({ kind: 'identity', token }));
        const userId = user?.result?.id;
        if (!CF_ID.test(userId ?? '')) throw new Error('CF_PRIVATE_COLLECTION_FAILED');
        if (identityOnly) {
          if (now() >= attempt.expiresAt) throw new Error('CF_PRIVATE_COLLECTION_FAILED');
          return [buildCloudflareRequest({ kind: 'identity', token })];
        }
        const accounts = (await read(buildCloudflareRequest({ kind: 'accounts', token })))?.result;
        if (!Array.isArray(accounts) || !accounts.length || !CF_ID.test(accounts[0]?.id ?? '')) throw new Error('CF_ACCOUNT_ACCESS_REQUIRED');
        // Several accounts: the one with the most own rows (each is read once, within the discovery budget).
        let best = { rows: [], accountId: accounts[0].id };
        for (const account of accounts.slice(0, 3)) {
          if (!CF_ID.test(account?.id ?? '')) continue;
          const rows = await discoverCloudflare({ read, token, userId, accountId: account.id, now: attempt.issuedAt }).catch(() => []);
          if (rows.length > best.rows.length) best = { rows, accountId: account.id };
        }
        const windows = selectCloudflareWindows(best.rows, userId, attempt.issuedAt);
        if (!windows.length) throw new Error('CF_NO_ACTIVITY');
        if (now() >= attempt.expiresAt) throw new Error('CF_PRIVATE_COLLECTION_FAILED');
        return [buildCloudflareRequest({ kind: 'identity', token }),
          ...windows.map(window => buildCloudflareRequest({ kind: 'page', token, accountId: best.accountId, userId, ...window }))];
      } catch (error) {
        const code = error instanceof Error && ['CF_ACCOUNT_ACCESS_REQUIRED', 'CF_NO_ACTIVITY'].includes(error.message) ? error.message : 'CF_PRIVATE_COLLECTION_FAILED';
        throw new Error(code);
      }
    },
    clear() { cleared = true; },
  };
}
