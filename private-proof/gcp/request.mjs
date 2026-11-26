// The requests the `gcp-work` plugin notarizes: the Google account check (identity step) and one Cloud Logging batch
// per step of `BATCHES`. The batch bodies are rendered from generated/catalog.json by policy.mjs, the same bytes the
// circuits accept, so the plugin and the circuits share one catalog.
import catalog from './generated/catalog.json' with { type: 'json' };
import { BATCHES, localBatchBody } from './policy.mjs';

export { BATCHES };
export const GCP_ACCOUNTS_HOST = 'accounts.google.com';
/** The Logs Explorer request whose headers carry the console session and the browser API key. */
export const GCP_CONSOLE_HOST = 'cloudconsole-pa.clients6.google.com';
export const GCP_CONSOLE_PATH = '/v3/entityServices/LoggingEntityService/entities/LOGGING_ENTRY_SUMMARY_STREAM:get';
export const GCP_BROWSER_LOG_HOST = 'logging.clients6.google.com';
export const GCP_MAX_SENT = catalog.limits.transcriptBytesPerDirection;
export const GCP_MAX_RECV = catalog.limits.transcriptBytesPerDirection;
/** The header that carries the run's nonce; its name is fixed by the circuits. */
export const GCP_NONCE_HEADER = 'x-16signals-nonce';

const fail = () => { throw new Error('GCP_REQUEST_INVALID'); };

/** The identity step: the signed-in account at Google's account index `account` (one digit). */
export function gcpSessionRequest(account) {
  if (typeof account !== 'string' || !/^[0-9]$/.test(account)) fail();
  return { url: `https://${GCP_ACCOUNTS_HOST}/ListAccounts?json=standard&authuser=${account}`, method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: ' ' };
}

/** One batch step (`groups:<n>`): the newest matching audit-log timestamp of each of its skill groups. */
export function gcpBatchRequest(step, policy, projectId, email, apiKey) {
  if (typeof apiKey !== 'string' || !/^AIza[A-Za-z0-9_-]{35}$/.test(apiKey)) fail();
  const { text } = localBatchBody(step, policy, projectId, email);
  // ASCII only (the project and email alphabets), so length is the byte count; room is left for the outer headers.
  if (text.length > catalog.limits.batchBodyBytes || /authorization:|bearer /i.test(text)) fail();
  return { url: `https://${GCP_BROWSER_LOG_HOST}/batch?key=${apiKey}`, method: 'POST',
    headers: { 'Content-Type': catalog.batchContentType, Accept: 'multipart/mixed' }, body: text };
}
