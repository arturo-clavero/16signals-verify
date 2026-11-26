import type { GcpPrivateRoute } from './gcpPrivateCompletion';
import { livePrivateRoute } from './gcpPrivateCompletion';

/**
 * 16signals fork (Cloudflare): the OAuth sign-in for one private Cloudflare run. Authorization Code + PKCE with the
 * public "16signals" client, through chrome.identity (Cloudflare's consent window; redirect to this extension's
 * chromiumapp.org URL). The token goes only to the offscreen run that asked (one token per run route), lives in memory
 * there and is revoked when the run ends (1 h expiry otherwise). It is never stored or sent to 16signals.
 */
declare const __FORK_CF_OAUTH_CLIENT_ID__: string | undefined;
export const CF_OAUTH = Object.freeze({
  authorize: 'https://dash.cloudflare.com/oauth2/auth', token: 'https://dash.cloudflare.com/oauth2/token',
  revoke: 'https://dash.cloudflare.com/oauth2/revoke', scope: 'audit-logs.read user-details.read account-settings.read',
});
export const cloudflareClientId = () => (typeof __FORK_CF_OAUTH_CLIENT_ID__ === 'string' ? __FORK_CF_OAUTH_CLIENT_ID__ : '');

const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
interface Deps {
  extensionId: string; offscreenUrl: string; now: () => number;
  /** chrome.identity.launchWebAuthFlow({ url, interactive: true }) */
  launch(url: string): Promise<string | undefined>;
  redirectUrl: string; clientId: string; fetch: typeof fetch;
}

/** One fixed diagnostic code per stage; never a value. */
function stage(code: string): void { try { console.warn(`CF_BG_${code}`); } catch { /* Diagnostics must not affect the run. */ } }

export async function readCloudflareToken(raw: unknown, sender: { id?: string; url?: string; tab?: unknown },
  routes: Map<string, GcpPrivateRoute>, deps: Deps): Promise<{ token: string } | { error: string }> {
  const message = raw as { type?: unknown; requestId?: unknown } | null;
  const keys = message && typeof message === 'object' ? Reflect.ownKeys(message) : [];
  const route = keys.length === 2 && message?.type === 'CF_PRIVATE_TOKEN'
    ? livePrivateRoute(message.requestId, sender, routes, { ...deps, now: deps.now() }, 'cloudflare') : null;
  if (!route || route.credentialsUsed || !/^[A-Za-z0-9_-]{16,128}$/.test(deps.clientId) ||
      !/^https:\/\/[a-p]{32}\.chromiumapp\.org\/$/.test(deps.redirectUrl)) { stage('ROUTE_REFUSED'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
  route.credentialsUsed = true;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  // Cloudflare refuses a short state (invalid_state): 32 hex characters.
  const state = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
  const url = new URL(CF_OAUTH.authorize);
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: deps.clientId, redirect_uri: deps.redirectUrl,
    scope: CF_OAUTH.scope, state, code_challenge: challenge, code_challenge_method: 'S256' })) url.searchParams.set(k, v);
  let redirected: URL;
  try {
    const result = await deps.launch(url.toString());
    redirected = new URL(result ?? '');
  } catch { stage('CONSENT_CANCELLED'); return { error: 'CF_OAUTH_CANCELLED' }; }
  if (`${redirected.origin}/` !== deps.redirectUrl || redirected.searchParams.get('state') !== state) { stage('STATE_MISMATCH'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
  if (redirected.searchParams.get('error')) { stage('CONSENT_DENIED'); return { error: 'CF_OAUTH_CANCELLED' }; }
  const code = redirected.searchParams.get('code');
  if (!code || code.length > 2048) { stage('NO_CODE'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
  if (!livePrivateRoute(message!.requestId, sender, routes, { ...deps, now: deps.now() }, 'cloudflare')) { stage('ROUTE_EXPIRED'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
  try {
    const response = await deps.fetch(CF_OAUTH.token, { method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: deps.redirectUrl, client_id: deps.clientId, code_verifier: verifier }) });
    const body = await response.json() as { access_token?: unknown; scope?: unknown };
    const token = body.access_token;
    if (!response.ok || typeof token !== 'string' || !/^[A-Za-z0-9._~+/=-]{20,512}$/.test(token)) { stage('EXCHANGE_FAILED'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
    stage('TOKEN_OK');
    return { token };
  } catch { stage('EXCHANGE_FAILED'); return { error: 'CF_PRIVATE_COLLECTION_FAILED' }; }
}

/** Best effort: the run is over, the token is no longer needed. */
export async function revokeCloudflareToken(token: string, clientId: string, fetchCf: typeof fetch = fetch): Promise<void> {
  try {
    await fetchCf(CF_OAUTH.revoke, { method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token, client_id: clientId }) });
  } catch { /* Expires within the hour anyway. */ }
}
