import { expect, it, vi } from 'vitest';
import { CF_PRIVATE_ROUTE_TTL_MS, livePrivateRoute, takePrivateCompletion, type GcpPrivateRoute } from '../../src/background/gcpPrivateCompletion';
import { readCloudflareToken, CF_OAUTH } from '../../src/background/cloudflarePrivateAuth';

const extensionId = 'private-extension', offscreenUrl = `chrome-extension://${extensionId}/offscreen.html`;
const sender = { id: extensionId, url: offscreenUrl }, deps = { extensionId, offscreenUrl, now: 1000 };
const routes = () => new Map<string, GcpPrivateRoute>([['run-1', { tabId: 8, createdAt: 100, pageProgress: true, cfPrivate: true }]]);
const result = () => ({ kind: 'CLOUDFLARE_PRIVATE_RESULT', version: 1,
  sessionIds: ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'],
  proofs: ['cf-json-small-v1', 'cf-actor-v1'].map((circuitId, i) => ({ circuitId, proof: 'AQID', publicInputs: Array(i ? 297 : 544).fill('0') })) });
const message = () => ({ type: 'CF_PRIVATE_COMPLETE', requestId: 'run-1', success: true, result: result() });
const redirectUrl = `https://${'a'.repeat(32)}.chromiumapp.org/`, clientId = 'c'.repeat(36);

it('completes only a Cloudflare route, with a closed copy of the result', () => {
  const map = routes(), raw = message(), expected = structuredClone(raw.result);
  const done = takePrivateCompletion(raw, sender, map, deps, 'cloudflare');
  expect(done).toEqual({ requestId: 'run-1', tabId: 8, response: { success: true, result: expected } });
  expect(map.size).toBe(0);
  expect(takePrivateCompletion(message(), sender, routes(), deps, 'aws')).toBeNull();
  expect(takePrivateCompletion({ ...message(), type: 'AWS_PRIVATE_COMPLETE' }, sender, routes(), deps, 'aws')).toBeNull();
  const both = routes(); both.get('run-1')!.awsPrivate = true;
  expect(livePrivateRoute('run-1', sender, both, deps, 'cloudflare')).toBeNull();
  expect(CF_PRIVATE_ROUTE_TTL_MS).toBe(13 * 60 * 1000);
});

it('passes only the candidate-facing Cloudflare errors', () => {
  for (const error of ['CF_ACCOUNT_ACCESS_REQUIRED', 'CF_NO_ACTIVITY', 'CF_OAUTH_CANCELLED']) {
    expect(takePrivateCompletion({ type: 'CF_PRIVATE_COMPLETE', requestId: 'run-1', success: false, error }, sender, routes(), deps, 'cloudflare')?.response)
      .toEqual({ success: false, error });
  }
  expect(takePrivateCompletion({ type: 'CF_PRIVATE_COMPLETE', requestId: 'run-1', success: false, error: 'secret token abc' }, sender, routes(), deps, 'cloudflare')?.response)
    .toEqual({ success: false, error: 'CF_PRIVATE_PROVING_FAILED' });
  expect(takePrivateCompletion({ ...message(), result: { ...result(), kind: 'AWS_PRIVATE_RESULT' } }, sender, routes(), deps, 'cloudflare')?.response)
    .toEqual({ success: false, error: 'CF_PRIVATE_PROVING_FAILED' });
});

function tokenDeps(over: Partial<Parameters<typeof readCloudflareToken>[3]> = {}) {
  let authUrl = '';
  const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
    const body = new URLSearchParams(String(init?.body));
    expect(body.get('code_verifier')?.length).toBe(43);
    expect(body.get('client_id')).toBe(clientId);
    return new Response(JSON.stringify({ access_token: 'tok_' + 'x'.repeat(40), scope: CF_OAUTH.scope }), { status: 200 });
  });
  return { authUrl: () => authUrl, fetchMock, deps: { extensionId, offscreenUrl, now: () => 1000, redirectUrl, clientId, fetch: fetchMock as unknown as typeof fetch,
    launch: async (url: string) => { authUrl = url; const u = new URL(url); return `${redirectUrl}?code=abc&state=${u.searchParams.get('state')}`; }, ...over } };
}

it('runs PKCE once per route and returns the token only to the offscreen run', async () => {
  const map = routes(), t = tokenDeps();
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, map, t.deps)).toEqual({ token: 'tok_' + 'x'.repeat(40) });
  const auth = new URL(t.authUrl());
  expect(auth.origin + auth.pathname).toBe(CF_OAUTH.authorize);
  expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
  expect(auth.searchParams.get('state')).toMatch(/^[0-9a-f]{32}$/);
  expect(auth.searchParams.get('scope')).toBe('audit-logs.read user-details.read account-settings.read');
  // A second token for the same run is refused.
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, map, t.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
});

it('refuses other senders, other routes, a bad state and a cancelled consent', async () => {
  const t = tokenDeps();
  for (const source of [{ ...sender, tab: { id: 1 } }, { ...sender, id: 'other' }]) {
    expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, source, routes(), t.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
  }
  const aws = new Map<string, GcpPrivateRoute>([['run-1', { tabId: 8, createdAt: 100, pageProgress: true, awsPrivate: true }]]);
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, aws, t.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1', extra: 1 }, sender, routes(), t.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
  const badState = tokenDeps({ launch: async () => `${redirectUrl}?code=abc&state=${'0'.repeat(32)}` });
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, routes(), badState.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
  expect(badState.fetchMock).not.toHaveBeenCalled();
  const cancelled = tokenDeps({ launch: async () => { throw new Error('The user did not approve access.'); } });
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, routes(), cancelled.deps)).toEqual({ error: 'CF_OAUTH_CANCELLED' });
  const noClient = tokenDeps({ clientId: '' });
  expect(await readCloudflareToken({ type: 'CF_PRIVATE_TOKEN', requestId: 'run-1' }, sender, routes(), noClient.deps)).toEqual({ error: 'CF_PRIVATE_COLLECTION_FAILED' });
});
