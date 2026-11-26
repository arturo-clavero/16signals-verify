// Synthetic Cloudflare transcripts (request + chunked response) built from fixture rows. Never real data.
import { fixtureText, FIXTURE_USER, FIXTURE_ACCOUNT } from './row-fixture.mjs';
import { buildCloudflareRequest } from './request.mjs';

const enc = s => new TextEncoder().encode(s);
export const FIXTURE_TOKEN = 'tok_' + 'x'.repeat(40);

export function requestBytes(kind, extra = {}) {
  const r = buildCloudflareRequest({ kind, token: FIXTURE_TOKEN, accountId: FIXTURE_ACCOUNT, userId: FIXTURE_USER,
    since: '2026-08-27T00:00:00.000Z', before: '2026-11-25T08:00:00.000Z', limit: 25, ...extra });
  const url = new URL(r.url);
  // As hyper writes it: origin-form target, lower-case header names in the given order.
  return enc(`GET ${url.pathname}${url.search} HTTP/1.1\r\n` +
    Object.entries(r.headers).map(([k, v]) => `${k.toLowerCase()}: ${v}\r\n`).join('') + '\r\n');
}

/** A chunked 200 response; `chunkSizes` splits the body (the last chunk takes the rest). */
export function responseBytes(body, chunkSizes = []) {
  const head = 'HTTP/1.1 200 OK\r\nDate: Tue, 25 Nov 2026 01:00:00 GMT\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n' +
    'Connection: close\r\nCF-Ray: 0123456789abcdef-SIN\r\nSet-Cookie: __cfruid=abc; path=/\r\nSet-Cookie: _cfuvid=def; path=/\r\n\r\n';
  const bytes = enc(body), parts = [];
  let at = 0;
  for (const size of chunkSizes) { parts.push(bytes.subarray(at, at + size)); at += size; }
  if (at < bytes.length) parts.push(bytes.subarray(at));
  const out = [enc(head)];
  for (const p of parts) out.push(enc(p.length.toString(16) + '\r\n'), p, enc('\r\n'));
  out.push(enc('0\r\n\r\n'));
  const total = out.reduce((n, p) => n + p.length, 0), all = new Uint8Array(total);
  out.reduce((n, p) => (all.set(p, n), n + p.length), 0);
  return all;
}

export const identityBody = () => `{"result":{"id":"${FIXTURE_USER}","email":"someone@example.test","username":"u"},"success":true,"errors":[],"messages":[]}`;
export const pageBody = rows => `{"errors":[],"result":[${rows.map(r => typeof r === 'string' ? r : fixtureText(r)).join(',')}],"result_info":{"count":"${rows.length}","cursor":"c"},"success":true}`;
