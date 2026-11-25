import { describe, it, expect, vi } from 'vitest';
import { readAwsPrivateCapture } from '../../src/background/awsPrivateCapture';
import { readConsoleCredentials } from '../../src/entries/Content/awsPrivateCredentials';
import type { GcpPrivateRoute } from '../../src/background/gcpPrivateCompletion';

const origin = 'https://111122223333-abcdefgh.ap-southeast-2.console.aws.amazon.com';
const credentials = () => ({ accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
  sessionToken: 't'.repeat(100), expiration: new Date(Date.now() + 3600000).toISOString() });
function fixture() {
  const route: GcpPrivateRoute = { tabId: 1, windowId: 7, createdAt: Date.now(), awsPrivate: true, pageProgress: true };
  const routes = new Map([['run', route]]);
  const header = { id: 'capture', url: origin + '/cloudtrailv2/tb/creds', method: 'POST', timestamp: Date.now(),
    requestHeaders: [{ name: 'Cookie', value: 'PRIVATE_COOKIE_SENTINEL' }, { name: 'Origin', value: origin }, { name: 'x-csrf-token', value: 'PRIVATE_CSRF_SENTINEL' }] };
  const window = { tabId: 9, headers: [header] };
  const sender = { id: 'extension', url: 'chrome-extension://extension/offscreen.html' };
  const message = { type: 'AWS_PRIVATE_CREDENTIALS', requestId: 'run', windowId: 7, captureId: 'capture' };
  const deps = { extensionId: sender.id, offscreenUrl: sender.url, now: Date.now,
    window: vi.fn((id: number) => id === 7 ? window : undefined),
    tab: vi.fn(async () => ({ url: origin + '/cloudtrailv2/home', windowId: 7 })),
    send: vi.fn(async (_tab: number, sent: unknown): Promise<unknown> => { window.headers.push(ownFetch(header, sent)); return credentials(); }) };
  return { route, routes, header, window, sender, message, deps };
}
// The isolated re-fetch is itself a request of the managed tab and lands in its header log, carrying the marker.
type Logged = { id: string; url: string; method: string; timestamp: number; requestHeaders: Array<{ name: string; value: string }> };
function ownFetch(header: Logged, sent: unknown, edit?: { name: string; value: string }, marker = (sent as { marker: string }).marker): Logged {
  return { ...header, id: 'own-fetch', timestamp: Date.now(), requestHeaders: [...header.requestHeaders.map(row =>
    row.name === edit?.name ? { ...row, value: edit.value } : row), { name: 'X-16signals-Capture', value: marker }] };
}
const consoleRequest = (header: Logged, id: string, edit: { name: string; value: string }): Logged => ({ ...header, id, timestamp: Date.now(),
  requestHeaders: header.requestHeaders.map(row => row.name === edit.name ? { ...row, value: edit.value } : row) });
const error = { message: 'AWS_PRIVATE_COLLECTION_FAILED' };

describe('AWS managed-window credential route', () => {
  it('uses the captured top-level tab once and erases the intermediate credential response', async () => {
    const f = fixture(), value = credentials();
    f.deps.send.mockImplementation(async (_tab, sent) => { f.window.headers.push(ownFetch(f.header, sent)); return value; });
    const result = await readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps);
    expect(result.accountId).toBe('111122223333'); expect(result.credentials.accessKeyId).toMatch(/^ASIA/);
    expect(Object.values(value).every(value => value === '')).toBe(true);
    expect(f.deps.send).toHaveBeenCalledWith(9, { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: f.header.url, csrfToken: 'PRIVATE_CSRF_SENTINEL',
      marker: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/) });
    expect(JSON.stringify(result)).not.toContain('PRIVATE_COOKIE_SENTINEL');
    await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
    expect(f.deps.send).toHaveBeenCalledTimes(1);
  });
  it('refuses foreign senders, page callers, other providers, other windows and stale captures before fetch', async () => {
    const changes = [
      (f: ReturnType<typeof fixture>) => { f.sender.url = origin; },
      (f: ReturnType<typeof fixture>) => { Object.assign(f.sender, { tab: { id: 1 } }); },
      (f: ReturnType<typeof fixture>) => { f.route.gcpPrivate = true; },
      (f: ReturnType<typeof fixture>) => { f.message.windowId = 8; },
      (f: ReturnType<typeof fixture>) => { f.header.timestamp -= 120001; },
      (f: ReturnType<typeof fixture>) => { f.route.createdAt -= 13 * 60 * 1000; },
      (f: ReturnType<typeof fixture>) => { f.deps.tab.mockResolvedValue({ url: 'https://sentinel.invalid/', windowId: 7 }); },
    ];
    for (const change of changes) {
      const f = fixture(); change(f);
      await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
      expect(f.deps.send).not.toHaveBeenCalled();
    }
  });
  it('discards credentials when cancellation, account switching or window replacement races the response', async () => {
    for (const change of ['cancel', 'switch', 'window']) {
      const f = fixture(), value = credentials();
      f.deps.send.mockImplementation(async (_tab, sent) => {
        if (change === 'cancel') f.routes.delete('run');
        // A switch before the re-fetch was sent: the Console's latest credential request carries other cookies.
        if (change === 'switch') f.window.headers.push(consoleRequest(f.header, 'changed', { name: 'Cookie', value: 'OTHER_SESSION' }));
        if (change === 'window') f.deps.window.mockReturnValue({ ...f.window });
        f.window.headers.push(ownFetch(f.header, sent));
        return value;
      });
      await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
      expect(Object.values(value).every(value => value === '')).toBe(true);
    }
  });
  it('ignores Console cookie changes made after its last credential request', async () => {
    const f = fixture();
    f.deps.send.mockImplementation(async (_tab, sent) => {
      f.window.headers.push(ownFetch(f.header, sent, { name: 'Cookie', value: 'PRIVATE_COOKIE_SENTINEL; noflush_Region=ap-southeast-2' }));
      return credentials();
    });
    expect((await readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).credentials.accessKeyId).toMatch(/^ASIA/);
  });
  it('ignores Console credential requests sent while its own re-fetch is in flight', async () => {
    // Seen live: the Console asks for credentials again, with newer cookies, before the re-fetch returns.
    const f = fixture();
    f.deps.send.mockImplementation(async (_tab, sent) => {
      f.window.headers.push(ownFetch(f.header, sent));
      f.window.headers.push(consoleRequest(f.header, 'console-again', { name: 'Cookie', value: 'PRIVATE_COOKIE_SENTINEL; noflush_Region=ap-southeast-2' }));
      return credentials();
    });
    expect((await readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).credentials.accessKeyId).toMatch(/^ASIA/);
  });
  it('excludes only its own marked re-fetch from the session check', async () => {
    // Own request excluded even if it differed; a page request carrying the header name with another value is not.
    const own = fixture();
    own.deps.send.mockImplementation(async (_tab, sent) => {
      own.window.headers.push(ownFetch(own.header, sent, { name: 'x-csrf-token', value: 'OTHER_SESSION' }));
      return credentials();
    });
    await expect(readAwsPrivateCapture(own.message, own.sender, own.routes, own.deps)).resolves.toBeTruthy();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const forged = fixture(), value = credentials();
    forged.deps.send.mockImplementation(async (_tab, sent) => {
      forged.window.headers.push(ownFetch(forged.header, sent, { name: 'Cookie', value: 'OTHER_SESSION' }, '00000000-0000-4000-8000-000000000000'));
      forged.window.headers.push(ownFetch(forged.header, sent));
      return value;
    });
    await expect(readAwsPrivateCapture(forged.message, forged.sender, forged.routes, forged.deps)).rejects.toMatchObject(error);
    expect(Object.values(value).every(value => value === '')).toBe(true);
    expect(warn).toHaveBeenCalledWith('AWS_CAPTURE_POST_SESSION_MISMATCH_COOKIE');
    warn.mockRestore();
  });
  it('logs a fixed stage code for each failure, never a header, cookie or credential value', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cases: Array<[string, (f: ReturnType<typeof fixture>) => void]> = [
      ['AWS_CAPTURE_NO_CONSOLE_REQUEST', f => { f.message.captureId = 'missing'; }],
      ['AWS_CAPTURE_OWN_REFETCH_NOT_SEEN', f => { f.deps.send.mockResolvedValue(credentials()); }],
      ['AWS_CAPTURE_REFETCH_STATUS_403', f => { f.deps.send.mockRejectedValue(new Error('AWS_REFETCH_STATUS_403')); }],
      ['AWS_CAPTURE_REFETCH_FAILED', f => { f.deps.send.mockRejectedValue(new Error('PRIVATE_COOKIE_SENTINEL')); }],
      ['AWS_CAPTURE_PRE_SESSION_MISMATCH_COOKIE', f => { f.window.headers.push(consoleRequest(f.header, 'other', { name: 'Cookie', value: 'OTHER_SESSION' })); }],
      ['AWS_CAPTURE_POST_TAB_CHANGED', f => { f.deps.tab.mockResolvedValueOnce({ url: origin + '/x', windowId: 7 }).mockResolvedValue({ url: 'https://sentinel.invalid/', windowId: 7 }); }],
      ['AWS_CAPTURE_CREDENTIALS_INVALID', f => { f.deps.send.mockImplementation(async (_tab, sent) => {
        f.window.headers.push(ownFetch(f.header, sent)); return { accessKeyId: 'AKIA_PRIVATE' }; }); }],
    ];
    for (const [code, change] of cases) {
      const f = fixture(); change(f); warn.mockClear();
      await expect(readAwsPrivateCapture(f.message, f.sender, f.routes, f.deps)).rejects.toMatchObject(error);
      expect(warn.mock.calls).toEqual([[code]]);
    }
    warn.mockRestore();
  });
});

describe('AWS isolated content credential fetch', () => {
  const sender = { id: 'extension', url: 'chrome-extension://extension/background.bundle.js' };
  const message = { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: origin + '/cloudtrailv2/tb/creds', csrfToken: 'csrf',
    marker: '11111111-2222-4333-8444-555555555555' };
  const deps = () => ({ extensionId: sender.id, backgroundUrl: sender.url, origin, top: true,
    fetchAws: vi.fn(async () => new Response(JSON.stringify(credentials()))) as unknown as typeof fetch });
  it('uses same-origin cookies with a fixed endpoint and returns a closed credential shape', async () => {
    const d = deps(), result = await readConsoleCredentials(message, sender, d);
    expect(result.accessKeyId).toMatch(/^ASIA/);
    expect(d.fetchAws).toHaveBeenCalledWith(message.url, expect.objectContaining({ method: 'POST', credentials: 'include', mode: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'x-csrf-token': 'csrf', 'x-16signals-capture': message.marker } }));
    expect(Object.keys(result).sort()).toEqual(['accessKeyId', 'expiration', 'secretAccessKey', 'sessionToken']);
  });
  it('rejects with a fixed stage code: HTTP status or an invalid credential body', async () => {
    for (const [response, code] of [[new Response('{}', { status: 403 }), 'AWS_REFETCH_STATUS_403'],
      [new Response(JSON.stringify({ accessKeyId: 'AKIA_PRIVATE' })), 'AWS_REFETCH_INVALID']] as const) {
      const d = { ...deps(), fetchAws: vi.fn(async () => response) as unknown as typeof fetch };
      await expect(readConsoleCredentials(message, sender, d)).rejects.toMatchObject({ message: code });
    }
  });
  it('refuses page/foreign senders, subframes, origin/path substitutions and header injection', async () => {
    for (const [m, s, overrides] of [
      [message, { ...sender, id: 'other' }, {}], [message, { ...sender, tab: {} }, {}],
      [message, sender, { top: false }], [message, sender, { origin: 'https://sentinel.invalid' }],
      [{ ...message, url: message.url + '?url=https://sentinel.invalid' }, sender, {}],
      [{ ...message, csrfToken: 'csrf\r\ninjected: value' }, sender, {}],
      [{ ...message, marker: 'marker\r\ninjected: value' }, sender, {}], [{ ...message, marker: undefined }, sender, {}],
    ] as const) {
      const d = { ...deps(), ...overrides };
      await expect(readConsoleCredentials(m, s, d)).rejects.toMatchObject({ message: 'AWS_REFETCH_REFUSED' });
      expect(d.fetchAws).not.toHaveBeenCalled();
    }
  });
});
