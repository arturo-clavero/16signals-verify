import { awsConsoleSession, awsPrivateCredentials } from '../aws-private/browser-client.mjs';
import { livePrivateRoute, type GcpPrivateRoute } from './gcpPrivateCompletion';

/** Request header that marks the extension's own credential re-fetch in the managed tab's header log. */
export const AWS_CAPTURE_MARKER = 'x-16signals-capture';

type LoggedHeader = { id: string; requestHeaders?: Array<{ name: string; value?: string }> };
const SESSION_FIELDS = ['cookie', 'x-csrf-token', 'origin'] as const;
/** Failure stage for the background console: a fixed code, never a header, cookie or credential value. */
class CaptureStage extends Error {}
const stage = (code: string): never => { throw new CaptureStage(code); };

/** A one-use capture from this approved run's managed tab, never a page-supplied credential tuple. */
export async function readAwsPrivateCapture(raw: unknown, sender: { id?: string; url?: string; tab?: unknown },
  routes: Map<string, GcpPrivateRoute>, deps: {
    extensionId: string; offscreenUrl: string; now(): number;
    window(id: number): { tabId: number; headers: Array<{ id: string }> } | undefined;
    tab(id: number): Promise<{ url?: string; windowId?: number }>;
    send(id: number, message: unknown): Promise<unknown>;
  }) {
  try {
    const message = raw as { type?: unknown; requestId?: unknown; windowId?: unknown; captureId?: unknown };
    if (!message || Object.keys(message).length !== 4 || message.type !== 'AWS_PRIVATE_CREDENTIALS' ||
        typeof message.requestId !== 'string' || !Number.isInteger(message.windowId) ||
        typeof message.captureId !== 'string' || !/^[A-Za-z0-9._-]{1,256}$/.test(message.captureId)) stage('INVALID_REQUEST');
    const route = livePrivateRoute(message.requestId as string, sender, routes, { ...deps, now: deps.now() }, 'aws');
    if (!route || route.windowId !== message.windowId || route.credentialsUsed) stage('ROUTE_INVALID');
    route!.credentialsUsed = true;
    const windowId = message.windowId as number, managed = deps.window(windowId);
    if (!managed) stage('WINDOW_MISSING');
    const headers = managed!.headers as LoggedHeader[];
    let capture: ReturnType<typeof awsConsoleSession>;
    try { capture = awsConsoleSession(headers.find(header => header.id === message.captureId), deps.now()); }
    catch { return stage('NO_CONSOLE_REQUEST'); }
    const origin = new URL(capture.url).origin;
    // Marks the isolated re-fetch below, itself a request of this tab. The session check compares the capture with the
    // Console's own latest credential request sent before that re-fetch: requests the Console sends while the re-fetch
    // is in flight cannot change the credentials it returns. Unguessable, so a page cannot hide its requests behind it.
    const marker = crypto.randomUUID();
    const own = (header: LoggedHeader) =>
      header.requestHeaders?.some(row => row.name.toLowerCase() === AWS_CAPTURE_MARKER && row.value === marker) === true;
    const check = async (phase: 'PRE' | 'POST') => {
      const tab = await deps.tab(managed!.tabId);
      if (livePrivateRoute(message.requestId as string, sender, routes, { ...deps, now: deps.now() }, 'aws') !== route ||
          deps.window(windowId) !== managed) stage(`${phase}_ROUTE_CLOSED`);
      if (tab.windowId !== windowId || !tab.url || new URL(tab.url).origin !== origin) stage(`${phase}_TAB_CHANGED`);
      const ownIndex = headers.findIndex(own);
      if (phase === 'POST' && ownIndex < 0) stage('OWN_REFETCH_NOT_SEEN');
      const earlier = ownIndex < 0 ? headers : headers.slice(0, ownIndex);
      const latest = [...earlier].reverse().find(header => {
        try { awsConsoleSession(header, deps.now()); return true; } catch { return false; }
      });
      if (!latest) stage(`${phase}_NO_CONSOLE_REQUEST`);
      const current = awsConsoleSession(latest, deps.now());
      if (current.url !== capture.url) stage(`${phase}_SESSION_MISMATCH_URL`);
      for (const key of SESSION_FIELDS) if (current.headers[key] !== capture.headers[key]) stage(`${phase}_SESSION_MISMATCH_${key.toUpperCase()}`);
    };
    await check('PRE');
    let value: unknown;
    try {
      value = await deps.send(managed!.tabId, { type: 'AWS_PRIVATE_CONSOLE_CREDENTIALS', url: capture.url, csrfToken: capture.headers['x-csrf-token'], marker });
    } catch (error) {
      const code = error instanceof Error ? /^AWS_REFETCH_([A-Z0-9_]{1,32})$/.exec(error.message)?.[1] : undefined;
      stage(`REFETCH_${code ?? 'FAILED'}`);
    }
    try {
      await check('POST');
      let credentials;
      try { credentials = awsPrivateCredentials(value, deps.now()); } catch { stage('CREDENTIALS_INVALID'); }
      return { credentials: credentials!, ...(capture.accountId ? { accountId: capture.accountId } : {}) };
    } finally {
      if (value && typeof value === 'object') for (const key of Object.keys(value)) (value as Record<string, unknown>)[key] = '';
    }
  } catch (error) {
    try { console.warn(`AWS_CAPTURE_${error instanceof CaptureStage ? error.message : 'FAILED'}`); } catch { /* Diagnostics only. */ }
    throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
  }
}
