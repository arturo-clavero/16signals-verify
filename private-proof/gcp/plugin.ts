// Built-in plugin `gcp-work` (method GCP_WORK), bundled by fork/build-plugins.mjs. It opens Logs Explorer for the
// project, picks up the Google account cookie and the console's request headers as the pages load, then notarizes
// the identity request and one Cloud Logging batch per step through the verifier. The extension's offscreen module
// plans what each transcript reveals and proves it locally. The extension templates the run values into
// `'__PLUGIN_PARAMS__'` and the per-method URL placeholders; everything else is fixed code.
import { BATCHES, GCP_ACCOUNTS_HOST, GCP_BROWSER_LOG_HOST, GCP_CONSOLE_HOST, GCP_CONSOLE_PATH, GCP_MAX_RECV, GCP_MAX_SENT,
  GCP_NONCE_HEADER, gcpBatchRequest, gcpSessionRequest } from './request.mjs';

import type { DivFunction, OpenWindowFunction, UseEffectFunction, UseHeadersFunction, UseStateFunction, SetStateFunction, DoneFunction, ProveFunction, ProveRequest, InterceptedRequestHeader } from '../plugin/api';
declare const div: DivFunction, openWindow: OpenWindowFunction, useEffect: UseEffectFunction;
declare const useState: UseStateFunction, setState: SetStateFunction, done: DoneFunction, useHeaders: UseHeadersFunction;
declare const prove: ProveFunction;
declare const __VERIFIER_URL_GCP_WORK__: string, __PROXY_URL_GCP_WORK__: string;
declare const reportProgress: ((value: { method: string; status: string; index: number; total: number }) => void) | undefined;

// fastCheck (optional): prove the identity session only.
const P = JSON.parse('__PLUGIN_PARAMS__') as { proofId: string; nonceMac: string; windowDays: number; cutoff: number;
  fastCheck?: boolean; privateInput?: { projectId?: string } };
const projectId = P.privateInput?.projectId;
const policy = { cutoff: P.cutoff, windowDays: P.windowDays };
const VERIFIER = __VERIFIER_URL_GCP_WORK__, PROXY = __PROXY_URL_GCP_WORK__;
if (!/^[a-f0-9-]{36}$/.test(P.proofId) || !/^[A-Za-z0-9_-]{43}$/.test(P.nonceMac) ||
    (!P.fastCheck && (typeof projectId !== 'string' || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId) ||
      ![7, 30, 90].includes(policy.windowDays) || !Number.isSafeInteger(policy.cutoff) || policy.cutoff < 0)))
  throw new Error('GCP_RUN_INVALID');
// The steps are fixed by the catalog, so they do not depend on the length of the project or the account.
const batches = P.fastCheck ? [] : BATCHES.map(batch => batch.step);
const consoleUrl = 'https://console.cloud.google.com/logs/query' + (projectId ? `?project=${encodeURIComponent(projectId)}` : '');
const loginUrl = `https://${GCP_ACCOUNTS_HOST}/AccountChooser?continue=${encodeURIComponent(consoleUrl)}`;
const permission = (host: string, pathname: string) => ({ host, pathname, method: 'POST', verifierUrl: VERIFIER, proxyUrl: PROXY + host });
const config = {
  name: 'Private Google Cloud activity verification',
  description: 'Proves which skill groups had activity in your Google Cloud project in the selected window. Your project, account, credentials and event times stay on this device.',
  timeout: 300000, urls: [loginUrl, consoleUrl],
  requests: [permission(GCP_ACCOUNTS_HOST, '/ListAccounts'), permission(GCP_BROWSER_LOG_HOST, '/batch')],
};
const header = (request: InterceptedRequestHeader, key: string) => request.requestHeaders.find(value => value.name.toLowerCase() === key)?.value ?? '';
const report = (index: number, status: string) => {
  setState('collected', index);
  try { if (typeof reportProgress === 'function') reportProgress({ method: 'GCP_WORK', status, index, total: batches.length + 1 }); } catch { /* Progress is informational. */ }
};
const call = (request: ProveRequest, host: string, step: string) => prove({ ...request, headers: { ...request.headers,
  ...(step === 'identity' ? { Cookie: useState('accountCookie', ''), Origin: 'https://www.google.com' }
    : useState<Record<string, string>>('consoleHeaders', {})),
  Host: host, Connection: 'close', 'Accept-Encoding': 'identity', [GCP_NONCE_HEADER]: P.nonceMac } }, {
  verifierUrl: VERIFIER, proxyUrl: PROXY + host, maxRecvData: GCP_MAX_RECV, maxSentData: GCP_MAX_SENT, handlers: [],
  sessionData: { proofId: P.proofId, nonceMac: P.nonceMac, method: 'GCP_WORK', step, mode: 'Proxy' },
}) as Promise<{ privateAccountEmail?: string } | undefined>;

const run = async () => {
  if (useState('running', false) || useState('finished', false) || !useState('accountCookie', '') || !useState('apiKey', '')) return;
  setState('running', true);
  const completed: string[] = [];
  try {
    report(0, 'running');
    setState('current', 'Confirming your Google account…');
    const identity = await call(gcpSessionRequest(useState('account', '')), GCP_ACCOUNTS_HOST, 'identity');
    // The offscreen module reads the account from the authenticated identity transcript.
    const email = identity?.privateAccountEmail;
    if (!email) throw new Error();
    completed.push('identity'); report(completed.length, 'running');
    for (let index = 0; index < batches.length; index++) {
      const step = batches[index];
      setState('current', `Checking activity batch ${index + 1} of ${batches.length}…`);
      try {
        await call(gcpBatchRequest(step, policy, projectId as string, email, useState('apiKey', '')), GCP_BROWSER_LOG_HOST, step);
        completed.push(step);
      } catch { /* The proof needs every batch; a missing one fails the run below. */ }
      report(completed.length, 'running');
    }
  } catch { /* Without a valid identity no batch can be proved. */ }
  finally {
    const complete = completed.length === batches.length + 1;
    setState('current', complete ? 'Done. You can close this window and return to the page that started it.'
      : 'The check could not finish. Return to the page that started it to see what to try next.');
    setState('finished', true); setState('accountCookie', ''); setState('consoleHeaders', {}); setState('apiKey', '');
    report(completed.length, complete ? 'done' : 'failed');
    done({ kind: 'GCP_GROUPS', steps: ['identity', ...batches].map(step => ({ step, ok: completed.includes(step) })) });
  }
};

const main = () => {
  const requests = useHeaders(values => [
    ...values.filter(value => value.url.startsWith(`https://${GCP_ACCOUNTS_HOST}/`)).slice(-1),
    ...values.filter(value => value.url.startsWith(`https://${GCP_CONSOLE_HOST}${GCP_CONSOLE_PATH}?`)).slice(-1),
  ]);
  if (!useState('running', false) && !useState('finished', false)) for (const request of requests) {
    if (Date.now() - request.timestamp > 120000 || request.timestamp > Date.now() + 5000) continue;
    const cookie = header(request, 'cookie');
    if (!cookie || cookie.length > 6000 || /[\r\n]/.test(cookie)) continue;
    if (request.url.startsWith(`https://${GCP_ACCOUNTS_HOST}/`)) {
      if (/(?:^|;\s*)(?:LSID|__Host-3PLSID)=/.test(cookie) && cookie !== useState('accountCookie', '')) setState('accountCookie', cookie);
      continue;
    }
    // The Logs Explorer request: the console's SAPISIDHASH authorization, account index and browser API key.
    const auth = header(request, 'authorization'), account = header(request, 'x-goog-authuser');
    const key = /[?&]key=(AIza[A-Za-z0-9_-]{35})(?:&|$)/.exec(request.url)?.[1];
    if (request.method !== 'POST' || !key || !/^[0-9]$/.test(account) || header(request, 'origin') !== 'https://console.cloud.google.com' ||
        !/^SAPISIDHASH [0-9]+_[a-f0-9]{40}(?: [A-Z0-9_]+ [A-Za-z0-9_-]+)*$/.test(auth) || auth.length > 1024) continue;
    if (useState('captureId', '') === request.id) continue;
    setState('captureId', request.id);
    setState('account', account); setState('apiKey', key);
    setState('consoleHeaders', { Cookie: cookie, Authorization: auth, Origin: 'https://console.cloud.google.com', 'X-Goog-AuthUser': account });
  }
  const ready = Boolean(useState('accountCookie', '') && useState('apiKey', ''));
  useEffect(() => { void openWindow(loginUrl); }, []);
  useEffect(() => { if (ready) void run(); }, [ready]);
  const running = useState('running', false), finished = useState('finished', false);
  const progress = useState<{ message: string } | null>('_proveProgress', null);
  const line = (text: string) => div({ style: { marginTop: '6px' } }, [text]);
  return div({ style: { position: 'fixed', bottom: '0', right: '8px', width: '320px', maxWidth: 'calc(100vw - 16px)',
    boxSizing: 'border-box', background: 'white', padding: '12px', zIndex: '999999', fontSize: '13px', lineHeight: '1.5', color: '#1f2328',
    border: '1px solid #d0d7de', borderBottom: '0', borderRadius: '8px 8px 0 0', boxShadow: '0 -4px 16px rgba(15, 23, 42, 0.12)' } }, [
    div({ style: { fontWeight: '600' } }, [config.name]),
    div({ style: { marginTop: '6px', fontWeight: '600' } }, [running || finished ? useState('current', 'Preparing the check…')
      : useState('accountCookie', '') ? 'Open the selected project in Logs Explorer to continue.' : 'Choose your Google account to continue.']),
    ...(running ? [line(`${useState('collected', 0)} of ${batches.length + 1} responses collected.`),
      ...(progress?.message ? [div({ style: { marginTop: '2px', color: '#59636e' } }, [progress.message])] : [])] : []),
    ...(finished ? [] : [
      line(P.fastCheck ? 'Fast check: confirming the Google account linked to your saved activity.' : 'Full activity check: collecting your current activity.'),
      line('Keep this window open; closing it cancels verification.'),
    ]),
  ]);
};
export default { main, run, config };
