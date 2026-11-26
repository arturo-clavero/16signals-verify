// Built-in plugin `cloudflare-private-work` (method CLOUDFLARE_ACCOUNT), bundled by fork/build-plugins.mjs. It opens
// the Cloudflare dashboard, lets the extension's private-proof collector (`collectCloudflarePrivate`, OAuth with PKCE)
// prepare the API requests and notarizes each of them through the verifier. The extension templates the run values
// into `'__PLUGIN_PARAMS__'` and the per-method URL placeholders; everything else is fixed code.
/* eslint-disable no-useless-assignment -- `requests` is cleared on purpose so the proof data is dropped as soon as
   the run ends. */
import { CF_API_HOST, CF_PAGE_BYTES, CF_SMALL_BYTES, CF_SENT_BYTES, CF_RUN_STEPS } from './request.mjs';

import type { DivFunction, OpenWindowFunction, UseEffectFunction, UseStateFunction, SetStateFunction, DoneFunction, ProveFunction, ProveRequest } from '../plugin/api';
declare const div: DivFunction, openWindow: OpenWindowFunction, useEffect: UseEffectFunction;
declare const useState: UseStateFunction, setState: SetStateFunction, done: DoneFunction;
declare const collectCloudflarePrivate: () => Promise<ProveRequest[]>;
declare const prove: ProveFunction;
declare const __VERIFIER_URL_CLOUDFLARE_ACCOUNT__: string, __PROXY_URL_CLOUDFLARE_ACCOUNT__: string;

// fastCheck (optional): prove the identity session only.
const { privateAttempt, fastCheck } = JSON.parse('__PLUGIN_PARAMS__');
const P = privateAttempt as { proofId: string; pluginSha256: string; nonceMac: string; issuedAt: number; expiresAt: number };
const VERIFIER = __VERIFIER_URL_CLOUDFLARE_ACCOUNT__, PROXY = __PROXY_URL_CLOUDFLARE_ACCOUNT__;
if (!P || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(P.proofId) ||
    !/^[a-f0-9]{64}$/.test(P.pluginSha256) || !/^[A-Za-z0-9_-]{43}$/.test(P.nonceMac) ||
    !Number.isSafeInteger(P.issuedAt) || P.issuedAt > Date.now() || !Number.isSafeInteger(P.expiresAt) ||
    P.expiresAt <= Date.now() || P.expiresAt - P.issuedAt !== 900000) throw new Error('CF_PRIVATE_PROVING_FAILED');
const DASHBOARD = 'https://dash.cloudflare.com/';
const config = {
  name: 'Private Cloudflare activity verification',
  description: 'Proves your own recent Cloudflare changes. Your sign-in and account details stay on this device.',
  timeout: Math.min(295000, P.expiresAt - Date.now()),
  requests: [{ method: 'GET', host: CF_API_HOST, pathname: '/client/v4/**', verifierUrl: VERIFIER, proxyUrl: PROXY + CF_API_HOST }],
  urls: [DASHBOARD],
};
const run = async () => {
  if (useState('running', false)) return;
  setState('running', true);
  setState('current', 'Approve read-only access in the Cloudflare window that opens.');
  let requests: Array<ProveRequest | null> | undefined;
  let proved = 0;
  try {
    requests = await collectCloudflarePrivate();
    if (!Array.isArray(requests) || requests.length < (fastCheck ? 1 : 2) || requests.length > (fastCheck ? 1 : CF_RUN_STEPS.length)) throw new Error();
    for (let index = 0; index < requests.length; index++) {
      const request = requests[index];
      if (!request || !request.url.startsWith(`https://${CF_API_HOST}/client/v4/`)) throw new Error();
      setState('current', index === 0 ? 'Recording your Cloudflare user check…' : `Recording your Cloudflare history: page ${index} of ${requests.length - 1}…`);
      await prove(request, { verifierUrl: VERIFIER, proxyUrl: PROXY + CF_API_HOST,
        maxRecvData: index ? CF_PAGE_BYTES : CF_SMALL_BYTES, maxSentData: CF_SENT_BYTES, handlers: [],
        sessionData: { proofId: P.proofId, nonceMac: P.nonceMac, method: 'CLOUDFLARE_ACCOUNT', step: CF_RUN_STEPS[index], mode: 'Proxy' } });
      requests[index] = null;
      proved++;
    }
  } catch { /* The compiled witness owner refuses an incomplete run. */ }
  finally {
    const complete = proved > 0 && proved === requests?.length;
    setState('current', complete ? 'Done. You can close this window and return to the page that started it.'
      : 'The check could not finish. Return to the page that started it to see what to try next.');
    setState('finished', true);
    requests = undefined; done();
  }
};
const main = () => {
  useEffect(() => { void openWindow(DASHBOARD).then(() => run()); }, []);
  const started = useState('running', false) || useState('finished', false);
  const progress = useState<{ message: string } | null>('_proveProgress', null);
  const line = (text: string) => div({ style: { marginTop: '6px' } }, [text]);
  return div({ style: { position: 'fixed', bottom: '0', right: '8px', width: '320px', maxWidth: 'calc(100vw - 16px)',
    boxSizing: 'border-box', background: 'white', padding: '12px', zIndex: '999999', fontSize: '13px', lineHeight: '1.5', color: '#1f2328',
    border: '1px solid #d0d7de', borderBottom: '0', borderRadius: '8px 8px 0 0', boxShadow: '0 -4px 16px rgba(15, 23, 42, 0.12)' } }, [
    div({ style: { fontWeight: '600' } }, [config.name]),
    div({ style: { marginTop: '6px', fontWeight: '600' } }, [started ? useState('current', 'Preparing the check…') : 'Opening Cloudflare…']),
    ...(useState('running', false) && progress?.message ? [div({ style: { marginTop: '2px', color: '#59636e' } }, [progress.message])] : []),
    ...(useState('finished', false) ? [] : [
      line('The extension asks Cloudflare for read-only access to your audit log and user details, for this check only.'),
      line(fastCheck ? 'Fast check: confirming the Cloudflare user linked to your saved activity. About 1 minute.'
        : 'Full activity check: about 5 to 8 minutes. Keep this window open; closing it cancels verification.'),
    ]),
  ]);
};
export default { main, run, config };
