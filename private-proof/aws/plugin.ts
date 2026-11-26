// Built-in plugin `aws-private-work` (method AWS_ACCOUNT), bundled by fork/build-plugins.mjs. It opens the AWS console,
// waits for CloudTrail to load with an IAM-user session, hands the captured request to the extension's private-proof
// collector (`collectAwsPrivate`) and notarizes each collected request through the verifier. The extension templates
// the run values into `'__PLUGIN_PARAMS__'` and the per-method URL placeholders; everything else is fixed code.
/* eslint-disable no-useless-assignment -- `requests` is cleared on purpose so the proof data is dropped as soon as
   the run ends. */
import { AWS_CONSOLE_URL } from './console-session.mjs';
import { awsCollectedSteps } from './sessions.mjs';
import { AWS_PAGE_BYTES, AWS_CLOUDTRAIL_HOSTS } from './request.mjs';

import type { DivFunction, OpenWindowFunction, UseEffectFunction, UseHeadersFunction, UseStateFunction, SetStateFunction, DoneFunction, ProveFunction, ProveRequest } from '../plugin/api';
declare const div: DivFunction, openWindow: OpenWindowFunction, useEffect: UseEffectFunction;
declare const useState: UseStateFunction, setState: SetStateFunction, done: DoneFunction, useHeaders: UseHeadersFunction;
declare const collectAwsPrivate: (captureId: string) => Promise<ProveRequest[]>;
declare const prove: ProveFunction;
declare const __VERIFIER_URL_AWS_ACCOUNT__: string, __PROXY_URL_AWS_ACCOUNT__: string;

const { privateAttempt, fastCheck } = JSON.parse('__PLUGIN_PARAMS__');
const P = privateAttempt as {
  proofId: string; pluginSha256: string; nonceMac: string; identityService: string; region: string; issuedAt: number; expiresAt: number;
};
const VERIFIER = __VERIFIER_URL_AWS_ACCOUNT__, PROXY = __PROXY_URL_AWS_ACCOUNT__;
if (!P || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(P.proofId) ||
    !/^[a-f0-9]{64}$/.test(P.pluginSha256) || P.identityService !== 'iam' || P.region !== 'us-east-1' ||
    !/^[A-Za-z0-9_-]{43}$/.test(P.nonceMac) || !Number.isSafeInteger(P.issuedAt) || P.issuedAt > Date.now() ||
    !Number.isSafeInteger(P.expiresAt) || P.expiresAt <= Date.now() || P.expiresAt - P.issuedAt !== 900000)
  throw new Error('AWS_PRIVATE_PROVING_FAILED');
// IAM for the identity; CloudTrail in us-east-1 for single events, in any allowed Region for page sessions.
const hosts = ['iam.amazonaws.com', ...AWS_CLOUDTRAIL_HOSTS];
const config = {
  name: 'Private AWS activity verification',
  description: 'Proves supported AWS activity by your IAM user. Credentials and employer data stay on this device.',
  timeout: Math.min(295000, P.expiresAt - Date.now()),
  requests: hosts.map(host => ({ method: 'POST', host, pathname: '/', verifierUrl: VERIFIER, proxyUrl: PROXY + host })),
  urls: [AWS_CONSOLE_URL],
};
const run = async () => {
  if (useState('running', false) || !useState('captureId', '')) return;
  setState('running', true);
  setState('current', 'Confirming your IAM user and reading your AWS history. This can take a minute or two.');
  let requests: Array<ProveRequest | null> | undefined;
  let proved = 0;
  try {
    requests = await collectAwsPrivate(useState('captureId', ''));
    const steps = Array.isArray(requests) ? awsCollectedSteps(requests) : [];
    if (!Array.isArray(requests) || (requests.length < (fastCheck ? 1 : 2) || requests.length > steps.length)) throw new Error();
    for (let index = 0; index < requests.length; index++) {
      const request = requests[index], page = steps[index].startsWith('P');
      const host = !index ? hosts[0] : page ? hosts.slice(1).find(name => request?.url === `https://${name}/`) : hosts[1];
      if (!request || !host || request.url !== `https://${host}/`) throw new Error();
      const pages = steps.slice(0, requests.length).filter(step => step.startsWith('P')).length;
      const pageNumber = steps.slice(0, index + 1).filter(step => step.startsWith('P')).length;
      setState('current', page ? `Recording your AWS history: page session ${pageNumber} of ${pages}…`
        : index === 0 ? 'Recording your IAM user check…' : `Recording AWS response ${index + 1} of ${requests.length}…`);
      // A page session receives one LookupEvents page; the other sessions one small response.
      await prove(request, { verifierUrl: VERIFIER, proxyUrl: PROXY + host,
        maxRecvData: page ? AWS_PAGE_BYTES : 16384, maxSentData: 16384, handlers: [],
        sessionData: { proofId: P.proofId, nonceMac: P.nonceMac, method: 'AWS_ACCOUNT', step: steps[index], mode: 'Proxy' } });
      requests[index] = null;
      proved++;
    }
  } catch { /* The compiled witness owner refuses an incomplete native pair. */ }
  finally {
    const complete = proved > 0 && proved === requests?.length;
    setState('current', complete ? 'Done. You can close this window and return to the page that started it.'
      : 'The check could not finish. Return to the page that started it to see what to try next.');
    setState('finished', true);
    requests = undefined; setState('captureId', ''); done();
  }
};
const main = () => {
  const captured = useHeaders(rows => rows.filter(row => row.method === 'POST' && row.url.endsWith('/cloudtrailv2/tb/creds')));
  const latest = captured[captured.length - 1];
  useEffect(() => { void openWindow(AWS_CONSOLE_URL); }, []);
  useEffect(() => {
    if (latest && !useState('running', false)) { setState('captureId', latest.id); void run(); }
  }, [latest?.id || '']);
  // A fixed panel like the other providers' plugins: plain text would land below the Console's full-height layout.
  // The status line comes first and changes at each stage, so a long step never looks stuck.
  const started = useState('running', false) || useState('finished', false);
  const progress = useState<{ message: string } | null>('_proveProgress', null);
  const line = (text: string) => div({ style: { marginTop: '6px' } }, [text]);
  return div({ style: { position: 'fixed', bottom: '0', right: '8px', width: '320px', maxWidth: 'calc(100vw - 16px)',
    boxSizing: 'border-box', background: 'white', padding: '12px', zIndex: '999999', fontSize: '13px', lineHeight: '1.5', color: '#1f2328',
    border: '1px solid #d0d7de', borderBottom: '0', borderRadius: '8px 8px 0 0', boxShadow: '0 -4px 16px rgba(15, 23, 42, 0.12)' } }, [
    div({ style: { fontWeight: '600' } }, [config.name]),
    div({ style: { marginTop: '6px', fontWeight: '600' } }, [
      started ? useState('current', 'Preparing the check…') : 'Waiting for CloudTrail to open with your IAM user…']),
    ...(useState('running', false) && progress?.message ? [div({ style: { marginTop: '2px', color: '#59636e' } }, [progress.message])] : []),
    ...(useState('finished', false) ? [] : [
      line(fastCheck ? 'Fast check: confirming the IAM user linked to your saved activity.' : 'Full activity check: about 8 to 10 minutes.')]),
    ...(started ? [] : [
      line('Use your IAM-user session for this check. Role, SSO and root sessions are not supported.'),
      line('If AWS shows Choose AWS sessions, choose Add session, then sign in with your account ID or alias, IAM username and password. Open CloudTrail with that same IAM user.'),
      line('You do not need to select events in CloudTrail.'),
    ]),
    ...(useState('finished', false) ? [] : [line('Keep this window open; closing it cancels verification.')]),
  ]);
};
export default { main, run, config };
