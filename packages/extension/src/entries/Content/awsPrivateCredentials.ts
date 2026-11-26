import { awsPrivateCredentials, readAwsPrivateResponse } from '../../aws-private/browser-client.mjs';

/** One fixed code per re-fetch outcome for the page console; never a header, cookie or credential value. */
const stage = (code: string) => { try { console.warn(`AWS_CS_REFETCH_${code}`); } catch { /* Diagnostics only. */ } };

/** Runs only in the isolated content world on the exact Console origin; no window.postMessage response. */
export async function readConsoleCredentials(raw: unknown, sender: { id?: string; tab?: unknown; url?: string }, deps: {
  extensionId: string; backgroundUrl: string; origin: string; top: boolean; fetchAws?: typeof fetch;
}) {
  // Rejections carry only a fixed stage code (refused, HTTP status, failed, invalid) for the background console.
  let code = 'REFUSED_SHAPE', status: number | undefined;
  try {
    const message = raw as { type?: unknown; url?: unknown; csrfToken?: unknown; marker?: unknown };
    // Each refusal names its check; a SHAPE refusal with a marker-less message means a background from another build.
    const refuse = (check: string): never => { code = `REFUSED_${check}`; throw new Error(); };
    if (!message || message.type !== 'AWS_PRIVATE_CONSOLE_CREDENTIALS' || Object.keys(message).length !== 4) refuse('SHAPE');
    if (typeof message.marker !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(message.marker)) refuse('MARKER');
    if (sender.id !== deps.extensionId || sender.tab !== undefined || (sender.url && sender.url !== deps.backgroundUrl)) refuse('SENDER');
    if (!deps.top) refuse('CONTEXT');
    if (typeof message.url !== 'string' || !/^https:\/\/(?:(\d{12})-[a-z0-9]{8}\.)?ap-southeast-2\.console\.aws\.amazon\.com\/cloudtrailv2\/tb\/creds$/.test(message.url)) refuse('URL');
    if (new URL(message.url as string).origin !== deps.origin) refuse('ORIGIN');
    if (typeof message.csrfToken !== 'string' || !message.csrfToken || message.csrfToken.length > 4096 || /[\r\n\0]/.test(message.csrfToken)) refuse('CSRF');
    const { url, csrfToken, marker } = message as { url: string; csrfToken: string; marker: string };
    code = 'FAILED';
    const fetchAws = deps.fetchAws ?? fetch;
    const body = await readAwsPrivateResponse(url, { method: 'POST', mode: 'same-origin', credentials: 'include',
      headers: { 'x-csrf-token': csrfToken, 'x-tlsn-capture': marker } },
      { fetchAws: async (url, init) => { const response = await fetchAws(url, init); status = response.status; return response; } });
    code = 'INVALID';
    const credentials = awsPrivateCredentials(JSON.parse(body));
    stage('OK');
    return credentials;
  } catch {
    if (code === 'FAILED' && status !== undefined && status !== 200) code = `STATUS_${Number.isInteger(status) ? status : 0}`;
    stage(code);
    throw new Error(`AWS_REFETCH_${code}`);
  }
}
