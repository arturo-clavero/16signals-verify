import { awsPrivateCredentials, readAwsPrivateResponse } from '../../aws-private/browser-client.mjs';

/** Runs only in the isolated content world on the exact Console origin; no window.postMessage response. */
export async function readConsoleCredentials(raw: unknown, sender: { id?: string; tab?: unknown; url?: string }, deps: {
  extensionId: string; backgroundUrl: string; origin: string; top: boolean; fetchAws?: typeof fetch;
}) {
  // Rejections carry only a fixed stage code (refused, HTTP status, failed, invalid) for the background console.
  let code = 'REFUSED', status: number | undefined;
  try {
    const message = raw as { type?: unknown; url?: unknown; csrfToken?: unknown; marker?: unknown };
    if (!message || Object.keys(message).length !== 4 || typeof message.marker !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(message.marker) || message.type !== 'AWS_PRIVATE_CONSOLE_CREDENTIALS' ||
        sender.id !== deps.extensionId || sender.tab !== undefined || (sender.url && sender.url !== deps.backgroundUrl) || !deps.top ||
        typeof message.url !== 'string' || !/^https:\/\/(?:(\d{12})-[a-z0-9]{8}\.)?ap-southeast-2\.console\.aws\.amazon\.com\/cloudtrailv2\/tb\/creds$/.test(message.url) ||
        new URL(message.url).origin !== deps.origin || typeof message.csrfToken !== 'string' ||
        !message.csrfToken || message.csrfToken.length > 4096 || /[\r\n\0]/.test(message.csrfToken)) throw new Error();
    code = 'FAILED';
    const fetchAws = deps.fetchAws ?? fetch;
    const body = await readAwsPrivateResponse(message.url, { method: 'POST', mode: 'same-origin', credentials: 'include',
      headers: { 'x-csrf-token': message.csrfToken, 'x-16signals-capture': message.marker } },
      { fetchAws: async (url, init) => { const response = await fetchAws(url, init); status = response.status; return response; } });
    code = 'INVALID';
    return awsPrivateCredentials(JSON.parse(body));
  } catch {
    if (code === 'FAILED' && status !== undefined && status !== 200) code = `STATUS_${Number.isInteger(status) ? status : 0}`;
    throw new Error(`AWS_REFETCH_${code}`);
  }
}
