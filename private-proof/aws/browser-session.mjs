import { buildAwsRequest, awsCloudTrailRegion, AWS_LIMITS, AWS_REGION } from './request.mjs';
import { parseAwsIdentity } from './console-session.mjs';
import { validateAwsAttempt } from './authenticated-transcript.mjs';
import { AWS_MAX_PAGE_SESSIONS, AWS_PAGE_STEPS } from './sessions.mjs';
import { discoverAwsRegions } from './activity-discovery.mjs';
import { rankAwsActivity, packAwsSessions } from './activity-selection.mjs';
import { AWS_PAGE_ROW_CAP } from './page-plan.mjs';
import { parseJsonStructure } from '../gcp/json-structure.mjs';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
// `stage` is a fixed diagnostic code (never a value) that the extension logs; the message stays the same for callers.
/**
 * Page runs: discovery reads (at most `pages`, started within `ms`), the proof budget in rows and the page sessions.
 * Budget and caps follow measured proving speed: about 5 s per row and 45-50 s per page session on 12 cores (a live run
 * of 3 sessions and 16 rows took 341 s; 5 sessions and 25 rows come to about 8 minutes).
 */
export const AWS_PAGE_RUN = Object.freeze({ pages: 45, ms: 50000, budget: 25, rowCap: AWS_PAGE_ROW_CAP, sessions: AWS_MAX_PAGE_SESSIONS });
// readAwsPrivateResponse stages of a discovery read that failed in transit rather than being refused.
const DISCOVERY_TRANSIENT = /^(?:NETWORK|READ|STATUS_5\d\d|LOOKUP_REFUSED_400)$/;
/** Back-off in ms before each retry of a discovery read that failed in transit (two retries). */
export const AWS_DISCOVERY_RETRIES = Object.freeze([700, 2000]);
const fail = stage => { throw Object.assign(new Error('AWS_PRIVATE_COLLECTION_FAILED'), stage ? { stage } : {}); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
const hash = async value => hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
const json = text => {
  const bytes = encoder.encode(text);
  try { parseJsonStructure(bytes); return JSON.parse(text); }
  finally { bytes.fill(0); }
};

/** Only temporary Console credentials, copied into a closed in-memory shape. */
export function awsPrivateCredentials(value, now = Date.now()) {
  const expiresAt = Date.parse(value?.expiration);
  if (!Number.isSafeInteger(now) || ['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration'].some(key => typeof value?.[key] !== 'string') ||
      !/^ASIA[A-Z0-9]{16}$/.test(value?.accessKeyId ?? '') ||
      !/^[A-Za-z0-9/+=]{40}$/.test(value?.secretAccessKey ?? '') ||
      !/^[A-Za-z0-9/+=]{16,8192}$/.test(value?.sessionToken ?? '') ||
      !Number.isSafeInteger(expiresAt) || expiresAt <= now + 60000 || expiresAt > now + 43200000) fail();
  return { accessKeyId: value.accessKeyId, secretAccessKey: value.secretAccessKey,
    sessionToken: value.sessionToken, expiration: value.expiration };
}

/** Fixed SigV4 read-request grammar, signed with the browser's WebCrypto. */
export async function signAwsPrivateRequest(options, credentials, { nonceMac, now = Date.now() }) {
  const keys = options?.kind === 'identity' ? ['kind'] : options?.kind === 'event' ? ['kind', 'eventId'] :
    ['kind', 'userName', 'start', 'end', ...(options?.region === undefined ? [] : ['region']), ...(options?.nextToken === undefined ? [] : ['nextToken'])];
  if (!exact(options, keys) || !['identity', 'event', 'discovery', 'page'].includes(options.kind) ||
      !/^[A-Za-z0-9_-]{43}$/.test(nonceMac ?? '')) fail();
  const copy = awsPrivateCredentials(credentials, now);
  const request = buildAwsRequest({ ...options, identityService: 'iam' });
  const service = options.kind === 'identity' ? 'iam' : 'cloudtrail', region = options.kind === 'identity' ? AWS_REGION : awsCloudTrailRegion(new URL(request.url).hostname) ?? fail();
  const date = new Date(now).toISOString().replace(/[:-]|\.\d{3}/g, '');
  const headers = { ...request.headers, host: new URL(request.url).hostname, 'x-amz-date': date,
    'x-amz-security-token': copy.sessionToken, 'x-16signals-nonce': nonceMac };
  const names = Object.keys(headers).sort(), signedHeaders = names.join(';');
  const scope = `${date.slice(0, 8)}/${region}/${service}/aws4_request`;
  let key = encoder.encode(`AWS4${copy.secretAccessKey}`);
  const hmac = async text => {
    const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(text)));
  };
  try {
    const canonical = ['POST', '/', '', names.map(name => `${name}:${headers[name]}\n`).join(''), signedHeaders, await hash(request.body)].join('\n');
    for (const part of [date.slice(0, 8), region, service, 'aws4_request']) {
      const next = await hmac(part); key.fill(0); key = next;
    }
    const signature = await hmac(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${await hash(canonical)}`);
    try { headers.authorization = `AWS4-HMAC-SHA256 Credential=${copy.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${hex(signature)}`; }
    finally { signature.fill(0); }
    return { ...request, headers: { ...headers, 'accept-encoding': 'identity', connection: 'close' } };
  } finally { key.fill(0); for (const name of Object.keys(copy)) copy[name] = ''; }
}

/** Bounded, cancellable browser fetch. No error body, redirect or cookie leaves this caller. */
export async function readAwsPrivateResponse(url, options, { fetchAws = fetch, signal, limit = 16384 } = {}) {
  let reader, activityAccessRequired = false, stage = 'NETWORK';
  const chunks = [];
  try {
    const response = await fetchAws(url, { ...options, redirect: 'error', cache: 'no-store',
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000) });
    stage = 'NO_BODY';
    if (!response.body) fail();
    reader = response.body.getReader();
    stage = 'REDIRECT';
    if (response.redirected) fail();
    const deniedLookup = [400, 403].includes(response.status) && /^https:\/\/[a-z0-9.-]+\/$/.test(url) &&
      awsCloudTrailRegion(new URL(url).hostname) !== null &&
      options?.headers?.['x-amz-target'] === 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents';
    stage = `STATUS_${Number.isInteger(response.status) ? response.status : 0}`;
    if (response.status !== 200 && !deniedLookup) fail();
    stage = 'READ';
    let length = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value); length += value.byteLength;
      if (length > limit) { stage = 'TOO_LARGE'; fail(); }
    }
    stage = 'ABORTED';
    if (signal?.aborted) fail();
    stage = 'DECODE';
    const bytes = new Uint8Array(length);
    try {
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const text = decoder.decode(bytes);
      if (deniedLookup) {
        const type = json(text)?.__type;
        activityAccessRequired = typeof type === 'string' && /^(?:[A-Za-z0-9_.]+#)?AccessDenied(?:Exception)?$/.test(type);
        stage = `LOOKUP_REFUSED_${response.status}`;
        fail();
      }
      return text;
    } finally { bytes.fill(0); }
  } catch {
    if (activityAccessRequired) throw new Error('AWS_ACTIVITY_ACCESS_REQUIRED');
    fail(stage);
  }
  finally { await reader?.cancel().catch(() => {}); reader?.releaseLock(); for (const chunk of chunks) chunk.fill(0); }
}

/**
 * Local selection is provisional: only the native transcripts and their ZK bundle establish a claim.
 * Discovers, ranks and packs the user's writes into page sessions (P0..).
 */
export function createAwsLocalSession({ attempt, fetchAws = fetch, now = Date.now, identityOnly = false }) {
  validateAwsAttempt(attempt, now());
  attempt = { ...attempt };
  const controller = new AbortController();
  let credentials, used = false, closed = false, pageRows, discoveryReport;
  const backOff = ms => new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(wait); reject(Object.assign(new Error('AWS_PRIVATE_COLLECTION_FAILED'), { stage: 'ABORTED' })); };
    const wait = setTimeout(() => { controller.signal.removeEventListener('abort', abort); resolve(); }, ms);
    controller.signal.addEventListener('abort', abort, { once: true });
    if (controller.signal.aborted) abort();
  });
  const clear = () => {
    closed = true; controller.abort(); clearTimeout(timer);
    if (credentials) for (const key of Object.keys(credentials)) credentials[key] = '';
    credentials = undefined;
  };
  const timer = setTimeout(clear, attempt.expiresAt - now());
  const check = () => { if (closed || controller.signal.aborted) fail(); validateAwsAttempt(attempt, now()); };
  const sign = async options => {
    check(); const signed = await signAwsPrivateRequest(options, credentials, { nonceMac: attempt.nonceMac, now: now() });
    check(); return signed;
  };
  return {
    clear,
    /**
     * After prepare() of a page run: what discovery could not read (Region names whose probe still failed in transit
     * after the retries, and whether us-east-1 was read to the end of its budget), for the extension's diagnostics.
     * Local only, never sent. Undefined before discovery.
     */
    discoveryReport: () => (discoveryReport ? structuredClone(discoveryReport) : undefined),
    /** After prepare() of a page run: the event ids each page session proves ({ P0: [...], ... }), else undefined. */
    pageRows: () => (pageRows ? structuredClone(pageRows) : undefined),
    async prepare(capture) {
      let phase = 'CHECK';
      try {
        check(); if (used) fail(); used = true;
        const accountId = capture?.accountId;
        phase = 'CREDENTIALS';
        credentials = awsPrivateCredentials(capture?.credentials, now());
        phase = 'CREDENTIALS_EXPIRE_BEFORE_ATTEMPT';
        if (Date.parse(credentials.expiration) <= attempt.expiresAt) fail();
        phase = 'ACCOUNT_ID';
        if (accountId !== undefined && !/^\d{12}$/.test(accountId)) fail();
        // LookupEvents allows 2 requests/s per account and Region: each Region (and IAM) is its own paced lane with
        // its own call cap, and lanes run in parallel.
        const lanes = new Map();
        const pause = () => new Promise((resolve, reject) => {
          const abort = () => { clearTimeout(timer); reject(new Error('AWS_PRIVATE_COLLECTION_FAILED')); };
          const timer = setTimeout(() => { controller.signal.removeEventListener('abort', abort); resolve(); }, AWS_LIMITS.intervalMs);
          controller.signal.addEventListener('abort', abort, { once: true });
          if (controller.signal.aborted) abort();
        });
        const read = (options, limit) => {
          const name = options.kind === 'identity' ? 'iam' : options.region ?? AWS_REGION;
          const lane = lanes.get(name) ?? { calls: 0, last: undefined };
          lanes.set(name, lane);
          if (lane.calls++ >= AWS_LIMITS.attempts) fail();
          const previous = lane.last;
          const call = (async () => {
            if (previous) { await previous.catch(() => {}); await pause(); }
            const request = await sign(options);
            const body = await readAwsPrivateResponse(request.url, { method: request.method, headers: request.headers, body: request.body, credentials: 'omit' },
              { fetchAws, signal: controller.signal, limit });
            check(); return body;
          })();
          lane.last = call;
          return call;
        };
        phase = 'IDENTITY_FETCH';
        const identityBody = await read({ kind: 'identity' });
        phase = 'IDENTITY_PARSE';
        const identity = parseAwsIdentity(identityBody, 'iam');
        phase = 'IDENTITY_ACCOUNT';
        if (accountId !== undefined && accountId !== identity.accountId) fail();
        if (identityOnly) { const request = await sign({ kind: 'identity' }); check(); return [request]; }
        // Local and unproven: never sent to 16signals. Only the page sessions' transcripts and proofs make a claim.
        phase = 'DISCOVERY';
        const end = Math.floor(attempt.issuedAt / 1000), userName = identity.arn.slice(identity.arn.lastIndexOf('/') + 1);
        let discoveryReads = 0;
        const discoveryRead = async options => {
          try {
            // A read that fails in transit (timeout, dropped connection, AWS 5xx or throttling) is retried with a short
            // back-off before it counts as failed, so a slow moment never silently shrinks what discovery sees.
            for (let retry = 0; ; retry++) {
              try { return await read(options, AWS_LIMITS.discoveryBytes); } catch (error) {
                if (closed || !DISCOVERY_TRANSIENT.test(error?.stage ?? '') || retry >= AWS_DISCOVERY_RETRIES.length) throw error;
                await backOff(AWS_DISCOVERY_RETRIES[retry]);
              }
            }
          } catch (error) {
            // Still failing after the retries: after the first page, discovery ends with the pages read so far (and a
            // Region probe marks the Region unread). The first read, refused access and a closed session still fail.
            if (discoveryReads && !closed && DISCOVERY_TRANSIENT.test(error?.stage ?? '')) return null;
            throw error;
          } finally { discoveryReads++; }
        };
        const discovery = await discoverAwsRegions({ read: discoveryRead, identity, end,
          maxPages: AWS_PAGE_RUN.pages, timeMs: AWS_PAGE_RUN.ms, now });
        discoveryReport = { unread: [...discovery.probe.unread], homeComplete: discovery.probe.homeComplete };
        phase = 'SELECTION';
        // The job's skill groups (server attempt state) weigh the choice and the session order; they never limit it.
        const jobGroups = Array.isArray(attempt.jobGroups) ? attempt.jobGroups : [];
        const ranking = rankAwsActivity(discovery.candidates, { budget: AWS_PAGE_RUN.budget, jobGroups, discovery });
        const { sessions } = packAwsSessions(ranking.picks, discovery, { rowCap: AWS_PAGE_RUN.rowCap, jobGroups, maxSessions: AWS_PAGE_RUN.sessions });
        phase = 'NO_EVENTS';
        if (!sessions.length) fail();
        phase = 'SIGN';
        const requests = [await sign({ kind: 'identity' })];
        for (const session of sessions) requests.push(await sign({ kind: 'page', region: session.region, userName, start: session.start, end: session.end }));
        pageRows = Object.fromEntries(sessions.map((session, index) => [AWS_PAGE_STEPS[index], [...session.eventIds]]));
        check(); return requests;
      } catch (error) {
        if (error instanceof Error && error.message === 'AWS_ACTIVITY_ACCESS_REQUIRED') throw new Error('AWS_ACTIVITY_ACCESS_REQUIRED');
        fail(typeof error?.stage === 'string' ? `${phase}_${error.stage}` : phase);
      }
      finally { clear(); }
    },
  };
}
