import { createHash } from 'node:crypto';
import { fixtureExpected } from './event-fixture.mjs';
import { planAwsPageSession } from './page-plan.mjs';
import { buildAwsRequest } from './request.mjs';

// Synthetic page sessions only: no AWS request, no TLS. Identity values match identityFixture().
export const PAGE_IDENTITY = Object.freeze({ principalId: 'AIDAEXAMPLESYNTHETIC01', account: '111122223333',
  userName: 'AWS_PRIVATE_USER_SENTINEL', arn: 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL' });
const DAY = 86400;
export const PAGE_AGENTS = Object.freeze({
  cli: 'aws-cli/2.22.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8 md/arch#x86_64 lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/prompt#off md/command#synthetic',
  terraform: 'APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.32.6 ua/2.1 os/linux lang/go#1.23.3',
  console: 'console.amazonaws.com',
});

/**
 * One CloudTrail event in AWS's key order. `time` in epoch seconds. Options: console (sign-in session context),
 * errorCode, noUserAgent, invokedBy, principalId/arn/account/userName overrides, host (tlsDetails host), keyExchange,
 * swapOperation (eventName before eventSource), requestParameters, region (awsRegion).
 */
export function pageEvent(index, { eventSource, eventName, time, agent = 'cli', ...options }) {
  const id = `${String(index).padStart(8, '0')}-0000-4000-8000-${String(index).padStart(12, '0')}`;
  const userIdentity = { type: options.type ?? 'IAMUser', principalId: options.principalId ?? PAGE_IDENTITY.principalId,
    arn: options.arn ?? PAGE_IDENTITY.arn, accountId: options.account ?? PAGE_IDENTITY.account,
    accessKeyId: options.console ? 'ASIAEXAMPLESYNTH0001' : 'AKIAEXAMPLESYNTH0001', userName: options.userName ?? PAGE_IDENTITY.userName,
    ...(options.console ? { sessionContext: { attributes: { creationDate: '2026-10-01T00:00:00Z', mfaAuthenticated: 'true' } } } : {}),
    ...(options.invokedBy ? { invokedBy: options.invokedBy } : {}) };
  const operation = options.swapOperation ? { eventName, eventSource } : { eventSource, eventName };
  return { eventVersion: '1.11', userIdentity, eventTime: new Date(time * 1000).toISOString().replace('.000', ''), ...operation,
    awsRegion: options.region ?? 'us-east-1', sourceIPAddress: options.console ? 'AWS Internal' : '192.0.2.10',
    ...(options.noUserAgent ? {} : { userAgent: PAGE_AGENTS[agent] ?? agent }),
    ...(options.errorCode ? { errorCode: options.errorCode, errorMessage: 'synthetic failure' } : {}),
    requestParameters: options.requestParameters ?? { resourceName: `synthetic-resource-${index}`, setting: 'x'.repeat(options.padding ?? 40) },
    responseElements: null, requestID: id, eventID: id, readOnly: options.readOnly ?? false, eventType: 'AwsApiCall',
    managementEvent: true, recipientAccountId: options.recipient ?? PAGE_IDENTITY.account, eventCategory: 'Management',
    tlsDetails: { tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256',
      clientProvidedHostHeader: options.host ?? `${eventSource.split('.')[0]}.${options.region ?? 'us-east-1'}.amazonaws.com`,
      ...(options.keyExchange ? { keyExchange: 'X25519MLKEM768' } : {}) },
    ...(options.console ? { sessionCredentialFromConsole: 'true' } : {}) };
}

export const pageRow = event => ({ AccessKeyId: event.userIdentity.accessKeyId, CloudTrailEvent: JSON.stringify(event), EventId: event.eventID,
  EventName: event.eventName, EventSource: event.eventSource, EventTime: Date.parse(event.eventTime) / 1000,
  ReadOnly: String(event.readOnly), Resources: [], Username: event.userIdentity.userName });

/**
 * A planned page session and its native-shaped receipt. `events` newest first (as AWS returns them), `select` the
 * event ids to prove (default: all). `mutate` may edit the plaintext response before planning ({ head, body }).
 * `region`: the CloudTrail endpoint the session reads.
 */
export function pageSessionFixture({ region = 'us-east-1', step = 'P0', sessionId = '33333333-3333-4333-8333-333333333333', events, start, end,
  select, issuedAt = fixtureExpected.issuedAt, headers, chunked, blinderSeed = step, mutate } = {}) {
  const expected = { ...fixtureExpected, sessionId, step, issuedAt };
  end ??= Math.floor(issuedAt / 1000); start ??= end - 89 * DAY;
  const request = buildAwsRequest({ kind: 'page', region, userName: PAGE_IDENTITY.userName, start, end });
  const serverName = new URL(request.url).hostname;
  const requestHeaders = { ...request.headers, host: serverName, 'x-amz-date': '20261029T080000Z',
    'x-amz-security-token': 'SYNTHETIC_PRIVATE_SESSION_TOKEN', 'x-tlsn-nonce': expected.nonceMac,
    authorization: 'SYNTHETIC_PRIVATE_AUTHORIZATION', 'accept-encoding': 'identity', connection: 'close' };
  const sent = Buffer.from(`POST / HTTP/1.1\r\n${Object.entries(requestHeaders).map(([name, value]) => `${name}: ${value}\r\n`).join('')}` +
    `content-length: ${Buffer.byteLength(request.body)}\r\n\r\n${request.body}`);
  let body = JSON.stringify({ Events: events.map(pageRow) });
  const responseHeaders = headers ?? [['x-amzn-requestid', 'synthetic-request-id'], ['content-type', 'application/x-amz-json-1.1'],
    ['date', 'Thu, 29 Oct 2026 08:00:00 GMT'], ['connection', 'close']];
  let head = `HTTP/1.1 200 OK\r\n${responseHeaders.map(([name, value]) => `${name}: ${value}\r\n`).join('')}`;
  ({ head, body } = mutate?.({ head, body }) ?? { head, body });
  const recv = chunked
    ? Buffer.from(`${head}transfer-encoding: chunked\r\n\r\n${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\n\r\n`)
    : Buffer.from(`${head}content-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  const meta = { step, serverName, nonceMac: expected.nonceMac };
  const { plan, privateSlots, publicRanges } = planAwsPageSession(meta, { sent: new Uint8Array(sent), recv: new Uint8Array(recv) },
    new Set(select ?? events.map(event => event.eventID)));
  return { ...nativeReceipt({ expected, sent, recv, plan, blinderSeed, serverName }), plan, privateSlots, publicRanges, plaintext: { sent, recv } };
}

/** Native-shaped receipt of a plan over full plaintext: hashed ranges get blinded commitments, gaps stay zero. */
export function nativeReceipt({ expected, sent, recv, plan, blinderSeed, serverName = 'cloudtrail.us-east-1.amazonaws.com' }) {
  const receipt = { server_name: serverName, session: { id: expected.sessionId, proofId: expected.proofId,
    pluginSha256: expected.pluginSha256, nonceMac: expected.nonceMac, step: expected.step, method: 'AWS_ACCOUNT', mode: 'Proxy' },
    config: { sent: plan.sentRangesWithHandlers, recv: plan.recvRangesWithHandlers }, results: [], transcript: {} };
  const openings = new Map(), claims = [];
  let salt = 0;
  for (const [direction, source] of [['sent', sent], ['recv', recv]]) {
    const bytes = Buffer.alloc(source.length);
    for (const range of plan[`${direction}RangesWithHandlers`]) {
      const part = source.subarray(range.start, range.end);
      if (range.handler.action.kind === 'REVEAL') {
        part.copy(bytes, range.start);
        receipt.results.push({ ...range.handler, value: part.toString('latin1') });
      } else {
        const preimage = Buffer.concat([part, createHash('sha256').update(`${blinderSeed}:${++salt}`).digest().subarray(0, 16)]);
        const hash = createHash('sha256').update(preimage).digest('hex');
        openings.set(hash, preimage);
        receipt.results.push({ ...range.handler, value: hash });
      }
    }
    receipt.transcript[direction] = bytes.toString('latin1');
    receipt.transcript[`${direction}_length`] = bytes.length;
  }
  return { receipt, expected, openings, claims };
}

/** The extension-side witness of a page session: full plaintext, native selections and openings. */
export function pageWitness({ receipt, openings, plaintext }) {
  const witness = { sessionId: receipt.session.id, serverName: receipt.server_name, step: receipt.session.step,
    proofId: receipt.session.proofId, nonceMac: receipt.session.nonceMac, selections: {}, openings: {} };
  for (const direction of ['sent', 'recv']) {
    const results = receipt.results.filter(result => result.type === direction.toUpperCase());
    witness.selections[direction] = structuredClone(receipt.config[direction]);
    witness.openings[direction] = receipt.config[direction].flatMap((range, index) => range.handler.action.kind !== 'HASH' ? [] : [{
      start: range.start, end: range.end, hash: Uint8Array.from(Buffer.from(results[index].value, 'hex')),
      blinder: Uint8Array.from(openings.get(results[index].value).subarray(range.end - range.start)) }]);
    witness[direction] = new Uint8Array(plaintext[direction]);
  }
  return witness;
}

/**
 * Claims the atom proofs give (what verifyAwsBundle derives from them): the Username value, and each client host
 * header as an escaped string (its decoded commitment is the prover's; any well-formed hash serves inspection).
 */
export function pageClaims({ receipt }) {
  return ['sent', 'recv'].flatMap(direction => {
    const results = receipt.results.filter(result => result.type === direction.toUpperCase()), text = receipt.transcript[direction];
    return receipt.config[direction].flatMap((range, index) => {
      if (range.handler.action.kind !== 'HASH') return [];
      const base = { direction: direction.toUpperCase(), start: range.start, end: range.end, hash: results[index].value };
      if (direction === 'sent' && text.slice(range.start - 17, range.start) === '"AttributeValue":') return [{ ...base, layer: 'outer', kind: 1 }];
      if (direction === 'recv' && text.slice(range.start - 30, range.start) === ',\\"clientProvidedHostHeader\\":') {
        return [{ ...base, layer: 'event', kind: 1, decodedHash: 'ab'.repeat(32), decodedLength: range.end - range.start - 2 }];
      }
      return [];
    });
  });
}
