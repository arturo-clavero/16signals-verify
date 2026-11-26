import { createHash, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AwsPrivateWitnessRun, AWS_PRIVATE_TIMEOUT_MS, awsPrivateAttemptParam } from '../../src/offscreen/awsPrivateWitness';
import * as awsClient from '../../src/aws-private/browser-client.mjs';
import type { AwsPrivateModule } from '../../src/aws-private/browser-client.mjs';
import type { GcpPrivateWitness } from '../../src/offscreen/gcpPrivateWitness';

const proofId = '11111111-1111-4111-8111-111111111111';
const ids = ['abcdefab-cdef-4abc-8def-abcdefabcdef', '33333333-3333-4333-8333-333333333333'];
const runData = { _autoApproved: '1', method: 'AWS_ACCOUNT', mode: 'Proxy', proofId, pluginSha256: 'a'.repeat(64) };
const attempt = () => ({ proofId, pluginSha256: runData.pluginSha256, nonceMac: 'b'.repeat(43),
  identityService: 'iam' as const, region: 'us-east-1' as const, issuedAt: Date.now(), expiresAt: Date.now() + 600_000 });
const bytes = () => new TextEncoder().encode('PRIVATE_SENTINEL');
const plan = () => Object.fromEntries(['sent', 'recv'].map(direction => [`${direction}RangesWithHandlers`, [{
  start: 0, end: bytes().length, handler: { type: direction.toUpperCase(), part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' } },
}]])) as ReturnType<AwsPrivateModule['getRevealPlan']>;
const bundle = () => ({ kind: 'AWS_PRIVATE_RESULT', version: 1, sessionIds: [...ids], proofs:
  ['aws-identity-link-v1', 'aws-event-link-v1'].map((circuitId, index) => ({ circuitId, proof: 'AQID',
    publicInputs: Array(index === 0 ? 264 : 199).fill('0') })) });
const module = (): AwsPrivateModule => ({ getRevealPlan: vi.fn(plan), selectPages: vi.fn(), clear: vi.fn(), prove: vi.fn().mockResolvedValue(bundle()) });
const buffers = (w: GcpPrivateWitness) => [w.sent, w.recv, ...[...w.openings.sent, ...w.openings.recv].flatMap(o => [o.hash, o.blinder])];
const runs: AwsPrivateWitnessRun[] = [];
const create = (local = module(), context = attempt()) => {
  const run = new AwsPrivateWitnessRun(runData, proofId, context, local); runs.push(run); return run;
};
const session = (index: number) => ({ ...runData, nonceMac: 'b'.repeat(43), step: index === 0 ? 'identity' : `E${index - 1}` });
const host = (index: number) => index === 0 ? 'iam.amazonaws.com' : 'cloudtrail.us-east-1.amazonaws.com';
async function prepare(run: AwsPrivateWitnessRun, index = 0, id = ids[index]) {
  run.begin(session(index), host(index), false);
  await run.selectRanges(id, host(index), bytes(), bytes(), () => { throw new Error('Must use AWS planner'); });
  const blinder = Array(16).fill(1), hash = createHash('sha256').update(bytes()).update(Uint8Array.from(blinder)).digest();
  const openings = { sent: [{ hash: [...hash], blinder: [...blinder] }], recv: [{ hash: [...hash], blinder: [...blinder] }] };
  const response = { results: ['SENT', 'RECV'].map(type => ({ type, part: 'ALL', action: { kind: 'HASH', algorithm: 'SHA256' }, value: hash.toString('hex') })) };
  return { openings, response, accept: () => run.accept(id, host(index), bytes(), bytes(), openings, response) };
}
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
afterEach(() => { for (const run of runs.splice(0)) run.clear(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('never collects after cancellation and erases a late credential response without fetching AWS', async () => {
  const run = create(), capture = vi.fn(); run.clear();
  await expect(run.collect(capture)).rejects.toThrow('AWS_PRIVATE_COLLECTION_FAILED');
  expect(capture).not.toHaveBeenCalled();
  const active = create(), fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  let resolve!: (value: any) => void;
  const pending = active.collect(() => new Promise(yes => { resolve = yes; }));
  active.clear();
  const credentials = { accessKeyId: 'ASIA' + 'A'.repeat(16), secretAccessKey: 's'.repeat(40),
    sessionToken: 't'.repeat(100), expiration: new Date(Date.now() + 3600000).toISOString() };
  resolve({ credentials });
  await expect(pending).rejects.toThrow('AWS_PRIVATE_COLLECTION_FAILED');
  expect(Object.values(credentials).every(value => value === '')).toBe(true);
  expect(fetch).not.toHaveBeenCalled();
});

it('takes the plugin attempt with optional job groups and hands them to the local selection', async () => {
  const base = attempt(), sha = runData.pluginSha256;
  expect(awsPrivateAttemptParam(base, proofId, sha)).toBe(base);
  const named = { ...base, jobGroups: ['lambda', 'iam-access'] };
  expect(awsPrivateAttemptParam(named, proofId, sha)).toBe(named);
  for (const bad of [{ ...base, jobGroups: [] }, { ...base, jobGroups: 'lambda' }, { ...base, jobGroups: ['Lambda'] }, { ...base, jobGroups: [1] },
    { ...base, jobGroups: Array(65).fill('lambda') }, { ...base, extra: 1 }, { ...base, proofId: ids[0] }, { ...base, pluginSha256: 'c'.repeat(64) },
    null, [base]])
    expect(() => awsPrivateAttemptParam(bad, proofId, sha)).toThrow('AWS_PRIVATE_PROVING_FAILED');
  const session = vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: vi.fn().mockResolvedValue([]), clear: vi.fn() } as never);
  await expect(create(module(), named).collect(async () => ({ credentials: {} }) as never)).rejects.toThrow();
  expect(session.mock.calls[0][0].attempt.jobGroups).toEqual(['lambda', 'iam-access']);
});

it('binds the approved private method, plugin, request, nonce, IAM service and expiry', () => {
  for (const change of [{ _autoApproved: '0' }, { method: 'AWS_WORK_POC' }, { method: 'GCP_WORK' }, { mode: 'Mpc' }, { pluginSha256: 'c'.repeat(64) }])
    expect(() => new AwsPrivateWitnessRun({ ...runData, ...change }, proofId, attempt(), module())).toThrow();
  for (const change of [{ identityService: 'sts' }, { region: 'us-west-2' }, { nonceMac: 'c'.repeat(64) }, { expiresAt: Date.now() }])
    expect(() => new AwsPrivateWitnessRun(runData, proofId, { ...attempt(), ...change } as ReturnType<typeof attempt>, module())).toThrow();
  expect(() => new AwsPrivateWitnessRun(runData, 'wrong', attempt(), module())).toThrow();
  expect(() => new AwsPrivateWitnessRun(runData, proofId, attempt(), { ...module(), getRevealPlan: undefined } as never)).toThrow();
});

it('accepts exactly identity then E0 and returns only the closed AWS bundle, clearing retained bytes', async () => {
  const local = module(); let held: Uint8Array[] = [];
  local.prove = vi.fn(async witnesses => { held = witnesses.flatMap(buffers); return bundle(); });
  const run = create(local);
  expect(Object.keys(await (await prepare(run)).accept())).toEqual(['results']);
  await (await prepare(run, 1)).accept();
  const result = await run.finish();
  expect(result).toEqual(bundle()); expect(JSON.stringify(result)).not.toContain('PRIVATE_SENTINEL');
  expect(held.length).toBeGreaterThan(0); expect(held.every(b => b.every(n => n === 0))).toBe(true);
  expect(local.clear).toHaveBeenCalledOnce();
  await expect(run.finish()).rejects.toThrow();
});

it('rejects wrong hosts, nonce, legacy steps, relay, missing sessions and UUID case aliases', async () => {
  for (const change of [{ step: 'E0' }, { step: ids[1] }, { nonceMac: 'c'.repeat(43) }])
    expect(() => create().begin({ ...session(0), ...change }, host(0), false)).toThrow();
  expect(() => create().begin(session(0), 'accounts.google.com', false)).toThrow();
  expect(() => create().begin(session(0), host(0), true)).toThrow();
  await expect(create().finish()).rejects.toThrow();
  const run = create(); await (await prepare(run)).accept();
  await expect(prepare(run, 1, ids[0].toUpperCase())).rejects.toThrow();
});

it('rejects altered native openings and results before any private proof is generated', async () => {
  for (const alter of [
    (native: Awaited<ReturnType<typeof prepare>>) => { native.openings.sent[0].blinder[0] ^= 1; },
    (native: Awaited<ReturnType<typeof prepare>>) => { native.openings.sent.push(native.openings.sent[0]); },
    (native: Awaited<ReturnType<typeof prepare>>) => { native.response.results[0].value = 'a'.repeat(64); },
  ]) {
    const local = module(), run = create(local), native = await prepare(run); alter(native);
    await expect(native.accept()).rejects.toThrow(); expect(local.prove).not.toHaveBeenCalled(); run.clear();
  }
});

it('rejects transplanted session IDs and private fields from the compiled module', async () => {
  for (const result of [{ ...bundle(), sessionIds: [...ids].reverse() }, { ...bundle(), witness: 'PRIVATE_SENTINEL' }]) {
    const local = module(); local.prove = vi.fn().mockResolvedValue(result);
    const run = create(local); await (await prepare(run)).accept(); await (await prepare(run, 1)).accept();
    await expect(run.finish()).rejects.toThrow(); expect(local.clear).toHaveBeenCalledOnce();
  }
});

it('clears pending planner copies at the earlier attempt or absolute thirteen-minute expiry', async () => {
  vi.useFakeTimers();
  for (const lifetime of [1000, 900_000]) {
    const local = module(); let copies: { sent: Uint8Array; recv: Uint8Array } | undefined, resolve!: (value: ReturnType<typeof plan>) => void;
    local.getRevealPlan = vi.fn((_session, value) => { copies = value; return new Promise(yes => { resolve = yes; }); }) as never;
    const run = create(local, { ...attempt(), expiresAt: Date.now() + lifetime });
    run.begin(session(0), host(0), false);
    const pending = expect(run.selectRanges(ids[0], host(0), bytes(), bytes(), () => { throw new Error(); })).rejects.toThrow();
    if (lifetime > 300_000) {
      vi.advanceTimersByTime(300_000);
      expect(local.clear).not.toHaveBeenCalled();
      expect(copies!.sent.some(n => n !== 0)).toBe(true);
    }
    vi.advanceTimersByTime(Math.min(lifetime, AWS_PRIVATE_TIMEOUT_MS) - (lifetime > 300_000 ? 300_000 : 0));
    expect(copies!.sent.every(n => n === 0) && copies!.recv.every(n => n === 0)).toBe(true);
    expect(local.clear).toHaveBeenCalledOnce(); resolve(plan()); await pending;
  }
});

it('cancellation settles a hung module and erases its witness copies', async () => {
  const local = module(); let held: Uint8Array[] = [], signal!: AbortSignal;
  local.prove = vi.fn((witnesses, current) => { held = witnesses.flatMap(buffers); signal = current; return new Promise(() => {}); });
  const run = create(local); await (await prepare(run)).accept(); await (await prepare(run, 1)).accept();
  const pending = expect(run.finish()).rejects.toThrow(); run.clear(); await pending;
  expect(signal.aborted).toBe(true); expect(held.every(b => b.every(n => n === 0))).toBe(true);
});


it('uses the locally discovered group count and rejects truncated results', async () => {
  const allIds = [...ids, ...Array.from({ length: 8 }, (_, index) => `4444444${index}-4444-4444-8444-444444444444`)];
  for (let count = 2; count <= awsClient.AWS_SESSION_STEPS.length; count++) {
    const prepareCollection = vi.fn().mockResolvedValue(Array.from({ length: count }, () => ({})));
    vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: prepareCollection, clear: vi.fn() } as never);
    for (const truncated of [false, ...(count > 2 ? [true] : [])]) {
      const result = { ...bundle(), sessionIds: allIds.slice(0, truncated ? count - 1 : count) };
      const local = module(); local.prove = vi.fn().mockResolvedValue(result);
      const run = create(local), credentials = { secretAccessKey: 'PRIVATE_SENTINEL' };
      expect(await run.collect(async () => ({ credentials }) as never)).toHaveLength(count);
      expect(credentials.secretAccessKey).toBe('');
      for (let index = 0; index < count; index++) await (await prepare(run, index, allIds[index])).accept();
      if (truncated) await expect(run.finish()).rejects.toThrow();
      else expect(await run.finish()).toEqual(result);
      expect(local.clear).toHaveBeenCalledOnce();
    }
    vi.restoreAllMocks();
  }
});

it('rejects an invalid discovered count and erases captured credentials', async () => {
  for (const count of [0, 1, awsClient.AWS_SESSION_STEPS.length + 1]) {
    vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({
      prepare: vi.fn().mockResolvedValue(Array(count).fill({})), clear: vi.fn(),
    } as never);
    const run = create(), credentials = { secretAccessKey: 'PRIVATE_SENTINEL' };
    await expect(run.collect(async () => ({ credentials }) as never)).rejects.toThrow('AWS_PRIVATE_COLLECTION_FAILED');
    expect(credentials.secretAccessKey).toBe('');
    vi.restoreAllMocks();
  }
});


it('retains only a fixed collection-permission flag while erasing captured credentials', async () => {
  for (const failure of [new Error('AWS_ACTIVITY_ACCESS_REQUIRED'), new Error('PRIVATE_ARN_SENTINEL'), { message: 'AWS_ACTIVITY_ACCESS_REQUIRED' }]) {
    const clear = vi.fn();
    vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: vi.fn().mockRejectedValue(failure), clear } as never);
    const run = create(), credentials = { secretAccessKey: 'PRIVATE_CREDENTIAL_SENTINEL' };
    const denied = failure instanceof Error && failure.message === 'AWS_ACTIVITY_ACCESS_REQUIRED';
    await expect(run.collect(async () => ({ credentials }) as never)).rejects.toThrow(denied ? 'AWS_ACTIVITY_ACCESS_REQUIRED' : 'AWS_PRIVATE_COLLECTION_FAILED');
    expect(credentials.secretAccessKey).toBe('');
    run.clear();
    expect(clear).toHaveBeenCalledOnce();
    expect(run.activityAccessRequired).toBe(denied);
    vi.restoreAllMocks();
  }
});

it('Fast collects only IAM and completes exactly one fresh session', async () => {
  const prepareCollection = vi.fn().mockResolvedValue([{}]);
  const collect = vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: prepareCollection, clear: vi.fn() } as never);
  const result = { ...bundle(), sessionIds: ids.slice(0, 1) };
  const local = { ...module(), fastCheck: true, prove: vi.fn().mockResolvedValue(result) };
  const run = create(local), credentials = { secretAccessKey: 'PRIVATE_SENTINEL' };
  expect(await run.collect(async () => ({ credentials }) as never)).toHaveLength(1);
  expect(collect).toHaveBeenCalledWith(expect.objectContaining({ identityOnly: true }));
  expect(credentials.secretAccessKey).toBe('');
  await (await prepare(run)).accept();
  expect(await run.finish()).toEqual(result);
});

it('logs one fixed collection stage code to the offscreen console, never a value', async () => {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const cases: Array<[string, () => unknown, () => Promise<unknown>]> = [
    ['AWS_OFF_PREPARE_CREDENTIALS_EXPIRE_BEFORE_ATTEMPT', () => vi.fn().mockRejectedValue(Object.assign(new Error('AWS_PRIVATE_COLLECTION_FAILED'),
      { stage: 'CREDENTIALS_EXPIRE_BEFORE_ATTEMPT' })), async () => ({ credentials: { secretAccessKey: 'PRIVATE_SENTINEL' } })],
    ['AWS_OFF_PREPARE_UNSPECIFIED', () => vi.fn().mockRejectedValue(Object.assign(new Error('x'), { stage: 'PRIVATE SENTINEL value' })),
      async () => ({ credentials: {} })],
    ['AWS_OFF_CAPTURE_FAILED', () => vi.fn(), async () => { throw new Error('AWS_PRIVATE_COLLECTION_FAILED'); }],
    ['AWS_OFF_COLLECT_COUNT_0', () => vi.fn().mockResolvedValue([]), async () => ({ credentials: {} })],
  ];
  for (const [code, prepare, capture] of cases) {
    vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: prepare(), clear: vi.fn() } as never);
    warn.mockClear();
    await expect(create().collect(capture as never)).rejects.toThrow();
    expect(warn.mock.calls).toEqual([[code]]);
  }
  vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ prepare: vi.fn().mockResolvedValue([{}, {}]), clear: vi.fn() } as never);
  warn.mockClear();
  await create().collect(async () => ({ credentials: {} }) as never);
  expect(warn.mock.calls).toEqual([['AWS_OFF_COLLECT_OK_2']]);
  vi.restoreAllMocks();
});

it('page runs: P0.. steps, the local row selection handed to the planner, gaps only in a page response', async () => {
  const pageBody = JSON.stringify({ LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: 'x' }] });
  const rows = { P0: ['00000000-0000-4000-8000-000000000001'], P1: ['00000000-0000-4000-8000-000000000002'] };
  vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ clear: vi.fn(), pageRows: () => rows,
    prepare: vi.fn().mockResolvedValue([{}, { body: pageBody }, { body: pageBody }]) } as never);
  // A page response: the plan authenticates its first bytes and leaves the rest a gap.
  const page = new Uint8Array(200_000).fill(65), head = 16;
  const local = module();
  local.getRevealPlan = vi.fn((meta: { step: string }) => (meta.step === 'identity' ? plan() : {
    sentRangesWithHandlers: [{ start: 0, end: bytes().length, handler: { type: 'SENT', part: 'ALL', action: { kind: 'REVEAL' } } }],
    recvRangesWithHandlers: [{ start: 0, end: head, handler: { type: 'RECV', part: 'BODY', action: { kind: 'REVEAL' } } }],
  })) as never;
  const sessionIds = [ids[0], '44444440-4444-4444-8444-444444444444', '44444441-4444-4444-8444-444444444444'];
  local.prove = vi.fn().mockResolvedValue({ ...bundle(), sessionIds });
  const run = create(local);
  expect(run.recvLimit('P0')).toBe(307200);
  expect(run.recvLimit('E0')).toBe(16384);
  expect(await run.collect(async () => ({ credentials: {} }) as never)).toHaveLength(3);
  expect(local.selectPages).toHaveBeenCalledWith(rows);
  await (await prepare(run, 0)).accept();
  for (const [index, step] of ['P0', 'P1'].entries()) {
    run.begin({ ...runData, nonceMac: 'b'.repeat(43), step }, host(1), false);
    await run.selectRanges(sessionIds[index + 1], host(1), bytes(), page, () => { throw new Error('Must use AWS planner'); });
    const text = new TextDecoder().decode(page.subarray(0, head));
    await run.accept(sessionIds[index + 1], host(1), bytes(), page, { sent: [], recv: [] }, { results: [
      { type: 'SENT', part: 'ALL', action: { kind: 'REVEAL' }, value: new TextDecoder().decode(bytes()) },
      { type: 'RECV', part: 'BODY', action: { kind: 'REVEAL' }, value: text }] });
  }
  expect(await run.finish()).toEqual({ ...bundle(), sessionIds });
  // An event step keeps full coverage and the small limit.
  const strict = create();
  vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ clear: vi.fn(), prepare: vi.fn().mockResolvedValue([{}, {}]) } as never);
  await strict.collect(async () => ({ credentials: {} }) as never);
  await (await prepare(strict, 0)).accept();
  strict.begin(session(1), host(1), false);
  await expect(strict.selectRanges(ids[1], host(1), bytes(), page, () => plan() as never)).rejects.toThrow();
});

it('page sessions must reach the CloudTrail host of their own Region', async () => {
  const pageBody = JSON.stringify({ LookupAttributes: [{ AttributeKey: 'Username', AttributeValue: 'x' }] });
  const page = (url: string) => ({ url, body: pageBody });
  vi.spyOn(awsClient, 'createAwsLocalSession').mockReturnValue({ clear: vi.fn(), pageRows: () => ({ P0: ['00000000-0000-4000-8000-000000000001'], P1: ['00000000-0000-4000-8000-000000000002'] }),
    prepare: vi.fn().mockResolvedValue([{}, page('https://cloudtrail.eu-west-1.amazonaws.com/'), page('https://cloudtrail.attacker.invalid/')]) } as never);
  const run = create();
  await run.collect(async () => ({ credentials: {} }) as never);
  await (await prepare(run, 0)).accept();
  // P0 reads eu-west-1: the us-east-1 host is refused, the eu-west-1 host accepted.
  expect(() => run.begin({ ...runData, nonceMac: 'b'.repeat(43), step: 'P0' }, 'cloudtrail.us-east-1.amazonaws.com', false)).toThrow();
  const other = create();
  await other.collect(async () => ({ credentials: {} }) as never);
  await (await prepare(other, 0)).accept();
  expect(() => other.begin({ ...runData, nonceMac: 'b'.repeat(43), step: 'P0' }, 'cloudtrail.eu-west-1.amazonaws.com', false)).not.toThrow();
  vi.restoreAllMocks();
});
