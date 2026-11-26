// The demo server end to end, without a browser: synthetic Cloudflare sessions (the provider's own test fixtures) are
// posted as the verifier's webhooks, signed like its receipts (receipt v2, the fake test key of
// servers/verifier/src/tests/receipt-v2-vectors.json), then the proof bundle; the package that comes back must check.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import test from 'node:test';
import { checkPackage } from '../../packages/proof-check/index.mjs';
import { createDemo, proxyUrlFor } from './server.mjs';
import { PROVIDERS } from './providers.mjs';
import cloudflare from '../../private-proof/cloudflare/descriptor.mjs';
import {
  planCloudflareSession,
  cloudflarePageRows,
  inspectCloudflareSession,
} from '../../private-proof/cloudflare/session.mjs';
import {
  requestBytes,
  responseBytes,
  identityBody,
  pageBody,
} from '../../private-proof/cloudflare/session-fixture.mjs';
import { receiptFor } from '../../private-proof/cloudflare/receipt-fixture.mjs';
import {
  authenticatedCloudflareTranscript,
  cloudflareTargets,
  verifyCloudflareBundle,
} from '../../private-proof/cloudflare/verify-bundle.mjs';

const json = (url) => JSON.parse(readFileSync(new URL(url, import.meta.url), 'utf8'));
const vector = json('../../servers/verifier/src/tests/receipt-v2-vectors.json');
const did = json('../../packages/proof-check/test-fixtures/proof-package/did.json');
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]),
  format: 'der',
  type: 'pkcs8',
});
const sha = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const head = (tag, l) =>
  Buffer.concat([
    Buffer.from([tag, l.direction === 'sent' ? 0 : 1]),
    u64(l.start),
    u64(l.end - l.start),
  ]);
const b64url = (value) => Buffer.from(value).toString('base64url');
function root(hashes) {
  let level = hashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(i + 1 < level.length ? sha(Buffer.from([1]), level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}

/** What the verifier posts with an attestor key: the session's payload plus `receipt` (v2 JWS) and salted `leaves`. */
function webhookOf(receipt, verifiedAt) {
  const bytes = {
    sent: Buffer.from(receipt.transcript.sent, 'latin1'),
    recv: Buffer.from(receipt.transcript.recv, 'latin1'),
  };
  const results = {
    sent: receipt.results.filter((r) => r.type === 'SENT'),
    recv: receipt.results.filter((r) => r.type === 'RECV'),
  };
  const leaves = [],
    hashes = [];
  let n = 0;
  for (const direction of ['sent', 'recv']) {
    receipt.config[direction].forEach((range, i) => {
      const result = results[direction][i],
        salt = sha(Buffer.from(`salt-${n++}`));
      const leaf = { direction, start: range.start, end: range.end, salt: salt.toString('hex') };
      if (result.action.kind === 'HASH') {
        Object.assign(leaf, { kind: 'commit', alg: 'sha256', digest: result.value });
        hashes.push(sha(head(2, leaf), salt, Buffer.from(result.value, 'hex')));
      } else {
        leaf.kind = 'reveal';
        hashes.push(sha(head(0, leaf), salt, bytes[direction].subarray(range.start, range.end)));
      }
      leaves.push(leaf);
    });
  }
  const header = JSON.stringify({ alg: 'EdDSA', kid: vector.kid, typ: 'tlsn-receipt+jws' });
  const payload = JSON.stringify({
    v: 2,
    serverName: receipt.server_name,
    sessionId: receipt.session.id,
    proofId: receipt.session.proofId,
    verifiedAt,
    tlsnVersion: '0.1.0-alpha.15',
    root: root(hashes).toString('hex'),
    leafCount: leaves.length,
  });
  const input = `${b64url(header)}.${b64url(payload)}`;
  return { ...receipt, receipt: `${input}.${b64url(sign(null, Buffer.from(input), key))}`, leaves };
}

// The Cloudflare fixture run of test-fixtures/make-packages.mjs: identity + one audit-log page of three rows.
const issuedAt = Date.parse('2026-11-25T08:00:00Z');
const attempt = {
  provider: 'cloudflare',
  proofId: '3f2b8c1e-5d4a-4c3b-9a1f-0000000000c1',
  pluginSha256: 'c'.repeat(64),
  nonceMac: 'n'.repeat(43),
  context: { issuedAt, expiresAt: issuedAt + 900000 },
};
const base = {
  proofId: attempt.proofId,
  pluginSha256: attempt.pluginSha256,
  nonceMac: attempt.nonceMac,
  ...attempt.context,
};
const sessions = [];
{
  const expected = { ...base, sessionId: '0b8e8f0e-0000-4000-8000-0000000000c1', step: 'identity' };
  sessions.push({
    expected,
    ...receiptFor({
      sent: requestBytes('identity'),
      recv: responseBytes(identityBody()),
      plan: planCloudflareSession(
        'identity',
        requestBytes('identity'),
        responseBytes(identityBody()),
      ),
      expected,
    }),
  });
  const rows = [
    {},
    { product: 'queues', type: null },
    { product: 'workers', type: 'scripts', action: 'update', context: 'dash' },
  ];
  const body = pageBody(rows),
    starts = cloudflarePageRows(body).map((r) => r.start);
  const recv = responseBytes(
    body,
    starts.slice(1).map((s, i) => s - (i ? starts[i] : 0)),
  );
  const page = { ...base, sessionId: '0b8e8f0e-0000-4000-8000-0000000000c2', step: 'P0' };
  sessions.push({
    expected: page,
    ...receiptFor({
      sent: requestBytes('page'),
      recv,
      plan: planCloudflareSession('P0', requestBytes('page'), recv, [0, 1, 2]),
      expected: page,
    }),
  });
}
const now = issuedAt + 120000;
const inspected = sessions.map((s) =>
  inspectCloudflareSession(
    authenticatedCloudflareTranscript(s.receipt, s.expected, now),
    s.expected.step,
  ),
);
const bundle = {
  kind: cloudflare.kind,
  version: 1,
  sessionIds: sessions.map((s) => s.expected.sessionId),
  proofs: cloudflareTargets(inspected[0], inspected.slice(1)).map((t) => ({
    circuitId: t.circuitId,
    proof: Buffer.alloc(16).toString('base64'),
    publicInputs: t.publicInputs.map(String),
  })),
};
const webhooks = sessions.map((s, i) =>
  webhookOf(s.receipt, new Date(issuedAt + 60000 * (i + 1)).toISOString()),
);

// Placeholder proofs: the provider verifier's runtime accepts exact public inputs; the ZK step is not run here.
const accept = {
  verify: async (entry, expected) =>
    entry.publicInputs.every((v, i) => BigInt(v) === BigInt(expected[i])),
};
const providers = {
  ...PROVIDERS,
  cloudflare: {
    ...PROVIDERS.cloudflare,
    loadRuntime: async () => ({ runtime: accept, vk: () => Uint8Array.of(1, 2, 3) }),
  },
};
const claim = cloudflare.claimFromResult(
  await verifyCloudflareBundle({ sessions, bundle, runtime: accept, now }),
).claim;
const noBb = {
  loadBb: async () => {
    throw new Error('not installed');
  },
};

async function withDemo(fn) {
  const demo = createDemo({
    verifierUrl: 'http://localhost:17047',
    did,
    providers,
    now: () => now,
    zk: noBb,
  });
  const server = createServer(demo.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, body) => {
    const response = await fetch(
      url + path,
      body === undefined
        ? {}
        : {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          },
    );
    return {
      status: response.status,
      type: response.headers.get('content-type'),
      body: response.headers.get('content-type')?.startsWith('application/json')
        ? await response.json()
        : await response.text(),
    };
  };
  try {
    await fn({ demo, call });
  } finally {
    server.close();
  }
}

test('webhooks + bundle -> a package that checks (receipt-signature, server-name, signed-root)', () =>
  withDemo(async ({ demo, call }) => {
    demo.attempts.set(attempt.proofId, attempt);
    assert.deepEqual((await call('/webhook', webhooks[0])).body, { stored: true });
    const pending = await call('/bundle', { proofId: attempt.proofId, bundle });
    assert.equal(pending.status, 409);
    assert.deepEqual(pending.body, { error: 'RECEIPTS_PENDING', have: 1, need: 2 });
    await call('/webhook', webhooks[1]);
    assert.deepEqual(
      (await call(`/status/${attempt.proofId}`)).body.received.map((r) => r.step),
      ['identity', 'P0'],
    );

    const { status, body } = await call('/bundle', { proofId: attempt.proofId, bundle });
    assert.equal(status, 200, JSON.stringify(body));
    const pkg = body.package;
    assert.equal(pkg.provider, 'cloudflare');
    assert.equal(pkg.claim, claim);
    assert.equal(pkg.runs.length, 2);
    assert.deepEqual(pkg.runs[0].zk, bundle);
    assert.equal(pkg.runs[1].zk, undefined);
    assert.ok(
      pkg.runs.every(
        (run) => run.disclosed.length === 0 && run.hidden.length > 0 && run.commitments.length > 0,
      ),
    );
    assert.deepEqual(Object.keys(pkg.vks).sort(), Object.keys(pkg.pins).sort());
    assert.equal(body.status, 'partial'); // the ZK proofs are placeholders and bb.js is not loaded
    for (const id of ['receipt-signature', 'server-name', 'signed-root'])
      assert.match(
        body.lines.find((l) => l.includes(` ${id}:`)),
        /^ok /,
        id,
      );
    // The demo signs the claim as its issuer, so the claim check passes on that signature.
    assert.match(
      body.lines.find((l) => l.includes(' claim-from-data:')),
      /^ok .*signed by demo issuer\)$/,
    );
    assert.equal(body.lines.at(-1), `partial ${body.proofHash} ${claim}`);
    assert.equal(body.attestation.proofHash, body.proofHash);
    assert.equal(body.attestation.claim, claim);

    // The returned package checks the same way on its own; with the issuer's key from the demo's keys.json, so does the claim.
    const checked = await checkPackage(pkg, {
      providers: [cloudflare],
      keys: { dids: [did] },
      zk: noBb,
    });
    assert.deepEqual(
      checked.checks.filter((c) => c.ok === true).map((c) => c.id),
      ['receipt-signature', 'server-name', 'signed-root'],
    );
    assert.equal(checked.proofHash, body.proofHash);
    const trusted = (await call('/verify/keys.json')).body;
    const signed = await checkPackage(pkg, {
      providers: [cloudflare],
      keys: trusted,
      attestation: body.attestation,
      zk: noBb,
      now,
    });
    assert.equal(signed.checks.find((c) => c.id === 'claim-from-data').ok, true);
  }));

test('a tampered bundle, a session of another attempt and unknown attempts are refused', () =>
  withDemo(async ({ demo, call }) => {
    demo.attempts.set(attempt.proofId, attempt);
    for (const w of webhooks) await call('/webhook', w);
    const tampered = {
      ...bundle,
      proofs: bundle.proofs.map((p, i) =>
        i
          ? p
          : { ...p, publicInputs: p.publicInputs.map((v, j) => (j ? v : String(BigInt(v) + 1n))) },
      ),
    };
    const refused = await call('/bundle', { proofId: attempt.proofId, bundle: tampered });
    assert.equal(refused.status, 422);
    assert.match(refused.body.error, /Cloudflare verifier refused/);
    assert.equal(
      (await call('/bundle', { proofId: '00000000-0000-4000-8000-000000000000', bundle })).status,
      404,
    );
    assert.deepEqual(
      (
        await call('/webhook', {
          ...webhooks[0],
          session: { ...webhooks[0].session, id: 'x', proofId: 'other' },
        })
      ).body,
      { stored: false },
    );
    assert.equal((await call('/webhook', { nothing: true })).status, 400);
    const unsigned = { ...webhooks[1] };
    delete unsigned.receipt;
    await call('/webhook', unsigned);
    const noReceipt = await call('/bundle', { proofId: attempt.proofId, bundle });
    assert.equal(noReceipt.status, 422);
    assert.match(noReceipt.body.error, /no receipt/);
  }));

test('/start gives the page the run values for each provider', () =>
  withDemo(async ({ demo, call }) => {
    const fingerprint = 'ab'.repeat(32);
    for (const [provider, pluginId, method] of [
      ['gcp', 'gcp-work', 'GCP_WORK'],
      ['aws', 'aws-private-work', 'AWS_ACCOUNT'],
      ['cloudflare', 'cloudflare-private-work', 'CLOUDFLARE_ACCOUNT'],
    ]) {
      const { status, body } = await call('/start', { provider, fingerprint, windowDays: 90 });
      assert.equal(status, 200);
      const { proofId, payload } = body;
      const stored = demo.attempts.get(proofId);
      assert.match(proofId, /^[0-9a-f-]{36}$/);
      assert.match(stored.nonceMac, /^[A-Za-z0-9_-]{43}$/);
      assert.deepEqual(
        { ...payload, params: undefined },
        {
          pluginId,
          fingerprint,
          verifierUrl: 'http://localhost:17047',
          proxyUrl: 'ws://localhost:17047/proxy?token=',
          methodUrls: {
            [method]: {
              verifierUrl: 'http://localhost:17047',
              proxyUrl: 'ws://localhost:17047/proxy?token=',
            },
          },
          params: undefined,
          requestId: proofId,
          sessionData: { proofId, method, mode: 'Proxy' },
        },
      );
      if (provider === 'gcp') {
        assert.deepEqual(payload.params, {
          windowDays: 90,
          cutoff: now,
          catalogDigest: payload.params.catalogDigest,
          proofId,
          nonceMac: stored.nonceMac,
        });
        assert.deepEqual(stored.policy, { windowDays: 90, cutoff: now });
      } else {
        const extra = provider === 'aws' ? { identityService: 'iam', region: 'us-east-1' } : {};
        assert.deepEqual(payload.params, {
          privateAttempt: {
            issuedAt: now,
            expiresAt: now + 900000,
            ...extra,
            proofId,
            pluginSha256: fingerprint,
            nonceMac: stored.nonceMac,
          },
        });
        assert.deepEqual(stored.context, { issuedAt: now, expiresAt: now + 900000, ...extra });
      }
    }
    assert.equal(
      (await call('/start', { provider: 'gcp', fingerprint, windowDays: 12 })).status,
      400,
    );
    assert.equal((await call('/start', { provider: 'gcp', fingerprint: 'nope' })).status, 400);
    assert.equal((await call('/start', { provider: 'github', fingerprint })).status, 400);
    assert.equal(
      proxyUrlFor('https://verifier.example.com/base/'),
      'wss://verifier.example.com/base/proxy?token=',
    );
  }));

test('static files: the page, the verify page with the DID trusted, nothing outside the allowed folders', () =>
  withDemo(async ({ call }) => {
    const page = await call('/');
    assert.equal(page.status, 200);
    assert.match(page.body, /TLSN_RUN_BUILTIN/);
    assert.equal((await call('/verify/')).status, 200);
    assert.equal((await call('/verify/page.mjs')).type, 'text/javascript');
    assert.equal((await call('/private-proof/cloudflare/descriptor.mjs')).status, 200);
    const keys = (await call('/verify/keys.json')).body;
    assert.deepEqual(keys.dids, [did]);
    assert.deepEqual(
      keys.keys.map((key) => key.label),
      ['demo issuer'],
    );
    assert.deepEqual((await call('/did.json')).body, did);
    for (const path of [
      '/package.json',
      '/servers/verifier/Cargo.toml',
      '/private-proof/gcp/package.json/../../../package.json',
      '/examples/demo/server.mjs',
      '/%2e%2e/%2e%2e/etc/passwd',
      '/private-proof/gcp/node_modules/x.js',
    ]) {
      assert.equal((await call(path)).status, 404, path);
    }
  }));
