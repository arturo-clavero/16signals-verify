#!/usr/bin/env node
// End-to-end demo: a page that asks the extension for a private proof, a webhook for the TLS verifier's signed
// receipts, and a proof package built from both and checked. Node 22+, no dependencies, state in memory.
//
//   GET  /               the demo page                 POST /start    a new attempt: the run's values for the page
//   POST /webhook        the verifier's webhook        GET  /status/<proofId>  receipts received so far
//   POST /bundle         { proofId, bundle } -> verified, packaged and checked
//   GET  /did.json       the verifier's DID document   GET  /verify/  the verify page (with that DID trusted)
//   GET  /verify/keys.json  the trusted keys: the repository's, the verifier's DID and the demo issuer's key
//
// The demo is also the issuer: it signs an attestation of each package's claim (an Ed25519 key from ISSUER_KEY_FILE,
// a PKCS#8 PEM, or a new one at every start) and trusts its own key on the verify page.
//
//   DEMO_PORT=18474 DEMO_HOST=127.0.0.1 VERIFIER_URL=http://localhost:17047 [DID_FILE=did.json] [ISSUER_KEY_FILE=issuer.pem] \
//     node examples/demo/server.mjs
import { createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundleCommitment, buildPackage, checkPackage, createAttestation, packageHash, packageLines, signAttestation, verifierKeyId,
  webhookRun } from '../../packages/proof-check/index.mjs';
import { PROVIDERS } from './providers.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const REPO = resolve(HERE, '../..');
const STATIC = ['verify/', 'packages/proof-check/', 'private-proof/'];
const TYPES = { '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript', '.js': 'text/javascript', '.json': 'application/json', '.css': 'text/css' };
const MAX_BODY = 16 * 1024 * 1024;
const MAX_WEBHOOKS = 512;
const ATTESTATION_DAYS = 30;

class HttpError extends Error {
  constructor(status, error, extra = {}) { super(error); this.status = status; this.extra = extra; }
}

/** `ws(s)://host/proxy?token=`: the plugin appends the provider host. */
export const proxyUrlFor = verifierUrl => {
  const url = new URL(verifierUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/proxy`;
  url.search = '';
  return `${url}?token=`;
};

/** The demo issuer's key: `{ privateKeyPem, key: { id, label, publicKeyPem } }`, from a PKCS#8 Ed25519 PEM or new. */
export async function issuerKey(privateKeyPem = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' })) {
  const publicKeyPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  return { privateKeyPem, key: { id: await verifierKeyId(publicKeyPem), label: 'demo issuer', publicKeyPem } };
}

/**
 * The demo's request handler and its in-memory state. `did`: the verifier's DID document (default: `didFile`, else
 * fetched from `<verifierUrl>/.well-known/did.json`). `issuer`: the key that signs each package's claim (`issuerKey()`;
 * default: a new one). `zk`: checkPackage's ZK options.
 */
export function createDemo({ verifierUrl = 'http://localhost:17047', did, didFile, issuer, providers = PROVIDERS, now = () => Date.now(), zk } = {}) {
  const issuing = issuer ? Promise.resolve(issuer) : issuerKey();
  const attempts = new Map();   // proofId -> { provider, proofId, nonceMac, pluginSha256, context, policy?, params }
  const webhooks = new Map();   // result id (session.id) -> webhook payload
  const runtimes = new Map();   // provider -> Promise<{ runtime, vk }>
  const descriptors = Object.values(providers).map(p => p.descriptor);
  let didDocument = did ?? null;
  const proxyUrl = proxyUrlFor(verifierUrl);

  async function verifierDid() {
    if (didDocument) return didDocument;
    if (didFile) return (didDocument = JSON.parse(await readFile(didFile, 'utf8')));
    const response = await fetch(new URL('/.well-known/did.json', verifierUrl));
    if (!response.ok) throw new HttpError(502, `no DID document at ${verifierUrl}/.well-known/did.json (${response.status}): start the verifier with an attestor key`);
    return (didDocument = await response.json());
  }

  function start({ provider, fingerprint, windowDays }) {
    const p = providers[provider];
    if (!p) throw new HttpError(400, `unknown provider ${provider}`);
    if (typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)) throw new HttpError(400, 'fingerprint must be the plugin sha256 from window.tlsn.builtInPlugins');
    let started;
    try { started = p.start({ now: now(), windowDays }); } catch (error) { throw new HttpError(400, error.message); }
    // A real backend keys the nonce to its own secret; here it only has to be fresh, 32 bytes, base64url.
    const attempt = { provider, proofId: randomUUID(), nonceMac: randomBytes(32).toString('base64url'), pluginSha256: fingerprint,
      context: started.context, policy: started.policy };
    attempts.set(attempt.proofId, attempt);
    return { proofId: attempt.proofId, payload: {
      pluginId: p.pluginId, fingerprint, verifierUrl, proxyUrl, methodUrls: { [p.method]: { verifierUrl, proxyUrl } },
      params: started.params(attempt), requestId: attempt.proofId, sessionData: { proofId: attempt.proofId, method: p.method, mode: 'Proxy' },
    } };
  }

  function webhook(payload) {
    const session = payload?.session;
    if (typeof session?.id !== 'string' || typeof session.proofId !== 'string') throw new HttpError(400, 'not a verifier webhook with session.id and session.proofId');
    if (!attempts.has(session.proofId)) return { stored: false };
    if (webhooks.size >= MAX_WEBHOOKS) webhooks.delete(webhooks.keys().next().value);
    webhooks.set(session.id, payload);
    return { stored: true };
  }

  const received = proofId => [...webhooks.values()].filter(w => w.session.proofId === proofId)
    .map(w => ({ step: w.session.step ?? null, serverName: w.server_name ?? null, receipt: typeof w.receipt === 'string' }));

  async function bundle({ proofId, bundle: proofBundle }) {
    const attempt = attempts.get(proofId);
    if (!attempt) throw new HttpError(404, 'unknown proofId');
    if (!Array.isArray(proofBundle?.sessionIds) || !proofBundle.sessionIds.length) throw new HttpError(400, 'the bundle has no sessionIds');
    const p = providers[attempt.provider];
    const payloads = proofBundle.sessionIds.map(id => webhooks.get(id));
    if (payloads.some(w => !w)) throw new HttpError(409, 'RECEIPTS_PENDING', { have: payloads.filter(Boolean).length, need: payloads.length });
    if (payloads.some(w => w.session.proofId !== proofId)) throw new HttpError(400, 'a session belongs to another attempt');

    // 1. The provider's verifier: the bundle against the verifier's transcripts, bound to this attempt.
    const sessions = payloads.map(w => ({
      receipt: { server_name: w.server_name, session: w.session, config: w.config, results: w.results, transcript: w.transcript },
      expected: { ...attempt.context, sessionId: w.session.id, proofId, pluginSha256: attempt.pluginSha256, nonceMac: attempt.nonceMac, step: w.session.step },
    }));
    if (!runtimes.has(attempt.provider)) runtimes.set(attempt.provider, p.loadRuntime().catch(error => { runtimes.delete(attempt.provider); throw error; }));
    let loaded;
    try { loaded = await runtimes.get(attempt.provider); }
    catch (error) { throw new HttpError(500, `cannot load the ${p.label} circuits and keys (run npm run build:fork first): ${error.message}`); }
    let result;
    try { result = await p.verify({ sessions, bundle: proofBundle, attempt, runtime: loaded.runtime, now: now() }); }
    catch (error) { throw new HttpError(422, `the ${p.label} verifier refused the bundle: ${error.message}`); }

    // 2. The package: one run per session from its signed receipt, the ZK bundle on the first.
    let pkg;
    try {
      const runs = await Promise.all(payloads.map((w, i) => webhookRun(w, { zk: i === 0 ? proofBundle : undefined })));
      const used = [...new Set(proofBundle.proofs.map(entry => entry.circuitId))];
      pkg = await buildPackage({ descriptor: p.descriptor, claim: p.descriptor.claimFromResult(result).claim, runs,
        vks: Object.fromEntries(used.map(id => [id, loaded.vk(id)])) });
    } catch (error) { throw new HttpError(422, error.message); }

    // 3. The issuer's signed attestation of the claim, over the package hash.
    const { privateKeyPem, key } = await issuing;
    const { claim, window } = p.descriptor.claimFromResult(result);
    const fields = { provider: pkg.provider, claim, window, proofHash: await packageHash(pkg),
      ...(Object.keys(pkg.pins).length ? { vkHashes: pkg.pins } : {}) };
    const attestation = await signAttestation(createAttestation({ ...fields, commitment: await bundleCommitment(fields),
      issuedAt: new Date(now()).toISOString(), expiresAt: new Date(now() + ATTESTATION_DAYS * 86400000).toISOString() }), privateKeyPem);

    // 4. Re-checked the way any reader would.
    const checked = await checkPackage(pkg, { providers: descriptors, keys: { dids: [await verifierDid()], keys: [key] }, attestation, zk, now: now() });
    return { status: checked.status, claim: checked.claim, proofHash: checked.proofHash, lines: packageLines(checked), package: pkg, attestation };
  }

  async function serveFile(res, path) {
    const file = resolve(REPO, `.${path}`);
    const rel = file.slice(REPO.length + 1).split(sep).join('/');
    if (!file.startsWith(REPO + sep) || !STATIC.some(prefix => rel.startsWith(prefix)) || /(^|\/)(node_modules|dist)(\/|$)/.test(rel) || !TYPES[extname(file)]) {
      throw new HttpError(404, 'not found');
    }
    const body = await readFile(file).catch(() => { throw new HttpError(404, 'not found'); });
    res.writeHead(200, { 'content-type': TYPES[extname(file)] }).end(body);
  }

  async function readJson(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY) throw new HttpError(413, 'body too large');
      chunks.push(chunk);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new HttpError(400, 'not JSON'); }
  }

  const send = (res, status, value) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));

  async function handler(req, res) {
    try {
      const { pathname } = new URL(req.url, 'http://demo');
      if (req.method === 'POST') {
        if (pathname === '/start') return send(res, 200, start(await readJson(req)));
        if (pathname === '/webhook') return send(res, 200, webhook(await readJson(req)));
        if (pathname === '/bundle') return send(res, 200, await bundle(await readJson(req)));
        throw new HttpError(404, 'not found');
      }
      if (req.method !== 'GET') throw new HttpError(405, 'method not allowed');
      if (pathname === '/') return res.writeHead(200, { 'content-type': TYPES['.html'] }).end(await readFile(resolve(HERE, 'index.html')));
      if (pathname === '/config') return send(res, 200, { verifierUrl, providers: Object.fromEntries(Object.entries(providers).map(([id, p]) => [id, { label: p.label, pluginId: p.pluginId }])) });
      if (pathname === '/did.json') return send(res, 200, await verifierDid());
      if (pathname.startsWith('/status/')) return send(res, 200, { received: received(pathname.slice(8)) });
      if (pathname === '/verify') return res.writeHead(302, { location: '/verify/' }).end();
      // The verify page with the verifier's DID document and the demo issuer's key trusted, so receipts from a local
      // verifier and the claims the demo signs check there too.
      if (pathname === '/verify/keys.json') {
        const keys = JSON.parse(await readFile(resolve(REPO, 'verify/keys.json'), 'utf8'));
        return send(res, 200, { ...keys, keys: [...(keys.keys ?? []), (await issuing).key], dids: [...(keys.dids ?? []), await verifierDid()] });
      }
      return await serveFile(res, pathname.endsWith('/') ? `${pathname}index.html` : pathname);
    } catch (error) {
      if (!(error instanceof HttpError)) console.error(error);
      return send(res, error.status ?? 500, { error: error instanceof HttpError ? error.message : 'internal error', ...(error.extra ?? {}) });
    }
  }

  return { handler, attempts, webhooks };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.DEMO_PORT ?? 18474);
  const host = process.env.DEMO_HOST ?? '127.0.0.1';
  const issuer = await issuerKey(process.env.ISSUER_KEY_FILE ? await readFile(process.env.ISSUER_KEY_FILE, 'utf8') : undefined);
  const demo = createDemo({ verifierUrl: process.env.VERIFIER_URL ?? 'http://localhost:17047', didFile: process.env.DID_FILE, issuer });
  createServer(demo.handler).listen(port, host, () => {
    console.log(`demo on http://localhost:${port}/ (listening on ${host}:${port}), verifier ${process.env.VERIFIER_URL ?? 'http://localhost:17047'}`);
  });
}
