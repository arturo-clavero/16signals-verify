import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PLUGINS, bundleProblems, buildPlugins } from './build-plugins.mjs';
import { BATCHES, gcpBatchRequest } from '../private-proof/gcp/request.mjs';

const here = dirname(fileURLToPath(import.meta.url));

test('builds every plugin, byte-identical on a second build', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'tlsn-plugins-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const first = await buildPlugins(join(dir, 'a'));
  const second = await buildPlugins(join(dir, 'b'));
  assert.deepEqual(Object.keys(first).sort(), Object.keys(PLUGINS).sort());
  assert.deepEqual(first, second);
  assert.deepEqual(readdirSync(join(dir, 'a')).sort(), Object.keys(PLUGINS).map(id => `${id}.js`).sort());
  for (const [id, { method }] of Object.entries(PLUGINS)) {
    const code = readFileSync(join(dir, 'a', `${id}.js`), 'utf8');
    assert.deepEqual(bundleProblems(code, method), [], id);
    assert.ok(readFileSync(join(dir, 'b', `${id}.js`), 'utf8') === code, id);
  }
});

test('bundleProblems refuses folded or missing placeholders', () => {
  const ok = 'var p=JSON.parse(\'__PLUGIN_PARAMS__\'),v="__VERIFIER_URL_X__",x="__PROXY_URL_X__";export{a as default};';
  assert.deepEqual(bundleProblems(ok, 'X'), []);
  assert.match(bundleProblems(ok.replace('"__PROXY_URL_X__"', '"ws:__PROXY_URL_X__"'), 'X').join(), /PROXY_URL_X__ is not a whole/);
  assert.match(bundleProblems(ok.replace("'__PLUGIN_PARAMS__'", 'q'), 'X').join(), /__PLUGIN_PARAMS__ missing/);
  assert.match(bundleProblems(ok + 'k="HASH";', 'X').join(), /HASH/);
  assert.match(bundleProblems(ok.replace('export{a as default};', ''), 'X').join(), /no default export/);
});

test('gcp-work: the extension parses and substitutes the bundle, which loads with the run values', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'tlsn-plugins-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fingerprints = await buildPlugins(join(dir, 'plugins'));
  const parser = join(here, '../packages/extension/src/constants/builtinPlugins.ts');
  const listed = spawnSync(process.execPath, ['--no-warnings', join(here, 'builtin-plugins.mts'), parser, join(dir, 'stage'), join(dir, 'plugins')], { encoding: 'utf8' });
  assert.equal(listed.status, 0, listed.stderr);
  const index = JSON.parse(listed.stdout);
  const entry = index.find(plugin => plugin.id === 'gcp-work');
  assert.equal(entry?.sha256, fingerprints['gcp-work']);
  assert.deepEqual(index.map(plugin => plugin.id).sort(), Object.keys(PLUGINS).sort());

  const { substitutePlugin } = await import(pathToFileURL(parser).href);
  const params = { proofId: '0f8b6c1e-2d3a-4b5c-8d9e-0a1b2c3d4e5f', nonceMac: 'A'.repeat(43), windowDays: 30,
    cutoff: Date.parse('2026-01-01T00:00:00Z'), privateInput: { projectId: 'my-project-1' } };
  const code = substitutePlugin(readFileSync(join(dir, 'plugins', 'gcp-work.js'), 'utf8'), entry.layout, {
    verifierUrl: 'http://localhost:7047', proxyUrl: 'ws://localhost:7047/proxy?token=',
    methodUrls: { GCP_WORK: { verifierUrl: 'https://verifier.example', proxyUrl: 'wss://verifier.example/proxy?token=' } },
    params: JSON.stringify(params) });
  assert.ok(code);
  const opened = [];
  Object.assign(globalThis, { div: (options, children) => ({ type: 'div', options, children }), useEffect: callback => callback(),
    useState: (_key, value) => value, setState: () => {}, done: () => {}, useHeaders: () => [], prove: async () => ({}),
    openWindow: async url => { opened.push(url); } });
  t.after(() => { for (const name of ['div', 'useEffect', 'useState', 'setState', 'done', 'useHeaders', 'prove', 'openWindow']) delete globalThis[name]; });
  writeFileSync(join(dir, 'run.mjs'), code);
  const plugin = (await import(pathToFileURL(join(dir, 'run.mjs')).href)).default;
  assert.deepEqual(plugin.config.requests.map(r => [r.host, r.pathname, r.proxyUrl]), [
    ['accounts.google.com', '/ListAccounts', 'wss://verifier.example/proxy?token=accounts.google.com'],
    ['logging.clients6.google.com', '/batch', 'wss://verifier.example/proxy?token=logging.clients6.google.com']]);
  assert.match(JSON.stringify(plugin.main()), /Choose your Google account to continue/);
  assert.deepEqual(opened, ['https://accounts.google.com/AccountChooser?continue=' +
    encodeURIComponent('https://console.cloud.google.com/logs/query?project=my-project-1')]);

  // A full run from captured headers: the identity step, then one batch per catalog step, with the circuits' nonce header.
  const state = new Map(), proved = [], results = [], now = Date.now(), apiKey = 'AIza' + 'k'.repeat(35);
  const auth = `SAPISIDHASH ${Math.floor(now / 1000)}_${'a'.repeat(40)}`;
  const headers = list => Object.entries(list).map(([name, value]) => ({ name, value }));
  Object.assign(globalThis, { useEffect: () => {}, useState: (key, value) => state.has(key) ? state.get(key) : value,
    setState: (key, value) => state.set(key, value), done: result => results.push(result),
    useHeaders: () => [
      { id: '1', method: 'GET', url: 'https://accounts.google.com/CheckCookie', timestamp: now, requestHeaders: headers({ Cookie: 'LSID=x; SID=y' }) },
      { id: '2', method: 'POST', url: `https://cloudconsole-pa.clients6.google.com/v3/entityServices/LoggingEntityService/entities/LOGGING_ENTRY_SUMMARY_STREAM:get?key=${apiKey}`,
        timestamp: now, requestHeaders: headers({ Cookie: 'SID=y', Authorization: auth, 'X-Goog-AuthUser': '1', Origin: 'https://console.cloud.google.com' }) }],
    prove: async (request, options) => { proved.push({ request, options }); return options.sessionData.step === 'identity' ? { privateAccountEmail: 'dev@example.com' } : {}; } });
  plugin.main();
  await plugin.run();
  assert.deepEqual(proved.map(p => p.options.sessionData.step), ['identity', ...BATCHES.map(batch => batch.step)]);
  assert.equal(proved[0].request.url, 'https://accounts.google.com/ListAccounts?json=standard&authuser=1');
  assert.equal(proved[0].request.headers.Cookie, 'LSID=x; SID=y');
  for (const { request, options } of proved) {
    assert.equal(request.headers['x-16signals-nonce'], params.nonceMac);
    assert.equal(options.sessionData.method, 'GCP_WORK');
    assert.ok(options.proxyUrl.startsWith('wss://verifier.example/proxy?token='));
  }
  for (const [index, batch] of BATCHES.entries()) {
    const { request } = proved[index + 1];
    assert.deepEqual(request.body, gcpBatchRequest(batch.step, params, 'my-project-1', 'dev@example.com', apiKey).body);
    assert.equal(request.url, `https://logging.clients6.google.com/batch?key=${apiKey}`);
    assert.equal(request.headers.Authorization, auth);
  }
  assert.deepEqual(results, [{ kind: 'GCP_GROUPS', steps: ['identity', ...BATCHES.map(batch => batch.step)].map(step => ({ step, ok: true })) }]);
  assert.equal(state.get('apiKey'), '');
});
