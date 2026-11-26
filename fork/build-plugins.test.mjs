import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { PLUGINS, bundleProblems, buildPlugins } from './build-plugins.mjs';

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
