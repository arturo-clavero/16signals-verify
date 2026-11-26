import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = join(here, '..');

// Runs build.sh against a settings file. npm, node and nargo are stubs that exit 97, so a run that gets past the
// settings checks stops at the first heavy step instead of building.
function run(t, config, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tlsn-config-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const name of ['npm', 'node', 'nargo']) {
    writeFileSync(join(bin, name), '#!/bin/sh\necho "stub $0" >&2\nexit 97\n');
    chmodSync(join(bin, name), 0o755);
  }
  const plugins = join(dir, 'plugins');
  mkdirSync(plugins);
  writeFileSync(join(plugins, 'cloudflare-private-work.js'), '');
  writeFileSync(join(dir, 'key.pub.b64'), 'AAAA\n');
  const file = join(dir, 'config.env');
  writeFileSync(file, config.replaceAll('$DIR', dir));
  const work = join(here, '.work'), hadWork = existsSync(work);
  t.after(() => { if (!hadWork && existsSync(work)) rmdirSync(work); });
  const result = spawnSync('bash', [join(here, 'build.sh')], { encoding: 'utf8', env: {
    PATH: `${bin}:/usr/bin:/bin`, HOME: dir, FORK_CONFIG: file, ...env } });
  return { status: result.status, out: result.stdout + result.stderr };
}

const production = 'FORK_KEY_FILE=$DIR/key.pub.b64\nFORK_PLUGIN_DIR=$DIR/plugins\n';

test('settings come from the file; relative paths resolve from the repository root', t => {
  const { status, out } = run(t, '# comment\n\nFORK_KEY_FILE=missing.pub.b64\r\n');
  assert.equal(status, 1);
  assert.match(out, /settings: .*config\.env/);
  assert.ok(out.includes(`FORK_KEY_FILE not found: ${join(root, 'missing.pub.b64')}`), out);
});

test('an environment variable overrides the file', t => {
  const { status, out } = run(t, 'FORK_KEY_FILE=missing.pub.b64\n', { FORK_KEY_FILE: '/nonexistent/env.pub.b64' });
  assert.equal(status, 1);
  assert.ok(out.includes('FORK_KEY_FILE not found: /nonexistent/env.pub.b64'), out);
});

test('refuses unknown settings, shell code and a missing FORK_CONFIG file', t => {
  for (const line of ['FORK_ORIGINS=https://app.example.com', 'export FORK_NAME=x', '$(touch /tmp/x)', 'PATH=/tmp']) {
    const { status, out } = run(t, line + '\n');
    assert.equal(status, 1);
    assert.match(out, /not a known KEY=value setting/);
  }
  const { status, out } = run(t, '', { FORK_CONFIG: '/nonexistent/config.env' });
  assert.equal(status, 1);
  assert.match(out, /FORK_CONFIG not found/);
});

test('a production build fails closed on missing or bad values', t => {
  const cases = [
    [production, /FORK_PRODUCT_ORIGINS is required/],
    [production + 'FORK_PRODUCT_ORIGINS=http://app.example.com\n', /must be https/],
    [production + 'FORK_PRODUCT_ORIGINS="https://app.example.com"\n', /needs FORK_CF_OAUTH_CLIENT_ID/],
    [production + 'FORK_PRODUCT_ORIGINS=https://app.example.com\nFORK_CF_OAUTH_CLIENT_ID=bad id\n', /not an OAuth client id/],
  ];
  for (const [config, message] of cases) {
    const { status, out } = run(t, config);
    assert.equal(status, 1, out);
    assert.match(out, message);
  }
  // Complete settings pass the checks and reach the first heavy step (a stub here).
  const { status, out } = run(t, production + 'FORK_PRODUCT_ORIGINS=https://app.example.com\nFORK_CF_OAUTH_CLIENT_ID=abcdefgh-12345678\n');
  assert.equal(status, 97, out);
});

test('config.example.env as is (empty values) keeps the development defaults', t => {
  const { status, out } = run(t, readFileSync(join(here, 'config.example.env'), 'utf8'));
  assert.equal(status, 97, out);
  assert.match(out, /aws-private-work and cloudflare-private-work from source/);
});

test('without FORK_PLUGIN_DIR a production build packages cloudflare-private-work, so it needs the OAuth client id', t => {
  const keyed = 'FORK_KEY_FILE=$DIR/key.pub.b64\nFORK_PRODUCT_ORIGINS=https://app.example.com\n';
  const missing = run(t, keyed);
  assert.equal(missing.status, 1, missing.out);
  assert.match(missing.out, /needs FORK_CF_OAUTH_CLIENT_ID/);
  const { status, out } = run(t, keyed + 'FORK_CF_OAUTH_CLIENT_ID=abcdefgh-12345678\n');
  assert.equal(status, 97, out);
});
