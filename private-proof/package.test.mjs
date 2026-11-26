// The published package holds exactly the descriptors' import closure, and its config loads the three providers.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { loadConfig } from '../packages/proof-check/config.mjs';
import providers, { aws, cloudflare, gcp } from './index.mjs';

const root = new URL('./', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

/** Files reached from `entry` through relative static imports, as paths relative to this folder. */
function closure(entry, seen = new Set()) {
  const path = new URL(entry, root).href.slice(root.href.length);
  if (seen.has(path)) return seen;
  seen.add(path);
  if (!path.endsWith('.mjs')) return seen;
  const source = readFileSync(new URL(path, root), 'utf8');
  for (const [, spec] of source.matchAll(
    /(?:^|\n)\s*(?:import|export)\b[^'"]*?['"](\.[^'"]+)['"]/g,
  )) {
    closure(new URL(spec, new URL(path, root)).href.slice(root.href.length), seen);
  }
  return seen;
}

test('files lists exactly the import closure of the exports, the config and the license files', () => {
  const expected = new Set([
    ...Object.values(manifest.exports)
      .filter((target) => target.endsWith('.mjs'))
      .flatMap((target) => [...closure(target)]),
    'verify.config.json',
    'LICENSE-MIT',
    'LICENSE-APACHE',
  ]);
  assert.deepEqual([...manifest.files].sort(), [...expected].sort());
});

test('the exports are the three descriptors', () => {
  assert.deepEqual(
    providers.map((descriptor) => descriptor.id),
    ['gcp', 'aws', 'cloudflare'],
  );
  assert.deepEqual([gcp.id, aws.id, cloudflare.id], ['gcp', 'aws', 'cloudflare']);
});

test('the packaged config loads the three providers with no trusted keys', async () => {
  const config = await loadConfig(new URL('verify.config.json', root), {
    readJson: async (url) => JSON.parse(await readFile(url, 'utf8')),
  });
  assert.deepEqual(
    config.providers.map((descriptor) => descriptor.id),
    ['gcp', 'aws', 'cloudflare'],
  );
  assert.deepEqual(config.keys, { keys: [] });
});
