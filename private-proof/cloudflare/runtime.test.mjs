import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { loadCloudflareArtifacts, loadCloudflareVerificationKeys } from './artifact-registry.mjs';
import { createCloudflareProofRuntime } from './proof-runtime.mjs';
import { CF_CIRCUITS } from './verify-bundle.mjs';

// The runtime the server verifier and the browser worker use accepts exactly the pinned artifact set.
test('runtime: the pinned artifacts and keys cover every target circuit', { skip: !(await readFile(new URL('./generated/pins.json', import.meta.url)).catch(() => null)) }, async () => {
  const load = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url)).then(b => new Uint8Array(b));
  const artifacts = await loadCloudflareArtifacts(load), keys = await loadCloudflareVerificationKeys(load);
  assert.deepEqual(Object.keys(artifacts).sort(), Object.keys(CF_CIRCUITS).sort());
  const runtime = await createCloudflareProofRuntime(artifacts, keys);
  await runtime.close?.();
});
