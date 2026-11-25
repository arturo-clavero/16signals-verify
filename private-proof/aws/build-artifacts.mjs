import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { findPackageJSON } from 'node:module';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';
import { loadPinnedArtifacts } from '../gcp/artifact-registry.mjs';
import packageInfo from '../gcp/package.json' with { type: 'json' };

assert.ok(process.argv.slice(2).every(arg => arg === '--update-pins'));
const backend = packageInfo.dependencies['@aztec/bb.js'];
assert.equal(JSON.parse(await readFile(findPackageJSON('@aztec/bb.js', import.meta.url))).version, backend);
const compiler = '1.0.0-beta.19+74d6be658e1ad252f87943292ba09bdd4da80bd4';
const nargo = process.env.GCP_NOIR_NARGO || 'nargo';
const version = spawnSync(nargo, ['--version'], { encoding: 'utf8' });
assert.equal(version.status, 0, 'Install the pinned Noir compiler or set GCP_NOIR_NARGO.');
assert.ok(version.stdout.includes(`noirc version = ${compiler}\n`) && version.stdout.includes('is dirty: false'), 'Wrong Noir compiler.');
const shared = await loadPinnedArtifacts(file => readFile(new URL(`../gcp/dist/artifacts/${file}`, import.meta.url)));
const artifacts = Object.fromEntries(['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1'].map(id => [id, shared[id]]));
for (const name of ['escaped-atom', 'xml-text', 'identity-refresh', 'identity-link', 'event-link', 'escaped-atoms-small', 'escaped-atom-small', 'user-agent-class', 'event-batch', 'event-batch-wide']) {
  const directory = new URL(`./circuits/${name}/`, import.meta.url);
  const result = spawnSync(nargo, ['compile'], { cwd: fileURLToPath(directory), encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, `Compilation failed for ${name}: ${result.stderr}`);
  artifacts[`aws-${name}-v1`] = JSON.parse(await readFile(new URL(`./circuits/${name}/target/aws_private_${name.replaceAll('-', '_')}.json`, import.meta.url)));
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const pins = { compiler, backend, verifierTarget: 'noir-recursive', circuits: {} }, files = [];
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, memory: { maximum: 32768 } });
try {
  for (const [id, artifact] of Object.entries(artifacts)) {
    assert.equal(artifact.noir_version, compiler);
    const content = Buffer.from(JSON.stringify({ noir_version: artifact.noir_version, abi: artifact.abi, bytecode: artifact.bytecode }) + '\n');
    assert.ok(content.length > 0 && content.length <= 10000000);
    const started = performance.now(), sha256 = hash(content), file = `${id}-${sha256}.json`;
    const key = await new UltraHonkBackend(artifact.bytecode, api).getVerificationKey({ verifierTarget: pins.verifierTarget });
    assert.ok(key instanceof Uint8Array && key.length > 0 && key.length <= 65536);
    const keySha256 = hash(key), keyFile = `${id}-${keySha256}.vk`;
    pins.circuits[id] = { file, sha256, bytes: content.length, keyFile, keySha256, keyBytes: key.length };
    files.push([file, content], [keyFile, key]);
    console.log(JSON.stringify({ circuitId: id, keySha256, keyBytes: key.length, buildMs: Math.round(performance.now() - started) }));
  }
} finally { await api.destroy(); }
const manifest = new URL('./generated/pins.json', import.meta.url);
if (process.argv.includes('--update-pins')) {
  await mkdir(new URL('./generated/', import.meta.url), { recursive: true });
  await writeFile(manifest, JSON.stringify(pins, null, 2) + '\n');
} else assert.deepEqual(pins, JSON.parse(await readFile(manifest)), 'Artifact/key change requires review before --update-pins.');
await mkdir(new URL('./dist/artifacts/', import.meta.url), { recursive: true });
for (const [file, bytes] of files) await writeFile(new URL(`./dist/artifacts/${file}`, import.meta.url), bytes);
console.log(`Built ${Object.keys(pins.circuits).length} pinned AWS circuit/key pairs.`);
