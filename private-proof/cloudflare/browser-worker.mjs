import { loadCloudflareArtifacts, loadCloudflareVerificationKeys } from './artifact-registry.mjs';
import { createCloudflareProofRuntime } from './proof-runtime.mjs';
import { eraseCloudflareInputs } from './circuit-inputs.mjs';

let runtime, busy = false;
async function packaged(file) {
  const response = await fetch(new URL(`./artifacts/${file}`, self.location.href));
  if (!response.ok) throw new Error('CF_PRIVATE_ARTIFACT_INVALID');
  return new Uint8Array(await response.arrayBuffer());
}
self.onmessage = async ({ data }) => {
  const id = typeof data?.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(data.id) ? data.id : null;
  if (!id || busy || !data || Object.keys(data).length !== 3 || !['id', 'circuitId', 'inputs'].every(key => Object.hasOwn(data, key))) {
    eraseCloudflareInputs(data?.inputs);
    self.postMessage({ id, ok: false, error: 'CF_PRIVATE_PROVING_FAILED' });
    return;
  }
  busy = true;
  try {
    runtime ??= await createCloudflareProofRuntime(await loadCloudflareArtifacts(packaged), await loadCloudflareVerificationKeys(packaged), { forProving: true });
    const entry = await runtime.prove(data.circuitId, data.inputs);
    self.postMessage({ id, ok: true, entry });
  } catch {
    self.postMessage({ id, ok: false, error: 'CF_PRIVATE_PROVING_FAILED' });
  } finally { eraseCloudflareInputs(data.inputs); busy = false; }
};
