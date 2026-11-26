import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { pinnedCloudflareKey } from './artifact-registry.mjs';
import { CF_CIRCUITS } from './verify-bundle.mjs';

const options = {
  // One source of truth: every circuit a target can name (verify-bundle.mjs).
  ids: Object.keys(CF_CIRCUITS),
  invalidCode: 'CF_PRIVATE_PROOF_INVALID', provingCode: 'CF_PRIVATE_PROVING_FAILED', keyForCircuit: pinnedCloudflareKey,
};
// Verifying runs on the server too: one thread. Proving runs in the extension's isolated worker: up to 16 threads.
const verifier = proofRuntimeFactory({ ...options, threads: 1 });
const prover = proofRuntimeFactory({ ...options, threads: 16 });

/** Only the browser proof worker passes `forProving`; verifiers keep the single-thread runtime. */
export async function createCloudflareProofRuntime(artifacts, pinnedKeys, { forProving = false } = {}) {
  pinnedCloudflareKey(pinnedKeys, 'cf-actor-v1');
  return (forProving ? prover : verifier)(artifacts, pinnedKeys);
}
