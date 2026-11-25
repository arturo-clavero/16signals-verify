import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { pinnedAwsKey } from './artifact-registry.mjs';

const options = {
  ids: ['header-v1', 'atom-v1', 'headers-small-v1', 'atoms-small-v1', 'aws-xml-text-v1',
    'aws-escaped-atom-v1', 'aws-escaped-atoms-small-v1', 'aws-escaped-atom-small-v1', 'aws-identity-refresh-v1', 'aws-identity-link-v1', 'aws-event-link-v1', 'aws-user-agent-class-v1',
    'aws-event-batch-v1', 'aws-event-batch-wide-v1'],
  invalidCode: 'AWS_PRIVATE_PROOF_INVALID', provingCode: 'AWS_PRIVATE_PROVING_FAILED', keyForCircuit: pinnedAwsKey,
};
// Verifying a whole bundle takes about a second and also runs on the server: one thread is enough.
const verifier = proofRuntimeFactory({ ...options, threads: 1 });
// Proving dominates a check's run time. bb.js caps this at navigator.hardwareConcurrency, and falls back to one
// thread when the proving page is not cross-origin isolated (the extension manifest sets COOP/COEP for this).
const prover = proofRuntimeFactory({ ...options, threads: 16 });

/** Only the browser proof worker passes `forProving`; verifiers keep the single-thread runtime. */
export async function createAwsProofRuntime(artifacts, pinnedKeys, { forProving = false } = {}) {
  // AWS verification always requires packaged keys, including in component callers.
  pinnedAwsKey(pinnedKeys, 'aws-event-link-v1');
  return (forProving ? prover : verifier)(artifacts, pinnedKeys);
}
