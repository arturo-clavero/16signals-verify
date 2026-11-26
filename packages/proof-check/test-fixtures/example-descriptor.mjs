// A minimal provider for the tests: its claim is the first public input of its single circuit.
export default {
  id: 'example',
  kind: 'EXAMPLE_RESULT',
  pins: { circuits: { 'example-v1': { sha256: 'e'.repeat(64) } } },
  claim: bundle => ({ claim: `example:value-${bundle.proofs[0].publicInputs[0]}`, window: 30 }),
  describe: ({ claim }) => `Example: ${claim.slice('example:'.length)}.`,
};
