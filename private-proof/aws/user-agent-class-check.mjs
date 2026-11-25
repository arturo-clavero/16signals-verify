import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { loadAwsArtifacts, loadAwsVerificationKeys, pinnedAwsKey } from './artifact-registry.mjs';
import { awsCircuitInputs } from './circuit-inputs.mjs';
import { awsToolClass } from './tool-class.mjs';

// Real proofs of the userAgent class circuit with the pinned artifact and key, on synthetic userAgents:
// `node user-agent-class-check.mjs [threads]` after build-artifacts.mjs. Heavy: run under the shared lock.
const threads = Number(process.argv[2] ?? 1);
assert.ok(Number.isInteger(threads) && threads >= 1 && threads <= 16);
const id = 'aws-user-agent-class-v1', load = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url));
const artifacts = await loadAwsArtifacts(load), keys = await loadAwsVerificationKeys(load);
const runtime = await proofRuntimeFactory({ ids: [id], invalidCode: 'INVALID', provingCode: 'PROVING_FAILED',
  keyForCircuit: pinnedAwsKey, threads })({ [id]: artifacts[id] }, keys);
const field = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const agents = [
  'console.amazonaws.com',
  'aws-cli/2.22.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8 md/arch#x86_64 lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/prompt#off md/command#iam.update-assume-role-policy',
  'APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.32.6 ua/2.1 os/linux lang/go#1.23.3 md/GOOS#linux md/GOARCH#amd64 api/iam#1.38.2',
  'Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0 os/linux#6.8 lang/python#3.12.6',
  '[aws-cli/2.42.1 md/awscrt#0.38.1 ua/2.1 os/linux md/command#s3api.put-bucket-versioning]',
  'curl/8.5.0',
  `aws-sdk-js/3.700.0 ${'x'.repeat(480)}`,
];
const results = [];
try {
  for (const agent of agents) {
    const decoded = Buffer.from(JSON.stringify(agent)), preimage = Buffer.concat([decoded, randomBytes(16)]);
    const commitment = createHash('sha256').update(preimage).digest('hex');
    const target = { circuitId: id, publicInputs: [...Buffer.from(commitment, 'hex'), decoded.length, null] };
    const inputs = awsCircuitInputs(target, new Map([[commitment, preimage]]));
    const started = performance.now(), entry = await runtime.prove(id, inputs), provingMs = performance.now() - started;
    const expected = awsToolClass(JSON.stringify(agent));
    assert.equal(BigInt(entry.publicInputs.at(-1)), BigInt(expected));
    const publicInputs = [...target.publicInputs.slice(0, -1), expected].map(field);
    assert.equal(await runtime.verify(entry, publicInputs), true);
    // Claiming any other class, or another commitment, fails verification.
    for (let other = 0; other <= 4; other++) if (other !== expected) {
      assert.equal(await runtime.verify({ ...entry, publicInputs: [...publicInputs.slice(0, -1), field(other)] },
        [...publicInputs.slice(0, -1), field(other)]), false);
    }
    const moved = [...publicInputs]; moved[0] = field(BigInt(moved[0]) ^ 1n);
    assert.equal(await runtime.verify({ ...entry, publicInputs: moved }, moved), false);
    results.push({ bytes: decoded.length, class: expected, provingMs: Math.round(provingMs) });
  }
} finally { await runtime.close(); }
console.log(JSON.stringify({ synthetic: true, circuitId: id, threads, results,
  otherClassesRejected: true, movedCommitmentRejected: true, peakRssKiB: process.resourceUsage().maxRSS }));
