import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Noir } from '@noir-lang/noir_js';
import { proofRuntimeFactory } from '../gcp/proof-runtime-core.mjs';
import { loadAwsArtifacts, loadAwsVerificationKeys, pinnedAwsKey } from './artifact-registry.mjs';
import { awsCircuitInputs } from './circuit-inputs.mjs';
import { AWS_EVENT_BATCH_CIRCUITS, awsBatchToolClasses } from './event-batch.mjs';
import { identity, middleOf, other, plan, texts, wire } from './event-batch-fixture.mjs';
import { awsToolClass } from './tool-class.mjs';

// Batch row circuits with the pinned artifacts and keys on synthetic rows shaped like real LookupEvents rows:
// every rejection case must fail witness generation for the stated reason, then (unless --no-prove) one real
// proof per circuit is verified with the pinned key and its tool classes checked.
// `node event-batch-check.mjs [threads] [--no-prove]` after build-artifacts.mjs. Heavy: run under the shared lock.
const threads = Number(process.argv[2] ?? 1), prove = !process.argv.includes('--no-prove');
assert.ok(Number.isInteger(threads) && threads >= 1 && threads <= 16);
const load = file => readFile(new URL(`./dist/artifacts/${file}`, import.meta.url));
const ids = AWS_EVENT_BATCH_CIRCUITS.map(circuit => circuit.circuitId);
const artifacts = await loadAwsArtifacts(load), keys = await loadAwsVerificationKeys(load);

const noirs = Object.fromEntries(ids.map(id => [id, new Noir(artifacts[id])]));
const execute = (target, openings, tamper = inputs => inputs) =>
  noirs[target.circuitId].execute(tamper(awsCircuitInputs(target, openings)));

// Middle sizes that select each circuit: a row the narrow circuit holds, and one only the wide circuit holds.
const sizes = { 'aws-event-batch-v1': 700, 'aws-event-batch-wide-v1': 1900 };
const dryRun = `${wire('aws-cli/2.22.4')},\\"errorCode\\":${wire('Client.DryRunOperation')},\\"errorMessage\\":${wire('Request would have succeeded, but DryRun flag is set.')}`;
const failedWrite = `${wire('aws-cli/2.22.4')},\\"errorCode\\":${wire('AccessDenied')},\\"errorMessage\\":${wire(`User: ${identity.arn} is not authorized to perform: iam:UpdateAssumeRolePolicy`)}`;
// Each case changes the last row of an otherwise valid batch (or the inputs) and names the expected failure.
const cases = {
  otherUserPrincipal: [{ id: wire(other.id) }, /Actor is not the proven IAM user/],
  otherUser: [{ id: wire(other.id), arn: wire(`arn:aws:iam::${identity.account}:user/someone-else`) }, /Actor span length/],
  assumedRole: [{ id: wire('AROAEXAMPLESYNTHETIC0:session'), arn: wire(`arn:aws:sts::${identity.account}:assumed-role/admin/session`) }, /Actor span length/],
  // Same lengths as the proven identity, so only byte equality can reject them.
  otherUserSameLength: [{ id: wire(other.id), arn: wire(identity.arn.replace(/.$/, 'f')) }, /Actor is not the proven IAM user/],
  assumedRoleSameLength: [{ id: wire('AROAEXAMPLE:session'.padEnd(identity.id.length, 'x')),
    arn: wire(`arn:aws:sts::${identity.account}:assumed-role/a/`.padEnd(identity.arn.length, 'b')) }, /Actor is not the proven IAM user/],
  otherArn: [{ arn: wire(`arn:aws:iam::${identity.account}:user/someone-else`) }, /Actor span length/],
  otherAccountActor: [{ account: wire(other.account) }, /Actor is not the proven account/],
  otherAccount: [{ arn: wire(`arn:aws:iam::${other.account}:user/${identity.user}`), account: wire(other.account), recipient: wire(other.account) }, /Actor is not the proven IAM user/],
  otherRecipientAccount: [{ recipient: wire(other.account) }, /Recipient is not the proven account/],
  unquotedAccount: [{ account: identity.account }, /Actor span length/],
  keyOrderChangeActor: [{ actor: `${wire(identity.arn)},\\"principalId\\":${wire(identity.id)},\\"accountId\\":${wire(identity.account)}` }, /Actor span length/],
  keyOrderChangeBody: [{ afterUa: `,\\"sourceIPAddress\\":${wire('203.0.113.7')},\\"requestParameters\\":` }, /requestParameters must follow the user agent/],
  failedWrite: [{ ua: failedWrite }, /requestParameters must follow the user agent/],
  ec2DryRun: [{ ua: dryRun }, /requestParameters must follow the user agent/],
  errorCodeHiddenInUserAgent: [{ ua: wire('aws-cli/2.22.4\\",\\"errorCode\\":\\"Client.DryRunOperation') }, /requestParameters must follow the user agent/],
  // The same failed call claimed with the whole span as the userAgent.
  failedCallWholeSpan: [{ ua: failedWrite }, /User agent is not one plain string/, (inputs, r) => ({ ...inputs,
    ua_lengths: inputs.ua_lengths.map((n, i) => i === r ? Buffer.from(failedWrite, 'latin1').length : n) })],
  quoteInUserAgent: [{ ua: wire('aws-cli/2.22.4 "x') }, /User agent is not one plain string/],
  backslashInUserAgent: [{ ua: wire('aws-cli/2.22.4 \\\\ x') }, /User agent quotes/],
  // A body that runs into the next row, so the recipient revealed after it belongs to another event.
  recipientFromAnotherRow: [{ middle: `${middleOf(1, 300)}}","EventId":"x"},{"AccessKeyId":"y","CloudTrailEvent":"{\\"eventVersion\\":\\"1.11\\"` }, /Event body leaves the event string/],
  danglingEscapeAtBodyEnd: [{ middle: `${middleOf(1, 300)}\\` }, /Event body ends inside an escape/],
  // A chunk header spliced into a committed span (the page check also requires Content-Length framing).
  chunkedActor: [{ arn: wire(`arn:aws:iam::${identity.account}:user/batch-\r\n1f4\r\ncandidate`) }, /Actor span length/],
  identityUserIdOverCap: [{}, /Transcript byte limit/, inputs => ({ ...inputs, identity_lengths: [65, ...inputs.identity_lengths.slice(1)] })],
  identityArnOverCap: [{}, /Transcript byte limit/, inputs => ({ ...inputs, identity_lengths: [inputs.identity_lengths[0], 129, ...inputs.identity_lengths.slice(2)] })],
  identityPathOverCap: [{}, /Transcript byte limit/, inputs => ({ ...inputs, identity_lengths: [...inputs.identity_lengths.slice(0, 2), 65, inputs.identity_lengths[3]] })],
  bodyOverCap: [{}, /Transcript byte limit/, (inputs, r, cap) => ({ ...inputs,
    row_lengths: inputs.row_lengths.map((l, i) => i === r ? [l[0], cap + 1, l[2]] : l) })],
};

const result = { synthetic: true, threads, circuits: {} };
for (const circuit of AWS_EVENT_BATCH_CIRCUITS) {
  const id = circuit.circuitId, K = circuit.rows;
  const good = Array.from({ length: K }, (_, n) => texts(n, sizes[id]));
  const { openings, targets } = plan(good);
  assert.equal(targets.length, 1); assert.equal(targets[0].circuitId, id);
  const t0 = performance.now(), { returnValue } = await execute(targets[0], openings);
  const witnessMs = Math.round(performance.now() - t0);
  const expectedClasses = good.map(t => awsToolClass(`"${t.body.slice(2, t.body.indexOf('\\', 2))}"`));
  assert.deepEqual(returnValue.map(Number), expectedClasses);
  const rejected = {};
  for (const [name, [override, reason, tamper]] of Object.entries(cases)) {
    const rows = [...good.slice(0, K - 1), texts(K - 1, sizes[id], override)];
    const { openings: o, targets: t } = plan(rows);
    const target = t.find(entry => entry.circuitId === id) ?? t[0];
    let message = null;
    try { await execute(target, o, inputs => tamper ? tamper(inputs, K - 1, circuit.bodyBytes) : inputs); }
    catch (error) { message = String(error?.message ?? error); }
    assert.ok(message !== null, `${id} accepted ${name}`);
    assert.match(message, reason, `${id} ${name}: ${message}`);
    rejected[name] = message.replace(/^.*?(Circuit execution failed: )?/s, "").slice(0, 120);
  }
  // Two distinct rows: padding repeats the last row, which counts once.
  const pair = plan(good.slice(0, 2));
  assert.deepEqual(pair.targets[0].rows, K === 5 ? [0, 1, 1, 1, 1] : [0, 1, 1]);
  const padded = await execute(pair.targets[0], pair.openings), outputs = pair.targets[0].publicInputs.length - K;
  const counted = awsBatchToolClasses(pair.targets, [pair.targets[0].publicInputs.map((v, i) => v ?? padded.returnValue[i - outputs])]);
  assert.equal(counted.size, 2);
  const entry = { K, bodyBytes: circuit.bodyBytes, witnessMs, classes: expectedClasses, rejected, paddedRowsCounted: counted.size };
  if (prove) {
    const runtime = await proofRuntimeFactory({ ids: [id], invalidCode: 'INVALID', provingCode: 'PROVING_FAILED',
      keyForCircuit: pinnedAwsKey, threads })({ [id]: artifacts[id] }, keys);
    try {
      const inputs = awsCircuitInputs(targets[0], openings), hex = values => values.map(v => `0x${BigInt(v).toString(16)}`);
      const t1 = performance.now(), proof = await runtime.prove(id, inputs), provingMs = Math.round(performance.now() - t1);
      const actual = proof.publicInputs.map(value => BigInt(value));
      assert.deepEqual([...awsBatchToolClasses(targets, [actual]).values()], expectedClasses);
      const expected = targets[0].publicInputs.map((v, i) => v ?? actual[i]);
      const t2 = performance.now(); assert.equal(await runtime.verify(proof, expected), true);
      const verifyMs = Math.round(performance.now() - t2);
      // Another tool class or another row commitment fails verification.
      const wrongClass = [...expected]; wrongClass[wrongClass.length - 1] = (actual.at(-1) + 1n) % 5n;
      assert.equal(await runtime.verify({ ...proof, publicInputs: hex(wrongClass) }, wrongClass), false);
      const moved = [...expected]; moved[140] = BigInt(moved[140]) ^ 1n;
      assert.equal(await runtime.verify({ ...proof, publicInputs: hex(moved) }, moved), false);
      Object.assign(entry, { provingMs, secondsPerRow: +(provingMs / 1000 / K).toFixed(2), verifyMs, proofChars: proof.proof.length });
    } finally { await runtime.close(); }
  }
  result.circuits[id] = entry;
}
console.log(JSON.stringify({ ...result, peakRssKiB: process.resourceUsage().maxRSS }, null, 1));
