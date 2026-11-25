import { createHash, randomBytes } from 'node:crypto';
import { assembleAwsBatchExpectations } from './event-batch.mjs';

// Synthetic LookupEvents rows shaped like real ones (wire spans of the outer JSON) for the batch row circuits.
// No AWS data. `plan(rows)` commits every span with a random blinder like the TLS transcript commitments do.
export const identity = { id: 'AIDAEXAMPLESYNTHETIC01', path: '/', user: 'batch-candidate', account: '111122223333' };
identity.arn = `arn:aws:iam::${identity.account}:user${identity.path}${identity.user}`;
export const other = { id: 'AIDAEXAMPLEOTHERUSER01', account: '999988887777' };
const agents = [
  'aws-cli/2.22.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8 md/arch#x86_64 lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/prompt#off md/command#iam.update-assume-role-policy',
  'APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.32.6 ua/2.1 os/linux lang/go#1.23.3 api/iam#1.38.2',
  'console.amazonaws.com', 'Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0 os/linux#6.8 lang/python#3.12.6', 'curl/8.5.0',
];
export const wire = value => `\\"${value}\\"`;
// requestParameters through managementEvent of an IAM write, padded with spaces inside the policy string.
export const middleOf = (n, bytes) => {
  const head = `{\\"roleName\\":\\"batch-role-${n}\\",\\"policyDocument\\":\\"{\\\\\\"Version\\\\\\":\\\\\\"2012-10-17\\\\\\"`;
  const tail = `}\\"},\\"responseElements\\":null,\\"requestID\\":\\"0c3e2b1a-0000-4000-8000-00000000000${n}\\",\\"eventID\\":\\"9d1c2b3a-0000-4000-8000-00000000000${n}\\",\\"readOnly\\":false,\\"eventType\\":\\"AwsApiCall\\",\\"managementEvent\\":true`;
  return head + ' '.repeat(Math.max(0, bytes - head.length - tail.length)) + tail;
};
export const texts = (n, middleBytes, o = {}) => {
  const r = { id: wire(identity.id), arn: wire(identity.arn), account: wire(identity.account), ua: wire(agents[n % agents.length]),
    afterUa: ',\\"requestParameters\\":', middle: middleOf(n, middleBytes), recipient: wire(identity.account), ...o };
  return { actor: o.actor ?? `${r.id},\\"arn\\":${r.arn},\\"accountId\\":${r.account}`, body: `${r.ua}${r.afterUa}${r.middle}`, recipient: r.recipient };
};

let offset = 1000;
function committed(openings, text) {
  const data = Buffer.from(text, 'latin1'), preimage = Buffer.concat([data, randomBytes(16)]);
  const hash = createHash('sha256').update(preimage).digest('hex');
  openings.set(hash, Uint8Array.from(preimage));
  const slot = { hash, start: offset, end: offset + data.length }; offset = slot.end + 40;
  return slot;
}
const issuedAt = Date.parse('2026-11-24T12:00:00Z');
export function plan(rowTexts) {
  const openings = new Map();
  const ids = { UserId: identity.id, Arn: identity.arn, Path: identity.path, UserName: identity.user };
  const bindings = Object.fromEntries(Object.entries(ids).map(([name, text]) => [name, committed(openings, text)]));
  const rows = rowTexts.map(t => ({ eventSource: 'iam.amazonaws.com', eventName: 'UpdateAssumeRolePolicy', day: '2026-11-20',
    actor: committed(openings, t.actor), body: committed(openings, t.body), recipient: committed(openings, t.recipient) }));
  return { openings, targets: assembleAwsBatchExpectations(bindings, rows, { issuedAt }) };
}
