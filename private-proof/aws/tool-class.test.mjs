import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { AWS_TOOL_CLASSES, awsToolClass, awsToolName } from './tool-class.mjs';

test('the circuit patterns and class ids equal the JavaScript table', async () => {
  const source = await readFile(new URL('./circuits/lib/src/tool.nr', import.meta.url), 'utf8');
  const ids = Object.fromEntries([...source.matchAll(/^pub global ([A-Z_]+): u8 = (\d+);$/gm)].map(([, name, id]) => [name, Number(id)]));
  const patterns = [...source.matchAll(/^global ([A-Z_]+)_(PREFIX|TOKEN)_\d+: \[u8; (\d+)\] = "([^"\\]*)"\.as_bytes\(\);$/gm)];
  assert.ok(patterns.length > 0);
  const fromCircuit = {};
  for (const [, name, mode, length, text] of patterns) {
    assert.equal(Number(length), text.length);
    const entry = fromCircuit[name] ??= { id: ids[name], prefixes: [], tokens: [] };
    entry[mode === 'PREFIX' ? 'prefixes' : 'tokens'].push(text);
  }
  assert.deepEqual(fromCircuit, Object.fromEntries(AWS_TOOL_CLASSES.map(({ tool, id, prefixes, tokens }) =>
    [tool.toUpperCase().replace('-', '_'), { id, prefixes: [...prefixes], tokens: [...tokens] }])));
  assert.match(source, /if console \{ CONSOLE \} else if cli \{ CLI \} else if terraform \{ TERRAFORM \} else if sdk \{ SDK_OTHER \} else \{ 0 \}/);
});

test('classifies documented userAgent shapes like the circuit tests', () => {
  const cases = [
    ['"console.amazonaws.com"', 'console'], ['"signin.amazonaws.com"', 'console'], ['"AWS Internal"', 'console'],
    ['"Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0"', 'console'],
    ['"aws-cli/2.22.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8 md/command#iam.update-assume-role-policy"', 'cli'],
    ['"APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 aws-sdk-go-v2/1.32.6"', 'terraform'],
    ['"aws-sdk-go/1.44.0 (go1.19; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io)"', 'terraform'],
    ['"Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0"', 'sdk-other'], ['"aws-sdk-js/3.700.0 ua/2.1 api/lambda#3.700.0"', 'sdk-other'],
    ['"curl/8.5.0"', null], ['""', null], ['"aws-cl"', null], ['"aws-cli/"', 'cli'], ['"console"', null],
    ['"APN/1.0 HashiCorp/1.0 Terraform"', null], ['" aws-cli/2.22.4"', null], ['"x-aws-cli/2.22.4"', null],
    ['"curl/8 console.amazonaws.com"', null], ['"curl/8 xAPN/1.0 HashiCorp/1.0 Terraform/1.9.8"', null],
    ['"curl/8 md/aws-sdk-go"', null], ['"aws-cli/2.22.4 APN/1.0 HashiCorp/1.0 Terraform/1.9.8"', 'cli'],
    ['"curl/8 aws-sdk-go/1.0"', 'sdk-other'],
    ['"[aws-cli/2.42.1 md/awscrt#0.38.1 ua/2.1 md/command#s3api.put-bucket-versioning]"', 'cli'],
    ['"[APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) aws-sdk-go-v2/1.32.6]"', 'terraform'],
    ['"[Boto3/1.35.0 md/Botocore#1.35.0]"', 'sdk-other'], ['"[console.amazonaws.com]"', 'console'],
    ['"[[aws-cli/2.42.1]"', null], ['"["', null], ['"curl/8 [aws-cli/2.42.1"', null],
    ['"curl/8 [aws-sdk-go/1.0"', null], ['" [aws-cli/2.42.1"', null],
  ];
  for (const [value, tool] of cases) assert.equal(awsToolName(awsToolClass(value)), tool, value);
  assert.throws(() => awsToolClass('1234'), /AWS_TOOL_CLASS_INVALID/);
  assert.equal(awsToolName(5), null);
});
