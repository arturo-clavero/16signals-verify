/**
 * Tool classes proven from a CloudTrail userAgent by the aws-user-agent-class-v1 circuit, which outputs
 * only the class id. This table mirrors the circuit's patterns (tool-class.test.mjs keeps them equal);
 * changing a pattern changes the circuit and its pinned key.
 *
 * The value is the decoded JSON string, quotes included. A prefix starts right after the opening quote;
 * a token starts after the opening quote or a space. One optional `[` may follow the opening quote (S3 events
 * wrap the whole userAgent in brackets); patterns at the start then begin after it. Matches end before the
 * closing quote. The first
 * class that matches wins, in table order; id 0 means none matched and no tool is reported.
 * The userAgent is whatever the calling tool sent, so the class says which tool the request reported,
 * not who typed it.
 */
export const AWS_TOOL_CLASSES = Object.freeze([
  Object.freeze({ id: 1, tool: 'console', prefixes: Object.freeze(['console.', 'signin.amazonaws.com', 'AWS Internal', 'Mozilla/']), tokens: Object.freeze([]) }),
  Object.freeze({ id: 2, tool: 'cli', prefixes: Object.freeze(['aws-cli/']), tokens: Object.freeze([]) }),
  Object.freeze({ id: 3, tool: 'terraform', prefixes: Object.freeze([]), tokens: Object.freeze(['APN/1.0 HashiCorp/1.0 Terraform/']) }),
  Object.freeze({ id: 4, tool: 'sdk-other', prefixes: Object.freeze([]), tokens: Object.freeze(['aws-sdk-', 'Boto3/']) }),
]);

/** The tool name for a proven class id, or null for 0 (no class). */
export function awsToolName(id) {
  return AWS_TOOL_CLASSES.find(entry => entry.id === id)?.tool ?? null;
}

/** Reference classifier for tests and fixtures; the verifier trusts only the circuit output. */
export function awsToolClass(value) {
  if (typeof value !== 'string' || value.length < 2 || !value.startsWith('"')) throw new Error('AWS_TOOL_CLASS_INVALID');
  const body = value.slice(1, -1), start = body.startsWith('[') ? 1 : 0;
  const entry = AWS_TOOL_CLASSES.find(({ prefixes, tokens }) => prefixes.some(text => body.startsWith(text, start)) ||
    tokens.some(text => body.startsWith(text, start) || body.includes(` ${text}`)));
  return entry?.id ?? 0;
}
