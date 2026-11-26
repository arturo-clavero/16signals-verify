#!/usr/bin/env node
// Writes a new Ed25519 attestor key for the TLS verifier as a one-line JWK file, readable by you only (mode 600).
// Prints only the public part. Refuses to overwrite an existing file.
//
//   node examples/demo/make-attestor-key.mjs [attestor-key.json]
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const file = process.argv[2] ?? 'attestor-key.json';
const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
try {
  writeFileSync(file, `${JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d })}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
} catch (error) {
  console.error(error.code === 'EEXIST' ? `${file} exists; not overwriting it` : error.message);
  process.exit(1);
}
console.log(`wrote ${file} (mode 600), public key x=${jwk.x}`);
