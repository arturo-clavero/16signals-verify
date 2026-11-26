#!/usr/bin/env node
// Usage: proof-check <attestation.json> [--bundle bundle.json] [--keys keys.json] [--config config.json] [--now <ISO time>]
// The file holds a signed attestation, or { attestation, bundle }. Providers (and keys, unless --keys) come from the
// config; the default is verify/verify.config.json in this repository. Prints one line per check.
// Exit codes: 0 all checks passed, 1 a check failed, 2 bad input.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parseDropped, verifyCommitment } from './check.mjs';
import { loadConfig } from './config.mjs';

const USAGE = 'usage: proof-check <attestation.json> [--bundle bundle.json] [--keys keys.json] [--config config.json] [--now <ISO time>]';
const DEFAULT_CONFIG = new URL('../../verify/verify.config.json', import.meta.url);
const readJson = async url => JSON.parse(await readFile(url, 'utf8'));
const exit = (code, message) => { if (message) (code === 2 ? console.error : console.log)(message); process.exit(code); };

const positional = [], options = {};
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  const match = /^--(bundle|keys|config|now)$/.exec(args[i]);
  if (match && args[i + 1] !== undefined) options[match[1]] = args[++i];
  else if (args[i].startsWith('-')) exit(2, USAGE);
  else positional.push(args[i]);
}
if (positional.length !== 1) exit(2, USAGE);

let input;
try {
  const config = await loadConfig(options.config ? pathToFileURL(options.config) : DEFAULT_CONFIG, { readJson });
  const dropped = parseDropped(await readFile(positional[0], 'utf8'));
  if (!dropped.attestation) throw new Error('expected a signed attestation');
  if (options.bundle) dropped.bundle = JSON.parse(await readFile(options.bundle, 'utf8'));
  const now = options.now === undefined ? undefined : Date.parse(options.now);
  if (Number.isNaN(now)) throw new Error('--now: not a date');
  input = { dropped, providers: config.providers, keys: options.keys ? await readJson(options.keys) : config.keys, now };
} catch (error) {
  exit(2, `proof-check: ${error.message}`);
}

let result;
try { result = await verifyCommitment(input); } catch (error) { exit(2, `proof-check: ${error.message}`); }
for (const check of result.checks) console.log(`${check.ok ? 'ok  ' : 'FAIL'} ${check.label}${check.detail ? ` (${check.detail})` : ''}`);
console.log(`${result.status} ${result.commitment}${result.claim ? ` ${result.claim}` : ''}`);
process.exitCode = result.status === 'verified' ? 0 : 1;
