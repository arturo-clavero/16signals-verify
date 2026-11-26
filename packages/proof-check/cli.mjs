#!/usr/bin/env node
// Usage: proof-check <attestation.json> [--bundle bundle.json] [--keys keys.json] [--config config.json] [--now <ISO time>]
//        proof-check --proof package.json [--did did.json] [--claim <claim>] [--attestation attestation.json]
//                    [--uid <BAS uid> [--network bsc]] [--keys keys.json] [--config config.json] [--now <ISO time>]
// The attestation file holds a signed attestation, or { attestation, bundle }. The --proof file holds a proof package,
// or { package, attestation }; --attestation adds the issuer's signed attestation of the package's claim. Providers
// (and keys, unless --keys) come from the config; the default is verify/verify.config.json in this repository. Prints
// one line per check.
// Exit codes: 0 all checks passed, 1 a check failed, 2 bad input. With --proof, attested and not-applicable lines
// never fail, and a check that could not run here (no DID document, no bb.js) also exits 2.
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parseDropped, verifyCommitment } from './check.mjs';
import { loadConfig } from './config.mjs';
import { checkPackage, packageLines } from './package/check-package.mjs';
import { closeZk } from './package/zk.mjs';

const USAGE = `usage: proof-check <attestation.json> [--bundle bundle.json] [--keys keys.json] [--config config.json] [--now <ISO time>]
       proof-check --proof package.json [--did did.json] [--claim <claim>] [--attestation attestation.json]
                   [--uid <BAS uid> [--network bsc|bsc-testnet]] [--keys keys.json] [--config config.json] [--now <ISO time>]`;
const DEFAULT_CONFIG = new URL('../../verify/verify.config.json', import.meta.url);
const readJson = async url => JSON.parse(await readFile(url, 'utf8'));
const exit = (code, message) => { if (message) (code === 2 ? console.error : console.log)(message); process.exit(code); };

const positional = [], options = {};
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  const match = /^--(bundle|keys|config|now|proof|did|claim|attestation|uid|network)$/.exec(args[i]);
  if (match && args[i + 1] !== undefined) options[match[1]] = args[++i];
  else if (args[i].startsWith('-')) exit(2, USAGE);
  else positional.push(args[i]);
}
if (positional.length !== (options.proof ? 0 : 1)) exit(2, USAGE);

let input, config;
try {
  config = await loadConfig(options.config ? pathToFileURL(options.config) : DEFAULT_CONFIG, { readJson });
  const now = options.now === undefined ? undefined : Date.parse(options.now);
  if (Number.isNaN(now)) throw new Error('--now: not a date');
  const keys = options.keys ? await readJson(options.keys) : config.keys;
  if (options.proof) {
    const dropped = parseDropped(await readFile(options.proof, 'utf8'));
    if (!dropped.package) throw new Error('expected a proof package');
    const dids = [...(keys?.dids ?? []), ...(options.did ? [await readJson(options.did)] : [])];
    const attestation = options.attestation ? await readJson(options.attestation) : dropped.attestation;
    input = { pkg: dropped.package, providers: config.providers, keys: { ...keys, dids }, claim: options.claim, attestation, now };
  } else {
    const dropped = parseDropped(await readFile(positional[0], 'utf8'));
    if (!dropped.attestation) throw new Error('expected a signed attestation');
    if (options.bundle) dropped.bundle = JSON.parse(await readFile(options.bundle, 'utf8'));
    input = { dropped, providers: config.providers, keys, now };
  }
} catch (error) {
  exit(2, `proof-check: ${error.message}`);
}

/** A BNB Chain (BAS) registry for one attestation UID, from the config's bnb registry entry. */
async function bnbRegistries() {
  if (!options.uid) return [];
  const entry = config.registries.find(item => item?.type === 'bnb');
  if (!entry?.module) throw new Error('--uid needs a bnb registry in the config');
  const [{ createPublicClient, http }, { NETWORKS, bnbRegistry }] = await Promise.all([import('viem'), import(entry.module)]);
  const network = options.network ?? entry.network ?? 'bsc-testnet';
  if (!NETWORKS[network]) throw new Error(`--network: unknown network ${network}`);
  const client = createPublicClient({ transport: http(NETWORKS[network].rpcUrl) });
  return [bnbRegistry({ uid: options.uid.toLowerCase(), client, network, now: input.now })];
}

if (options.proof) {
  let result;
  try {
    const { pkg, ...rest } = input;
    result = await checkPackage(pkg, { ...rest, registries: await bnbRegistries() });
  } catch (error) {
    await closeZk();
    exit(2, `proof-check: ${error.message}`);
  }
  await closeZk();
  for (const line of packageLines(result)) console.log(line);
  process.exitCode = result.status === 'verified' ? 0 : result.status === 'failed' ? 1 : 2;
} else {
  let result;
  try { result = await verifyCommitment(input); } catch (error) { exit(2, `proof-check: ${error.message}`); }
  for (const check of result.checks) console.log(`${check.ok ? 'ok  ' : 'FAIL'} ${check.label}${check.detail ? ` (${check.detail})` : ''}`);
  console.log(`${result.status} ${result.commitment}${result.claim ? ` ${result.claim}` : ''}`);
  process.exitCode = result.status === 'verified' ? 0 : 1;
}
