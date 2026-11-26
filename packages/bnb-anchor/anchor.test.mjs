import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { encodeAbiParameters, encodeEventTopics, zeroHash } from 'viem';
import { createAttestation, signAttestation, verifierKeyId } from '../proof-check/attestation.mjs';
import { bundleCommitment } from '../proof-check/commitment.mjs';
import { BAS_ABI, NETWORKS, SCHEMA_UID, anchorRequest, bnbRegistry, decodeAnchor, publishAnchor, readAnchor } from './anchor.mjs';
import { verifyCommitment } from '../proof-check/index.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
const keys = { keys: [{ id: await verifierKeyId(pem.publicKey), label: 'test', publicKeyPem: pem.publicKey }] };
const NOW = Date.now();
const fields = { provider: 'cloudflare', claim: 'cloudflare:groups:1,3:user', window: 90, proofHash: 'c'.repeat(64) };
const signed = await signAttestation(createAttestation({ ...fields, commitment: await bundleCommitment(fields),
  issuedAt: new Date(NOW - 60000).toISOString(), expiresAt: new Date(NOW + 86400000).toISOString() }), pem.privateKey);
const UID = `0x${'ab'.repeat(32)}`;
const record = (overrides = {}) => ({ uid: UID, schema: SCHEMA_UID, time: BigInt(Math.floor(NOW / 1000)), expirationTime: anchorRequest(signed).data.expirationTime,
  revocationTime: 0n, refUID: zeroHash, recipient: `0x${'0'.repeat(40)}`, attester: `0x${'1'.repeat(40)}`, revocable: true,
  data: anchorRequest(signed).data.data, ...overrides });
const chain = (rec = record()) => ({ readContract: async ({ address, functionName, args }) => {
  assert.equal(address, NETWORKS['bsc-testnet'].bas);
  assert.equal(functionName, 'getAttestation');
  return args[0] === UID ? rec : { ...rec, uid: zeroHash };
} });

test('the request carries the commitment, claim and the signed attestation, and expires with it', () => {
  const request = anchorRequest(signed);
  assert.equal(request.schema, SCHEMA_UID);
  assert.equal(request.data.expirationTime, BigInt(Math.floor(Date.parse(signed.expiresAt) / 1000)));
  assert.deepEqual(decodeAnchor(record(), { now: NOW }).attestation, signed);
  assert.throws(() => anchorRequest({ ...signed, sig: undefined }), /unsigned/);
  assert.throws(() => anchorRequest({ ...signed, email: 'x' }), /ATTESTATION_INVALID/);
});

test('reading rejects other schemas, revoked records and fields that disagree with the signed attestation', async () => {
  assert.equal((await readAnchor({ uid: UID, client: chain(), now: NOW })).attestation.claim, fields.claim);
  assert.equal(await readAnchor({ uid: `0x${'cd'.repeat(32)}`, client: chain(), now: NOW }), null);
  await assert.rejects(readAnchor({ uid: UID, client: chain(record({ schema: zeroHash })) }), /schema/);
  await assert.rejects(readAnchor({ uid: UID, client: chain(record({ revocationTime: 5n })) }), /revoked/);
  const tampered = encodeAbiParameters([{ type: 'bytes32' }, { type: 'string' }, { type: 'string' }, { type: 'uint16' }, { type: 'string' }],
    [`0x${signed.commitment}`, 'cloudflare', 'cloudflare:groups:1,2,3:user', 90, JSON.stringify(signed)]);
  await assert.rejects(readAnchor({ uid: UID, client: chain(record({ data: tampered })) }), /fields/);
  await assert.rejects(readAnchor({ uid: 'nope', client: chain() }), /uid/);
});

test('the registry plugs into proof-check and an anchored attestation checks end to end', async () => {
  const registries = [bnbRegistry({ uid: UID, client: chain(), now: NOW })];
  const providers = [{ id: 'cloudflare' }];
  const result = await verifyCommitment({ commitment: signed.commitment, keys, providers, registries, now: NOW });
  assert.equal(result.status, 'signature-only');
  assert.equal(result.claim, fields.claim);
  const other = await verifyCommitment({ commitment: 'f'.repeat(64), keys, providers, registries, now: NOW });
  assert.equal(other.status, 'not-found');
});

test('the registry finds the anchored attestation by the proof hash it names', async () => {
  const registry = bnbRegistry({ uid: UID, client: chain(), now: NOW });
  assert.deepEqual(await registry.findByProofHash({ proofHash: fields.proofHash }), [signed]);
  assert.deepEqual(await registry.findByProofHash({ proofHash: 'd'.repeat(64) }), []);
});

test('publishing sends attest to BAS and returns the uid from its Attested event', async () => {
  const bas = NETWORKS['bsc-testnet'].bas;
  let sent;
  const wallet = { writeContract: async call => { sent = call; return '0xtx'; } };
  const topics = encodeEventTopics({ abi: BAS_ABI, eventName: 'Attested', args: { recipient: `0x${'0'.repeat(40)}`, attester: `0x${'1'.repeat(40)}`, schemaUID: SCHEMA_UID } });
  const log = { address: bas, topics, data: encodeAbiParameters([{ type: 'bytes32' }], [UID]), blockNumber: 1n, logIndex: 0, transactionHash: '0xtx', transactionIndex: 0, blockHash: zeroHash, removed: false };
  const client = { waitForTransactionReceipt: async () => ({ status: 'success', logs: [log] }) };
  assert.deepEqual(await publishAnchor({ signed, wallet, client }), { uid: UID, txHash: '0xtx' });
  assert.equal(sent.address, bas);
  assert.equal(sent.functionName, 'attest');
  await assert.rejects(publishAnchor({ signed, wallet, client: { waitForTransactionReceipt: async () => ({ status: 'reverted', logs: [] }) } }), /reverted/);
});
