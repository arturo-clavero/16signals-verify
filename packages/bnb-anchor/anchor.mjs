// Anchors signed attestations on BNB Chain through BAS and reads them back.
import { decodeAbiParameters, encodeAbiParameters, encodePacked, keccak256, parseAbiParameters, zeroAddress, zeroHash } from 'viem';
import { attestationShape } from '../proof-check/attestation.mjs';
import { canonicalize } from '../proof-check/commitment.mjs';

/** BAS deployments. */
export const NETWORKS = Object.freeze({
  'bsc-testnet': Object.freeze({ chainId: 97, bas: '0x6c2270298b1e6046898a322acB3Cbad6F99f7CBD',
    schemaRegistry: '0x08C8b8417313fF130526862f90cd822B55002D72', rpcUrl: 'https://data-seed-prebsc-1-s1.bnbchain.org:8545',
    explorer: 'https://testnet.bscscan.com' }),
  'bsc': Object.freeze({ chainId: 56, bas: '0x247Fe62d887bc9410c3848DF2f322e52DA9a51bC',
    schemaRegistry: '0x5e905F77f59491F03eBB78c204986aaDEB0C6bDa', rpcUrl: 'https://bsc-dataseed.bnbchain.org',
    explorer: 'https://bscscan.com' }),
});

/** Commitment and claim fields plus the signed attestation as JSON. */
export const SCHEMA = 'bytes32 commitment,string provider,string claim,uint16 window,string attestation';
const FIELDS = parseAbiParameters(SCHEMA);
/** Schema UID as the registry computes it. */
export const SCHEMA_UID = keccak256(encodePacked(['string', 'address', 'bool'], [SCHEMA, zeroAddress, true]));

export const BAS_ABI = [
  { type: 'function', name: 'attest', stateMutability: 'payable', outputs: [{ type: 'bytes32' }], inputs: [{ name: 'request', type: 'tuple',
    components: [{ name: 'schema', type: 'bytes32' }, { name: 'data', type: 'tuple', components: [
      { name: 'recipient', type: 'address' }, { name: 'expirationTime', type: 'uint64' }, { name: 'revocable', type: 'bool' },
      { name: 'refUID', type: 'bytes32' }, { name: 'data', type: 'bytes' }, { name: 'value', type: 'uint256' }] }] }] },
  { type: 'function', name: 'getAttestation', stateMutability: 'view', inputs: [{ name: 'uid', type: 'bytes32' }], outputs: [{ type: 'tuple',
    components: [{ name: 'uid', type: 'bytes32' }, { name: 'schema', type: 'bytes32' }, { name: 'time', type: 'uint64' },
      { name: 'expirationTime', type: 'uint64' }, { name: 'revocationTime', type: 'uint64' }, { name: 'refUID', type: 'bytes32' },
      { name: 'recipient', type: 'address' }, { name: 'attester', type: 'address' }, { name: 'revocable', type: 'bool' },
      { name: 'data', type: 'bytes' }] }] },
  { type: 'event', name: 'Attested', inputs: [{ name: 'recipient', type: 'address', indexed: true },
    { name: 'attester', type: 'address', indexed: true }, { name: 'uid', type: 'bytes32', indexed: false },
    { name: 'schemaUID', type: 'bytes32', indexed: true }] },
];
export const REGISTRY_ABI = [{ type: 'function', name: 'register', stateMutability: 'nonpayable', outputs: [{ type: 'bytes32' }],
  inputs: [{ name: 'schema', type: 'string' }, { name: 'resolver', type: 'address' }, { name: 'revocable', type: 'bool' }] }];

const UID = /^0x[0-9a-f]{64}$/i;
const fail = reason => { throw new Error(`BNB_ANCHOR_INVALID: ${reason}`); };

/** BAS request for a signed attestation; expires with it. */
export function anchorRequest(signed) {
  const clean = attestationShape(Object.fromEntries(Object.entries(signed ?? {}).filter(([key]) => !['verifierKeyId', 'sig'].includes(key))));
  if (typeof signed.verifierKeyId !== 'string' || typeof signed.sig !== 'string') fail('unsigned attestation');
  const data = encodeAbiParameters(FIELDS, [`0x${clean.commitment}`, clean.provider, clean.claim, clean.window ?? 0, canonicalize(signed)]);
  return { schema: SCHEMA_UID, data: { recipient: zeroAddress, expirationTime: BigInt(Math.floor(Date.parse(clean.expiresAt) / 1000)),
    revocable: true, refUID: zeroHash, data, value: 0n } };
}

/** Decodes a BAS record into its signed attestation. */
export function decodeAnchor(record, { now = Date.now() } = {}) {
  if (!record || record.schema?.toLowerCase() !== SCHEMA_UID) fail('schema');
  if (record.revocationTime && BigInt(record.revocationTime) !== 0n) fail('revoked');
  const [commitment, provider, claim, window, json] = decodeAbiParameters(FIELDS, record.data);
  let attestation;
  try { attestation = JSON.parse(json); } catch { fail('attestation json'); }
  // Fields must match the signed attestation.
  if (`0x${attestation?.commitment}` !== commitment || attestation.provider !== provider || attestation.claim !== claim ||
      (attestation.window ?? 0) !== window) fail('fields');
  return { uid: record.uid, attester: record.attester, time: Number(record.time), expired: Number(record.expirationTime) * 1000 < now,
    attestation };
}

/** Publishes a signed attestation. Returns { uid, txHash }. */
export async function publishAnchor({ signed, wallet, client, network = 'bsc-testnet' }) {
  const { bas } = NETWORKS[network] ?? fail('network');
  const txHash = await wallet.writeContract({ address: bas, abi: BAS_ABI, functionName: 'attest', args: [anchorRequest(signed)] });
  const receipt = await client.waitForTransactionReceipt({ hash: txHash });
  if (receipt.status !== 'success') fail('transaction reverted');
  const { parseEventLogs } = await import('viem');
  const [event] = parseEventLogs({ abi: BAS_ABI, eventName: 'Attested', logs: receipt.logs })
    .filter(log => log.address.toLowerCase() === bas.toLowerCase() && log.args.schemaUID.toLowerCase() === SCHEMA_UID);
  if (!event) fail('no Attested event');
  return { uid: event.args.uid, txHash };
}

/** Reads one anchor by its BAS UID. */
export async function readAnchor({ uid, client, network = 'bsc-testnet', now }) {
  if (!UID.test(uid ?? '')) fail('uid');
  const { bas } = NETWORKS[network] ?? fail('network');
  const record = await client.readContract({ address: bas, abi: BAS_ABI, functionName: 'getAttestation', args: [uid] });
  if (!record || record.uid === zeroHash) return null;
  return decodeAnchor(record, { now });
}

/** Registry for verifyCommitment backed by one BAS UID. */
export function bnbRegistry({ uid, client, network, now }) {
  let anchor;
  const load = async () => (anchor ??= await readAnchor({ uid, client, network, now }));
  return {
    async findAttestations({ commitment }) {
      const found = await load();
      return found && found.attestation.commitment === commitment ? [found.attestation] : [];
    },
    async findBundle() { return null; },
    anchor: load,
  };
}
