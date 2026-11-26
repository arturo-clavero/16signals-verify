#!/usr/bin/env node
// Usage: bnb-anchor register | publish <file.json> | read <uid>
// Env: BNB_NETWORK (bsc-testnet | bsc), BNB_RPC_URL, BNB_PRIVATE_KEY for register/publish.
import { readFile } from 'node:fs/promises';
import { createPublicClient, createWalletClient, defineChain, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { NETWORKS, REGISTRY_ABI, SCHEMA, SCHEMA_UID, publishAnchor, readAnchor } from './anchor.mjs';
import { zeroAddress } from 'viem';

const network = process.env.BNB_NETWORK ?? 'bsc-testnet';
const config = NETWORKS[network];
if (!config) throw new Error(`unknown BNB_NETWORK ${network}`);
const chain = defineChain({ id: config.chainId, name: network, nativeCurrency: { name: 'BNB', symbol: 'BNB', decimals: 18 },
  rpcUrls: { default: { http: [process.env.BNB_RPC_URL ?? config.rpcUrl] } } });
const client = createPublicClient({ chain, transport: http() });
const wallet = () => {
  const key = process.env.BNB_PRIVATE_KEY;
  if (!/^0x[0-9a-fA-F]{64}$/.test(key ?? '')) throw new Error('set BNB_PRIVATE_KEY to a 0x-prefixed private key');
  return createWalletClient({ chain, transport: http(), account: privateKeyToAccount(key) });
};

const [command, arg] = process.argv.slice(2);
if (command === 'register') {
  const existing = await client.readContract({ address: config.schemaRegistry, abi: REGISTRY_ABI, functionName: 'getSchema',
    args: [SCHEMA_UID] });
  if (existing.uid.toLowerCase() === SCHEMA_UID) {
    console.log(JSON.stringify({ schemaUid: SCHEMA_UID, registered: 'already' }));
  } else {
    const hash = await wallet().writeContract({ address: config.schemaRegistry, abi: REGISTRY_ABI, functionName: 'register',
      args: [SCHEMA, zeroAddress, true] });
    const receipt = await client.waitForTransactionReceipt({ hash });
    if (receipt.status !== 'success') throw new Error(`register reverted: ${config.explorer}/tx/${hash}`);
    console.log(JSON.stringify({ schemaUid: SCHEMA_UID, tx: `${config.explorer}/tx/${hash}` }));
  }
} else if (command === 'publish' && arg) {
  const parsed = JSON.parse(await readFile(arg, 'utf8'));
  const { uid, txHash } = await publishAnchor({ signed: parsed.attestation ?? parsed, wallet: wallet(), client, network });
  console.log(JSON.stringify({ uid, tx: `${config.explorer}/tx/${txHash}` }));
} else if (command === 'read' && arg) {
  console.log(JSON.stringify(await readAnchor({ uid: arg, client, network }), null, 2));
} else {
  console.error('usage: bnb-anchor register | publish <file.json> | read <uid>');
  process.exit(2);
}
