# @16signals-verify/bnb-anchor

Anchors a signed attestation on BNB Smart Chain through the BNB Attestation Service (BAS), and reads it back. Plain ES
module (Node 22+ and current browsers) with one dependency, `viem`. This repository deploys no contract; it registers
one schema and writes one record per attestation. Background and trade-offs: [docs/bnb.md](../../docs/bnb.md).

## What goes on chain

The signed attestation and nothing else: no proof, no transcript, no user or account identifier. Anyone can anchor an
attestation they hold. Trust comes from the Ed25519 signature inside the record, which the reader checks against its
trusted keys.

## Networks and schema

| Network | `BNB_NETWORK` | Chain id |
| --- | --- | --- |
| BSC testnet (default) | `bsc-testnet` | 97 |
| BSC mainnet | `bsc` | 56 |

Contract addresses are in `NETWORKS` in [`anchor.mjs`](anchor.mjs) and in [docs/bnb.md](../../docs/bnb.md). The schema
is `bytes32 commitment,string provider,string claim,uint16 window,string attestation` (no resolver, revocable). Its
UID is exported as `SCHEMA_UID`.

## CLI

In this repository, after the root `npm ci`, run `node cli.mjs` from this folder. Once the package is published (not
yet), `npm i -g @16signals-verify/bnb-anchor` installs it as `bnb-anchor`:

```sh
export BNB_PRIVATE_KEY=0x...            # funded account, needed for register and publish
bnb-anchor register                     # once per network: registers the schema (no-op if it already is)
bnb-anchor publish attestation.json     # a signed attestation, or { "attestation": ..., "bundle": ... }
bnb-anchor read 0x<uid>                 # prints the anchored attestation
```

Environment variables the CLI reads:

| Variable | Effect |
| --- | --- |
| `BNB_NETWORK` | `bsc-testnet` (default) or `bsc` |
| `BNB_RPC_URL` | Overrides the network's public RPC |
| `BNB_PRIVATE_KEY` | 0x-prefixed private key; required for `register` and `publish` |

## From code

```js
import { createPublicClient, createWalletClient, http } from 'viem';
import { publishAnchor, readAnchor, bnbRegistry, NETWORKS } from '@16signals-verify/bnb-anchor';

const { uid, txHash } = await publishAnchor({ signed, wallet, client, network: 'bsc-testnet' });
const anchor = await readAnchor({ uid, client, network: 'bsc-testnet' });  // { uid, attester, time, expired, attestation } or null
```

`readAnchor` rejects records of another schema, revoked records, and records whose indexed fields disagree with the
signed attestation they carry. `NETWORKS[network].rpcUrl` is the default RPC for a read-only client.

## As a proof-check registry

`bnbRegistry({ uid, client, network })` returns a registry for
[`@16signals-verify/proof-check`](../proof-check/README.md): `findAttestations` returns the anchored attestation when its
commitment matches, `findBundle` returns `null` (the bundle is not on chain), and `anchor()` returns the decoded
record.

```js
const registry = bnbRegistry({ uid, client, network });
const { attestation } = await registry.anchor();
const result = await verifyCommitment({ commitment: attestation.commitment, registries: [registry], keys, providers });
```

The [verify page](../../verify/README.md) uses this for `?uid=0x...`.

## Tests

```sh
npm test
```

Tests use fakes for the chain and need no network.
