# BNB Chain anchoring

A signed verifier attestation can be anchored on BNB Smart Chain through the
[BNB Attestation Service](https://github.com/basdotio/bas-contract) (BAS), an EAS fork. Anchoring makes the
attestation public and durable without anyone hosting a file: the verify page reads it back by its BAS UID and runs
the same checks as for a dropped file.

What goes on chain is exactly the signed attestation: the provider, the coarse claim, the window, the commitment, the
proof hash and pinned key hashes, timestamps, the verifier key id and the signature. No proof, no transcript, no
identifier of the user or their cloud account. The public proof bundle stays off chain (it is too large); share it as a
file if the reader should check the proof hash and public inputs too.

## Schema

```
bytes32 commitment,string provider,string claim,uint16 window,string attestation
```

`attestation` is the canonical JSON of the signed attestation; the other fields repeat its commitment and claim so
indexers can filter on them. No resolver, revocable. The schema UID is
`keccak256(abi.encodePacked(schema, address(0), true))`:
`0x2cdf9b676be2e7054032660c9ecb2b367de6e3a4ecf7ebb4bc056feae98525bb`. Each anchor expires on chain when the attestation
does.

| Network | Chain id | BAS | Schema registry |
|---|---|---|---|
| BSC testnet (default) | 97 | `0x6c2270298b1e6046898a322acB3Cbad6F99f7CBD` | `0x08C8b8417313fF130526862f90cd822B55002D72` |
| BSC mainnet | 56 | `0x247Fe62d887bc9410c3848DF2f322e52DA9a51bC` | `0x5e905F77f59491F03eBB78c204986aaDEB0C6bDa` |

The schema is registered on BSC testnet (registration transaction
[`0x5eef6dc9…a705c`](https://testnet.bscscan.com/tx/0x5eef6dc955ff2a8e0322fb6ff2c67ed0dd636529721d4c7d547fd455a22a705c)).
It is not yet registered on mainnet; `register` does it once and reports `"registered": "already"` after that.

## Publishing

```sh
cd packages/bnb-anchor && npm ci
export BNB_PRIVATE_KEY=0x…        # a funded account on the network (testnet BNB from the BNB Chain faucet)
node cli.mjs register             # once per network: registers the schema, prints its UID
node cli.mjs publish attestation.json   # a signed attestation, or { "attestation": …, "bundle": … }
# → { "uid": "0x…", "tx": "https://testnet.bscscan.com/tx/0x…" }
node cli.mjs read 0x…             # prints the anchored attestation
```

`BNB_NETWORK=bsc` selects mainnet and `BNB_RPC_URL` overrides the public RPC. The publishing account is the on-chain
attester; it does not need to be the verifier, because trust comes from the Ed25519 signature inside the record, which
the reader checks against `verify/keys.json`. Anyone can anchor an attestation they hold, and anchoring a forged one
gains nothing: it fails the signature check.

## Reading

`verify/?uid=0x…` (or the UID field on the page), or `proof-check --uid 0x…` on the command line. In code, `bnbRegistry({ uid, client })` from
[`packages/bnb-anchor/anchor.mjs`](../packages/bnb-anchor/anchor.mjs) is a registry for `verifyCommitment` in
[`packages/proof-check`](../packages/proof-check); the verify page enables the UID lookup through the `bnb` entry in
`verify/verify.config.json`. `readAnchor` rejects records of another schema, revoked records, and
records whose indexed fields disagree with the signed attestation they carry.

### Example

A test record on BSC testnet anyone can read:

```sh
node packages/bnb-anchor/cli.mjs read 0x6805e4278836ac8ce88a2e7ee7e25992e879683ec58b401faefff7660547feb7
```

It anchors an attestation over a synthetic Google Cloud bundle (the one `verify/verify.test.mjs` builds), signed with
a throwaway test key that is not in `verify/keys.json`, so the page and `proof-check --uid` read it and report
`unknown-key`: it demonstrates the lookup, not a trusted claim. The record is in transaction
[`0x0e0083eb…f687c60`](https://testnet.bscscan.com/tx/0x0e0083eb77fa99840f133f00d1e37184177e9b7fefb58e8d567594616f687c60).

## Trade-offs

- The RPC the page uses sees the viewer's IP address and the UID looked up; host the page yourself and pass your own
  RPC if that matters.
- A revoked anchor is treated as absent; the signed attestation itself (as a file) is unaffected.
- Lookup is by UID. Finding anchors by commitment needs an indexer over `Attested` events for the schema UID above.
