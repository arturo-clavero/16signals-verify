# Verifying an attestation

Anyone holding a signed attestation can check it. Nothing here needs an account, a key or the operator's servers.

## The verify page

Open `verify/` on any static host of this repository and drop a JSON file on the page: a signed attestation, or `{
"attestation": …, "bundle": … }` with the public proof bundle as well, or a [proof package](#proof-packages). The bundle is optional. There is no lookup by
commitment over the network. A dropped attestation's commitment is recomputed from its fields rather than taken from
its label.

It can also look up an attestation anchored on BNB Smart Chain: enter its BAS attestation UID, or open
`verify/?uid=0x…` (add `&network=bsc` for mainnet; testnet is the default). The page reads that one record with
`getAttestation` from a public RPC, checks it uses this repository's schema and is not revoked, and verifies the signed
attestation it carries exactly like a dropped one. The public bundle is not on chain; drop the bundle file after the
lookup to add its checks, otherwise the result is signature-only. See [BNB Chain anchoring](bnb.md).

The page:

1. loads [`verify/verify.config.json`](../verify/verify.config.json): the provider descriptors, the BNB registry and
   [`verify/keys.json`](../verify/keys.json), the verifier keys it accepts;
2. reads the signed attestation, and the public bundle if present, from the dropped file;
3. runs the checks below in the viewer's browser and shows the result.

All checks live in [`packages/proof-check/check.mjs`](../packages/proof-check/check.mjs) (no DOM, no network; tested
in Node). Provider-specific parts (pinned keys, recomputing the claim, the headline) come from each
`private-proof/<provider>/descriptor.mjs`. An attestation for a provider with no descriptor does not verify. The same
checks run from the command line:

```sh
node packages/proof-check/cli.mjs evidence.json [--bundle bundle.json] [--keys keys.json]
```

It prints one line per check and exits 0 when all pass, 1 when one fails, 2 on bad input. See the
[package README](../packages/proof-check/README.md) to plug in other providers, registries or keys.

## What each check means

| Check | What it establishes |
| --- | --- |
| Signed by a listed verifier key, unexpired, and the commitment recomputes from its fields | A verifier you accept signed exactly this claim, proof hash and pins, and the attestation has not expired |
| The provider is one these checks support | Shown only when it fails: the attestation names a provider with no descriptor, so nothing else about it can be checked |
| Published proof bundle hashes to the signed proof hash | The bundle in the file is the one the signer saw |
| Verification keys are the ones pinned in this repository | The proofs were made for these circuits, with these keys, and no others |
| Claim matches the proven public inputs | The claim is not just a label: for GCP the observed groups and window are recomputed from the public inputs; for AWS event runs the bundle proves one linked event per operation or skill area the claim lists, and they are known and in catalog order (the names themselves come from receipts that stay private); Cloudflare claims (`cloudflare:groups:<positions>:user`) are checked for format and known skill-group positions |

Results:

| Status | Meaning |
| --- | --- |
| Verified | All checks passed |
| Signed by the verifier (public proof bundle not available) | The signature checks out; there is no public bundle to check the proof hash and claim against |
| Does not verify | An attestation was found but a check failed |
| No attestation found | The dropped file holds no signed attestation |

What the page **takes from the signature** and cannot check itself (it says so under Details):

- the proofs came from a real TLS session with the provider, as observed by the TLSNotary verifier;
- the public inputs match that authenticated session;
- the zero-knowledge proofs verify. The page does not re-run the ZK verifier until the verification keys are hosted
  with it.

## Proof packages

A proof package carries what the TLSNotary verifier signed for a claim: its receipts (one per TLS session), the
transcript pieces as leaf hashes, commitment digests or, when the claim needs them, disclosed bytes, and the
zero-knowledge proofs over the hidden values. Drop one on the page, or run

```sh
node packages/proof-check/cli.mjs --proof package.json [--did did.json] [--uid <BAS uid>]
```

| Check | What it establishes |
| --- | --- |
| Every receipt is signed by the key in the issuer's DID document | The verifier named by the receipt's `kid` signed each session's server name, time and Merkle root. The key comes from `keys.json` (`dids`), `--did`, or, on the page, the issuer's `/.well-known/did.json` |
| Every receipt names a host of the provider | Each session was with a host the provider descriptor lists (`hosts`), for its position in the proof |
| The published pieces rebuild the signed Merkle root | The package's pieces are exactly the ranges the verifier signed |
| The claim follows from the disclosed data | The descriptor rebuilt the claim from the disclosed bytes. When the package discloses none, the line reads *attested*: the claim is taken from the issuer |
| The zero-knowledge proofs verify and open every signed commitment | The hidden values satisfy the pinned circuits, and the proofs are about the committed values the verifier signed. The page loads `@aztec/bb.js` for this step only |
| The package hash is in an on-chain record signed by a listed key | An attestation naming `sha256(canonical package)`, signed by a key in `keys.json`, is anchored on BNB Chain: look up its UID first, then drop the package |

A line that could not run here (no DID document, no registry, no prover library) is shown as such; it is not a pass.
The package format and options are in the [package README](../packages/proof-check/README.md#proof-packages).

## Publishing a verifier key

A verifier operator signs attestations with an Ed25519 key and publishes the public key.

```sh
openssl genpkey -algorithm ed25519 -out attest-key.pem      # PKCS#8 private key; keep it in the signer's env only
openssl pkey -in attest-key.pem -pubout -out attest-pub.pem
# verifierKeyId: the first 16 bytes (32 hex) of sha256 over the public key's SPKI DER encoding
openssl pkey -pubin -in attest-pub.pem -outform DER | sha256sum | cut -c1-32
```

The same id comes from `verifierKeyId(publicKeyPem)` in [`packages/proof-check`](../packages/proof-check). Add the key
to `verify/keys.json`:

```json
{
  "keys": [
    {
      "id": "<32 hex verifierKeyId>",
      "label": "Example verifier",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

`label` is optional and shown on the page. The page accepts an attestation only if its `verifierKeyId` matches an
`id` here and the signature verifies with that `publicKeyPem`. Anyone hosting the page decides which keys to trust
by editing this file.

## Hosting the page

The page is static, but it imports files from outside `verify/`, so serve the **repository root**:

- `verify/` (page, `verify.config.json`, `keys.json`);
- `packages/proof-check/` and `packages/bnb-anchor/`;
- each `private-proof/<provider>/descriptor.mjs` listed in the config and the files it imports: the provider's
  `generated/` pins, `private-proof/gcp/policy.mjs` (the GCP batch layout), and the AWS and Cloudflare catalogs
  (`operation-catalog.mjs`, `skill-groups.mjs`), and the AWS and Cloudflare `request.mjs` (their TLS hosts).

The page imports `viem` (BNB lookups) and `@aztec/bb.js` (zero-knowledge proofs in dropped packages) from esm.sh
through the import map in `verify/index.html`, only when needed.

Locally:

```sh
python3 -m http.server 8080
# http://localhost:8080/verify/
```

On GitHub Pages: publish the repository root of the branch that contains `verify/` (Settings → Pages → Deploy from a
branch, folder `/`). The page is then at `https://<owner>.github.io/<repo>/verify/`. Any other static host works the
same way.

Who sees what: the static host sees the viewer's IP address. The dropped file is read in the browser and not sent
anywhere. The page sends no referrer. Checking a proof package fetches the issuer's DID document from its did:web host
unless `keys.json` lists it, and esm.sh serves the prover library.
