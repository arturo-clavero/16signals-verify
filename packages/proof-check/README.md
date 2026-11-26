# @tlsn-fork/proof-check

Checks a signed attestation, and the public proof bundle when there is one, for any evidence type; and re-checks a
proof package (the verifier's signed receipts behind a claim). Plain ES modules (Node 22+ and current browsers), no
build step. The checks run without a DOM or network access: providers, registries and trusted keys are passed in. The
only dependency, `@aztec/bb.js` (optional), is imported lazily by the zero-knowledge step of package checks.

## Checking

```js
import { verifyCommitment, describeClaim } from '@tlsn-fork/proof-check';

const result = await verifyCommitment({
  dropped: { attestation, bundle },  // from a file; or pass `commitment` and `registries` to look them up
  keys,                               // trusted verifier keys
  providers: [gcp, aws, cloudflare],  // provider descriptors
  registries: [],                     // optional
  now: Date.now(),                    // optional
});
```

`evaluate({ commitment, attestations, bundle, keys, providers, now })` is the same without the lookup.
`parseDropped(text)` reads a file holding a bundle, an attestation, `{ attestation, bundle }`, a proof package, or
`{ package, attestation }` (a package with the issuer's signed attestation of its claim).

The result:

```js
{
  status: 'verified' | 'signature-only' | 'failed' | 'not-found',
  checks: [{ id, ok, label, detail? }],  // in the order they ran
  restsOnSignature: [...],               // what the checks cannot establish
  provider, claim, window, verifier,     // once a signature is accepted
  commitment,                            // from verifyCommitment
}
```

Check ids are stable, so an app can show its own text: `signature`, `provider`, `bundle`, `proof-hash`,
`verification-keys`, `claim`. `label` is an English description; `detail` is a short reason (for example `expired`,
`unknown-key`, or the unsupported provider). `describeClaim(result, providers)` gives a plain-language headline.

Statuses: `verified` all checks passed; `signature-only` the signature is good but there is no public bundle;
`failed` an attestation was found but a check failed; `not-found` no attestation was given or found.

## Proof packages

A proof package lets anyone re-check what the TLSNotary verifier (`servers/verifier`) signed for a claim, without the
transcript. Format v1:

```jsonc
{
  "v": 1,
  "provider": "gcp",                   // descriptor id
  "claim": "gcp:observed:g2,g10",      // optional: the claim it backs
  "runs": [{                           // one per verified TLS session; runs sharing a proofId are one proof
    "receipt": "<compact JWS>",        // the verifier's signed receipt, v1 or v2
    "leaves": [{ "direction": "sent|recv", "start": 0, "end": 38, "kind": "reveal|commit" }],
    "disclosed": [{ "leaf": 3, "salt": "<hex>", "bytes": "<base64>" }],                // optional
    "commitments": [{ "leaf": 7, "salt": "<hex>", "alg": "sha256", "digest": "<hex>" }],
    "hidden": [{ "leaf": 5, "hash": "<hex leaf hash>" }],
    "zk": { "kind": "...", "version": 1, "proofs": [{ "circuitId", "proof", "publicInputs" }] }  // on a proof's first run
  }],
  "pins": { "<circuitId>": "<vk sha256>" },
  "vks": { "<circuitId>": "<base64 vk>" }  // optional; always checked against the provider's pins
}
```

`proofHash = sha256(canonical JSON of the package)` (`packageHash`).

```js
import { checkPackage, packageLines, closeZk } from '@tlsn-fork/proof-check';

const result = await checkPackage(pkg, {
  providers: [gcp, aws, cloudflare],
  keys: { dids: [didDocument], keys: [] },  // trusted DID documents (receipts) and attestation keys (on-chain, claim)
  resolveDid,                               // optional: did -> DID document, for issuers not in keys.dids
  registries,                               // optional: { findByProofHash } for the on-chain check
  claim, proofHash,                         // optional: what a published claim says; must match
  attestation,                              // optional: the issuer's signed attestation of the package's claim
});
// { status: 'verified' | 'partial' | 'failed', proofHash, provider, claim, checks: [{ id, ok, label, detail?, reason? }] }
```

| Check id | Passes when |
| --- | --- |
| `receipt-signature` | Every receipt verifies (EdDSA, `typ` `tlsn-receipt+jws`) under the key its `kid` names in the issuer's did:web document, listed in `assertionMethod` |
| `server-name` | Every signed `serverName` is one of the descriptor's `hosts` for that session's position in its proof |
| `signed-root` | Disclosed bytes, commitments and hidden leaf hashes rebuild every signed Merkle root and leaf count |
| `claim-from-data` | In order: the descriptor's `claimFromData` rebuilds the claim from the disclosed bytes; or, once `zk-proofs` passed, the descriptor's `claim` rebuilds it from the proofs' public inputs (GCP); or an attestation signed by a key in `keys.keys`, unexpired, names this package hash, provider and claim (`attestation`, else the record the `on-chain` check found). A rebuilt claim or a trusted signature that differs fails, as does `claim` naming another claim. Otherwise `ok: null, reason: 'attested'` (the package's own claim, taken from the issuer); a claim the proofs determine but that waits on `zk-proofs` is not run |
| `zk-proofs` | Every proof verifies under the provider's pinned key, and together they open every signed commitment digest. A provider with pins requires them; without any it is `reason: 'not-applicable'` |
| `on-chain` | A registry holds an attestation naming `proofHash`, signed by a key in `keys.keys` |

`ok` is true, false, or null (not run here; `detail` says why). Nulls with `reason` `attested` or `not-applicable` are
settled: `verified` means every other check passed, `partial` that none failed but some could not run. The ZK step
needs `@aztec/bb.js` 4.2.0-aztecnr-rc.2 and embeds the 192-byte verifier setup instead of downloading a CRS; without
the library the binding is still checked and the step stays open. `closeZk()` releases it.

The test packages in `test-fixtures/proof-package` are built from the providers' synthetic fixtures by
`test-fixtures/make-packages.mjs`, signed with the test key of `servers/verifier/src/tests/receipt-v2-vectors.json`.

### Building a package

From the verifier's webhooks (one per TLS session, with `receipt` and `leaves`) and the proof bundle the page got
from the extension, once the provider's `verify-bundle.mjs` accepted it:

```js
import { buildPackage, webhookRun } from '@tlsn-fork/proof-check';

const runs = await Promise.all(webhooks.map((payload, i) => webhookRun(payload, { zk: i === 0 ? bundle : undefined })));
const pkg = await buildPackage({ descriptor: gcp, claim: gcp.claimFromResult(result).claim, runs, vks });
```

`webhookRun(payload, { zk?, disclose? })` reads the transcript from the payload; `buildRun({ receipt, leaves, sent,
recv, zk?, disclose? })` takes the bytes directly. Each run must rebuild its signed root, or it throws. Reveal leaves
are published as hashes unless `disclose(leaf, index)` returns true; commit leaves always carry salt and digest.
`buildPackage` takes `pins` from the descriptor for the circuits the bundle uses (or pass `pins`); `vks` (circuit id ->
key bytes or base64) is optional. [`examples/demo`](../../examples/demo/README.md) does all of this for a live run.

## Plug points

**Provider descriptor.** One per evidence type, picked by `attestation.provider`. An attestation whose provider has
no descriptor fails the `provider` check. Only `id` is required:

```js
export default {
  id: 'example',                 // attestation.provider
  kind: 'EXAMPLE_RESULT',        // bundle.kind
  pins: { circuits: { 'example-v1': { sha256: '<vk sha256>' } } },  // or a (possibly async) loader
  claim(bundle, { claim }) {},   // claim recomputed from the public inputs: { claim, window } or null
  claimFromResult(result) {},    // claim for a result of the provider's own bundle verifier (publishing side)
  describe({ claim, window }) {},// headline, or null for the default
  hosts: ['api.example.com'],    // TLS hosts a receipt may name, or (index in proof) => hosts
  claimFromData({ claim, runs }) {},  // claim rebuilt from disclosed bytes ({ direction, start, end, bytes }), or null
};
```

A pin is `{ sha256 }` or `{ keyFile, keySha256 }`. Without `pins`, the keys are only checked to cover exactly the
circuits used; without `claim`, the claim is not recomputed.

**Registry.** Looks attestations and bundles up by commitment:

```js
{
  findAttestations: async ({ commitment }) => [/* signed attestations */],
  findBundle: async ({ commitment, proofHash }) => ({ json: '<bundle JSON>' }) /* or null */,
  findByProofHash: async ({ proofHash }) => [/* signed attestations */],  // optional, for proof packages
}
```

`bnbRegistry` in `@tlsn-fork/bnb-anchor` is one.

**Trusted keys.** Attestations are accepted only from these keys; `id` is `verifierKeyId(publicKeyPem)`:

```json
{ "keys": [{ "id": "<32 hex>", "label": "Example verifier", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }] }
```

An optional `dids` array lists DID documents whose receipt keys package checks accept without resolving them.

**Config file.** `loadConfig(url, { readJson })` reads one, resolving paths against the file:

```json
{
  "providers": ["./example/descriptor.mjs"],
  "keys": "./keys.json",
  "registries": [{ "type": "bnb", "module": "./bnb-anchor/anchor.mjs", "network": "bsc-testnet" }]
}
```

Each provider module default-exports a descriptor. Registry entries are for the app; only `module` is resolved.

## CLI

```sh
proof-check <attestation.json> [--bundle bundle.json] [--keys keys.json] [--config config.json] [--now <ISO time>]
proof-check --uid <BAS uid> [--network bsc] [--bundle bundle.json] [--keys keys.json] [--config config.json]
proof-check --proof package.json [--did did.json] [--claim <claim>] [--attestation attestation.json] [--uid <BAS uid> [--network bsc]] [--keys keys.json] [--config config.json]
```

With `--uid` (and no file) the signed attestation is read from that BAS record through the config's `bnb` registry,
as the verify page's `?uid=` does; `--bundle` adds the public proof bundle, which is not on chain.

With `--proof` it re-checks a proof package (or `{ package, attestation }`): `--did` adds a trusted DID document,
`--attestation` the issuer's signed attestation of the claim (its key must be in `keys`), `--uid` reads that BAS
attestation through the config's `bnb` registry for the on-chain check, which also backs the claim. Lines are marked `ok`, `FAIL`, `att` (attested), `n/a` or
`--` (not run).

The file holds a signed attestation or `{ attestation, bundle }`. Providers, and keys unless `--keys` is given, come
from the config; the default is `verify/verify.config.json` in this repository. It prints one line per check and a
summary line.

| Exit code | Meaning |
| --- | --- |
| 0 | Every check passed (with `--proof`, attested and not-applicable lines aside) |
| 1 | A check failed (including a missing bundle) |
| 2 | Bad input: usage, unreadable file, not an attestation, bad config; with `--proof`, also a check that could not run |

## Publishing side

`bundleCommitment`, `createAttestation`, `signAttestation`, `verifierKeyId`, `verifyAttestation` build and sign
attestations; `fromVerifiedBundle(descriptor, bundle, result, { pins?, coreDigest?, pluginSha256? })` gives the
commitment fields for a bundle the provider's verifier accepted; `publicBundle`, `proofHash` and `vkHashesFor`
are its parts.
