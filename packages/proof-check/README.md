# @tlsn-fork/proof-check

Checks a signed attestation, and the public proof bundle when there is one, for any evidence type. Plain ES modules
(Node 22+ and current browsers), no build step, no dependencies. The checks run without a DOM or network access:
providers, registries and trusted keys are passed in.

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
`parseDropped(text)` reads a file holding a bundle, an attestation, or `{ attestation, bundle }`.

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
};
```

A pin is `{ sha256 }` or `{ keyFile, keySha256 }`. Without `pins`, the keys are only checked to cover exactly the
circuits used; without `claim`, the claim is not recomputed.

**Registry.** Looks attestations and bundles up by commitment:

```js
{
  findAttestations: async ({ commitment }) => [/* signed attestations */],
  findBundle: async ({ commitment, proofHash }) => ({ json: '<bundle JSON>' }) /* or null */,
}
```

`bnbRegistry` in `@tlsn-fork/bnb-anchor` is one.

**Trusted keys.** Attestations are accepted only from these keys; `id` is `verifierKeyId(publicKeyPem)`:

```json
{ "keys": [{ "id": "<32 hex>", "label": "Example verifier", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }] }
```

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
```

The file holds a signed attestation or `{ attestation, bundle }`. Providers, and keys unless `--keys` is given, come
from the config; the default is `verify/verify.config.json` in this repository. It prints one line per check and a
summary line.

| Exit code | Meaning |
| --- | --- |
| 0 | Every check passed |
| 1 | A check failed (including a missing bundle) |
| 2 | Bad input: usage, unreadable file, not an attestation, bad config |

## Publishing side

`bundleCommitment`, `createAttestation`, `signAttestation`, `verifierKeyId`, `verifyAttestation` build and sign
attestations; `fromVerifiedBundle(descriptor, bundle, result, { pins?, coreDigest?, pluginSha256? })` gives the
commitment fields for a bundle the provider's verifier accepted; `publicBundle`, `proofHash` and `vkHashesFor`
are its parts.
