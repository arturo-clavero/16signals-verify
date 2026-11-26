# Verify page

A static page that checks, in the viewer's browser, a proof package (receipts, signed data, zero-knowledge proofs re-run
with bb.js) or a signed attestation and its public proof bundle.
It uses [`packages/proof-check`](../packages/proof-check) for every check. The dropped file is read in the browser
and sent nowhere. How to read the result: [docs/verification.md](../docs/verification.md).

## Use it

Serve the repository root (the page imports files outside `verify/`) and open `/verify/`:

```sh
python3 -m http.server 8080
# http://localhost:8080/verify/
```

Drop a JSON file: a proof package, a signed attestation, or `{ "attestation": ..., "bundle": ... }`. With the BNB registry enabled, you
can also enter a BAS attestation UID, or open `/verify/?uid=0x...` (add `&network=bsc` for mainnet; testnet is the
default). A looked-up record has no bundle; drop the bundle file afterwards to add its checks.

## Copy it into your own site

Copy `verify/` and what it imports: `packages/proof-check/`, `packages/bnb-anchor/` (only if you use the UID lookup),
and each `private-proof/<provider>/descriptor.mjs` listed in the config together with its imports (the provider's
`generated/` pins, and for GCP, AWS and Cloudflare their `policy.mjs`, `operation-catalog.mjs` and `skill-groups.mjs`).
Keep the relative layout, or edit the paths in `verify.config.json`.

Files:

| File | Purpose |
| --- | --- |
| `index.html` | The page; an import map for `viem` (only used by the UID lookup) |
| `page.mjs` | Exports `mountVerify` |
| `verify.config.json` | Providers, registries, trusted keys |
| `keys.json` | The verifier public keys the page accepts |

## `verify.config.json`

Paths are relative to the config file.

```json
{
  "providers": ["../private-proof/gcp/descriptor.mjs", "../private-proof/aws/descriptor.mjs", "../private-proof/cloudflare/descriptor.mjs"],
  "registries": [{ "type": "bnb", "module": "../packages/bnb-anchor/anchor.mjs", "network": "bsc-testnet" }],
  "keys": "./keys.json"
}
```

- `providers`: modules whose default export is a provider descriptor. An attestation for a provider not listed fails.
- `registries`: a `bnb` entry adds the UID lookup. Remove it for a file-only page.
- `keys`: a path, or the keys object itself.

## `keys.json`

```json
{ "keys": [{ "id": "<32 hex>", "label": "Example verifier", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }] }
```

`id` is `verifierKeyId(publicKeyPem)` from proof-check. The page accepts only attestations signed by a listed key, so
the host decides whom to trust. How to create a key: [docs/verification.md](../docs/verification.md#publishing-a-verifier-key).
The file in this repository has no keys until you add yours.

## `mountVerify(el, config)`

```html
<div id="verify"></div>
<script type="module">
  import { mountVerify } from './page.mjs';
  mountVerify(document.getElementById('verify'), './verify.config.json');
</script>
```

`config` is a URL of a config file, or a config object (providers may be descriptor objects and `keys` a keys
object). It renders the lookup form, the file drop and the result into `el`. For your own design, skip it and call
`verifyCommitment` from proof-check, then render `result.checks` by each check's `id`.

## Browser requirements

The descriptors use JSON import attributes (`import ... with { type: 'json' }`): Chrome 123+, Safari 17.2+,
Firefox 138+.

## Tests

```sh
node --test verify/verify.test.mjs
```
