# Private proofs

A provider is one kind of evidence, such as "activity in a Google Cloud project". It has two sides:

- **Prover side**, run in the extension: a plan for the TLS sessions to open, the values to hide, and Noir circuits
  that prove facts about those hidden values in the browser (`client-plan.mjs`, `browser-client.mjs`,
  `browser-worker.mjs`, `proof-runtime*.mjs`, `circuits/`). The extension packages one plugin per provider.
- **Checking side**, used by the backend and by [`packages/proof-check`](../packages/proof-check): a bundle verifier
  (`verify-bundle.mjs`) that checks a proof bundle against the verifier's receipts and the pinned keys, and a
  `descriptor.mjs` that tells proof-check the provider's id, bundle kind, pinned verification keys, how to recompute
  the claim and how to describe it.

Everything private stays in the browser; the relying party learns a coarse claim. See
[docs/architecture.md](../docs/architecture.md) for the flow and trust model.

## The providers

| Provider | Folder | Plugin id | Proves | Claim |
| --- | --- | --- | --- | --- |
| Google Cloud | [`gcp`](gcp/README.md) | `gcp-work` | Which skill groups had activity in the last 7, 30 or 90 days | `gcp:observed:<groups>` |
| AWS | [`aws`](aws/README.md) | `aws-private-work` | Which operations or skill groups an IAM user acted in during the last 90 days | `aws:activity:...`, `aws:areas:...`, `aws:groups:...` |
| Cloudflare | [`cloudflare`](cloudflare/README.md) | `cloudflare-private-work` | Which skill groups the signed-in user changed in the last 90 days | `cloudflare:groups:<positions>:user` |

Each folder has its own tests (`npm ci && npm test`, serial, no cloud account needed).

## Add a provider

1. **Circuits and prover.** Write the circuits under `circuits/`, a client plan that locates each private value in the
   transcript, and a worker that proves them. Build and pin the artifacts (see each provider's
   `build-artifacts.mjs` and `generated/`).
2. **Bundle verifier.** `verify-bundle.mjs`: derive the expected proofs from authenticated receipts, check every
   proof's hashed inputs against the recorded commitments, and verify against the pinned keys.
3. **Descriptor.** `descriptor.mjs` default-exports `{ id, kind, pins, claim, claimFromResult, describe }`. Only `id`
   is required. See [packages/proof-check/README.md](../packages/proof-check/README.md).
4. **Plugin and extension.** Add a built-in plugin for the provider and its plugin id to the extension's allowed
   list, and the provider's hosts to the build's host access ([docs/architecture.md](../docs/architecture.md#build)).
5. **Register it for checking.** Add the descriptor path to `providers` in
   [`verify/verify.config.json`](../verify/verify.config.json) or your own config.

A provider that only needs checking, not generating, needs just the descriptor and its pinned keys.
