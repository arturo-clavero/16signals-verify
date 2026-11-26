# CROPS compliance checklist

This page maps each CROPS property to the code that enforces it and the test that checks it. The reasoning and
trade-offs are in [crops.md](crops.md); components are in [architecture.md](architecture.md).

"None" in the test column means no automated test checks that guarantee today. Paths are relative to the repository
root.

## Censorship resistance

| Guarantee | Where enforced (file/function) | Test that checks it | Limits |
| --- | --- | --- | --- |
| Anyone can check an attestation with a static page | `verify/verify.mjs` `verifyCommitment`, `evaluate`; `verify/page.mjs` | `verify/verify.test.mjs`: "a published attestation and bundle verify end to end and the claim is recomputed from public inputs" | Any static host works; the page makes no network lookup by commitment |
| A signed attestation and bundle are plain files the user keeps and can share; checking them needs no network lookup | `verify/verify.mjs` `parseDropped`, `verifyCommitment` | `verify/verify.test.mjs`: "a dropped attestation plus bundle file verifies without a network lookup" | The viewer needs the files from somewhere; nothing stores them for the user |
| Anyone can sign with their own key and be accepted by their own page | `crops/proof-bundle/attestation.mjs` `signAttestation`, `verifierKeyId`; `verify/keys.json` | `crops/proof-bundle/attestation.test.mjs`: "a signed attestation verifies with its key and carries a stable key id" | Each page host decides which keys it lists |

## Open source

| Guarantee | Where enforced (file/function) | Test that checks it | Limits |
| --- | --- | --- | --- |
| MIT or Apache-2.0 at the user's option | `LICENSE-MIT`, `LICENSE-APACHE`; `"license": "MIT OR Apache-2.0"` in each `crops/*/package.json` | None | |
| Shipped third-party code is under permissive licences only | `fork/third-party-licenses.mts` `isPermissive`, run by `fork/third-party-notices.mts` from `fork/build.sh` | None (enforced when `npm run build:fork` runs) | Covers the bundled npm modules and the Rust crates of the WASM prover |
| The TLSNotary core and its patches are pinned | `core/VERSION`; `core/prepare-core.sh` refuses an empty or changed patch series | None (enforced at build) | |
| The WASM prover is built from pinned inputs | `fork/build-wasm.mjs`, `fork/wasm-build-pins.json` | `fork/build-wasm.test.mjs`: "rejects a tampered cached WASM before replacing the installed package", "rejects a stale recipe or changed provenance inputs" | Needs the pinned Rust toolchain to reproduce |
| Circuits and verification keys are pinned by hash | `private-proof/gcp/generated/verification-keys.json`, `private-proof/aws/generated/pins.json`; `private-proof/*/artifact-registry.mjs` | `private-proof/aws/artifact-registry.test.mjs`: "rejects corrupt, truncated and substituted artifacts or keys"; `private-proof/gcp/artifact-registry.test.mjs`; `private-proof/gcp/verification-key-registry.test.mjs` | Needs the pinned Noir compiler (`GCP_NOIR_NARGO`) to rebuild |
| `crops/` and `verify/` run as published, with no build step | Plain `.mjs` files | The `node --test` commands below run the source as is | |

## Privacy

| Guarantee | Where enforced (file/function) | Test that checks it | Limits |
| --- | --- | --- | --- |
| Private ranges reach the verifier only as `sha256(value ‖ blinder)` with a 16-byte blinder | `packages/extension/src/offscreen/gcpPrivateWitness.ts`; `private-proof/gcp/client-plan.mjs`; `private-proof/aws/client.mjs` | `private-proof/gcp/client-plan.test.mjs`: "wrong blinder, opening range, duplicate session and account mismatch fail before proving"; `packages/extension/tests/offscreen/gcpPrivateWitness.test.ts`: "rejects reveals, partial hashes and oversized transcripts on the default path" | The verifier sees the revealed HTTP framing, the user's IP address, hosts, timing and traffic sizes |
| Bundles are accepted only from Proxy-mode receipts with hashed private ranges | `private-proof/gcp/authenticated-transcript.mjs` `authenticatedTranscript`; `private-proof/aws/authenticated-transcript.mjs` `authenticatedAwsTranscript` | `private-proof/aws/authenticated-transcript.test.mjs`: "does not promote a plaintext method to private assurance" | |
| Transcript bytes and blinders are erased when a run settles | `packages/extension/src/offscreen/gcpPrivateWitness.ts` (`clearGcpOpenings`); `packages/extension/src/offscreen/awsPrivateWitness.ts` | `packages/extension/tests/offscreen/gcpPrivateWitness.test.ts`: "preserves full-hash runs, returns only provisional email and sanitized final proof, and erases copies"; `packages/extension/tests/offscreen/awsPrivateWitness.test.ts`: "cancellation settles a hung module and erases its witness copies" | Assumes the user's browser is not compromised |
| The claim is coarse: lowercase words, digits and separators only | `crops/proof-bundle/commitment.mjs` `commitmentFields` (`CLAIM`); `crops/proof-bundle/cloud.mjs` `claimOf` | `crops/proof-bundle/commitment.test.mjs`: "commitment fields are a closed shape with coarse claims only"; `crops/proof-bundle/cloud.test.mjs`: "gcp claim lists observed groups only; aws claim names the proved activity families" | The claim is public once published, and linked to the writer wallet and the publication time |
| An attestation has a closed set of fields; no identifier or free text can be added | `crops/proof-bundle/attestation.mjs` `createAttestation`, `attestationShape` | `crops/proof-bundle/attestation.test.mjs`: "attestations reject inconsistent or personal fields before signing", "verification fails closed with a reason" | |
| Session ids are not part of the published bundle or its hash | `crops/proof-bundle/cloud.mjs` `publicBundle`, `proofHash` | `crops/proof-bundle/cloud.test.mjs`: "proof hash covers exactly the proofs and public inputs, not session routing ids" | |
| A denied CloudTrail lookup is reported as a fixed code (`AWS_ACTIVITY_ACCESS_REQUIRED`), not the response body | `packages/extension/src/offscreen/awsPrivateWitness.ts`; `packages/extension/src/background/gcpPrivateCompletion.ts` `takePrivateCompletion` | `packages/extension/tests/background/awsPrivateCompletion.test.ts`: "passes only the closed AWS permission failure and never extends it to GCP or forged senders" | |

## Security

| Guarantee | Where enforced (file/function) | Test that checks it | Limits |
| --- | --- | --- | --- |
| Attestations are Ed25519 signatures over the canonical attestation and the key id | `crops/proof-bundle/attestation.mjs` `signAttestation`, `verifyAttestation` | `crops/proof-bundle/attestation.test.mjs`: "a signed attestation verifies with its key and carries a stable key id" | Trust rests on the signer (below) |
| Verification fails closed: wrong key, changed field, expired or not yet valid | `crops/proof-bundle/attestation.mjs` `verifyAttestation` | `crops/proof-bundle/attestation.test.mjs`: "verification fails closed with a reason" | |
| The commitment is domain-separated and recomputed, never taken from a label | `crops/proof-bundle/commitment.mjs` `bundleCommitment`; `verify/verify.mjs` `verifyCommitment` | `crops/proof-bundle/commitment.test.mjs`: "commitment is sha256 over the domain-separated canonical fields"; `verify/verify.test.mjs`: "a dropped attestation plus bundle file verifies without a network lookup" | |
| The verify page never shows "Verified" for a swapped bundle, an unknown key or a claim the public inputs do not support | `verify/verify.mjs` `evaluate`, `claimFromPublicInputs` | `verify/verify.test.mjs`: "a swapped bundle, unknown key or missing data never shows verified", "a signature over a claim the public inputs do not support fails" | See the verify page limits below |
| A bundle is accepted only if every proof matches a recorded commitment and verifies against a pinned key | `private-proof/gcp/verify-bundle.mjs` `verifyBundle`; `private-proof/aws/verify-bundle.mjs` `verifyAwsBundle` | `private-proof/gcp/verify-bundle.test.mjs`; `private-proof/aws/verify-bundle.test.mjs`; `private-proof/aws/grouped.test.mjs`: "each group requires its own native receipt, actor relation, cutoff and proof" | The receipts must be authenticated by the caller first |
| The extension runs only plugin files it ships, checked by sha256; the page passes values, never code | `packages/extension/src/offscreen/builtinRun.ts` | `packages/extension/tests/offscreen/builtinRun.test.ts`: "a packaged file that is not the fingerprinted version is refused", "a `code` field in the message is never used" | |
| The page API answers only on build-time origins; none by default | `packages/extension/src/constants/productOrigins.ts` | `packages/extension/tests/constants/productOrigins.test.ts`: "is empty (fail closed) without a build-time list" | |
| `window.tlsn` cannot be replaced by another extension | `packages/extension/src/entries/Content/pageApiLock.ts` | `packages/extension/tests/entries/pageApiLock.test.ts`: "the property cannot be deleted or redefined by someone else" | |
| Private results are accepted only from the extension's own offscreen document on a live route | `packages/extension/src/background/gcpPrivateCompletion.ts` `takePrivateCompletion` (GCP and AWS routes) | `packages/extension/tests/background/gcpPrivateCompletion.test.ts`: "rejects content scripts, other extensions and other extension pages without deleting an active route" | |
| AWS console credentials are captured once from the managed tab, never from the page | `packages/extension/src/background/awsPrivateCapture.ts` | `packages/extension/tests/background/awsPrivateCapture.test.ts`: "refuses foreign senders, page callers, other providers, other windows and stale captures before fetch" | |
| The production manifest asks only for `offscreen` and `webRequest` | `fork/build.sh` (`expected = ["offscreen", "webRequest"]`) | `fork/build-manifest.test.mjs`: "package captures AWS early and the production guard limits the regional wildcard" | |

## Limits

### What is trusted

| Party | Trusted for | If it misbehaves |
| --- | --- | --- |
| TLSNotary verifier operator | Observing a real TLS session and recording the commitments honestly | The proofs prove statements about a transcript that was never sent. Anyone can run their own verifier and publish its key |
| Attestation signer | Running `verifyBundle` or `verifyAwsBundle` before signing, and keeping the private key secret | A signature can cover a bundle that was never checked. The verify page does not re-run the zero-knowledge verifier |
| Extension build | Running only packaged plugins and keeping witness data local | A modified build can leak private values. Build it yourself from this repository |
| Verify page host | Serving `verify/keys.json` and the page code unchanged | It can list any key. Host it yourself to choose your keys |

### What is not private

- **The claim**, the commitment and the signed attestation, to whoever receives them.
- **A public bundle, if shared.** Its public inputs include blinded hashes, the lengths of hidden values (for
  example of an email address or project id) and the time cutoff. Share it only when the user chooses to.
- **Network metadata seen by the verifier** in Proxy mode: IP address, hosts, timing, traffic sizes and the revealed
  HTTP framing.

### Known gaps

- The verify page checks signatures, hashes and pins, not the zero-knowledge proofs themselves.
- For AWS event runs, the verify page checks that the bundle proves one linked event per operation or skill area the
  claim lists, in catalog order. It cannot recompute the names: they come from receipts that stay private, so it
  trusts the signer for them. Page-run claims (`aws:groups:...`) are checked for format only.
- Nothing stores attestations or bundles for the user, and the verify page has no lookup by commitment. A lost file
  cannot be recovered from this repository.

## How to check it yourself

Node 22.10 or later. Run one package at a time.

```sh
(cd crops/proof-bundle && npm test)              # no dependencies
node --test --test-concurrency=1 verify/verify.test.mjs

(cd private-proof/gcp && npm ci && npm test)
(cd private-proof/aws && npm ci && npm test)
node --test --test-concurrency=1 fork/build-manifest.test.mjs fork/build-wasm.test.mjs

npm ci && (cd packages/extension && npm test)   # vitest
```

To check one row, run its test file alone, for example
`node --test --test-concurrency=1 crops/proof-bundle/attestation.test.mjs`.
