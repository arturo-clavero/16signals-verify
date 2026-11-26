# Google Cloud private proof

Zero-knowledge proof of Google Cloud activity, produced in the browser. A person signed in to the Google Cloud console
proves which skill groups they were active in over the last 7, 30 or 90 days, without revealing project ids, email
addresses, log entries or other raw data. The relying party learns a coarse claim, `gcp:observed:<groups>` (for example
`gcp:observed:g1,g4`), and the window. It is the first of three providers; see [`../aws`](../aws) and
[`../cloudflare`](../cloudflare), and [`../README.md`](../README.md) for how a provider is organised. The shared flow
and trust model are in [docs/architecture.md](../../docs/architecture.md).

## Flow

1. The page starts the `gcp-work` built-in plugin ([`plugin.ts`](plugin.ts), bundled by
   [`fork/build-plugins.mjs`](../../fork/build-plugins.mjs)) through the extension.
2. One TLS session reads the user's identity; five further sessions each send one batch of log queries for up to six
   skill groups. Each session runs through the TLSNotary verifier in Proxy mode.
3. Fixed text is revealed. Private values (email, project ids, log entries) are hashed with a random blinder and only
   the hashes reach the verifier. A request header carrying a per-run nonce is fixed by the circuit.
4. Noir circuits run in a worker in the browser and prove that the hidden values have the expected structure, belong
   to the same identity, and fall inside the window.
5. `verify-bundle.mjs` checks the proof bundle against the verifier's receipts and the pinned verification keys.
6. `descriptor.mjs` gives proof-check the claim (from a verified result and recomputed from the public inputs) and its
   headline.

A group that is not in the claim was not established, which is not evidence of no activity.

## Files

| File or folder | Purpose |
| --- | --- |
| `descriptor.mjs` | Provider descriptor for proof-check: pins, claim, headline |
| `plugin.ts`, `request.mjs` | The `gcp-work` built-in plugin and the requests it notarizes (bodies rendered from the catalog) |
| `policy.mjs`, `generated/catalog.json` | The batch layout: which groups go in which query, the window policy |
| `circuits/` | Noir circuits: `identity-scope`, `query-scope`, `timestamps`, `atom`, `atoms-small`, `header`, `headers-small`, `lib` |
| `generated/verification-keys.json` | Pinned verification-key hashes (`pins`) |
| `client-plan.mjs`, `browser-client.mjs`, `browser-worker.mjs`, `proof-runtime*.mjs` | Prover side: plan, run and prove in the browser |
| `browser-link.mjs` | Local browser storage for a link between runs; used by all three providers |
| `verify-bundle.mjs`, `authenticated-transcript.mjs` | Check a bundle against authenticated receipts |
| `build-artifacts.mjs`, `build-verification-keys.mjs`, `build-browser.mjs` | Build the circuit artifacts, keys and browser bundle (need the pinned Noir compiler) |

## Tests

```sh
cd private-proof/gcp
npm ci
npm test
```

`npm test` runs `node --test --test-concurrency=1`. The tests use synthetic fixtures and need no Google Cloud account
or network.
