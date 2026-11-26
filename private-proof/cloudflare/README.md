# Cloudflare private proof

Zero-knowledge proof of Cloudflare activity, produced in the browser. A person who signs in to Cloudflare proves that
their own user made certain kinds of successful, state-changing changes in the last 90 days, without revealing resource
names, ids, request bodies, account ids or the audit-log rows themselves. The relying party learns a coarse claim and
nothing else.

This package is the Cloudflare counterpart of [`../gcp`](../gcp) and [`../aws`](../aws). It reuses the same TLS
notarization, Proxy-mode verifier and hash-commitment scheme described in [`docs/architecture.md`](../../docs/architecture.md).

## What is proven and what stays private

Proven:

- the proof comes from the Cloudflare user the sign-in belongs to (`attribution: cloudflare-user`);
- every counted row is a successful, non-view audit-log action whose actor is that user (the same id as the identity
  session), with a known product, resource type and action from the catalog, inside the 90-day window;
- the fields that are revealed (product, type, action, result, actor type, tool context, day) come from the real row
  structure, and every hidden value is proven to be exactly one JSON value or string tail.

Revealed to the verifier (not to the relying party): HTTP framing, the host (`api.cloudflare.com`), request timing,
traffic sizes, the user's IP address and the revealed row skeleton above. Everything else (the access token, account id,
user id, resource names and ids, request and response objects, times within the day) is committed as
`sha256(value || blinder)` with a 16-byte blinder and only appears inside proofs.

Not covered: configuration correctness, downstream outcomes, or the absence of activity. A skill group that is not in the
result was not established, which is different from "no activity".

## Sign-in and run flow

1. **Sign-in.** [`cloudflarePrivateAuth.ts`](../../packages/extension/src/background/cloudflarePrivateAuth.ts) runs OAuth
   Authorization Code with PKCE through `chrome.identity.launchWebAuthFlow`, against `dash.cloudflare.com`. The scopes
   are `audit-logs.read user-details.read account-settings.read`. The OAuth client id is a public client id set at build
   time with `FORK_CF_OAUTH_CLIENT_ID` (`fork/build.sh`); without it the check cannot sign in. The token is handed only to
   the offscreen run that asked, kept in memory, and revoked when the run ends. It is never stored.
2. **Discovery (not proven).** [`discovery.mjs`](discovery.mjs) reads the user's own successful non-view rows locally
   (up to 5 reads of 1,000 rows, newest first) and matches them against the catalog. Nothing is sent anywhere. It then
   picks up to 3 disjoint windows of at most 12 consecutive rows, preferring windows with the most distinct
   (skill group, day) pairs.
3. **Identity session.** One TLS session fetches `GET /client/v4/user`. Only the user id is read from the body, as a
   hidden value.
4. **Page sessions** `P0`..`P2` ([`session.mjs`](session.mjs), [`request.mjs`](request.mjs)). Each fetches one
   `GET /client/v4/accounts/<id>/logs/audit` page for a time window and proves up to 12 selected rows. The request is
   fixed: the account id, the query and every header value except a short public list are hidden, and `Authorization`
   is always hidden.
5. **Row structure.** Cloudflare serves each row as compact JSON with sorted keys, so a row has one fixed grammar
   ([`row-structure.mjs`](row-structure.mjs)). The prover reveals the skeleton and hides each value as its own piece;
   the verifier reads the public fields from the skeleton only. Cloudflare answers with chunked transfer encoding;
   [`http-chunked.mjs`](http-chunked.mjs) maps wire bytes to body bytes, and a row that crosses a chunk boundary is dropped.
6. **Proofs and verification.** [`verify-bundle.mjs`](verify-bundle.mjs) derives the proof targets from the
   authenticated receipts, so prover and verifier compute the same list, and checks every proof against the keys pinned
   in [`generated/pins.json`](generated/pins.json). Proving runs in a worker ([`browser-worker.mjs`](browser-worker.mjs))
   with `@noir-lang/noir_js` and `@aztec/bb.js` (UltraHonk).
7. **Fast identity check.** A run can be saved as a local browser link. A later check then reads only the identity and
   proves with `identity-refresh` that the fresh user id equals the recorded one, instead of redoing the audit-log pages.

## Skill groups and counted actions

[`skill-groups.mjs`](skill-groups.mjs) lists 9 skill groups in 5 areas and the audit-log actions (`resource.product`,
`resource.type`, `action.type`) that count as evidence for each. Each operation has a tier: `basic` (creates or toggles
one resource), `intermediate` (configuration whose effect has to be understood) or `advanced` (cross-resource or
security-critical design). The tier describes the kind of work, never its quality.

| Area | Group | Counted actions |
| --- | --- | --- |
| Edge compute | Workers deploys and versions | `workers` `scripts` update; `scripts.deployments` create; `scripts.versions` create |
| Edge compute | Worker settings and routing | `workers` `scripts.script-settings` update; `scripts.subdomain` create; `subdomain` update; `scripts.schedules` update |
| Data and storage | Workers KV | `storage` `kv.namespaces` create; `kv.namespaces.values` update |
| Data and storage | D1 SQL databases | `d1` `database` create; `database.query` create |
| Messaging and workflows | Queues | `queues` create; `consumers` create |
| Messaging and workflows | Workflows | `workflows` update |
| AI and vectors | Vectorize indexes | `vectorize` `indexes` create |
| Security and access | Secrets | `workers` `scripts.secrets` update; `secrets_store` `stores.secrets` create |
| Security and access | API tokens and OAuth apps | `tokens` create and delete; `oauth_clients` create |

A row counts only when the actor is the signed-in user, the result is `success`, and the actor context is one of
`oauth`, `dash`, `api_token` or `api_key`. The context maps to a tool (`cli`, `console`, `api`) and is revealed. View
actions and actions by system or account actors never count. The group order and ids are fixed once shipped.

## Circuits

All under [`circuits/`](circuits), compiled with a pinned Noir compiler; shared code is in `circuits/lib`.

| Circuit | Purpose |
| --- | --- |
| `headers` | Hidden header values and request-target pieces (up to 512 bytes, 4 per proof): printable ASCII, no CR or LF |
| `headers` (small, single) | Smaller variant (16 values of 64 bytes) and a single-value variant (2,048 bytes) |
| `json-small` | 16 hidden row pieces of up to 64 bytes per proof: one JSON value or string tail |
| `json` | 4 hidden row pieces of up to 512 bytes per proof |
| `json-wide` | One hidden row piece of up to 4,096 bytes (large request or response objects) |
| `actor` | Binds up to 8 rows' actor ids to the identity session's user id: same length, same bytes |
| `identity-refresh` | Shows a fresh user id equals the one from a saved, already verified run |
| `lib` | Shared Noir modules |

Pinned artifact hashes are checked by `artifact-registry.mjs`; rebuild artifacts with `build-artifacts.mjs`.

## Result and claim format

`verifyCloudflareBundle` returns:

```
{ attribution: 'cloudflare-user', windowDays: 90, observations: [{ group, ... }] }
```

[`descriptor.mjs`](descriptor.mjs) (`claimFromResult`) turns it into the public claim, which
admits only lowercase words, digits and separators:

| Claim | Meaning |
| --- | --- |
| `cloudflare:groups:<positions>:user` | 1-based positions in `CLOUDFLARE_SKILL_GROUPS`, e.g. `cloudflare:groups:1,3:user` |

The window is always 90 days. The same descriptor gives the headline with the group labels for
[`packages/proof-check`](../../packages/proof-check) and the verify page. Like the AWS page-run claims, it is checked
for format and known positions only.

## Tests

```
cd private-proof/cloudflare
npm ci
npm test
```

`npm test` runs the unit and fixture tests serially (`node --test --test-concurrency=1`). They use synthetic receipts and
rows and need no Cloudflare account or network. The extension side has its own tests in
[`packages/extension/src/cloudflare-private`](../../packages/extension/src/cloudflare-private).

`node full-path-check.mjs [rows] [threads]` is optional and heavy: it proves a synthetic run end to end with real
proofs and verifies the bundle against the pinned keys. It needs built artifacts (`node build-artifacts.mjs`, which needs
the pinned Noir compiler) and a lot of memory, so run it alone.

## Limits

- Window: 90 days ending when the attempt is issued.
- At most 3 page sessions per run, 12 rows each; discovery reads at most 5,000 rows.
- A page session fetches one response of up to 300 KB; a row must fit the row grammar and its size limits and lie inside
  one chunk, otherwise it is skipped.
- Only actions in the catalog count; other actions are not proven. Entries were added from real audit-log samples only.
- Audit logs record account-level changes. Activity that does not appear there (for example traffic served, data read
  or written at runtime by a Worker, or products that do not write audit-log rows) cannot be shown.
- The tool context comes from the audit row, so it says which kind of credential made the change, not who typed it.
- Proving is memory-heavy in the browser; the 12-row cap follows measured memory use.
