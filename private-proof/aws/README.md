# AWS private proof

Zero-knowledge proof of AWS activity, produced in the browser. A person signed in to the AWS console proves that their
IAM user made certain kinds of successful, state-changing calls in the last 90 days, without revealing resource names,
policy documents, account ids or the CloudTrail rows themselves. The relying party learns a coarse claim and nothing else.

This package is the AWS counterpart of [`../gcp`](../gcp). It reuses the same TLS notarization, Proxy-mode verifier and
hash-commitment scheme described in [`docs/architecture.md`](../../docs/architecture.md).

## What is proven and what stays private

Proven:

- the proof comes from the IAM user the console session belongs to (`attribution: iam-user`);
- every counted event is a successful, non-read-only call recorded in CloudTrail for that user, inside the 90-day window;
- the identity and the events belong to the same account, and the event fields satisfy the operation's reviewed schema;
- optionally, which kind of tool made the call (console, CLI, Terraform, other SDK), read from the CloudTrail `userAgent`.

Revealed to the verifier (not to the relying party): HTTP framing, hosts, request timing, traffic sizes and the user's IP
address. Everything else (names, ARNs, policy bodies, ids, timestamps) is committed as `sha256(value || blinder)` with a
16-byte blinder and only ever appears inside proofs.

Not covered: configuration correctness, downstream outcomes, or the absence of activity. A skill group that is not in the
result was not established, which is different from "no activity".

## Run flow

1. **Identity session.** One TLS session fetches the caller identity (`GetCallerIdentity`, then the IAM user). The user
   name and account id stay hashed. The result is saved as a local browser link ([`../gcp/browser-link.mjs`](../gcp/browser-link.mjs)),
   so a later run can use the `identity-refresh` circuit to show that a fresh identity read matches the saved one,
   instead of reproving the whole identity.
2. **Discovery.** The client pages through CloudTrail `LookupEvents` for the user (`activity-discovery.mjs`) and matches
   events against the catalog by service and event name. `activity-selection.mjs` then picks what to prove. If
   CloudTrail denies the lookup, the run stops with the fixed error `AWS_ACTIVITY_ACCESS_REQUIRED` and nothing from the
   response body is kept.
3. **Proving sessions.** A run uses one of two kinds, never both:
   - **Event sessions** (`E0`, `E1`, ...): one session per selected skill area, each fetching a single event by
     `EventId`. At most 4 event sessions per run (`sessions.mjs`).
   - **Page sessions** (`P0`, `P1`, ...): each fetches one `LookupEvents` page (50 rows) for a time window and proves
     several of its rows in batches. At most 5 page sessions per run. Sessions can target any commercial Region in
     `AWS_REGIONS` (`request.mjs`); events of global services (IAM, STS, CloudFront, Route 53, Organizations) are only
     recorded in `us-east-1`.
4. **Batched proofs.** Rows are proven in groups by the `event-batch` circuits, with a tool-class proof per
   row where requested. `event-batch.mjs` plans the batches; `proof-runtime.mjs` runs them with `@noir-lang/noir_js`
   and `@aztec/bb.js` (UltraHonk) in a worker (`browser-worker.mjs`).
5. **Verification.** `verify-bundle.mjs` checks, from authenticated verifier receipts, that every proof's hashed inputs
   match a recorded commitment, that lengths match committed ranges, that sessions and windows are consistent
   (page windows must not overlap), and that every proof verifies against the pinned keys in
   [`generated/pins.json`](generated/pins.json).

## Operation catalog and skill groups

[`operation-catalog.mjs`](operation-catalog.mjs) lists the operations that can be proven. Each entry carries the allowed
request and response trees, reviewed from real samples. It currently has 11 operations in 8 skill areas: IAM role trust
update and policy attach, Lambda configuration and code update, security group ingress, S3 versioning and lifecycle,
CloudFormation change set, ECS task definition, DynamoDB TTL and CloudWatch metric alarm. `AWS_SKILL_AREAS` fixes the
area order; area ids never change once shipped.

[`skill-groups.mjs`](skill-groups.mjs) is the wider, name-only catalog used for discovery and display: 25 groups
(IAM roles and policies, identity federation, organizations, KMS, secrets, VPC, security groups, load balancing, DNS,
edge, compute, Lambda, API Gateway, workflows, event routing, messaging, ECS, EKS, ECR, relational databases, DynamoDB,
S3, infrastructure as code, CI/CD, observability) with 152 CloudTrail operations. Each operation has a tier:

| Tier | Meaning |
| --- | --- |
| `basic` | creates or toggles one resource |
| `intermediate` | configuration whose effect has to be understood |
| `advanced` | cross-resource or security-critical design |

The tier describes the kind of work, never its quality. Operations usually issued by automation are flagged `auto`.
Matching a group by name is activity evidence only; proving the event itself requires a full entry in
`operation-catalog.mjs`.

## Tool class

[`tool-class.mjs`](tool-class.mjs) mirrors the `user-agent-class` circuit, which outputs only a class id from the decoded
`userAgent`: `console`, `cli`, `terraform` or `sdk-other` (0 means none matched). The `userAgent` is whatever the calling
tool sent, so the class says which tool the request reported, not who typed it.

## Circuits

All under [`circuits/`](circuits), compiled with a pinned Noir compiler; shared code is in `circuits/lib`.

| Circuit | Purpose |
| --- | --- |
| `identity-link` | Binds the IAM identity JSON to its commitments and checks its structure |
| `identity-refresh` | Shows a fresh identity read matches the identity from a saved, already verified run |
| `event-link` | Links a single event's request id, event id, time and actor to the identity |
| `event-batch` | Proves five LookupEvents rows per proof with a short event body |
| `event-batch-wide` | Proves three rows per proof with event bodies up to 2,048 bytes |
| `user-agent-class` | Outputs the tool class of a committed `userAgent` |
| `escaped-atom` | Binds an escaped (JSON-in-JSON) value to its decoded form |
| `escaped-atom-small`, `escaped-atoms-small` | Smaller variants for short tails (one value, up to eight values) |
| `xml-text` | Binds a complete XML element-text span from the identity response |
| `lib` | Shared Noir modules: identity, escaped values, batch rows, tool classes |

Pinned artifact hashes are checked by `artifact-registry.mjs`; rebuild artifacts with `build-artifacts.mjs`.

## Result and claim formats

`verifyAwsBundle` returns one of two shapes:

```
{ activities: [operation ids], attribution: 'iam-user', windowDays: 90, tools: [...] }   // event runs
{ attribution: 'iam-user', windowDays: 90, observations: [{ group, eventSource, ... }] } // page runs
```

[`crops/proof-bundle/cloud.mjs`](../../crops/proof-bundle/cloud.mjs) (`claimOf`) turns the result into the public claim.
Claims admit only lowercase words, digits and separators:

| Claim | Used for |
| --- | --- |
| `aws:activity:<operation ids>:iam-user` | event runs, ids in catalog order, e.g. `aws:activity:iam-role-trust-update,security-group-ingress:iam-user` |
| `aws:areas:<positions>:iam-user` | event runs whose names exceed 128 bytes; 1-based skill-area positions |
| `aws:groups:<positions>:iam-user` | page runs; 1-based skill-group positions in display order |
| `aws:iam-role-trust-update:iam-user` | legacy single-activity form, still accepted |

All claims carry a 90-day window. [`verify/verify.mjs`](../../verify/verify.mjs) accepts the same formats.

## Tests

```
cd private-proof/aws
npm ci
npm test
```

`npm test` runs the unit and fixture tests serially (`node --test --test-concurrency=1`). They use synthetic receipts and
need no AWS account or network. Several tests run the planner, prover double and verifier end to end.

Optional heavy checks run real proofs on synthetic data and need built artifacts (`node build-artifacts.mjs`, which
needs the pinned Noir compiler). A single batch proof can peak at several GB of memory, so run them one at a time:

- `node page-path-check.mjs`: a full page run, from planning to verification;
- `node event-batch-check.mjs`: batch row rejection cases and one real batch proof;
- `node user-agent-class-check.mjs [threads]`: real tool-class proofs.

## Limits

- Window: 90 days ending when the attempt is issued.
- Event runs: at most 4 event sessions; page runs: at most 5 page sessions; one kind per run.
- A page session fetches one response of up to 300 KB (50 rows); rows with event bodies beyond 2,048 bytes cannot be proven.
- Only operations with a full catalog entry can be proven; other matches are reported by name only.
- Only commercial Regions in `AWS_REGIONS`; global-service events are read from `us-east-1`.
- Proving is memory-heavy in the browser; the caps above follow measured proving time.
