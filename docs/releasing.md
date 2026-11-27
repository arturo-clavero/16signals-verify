# Releasing the npm packages

Three packages are published from this repository under the `@16signals-verify` scope. They share one version and are
released together by [`.github/workflows/release.yml`](../.github/workflows/release.yml), which runs when an `npm-v*` tag
is pushed and needs the `NPM_TOKEN` secret below.

| Package | Folder | Depends on |
| --- | --- | --- |
| `@16signals-verify/providers` | [`private-proof`](../private-proof) | nothing |
| `@16signals-verify/proof-check` | [`packages/proof-check`](../packages/proof-check) | `providers`; optional `@aztec/bb.js` (ZK step), `viem` (`--uid`) |
| `@16signals-verify/bnb-anchor` | [`packages/bnb-anchor`](../packages/bnb-anchor) | `proof-check`, `viem` |

The workflow publishes them in that order, with [provenance](https://docs.npmjs.com/generating-provenance-statements)
(each tarball is linked to the commit and workflow run that built it).

## One-time setup

1. **Create the npm organization.** On [npmjs.com](https://www.npmjs.com), sign in, choose *Add Organization*, name it
   `16signals-verify` (the free plan is enough for public packages). The scope `@16signals-verify` belongs to it.
2. **Create a token.** In your npm account, *Access Tokens* → *Generate New Token* → a granular token with *Read and
   write* on packages and scopes for the `16signals-verify` organization (or a classic *Automation* token, which skips
   two-factor prompts in CI).
3. **Store it in GitHub.** In the repository, *Settings* → *Secrets and variables* → *Actions* → *New repository
   secret*, name `NPM_TOKEN`, value the token. Never paste it anywhere else.

## Each release

1. **Bump the versions.** Set the same `version` in `private-proof/package.json`, `packages/proof-check/package.json`
   and `packages/bnb-anchor/package.json`, and raise the `@16signals-verify/*` ranges in their `dependencies` if the
   minor version changes (`^0.1.0` only accepts `0.1.x`). Then refresh the lockfile from the repository root:

   ```sh
   npm install --package-lock-only --ignore-scripts
   ```

2. **Check the tarballs locally** (nothing is uploaded):

   ```sh
   for dir in private-proof packages/proof-check packages/bnb-anchor; do (cd "$dir" && npm pack --dry-run); done
   node --test --test-concurrency=1 packages/proof-check/*.test.mjs packages/bnb-anchor/*.test.mjs private-proof/package.test.mjs
   ```

   `private-proof/package.test.mjs` fails if the providers package's `files` list no longer matches what the
   descriptors import.

3. **Merge to `main`, tag, push.** The tag is `npm-v` followed by the version:

   ```sh
   git tag npm-v0.1.0
   git push origin npm-v0.1.0
   ```

   The workflow checks that the tag matches every package's version and that `NPM_TOKEN` is set, installs the three
   packages' dependencies, runs their tests and publishes. The `npm-v` prefix keeps these tags apart from the `v*` tags
   that other workflows react to.

4. **Check the result** on `https://www.npmjs.com/package/@16signals-verify/proof-check` (and the other two): the
   version, the provenance badge, and the file list.

A version cannot be published twice. If a publish fails halfway, fix the cause, bump the patch version of every
package and tag again.

## Publishing from a laptop

Without the workflow, publish each folder in the order above with
`npm publish --access public --provenance=false` (provenance is only possible from CI). An account whose only second
factor is a security key cannot answer the command line's one-time-password prompt; use a granular token with
*Bypass two-factor authentication* instead. npm then holds each version as *staged* until a maintainer approves it on
the package page with the security key; it installs a few minutes after approval.
