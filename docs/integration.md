# Plug it into your project

From a TLS verifier to a checked proof package. A runnable version of these steps: [examples/demo](../examples/demo/README.md).

1. **Run a TLS verifier.** Build and run it with Docker (the build context is the repository root). The webhook
   file maps the provider host to your backend; `*` matches any host.

   ```sh
   docker build -f servers/verifier/Dockerfile -t tlsn-verifier-server .
   docker run -p 7047:7047 \
     -v "$PWD/my-config.yaml:/app/config.yaml" \
     -v "$PWD/attestor-key.json:/run/attestor-key.json:ro" \
     -e TLSN_ATTESTOR_KEY_FILE=/run/attestor-key.json \
     -e TLSN_ATTESTOR_KID='did:web:verifier.example.com#tlsn-attestor' \
     tlsn-verifier-server
   ```

   `my-config.yaml` holds `webhooks: { "*": { url: "https://your-backend.example.com/webhook" } }`. With an attestor
   key (an Ed25519 JWK) every webhook payload also carries a signed `receipt`; without one it carries none. Key
   format, the `did:web` setup and the limits (`TLSN_MAX_SESSIONS`, `TLSN_MEMORY_BUDGET_MB`, ...) are in
   [servers/verifier/README.md](../servers/verifier/README.md). The built-in proxy is at `ws://<host>:7047/proxy`.

2. **Build the extension for your site.** Set `FORK_PRODUCT_ORIGINS` (your page's origin), `FORK_KEY_FILE` and, for
   Cloudflare, `FORK_CF_OAUTH_CLIENT_ID` in `fork/config.env`, then
   `npm ci && npm run build:fork`. Load `fork/out/extension` unpacked. With an empty config you get a development
   build for pages on `http://localhost:5173` or `:5175`. See [Build for your site](architecture.md#build-for-your-site).

3. **Request a proof from your page.** On an allowed origin, in the top frame:

   ```js
   window.postMessage({ type: 'TLSN_RUN_BUILTIN', payload: {
     pluginId: 'gcp-work',            // or 'aws-private-work', 'cloudflare-private-work'
     fingerprint,                     // sha256 of the packaged plugin, from window.tlsn.builtInPlugins
     verifierUrl, proxyUrl,           // your verifier and its proxy
     params: JSON.stringify(params),  // the plugin's parameters
     requestId,                       // your id; every reply carries it
     sessionData,                     // optional, string values
   } }, window.location.origin);
   ```

   `window.tlsn.runBuiltIn({...})` wraps this and returns the result or rejects with an error. Replies are window
   messages with your `requestId`: `TLSN_RUN_BUILTIN_ACK` (private runs), progress events, then
   `TLSN_RUN_BUILTIN_RESPONSE` with `{ success, result }` or `{ success: false, error }`. No ACK within 10 seconds
   means the extension is missing or was reloaded.

4. **Build the proof package in your backend.** Check the proof bundle against the verifier's receipts with the
   provider's `verify-bundle.mjs`, then build the package from the webhooks with `webhookRun` and `buildPackage`
   from `proof-check` (see [building a package](../packages/proof-check/README.md#building-a-package)). To publish a
   signed attestation as well, use `fromVerifiedBundle`, `createAttestation` and `signAttestation`
   ([publishing side](../packages/proof-check/README.md#publishing-side)).

5. **Check a proof.**

   ```sh
   node packages/proof-check/cli.mjs --proof package.json --did did.json   # did.json: your verifier's DID document
   node packages/proof-check/cli.mjs attestation.json --bundle bundle.json  # a signed attestation
   ```

   It prints one line per check. Exit code 0 means all checks passed, 1 a check failed, 2 bad input.

6. **Optional: anchor on BNB Chain.**

   ```sh
   cd packages/bnb-anchor              # after the root npm ci
   export BNB_PRIVATE_KEY=0x...        # funded account; BNB_NETWORK=bsc for mainnet (default: bsc-testnet)
   node cli.mjs register               # once per network
   node cli.mjs publish attestation.json
   node cli.mjs read 0x<uid>
   ```

7. **Optional: host the verify page.** Serve the repository root and open `/verify/`
   (`python3 -m http.server 8080`, then `http://localhost:8080/verify/`). Put your verifier's public key in
   `verify/keys.json`. See [verify/README.md](../verify/README.md).

