# TLSNotary Verifier Server

A Rust-based HTTP server with WebSocket support for TLSNotary verification operations.

## Features

- **Health Check Endpoint**: Simple `/health` endpoint that returns "ok" for monitoring
- **Verifier WebSocket**: WebSocket server at `/verifier` for TLSNotary verification
- **Signed receipts**: optional Ed25519 receipts over each verified proof, key published at `/.well-known/did.json` (see [Signed receipts](#signed-receipts))
- **CORS Enabled**: Permissive CORS configuration for cross-origin requests
- **Async Runtime**: Built on Tokio for high-performance async operations
- **Logging**: Structured logging with tracing for debugging and monitoring
- **Error Handling**: Proper error handling and automatic cleanup on failure

## Dependencies

- **tlsn**: TLSNotary verification library
- **axum**: Modern web framework with WebSocket support
- **tokio**: Async runtime with full features
- **tokio-util**: Async utilities for stream compatibility
- **tower-http**: CORS middleware
- **tracing**: Structured logging and diagnostics
- **eyre**: Error handling and reporting

## Building

The server builds against the same pinned, patched TLSNotary core as the extension's WASM prover (mux backpressure,
several proofs on one session). Prepare it once at `core/tlsn` (the path `Cargo.toml` points at; it is git-ignored):

```bash
# From the repository root
bash core/prepare-core.sh "$PWD/core/tlsn"
```

```bash
# From the verifier package directory
cargo build

# For production release
cargo build --release
```

## Running

```bash
# Development mode
cargo run

# Production release
cargo run --release
```

The server will start on `0.0.0.0:7047` by default.

## API Endpoints

### Health Check

**GET** `/health`

Returns a simple "ok" response to verify the server is running.

**Example:**

```bash
curl http://localhost:7047/health
# Response: ok
```

### Create Session

**POST** `/session`

Creates a new verification session with specified data limits. Returns a session ID that can be used to connect to the verifier WebSocket.

**Request Body:**

```json
{
  "maxRecvData": 16384,
  "maxSentData": 4096
}
```

**Response:**

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Example:**

```bash
curl -X POST http://localhost:7047/session \
  -H "Content-Type: application/json" \
  -d '{"maxRecvData": 16384, "maxSentData": 4096}'
```

### Verifier WebSocket

**WS** `/verifier?sessionId=<session-id>`

Establishes a WebSocket connection for TLSNotary verification using a previously created session. Upon connection:

1. Validates the session ID exists
2. Retrieves maxRecvData and maxSentData from the session
3. Spawns a verifier with the configured limits
4. Performs TLS proof verification
5. Cleans up and removes the session when connection closes

**Query Parameters:**

- `sessionId` (required): Session ID returned from POST /session

**Error Responses:**

- `404 Not Found`: Session ID does not exist or has already been used

**Example using websocat:**

```bash
# First, create a session
SESSION_ID=$(curl -s -X POST http://localhost:7047/session \
  -H "Content-Type: application/json" \
  -d '{"maxRecvData": 16384, "maxSentData": 4096}' | jq -r '.sessionId')

# Then connect with the session ID
websocat "ws://localhost:7047/verifier?sessionId=$SESSION_ID"
```

**Example using JavaScript:**

```javascript
// Create a session first
const response = await fetch('http://localhost:7047/session', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ maxRecvData: 16384, maxSentData: 4096 }),
});
const { sessionId } = await response.json();

// Connect to verifier with session ID
const ws = new WebSocket(`ws://localhost:7047/verifier?sessionId=${sessionId}`);

ws.onopen = () => {
  console.log('Connected to verifier');
};

ws.onmessage = (event) => {
  console.log('Verification result:', event.data);
};

ws.onclose = () => {
  console.log('Verifier disconnected, session cleaned up');
};

ws.onerror = (error) => {
  console.error('Verification error:', error);
};
```

### Proof protocol on `/session`

The client sends `register`, then one `reveal_config` per proof **before** the prover's prove request: the
verifier checks each proof against the ranges announced for it.

- Results: a `REVEAL` range must lie in revealed plaintext; a `HASH` range must match a hash commitment of exactly
  that range, direction and algorithm, and its result is the commitment's hex digest. A hash-only proof (nothing
  revealed) is accepted. An `ALL` handler must cover the whole transcript of its direction.
- Several proofs on one session: `register` with `"multiReveal": true` gets `session_registered` with
  `"multiReveal": true` and may then prove the same transcript several times: per proof a `reveal_config` (from
  the second proof on with a `step`, `[A-Za-z0-9_-]{1,32}`), the prove request, then
  `reveal_completed {reveal, resultId, results}`. `{"type":"finish"}` (or the client closing, or 60 s without a
  further `reveal_config`) ends it with `session_closed {reveals}`. At most 64 proofs. Each proof is a result of
  its own (webhook shape unchanged): the first under the session id, each later one under a fresh UUID, its
  `sessionData` carrying the proof's `step`, `revealOf` (the session id) and `reveal` (0-based index); a client
  cannot set those two keys. The first proof proves the server identity; a later one may leave it out but may
  not name another server. A failed proof ends the session; earlier results stand. A client without
  `multiReveal` sees the upstream protocol (`session_completed`).
- The TLS connection, and then each proof, may take up to 300 s.

## Verifier Architecture

The verifier implementation follows this flow:

1. **Session Creation**: Client sends POST request to `/session` with maxRecvData and maxSentData
2. **Session Storage**: Server generates UUID, stores session config in HashMap
3. **WebSocket Connection**: Client connects to `/verifier?sessionId=<id>`
4. **Session Lookup**: Server validates session exists and retrieves configuration
5. **Task Spawning**: Server spawns async task with session-specific limits
6. **Verification Process**:
   - Uses maxRecvData and maxSentData from session config
   - Configures protocol validator with session limits
   - Creates verifier with TLSNotary config
   - Performs MPC-TLS verification
   - Validates server name and transcript data
7. **Error Handling**: Any errors are caught, logged, and cleaned up automatically
8. **Cleanup**: Session is removed from storage when WebSocket closes

### Session Management

- **Thread-safe storage**: Uses `Arc<Mutex<HashMap>>` for concurrent access
- **One-time use**: Sessions are automatically removed after WebSocket closes
- **Session isolation**: Each verifier gets independent maxRecvData/maxSentData limits
- **Error handling**: Invalid session IDs return 404 before WebSocket upgrade

**Note**: The current implementation logs all incoming WebSocket messages. Full verifier integration requires converting the axum WebSocket to AsyncRead/AsyncWrite format using the WsStream bridge.

## Configuration

The server configuration is currently hardcoded in `main.rs`:

- **Host**: `0.0.0.0` (all interfaces)
- **Port**: `7047`

To change these, modify the `SocketAddr::from()` call in `main.rs`.

Limits, read from the environment at start-up (a malformed value stops the server):

| Variable | Default | Effect |
|---|---|---|
| `TLSN_MAX_SESSIONS` | 20 | `/session` upgrades get 429 while this many sessions are active |
| `TLSN_MAX_RECV_DATA`, `TLSN_MAX_SENT_DATA` | none | a `register` declaring more bytes is refused |
| `TLSN_MAX_REVEAL_BLOCKS` | 2500 | a proof touching more 16-byte AES blocks (revealed and hash-committed ranges, per direction) is refused with `REVEAL_TOO_LARGE`, at `reveal_config` and again at the prove request, before the prove phase where verifier memory grows with the block count |
| `TLSN_MEMORY_BUDGET_MB` | 85% of the container's cgroup memory limit; none without a limit | memory-weighted admission: 64 MB per session at the `/session` upgrade (429 when full), then the step budget of its blocks (180 MB up to 120 blocks, 320 up to 400, 520 up to 820, 860 up to 1420, 1640 up to 2520) at `reveal_config` and at the prove request, waiting up to 30 s in a FIFO queue, else `VERIFIER_BUSY` (retryable). The reveal ceiling is lowered to what one session can be admitted with; at least 180 |

Refusals log one JSON line each (`tlsn.reveal.too_large`, `tlsn.admission`), counts only. A session holds its
reservation (the largest of its proofs) until it ends.

A new `/session` socket must send `register` within 30 s and its first `reveal_config` within 180 s.

## Signed receipts

With an attestor key configured, every verified proof's webhook payload gains two top-level fields, both or
neither: `receipt`, a compact JWS signed by the verifier, and `leaves`, the salted ranges the receipt's Merkle root
commits to. A reader holding the payload and the verifier's public key can check which bytes of which TLS session
the verifier witnessed, without trusting whoever relays the payload. Without a key nothing changes.

### Configuration

| Variable | Effect |
|---|---|
| `TLSN_ATTESTOR_KEY` | the private key, a one-line OKP Ed25519 JWK: `{"kty":"OKP","crv":"Ed25519","x":"<32 bytes b64url>","d":"<32 bytes b64url>"}` (unpadded base64url; extra members such as `kid`, `use`, `alg: "EdDSA"` are allowed) |
| `TLSN_ATTESTOR_KEY_FILE` | instead of `TLSN_ATTESTOR_KEY`: a file holding that JWK (e.g. a mounted secret); setting both is an error |
| `TLSN_ATTESTOR_KID` | required with a key: the key's full DID URL, `did:web:<host>#<fragment>`, e.g. `did:web:verifier.example.com#tlsn-attestor`. `<host>` is the public host the verifier is served on (a port is percent-encoded, `did:web:localhost%3A7047`) |

Generate a key with
`node -e "const {generateKeyPairSync:g}=require('crypto');console.log(JSON.stringify(g('ed25519').privateKey.export({format:'jwk'})))"`.
The server checks that `x` is the public key of `d` and refuses to start on a malformed key or kid. The key, the
receipts and the salts are never logged.

`GET /.well-known/did.json` serves the did:web document for the kid's host (404 without a key): one
`JsonWebKey2020` verification method with the public JWK (`kty`, `crv`, `x`, `alg`, `use`; never `d`), listed in
`assertionMethod`. Serve the verifier at `https://<host>/` so `did:web:<host>` resolves to it. Only the current key
is listed: when you rotate (new fragment, e.g. `tlsn-attestor-2`), receipts signed by the old key need the old
public key from elsewhere.

### Format

`receipt` header: `{"alg":"EdDSA","kid":"<TLSN_ATTESTOR_KID>","typ":"tlsn-receipt+jws"}`. Payload, in this order:
`{"v":1,"serverName","sessionId","proofId","verifiedAt","tlsnVersion","root","leafCount"}`. `sessionId` is the id
the result is delivered under (for a later proof of a multi-reveal session, its own result id), `proofId` the
client's `sessionData.proofId` (omitted when it sent none), `verifiedAt` RFC 3339 UTC with milliseconds,
`tlsnVersion` the TLSNotary core version, `root` 64 lowercase hex.

`leaves`: one per `config.sent` range in config order, then one per `config.recv` range, as
`{"direction":"sent"|"recv","start","end","salt":"<64 lowercase hex>"}`; never the bytes. Each salt is 32 fresh
OS CSPRNG bytes.

```text
leafHash = SHA-256(0x00 ‖ dir ‖ u64be(start) ‖ u64be(end − start) ‖ salt ‖ bytes)    dir: 0x00 sent, 0x01 recv
nodeHash = SHA-256(0x01 ‖ left ‖ right)
```

over the raw transcript bytes the verifier holds. Levels pair (0,1), (2,3), …; an odd last node is promoted
unchanged; one leaf is its own root. Test vectors:
[`src/tests/receipt-merkle-vectors.json`](src/tests/receipt-merkle-vectors.json).

**v2 (private ranges).** A `HASH` range was never revealed, so it gets a commit leaf over the commitment digest
the verifier checked for exactly that range, direction and algorithm (the same value as that range's `results`
entry), binding the commitment a zero-knowledge proof later opens to the TLS session:

```text
commitLeafHash = SHA-256(0x02 ‖ dir ‖ u64be(start) ‖ u64be(end − start) ‖ salt ‖ digest)    digest: raw bytes
```

Same leaf order and tree rules. A proof with at least one commit leaf signs `"v":2` (payload otherwise identical)
and every leaf gains `kind` (`"reveal"` | `"commit"`); a commit leaf also gains `alg` (`sha256`, `blake3`,
`keccak256`) and `digest` (lowercase hex). A proof without a `HASH` range keeps v1 byte for byte, so treat a leaf
without `kind` as `reveal`. Test vector for other implementations:
[`src/tests/receipt-v2-vectors.json`](src/tests/receipt-v2-vectors.json) (transcript, salts, digests, preimages,
levels, root and the exact JWS under the fake test seed `0x07` × 32).

No receipt (the payload is otherwise unchanged; the reason is logged by name) when a proof has no range, a `HASH`
range lacks its exact verified commitment, or the CSPRNG fails.

### Verifying a receipt

1. Resolve the header's `kid`: fetch `https://<host>/.well-known/did.json` for `did:web:<host>`, take the
   `verificationMethod` whose `id` is the kid and which is listed in `assertionMethod`.
2. Verify the JWS with that key, EdDSA only (e.g. `jose`: `compactVerify(jws, key, { algorithms: ['EdDSA'] })`),
   and check `typ` is `tlsn-receipt+jws`.
3. Recompute every leaf hash from `leaves` and the bytes you were given (the revealed bytes for a reveal leaf,
   `digest` for a commit leaf), build the tree, and compare with `root` and `leafCount`. To check a single range,
   an inclusion proof (its siblings, bottom up) against `root` is enough.
4. Check `serverName`, `sessionId` / `proofId` and `verifiedAt` against what you expect.

## Development

### Adding New Routes

Add routes to the Router in `main.rs`:

```rust
let app = Router::new()
    .route("/health", get(health_handler))
    .route("/verifier", get(verifier_ws_handler))
    .route("/your-route", get(your_handler))  // Add here
    .layer(CorsLayer::permissive())
    .with_state(app_state);
```

### Project Structure

```
src/
├── main.rs       # Server setup, routing, and WebSocket handling
├── config.rs     # Configuration constants (MAX_SENT_DATA, MAX_RECV_DATA)
└── verifier.rs   # TLSNotary verification logic
```

### Extending Application State

Modify the `AppState` struct to share data between handlers:

```rust
struct AppState {
    // Add your shared state here
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}
```

## Integration with Extension

This server is designed to work with the TLSNotary browser extension located in `packages/extension`. The extension will connect to the WebSocket endpoint for verification operations.

## License

See the root LICENSE file for license information.
