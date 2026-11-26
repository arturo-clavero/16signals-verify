//! Signed attestor receipts.
//!
//! After a proof verifies, the verifier commits to every range of the reveal
//! config with a salted Merkle tree and signs a small receipt with an Ed25519
//! key. The webhook payload gains two additive top-level fields, both or
//! neither:
//!
//! ```text
//! receipt: "<compact JWS, EdDSA, typ tlsn-receipt+jws, kid TLSN_ATTESTOR_KID>"
//! leaves:  [{ direction: "sent"|"recv", start, end, salt: "<64 hex>" }, ...]
//! ```
//!
//! Leaves are built over the RAW transcript bytes the verifier holds, one per
//! `config.sent` range in config order, then one per `config.recv` range:
//!
//! ```text
//! leafHash = SHA-256(0x00 || dir || u64be(start) || u64be(end - start) || salt || bytes)
//!            dir = 0x00 sent, 0x01 recv; salt = 32 CSPRNG bytes, fresh per leaf
//! nodeHash = SHA-256(0x01 || left || right)
//! ```
//!
//! Levels pair (0,1), (2,3), ...; an odd last node is promoted unchanged; one
//! leaf is its own root; zero leaves give no root and no receipt.
//!
//! Without a key nothing is emitted. A key that is set but malformed stops the
//! server at start-up. The key, the receipts and the salts are never logged.
//! The public key is served as a did:web document (`/.well-known/did.json`).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::RangeWithHandler;

/// Private OKP Ed25519 JWK JSON (`kty OKP, crv Ed25519, x, d`). Unset or
/// empty (and no key file): no receipts.
pub(crate) const KEY_ENV: &str = "TLSN_ATTESTOR_KEY";
/// Path of a file holding the same private JWK (e.g. a mounted secret).
pub(crate) const KEY_FILE_ENV: &str = "TLSN_ATTESTOR_KEY_FILE";
/// Full DID URL of the key, `did:web:<host>#<fragment>`, e.g.
/// `did:web:verifier.example.com#tlsn-attestor`. Required with a key.
pub(crate) const KID_ENV: &str = "TLSN_ATTESTOR_KID";
/// `typ` of the JWS header.
pub(crate) const JWS_TYP: &str = "tlsn-receipt+jws";
/// TLSNotary core version the verifier is built against (the `tlsn` version
/// pin in Cargo.toml; a test keeps the two in step).
pub(crate) const TLSN_VERSION: &str = "0.1.0-alpha.15";
/// Receipt payload / construction version.
pub(crate) const RECEIPT_VERSION: u8 = 1;
const MAX_KEY_LEN: usize = 1024;
const MAX_KID_LEN: usize = 256;

pub(crate) type Hash = [u8; 32];
pub(crate) type Salt = [u8; 32];

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LeafDirection {
    Sent,
    Recv,
}

impl LeafDirection {
    fn tag(self) -> u8 {
        match self {
            Self::Sent => 0x00,
            Self::Recv => 0x01,
        }
    }
}

/// `0x00 || dir || u64be(start) || u64be(len) || salt || bytes`.
pub(crate) fn leaf_preimage(direction: LeafDirection, start: usize, bytes: &[u8], salt: &Salt) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + 32 + bytes.len());
    out.push(LEAF_TAG);
    out.push(direction.tag());
    out.extend_from_slice(&(start as u64).to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(bytes);
    out
}

pub(crate) fn leaf_hash(direction: LeafDirection, start: usize, bytes: &[u8], salt: &Salt) -> Hash {
    Sha256::digest(leaf_preimage(direction, start, bytes, salt)).into()
}

pub(crate) fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Every tree level, leaves first, root last. Empty input gives no levels.
pub(crate) fn levels(leaves: &[Hash]) -> Vec<Vec<Hash>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut out = vec![leaves.to_vec()];
    while out[out.len() - 1].len() > 1 {
        let next = out[out.len() - 1]
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node_hash(l, r),
                [single] => *single, // odd last node: promoted, never duplicated
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            })
            .collect();
        out.push(next);
    }
    out
}

/// The Merkle root, or None for zero leaves (invalid: no receipt).
pub(crate) fn merkle_root(leaves: &[Hash]) -> Option<Hash> {
    levels(leaves).last().map(|top| top[0])
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 3339 UTC with milliseconds, e.g. `2026-11-26T12:00:00.000Z`.
pub(crate) fn iso8601_utc(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant), proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// One leaf as published next to the receipt: the range and the salt, never
/// the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ReceiptLeaf {
    pub(crate) direction: LeafDirection,
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// 64 lowercase hex.
    pub(crate) salt: String,
}

/// The additive payload fields. Flattened into the webhook body, so `receipt`
/// and `leaves` are present together or not at all.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Attestation {
    pub(crate) receipt: String,
    pub(crate) leaves: Vec<ReceiptLeaf>,
}

/// The signed payload, fields in this order (serde keeps declaration order).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptPayload<'a> {
    pub(crate) v: u8,
    pub(crate) server_name: &'a str,
    /// The id the result is delivered under (the session id, or for a later
    /// proof of a multi-reveal session its own result id).
    pub(crate) session_id: &'a str,
    /// The client's `sessionData.proofId`, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<&'a str>,
    pub(crate) verified_at: String,
    pub(crate) tlsn_version: &'static str,
    pub(crate) root: String,
    pub(crate) leaf_count: usize,
}

#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

/// Why a verified proof got no receipt. Logged by name only, never with content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoReceipt {
    /// No range at all (empty tree).
    NoRanges,
    /// A range lies outside the transcript (the verifier validates them first).
    RangeOutOfBounds,
    /// The OS CSPRNG failed.
    Rng,
    /// Payload serialisation failed.
    Encoding,
}

impl NoReceipt {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoRanges => "no disclosed ranges",
            Self::RangeOutOfBounds => "a disclosed range is outside the transcript",
            Self::Rng => "the OS random number generator failed",
            Self::Encoding => "receipt serialisation failed",
        }
    }
}

/// Leaves (range + salt) in leaf order, with their hashes, over the raw
/// transcript bytes. `salt(i)` gives the salt of leaf `i`.
pub(crate) fn build_leaves(
    sent: &[RangeWithHandler],
    recv: &[RangeWithHandler],
    sent_bytes: &[u8],
    recv_bytes: &[u8],
    mut salt: impl FnMut(usize) -> Result<Salt, NoReceipt>,
) -> Result<(Vec<ReceiptLeaf>, Vec<Hash>), NoReceipt> {
    let ranges = sent
        .iter()
        .map(|r| (LeafDirection::Sent, r, sent_bytes))
        .chain(recv.iter().map(|r| (LeafDirection::Recv, r, recv_bytes)));
    let mut leaves = Vec::with_capacity(sent.len() + recv.len());
    let mut hashes = Vec::with_capacity(sent.len() + recv.len());
    for (i, (direction, range, bytes)) in ranges.enumerate() {
        let slice = bytes
            .get(range.start..range.end)
            .ok_or(NoReceipt::RangeOutOfBounds)?;
        let s = salt(i)?;
        hashes.push(leaf_hash(direction, range.start, slice, &s));
        leaves.push(ReceiptLeaf {
            direction,
            start: range.start,
            end: range.end,
            salt: hex(&s),
        });
    }
    Ok((leaves, hashes))
}

/// 32 fresh bytes from the OS CSPRNG.
pub(crate) fn fresh_salt(_index: usize) -> Result<Salt, NoReceipt> {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|_| NoReceipt::Rng)?;
    Ok(salt)
}

/// What the attestor needs to know about one verified proof.
pub(crate) struct SessionFacts<'a> {
    pub(crate) server_name: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) session_data: &'a HashMap<String, String>,
    pub(crate) sent: &'a [RangeWithHandler],
    pub(crate) recv: &'a [RangeWithHandler],
    pub(crate) sent_bytes: &'a [u8],
    pub(crate) recv_bytes: &'a [u8],
}

/// The attestor key and kid. No `Debug` derive: it holds the private key.
pub(crate) struct Attestor {
    key: SigningKey,
    kid: String,
}

impl std::fmt::Debug for Attestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attestor").field("kid", &self.kid).finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct PrivateOkpJwk {
    kty: String,
    crv: String,
    x: String,
    d: String,
    #[serde(default)]
    alg: Option<String>,
}

fn decode_32(name: &str, value: &str) -> Result<[u8; 32], String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| format!("{KEY_ENV}: \"{name}\" must be 32 bytes of unpadded base64url"))
}

/// Parses the private JWK. Error messages never contain key material.
pub(crate) fn parse_key(jwk: &str) -> Result<SigningKey, String> {
    let jwk = jwk.trim();
    if jwk.len() > MAX_KEY_LEN {
        return Err(format!("{KEY_ENV} is longer than {MAX_KEY_LEN} characters"));
    }
    // The serde error text could quote a member value: replace it.
    let jwk: PrivateOkpJwk = serde_json::from_str(jwk).map_err(|_| {
        format!("{KEY_ENV} must be a private OKP Ed25519 JWK: a JSON object with string members kty, crv, x and d")
    })?;
    if jwk.kty != "OKP" {
        return Err(format!("{KEY_ENV}: kty must be \"OKP\""));
    }
    if jwk.crv != "Ed25519" {
        return Err(format!("{KEY_ENV}: crv must be \"Ed25519\""));
    }
    if jwk.alg.as_deref().is_some_and(|alg| alg != "EdDSA") {
        return Err(format!("{KEY_ENV}: alg, when present, must be \"EdDSA\""));
    }
    let seed = decode_32("d", &jwk.d)?;
    let x = decode_32("x", &jwk.x)?;
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().to_bytes() != x {
        return Err(format!("{KEY_ENV}: x is not the public key of d"));
    }
    Ok(key)
}

/// `did:web:<host>#<fragment>`: the full DID URL, as `did.json` lists it. The
/// verifier serves the document at `/.well-known/did.json`, so the DID is a
/// bare host (a port is percent-encoded, `did:web:localhost%3A7047`); path
/// DIDs (`did:web:<host>:<path>`) are refused.
pub(crate) fn check_kid(kid: &str) -> Result<(), String> {
    let ok = kid.len() <= MAX_KID_LEN
        && kid.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:%#-".contains(&b))
        && matches!(kid.strip_prefix("did:web:").and_then(|rest| rest.split_once('#')),
            Some((host, fragment))
                if !host.is_empty() && !host.contains(':') && !fragment.is_empty() && !fragment.contains('#'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{KID_ENV} must be the key's full DID URL, did:web:<host>#<fragment> (e.g. did:web:verifier.example.com#tlsn-attestor)"
        ))
    }
}

impl Attestor {
    /// Reads `TLSN_ATTESTOR_KEY` (or the file named by `TLSN_ATTESTOR_KEY_FILE`)
    /// and `TLSN_ATTESTOR_KID`. `Ok(None)`: no key configured.
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let inline = std::env::var(KEY_ENV).ok().filter(|k| !k.trim().is_empty());
        let file = std::env::var(KEY_FILE_ENV).ok().filter(|p| !p.trim().is_empty());
        let key = match (inline, file) {
            (Some(_), Some(_)) => return Err(format!("set {KEY_ENV} or {KEY_FILE_ENV}, not both")),
            (Some(k), None) => Some(k),
            (None, Some(path)) => Some(
                std::fs::read_to_string(path.trim())
                    .map_err(|e| format!("{KEY_FILE_ENV}: cannot read the key file: {}", e.kind()))?,
            ),
            (None, None) => None,
        };
        Self::from_values(key.as_deref(), std::env::var(KID_ENV).ok().as_deref())
    }

    pub(crate) fn from_values(key: Option<&str>, kid: Option<&str>) -> Result<Option<Self>, String> {
        let Some(key) = key.filter(|k| !k.trim().is_empty()) else {
            return Ok(None);
        };
        let key = parse_key(key)?;
        let kid = kid
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| format!("{KID_ENV} is required when {KEY_ENV} is set"))?;
        check_kid(kid)?;
        Ok(Some(Self {
            key,
            kid: kid.to_string(),
        }))
    }

    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// `did:web:<host>`: the kid without its fragment.
    pub(crate) fn did(&self) -> &str {
        self.kid.split_once('#').map_or(&self.kid, |(did, _)| did)
    }

    pub(crate) fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }

    /// The did:web document served at `/.well-known/did.json`: the public key
    /// only (never `d`), listed in `assertionMethod`.
    pub(crate) fn did_document(&self) -> serde_json::Value {
        serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "id": self.did(),
            "verificationMethod": [{
                "id": self.kid,
                "type": "JsonWebKey2020",
                "controller": self.did(),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(self.verifying_key().to_bytes()),
                    "alg": "EdDSA",
                    "use": "sig"
                }
            }],
            "assertionMethod": [self.kid]
        })
    }

    /// Compact JWS: b64url(header) "." b64url(payload) "." b64url(Ed25519 signature).
    pub(crate) fn sign(&self, payload: &ReceiptPayload<'_>) -> Result<String, NoReceipt> {
        let header = serde_json::to_vec(&JwsHeader {
            alg: "EdDSA",
            kid: &self.kid,
            typ: JWS_TYP,
        })
        .map_err(|_| NoReceipt::Encoding)?;
        let payload = serde_json::to_vec(payload).map_err(|_| NoReceipt::Encoding)?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = self.key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// Receipt + leaves for a verified proof, with fresh CSPRNG salts.
    pub(crate) fn attest(&self, facts: &SessionFacts<'_>) -> Result<Attestation, NoReceipt> {
        self.attest_with(facts, iso8601_utc(SystemTime::now()), fresh_salt)
    }

    pub(crate) fn attest_with(
        &self,
        facts: &SessionFacts<'_>,
        verified_at: String,
        salt: impl FnMut(usize) -> Result<Salt, NoReceipt>,
    ) -> Result<Attestation, NoReceipt> {
        let (leaves, hashes) = build_leaves(
            facts.sent,
            facts.recv,
            facts.sent_bytes,
            facts.recv_bytes,
            salt,
        )?;
        let root = merkle_root(&hashes).ok_or(NoReceipt::NoRanges)?;
        let receipt = self.sign(&ReceiptPayload {
            v: RECEIPT_VERSION,
            server_name: facts.server_name,
            session_id: facts.session_id,
            proof_id: facts
                .session_data
                .get("proofId")
                .map(String::as_str)
                .filter(|p| !p.is_empty()),
            verified_at,
            tlsn_version: TLSN_VERSION,
            root: hex(&root),
            leaf_count: leaves.len(),
        })?;
        Ok(Attestation { receipt, leaves })
    }
}
