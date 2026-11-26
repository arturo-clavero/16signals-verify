//! Tests for the attestor receipt (v1): the Merkle vectors
//! (`receipt-merkle-vectors.json`), the compact JWS, the additive payload
//! fields, the did:web document and the key rules. No network.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey};
use serde_json::Value;

use crate::attestor::{
    self, build_leaves, hex, leaf_hash, leaf_preimage, levels, merkle_root, node_hash, Attestor,
    Hash, LeafDirection, NoReceipt, Salt, SessionFacts,
};
use crate::{Handler, HandlerAction, HandlerPart, HandlerType, RangeWithHandler};

const VECTORS: &str = include_str!("receipt-merkle-vectors.json");

/// TEST ONLY: a fixed, obviously fake Ed25519 seed. Never a deployed key.
const TEST_SEED: [u8; 32] = [0x07; 32];
const TEST_KID: &str = "did:web:verifier.test.invalid#tlsn-attestor";

fn test_jwk_with(seed: &[u8; 32], x_seed: &[u8; 32]) -> String {
    let x = SigningKey::from_bytes(x_seed).verifying_key().to_bytes();
    format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(seed)
    )
}

fn test_jwk() -> String {
    test_jwk_with(&TEST_SEED, &TEST_SEED)
}

fn test_attestor() -> Attestor {
    Attestor::from_values(Some(&test_jwk()), Some(TEST_KID))
        .unwrap()
        .unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn range(direction: HandlerType, start: usize, end: usize) -> RangeWithHandler {
    RangeWithHandler {
        start,
        end,
        handler: Handler {
            handler_type: direction,
            part: HandlerPart::All,
            action: HandlerAction::Reveal,
        },
    }
}

fn vectors() -> Vec<Value> {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["construction"], "tlsn-receipt-merkle-v1");
    doc["vectors"].as_array().unwrap().clone()
}

fn num(v: &Value) -> usize {
    v.as_u64().unwrap() as usize
}

/// A vector's config ranges, a raw transcript per direction that holds each
/// range's bytes at its offsets (the vectors' overlapping ranges agree), and
/// the vector's salts in leaf order.
struct VectorInput {
    sent: Vec<RangeWithHandler>,
    recv: Vec<RangeWithHandler>,
    sent_bytes: Vec<u8>,
    recv_bytes: Vec<u8>,
    salts: Vec<Salt>,
}

fn vector_input(vector: &Value) -> VectorInput {
    let mut salts = Vec::new();
    let mut side = |name: &str, ty: HandlerType| {
        let mut ranges = Vec::new();
        let mut bytes = Vec::new();
        for r in vector["input"]["config"][name].as_array().unwrap() {
            let (start, end) = (num(&r["start"]), num(&r["end"]));
            let content = unhex(r["bytesHex"].as_str().unwrap());
            assert_eq!(content.len(), end - start);
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[start..end].copy_from_slice(&content);
            ranges.push(range(ty.clone(), start, end));
            salts.push(unhex32(r["salt"].as_str().unwrap()));
        }
        (ranges, bytes)
    };
    let (sent, sent_bytes) = side("sent", HandlerType::Sent);
    let (recv, recv_bytes) = side("recv", HandlerType::Recv);
    // Overlaps must agree, or the shared buffer would misrepresent a range.
    for (name, ranges, bytes) in [("sent", &sent, &sent_bytes), ("recv", &recv, &recv_bytes)] {
        for (r, src) in ranges
            .iter()
            .zip(vector["input"]["config"][name].as_array().unwrap())
        {
            assert_eq!(hex(&bytes[r.start..r.end]), src["bytesHex"].as_str().unwrap());
        }
    }
    VectorInput {
        sent,
        recv,
        sent_bytes,
        recv_bytes,
        salts,
    }
}

/// Inclusion proof for `index` from the levels.
fn inclusion_proof(levels: &[Vec<Hash>], index: usize) -> Vec<Hash> {
    let mut siblings = Vec::new();
    let mut i = index;
    for level in &levels[..levels.len() - 1] {
        if i % 2 == 1 {
            siblings.push(level[i - 1]);
        } else if i + 1 < level.len() {
            siblings.push(level[i + 1]);
        }
        i >>= 1;
    }
    siblings
}

/// Inclusion-proof check a receipt reader runs (README, Signed receipts).
fn verify_inclusion(leaf: &Hash, index: usize, count: usize, siblings: &[Hash], root: &Hash) -> bool {
    if index >= count {
        return false;
    }
    let (mut h, mut i, mut n, mut k) = (*leaf, index, count, 0usize);
    while n > 1 {
        if i % 2 == 1 {
            let Some(s) = siblings.get(k) else { return false };
            h = node_hash(s, &h);
            k += 1;
        } else if i + 1 < n {
            let Some(s) = siblings.get(k) else { return false };
            h = node_hash(&h, s);
            k += 1;
        }
        i >>= 1;
        n = n.div_ceil(2);
    }
    k == siblings.len() && h == *root
}

fn hashes(values: &Value) -> Vec<Hash> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|h| unhex32(h.as_str().unwrap()))
        .collect()
}

#[test]
fn attestor_vectors_file_has_three_vectors() {
    assert_eq!(vectors().len(), 3);
}

#[test]
fn attestor_vectors_leaves_levels_and_roots() {
    for vector in vectors() {
        let name = vector["name"].as_str().unwrap();
        let input = vector_input(&vector);
        let mut salts = input.salts.clone().into_iter();
        let (leaves, leaf_hashes) = build_leaves(
            &input.sent,
            &input.recv,
            &input.sent_bytes,
            &input.recv_bytes,
            |_| Ok(salts.next().unwrap()),
        )
        .unwrap();

        let expected = vector["leaves"].as_array().unwrap();
        assert_eq!(leaves.len(), expected.len(), "{name}");
        assert_eq!(leaves.len(), num(&vector["leafCount"]), "{name}");
        for (i, (leaf, want)) in leaves.iter().zip(expected).enumerate() {
            assert_eq!(num(&want["index"]), i, "{name}");
            let direction = match want["direction"].as_str().unwrap() {
                "sent" => LeafDirection::Sent,
                "recv" => LeafDirection::Recv,
                other => panic!("{name}: direction {other}"),
            };
            assert_eq!(leaf.direction, direction, "{name} leaf {i}");
            assert_eq!(leaf.start, num(&want["start"]), "{name} leaf {i}");
            assert_eq!(leaf.end, num(&want["end"]), "{name} leaf {i}");
            assert_eq!(leaf.salt, want["salt"].as_str().unwrap(), "{name} leaf {i}");
            let bytes = unhex(want["bytesHex"].as_str().unwrap());
            let salt = unhex32(want["salt"].as_str().unwrap());
            assert_eq!(
                hex(&leaf_preimage(direction, leaf.start, &bytes, &salt)),
                want["leafPreimageHex"].as_str().unwrap(),
                "{name} leaf {i} preimage"
            );
            let h = leaf_hash(direction, leaf.start, &bytes, &salt);
            assert_eq!(hex(&h), want["leafHash"].as_str().unwrap(), "{name} leaf {i}");
            assert_eq!(leaf_hashes[i], h, "{name} leaf {i} (built from the transcript)");
        }

        let got_levels = levels(&leaf_hashes);
        let want_levels: Vec<Vec<Hash>> = vector["levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(hashes)
            .collect();
        assert_eq!(got_levels, want_levels, "{name} levels");
        let root = merkle_root(&leaf_hashes).unwrap();
        assert_eq!(hex(&root), vector["root"].as_str().unwrap(), "{name} root");
        assert_eq!(hex(&root).len(), 64);
    }
}

#[test]
fn attestor_vectors_inclusion_proofs() {
    let mut valid = 0;
    let mut invalid = 0;
    for vector in vectors() {
        let name = vector["name"].as_str().unwrap();
        let leaf_hashes: Vec<Hash> = vector["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| unhex32(l["leafHash"].as_str().unwrap()))
            .collect();
        let tree = levels(&leaf_hashes);
        let root = unhex32(vector["root"].as_str().unwrap());
        for proof in vector["inclusionProofs"].as_array().unwrap() {
            let (index, count) = (num(&proof["leafIndex"]), num(&proof["leafCount"]));
            let siblings = hashes(&proof["siblings"]);
            assert_eq!(count, leaf_hashes.len(), "{name}");
            assert_eq!(inclusion_proof(&tree, index), siblings, "{name} proof {index}");
            assert!(
                verify_inclusion(&leaf_hashes[index], index, count, &siblings, &root),
                "{name} proof {index} must verify"
            );
            valid += 1;
        }
        for proof in vector["invalidInclusionProofs"].as_array().unwrap() {
            let leaf = unhex32(proof["leafHash"].as_str().unwrap());
            assert!(
                !verify_inclusion(
                    &leaf,
                    num(&proof["leafIndex"]),
                    num(&proof["leafCount"]),
                    &hashes(&proof["siblings"]),
                    &root
                ),
                "{name}: {}",
                proof["why"]
            );
            invalid += 1;
        }
    }
    assert_eq!((valid, invalid), (5, 3));
}

#[test]
fn attestor_empty_tree_has_no_root() {
    assert!(levels(&[]).is_empty());
    assert!(merkle_root(&[]).is_none());
    let one = [0x11; 32];
    assert_eq!(merkle_root(&[one]), Some(one));
    // Odd promotion: the third node is carried up, never paired with itself.
    let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    assert_eq!(merkle_root(&[a, b, c]), Some(node_hash(&node_hash(&a, &b), &c)));
}

fn session_data(proof_id: Option<&str>) -> HashMap<String, String> {
    let mut data = HashMap::new();
    data.insert("nonce".to_string(), "test-nonce".to_string());
    data.insert("step".to_string(), "A2".to_string());
    if let Some(p) = proof_id {
        data.insert("proofId".to_string(), p.to_string());
    }
    data
}

const PROOF_ID: &str = "3f2b8c1e-5d4a-4c3b-9a1f-000000000001";
const SESSION_ID: &str = "0b8e8f0e-0000-4000-8000-000000000001";

fn three_leaf_vector() -> (Value, VectorInput) {
    let v = vectors()
        .into_iter()
        .find(|v| v["name"] == "three-leaves-sent-and-recv-odd-promotion")
        .unwrap();
    let input = vector_input(&v);
    (v, input)
}

fn decode_part(part: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(part).unwrap()
}

#[test]
fn attestor_receipt_is_a_compact_eddsa_jws_over_the_contract_payload() {
    let attestor = test_attestor();
    let (vector, input) = three_leaf_vector();
    let data = session_data(Some(PROOF_ID));
    let mut salts = input.salts.clone().into_iter();
    let att = attestor
        .attest_with(
            &SessionFacts {
                server_name: "github.com",
                session_id: SESSION_ID,
                session_data: &data,
                sent: &input.sent,
                recv: &input.recv,
                sent_bytes: &input.sent_bytes,
                recv_bytes: &input.recv_bytes,
            },
            "2026-10-07T12:00:00.000Z".to_string(),
            |_| Ok(salts.next().unwrap()),
        )
        .unwrap();

    let parts: Vec<&str> = att.receipt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(att
        .receipt
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'));
    assert_eq!(
        String::from_utf8(decode_part(parts[0])).unwrap(),
        format!(r#"{{"alg":"EdDSA","kid":"{TEST_KID}","typ":"tlsn-receipt+jws"}}"#)
    );
    assert_eq!(
        String::from_utf8(decode_part(parts[1])).unwrap(),
        format!(
            concat!(
                r#"{{"v":1,"serverName":"github.com","sessionId":"{}","proofId":"{}","#,
                r#""verifiedAt":"2026-10-07T12:00:00.000Z","tlsnVersion":"0.1.0-alpha.15","#,
                r#""root":"{}","leafCount":3}}"#
            ),
            SESSION_ID,
            PROOF_ID,
            vector["root"].as_str().unwrap()
        )
    );

    let signature = Signature::from_slice(&decode_part(parts[2])).unwrap();
    let key = attestor.verifying_key();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify_strict(signing_input.as_bytes(), &signature).unwrap();
    // Another payload under the same signature fails.
    let tampered = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(b"{\"v\":1}"));
    assert!(key.verify_strict(tampered.as_bytes(), &signature).is_err());

    // Leaves: contract order, ranges and salts only.
    let want: Vec<(LeafDirection, usize, usize)> = vec![
        (LeafDirection::Sent, 0, 38),
        (LeafDirection::Recv, 0, 17),
        (LeafDirection::Recv, 17, 54),
    ];
    let got: Vec<_> = att.leaves.iter().map(|l| (l.direction, l.start, l.end)).collect();
    assert_eq!(got, want);
    let leaves_json = serde_json::to_value(&att.leaves).unwrap();
    for (leaf, src) in leaves_json.as_array().unwrap().iter().zip(vector["leaves"].as_array().unwrap()) {
        let keys: Vec<&String> = leaf.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 4, "{leaf}");
        assert_eq!(leaf["salt"], src["salt"]);
        assert_eq!(leaf["direction"], src["direction"]);
    }
}

#[test]
fn attestor_salts_are_fresh_csprng_bytes() {
    let attestor = test_attestor();
    let (_, input) = three_leaf_vector();
    let data = session_data(Some(PROOF_ID));
    let facts = SessionFacts {
        server_name: "github.com",
        session_id: SESSION_ID,
        session_data: &data,
        sent: &input.sent,
        recv: &input.recv,
        sent_bytes: &input.sent_bytes,
        recv_bytes: &input.recv_bytes,
    };
    let a = attestor.attest(&facts).unwrap();
    let b = attestor.attest(&facts).unwrap();
    let all: Vec<&String> = a.leaves.iter().chain(&b.leaves).map(|l| &l.salt).collect();
    for (i, s) in all.iter().enumerate() {
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert_ne!(s.as_str(), "0".repeat(64));
        assert!(all[i + 1..].iter().all(|t| t != s), "salt reused");
    }
    assert_ne!(a.receipt, b.receipt);
}

#[test]
fn attestor_no_receipt_without_ranges_or_in_bounds_bytes() {
    let attestor = test_attestor();
    let (_, input) = three_leaf_vector();
    let with = session_data(Some(PROOF_ID));
    let without = session_data(None);
    fn facts<'a>(
        data: &'a HashMap<String, String>,
        sent: &'a [RangeWithHandler],
        recv: &'a [RangeWithHandler],
        input: &'a VectorInput,
    ) -> SessionFacts<'a> {
        SessionFacts {
            server_name: "github.com",
            session_id: SESSION_ID,
            session_data: data,
            sent,
            recv,
            sent_bytes: &input.sent_bytes,
            recv_bytes: &input.recv_bytes,
        }
    }
    let at = |f: &SessionFacts<'_>| attestor.attest(f).map(|_| ()).unwrap_err();
    assert_eq!(at(&facts(&with, &[], &[], &input)), NoReceipt::NoRanges);
    // Without a proofId the receipt is still signed; the claim is left out.
    let att = attestor.attest(&facts(&without, &input.sent, &input.recv, &input)).unwrap();
    let claims: Value = serde_json::from_slice(
        &decode_part(att.receipt.split('.').nth(1).unwrap()),
    )
    .unwrap();
    assert!(claims.get("proofId").is_none(), "{claims}");
    assert_eq!(claims["sessionId"], SESSION_ID);
    let past_end = [range(HandlerType::Recv, 17, input.recv_bytes.len() + 1)];
    assert_eq!(at(&facts(&with, &input.sent, &past_end, &input)), NoReceipt::RangeOutOfBounds);
    let inverted = [range(HandlerType::Sent, 5, 4)];
    assert_eq!(at(&facts(&with, &inverted, &input.recv, &input)), NoReceipt::RangeOutOfBounds);
}

fn payload_value(attestation: Option<attestor::Attestation>) -> Value {
    let payload = crate::WebhookPayload {
        server_name: "github.com".to_string(),
        results: vec![],
        config: crate::RevealConfigForWebhook {
            sent: vec![],
            recv: vec![],
        },
        session: crate::SessionInfo {
            id: SESSION_ID.to_string(),
            data: session_data(Some(PROOF_ID)),
        },
        transcript: crate::RedactedTranscript {
            sent: String::new(),
            recv: String::new(),
            sent_length: 0,
            recv_length: 0,
        },
        attestation,
    };
    serde_json::to_value(&payload).unwrap()
}

#[test]
fn attestor_payload_fields_are_additive_and_paired() {
    let plain = payload_value(None);
    assert!(plain.get("receipt").is_none());
    assert!(plain.get("leaves").is_none());
    for key in ["server_name", "results", "config", "session", "transcript"] {
        assert!(plain.get(key).is_some(), "{key}");
    }

    let attestation = attestor::Attestation {
        receipt: "aGVhZGVy.cGF5bG9hZA.c2ln".to_string(),
        leaves: vec![attestor::ReceiptLeaf {
            direction: LeafDirection::Recv,
            start: 0,
            end: 17,
            salt: "ab".repeat(32),
        }],
    };
    let with = payload_value(Some(attestation));
    assert_eq!(with["receipt"], "aGVhZGVy.cGF5bG9hZA.c2ln");
    assert_eq!(
        with["leaves"],
        serde_json::json!([{"direction": "recv", "start": 0, "end": 17, "salt": "ab".repeat(32)}])
    );
    // Same body otherwise: the fields are additive.
    let mut stripped = with.clone();
    stripped.as_object_mut().unwrap().remove("receipt");
    stripped.as_object_mut().unwrap().remove("leaves");
    assert_eq!(stripped, plain);
}

#[test]
fn attestor_key_rules() {
    // Unset or empty: no receipts, and the kid alone is ignored.
    assert!(Attestor::from_values(None, None).unwrap().is_none());
    assert!(Attestor::from_values(Some(""), Some(TEST_KID)).unwrap().is_none());
    assert!(Attestor::from_values(None, Some(TEST_KID)).unwrap().is_none());

    let good = test_jwk();
    let att = Attestor::from_values(Some(&good), Some(TEST_KID)).unwrap().unwrap();
    assert_eq!(att.kid(), TEST_KID);
    assert_eq!(
        att.verifying_key().to_bytes(),
        SigningKey::from_bytes(&TEST_SEED).verifying_key().to_bytes()
    );
    // Extra JWK members are fine; alg, when present, must be EdDSA.
    let with_members = good.replacen('{', r#"{"kid":"tlsn-attestor","use":"sig","alg":"EdDSA","#, 1);
    assert!(Attestor::from_values(Some(&with_members), Some(TEST_KID)).unwrap().is_some());
    // Pretty-printed JSON is still JSON.
    let pretty = good.replace(',', ",\n  ");
    assert!(Attestor::from_values(Some(&pretty), Some(TEST_KID)).unwrap().is_some());

    let d = URL_SAFE_NO_PAD.encode(TEST_SEED);
    let refused = |key: &str, kid: Option<&str>, message: &str| {
        let err = Attestor::from_values(Some(key), kid).unwrap_err();
        assert!(err.contains(message), "{err:?} lacks {message:?}");
        assert!(!err.contains(&d), "the error leaks the key");
    };
    refused(&good, None, "TLSN_ATTESTOR_KID is required");
    refused(&good, Some(""), "TLSN_ATTESTOR_KID is required");
    for kid in [
        "tlsn-attestor",
        "did:web:verifier.example.com",
        "did:web:verifier.example.com#",
        "did:web:#tlsn-attestor",
        "did:key:z6Mk#tlsn-attestor",
        "did:web:verifier.example.com#a#b",
        "did:web:verifier.example.com#tlsn attestor",
        // A path DID would need its document at /<path>/did.json, which this
        // verifier does not serve.
        "did:web:example.com:verifier#tlsn-attestor",
    ] {
        refused(&good, Some(kid), "TLSN_ATTESTOR_KID must be");
    }
    refused("not json", Some(TEST_KID), "must be a private OKP Ed25519 JWK");
    refused(&format!(r#"{{"kty":"OKP","crv":"Ed25519","d":"{d}"}}"#), Some(TEST_KID), "private OKP Ed25519 JWK");
    refused(&format!(r#"{{"kty":"OKP","crv":"Ed25519","x":1,"d":"{d}"}}"#), Some(TEST_KID), "private OKP Ed25519 JWK");
    refused(&good.replace("\"OKP\"", "\"EC\""), Some(TEST_KID), "kty must be");
    refused(&good.replace("Ed25519", "X25519"), Some(TEST_KID), "crv must be");
    refused(&good.replacen('{', r#"{"alg":"ES256","#, 1), Some(TEST_KID), "alg");
    refused(&test_jwk_with(&TEST_SEED, &[0x08; 32]), Some(TEST_KID), "x is not the public key of d");
    let short = URL_SAFE_NO_PAD.encode(&TEST_SEED[..31]);
    refused(&good.replace(&d, &short), Some(TEST_KID), "\"d\" must be 32 bytes");
    let padded = base64::engine::general_purpose::URL_SAFE.encode(TEST_SEED);
    refused(&good.replace(&d, &padded), Some(TEST_KID), "\"d\" must be 32 bytes");
    let standard = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfb; 32]);
    refused(&test_jwk_with(&[0xfb; 32], &[0xfb; 32]).replace(&URL_SAFE_NO_PAD.encode([0xfb; 32]), &standard), Some(TEST_KID), "\"d\" must be 32 bytes");
    refused(&"x".repeat(2000), Some(TEST_KID), "longer than");

    // Debug never prints the key.
    assert!(!format!("{att:?}").contains(&d));
}

#[test]
fn attestor_tlsn_version_matches_the_cargo_pin() {
    let manifest = include_str!("../../Cargo.toml");
    assert!(
        manifest.contains(&format!("version = \"={}\"", attestor::TLSN_VERSION)),
        "TLSN_VERSION must follow the tlsn version pin in Cargo.toml"
    );
}

#[test]
fn attestor_did_document_lists_the_public_key_only() {
    let attestor = test_attestor();
    let doc = attestor.did_document();
    let x = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&TEST_SEED).verifying_key().to_bytes());
    assert_eq!(
        doc,
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id": "did:web:verifier.test.invalid",
            "verificationMethod": [{
                "id": TEST_KID,
                "type": "JsonWebKey2020",
                "controller": "did:web:verifier.test.invalid",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "EdDSA", "use": "sig"}
            }],
            "assertionMethod": [TEST_KID]
        })
    );
    assert!(!doc.to_string().contains(&URL_SAFE_NO_PAD.encode(TEST_SEED)), "d leaked");
    // A port stays percent-encoded in the DID.
    let local = Attestor::from_values(Some(&test_jwk()), Some("did:web:localhost%3A7047#tlsn-attestor"))
        .unwrap()
        .unwrap();
    assert_eq!(local.did(), "did:web:localhost%3A7047");
}

#[tokio::test]
async fn attestor_did_json_route() {
    use axum::extract::State;
    use axum::http::StatusCode;
    let state = |attestor: Option<Attestor>| {
        std::sync::Arc::new(crate::AppState {
            sessions: Default::default(),
            config: Default::default(),
            settings: std::sync::Arc::new(crate::settings::Settings {
                attestor: attestor.map(std::sync::Arc::new),
                ..Default::default()
            }),
        })
    };
    let off = crate::did_document_handler(State(state(None))).await;
    assert_eq!(off.status(), StatusCode::NOT_FOUND);
    let on = crate::did_document_handler(State(state(Some(test_attestor())))).await;
    assert_eq!(on.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(on.into_body()).await.unwrap().to_bytes();
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["id"], "did:web:verifier.test.invalid");
    assert_eq!(doc["assertionMethod"][0], TEST_KID);
}
