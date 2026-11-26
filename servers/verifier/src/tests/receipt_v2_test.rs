//! Tests for receipt v2: HASH-action (private) ranges become commit leaves
//! over the verified commitment digest. No network. `receipt-v2-vectors.json`
//! is the test vector other implementations reproduce (raw transcript, fixed
//! salts and digests, preimages, levels, root and the exact JWS under the
//! fake test seed).

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rangeset::set::RangeSet;
use serde_json::Value;
use tlsn::{
    hash::{HashAlgId, TypedHash},
    transcript::{hash::PlaintextHash, Direction, TranscriptCommitment},
};

use crate::attestor::{
    build_leaves, commit_leaf_hash, commit_leaf_preimage, hex, leaf_hash, leaf_preimage, levels,
    merkle_root, receipt_version, Attestor, Hash, LeafDirection, NoReceipt, Salt, SessionFacts,
};
use crate::{Handler, HandlerAction, HandlerPart, HandlerType, HashAlgorithm, RangeWithHandler};

const VECTOR: &str = include_str!("receipt-v2-vectors.json");

/// TEST ONLY: the same fixed, obviously fake seed as `attestor_test.rs`.
const TEST_SEED: [u8; 32] = [0x07; 32];
const TEST_KID: &str = "did:web:verifier.test.invalid#tlsn-attestor";
const SESSION_ID: &str = "0b8e8f0e-0000-4000-8000-000000000023";
const PROOF_ID: &str = "3f2b8c1e-5d4a-4c3b-9a1f-000000000023";
const VERIFIED_AT: &str = "2026-11-26T12:00:00.000Z";

fn attestor() -> Attestor {
    let x = SigningKey::from_bytes(&TEST_SEED).verifying_key().to_bytes();
    let jwk = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(TEST_SEED)
    );
    Attestor::from_values(Some(&jwk), Some(TEST_KID)).unwrap().unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn num(v: &Value) -> usize {
    v.as_u64().unwrap() as usize
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn direction(v: &Value) -> LeafDirection {
    match v.as_str().unwrap() {
        "sent" => LeafDirection::Sent,
        "recv" => LeafDirection::Recv,
        other => panic!("direction {other}"),
    }
}

fn algorithm(name: &str) -> (HashAlgorithm, HashAlgId) {
    match name {
        "sha256" => (HashAlgorithm::Sha256, HashAlgId::SHA256),
        "blake3" => (HashAlgorithm::Blake3, HashAlgId::BLAKE3),
        "keccak256" => (HashAlgorithm::Keccak256, HashAlgId::KECCAK256),
        other => panic!("alg {other}"),
    }
}

/// The vector as verifier inputs: config ranges, raw transcript, verified
/// commitments, salts.
struct Input {
    sent: Vec<RangeWithHandler>,
    recv: Vec<RangeWithHandler>,
    sent_bytes: Vec<u8>,
    recv_bytes: Vec<u8>,
    commitments: Vec<TranscriptCommitment>,
    salts: Vec<Salt>,
}

fn input(v: &Value) -> Input {
    let mut out = Input {
        sent: vec![],
        recv: vec![],
        sent_bytes: unhex(v["sentHex"].as_str().unwrap()),
        recv_bytes: unhex(v["recvHex"].as_str().unwrap()),
        commitments: vec![],
        salts: vec![],
    };
    for leaf in v["leaves"].as_array().unwrap() {
        let dir = direction(&leaf["direction"]);
        let (start, end) = (num(&leaf["start"]), num(&leaf["end"]));
        let action = match leaf["kind"].as_str().unwrap() {
            "reveal" => HandlerAction::Reveal,
            "commit" => {
                let (alg, id) = algorithm(leaf["alg"].as_str().unwrap());
                out.commitments.push(TranscriptCommitment::Hash(PlaintextHash {
                    direction: dir.transcript(),
                    idx: RangeSet::from(start..end),
                    hash: TypedHash {
                        alg: id,
                        value: unhex(leaf["digest"].as_str().unwrap()).try_into().unwrap(),
                    },
                }));
                HandlerAction::Hash { algorithm: alg }
            }
            other => panic!("kind {other}"),
        };
        let handler_type = match dir {
            LeafDirection::Sent => HandlerType::Sent,
            LeafDirection::Recv => HandlerType::Recv,
        };
        let range = RangeWithHandler {
            start,
            end,
            handler: Handler {
                handler_type,
                part: HandlerPart::Body,
                action,
            },
        };
        match dir {
            LeafDirection::Sent => out.sent.push(range),
            LeafDirection::Recv => out.recv.push(range),
        }
        out.salts.push(unhex(leaf["salt"].as_str().unwrap()).try_into().unwrap());
    }
    out
}

fn facts<'a>(input: &'a Input, data: &'a HashMap<String, String>) -> SessionFacts<'a> {
    SessionFacts {
        server_name: "api.cloudflare.com",
        session_id: SESSION_ID,
        session_data: data,
        sent: &input.sent,
        recv: &input.recv,
        sent_bytes: &input.sent_bytes,
        recv_bytes: &input.recv_bytes,
        commitments: &input.commitments,
    }
}

fn proof_data() -> HashMap<String, String> {
    HashMap::from([("proofId".to_string(), PROOF_ID.to_string())])
}

#[test]
fn receipt_v2_vector_leaves_levels_and_root() {
    let v = vector();
    for leaf in v["leaves"].as_array().unwrap() {
        let dir = direction(&leaf["direction"]);
        let (start, end) = (num(&leaf["start"]), num(&leaf["end"]));
        let salt: Salt = unhex(leaf["salt"].as_str().unwrap()).try_into().unwrap();
        let (pre, h) = if leaf["kind"] == "commit" {
            let digest = unhex(leaf["digest"].as_str().unwrap());
            (
                commit_leaf_preimage(dir, start, end - start, &salt, &digest),
                commit_leaf_hash(dir, start, end - start, &salt, &digest),
            )
        } else {
            let bytes = unhex(leaf["bytesHex"].as_str().unwrap());
            (leaf_preimage(dir, start, &bytes, &salt), leaf_hash(dir, start, &bytes, &salt))
        };
        assert_eq!(hex(&pre), leaf["leafPreimageHex"].as_str().unwrap());
        assert_eq!(hex(&h), leaf["leafHash"].as_str().unwrap());
    }

    let input = input(&v);
    let mut salts = input.salts.clone().into_iter();
    let (leaves, hashes) = build_leaves(
        &input.sent,
        &input.recv,
        &input.sent_bytes,
        &input.recv_bytes,
        |_| Ok(salts.next().unwrap()),
        |dir, start, end, alg| {
            crate::find_hash_digest_bytes(&input.commitments, dir.transcript(), start, end, alg)
        },
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&leaves).unwrap(), v["publishedLeaves"]);
    assert_eq!(receipt_version(&leaves), 2);
    let want_levels: Vec<Vec<Hash>> = v["levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|lv| {
            lv.as_array()
                .unwrap()
                .iter()
                .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
                .collect()
        })
        .collect();
    assert_eq!(levels(&hashes), want_levels);
    assert_eq!(hex(&merkle_root(&hashes).unwrap()), v["root"].as_str().unwrap());
}

#[test]
fn receipt_v2_vector_receipt_is_reproduced_byte_for_byte() {
    let v = vector();
    let input = input(&v);
    let data = proof_data();
    let mut salts = input.salts.clone().into_iter();
    let att = attestor()
        .attest_with(&facts(&input, &data), VERIFIED_AT.to_string(), |_| {
            Ok(salts.next().unwrap())
        })
        .unwrap();
    let parts: Vec<&str> = att.receipt.split('.').collect();
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
        v["header"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
        v["payload"].as_str().unwrap()
    );
    assert_eq!(att.receipt, v["receipt"].as_str().unwrap());
    assert_eq!(serde_json::to_value(&att.leaves).unwrap(), v["publishedLeaves"]);
    assert_eq!(
        v["publicJwk"]["x"].as_str().unwrap(),
        URL_SAFE_NO_PAD.encode(attestor().verifying_key().to_bytes())
    );
}

#[test]
fn receipt_v2_commit_leaf_ignores_the_zeroed_bytes_and_binds_the_digest() {
    let v = vector();
    let data = proof_data();
    let root = |input: &Input| {
        let mut salts = input.salts.clone().into_iter();
        let att = attestor()
            .attest_with(&facts(input, &data), VERIFIED_AT.to_string(), |_| {
                Ok(salts.next().unwrap())
            })
            .unwrap();
        att.receipt
    };
    let base = root(&input(&v));

    // Bytes under a commit range (zero in the verifier's view) do not enter the leaf.
    let mut changed_bytes = input(&v);
    let r = changed_bytes.sent[1].clone();
    changed_bytes.sent_bytes[r.start..r.end].fill(0x41);
    assert_eq!(root(&changed_bytes), base);

    // Another digest for the same range gives another root.
    let mut changed_digest = input(&v);
    if let TranscriptCommitment::Hash(h) = &mut changed_digest.commitments[0] {
        h.hash.value = vec![0x99; 32].try_into().unwrap();
    }
    assert_ne!(root(&changed_digest), base);
}

#[test]
fn receipt_v2_needs_a_matching_commitment_and_v1_stays_unchanged() {
    let v = vector();
    let data = proof_data();

    // A HASH range without its exact commitment (missing, other direction,
    // other range, other algorithm) gives no receipt.
    let variants: [fn(&mut Input); 4] = [
        |i| i.commitments.clear(),
        |i| {
            for c in &mut i.commitments {
                if let TranscriptCommitment::Hash(h) = c {
                    h.direction = match h.direction {
                        Direction::Sent => Direction::Received,
                        Direction::Received => Direction::Sent,
                    };
                }
            }
        },
        |i| {
            for c in &mut i.commitments {
                if let TranscriptCommitment::Hash(h) = c {
                    let end = h.idx.end().unwrap();
                    h.idx = RangeSet::from(h.idx.min().unwrap()..end - 1);
                }
            }
        },
        |i| {
            for c in &mut i.commitments {
                if let TranscriptCommitment::Hash(h) = c {
                    h.hash.alg = HashAlgId::KECCAK256;
                }
            }
        },
    ];
    for change in variants {
        let mut i = input(&v);
        change(&mut i);
        assert_eq!(
            attestor().attest(&facts(&i, &data)).map(|_| ()).unwrap_err(),
            NoReceipt::NoCommitment
        );
    }

    // Reveal-only session: v1 payload and leaves without kind / alg / digest.
    let mut i = input(&v);
    i.sent.retain(|r| matches!(r.handler.action, HandlerAction::Reveal));
    i.recv.retain(|r| matches!(r.handler.action, HandlerAction::Reveal));
    let att = attestor().attest(&facts(&i, &data)).unwrap();
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(att.receipt.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["v"], 1);
    assert_eq!(payload["leafCount"], 3);
    for leaf in serde_json::to_value(&att.leaves).unwrap().as_array().unwrap() {
        let mut keys: Vec<&String> = leaf.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["direction", "end", "salt", "start"]);
    }
}
