use cf_private_json::piece;
use gcp_private_json::commitment;

// Four hidden row pieces of up to 512 bytes (97% of live pieces are <= 256 B). Inactive slots: length, hash, kind 0.
fn main(hashes: pub [[u8; 32]; 4], lengths: pub [u32; 4], kinds: pub [u8; 4], preimages: [[u8; 528]; 4]) {
    for i in 0..4 {
        if lengths[i] == 0 {
            assert((hashes[i] == [0; 32]) & (kinds[i] == 0), "Inactive piece hash and kind must be zero");
        } else {
            let bytes: [u8; 512] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            piece(bytes, lengths[i], kinds[i]);
        }
    }
}

#[test]
fn all_inactive() { main([[0; 32]; 4], [0; 4], [0; 4], [[0; 528]; 4]); }

#[test(should_fail_with = "Inactive piece hash and kind must be zero")]
fn inactive_cannot_claim_a_kind() { main([[0; 32]; 4], [0; 4], [1, 0, 0, 0], [[0; 528]; 4]); }
