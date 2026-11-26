use cf_private_json::piece;
use gcp_private_json::commitment;

// Sixteen hidden row pieces of up to 64 bytes (most live pieces: ids, emails, short strings). Inactive slots: length,
// hash and kind 0.
fn main(hashes: pub [[u8; 32]; 16], lengths: pub [u32; 16], kinds: pub [u8; 16], preimages: [[u8; 80]; 16]) {
    for i in 0..16 {
        if lengths[i] == 0 {
            assert((hashes[i] == [0; 32]) & (kinds[i] == 0), "Inactive piece hash and kind must be zero");
        } else {
            let bytes: [u8; 64] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            piece(bytes, lengths[i], kinds[i]);
        }
    }
}

#[test]
fn all_inactive() { main([[0; 32]; 16], [0; 16], [0; 16], [[0; 80]; 16]); }
