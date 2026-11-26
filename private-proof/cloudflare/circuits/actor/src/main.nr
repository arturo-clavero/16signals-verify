use gcp_private_json::commitment;

// Binds up to eight rows' actor.id pieces to the identity session's result.id piece: same length, same bytes.
// Inactive slots: length and hash 0.
fn main(identity_hash: pub [u8; 32], identity_length: pub u32, hashes: pub [[u8; 32]; 8], lengths: pub [u32; 8],
        identity_preimage: [u8; 80], preimages: [[u8; 80]; 8]) {
    assert(identity_length > 0, "Identity id is required");
    let identity: [u8; 64] = commitment::authenticate(identity_preimage, identity_length, identity_hash);
    let mut active = 0;
    for i in 0..8 {
        if lengths[i] == 0 {
            assert(hashes[i] == [0; 32], "Inactive actor hash must be zero");
        } else {
            active += 1;
            assert(lengths[i] == identity_length, "Actor id length differs from the identity");
            let bytes: [u8; 64] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            for j in 0..64 { if j < identity_length { assert(bytes[j] == identity[j], "Actor id differs from the identity"); } }
        }
    }
    assert(active > 0, "At least one actor id is required");
}
