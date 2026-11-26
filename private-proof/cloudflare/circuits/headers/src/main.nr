use gcp_private_json::{atomic, commitment};

// Four hidden header values (or request-target pieces) of up to 512 bytes: printable ASCII or tab, so no CR/LF can
// hide inside them. Covers the Authorization value, the page query and Cloudflare's cookies. Inactive slots: 0.
fn main(hashes: pub [[u8; 32]; 4], lengths: pub [u32; 4], preimages: [[u8; 528]; 4]) {
    for i in 0..4 {
        if lengths[i] == 0 {
            assert(hashes[i] == [0; 32], "Inactive header hash must be zero");
        } else {
            let bytes: [u8; 512] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            atomic::header_value(bytes, lengths[i]);
        }
    }
}

#[test]
fn all_inactive() { main([[0; 32]; 4], [0; 4], [[0; 528]; 4]); }
