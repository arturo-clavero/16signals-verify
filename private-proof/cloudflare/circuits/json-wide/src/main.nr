use cf_private_json::piece;
use gcp_private_json::commitment;

// One hidden row piece of up to 4,096 bytes (a large request or response object).
fn main(hash: pub [u8; 32], length: pub u32, kind: pub u8, preimage: [u8; 4112]) {
    let bytes: [u8; 4096] = commitment::authenticate(preimage, length, hash);
    piece(bytes, length, kind);
}
