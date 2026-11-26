use gcp_private_json::commitment;

// Fast check: the verifier binds hashes[0] to the identity id of a verified recorded run and hashes[1] to a fresh
// identity receipt. Both open to the same id (same length, same bytes) under different blinders.
fn main(hashes: pub [[u8; 32]; 2], lengths: pub [u32; 2], old_preimage: [u8; 80], new_preimage: [u8; 80]) {
    assert((lengths[0] > 0) & (lengths[0] == lengths[1]), "Identity id length mismatch");
    let old: [u8; 64] = commitment::authenticate(old_preimage, lengths[0], hashes[0]);
    let current: [u8; 64] = commitment::authenticate(new_preimage, lengths[1], hashes[1]);
    for i in 0..64 { if i < lengths[0] { assert(old[i] == current[i], "Identity id mismatch"); } }
}

fn id(blinder: u8) -> [u8; 80] {
    let value = [34, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 34];
    let mut out = [0; 80];
    for i in 0..34 { out[i] = value[i]; }
    for i in 34..50 { out[i] = blinder; }
    out
}

global OLD_HASH: [u8; 32] = [58, 185, 58, 217, 237, 191, 105, 39, 72, 170, 176, 133, 48, 9, 20, 81, 85, 198, 90, 43, 68, 105, 88, 105, 7, 23, 120, 184, 48, 170, 209, 98];
global NEW_HASH: [u8; 32] = [231, 221, 102, 76, 13, 153, 20, 97, 147, 110, 175, 72, 53, 222, 129, 20, 204, 108, 254, 21, 149, 56, 30, 241, 228, 146, 109, 223, 66, 37, 84, 42];

#[test]
fn matches_with_different_blinders() { main([OLD_HASH, NEW_HASH], [34, 34], id(1), id(2)); }

#[test(should_fail_with = "Identity id mismatch")]
fn rejects_another_user() {
    let other = [34, 102, 101, 100, 99, 98, 97, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 102, 101, 100, 99, 98, 97, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 34];
    let mut fresh = id(2);
    for i in 0..34 { fresh[i] = other[i]; }
    let hash = [84, 75, 28, 142, 100, 219, 216, 40, 172, 81, 8, 112, 242, 173, 13, 168, 223, 250, 45, 80, 23, 79, 111, 104, 57, 110, 195, 19, 139, 68, 142, 195];
    main([OLD_HASH, hash], [34, 34], id(1), fresh);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_incorrect_opening() { let mut fresh = id(2); fresh[34] = 3; main([OLD_HASH, NEW_HASH], [34, 34], id(1), fresh); }

#[test(should_fail_with = "Identity id length mismatch")]
fn rejects_different_lengths() { main([OLD_HASH, NEW_HASH], [34, 33], id(1), id(2)); }

#[test(should_fail_with = "Identity id length mismatch")]
fn rejects_empty_identity() { main([OLD_HASH, NEW_HASH], [0, 0], id(1), id(2)); }
