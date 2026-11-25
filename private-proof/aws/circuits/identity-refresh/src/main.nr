use gcp_private_json::commitment;

// The verifier binds old_hash to a verified activity bundle and new_hash to a fresh GetUser receipt.
fn main(
    hashes: pub [[u8; 32]; 2], lengths: pub [u32; 2],
    old_preimage: [u8; 144], new_preimage: [u8; 144],
) {
    assert((lengths[0] > 0) & (lengths[0] == lengths[1]), "User ID length mismatch");
    let old = commitment::authenticate(old_preimage, lengths[0], hashes[0]);
    let current = commitment::authenticate(new_preimage, lengths[1], hashes[1]);
    for i in 0..128 { if i < lengths[0] { assert(old[i] == current[i], "User ID mismatch"); } }
}

fn fixture() -> ([[u8; 32]; 2], [u8; 144], [u8; 144]) {
    let old = [65, 73, 68, 65, 69, 88, 65, 77, 80, 76, 69, 83, 89, 78, 84, 72, 69, 84, 73, 67, 48, 49, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let fresh = [65, 73, 68, 65, 69, 88, 65, 77, 80, 76, 69, 83, 89, 78, 84, 72, 69, 84, 73, 67, 48, 49, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    ([[61, 210, 84, 233, 86, 61, 104, 61, 168, 43, 140, 188, 172, 35, 15, 55, 72, 122, 56, 212, 123, 14, 67, 95, 212, 115, 243, 75, 7, 171, 210, 248], [43, 103, 138, 198, 80, 13, 172, 176, 140, 118, 204, 105, 181, 61, 23, 62, 212, 2, 39, 158, 97, 253, 188, 23, 205, 227, 209, 90, 134, 65, 85, 247]], old, fresh)
}

#[test]
fn matches_with_different_blinders() {
    let (hashes, old, fresh) = fixture(); main(hashes, [22, 22], old, fresh);
}
#[test(should_fail_with = "User ID mismatch")]
fn rejects_another_authenticated_user() {
    let (mut hashes, old, _) = fixture();
    hashes[1] = [42, 46, 19, 142, 175, 226, 84, 34, 94, 17, 119, 100, 218, 91, 186, 189, 84, 143, 169, 141, 210, 234, 102, 9, 80, 220, 132, 122, 250, 116, 2, 115];
    let other = [65, 73, 68, 65, 79, 84, 72, 69, 82, 85, 83, 69, 82, 48, 48, 48, 48, 48, 48, 48, 48, 49, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    main(hashes, [22, 22], old, other);
}
#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_incorrect_opening() {
    let (hashes, old, mut fresh) = fixture(); fresh[22] = 3; main(hashes, [22, 22], old, fresh);
}
#[test(should_fail_with = "User ID length mismatch")]
fn rejects_different_lengths() {
    let (hashes, old, fresh) = fixture(); main(hashes, [22, 21], old, fresh);
}
#[test(should_fail_with = "User ID length mismatch")]
fn rejects_empty_identity() {
    let (hashes, old, fresh) = fixture(); main(hashes, [0, 0], old, fresh);
}
