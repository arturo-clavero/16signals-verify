use crate::{identity, tool};
use gcp_private_json::commitment;

// Batch row circuit for LookupEvents page rows: one opening of the identity session's raw IAM UserId, Arn,
// Path and UserName, then per row three spans of the outer JSON (the CloudTrailEvent string, so every inner
// quote is \" on the wire):
//   actor      \"<principalId>\",\"arn\":\"<arn>\",\"accountId\":\"<account>\"  byte-equal to the identity
//   body       \"<userAgent>\",\"requestParameters\":<...>  up to the byte before ,\"recipientAccountId\":
//   recipient  \"<account>\"
// The verifier binds every hash and length to its transcript range and checks the revealed bytes around them.
// Longer identities or spans fail closed.
pub global RAW_ID: u32 = 64;
pub global RAW_ARN: u32 = 128;
pub global RAW_PATH: u32 = 64;
pub global RAW_USER: u32 = 64;
pub global ACTOR: u32 = 256;
pub global UA: u32 = 320;
pub global RECIPIENT: u32 = 16;
// ,\"requestParameters\": on the wire.
global REQUEST_KEY: u32 = 22;

// Values hold no quote or backslash (the identity grammar rules them out), so each is exactly one string.
fn actor<let I: u32, let A: u32>(wire: [u8; ACTOR], length: u32, id: [u8; I], id_len: u32, arn: [u8; A], arn_len: u32, account: [u8; 12]) {
    let arn_key = "\\\",\\\"arn\\\":\\\"".as_bytes();
    let account_key = "\\\",\\\"accountId\\\":\\\"".as_bytes();
    assert(length == 2 + id_len + 13 + arn_len + 19 + 12 + 2, "Actor span length");
    // Reads at offsets that depend on the private lengths; no predicated writes (they copy whole arrays).
    assert((wire[0] == 92) & (wire[1] == 34), "Actor quotes");
    for i in 0..I { if i < id_len { assert(wire[2 + i] == id[i], "Actor is not the proven IAM user"); } }
    let a = 2 + id_len;
    for i in 0..13 { assert(wire[a + i] == arn_key[i], "Actor arn key"); }
    for i in 0..A { if i < arn_len { assert(wire[a + 13 + i] == arn[i], "Actor is not the proven IAM user"); } }
    let b = a + 13 + arn_len;
    for i in 0..19 { assert(wire[b + i] == account_key[i], "Actor account key"); }
    for i in 0..12 { assert(wire[b + 19 + i] == account[i], "Actor is not the proven account"); }
    assert((wire[b + 31] == 92) & (wire[b + 32] == 34), "Actor closing quote");
}

// The userAgent has no quote or backslash inside, so it is exactly one string and the key after it is
// requestParameters: AWS writes errorCode/errorMessage right after the userAgent, so a failed call or a dry run
// cannot be claimed. The whole span stays inside ONE outer JSON string (every outer quote escaped), so the
// recipientAccountId revealed after it belongs to the same event. ua_length is private: the first \" after the
// opening one fixes it. Returns the tool class of the decoded userAgent.
fn body<let B: u32>(wire: [u8; B], length: u32, ua_length: u32) -> u8 {
    let key = ",\\\"requestParameters\\\":".as_bytes();
    assert((ua_length >= 5) & (ua_length <= UA) & (ua_length + REQUEST_KEY <= length) & (length <= B), "Body span length");
    assert((wire[0] == 92) & (wire[1] == 34) & (wire[ua_length - 2] == 92) & (wire[ua_length - 1] == 34), "User agent quotes");
    let mut decoded = [0u8; UA];
    decoded[0] = 34;
    for i in 2..UA {
        if i < ua_length - 2 {
            assert((wire[i] != 34) & (wire[i] != 92), "User agent is not one plain string");
            decoded[i - 1] = wire[i];
        }
        if i == ua_length - 2 { decoded[i - 1] = 34; }
    }
    for i in 0..REQUEST_KEY { assert(wire[ua_length + i] == key[i], "requestParameters must follow the user agent"); }
    let mut escaped = false;
    for i in 0..B {
        if i < length {
            let c = wire[i];
            if escaped { escaped = false; } else {
                assert(c != 34, "Event body leaves the event string");
                escaped = c == 92;
            }
        }
    }
    assert(!escaped, "Event body ends inside an escape");
    tool::classify(decoded, ua_length - 2)
}

fn recipient(wire: [u8; RECIPIENT], length: u32, account: [u8; 12]) {
    assert(length == RECIPIENT, "Recipient length");
    assert((wire[0] == 92) & (wire[1] == 34) & (wire[14] == 92) & (wire[15] == 34), "Recipient quotes");
    for i in 0..12 { assert(wire[2 + i] == account[i], "Recipient is not the proven account"); }
}

// Unused slots repeat a proven row; the verifier counts distinct rows. Returns one tool class per slot.
pub fn rows<let K: u32, let B: u32>(
    identity_hashes: [[u8; 32]; 4], identity_lengths: [u32; 4],
    row_hashes: [[[u8; 32]; 3]; K], row_lengths: [[u32; 3]; K],
    id_preimage: [u8; RAW_ID + 16], arn_preimage: [u8; RAW_ARN + 16], path_preimage: [u8; RAW_PATH + 16], user_preimage: [u8; RAW_USER + 16],
    row_actor: [[u8; ACTOR + 16]; K], row_body: [[u8; B + 16]; K], row_recipient: [[u8; RECIPIENT + 16]; K], ua_lengths: [u32; K],
) -> [u8; K] {
    let id = commitment::authenticate(id_preimage, identity_lengths[0], identity_hashes[0]);
    let arn = commitment::authenticate(arn_preimage, identity_lengths[1], identity_hashes[1]);
    let path = commitment::authenticate(path_preimage, identity_lengths[2], identity_hashes[2]);
    let user = commitment::authenticate(user_preimage, identity_lengths[3], identity_hashes[3]);
    let account = identity::validate(id, identity_lengths[0], arn, identity_lengths[1], path, identity_lengths[2], user, identity_lengths[3]);
    let mut classes = [0u8; K];
    for r in 0..K {
        let h = row_hashes[r];
        let l = row_lengths[r];
        actor(commitment::authenticate(row_actor[r], l[0], h[0]), l[0], id, identity_lengths[0], arn, identity_lengths[1], account);
        classes[r] = body(commitment::authenticate(row_body[r], l[1], h[1]), l[1], ua_lengths[r]);
        recipient(commitment::authenticate(row_recipient[r], l[2], h[2]), l[2], account);
    }
    classes
}
