use aws_private_json::batch::{ACTOR, RAW_ARN, RAW_ID, RAW_PATH, RAW_USER, RECIPIENT, rows, UA};

// Three page rows per proof with an event body up to 2,048 bytes; longer rows are not provable.
global K: u32 = 3;
// userAgent (<= UA) + ,\"requestParameters\": + the event body up to recipientAccountId (<= 2048 bytes on the wire).
global BODY: u32 = UA + 22 + 2048;

fn main(
    identity_hashes: pub [[u8; 32]; 4], identity_lengths: pub [u32; 4],
    row_hashes: pub [[[u8; 32]; 3]; K], row_lengths: pub [[u32; 3]; K],
    id_preimage: [u8; RAW_ID + 16], arn_preimage: [u8; RAW_ARN + 16], path_preimage: [u8; RAW_PATH + 16], user_preimage: [u8; RAW_USER + 16],
    row_actor: [[u8; ACTOR + 16]; K], row_body: [[u8; BODY + 16]; K], row_recipient: [[u8; RECIPIENT + 16]; K], ua_lengths: [u32; K],
) -> pub [u8; K] {
    rows(identity_hashes, identity_lengths, row_hashes, row_lengths, id_preimage, arn_preimage, path_preimage, user_preimage,
        row_actor, row_body, row_recipient, ua_lengths)
}
