use aws_private_json::tool::{classify, CLI};
use gcp_private_json::commitment;

// The commitment and length are the decoded userAgent slot of an accepted escaped-atom proof.
fn main(commitment: pub [u8; 32], length: pub u32, preimage: [u8; 528]) -> pub u8 {
    let value: [u8; 512] = commitment::authenticate(preimage, length, commitment);
    classify(value, length)
}

global CLI_DIGEST: [u8; 32] = [253, 19, 154, 153, 104, 12, 55, 138, 239, 155, 65, 253, 224, 59, 96, 14, 3, 131, 0, 230, 138, 218, 63, 196, 91, 167, 102, 114, 229, 143, 254, 196];

fn cli_preimage() -> [u8; 528] {
    let mut preimage = [0; 528];
    let text = "\"aws-cli/2\"".as_bytes();
    for i in 0..11 { preimage[i] = text[i]; }
    for i in 11..27 { preimage[i] = 7; }
    preimage
}

// Reference digest of "aws-cli/2" (quoted) followed by sixteen 7 bytes, from Node's crypto.
#[test]
fn opens_the_committed_agent_and_returns_its_class() {
    assert(main(CLI_DIGEST, 11, cli_preimage()) == CLI);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_a_shorter_claimed_length() {
    // Claiming "aws-cl" would drop the class; the commitment pins the full value.
    let _ = main(CLI_DIGEST, 7, cli_preimage());
}
