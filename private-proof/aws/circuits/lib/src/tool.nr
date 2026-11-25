// Tool classes for a CloudTrail userAgent, mirrored in tool-class.mjs (a test keeps them equal).
// The value is the decoded JSON string, quotes included (the escaped-atom output, or a userAgent with no
// escapes inside, as the batch row circuit proves).
// A PREFIX pattern starts right after the opening quote; a TOKEN pattern starts after the
// opening quote or a space. One optional `[` may follow the opening quote (S3 events wrap
// the whole userAgent in brackets); patterns at the start then begin after it. Every match ends before the closing quote. The first class that
// matches wins, in this order; 0 means no class matched.
pub global CONSOLE: u8 = 1;
pub global CLI: u8 = 2;
pub global TERRAFORM: u8 = 3;
pub global SDK_OTHER: u8 = 4;
global CONSOLE_PREFIX_0: [u8; 8] = "console.".as_bytes();
global CONSOLE_PREFIX_1: [u8; 20] = "signin.amazonaws.com".as_bytes();
global CONSOLE_PREFIX_2: [u8; 12] = "AWS Internal".as_bytes();
global CONSOLE_PREFIX_3: [u8; 8] = "Mozilla/".as_bytes();
global CLI_PREFIX_0: [u8; 8] = "aws-cli/".as_bytes();
global TERRAFORM_TOKEN_0: [u8; 32] = "APN/1.0 HashiCorp/1.0 Terraform/".as_bytes();
global SDK_OTHER_TOKEN_0: [u8; 8] = "aws-sdk-".as_bytes();
global SDK_OTHER_TOKEN_1: [u8; 6] = "Boto3/".as_bytes();

fn matches_at<let N: u32, let L: u32>(value: [u8; N], length: u32, at: u32, pattern: [u8; L]) -> bool {
    // The closing quote sits at length - 1, so a match must end before it.
    let mut ok = at + L < length;
    for j in 0..L { ok = ok & (value[at + j] == pattern[j]); }
    ok
}

fn has_prefix<let N: u32, let L: u32>(value: [u8; N], length: u32, pattern: [u8; L]) -> bool {
    // Both start positions use fixed indices; the bracket picks one.
    let bracket = value[1] == 91;
    (!bracket & matches_at(value, length, 1, pattern)) | (bracket & matches_at(value, length, 2, pattern))
}

fn has_token<let N: u32, let L: u32>(value: [u8; N], length: u32, pattern: [u8; L]) -> bool {
    let mut found = has_prefix(value, length, pattern);
    for i in 2..(N - L) { found = found | ((value[i - 1] == 32) & matches_at(value, length, i, pattern)); }
    found
}

pub fn classify<let N: u32>(value: [u8; N], length: u32) -> u8 {
    assert((length >= 2) & (length <= N), "User agent byte limit");
    assert(value[0] == 34, "User agent is not a JSON string");
    let console = has_prefix(value, length, CONSOLE_PREFIX_0) | has_prefix(value, length, CONSOLE_PREFIX_1) |
        has_prefix(value, length, CONSOLE_PREFIX_2) | has_prefix(value, length, CONSOLE_PREFIX_3);
    let cli = has_prefix(value, length, CLI_PREFIX_0);
    let terraform = has_token(value, length, TERRAFORM_TOKEN_0);
    let sdk = has_token(value, length, SDK_OTHER_TOKEN_0) | has_token(value, length, SDK_OTHER_TOKEN_1);
    if console { CONSOLE } else if cli { CLI } else if terraform { TERRAFORM } else if sdk { SDK_OTHER } else { 0 }
}

fn padded<let L: u32>(text: [u8; L]) -> [u8; 512] {
    let mut value = [0; 512];
    for i in 0..L { value[i] = text[i]; }
    value
}

fn class_of<let L: u32>(text: str<L>) -> u8 {
    classify(padded(text.as_bytes()), L)
}

#[test]
fn classifies_documented_shapes() {
    assert(class_of("\"console.amazonaws.com\"") == CONSOLE);
    assert(class_of("\"signin.amazonaws.com\"") == CONSOLE);
    assert(class_of("\"AWS Internal\"") == CONSOLE);
    assert(class_of("\"Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0\"") == CONSOLE);
    assert(class_of("\"aws-cli/2.22.4 md/awscrt#0.22.0 ua/2.0 os/linux#6.8 md/arch#x86_64 lang/python#3.12.6 md/command#iam.update-assume-role-policy\"") == CLI);
    assert(class_of("\"APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) terraform-provider-aws/5.80.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.32.6 ua/2.1 os/linux lang/go#1.23.3 md/GOOS#linux md/GOARCH#amd64 api/iam#1.38.2\"") == TERRAFORM);
    assert(class_of("\"aws-sdk-go/1.44.0 (go1.19; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/0.15.5 (+https://www.terraform.io)\"") == TERRAFORM);
    assert(class_of("\"Boto3/1.35.0 md/Botocore#1.35.0 ua/2.0 os/linux#6.8 lang/python#3.12.6\"") == SDK_OTHER);
    assert(class_of("\"aws-sdk-js/3.700.0 ua/2.1 os/linux#6.8 lang/js md/nodejs#22.11.0 api/lambda#3.700.0\"") == SDK_OTHER);
}

#[test]
fn one_leading_bracket_is_allowed() {
    assert(class_of("\"[aws-cli/2.42.1 md/awscrt#0.38.1 ua/2.1 md/command#s3api.put-bucket-versioning]\"") == CLI);
    assert(class_of("\"[APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) aws-sdk-go-v2/1.32.6]\"") == TERRAFORM);
    assert(class_of("\"[Boto3/1.35.0 md/Botocore#1.35.0]\"") == SDK_OTHER);
    assert(class_of("\"[console.amazonaws.com]\"") == CONSOLE);
    assert(class_of("\"[[aws-cli/2.42.1]\"") == 0);
    assert(class_of("\"[\"") == 0);
    // A bracket later in the value is not a start.
    assert(class_of("\"curl/8 [aws-cli/2.42.1\"") == 0);
    assert(class_of("\"curl/8 [aws-sdk-go/1.0\"") == 0);
    assert(class_of("\" [aws-cli/2.42.1\"") == 0);
}

#[test]
fn unmatched_and_truncated_agents_have_no_class() {
    assert(class_of("\"curl/8.5.0\"") == 0);
    assert(class_of("\"\"") == 0);
    assert(class_of("\"aws-cl\"") == 0);
    assert(class_of("\"aws-cli/\"") == CLI);
    assert(class_of("\"APN/1.0 HashiCorp/1.0 Terraform\"") == 0);
    assert(class_of("\"console\"") == 0);
}

#[test]
fn class_text_outside_its_position_does_not_count() {
    // Prefix patterns only count right after the opening quote.
    assert(class_of("\" aws-cli/2.22.4\"") == 0);
    assert(class_of("\"x-aws-cli/2.22.4\"") == 0);
    assert(class_of("\"curl/8 console.amazonaws.com\"") == 0);
    // Token patterns need a space or the opening quote before them.
    assert(class_of("\"curl/8 xAPN/1.0 HashiCorp/1.0 Terraform/1.9.8\"") == 0);
    assert(class_of("\"curl/8 md/aws-sdk-go\"") == 0);
    // Earlier classes win over later ones.
    assert(class_of("\"aws-cli/2.22.4 APN/1.0 HashiCorp/1.0 Terraform/1.9.8\"") == CLI);
    assert(class_of("\"curl/8 aws-sdk-go/1.0\"") == SDK_OTHER);
}

#[test]
fn bytes_after_the_length_are_ignored() {
    // The private blinder and padding follow the value; a pattern there must not match.
    let mut value = padded("\"curl/8 \"".as_bytes());
    let tail = "aws-sdk-go/1".as_bytes();
    for i in 0..12 { value[9 + i] = tail[i]; }
    assert(classify(value, 9) == 0);
    // A value cut inside a pattern does not match either.
    assert(classify(padded("\"curl/8 aws-sdk-go\"".as_bytes()), 12) == 0);
}

#[test(should_fail_with = "User agent is not a JSON string")]
fn rejects_non_string_value() {
    let _ = classify(padded("1234".as_bytes()), 4);
}

#[test(should_fail_with = "User agent byte limit")]
fn rejects_length_past_capacity() {
    let _ = classify(padded("\"x\"".as_bytes()), 513);
}
