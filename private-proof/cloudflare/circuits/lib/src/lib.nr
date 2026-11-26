// Hidden pieces of Cloudflare Audit Logs v2 rows. The prover hides a piece; the verifier reads the revealed skeleton
// around it (row-structure.mjs). These checks make sure a hidden piece can never carry structure out of its slot.
// The bytes are authentic TLS transcript bytes, i.e. valid compact JSON from api.cloudflare.com; what is checked is
// where the piece starts and ends, not full JSON validity.
//
// Kinds: 1 = exactly one JSON value (string, container or scalar), 2 = a JSON string tail (the bytes after an opening
// quote and some revealed content, ending with the closing quote).
pub global VALUE: u8 = 1;
pub global TAIL: u8 = 2;

fn scalar_byte(c: u8) -> bool {
    ((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | (c == 43) | (c == 45) | (c == 46)
}

// `len` is the authenticated length; bytes after it are padding.
pub fn piece<let N: u32>(bytes: [u8; N], len: u32, kind: u8) {
    assert((len > 0) & (len <= N), "Piece byte limit");
    assert((kind == VALUE) | (kind == TAIL), "Unknown piece kind");
    let first = bytes[0];
    let nested = (kind == TAIL) | (first == 34) | (first == 123) | (first == 91);
    let mut in_string = false;
    let mut escaped = false;
    let mut depth: u32 = 0;
    if kind == TAIL { in_string = true; }
    for i in 0..N {
        if i < len {
            let c = bytes[i];
            if nested {
                if in_string {
                    if escaped { escaped = false; }
                    else if c == 92 { escaped = true; }
                    else if c == 34 { in_string = false; }
                    else { assert(c >= 32, "Unescaped control byte"); }
                } else if c == 34 { in_string = true; }
                else if (c == 123) | (c == 91) { depth += 1; }
                else if (c == 125) | (c == 93) { assert(depth > 0, "Unbalanced close"); depth -= 1; }
                else { assert(c > 32, "Whitespace or control outside a string"); }
                let open = in_string | (depth > 0);
                if i + 1 < len { assert(open, "Piece ends before its last byte"); }
                else { assert(!open, "Piece does not end at its last byte"); }
            } else {
                assert(scalar_byte(c), "Invalid scalar byte");
            }
        }
    }
}

#[test]
fn accepts_values_and_tails() {
    piece("\"a\\\"b\"".as_bytes(), 6, VALUE);
    piece("{\"a\":[1,{\"b\":\"}\"}]}".as_bytes(), 19, VALUE);
    piece("[]".as_bytes(), 2, VALUE);
    piece("-12.5e3".as_bytes(), 7, VALUE);
    piece("true".as_bytes(), 4, VALUE);
    piece("T07:00:55.123Z\"".as_bytes(), 15, TAIL);
    piece("{\"a\":1}xxxx".as_bytes(), 7, VALUE);
}

#[test(should_fail_with = "Piece ends before its last byte")]
fn string_with_structure_after_it_is_refused() { piece("\"a\",\"b\":\"c\"".as_bytes(), 11, VALUE); }

#[test(should_fail_with = "Piece ends before its last byte")]
fn two_objects_are_refused() { piece("{},{}".as_bytes(), 5, VALUE); }

#[test(should_fail_with = "Piece does not end at its last byte")]
fn unclosed_object_is_refused() { piece("{\"a\":1".as_bytes(), 6, VALUE); }

#[test(should_fail_with = "Invalid scalar byte")]
fn scalar_with_comma_is_refused() { piece("1,\"x\":2".as_bytes(), 7, VALUE); }

#[test(should_fail_with = "Invalid scalar byte")]
fn close_first_is_refused() { piece("}".as_bytes(), 1, VALUE); }

#[test(should_fail_with = "Piece ends before its last byte")]
fn extra_close_is_refused() { piece("{}}".as_bytes(), 3, VALUE); }

#[test(should_fail_with = "Piece ends before its last byte")]
fn tail_closing_early_is_refused() { piece("T07\",\"type\":\"x\"".as_bytes(), 15, TAIL); }

#[test(should_fail_with = "Unescaped control byte")]
fn control_in_string_is_refused() { piece([34, 10, 34], 3, VALUE); }

#[test(should_fail_with = "Piece byte limit")]
fn empty_piece_is_refused() { piece([0; 4], 0, VALUE); }
