//! Poly1305 field (mod 2^130 - 5) edge cases and structural invariants.

use twotime::poly::{self, F};

#[test]
fn p_is_2_pow_130_minus_5() {
    // P = 2^130 - 5 = 3·2^128 + (2^128 - 5).
    assert_eq!(poly::P.lo(), u128::MAX - 4);
    assert_eq!(poly::P.hi(), 3);
}

#[test]
fn from_hex_rfc_intermediates() {
    // The three 33-digit accumulators published in RFC 8439 §2.5.2.
    let a1 = F::from_hex("2c88c77849d64ae9147ddeb88e69c83fc");
    let a2 = F::from_hex("2d8adaf23b0337fa7cccfb4ea344b30de");
    let a3 = F::from_hex("28d31b7caff946c77c8844335369d03a7");
    assert_eq!(a1.hi(), 2);
    assert_eq!(a2.hi(), 2);
    assert_eq!(a3.hi(), 2);
    // And the full 130-bit acc + s printout (33 hex digits: hi = 2, lo below).
    let sum = F::from_hex("2a927010caf8b2bc2c6365130c11d06a8");
    assert_eq!(sum.hi(), 2);
    assert_eq!(sum.lo(), 0xa927010caf8b2bc2c6365130c11d06a8);
}

#[test]
fn r_zero_tag_equals_s() {
    // A.3 #2: with r = 0 the MAC is s for ANY message.
    let s = 0x9422874132428419;
    let t1 = poly::mac_rs(0, s, b"");
    let t2 = poly::mac_rs(0, s, b"any message at all, even none");
    let want = s.to_le_bytes();
    assert_eq!(t1, want);
    assert_eq!(t2, want);
}

#[test]
fn empty_message_tag_equals_s() {
    // acc starts at 0; with an empty message acc + s = s.
    let mut key = [0u8; 32];
    key[0] = 1;
    let (r, s) = poly::split_key(&key);
    assert!(r < poly::P, "clamped r must be below the modulus");
    let tag = poly::mac(&key, b"");
    assert_eq!(tag, s.to_le_bytes());
}

#[test]
fn clamp_masks() {
    // RFC 8439 §2.5: clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff,
    // which in little-endian bytes is:
    //   r[3],r[7],r[11],r[15] &= 15 (top nibble of each of those bytes)
    //   r[4],r[8],r[12]       &= 252 (low 2 bits of each of those bytes)
    let key = [0xffu8; 32];
    let (r, s) = poly::split_key(&key);
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&r.lo().to_le_bytes());
    assert_eq!(rb[3], 0x0f, "r[3] top nibble cleared");
    assert_eq!(rb[7], 0x0f, "r[7] top nibble cleared");
    assert_eq!(rb[11], 0x0f, "r[11] top nibble cleared");
    assert_eq!(rb[15], 0x0f, "r[15] top nibble cleared");
    assert_eq!(rb[4], 0xfc, "r[4] low 2 bits cleared");
    assert_eq!(rb[8], 0xfc, "r[8] low 2 bits cleared");
    assert_eq!(rb[12], 0xfc, "r[12] low 2 bits cleared");
    assert_eq!(rb[0], 0xff, "r[0] untouched by the clamp");
    // s is the untouched high half.
    assert_eq!(s, u128::from_le_bytes([0xff; 16]));
}

#[test]
fn a3_8_polynomial_equals_p_gives_tag_zero() {
    // A.3 #8 (RFC values verbatim): r = 1, s = 0, and the 48-byte data below
    // is engineered so the polynomial accumulator reduces to exactly
    // P = 2^130 - 5; (acc + s) mod 2^128 then lands on zero.
    let r = 1u128;
    let data = hex("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff fb fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01");
    let tag = poly::mac_rs(r, 0, &data);
    assert_eq!(tag, [0u8; 16]);
}

fn hex(s: &str) -> Vec<u8> {
    let t: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn f_ordering_and_zero() {
    assert!(F::ZERO < F::from_low(1));
    assert!(F::from_low(1) < F::from_low(2));
    assert!(F::from_low(u128::MAX) < F::from_parts(0, 1));
    assert!(F::from_parts(0, 1) < F::from_parts(0, 2));
    assert!(F::from_parts(u128::MAX - 4, 3) == poly::P);
}

#[test]
fn f_add_carries_into_hi() {
    // (2^128 - 5) + 5 = 2^128: lo wraps to 0, hi becomes 1.
    let a = F::from_low(u128::MAX - 4);
    let b = F::from_low(5);
    let c = a.add(b);
    assert_eq!(c.lo(), 0);
    assert_eq!(c.hi(), 1);
}

#[test]
fn mac_is_deterministic() {
    let key = twotime::kats::KEY_1C92;
    let msg = b"deterministic mac check";
    assert_eq!(poly::mac(&key, msg), poly::mac(&key, msg));
}

#[test]
fn acc_trace_length() {
    let key = twotime::kats::KEY_80_9F;
    let trace = poly::acc_trace(&key, &vec![0x20u8; 34]);
    // 34 bytes = 3 blocks (16 + 16 + 2) -> one accumulator per block.
    assert_eq!(trace.len(), 3);
}
