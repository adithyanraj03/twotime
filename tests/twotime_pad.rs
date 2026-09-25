//! Two-time-pad mathematics: the namesake attack, byte-exact.
//!
//! Two messages under one (key, nonce) share one keystream:
//!   C1 = P1 xor K,  C2 = P2 xor K  =>  C1 xor C2 = P1 xor P2
//! so an attacker who knows P1 recovers P2 = P1 xor C1 xor C2.

use twotime::chacha;
use twotime::twotime as pad;

fn canonical() -> pad::TwoTimePad {
    pad::canonical()
}

#[test]
fn canonical_lengths() {
    let t = canonical();
    assert_eq!(t.p1.len(), 114, "sunscreen plaintext is 114 bytes");
    assert_eq!(t.p2.len(), 172, "canonical second message is 172 bytes");
    assert_eq!(t.c1.len(), 114);
    assert_eq!(t.c2.len(), 172);
}

#[test]
fn keystream_cancellation_is_byte_exact() {
    let t = canonical();
    let (ok, n) = t.keystream_cancellation();
    assert!(ok, "C1 xor C2 must equal P1 xor P2");
    assert_eq!(n, 114, "cancellation holds over the overlapping 114 bytes");
    // Verify the actual bytes, not just the flag.
    let lhs = pad::xor(&t.c1, &t.c2[..114]);
    let rhs = pad::xor(&t.p1, &t.p2[..114]);
    assert_eq!(lhs, rhs);
}

#[test]
fn p2_recovered_from_p1_is_byte_exact() {
    let t = canonical();
    let recovered = t.recover_p2_from_p1();
    assert_eq!(recovered, t.p2[..114].to_vec());
}

#[test]
fn p2_prefix_recovery_via_16_byte_crib() {
    let t = canonical();
    let (prefix, n) = t.recover_p2_prefix(16);
    assert_eq!(n, 16);
    assert_eq!(prefix, t.p2[..16].to_vec());
    assert_eq!(&prefix, b"The sun never se");
}

#[test]
fn xor_self_is_zero() {
    let a: Vec<u8> = (0..255u8).collect();
    let z = pad::xor(&a, &a);
    assert!(z.iter().all(|&x| x == 0));
}

#[test]
fn xor_length_is_min() {
    assert_eq!(pad::xor(&[1, 2, 3], &[4, 5]).len(), 2);
    assert_eq!(pad::xor(&[1, 2, 3], &[4, 5]), vec![1 ^ 4, 2 ^ 5]);
}

#[test]
fn fresh_pad_has_no_cancellation() {
    // A genuine one-time-pad (unique nonce per message) does NOT leak:
    // C1 xor C2 = P1 xor P2 xor K1 xor K2, which is not P1 xor P2.
    let mut k = [0u8; 32];
    k[31] = 7;
    let n1 = [0u8; 12];
    let mut n2 = [0u8; 12];
    n2[11] = 1;
    let p1 = b"first message under nonce one";
    let p2 = b"second message under nonce two";
    let c1 = chacha::encrypt(&k, 0, &n1, p1);
    let c2 = chacha::encrypt(&k, 0, &n2, p2);
    let lhs = pad::xor(&c1, &c2);
    let rhs = pad::xor(p1, p2);
    assert_ne!(lhs, rhs, "distinct nonces must not cancel the keystream");
}
