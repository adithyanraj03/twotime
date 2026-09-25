//! ChaCha20 stream-cipher properties (RFC 8439 §2.1-2.4).

use twotime::chacha;

fn key() -> [u8; 32] {
    twotime::kats::KEY_SEQ
}
fn nonce() -> [u8; 12] {
    // RFC 8439 §2.3.2 nonce.
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4a, 0]
}

#[test]
fn quarter_round_rfc_vector() {
    // RFC 8439 §2.1.1.
    let [a, b, c, d] = chacha::quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);
    assert_eq!(a, 0xea2a92f4);
    assert_eq!(b, 0xcb1cf8ce);
    assert_eq!(c, 0x4581472e);
    assert_eq!(d, 0x5881c4bb);
}

#[test]
fn involution_round_trip() {
    let k = key();
    let n = nonce();
    let pt: Vec<u8> = (0..200u32).map(|x| (x.wrapping_mul(31) ^ 0xabcd) as u8).collect();
    let ct = chacha::encrypt(&k, 5, &n, &pt);
    assert_ne!(ct, pt);
    let back = chacha::encrypt(&k, 5, &n, &ct);
    assert_eq!(back, pt);
}

#[test]
fn partial_block_round_trip_37() {
    let k = key();
    let n = nonce();
    let pt: Vec<u8> = (0..37u8).collect();
    let ct = chacha::encrypt(&k, 0, &n, &pt);
    assert_eq!(ct.len(), 37);
    assert_eq!(chacha::encrypt(&k, 0, &n, &ct), pt);
}

#[test]
fn block_zero_differs_from_block_one() {
    let k = key();
    let n = nonce();
    assert_ne!(
        chacha::chacha20_block(&k, 0, &n),
        chacha::chacha20_block(&k, 1, &n)
    );
}

#[test]
fn keystream_deterministic() {
    let k = key();
    let n = nonce();
    assert_eq!(chacha::keystream(&k, 3, &n, 100), chacha::keystream(&k, 3, &n, 100));
    // Different counters give independent streams.
    assert_ne!(chacha::keystream(&k, 3, &n, 64), chacha::keystream(&k, 4, &n, 64));
}

#[test]
fn keystream_spans_block_boundary() {
    // 100 bytes = block 0 (64) + 36 of block 1.
    let k = key();
    let n = nonce();
    let full = chacha::keystream(&k, 0, &n, 100);
    let b0 = chacha::chacha20_block(&k, 0, &n);
    let b1 = chacha::chacha20_block(&k, 1, &n);
    assert_eq!(&full[..64], &b0[..]);
    assert_eq!(&full[64..100], &b1[..36]);
}

#[test]
fn counter_max_then_wraps() {
    // counter = 0xFFFFFFFF, then the next keystream block uses counter 0
    // of a *different* stream; here we only check that 0xFFFFFFFF works.
    let k = key();
    let n = nonce();
    let ks = chacha::keystream(&k, u32::MAX, &n, 64);
    assert_eq!(ks, chacha::chacha20_block(&k, u32::MAX, &n).to_vec());
}

#[test]
fn empty_keystream() {
    let k = key();
    let n = nonce();
    assert!(chacha::keystream(&k, 0, &n, 0).is_empty());
}
