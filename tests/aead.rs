//! AEAD round-trip and rejection behavior (RFC 8439 §2.8).

use twotime::aead;

fn key() -> [u8; 32] {
    twotime::kats::KEY_80_9F
}
fn const_iv() -> ([u8; 4], [u8; 8]) {
    ([0x07, 0, 0, 0], [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47])
}
fn aad() -> Vec<u8> {
    vec![0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]
}

#[test]
fn round_trip_with_aad() {
    let k = key();
    let (c, i) = const_iv();
    let pt = b"the quick brown fox jumps over the lazy dog";
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), pt);
    assert_ne!(ct.as_slice(), pt.as_slice());
    let out = aead::decrypt(&k, &c, &i, &aad(), &ct, tag).unwrap();
    assert_eq!(out, pt.as_slice());
}

#[test]
fn round_trip_without_aad() {
    let k = key();
    let (c, i) = const_iv();
    let pt = b"no associated data here";
    let (ct, tag) = aead::encrypt(&k, &c, &i, &[], pt);
    assert_eq!(aead::decrypt(&k, &c, &i, &[], &ct, tag).unwrap(), pt.as_slice());
}

#[test]
fn empty_message() {
    let k = key();
    let (c, i) = const_iv();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), b"");
    assert!(ct.is_empty());
    assert_eq!(tag.len(), 16);
    let out = aead::decrypt(&k, &c, &i, &aad(), &ct, tag).unwrap();
    assert!(out.is_empty());
}

#[test]
fn empty_aad_and_message() {
    let k = key();
    let (c, i) = const_iv();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &[], b"");
    assert!(ct.is_empty());
    assert!(aead::decrypt(&k, &c, &i, &[], &ct, tag).is_some());
}

#[test]
fn multi_block_1000_bytes() {
    let k = key();
    let (c, i) = const_iv();
    let pt: Vec<u8> = (0..1000u32).map(|x| (x * 7 + 3) as u8).collect();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), &pt);
    assert_eq!(ct.len(), 1000);
    assert_eq!(aead::decrypt(&k, &c, &i, &aad(), &ct, tag).unwrap(), pt.as_slice());
}

#[test]
fn partial_block_37_bytes() {
    let k = key();
    let (c, i) = const_iv();
    let pt: Vec<u8> = (0..37u8).collect();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), &pt);
    assert_eq!(aead::decrypt(&k, &c, &i, &aad(), &ct, tag).unwrap(), pt.as_slice());
}

#[test]
fn corrupted_tag_rejected() {
    let k = key();
    let (c, i) = const_iv();
    let (ct, mut tag) = aead::encrypt(&k, &c, &i, &aad(), b"secret");
    tag[0] ^= 1;
    assert!(aead::decrypt(&k, &c, &i, &aad(), &ct, tag).is_none());
    tag[0] ^= 1;
    assert!(aead::decrypt(&k, &c, &i, &aad(), &ct, tag).is_some());
}

#[test]
fn corrupted_ciphertext_rejected() {
    let k = key();
    let (c, i) = const_iv();
    let (mut ct, tag) = aead::encrypt(&k, &c, &i, &aad(), b"secret message");
    ct[5] ^= 0x80;
    assert!(aead::decrypt(&k, &c, &i, &aad(), &ct, tag).is_none());
}

#[test]
fn corrupted_aad_rejected() {
    let k = key();
    let (c, i) = const_iv();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), b"secret message");
    let mut bad = aad();
    bad[0] ^= 1;
    assert!(aead::decrypt(&k, &c, &i, &bad, &ct, tag).is_none());
}

#[test]
fn wrong_key_rejected() {
    let k = key();
    let (c, i) = const_iv();
    let (ct, tag) = aead::encrypt(&k, &c, &i, &aad(), b"secret message");
    let mut k2 = k;
    k2[31] ^= 1;
    assert!(aead::decrypt(&k2, &c, &i, &aad(), &ct, tag).is_none());
}

#[test]
fn encrypt_is_deterministic() {
    let k = key();
    let (c, i) = const_iv();
    let pt = b"determinism check";
    let (ct1, tag1) = aead::encrypt(&k, &c, &i, &aad(), pt);
    let (ct2, tag2) = aead::encrypt(&k, &c, &i, &aad(), pt);
    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
}

#[test]
fn otk_matches_rfc_2_6_2() {
    // §2.6.2: OTK = first 32 bytes of ChaCha20 block 0 of (key, 96-bit nonce).
    let k = [0u8; 32];
    let otk = aead::otk(&k, &[0; 4], &[0; 8]);
    assert_eq!(
        otk,
        twotime::poly::key_gen(&k, &[0u8; 12]),
        "otk must be the first 32 bytes of ChaCha20 block 0"
    );
}
