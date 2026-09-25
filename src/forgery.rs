//! Forgery-rejection battery.
//!
//! Every case below starts from the valid RFC 8439 §2.8.2 AEAD message
//! (key 0x80..0x9f, constant 07000000, IV 40..47, AAD 50515253c0..c7,
//! the "sunscreen" plaintext) and mutates exactly one field. A correct
//! AEAD implementation must **reject** every mutated message (the
//! Poly1305 tag will not validate) while **accepting** the untouched
//! control. Tag comparison is constant-time, so rejection leaks no
//! timing information about *which* byte differed.

use crate::aead;
use crate::kats::{KEY_80_9F, SUNSCREEN_PT};

/// One forgery-battery case outcome.
#[derive(Debug, Clone)]
pub struct ForgeryResult {
    pub name: String,
    /// `true` when the message is a valid control that should be accepted.
    pub is_control: bool,
    /// What the implementation decided: `true` = plaintext released.
    pub accepted: bool,
    /// `true` when the decision matches the expectation
    /// (controls accepted, forgeries rejected).
    pub ok: bool,
}

/// The fixed inputs of the battery (RFC 8439 §2.8.2).
pub struct BatteryInputs {
    pub const_part: [u8; 4],
    pub iv: [u8; 8],
    pub aad: Vec<u8>,
    pub pt: Vec<u8>,
    pub ct: Vec<u8>,
    pub tag: [u8; 16],
    pub key: [u8; 32],
}

/// Build the valid §2.8.2 message once.
#[must_use]
pub fn inputs() -> BatteryInputs {
    let const_part: [u8; 4] = [0x07, 0, 0, 0];
    let iv: [u8; 8] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7].to_vec();
    let pt = SUNSCREEN_PT.as_bytes().to_vec();
    let (ct, tag) = aead::encrypt(&KEY_80_9F, &const_part, &iv, &aad, &pt);
    BatteryInputs { const_part, iv, aad, pt, ct, tag, key: KEY_80_9F }
}

/// Run the full forgery battery. Every case is deterministic.
#[must_use]
pub fn battery() -> Vec<ForgeryResult> {
    let in_ = inputs();

    // Helper: attempt a decryption and record the outcome.
    let run = |name: String,
                   is_control: bool,
                   key: &[u8; 32],
                   const_part: &[u8; 4],
                   iv: &[u8; 8],
                   aad: &[u8],
                   ct: &[u8],
                   tag: [u8; 16]|
     -> ForgeryResult {
        let accepted = matches!(
            aead::decrypt(key, const_part, iv, aad, ct, tag),
            Some(pt) if pt == in_.pt
        );
        let ok = if is_control { accepted } else { !accepted };
        ForgeryResult { name, is_control, accepted, ok }
    };

    let mut out: Vec<ForgeryResult> = Vec::new();

    // --- controls (must be accepted) ---------------------------------
    out.push(run(
        "control: untouched §2.8.2 message".into(),
        true,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        in_.tag,
    ));

    // --- tag mutations (must be rejected) ----------------------------
    let mut tag_first_bit = in_.tag;
    tag_first_bit[0] ^= 1;
    out.push(run(
        "tag bit 0 flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        tag_first_bit,
    ));

    let mut tag_mid_bit = in_.tag;
    tag_mid_bit[8] ^= 0x80;
    out.push(run(
        "tag bit 71 flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        tag_mid_bit,
    ));

    let mut tag_last_bit = in_.tag;
    tag_last_bit[15] ^= 1;
    out.push(run(
        "tag bit 127 flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        tag_last_bit,
    ));

    out.push(run(
        "tag zeroed".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        [0u8; 16],
    ));

    // --- ciphertext mutations (must be rejected) ---------------------
    let mut ct_first = in_.ct.clone();
    ct_first[0] ^= 0x01;
    out.push(run(
        "ciphertext byte 0 flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &ct_first,
        in_.tag,
    ));

    let mut ct_last = in_.ct.clone();
    *ct_last.last_mut().expect("ct non-empty") ^= 0x80;
    out.push(run(
        "ciphertext last bit flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &ct_last,
        in_.tag,
    ));

    let ct_truncated = &in_.ct[..in_.ct.len() - 1];
    out.push(run(
        "ciphertext truncated (1 byte short)".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        ct_truncated,
        in_.tag,
    ));

    // ciphertext of a *different* plaintext under the same (key, nonce):
    // the tag belongs to the original message, so this must be rejected.
    let other_pt = b"Forged plaintext, same key and nonce.";
    let (other_ct, _other_tag) =
        aead::encrypt(&in_.key, &in_.const_part, &in_.iv, &in_.aad, other_pt);
    out.push(run(
        "ciphertext swapped (tag from another message)".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &other_ct,
        in_.tag,
    ));

    // --- AAD / nonce / key mutations (must be rejected) --------------
    let mut aad_mut = in_.aad.clone();
    aad_mut[0] ^= 0xff;
    out.push(run(
        "AAD byte 0 flipped".into(),
        false,
        &in_.key,
        &in_.const_part,
        &in_.iv,
        &aad_mut,
        &in_.ct,
        in_.tag,
    ));

    let mut iv_mut = in_.iv;
    iv_mut[0] ^= 1;
    out.push(run(
        "IV byte 0 flipped (new keystream, same tag)".into(),
        false,
        &in_.key,
        &in_.const_part,
        &iv_mut,
        &in_.aad,
        &in_.ct,
        in_.tag,
    ));

    let mut const_mut = in_.const_part;
    const_mut[0] ^= 0x01;
    out.push(run(
        "constant byte 0 flipped".into(),
        false,
        &in_.key,
        &const_mut,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        in_.tag,
    ));

    let mut key_mut = in_.key;
    key_mut[31] ^= 1;
    out.push(run(
        "key last bit flipped".into(),
        false,
        &key_mut,
        &in_.const_part,
        &in_.iv,
        &in_.aad,
        &in_.ct,
        in_.tag,
    ));

    out
}

/// Number of battery cases (stable; KAT'd in tests).
#[must_use]
pub fn case_count() -> usize {
    battery().len()
}
