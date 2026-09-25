//! The RFC 8439 KAT battery — every published test vector embedded
//! verbatim and re-executed on every run.
//!
//! Vectors covered:
//! * §2.1.1 — quarter round
//! * §2.2.1 — quarter round on the ChaCha state
//! * §2.3.2 — ChaCha20 block function (serialized 64-byte block)
//! * §2.4.2 — ChaCha20 cipher ("sunscreen" plaintext: keystream AND
//!   ciphertext)
//! * §2.5.2 — Poly1305 MAC including the three published intermediate
//!   accumulator values (block-by-block KAT)
//! * §2.6.2 — Poly1305 key generation from ChaCha20
//! * §2.8.2 — AEAD_CHACHA20_POLY1305 (one-time key, ciphertext, tag,
//!   and the complete 160-byte Poly1305 input buffer)
//! * Appendix A.1 — five ChaCha20 block functions
//! * Appendix A.2 — three ChaCha20 encryptions
//! * Appendix A.3 — eleven Poly1305 MACs, including the reduction
//!   edge cases (#5-#11, which exercise the mod 2^130-5 reduction's
//!   131-bit intermediate and exact-prime boundaries)
//! * Appendix A.4 — three Poly1305 key generations
//! * Appendix A.5 — full AEAD decryption (tag validates, plaintext
//!   recovered, one-time key and Poly1305 buffer reproduced)
//!
//! All hex below was extracted programmatically from the RFC text
//! (see `extracted.txt` provenance note) and length-checked.

use crate::aead;
use crate::chacha::{chacha20_block, encrypt, quarter_round, quarter_round_state, State};
use crate::poly;

/// One battery check result.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Check {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check { name: name.into(), ok: true, detail: detail.into() }
    }
    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check { name: name.into(), ok: false, detail: detail.into() }
    }
}

/// Parse a space-separated hex string (spaces stripped, pairs parsed).
fn hex_bytes(s: &str) -> Vec<u8> {
    let t: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex_bytes(s).try_into().expect("32 bytes")
}

fn hex12(s: &str) -> [u8; 12] {
    hex_bytes(s).try_into().expect("12 bytes")
}

fn hex16(s: &str) -> [u8; 16] {
    hex_bytes(s).try_into().expect("16 bytes")
}

/// RFC-style hex rendering of a 130-bit field element (no leading-zero
/// padding — exactly like the RFC 8439 §2.5.2 printout).
fn hex130(f: poly::F) -> String {
    if f.hi() > 0 {
        format!("{:x}{:032x}", f.hi(), f.lo())
    } else {
        format!("{:x}", f.lo())
    }
}

fn eq_detail(name: &str, got: &[u8], want: &[u8]) -> Check {
    if got == want {
        Check::pass(name, format!("{} bytes match", want.len()))
    } else {
        Check::fail(name, format!(
            "mismatch: got {}, want {} ({} bytes)",
            crate::crypto::to_hex(&got[..got.len().min(16)]),
            crate::crypto::to_hex(&want[..want.len().min(16)]),
            got.len()
        ))
    }
}

// ---------------------------------------------------------------------------
// §2 vectors
// ---------------------------------------------------------------------------

/// §2.3.2 serialized block (key 00..1f, nonce 000000090000004a00000000,
/// block count 1).
const SERIALIZED_BLOCK_2_3_2: &str = "10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2 b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e";

/// §2.4.2 sunscreen keystream (114 bytes, blocks 1 and 2).
const KEYSTREAM_SUNSCREEN: &str = "22 4f 51 f3 40 1b d9 e1 2f de 27 6f b8 63 1d ed 8c 13 1f 82 3d 2c 06 e2 7e 4f ca ec 9e f3 cf 78 8a 3b 0a a3 72 60 0a 92 b5 79 74 cd ed 2b 93 34 79 4c ba 40 c6 3e 34 cd ea 21 2c 4c f0 7d 41 b7 69 a6 74 9f 3f 63 0f 41 22 ca fe 28 ec 4d c4 7e 26 d4 34 6d 70 b9 8c 73 f3 e9 c5 3a c4 0c 59 45 39 8b 6e da 1a 83 2c 89 c1 67 ea cd 90 1d 7e 2b f3 63";

/// §2.4.2 sunscreen ciphertext (114 bytes).
const CT_SUNSCREEN: &str = "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d";

/// §2.6.2 Poly1305 key generation output (key 80..9f, nonce 000000000001020304050607).
const OTK_2_6_2: &str = "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71 a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46";

/// §2.8.2 AEAD one-time key.
const OTK_AEAD_2_8_2: &str = "7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84 0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff";

/// §2.8.2 AEAD keystream (114 bytes, blocks 1-2).
const KEYSTREAM_AEAD: &str = "9f 7b e9 5d 01 fd 40 ba 15 e2 8f fb 36 81 0a ae c1 c0 88 3f 09 01 6e de dd 8a d0 87 55 82 03 a5 4e 9e cb 38 ac 8e 5e 2b b8 da b2 0f fa db 52 e8 75 04 b2 6e be 69 6d 4f 60 a4 85 cf 11 b8 1b 59 fc b1 c4 5f 42 19 ee ac ec 6a de c3 4e 66 69 78 8e db 41 c4 9c a3 01 e1 27 e0 ac ab 3b 44 b9 cf 5c 86 bb 95 e0 6b 0d f2 90 1a b6 45 e4 ab e6 22 15 38";

/// §2.8.2 AEAD ciphertext (114 bytes).
const CT_AEAD_2_8_2: &str = "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc 3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 61 16";

/// §2.8.2 complete Poly1305 input buffer (160 bytes).
const BUFFER_AEAD_2_8_2: &str = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7 00 00 00 00 d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc 3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b 61 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0c 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00";

/// The "sunscreen" plaintext of §2.4.2/§2.8.2 (114 ASCII bytes).
pub const SUNSCREEN_PT: &str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

/// Key 0x00..0x1f (used by §2.3.2 and §2.4.2).
pub const KEY_SEQ: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Key 0x80..0x9f (used by §2.6.2 and §2.8.2).
pub const KEY_80_9F: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

/// The 127-byte "Twas brillig" plaintext of A.2#3/A.3#4.
const PT_TWAS: &str = "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61 6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f 76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64 20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77 61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77 65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65 73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20 72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e";

/// The 375-byte IETF-Contributions text of A.2#2/A.3#2/A.3#3.
const PT_IETF: &str = "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e 64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e 74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e 79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c 20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65 73 73 65 64 20 74 6f";

// ---------------------------------------------------------------------------
// Appendix A.1 — ChaCha20 block functions
// ---------------------------------------------------------------------------

const A1_KS1: &str = "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7 da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37 6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86";
const A1_KS2: &str = "9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed 29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5 31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f";
const A1_KS3: &str = "3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd 83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a 8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd 4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0";
const A1_KS4: &str = "72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32 8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca 13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09 24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96";
const A1_KS5: &str = "c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd 1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7 8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7 5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d";

// ---------------------------------------------------------------------------
// Appendix A.2 — ChaCha20 encryption
// ---------------------------------------------------------------------------

const A2_CT2: &str = "a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70 41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec 2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05 0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d 40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e 20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50 42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c 68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66 42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28 e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b 08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84 a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0 8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f 58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62 be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6 98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85 14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab 7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd c4 fd 80 6c 22 f2 21";

const A2_CT3: &str = "62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df 5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf 16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71 fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6 1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77 04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1 87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1";

// ---------------------------------------------------------------------------
// Appendix A.3 — Poly1305 MAC
// ---------------------------------------------------------------------------

const A3_KEY2_S: &str = "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e";
const A3_TAG3: &str = "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0";
const A3_TAG4: &str = "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62";

const A3_5_R: &str = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_5_DATA: &str = "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff";
const A3_5_TAG: &str = "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

const A3_6_R: &str = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_6_S: &str = "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff";
const A3_6_DATA: &str = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_6_TAG: &str = "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

const A3_7_R: &str = "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_7_DATA: &str = "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff f0 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_7_TAG: &str = "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

const A3_8_R: &str = "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_8_DATA: &str = "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff fb fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01";
const A3_8_TAG: &str = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

const A3_9_R: &str = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_9_DATA: &str = "fd ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff";
const A3_9_TAG: &str = "fa ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff";

const A3_10_R: &str = "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00";
const A3_10_DATA: &str = "e3 35 94 d7 50 5e 43 b9 00 00 00 00 00 00 00 00 33 94 d7 50 5e 43 79 cd 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_10_TAG: &str = "14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00";

const A3_11_R: &str = "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00";
const A3_11_DATA: &str = "e3 35 94 d7 50 5e 43 b9 00 00 00 00 00 00 00 00 33 94 d7 50 5e 43 79 cd 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
const A3_11_TAG: &str = "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

// ---------------------------------------------------------------------------
// Appendix A.4 — Poly1305 key generation
// ---------------------------------------------------------------------------

const A4_OTK1: &str = "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7";
const A4_OTK2: &str = "ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76 06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39";
const A4_OTK3: &str = "96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b 13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae";

// ---------------------------------------------------------------------------
// Appendix A.5 — AEAD decryption
// ---------------------------------------------------------------------------

const A5_CT: &str = "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd 5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf 33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a 0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a 0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 a6 ad 5c b4 02 2b 02 70 9b";

const A5_OTK: &str = "bd f0 4a a9 5c e4 de 89 95 b1 4b b6 a1 8f ec af 26 47 8f 50 c0 54 f5 63 db c0 a2 1e 26 15 72 aa";

const A5_BUFFER: &str = "f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00 64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd 5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf 33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a 0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a 0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00 0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00";

const A5_PT: &str = "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65 6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20 6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d 6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65 20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63 65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64 20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65 6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e 20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72 69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72 65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61 6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65 6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20 2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67 72 65 73 73 2e 2f e2 80 9d";

/// The A.2#3/A.3#4/A.5 ChaCha20 key (1c 92 40 a5 …).
pub const KEY_1C92: [u8; 32] =
    [0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0];

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// §2.1.1 quarter round KAT.
pub fn kat_quarter_round() -> Check {
    let got = quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);
    let want = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];
    if got == want {
        Check::pass("2.1.1 quarter round", "words match")
    } else {
        Check::fail(
            "2.1.1 quarter round",
            format!("got {got:02x?}, want {want:02x?}"),
        )
    }
}

/// §2.2.1 quarter round on the ChaCha state KAT.
pub fn kat_quarter_round_state() -> Check {
    let mut s: State = [
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
        0x2098d9d6, 0x91dbd320,
    ];
    quarter_round_state(&mut s, 2, 7, 8, 13);
    let want: State = [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
        0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
        0x2098d9d6, 0x91dbd320,
    ];
    if s == want {
        Check::pass("2.2.1 quarter round on state (2,7,8,13)", "state matches")
    } else {
        Check::fail(
            "2.2.1 quarter round on state (2,7,8,13)",
            format!(
                "positions 2,7,8,13: got {:08x} {:08x} {:08x} {:08x}",
                s[2], s[7], s[8], s[13]
            ),
        )
    }
}

/// §2.3.2 ChaCha20 block function KAT.
pub fn kat_block_function() -> Check {
    let block = chacha20_block(&KEY_SEQ, 1, &hex12("00 00 00 09 00 00 00 4a 00 00 00 00"));
    eq_detail("2.3.2 block function (serialized 64 bytes)", &block, &hex_bytes(SERIALIZED_BLOCK_2_3_2))
}

/// §2.4.2 ChaCha20 cipher KAT: keystream and ciphertext.
pub fn kat_sunscreen() -> (Check, Check) {
    let key = KEY_SEQ;
    let nonce = hex12("00 00 00 00 00 00 00 4a 00 00 00 00");
    let pt = SUNSCREEN_PT.as_bytes();

    let ks = crate::chacha::keystream(&key, 1, &nonce, pt.len());
    let c_ks = eq_detail("2.4.2 sunscreen keystream (114 bytes)", &ks, &hex_bytes(KEYSTREAM_SUNSCREEN));

    let ct = encrypt(&key, 1, &nonce, pt);
    let c_ct = eq_detail("2.4.2 sunscreen ciphertext (114 bytes)", &ct, &hex_bytes(CT_SUNSCREEN));
    (c_ks, c_ct)
}

/// §2.5.2 Poly1305 KAT, including the published intermediate
/// accumulators after each of the three message blocks.
/// Returns checks in order: block #1 acc, block #2 acc, block #3 acc,
/// tag, acc+s.
pub fn kat_poly1305() -> Vec<Check> {
    let key = hex32("85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b");
    let msg = b"Cryptographic Forum Research Group";

    let trace = poly::acc_trace(&key, msg);
    let wants: [poly::F; 3] = [
        poly::F::from_hex("2c88c77849d64ae9147ddeb88e69c83fc"),
        poly::F::from_hex("2d8adaf23b0337fa7cccfb4ea344b30de"),
        poly::F::from_hex("28d31b7caff946c77c8844335369d03a7"),
    ];
    let mut out: Vec<Check> = (0..3)
        .map(|i| {
            if trace.get(i) == Some(&wants[i]) {
                Check::pass(
                    format!("2.5.2 accumulator after block #{}", i + 1),
                    hex130(wants[i]),
                )
            } else {
                Check::fail(
                    format!("2.5.2 accumulator after block #{}", i + 1),
                    format!("got {}, want {}", hex130(trace.get(i).copied().unwrap_or_default()), hex130(wants[i])),
                )
            }
        })
        .collect();

    let tag = poly::mac(&key, msg);
    out.push(eq_detail(
        "2.5.2 Poly1305 tag (34-byte message)",
        &tag,
        &hex16("a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9"),
    ));

    // Full (acc + s) value as published (130 bits — the RFC shows the
    // raw sum; the tag is its low 128 bits).
    let (_r, s) = poly::split_key(&key);
    let lo = trace[2].lo();
    let sum_lo = lo.wrapping_add(s);
    let carry = if sum_lo < lo { 1 } else { 0 };
    let sum = poly::F::from_parts(sum_lo, trace[2].hi() + carry);
    let want = poly::F::from_hex("2a927010caf8b2bc2c6365130c11d06a8");
    out.push(if sum == want {
        Check::pass("2.5.2 acc + s before serialization", "0x2a927010caf8b2bc2c6365130c11d06a8")
    } else {
        Check::fail(
            "2.5.2 acc + s before serialization",
            format!("got {}", hex130(sum)),
        )
    });

    out
}

/// §2.6.2 Poly1305 key generation KAT.
pub fn kat_poly1305_keygen() -> Check {
    let otk = poly::key_gen(&KEY_80_9F, &hex12("00 00 00 00 00 01 02 03 04 05 06 07"));
    eq_detail("2.6.2 Poly1305 key generation (OTK)", &otk, &hex_bytes(OTK_2_6_2))
}

/// §2.8.2 AEAD KAT: one-time key, ciphertext, tag, and the full
/// Poly1305 input buffer.
pub fn kat_aead() -> (Check, Check, Check, Check, Check) {
    let const_part: [u8; 4] = [0x07, 0, 0, 0];
    let iv: [u8; 8] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = hex_bytes("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
    let pt = SUNSCREEN_PT.as_bytes();

    let k = aead::otk(&KEY_80_9F, &const_part, &iv);
    let c_otk = eq_detail("2.8.2 AEAD one-time key", &k, &hex_bytes(OTK_AEAD_2_8_2));

    let (r, s) = poly::split_key(&k);
    let r = poly::f_value(r);
    let rs = if r == 0x455e9a4057ab6080f47b42c052bac7bu128 && s == 0xff53d53e7875932aebd9751073d6e10au128 {
        Check::pass(
            "2.8.2 clamped r / s split",
            "r = 0x455e9a4057ab6080f47b42c052bac7b, s = 0xff53d53e7875932aebd9751073d6e10a",
        )
    } else {
        Check::fail(
            "2.8.2 clamped r / s split",
            format!("r = {r:032x}, s = {s:032x}"),
        )
    };

    let (ct, tag) = aead::encrypt(&KEY_80_9F, &const_part, &iv, &aad, pt);
    let c_ct = eq_detail("2.8.2 AEAD ciphertext (114 bytes)", &ct, &hex_bytes(CT_AEAD_2_8_2));
    let c_tag = eq_detail(
        "2.8.2 AEAD tag",
        &tag,
        &hex16("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91"),
    );
    let buf = aead::mac_buffer(&aad, &ct);
    let c_buf = eq_detail(
        "2.8.2 Poly1305 input buffer (160 bytes)",
        &buf,
        &hex_bytes(BUFFER_AEAD_2_8_2),
    );

    (c_otk, rs, c_ct, c_tag, c_buf)
}

/// Appendix A.1 — five ChaCha20 block functions.
pub fn kat_a1() -> Vec<Check> {
    let zero32 = [0u8; 32];
    let zero12 = [0u8; 12];
    let mut key_last1 = [0u8; 32];
    key_last1[31] = 1;
    let mut key_ff = [0u8; 32];
    key_ff[1] = 0xff;
    let mut nonce_last2 = [0u8; 12];
    nonce_last2[11] = 2;

    let cases: Vec<(&[u8; 32], u32, &[u8; 12], &str, &str)> = vec![
        (&zero32, 0, &zero12, "A.1 #1 (zero key/nonce, block 0)", A1_KS1),
        (&zero32, 1, &zero12, "A.1 #2 (zero key/nonce, block 1)", A1_KS2),
        (&key_last1, 1, &zero12, "A.1 #3 (key[31]=1, block 1)", A1_KS3),
        (&key_ff, 2, &zero12, "A.1 #4 (key[1]=0xff, block 2)", A1_KS4),
        (&zero32, 0, &nonce_last2, "A.1 #5 (nonce[11]=2, block 0)", A1_KS5),
    ];
    cases
        .iter()
        .map(|(key, counter, nonce, name, want)| {
            let got = chacha20_block(key, *counter, nonce);
            eq_detail(name, &got, &hex_bytes(want))
        })
        .collect()
}

/// Appendix A.2 — three ChaCha20 encryptions.
pub fn kat_a2() -> Vec<Check> {
    let zero32 = [0u8; 32];
    let zero12 = [0u8; 12];
    let mut key_last1 = [0u8; 32];
    key_last1[31] = 1;
    let mut nonce_last2 = [0u8; 12];
    nonce_last2[11] = 2;

    let pt32_zero = [0u8; 32];
    let ietf = hex_bytes(PT_IETF);
    let twas = hex_bytes(PT_TWAS);

    let mut out = Vec::new();
    out.push(eq_detail(
        "A.2 #1 (32 zero bytes, block 0)",
        &encrypt(&zero32, 0, &zero12, &pt32_zero),
        &hex_bytes(A1_KS1)[..32],
    ));
    out.push(eq_detail(
        "A.2 #2 (375-byte IETF text, key[31]=1, nonce[11]=2, block 1)",
        &encrypt(&key_last1, 1, &nonce_last2, &ietf),
        &hex_bytes(A2_CT2),
    ));
    out.push(eq_detail(
        "A.2 #3 (127-byte 'Twas brillig', counter 42)",
        &encrypt(&KEY_1C92, 42, &nonce_last2, &twas),
        &hex_bytes(A2_CT3),
    ));
    out
}

/// Appendix A.3 — eleven Poly1305 MACs.
pub fn kat_a3() -> Vec<Check> {
    let zero32 = [0u8; 32];
    let zero16 = [0u8; 16];
    let s2 = hex16(A3_KEY2_S);
    let ietf = hex_bytes(PT_IETF);
    let twas = hex_bytes(PT_TWAS);

    let mut key2 = [0u8; 32];
    key2[16..].copy_from_slice(&s2); // r = 0, s = 36e5f6…
    let mut key3 = [0u8; 32];
    key3[..16].copy_from_slice(&s2); // r = 36e5f6…, s = 0
    let mut key4 = [0u8; 32];
    key4.copy_from_slice(&KEY_1C92);

    let mut out = Vec::new();
    out.push(eq_detail(
        "A.3 #1 (zero key, 32 zero bytes)",
        &poly::mac(&zero32, &[0u8; 32]),
        &zero16,
    ));
    out.push(eq_detail(
        "A.3 #2 (r = 0: tag equals s regardless of message)",
        &poly::mac(&key2, &ietf),
        &s2,
    ));
    out.push(eq_detail(
        "A.3 #3 (375-byte IETF text, r = 36e5f6…)",
        &poly::mac(&key3, &ietf),
        &hex16(A3_TAG3),
    ));
    out.push(eq_detail(
        "A.3 #4 (127-byte 'Twas brillig', key 1c92…)",
        &poly::mac(&key4, &twas),
        &hex16(A3_TAG4),
    ));
    // #5-#11 use raw (r, s) pairs.
    let le128 = |s: &str| u128::from_le_bytes(hex16(s));
    let rs_cases: Vec<(&str, &str, &str, &str)> = vec![
        (A3_5_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_5_DATA, A3_5_TAG),
        (A3_6_R, A3_6_S, A3_6_DATA, A3_6_TAG),
        (A3_7_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_7_DATA, A3_7_TAG),
        (A3_8_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_8_DATA, A3_8_TAG),
        (A3_9_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_9_DATA, A3_9_TAG),
        (A3_10_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_10_DATA, A3_10_TAG),
        (A3_11_R, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", A3_11_DATA, A3_11_TAG),
    ];
    let notes = [
        "#5 (130-bit partial-reduction edge)",
        "#6 (acc + s overflows mod 2^128)",
        "#7 (all-ones data limb + carry)",
        "#8 (polynomial part exactly 2^130-5 -> tag 0)",
        "#9 (polynomial part exactly 2^130-6)",
        "#10 (131-bit 5H+L intermediate)",
        "#11 (131-bit 5H+L final)",
    ];
    for (i, (r, s, data, tag)) in rs_cases.iter().enumerate() {
        let got = poly::mac_rs(le128(r), le128(s), &hex_bytes(data));
        let name = format!("A.3 {}", notes[i]);
        out.push(eq_detail(&name, &got, &hex16(tag)));
    }
    out
}

/// Appendix A.4 — three Poly1305 key generations.
pub fn kat_a4() -> Vec<Check> {
    let zero32 = [0u8; 32];
    let zero12 = [0u8; 12];
    let mut key_last1 = [0u8; 32];
    key_last1[31] = 1;
    let mut nonce_last2 = [0u8; 12];
    nonce_last2[11] = 2;

    vec![
        eq_detail(
            "A.4 #1 (zero key/nonce)",
            &poly::key_gen(&zero32, &zero12),
            &hex_bytes(A4_OTK1),
        ),
        eq_detail(
            "A.4 #2 (key[31]=1, nonce[11]=2)",
            &poly::key_gen(&key_last1, &nonce_last2),
            &hex_bytes(A4_OTK2),
        ),
        eq_detail(
            "A.4 #3 (key 1c92…, nonce[11]=2)",
            &poly::key_gen(&KEY_1C92, &nonce_last2),
            &hex_bytes(A4_OTK3),
        ),
    ]
}

/// §2.8.2 AEAD keystream KAT (the published blocks 1-2).
pub fn kat_aead_keystream() -> Check {
    let const_part: [u8; 4] = [0x07, 0, 0, 0];
    let iv: [u8; 8] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let ks = crate::chacha::keystream(&KEY_80_9F, 1, &aead::make_nonce(&const_part, &iv), 114);
    eq_detail("2.8.2 AEAD keystream (114 bytes)", &ks, &hex_bytes(KEYSTREAM_AEAD))
}

/// Appendix A.5 — full AEAD decryption: the tag must validate and the
/// plaintext must be recovered byte-exact; the published one-time key
/// and Poly1305 buffer must also be reproduced.
pub fn kat_a5() -> (Check, Check, Check, Check) {
    let const_part = [0u8; 4];
    let iv = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let aad = hex_bytes("f3 33 88 86 00 00 00 00 00 00 4e 91");
    let ct = hex_bytes(A5_CT);
    let tag = hex16("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38");
    let want_pt = hex_bytes(A5_PT);

    let k = aead::otk(&KEY_1C92, &const_part, &iv);
    let c_otk = eq_detail("A.5 one-time key", &k, &hex_bytes(A5_OTK));

    let buf = aead::mac_buffer(&aad, &ct);
    let c_buf = eq_detail(
        "A.5 Poly1305 input buffer (304 bytes)",
        &buf,
        &hex_bytes(A5_BUFFER),
    );

    match aead::decrypt(&KEY_1C92, &const_part, &iv, &aad, &ct, tag) {
        Some(pt) => {
            let c_tag = Check::pass("A.5 tag validates", "tag accepted by constant-time compare");
            let c_pt = eq_detail("A.5 recovered plaintext (265 bytes)", &pt, &want_pt);
            (c_otk, c_buf, c_tag, c_pt)
        }
        None => {
            (
                c_otk,
                c_buf,
                Check::fail("A.5 tag validates", "tag REJECTED (should validate)"),
                Check::fail("A.5 recovered plaintext", "no plaintext (tag rejected)"),
            )
        }
    }
}

/// Run the entire battery. Returns one Check per vector part.
pub fn run_all() -> Vec<Check> {
    let mut out = Vec::new();
    out.push(kat_quarter_round());
    out.push(kat_quarter_round_state());
    out.push(kat_block_function());
    let (ks, ct) = kat_sunscreen();
    out.push(ks);
    out.push(ct);
    out.extend(kat_poly1305());
    out.push(kat_poly1305_keygen());
    let (e1, e2, e3, e4, e5) = kat_aead();
    out.push(e1);
    out.push(e2);
    out.push(e3);
    out.push(e4);
    out.push(e5);
    out.push(kat_aead_keystream());
    out.extend(kat_a1());
    out.extend(kat_a2());
    out.extend(kat_a3());
    out.extend(kat_a4());
    let (a1, a2, a3, a4) = kat_a5();
    out.push(a1);
    out.push(a2);
    out.push(a3);
    out.push(a4);
    out
}

/// Number of checks in the full battery (stable; KAT'd in tests).
pub fn check_count() -> usize {
    run_all().len()
}
