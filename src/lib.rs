//! twotime — ChaCha20-Poly1305 AEAD (RFC 8439), Rust std-only.
//!
//! A research crate built around the *two-time pad*: the one
//! construction failure that reduces a stream cipher to a
//! codebook. The crate implements the full RFC 8439 stack
//! (ChaCha20, Poly1305, AEAD) from scratch with zero dependencies,
//! verifies every published test vector in the RFC (KAT battery),
//! and then studies the failure mode the name promises:
//!
//! * the **two-time pad** attack, reproduced byte-exact
//!   (`C1 ⊕ C2 = P1 ⊕ P2`);
//! * a **forgery-rejection battery** for the AEAD tag;
//! * **avalanche** measurements contrasting the stream cipher's
//!   linearity (1 bit) with the MAC's diffusion (~64 of 128 bits);
//! * a **determinism attestation**: the report and PDF dossier are
//!   generated twice and must be byte-identical.
//!
//! Everything is a pure function of embedded constants: no clock, no
//! environment, no RNG.

pub mod aead;
pub mod attest;
pub mod avalanche;
pub mod battery;
pub mod chacha;
pub mod crypto;
pub mod forgery;
pub mod kats;
pub mod pdf;
pub mod poly;
pub mod svg;
pub mod twotime;

/// Crate version (appears in artifacts; no timestamps anywhere).
pub const VERSION: &str = "1.0.0";
