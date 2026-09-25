//! twotime — ChaCha20-Poly1305 AEAD (RFC 8439) from scratch, std-only Rust:
//! the full RFC stack, the two-time pad failure, byte-exact.

pub mod aead;
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
