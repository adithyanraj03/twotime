//! twotime — ChaCha20-Poly1305 AEAD (RFC 8439) from scratch, std-only Rust:
//! the full RFC stack, the two-time pad failure, byte-exact.

pub mod chacha;
pub mod crypto;

/// Crate version (appears in artifacts; no timestamps anywhere).
pub const VERSION: &str = "1.0.0";
