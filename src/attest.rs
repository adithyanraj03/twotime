//! Dual-run byte-identity attestation.
//!
//! The full battery report and the PDF dossier are generated **twice in
//! the same process** and compared byte-for-byte via SHA-256. No wall
//! clock and no environment input feed either artifact, so equality is
//! the expected outcome; the attestation records it with the version
//! string (never with timestamps).

use crate::crypto::{sha256, to_hex};

/// The outcome of a dual-run attestation.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub version: String,
    pub report_sha256_run1: String,
    pub report_sha256_run2: String,
    pub dossier_sha256_run1: String,
    pub dossier_sha256_run2: String,
    /// True when both artifacts are byte-identical across the two runs.
    pub identical: bool,
}

/// Generate the battery report and the dossier twice, hash each run.
pub fn attest() -> Attestation {
    let r1 = crate::battery::render_report();
    let d1 = crate::pdf::render_dossier(&r1);
    let r2 = crate::battery::render_report();
    let d2 = crate::pdf::render_dossier(&r2);

    let h_r1 = to_hex(&sha256(r1.as_bytes()));
    let h_r2 = to_hex(&sha256(r2.as_bytes()));
    let h_d1 = to_hex(&sha256(&d1));
    let h_d2 = to_hex(&sha256(&d2));

    Attestation {
        version: format!("twotime {}", crate::VERSION),
        report_sha256_run1: h_r1,
        report_sha256_run2: h_r2,
        dossier_sha256_run1: h_d1,
        dossier_sha256_run2: h_d2,
        identical: r1 == r2 && d1 == d2,
    }
}

/// Render the attestation record (deterministic text).
pub fn render_attestation(a: &Attestation) -> String {
    let mut s = String::new();
    s.push_str(&"=".repeat(80));
    s.push('\n');
    s.push_str("TWOTIME DETERMINISM ATTESTATION\n");
    s.push_str(&format!("crate   : {}\n", a.version));
    s.push_str("policy  : std-only, zero dependencies; no wall clock, no env input\n");
    s.push_str("method  : battery report + PDF dossier generated twice in-process;\n");
    s.push_str("          SHA-256 digests compared; artifacts are pure functions\n");
    s.push_str("          of the embedded RFC 8439 KAT vectors (no RNG anywhere)\n");
    s.push_str(&format!(
        "run 1   : report.txt sha256 = {}\n",
        a.report_sha256_run1
    ));
    s.push_str(&format!(
        "run 2   : report.txt sha256 = {}\n",
        a.report_sha256_run2
    ));
    s.push_str(&format!(
        "run 1   : dossier.pdf sha256 = {}\n",
        a.dossier_sha256_run1
    ));
    s.push_str(&format!(
        "run 2   : dossier.pdf sha256 = {}\n",
        a.dossier_sha256_run2
    ));
    s.push_str(&format!(
        "verdict : {}\n",
        if a.identical {
            "BYTE-IDENTICAL (dual-run diff empty)"
        } else {
            "MISMATCH (determinism violation)"
        }
    ));
    s.push_str(&"=".repeat(80));
    s.push('\n');
    s
}
