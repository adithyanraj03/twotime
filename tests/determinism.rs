//! Determinism: the report, dossier, attestation and SVGs are pure
//! functions of the embedded RFC vectors. Dual-run attestation must be
//! byte-identical; artifacts must be well-formed.

use twotime::attest;

#[test]
fn attest_is_identical() {
    let a = attest::attest();
    assert!(a.identical, "dual-run must be byte-identical");
    assert_eq!(a.report_sha256_run1, a.report_sha256_run2);
    assert_eq!(a.dossier_sha256_run1, a.dossier_sha256_run2);
}

#[test]
fn attest_report_across_calls() {
    // Two separate attest() calls (hence four report generations) must
    // produce the same digest.
    let a1 = attest::attest();
    let a2 = attest::attest();
    assert_eq!(a1.report_sha256_run1, a2.report_sha256_run1);
    assert_eq!(a1.dossier_sha256_run1, a2.dossier_sha256_run1);
}

#[test]
fn attestation_text_well_formed() {
    let a = attest::attest();
    let text = attest::render_attestation(&a);
    assert!(text.contains("TWOTIME DETERMINISM ATTESTATION"));
    assert!(text.contains("BYTE-IDENTICAL (dual-run diff empty)"));
    assert!(text.contains(&a.report_sha256_run1));
    assert!(text.contains(&a.dossier_sha256_run1));
    assert!(text.ends_with('\n'));
}

#[test]
fn report_well_formed() {
    let report = twotime::battery::render_report();
    assert!(report.contains("TWOTIME VERIFICATION REPORT"));
    assert!(report.contains("RFC 8439 KAT BATTERY"));
    assert!(report.contains("KAT total: 43 checks, 43 pass, 0 fail"));
    assert!(report.contains("TWO-TIME PAD ATTACK"));
    assert!(report.contains("FORGERY-REJECTION BATTERY"));
    assert!(report.contains("(c) 2026 Adithya N Raj"));
}

#[test]
fn dossier_is_valid_pdf_skeleton() {
    let report = twotime::battery::render_report();
    let pdf = twotime::pdf::render_dossier(&report);
    let head = String::from_utf8_lossy(&pdf[..1024.min(pdf.len())]);
    assert!(head.starts_with("%PDF-1."));
    let tail = String::from_utf8_lossy(&pdf[pdf.len() - 64..]);
    assert!(tail.contains("%%EOF"));
    assert!(pdf.windows(4).any(|w| w == b"xref"));
    assert!(pdf.windows(7).any(|w| w == b"trailer"));
    assert!(pdf.windows(9).any(|w| w == b"startxref"));
}

#[test]
fn svg_anim_well_formed() {
    let svg = twotime::svg::render_anim(6);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("<animate"));
    assert!(svg.contains("calcMode=\"discrete\""));
    assert!(svg.contains("repeatCount=\"indefinite\""));
    // Six frames -> six discrete keyTimes groups.
    let frames = svg.matches("<g opacity=\"0\">").count();
    assert_eq!(frames, 6);
}

#[test]
fn svg_contact_sheet_well_formed() {
    let svg = twotime::svg::render_contact_sheet(3);
    assert!(svg.contains("<svg"));
    assert!(svg.contains("<g transform="));
}

#[test]
fn version_is_pinned() {
    assert_eq!(twotime::VERSION, "1.0.0");
    let a = attest::attest();
    assert_eq!(a.version, "twotime 1.0.0");
}
