//! `twotime` CLI — verification commands.
//!
//! ```text
//! twotime help              this text
//! twotime version           version line
//! twotime demo              short demo (two-time pad, byte-exact)
//! twotime kats              RFC 8439 KAT battery summary
//! twotime battery [PATH]    write the verification report (default: assets/report.txt)
//! twotime dossier [PATH]    write the PDF dossier (default: assets/dossier.pdf)
//! twotime attest [PATH]     write the attestation (default: assets/attestation.txt)
//! twotime svg [DIR]         write anim.svg + frames.svg (default: assets)
//! ```

use std::io::Write;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let out = args.get(1).map(|s| s.as_str());
    let code = match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            0
        }
        "version" | "-V" | "--version" => {
            println!("twotime {}", twotime::VERSION);
            0
        }
        "demo" => demo(),
        "kats" => kats(),
        "battery" => {
            let path = out.unwrap_or("assets/report.txt");
            let report = twotime::battery::render_report();
            write_file(path, report.as_bytes());
            println!("wrote {path} ({} bytes)", report.len());
            0
        }
        "dossier" => {
            let path = out.unwrap_or("assets/dossier.pdf");
            let report = twotime::battery::render_report();
            let pdf = twotime::pdf::render_dossier(&report);
            write_file(path, &pdf);
            println!(
                "wrote {path} ({} bytes, sha256 {})",
                pdf.len(),
                twotime::crypto::to_hex(&twotime::crypto::sha256(&pdf))
            );
            0
        }
        "attest" => {
            let path = out.unwrap_or("assets/attestation.txt");
            let a = twotime::attest::attest();
            let text = twotime::attest::render_attestation(&a);
            write_file(path, text.as_bytes());
            print!("{text}");
            if a.identical {
                0
            } else {
                1
            }
        }
        "svg" => {
            let dir = out.unwrap_or("assets");
            let anim = twotime::svg::render_anim(6);
            let sheet = twotime::svg::render_contact_sheet(3);
            let p1 = format!("{dir}/anim.svg");
            let p2 = format!("{dir}/frames.svg");
            write_file(&p1, anim.as_bytes());
            write_file(&p2, sheet.as_bytes());
            println!("wrote {p1} ({} bytes)", anim.len());
            println!("wrote {p2} ({} bytes)", sheet.len());
            0
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "twotime {} - ChaCha20-Poly1305 AEAD (RFC 8439) and the two-time pad, verified",
        twotime::VERSION
    );
    println!();
    println!("commands:");
    println!("  twotime help              this text");
    println!("  twotime version           version line");
    println!("  twotime demo              short demo (two-time pad, byte-exact)");
    println!("  twotime kats              RFC 8439 KAT battery summary");
    println!("  twotime battery [PATH]    write the verification report (assets/report.txt)");
    println!("  twotime dossier [PATH]    write the PDF dossier (assets/dossier.pdf)");
    println!("  twotime attest [PATH]     write the attestation (assets/attestation.txt)");
    println!("  twotime svg [DIR]         write anim.svg + frames.svg (assets)");
}

fn write_file(path: &str, bytes: &[u8]) {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let mut f = std::fs::File::create(path).expect("create output file");
    f.write_all(bytes).expect("write output file");
}

fn demo() -> i32 {
    let tt = twotime::twotime::canonical();
    println!("two-time pad — one (key, nonce), two messages");
    println!("  P1[0..24] = {}", twotime::crypto::to_hex(&tt.p1[..24.min(tt.p1.len())]));
    println!("  P2[0..24] = {}", twotime::crypto::to_hex(&tt.p2[..24.min(tt.p2.len())]));
    println!("  C1[0..24] = {}", twotime::crypto::to_hex(&tt.c1[..24.min(tt.c1.len())]));
    println!("  C2[0..24] = {}", twotime::crypto::to_hex(&tt.c2[..24.min(tt.c2.len())]));
    let (cancel_ok, n) = tt.keystream_cancellation();
    println!(
        "  C1 XOR C2 == P1 XOR P2 over {n} bytes: {}",
        if cancel_ok { "byte-exact" } else { "MISMATCH" }
    );
    let recovered = tt.recover_p2_from_p1();
    let rec_ok = recovered == tt.p2[..recovered.len()];
    println!(
        "  P2 recovered = P1 XOR C1 XOR C2: {} ({} bytes)",
        if rec_ok { "byte-exact match" } else { "MISMATCH" },
        recovered.len()
    );
    println!(
        "  P2[0..24]   = {}",
        twotime::crypto::to_hex(&recovered[..24.min(recovered.len())])
    );
    if cancel_ok && rec_ok {
        0
    } else {
        1
    }
}

fn kats() -> i32 {
    let checks = twotime::kats::run_all();
    let mut ok = true;
    for (i, c) in checks.iter().enumerate() {
        if !c.ok {
            ok = false;
        }
        println!(
            "[{:>4}] {:<42} {}",
            if c.ok { "PASS" } else { "FAIL" },
            format!("#{} {}", i + 1, c.name),
            c.detail
        );
    }
    let pass = checks.iter().filter(|c| c.ok).count();
    println!();
    println!(
        "summary: {} checks, {} pass, {} fail  ->  {}",
        checks.len(),
        pass,
        checks.len() - pass,
        if ok { "ALL KATS PASS" } else { "KAT FAILURES" }
    );
    if ok {
        0
    } else {
        1
    }
}
