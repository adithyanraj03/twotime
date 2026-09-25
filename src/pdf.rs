//! Hand-rolled, deterministic PDF 1.4 writer (no dependencies).
//!
//! * Base-14 fonts only (Helvetica, Helvetica-Bold, Courier) — no font
//!   embedding, no xref streams, no object streams.
//! * Fixed `/ID` and fixed `CreationDate`/`ModDate` (constants, **no
//!   wall clock**), so the byte stream of a given document is
//!   reproducible run after run.
//! * ASCII-only text: `(`, `)`, `\` are escaped; any non-ASCII character
//!   is replaced with `?`.
//!
//! The test suite re-parses the xref table and checks every object
//! offset, and freezes the SHA-256 of the canonical dossier.

/// Page geometry (Letter, points).
const PAGE_W: f64 = 612.0;
const PAGE_H: f64 = 792.0;
const MARGIN: f64 = 72.0;
const BODY_PT: f64 = 9.0; // Courier 9pt
const BODY_LEADING: f64 = 12.5;
const TITLE_PT: f64 = 14.0;
const TITLE_LEADING: f64 = 20.0;
const CHARS_PER_LINE: usize = 86; // (612 - 2*72) / (0.6 * 9)
const LINES_PER_PAGE: usize = 50; // body lines after the title block

/// Escape a string for a PDF literal string (ASCII-only).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 128 => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

struct StyledLine {
    text: String,
    bold: bool,
}

/// Wrap `body` into `StyledLine`s; the first line becomes the title.
fn layout(title: &str, body: &str) -> Vec<StyledLine> {
    let mut lines: Vec<StyledLine> = Vec::new();
    lines.push(StyledLine {
        text: title.to_string(),
        bold: true,
    });
    for raw in body.lines() {
        let text = raw.replace('\t', "    ");
        if text.len() <= CHARS_PER_LINE {
            lines.push(StyledLine {
                text: text.clone(),
                bold: false,
            });
        } else {
            // Hard wrap at CHARS_PER_LINE (report lines are ASCII).
            let mut start = 0;
            while start < text.len() {
                let end = (start + CHARS_PER_LINE).min(text.len());
                lines.push(StyledLine {
                    text: text[start..end].to_string(),
                    bold: false,
                });
                start = end;
            }
        }
    }
    lines
}

/// Render `title` + `body` (plain text, '\n'-separated) into a PDF 1.4
/// byte stream.
pub fn render(title: &str, body: &str) -> Vec<u8> {
    let lines = layout(title, body);

    // Split lines into pages: page 1 holds the title + LINES_PER_PAGE body
    // lines; subsequent pages hold LINES_PER_PAGE + a little more (no
    // title overhead). Keep it simple: every page holds LINES_PER_PAGE
    // lines, the title consumes one slot on page 1.
    let mut pages: Vec<Vec<&StyledLine>> = Vec::new();
    let mut cur: Vec<&StyledLine> = Vec::new();
    for l in &lines {
        if cur.len() == LINES_PER_PAGE {
            pages.push(std::mem::take(&mut cur));
        }
        cur.push(l);
    }
    if !cur.is_empty() || pages.is_empty() {
        pages.push(cur);
    }
    let npages = pages.len();

    // Object numbering:
    //   1            catalog
    //   2            pages
    //   3 + 2*i      page i      (i = 0..npages)
    //   4 + 2*i      content i   (i = 0..npages)
    //   3 + 2*P      Helvetica
    //   4 + 2*P      Helvetica-Bold
    //   5 + 2*P      Courier
    //   6 + 2*P      Info
    let font_helv = 3 + 2 * npages;
    let font_bold = font_helv + 1;
    let font_cour = font_helv + 2;
    let info_obj = font_helv + 3;
    let size = info_obj + 1;

    let mut body_bytes: Vec<u8> = Vec::new();
    // Indexed by OBJECT NUMBER (not write order): the objects are emitted
    // out of numerical order (page trees first), and the xref table must
    // map each object number to its true byte offset.
    let mut offsets: Vec<usize> = vec![0usize; size];

    fn ext(v: &mut Vec<u8>, s: String) {
        v.extend_from_slice(s.as_bytes());
    }
    fn extb(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(s);
    }
    fn push_obj_start(bytes: &mut Vec<u8>, offsets: &mut Vec<usize>, n: usize) {
        offsets[n] = bytes.len();
        ext(bytes, format!("{n} 0 obj\n"));
    }

    // Assemble the header first (offsets are measured from byte 0).
    extb(&mut body_bytes, b"%PDF-1.4\n");
    // A binary comment line (PDF convention; also keeps naive text tools
    // from choking). Four bytes >= 0x80.
    extb(&mut body_bytes, b"%\xe2\xe3\xcf\xd3\n");

    for i in 0..npages {
        let page_obj = 3 + 2 * i;
        let cont_obj = 4 + 2 * i;
        // Page object
        push_obj_start(&mut body_bytes, &mut offsets, page_obj);
        ext(
            &mut body_bytes,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] /Resources << /Font << /F1 {font_helv} 0 R /F2 {font_bold} 0 R /F3 {font_cour} 0 R >> >> /Contents {cont_obj} 0 R >>\nendobj\n"
            ),
        );
    }

    // Content streams
    for (i, page) in pages.iter().enumerate() {
        let mut stream = String::new();
        stream.push_str("BT\n");
        let mut y = PAGE_H - MARGIN;
        for line in page.iter() {
            if line.bold {
                stream.push_str(&format!("/F2 {TITLE_PT:.1} Tf\n{MARGIN:.1} {y:.1} Td\n({}) Tj\n", esc(&line.text)));
                y -= TITLE_LEADING;
            } else {
                stream.push_str(&format!("/F3 {BODY_PT:.1} Tf\n{MARGIN:.1} {y:.1} Td\n({}) Tj\n", esc(&line.text)));
                y -= BODY_LEADING;
            }
        }
        stream.push_str("ET\n");
        let stream_id = 4 + 2 * i;
        push_obj_start(&mut body_bytes, &mut offsets, stream_id);
        let len = stream.len();
        ext(&mut body_bytes, format!("<< /Length {len} >>\nstream\n"));
        extb(&mut body_bytes, stream.as_bytes());
        extb(&mut body_bytes, b"endstream\nendobj\n");
    }

    // Fonts
    push_obj_start(&mut body_bytes, &mut offsets, font_helv);
    extb(&mut body_bytes, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n");
    push_obj_start(&mut body_bytes, &mut offsets, font_bold);
    extb(&mut body_bytes, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n");
    push_obj_start(&mut body_bytes, &mut offsets, font_cour);
    extb(&mut body_bytes, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n");

    // Info (fixed dates: determinism policy)
    push_obj_start(&mut body_bytes, &mut offsets, info_obj);
    ext(
        &mut body_bytes,
        format!(
            "<< /Title ({}) /Author (Adithya N Raj) /Creator (twotime {}) /Producer (twotime pdf module, Rust std-only) /CreationDate (D:20260101000000+00'00') /ModDate (D:20260101000000+00'00') >>\nendobj\n",
            esc(&format!("Twotime Verification Dossier v{}", crate::VERSION)),
            crate::VERSION
        ),
    );

    // Pages + catalog
    push_obj_start(&mut body_bytes, &mut offsets, 1);
    extb(&mut body_bytes, b"<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    push_obj_start(&mut body_bytes, &mut offsets, 2);
    let kids: Vec<String> = (0..npages).map(|i| format!("{} 0 R", 3 + 2 * i)).collect();
    ext(&mut body_bytes, format!("<< /Type /Pages /Kids [{}] /Count {npages} >>\nendobj\n", kids.join(" ")));

    // xref
    let xref_offset = body_bytes.len();
    extb(&mut body_bytes, b"xref\n");
    ext(&mut body_bytes, format!("0 {size}\n"));
    extb(&mut body_bytes, b"0000000000 65535 f \n");
    for obj in 1..size {
        ext(&mut body_bytes, format!("{:010} 00000 n \n", offsets[obj]));
    }
    extb(&mut body_bytes, b"trailer\n");
    // Fixed /ID (ASCII "TWOTIME-DOSSIER-1.0.0" and "...-1.0.0-2" hex) —
    // deterministic identity, no randomness.
    extb(&mut body_bytes, b"<< /Size ");
    ext(&mut body_bytes, format!("{size} "));
    extb(&mut body_bytes, b"/Root 1 0 R /Info ");
    ext(
        &mut body_bytes,
        format!("{info_obj} 0 R /ID [<54574f54494d452d444f53534945522d312e302e30> <54574f54494d452d444f53534945522d312e302e302d32>] >>\n"),
    );
    extb(&mut body_bytes, b"startxref\n");
    ext(&mut body_bytes, format!("{xref_offset}\n"));
    extb(&mut body_bytes, b"%%EOF\n");

    body_bytes
}

/// Render the canonical verification dossier from the report text.
pub fn render_dossier(report: &str) -> Vec<u8> {
    render(
        &format!("TWOTIME VERIFICATION DOSSIER v{}", crate::VERSION),
        report,
    )
}
