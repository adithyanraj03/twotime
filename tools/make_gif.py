#!/usr/bin/env python3
"""Twotime — GIF artifact generator (deterministic).

Rasterizes the six committed SVG frames (assets/frames.svg — the two-time
pad attack: setup, C1, C2, cancellation, exposure, recovery) into:

  assets/anim.gif  — 6-frame animation, 0.9 s per frame, infinite loop
  assets/sheet.gif — static 3x2 contact sheet (0.4 scale, same layout)

The frame content (every byte shown, every caption) is parsed verbatim from
the committed SVG, so the GIF is a pixel-faithful raster of
assets/frames.svg. No timestamps, no randomness: the output bytes are a pure
function of assets/frames.svg and the palette below. Re-run any time; the
hashes must match.
"""

import html
import os
import re

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")
FRAMES = os.path.join(ASSETS, "frames.svg")

# House palette (src/svg.rs).
PAPER = (0xF7, 0xF6, 0xF1)
INK = (0x25, 0x25, 0x24)
MUTED = (0x67, 0x66, 0x62)
HAIR = (0xDC, 0xDA, 0xD1)
GREEN = (0x22, 0xAC, 0x80)
INDIGO = (0x5B, 0x51, 0xC7)
BRICK = (0xA7, 0x42, 0x21)
ORANGE = (0xE8, 0x83, 0x3A)
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)

PALETTE_COLORS = [PAPER, INK, MUTED, HAIR, GREEN, INDIGO, ORANGE, BRICK, BLACK, WHITE]
FILLS = {
    "#F7F6F1": PAPER,
    "#252524": INK,
    "#676662": MUTED,
    "#DCDAD1": HAIR,
    "#22AC80": GREEN,
    "#5B51C7": INDIGO,
    "#A74221": BRICK,
    "#E8833A": ORANGE,
}

W, H = 760, 320


def fonts():
    base = r"C:\Windows\Fonts"
    reg = os.path.join(base, "cour.ttf")
    bold = os.path.join(base, "courbd.ttf")
    cache = {}

    def f(size, b=False):
        key = (int(size), b)
        if key not in cache:
            cache[key] = ImageFont.truetype(bold if b else reg, int(size))
        return cache[key]

    return f


def to_palette(img):
    pal = Image.new("P", (1, 1), 0)
    flat = [c for col in PALETTE_COLORS for c in col]
    flat += [0] * (768 - len(flat))
    pal.putpalette(flat)
    return img.convert("P", palette=pal, dither=Image.Dither.NONE)


def cells(svg_text):
    starts = [m.end() for m in re.finditer(r'<g transform="translate\([\d.]+,[\d.]+\)">', svg_text)]
    out = [svg_text[starts[i]:starts[i + 1]] for i in range(len(starts) - 1)]
    out.append(svg_text[starts[-1]:])
    return [ch[:ch.index("</g>")] if "</g>" in ch else ch for ch in out]


def parse_cell(ch):
    """One frame: the hairline rule and every caption row."""
    lm = re.search(r'<line x1="([\d.]+)" y1="([\d.]+)" x2="([\d.]+)" y2="([\d.]+)"', ch)
    rule = (float(lm.group(1)), float(lm.group(2)), float(lm.group(3)), float(lm.group(4)))
    texts = []
    for x, y, size, fill, bold, content in re.findall(
        r'<text x="([\d.]+)" y="([\d.]+)"[^>]*font-size="([\d.]+)"[^>]*fill="(#[0-9A-Fa-f]{6})"[^>]*(font-weight="bold")?[^>]*>([^<]*)',
        ch,
    ):
        texts.append((float(x), float(y), float(size), FILLS[fill], bold is not None, html.unescape(content)))
    return rule, texts


def render_frame(cell, f):
    rule, texts = parse_cell(cell)
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    d.line([(rule[0], rule[1]), (rule[2], rule[3])], fill=HAIR, width=1)
    for x, y, size, color, bold, s in texts:
        d.text((x, y - 0.8 * size), s, font=f(size, bold), fill=color)
    return img


def make_anim(path, frames):
    frames[0].save(
        path,
        save_all=True,
        append_images=frames[1:],
        duration=900,
        loop=0,
        optimize=False,
    )


def make_sheet(path, frames, title):
    scale = 0.4
    cw, ch = int(W * scale), int(H * scale)  # 304 x 128
    gap, margin, title_h = 10, 12, 26
    cols, rows = 3, 2
    w = margin * 2 + gap * (cols - 1) + cols * cw
    h = title_h + margin + gap * (rows - 1) + rows * ch
    img = Image.new("RGB", (w, h), PAPER)
    d = ImageDraw.Draw(img)
    f = fonts()
    d.text((12, 8), title, font=f(14, True), fill=INK)
    for i, fr in enumerate(frames):
        r, col = divmod(i, cols)
        x = margin + gap + col * (cw + gap)
        y = title_h + margin + gap + r * (ch + gap)
        small = fr.resize((cw, ch), Image.Resampling.LANCZOS)
        img.paste(small, (x, y))
        d.rectangle([x, y, x + cw - 1, y + ch - 1], outline=HAIR)
    to_palette(img).save(path, optimize=False)


def main():
    s = open(FRAMES, encoding="utf-8").read()
    chs = cells(s)
    assert len(chs) == 6, "expected 6 committed frames, got %d" % len(chs)
    title_m = re.search(r'<text[^>]*>([^<]*contact sheet[^<]*)</text>', s)
    title = html.unescape(title_m.group(1)) if title_m else "two-time pad attack — contact sheet (6 frames)"
    f = fonts()
    frames = [to_palette(render_frame(c, f)) for c in chs]
    os.makedirs(ASSETS, exist_ok=True)
    anim = os.path.join(ASSETS, "anim.gif")
    sheet = os.path.join(ASSETS, "sheet.gif")
    make_anim(anim, frames)
    make_sheet(sheet, frames, title)
    import hashlib

    for p in (anim, sheet):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        print("wrote %s (%d bytes) sha256 %s" % (os.path.basename(p), os.path.getsize(p), h))


if __name__ == "__main__":
    main()
