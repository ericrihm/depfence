#!/usr/bin/env python3
"""
Generate a demo GIF for depfence README.
Design principle: each frame communicates ONE idea. Hold long enough to read.
6 frames, ~10s total. Every frame earns its screen time.
"""

import os

from PIL import Image, ImageDraw, ImageFont

# ── palette (Dracula) ──────────────────────────────────────────────────────
BG       = (25,  26,  32)
FG       = (248, 248, 242)
DIM      = (98,  114, 164)
GREEN    = (80,  250, 123)
CYAN     = (139, 233, 253)
YELLOW   = (241, 250, 140)
RED      = (255,  85,  85)
MAGENTA  = (255, 121, 198)
BLUE_LT  = (98,  114, 164)
ORANGE   = (255, 184, 108)
ACCENT   = (189, 147, 249)  # purple for branding

FONT_PATH = "/System/Library/Fonts/SFNSMono.ttf"
FONT_SM = 13
FONT_MD = 16
FONT_LG = 28
FONT_XL = 36
W, H = 900, 480
PAD_X, PAD_Y = 24, 20


def load_font(size):
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except Exception:
        return ImageFont.load_default()


def char_w(font):
    bbox = font.getbbox("M")
    return bbox[2] - bbox[0]


def draw_text_segments(draw, x, y, segments, font):
    cw = char_w(font)
    for text, color in segments:
        draw.text((x, y), text, font=font, fill=color)
        x += len(text) * cw
    return x


def new_frame():
    return Image.new("RGB", (W, H), BG)


def sev_color(sev):
    return {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": MAGENTA, "LOW": BLUE_LT}[sev]


# ── Frame 1: Title & brand (1.2s) ──────────────────────────────────────────
# Viewer learns: what is this tool?
def frame_title():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font_xl = load_font(FONT_XL)
    font_md = load_font(FONT_MD)
    font_sm = load_font(FONT_SM)

    # centered title
    title = "depfence"
    tw = char_w(font_xl) * len(title)
    draw.text(((W - tw) // 2, 120), title, font=font_xl, fill=ACCENT)

    # tagline
    tag = "AI-aware supply chain security scanner"
    ttw = char_w(font_md) * len(tag)
    draw.text(((W - ttw) // 2, 180), tag, font=font_md, fill=DIM)

    # stats bar
    stats = "56 scanners  •  14 ecosystems  •  zero code execution"
    stw = char_w(font_sm) * len(stats)
    draw.text(((W - stw) // 2, 230), stats, font=font_sm, fill=CYAN)

    # badge line
    badges = "prompt injection  |  slopsquatting  |  MCP audit  |  AI model safety"
    bw = char_w(font_sm) * len(badges)
    draw.text(((W - bw) // 2, 270), badges, font=font_sm, fill=DIM)

    return img


# ── Frame 2: Command (0.8s) ────────────────────────────────────────────────
# Viewer learns: how do I use it?
def frame_command():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font = load_font(FONT_MD)
    ch = font.getbbox("M")[3] - font.getbbox("M")[1] + 4

    y = PAD_Y + ch
    segs = [("  ", FG), ("$ ", GREEN), ("depfence scan .", FG)]
    draw_text_segments(draw, PAD_X, y, segs, font)

    return img


# ── Frame 3: Scanning complete (1.0s) ─────────────────────────────────────
# Viewer learns: it scans many things, fast
def frame_scan_complete():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font = load_font(FONT_SM)
    cw = char_w(font)
    ch = font.getbbox("M")[3] - font.getbbox("M")[1] + 4

    y = PAD_Y
    draw_text_segments(draw, PAD_X, y, [("  ", FG), ("$ ", GREEN), ("depfence scan .", FG)], font)
    y += ch * 2

    draw_text_segments(draw, PAD_X, y, [("  ", FG), ("✓ ", GREEN), ("Scan complete", FG)], font)
    y += ch

    scanners = [
        ("osv_advisory",      "47 pkgs"),
        ("prompt_injection",  "18 files"),
        ("slopsquat",         "47 names"),
        ("malware_detect",    "47 pkgs"),
        ("mcp_scanner",       "3 configs"),
        ("gha_workflow",      "4 workflows"),
        ("model_format",      "2 models"),
        ("protestware",       "47 pkgs"),
    ]
    y += ch // 2
    for name, detail in scanners:
        segs = [("    ✓ ", GREEN), (f"{name:<22}", DIM), (detail, DIM)]
        draw_text_segments(draw, PAD_X, y, segs, font)
        y += ch

    y += ch
    segs = [("  ", FG), ("56 scanners", CYAN), (" completed in ", DIM), ("1.2s", GREEN)]
    draw_text_segments(draw, PAD_X, y, segs, font)

    return img


# ── Frame 4: Results table (3.5s) ─────────────────────────────────────────
# THE MONEY SHOT — viewer sees real findings with severity colors
def frame_results():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font = load_font(FONT_SM)
    cw = char_w(font)
    ch = font.getbbox("M")[3] - font.getbbox("M")[1] + 4

    IND = "  "
    hbar = "━"
    vbar = "│"
    tl, tc, tr = "┌", "┬", "┐"
    ml, mc, mr = "├", "┼", "┤"
    bl, bc, br = "└", "┴", "┘"

    ws = [10, 18, 22, 34]

    def hline(left, mid, right):
        parts = [IND, left]
        for i, w in enumerate(ws):
            parts.append(hbar * (w + 2))
            parts.append(mid if i < len(ws) - 1 else right)
        return "".join(parts)

    def trow(cells, colors):
        parts = [(IND + vbar + " ", DIM)]
        for i, (cell, col) in enumerate(zip(cells, colors)):
            w = ws[i]
            txt = cell[:w].ljust(w)
            parts.append((txt, col))
            sep = " " + vbar + " " if i < len(ws) - 1 else " " + vbar
            parts.append((sep, DIM))
        return parts

    findings = [
        ("CRITICAL", "prompt_injection", "git:myproject",         "Stealth override in commit"),
        ("CRITICAL", "malware",          "pypi:event-stream",     "Cryptocurrency miner payload"),
        ("HIGH",     "slopsquat",        "npm:reqeusts",          "LLM-hallucinated package name"),
        ("HIGH",     "cve",              "lodash 4.17.20",        "CVE-2021-23337: cmd inject"),
        ("MEDIUM",   "mcp_tool",         ".cursor/mcp.json",      "Tool shadowing: filesystem"),
        ("LOW",      "outdated",         "axios 0.21.0",          "18 months behind latest"),
    ]

    y = PAD_Y
    segs = [("  ", FG), ("depfence scan results", CYAN), (" — ", DIM), ("~/dev/myproject", DIM)]
    draw_text_segments(draw, PAD_X, y, segs, font)
    y += ch + ch // 2

    # top border
    draw.text((PAD_X, y), hline(tl, tc, tr), font=font, fill=DIM)
    y += ch

    # header
    draw_text_segments(draw, PAD_X, y,
        trow(["Severity", "Type", "Package", "Finding"], [CYAN]*4), font)
    y += ch

    # header separator
    draw.text((PAD_X, y), hline(ml, mc, mr), font=font, fill=DIM)
    y += ch

    for i, (sev, typ, pkg, title) in enumerate(findings):
        sc = sev_color(sev)
        draw_text_segments(draw, PAD_X, y,
            trow([sev, typ, pkg, title], [sc, DIM, ORANGE, FG]), font)
        y += ch
        if i < len(findings) - 1:
            draw.text((PAD_X, y), hline(ml, mc, mr), font=font, fill=(40, 42, 54))
            y += ch

    # bottom border
    draw.text((PAD_X, y), hline(bl, bc, br), font=font, fill=DIM)

    return img


# ── Frame 5: Summary + severity bar (2.0s) ────────────────────────────────
# Viewer learns: scope of findings, visual severity breakdown
def frame_summary():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font = load_font(FONT_MD)
    font_sm = load_font(FONT_SM)
    ch = font.getbbox("M")[3] - font.getbbox("M")[1] + 6

    y = PAD_Y + ch

    draw_text_segments(draw, PAD_X, y,
        [("  ", FG), ("Scan complete: ", DIM), ("6 findings", FG), (" in ", DIM), ("47 packages", FG)], font)
    y += ch * 2

    # severity breakdown with colored blocks
    bar_data = [
        ("CRITICAL", 2, RED),
        ("HIGH",     2, YELLOW),
        ("MEDIUM",   1, MAGENTA),
        ("LOW",      1, BLUE_LT),
    ]
    bar_x = PAD_X + 24
    bar_w_total = W - 2 * bar_x
    total = sum(c for _, c, _ in bar_data)

    for label, count, color in bar_data:
        seg_w = int(bar_w_total * count / total)
        draw.rectangle([bar_x, y, bar_x + seg_w - 2, y + 28], fill=color)
        # label inside the bar
        lbl = f"{count}"
        lw = char_w(font) * len(lbl)
        if seg_w > lw + 8:
            draw.text((bar_x + (seg_w - lw) // 2, y + 4), lbl, font=font, fill=BG)
        bar_x += seg_w

    y += 40

    # legend
    lx = PAD_X + 24
    for label, count, color in bar_data:
        segs = [("■ ", color), (f"{count} {label.lower()}  ", color)]
        lx = draw_text_segments(draw, lx, y, segs, font_sm)

    y += ch * 2

    draw_text_segments(draw, PAD_X, y,
        [("  ", FG), ("Fixable: ", DIM), ("4 of 6", GREEN), (" — run ", DIM),
         ("depfence scan --fix", CYAN)], font_sm)

    return img


# ── Frame 6: Install CTA (1.5s) ───────────────────────────────────────────
# Viewer learns: how to get it
def frame_cta():
    img = new_frame()
    draw = ImageDraw.Draw(img)
    font_md = load_font(FONT_MD)
    font_lg = load_font(FONT_LG)
    font_sm = load_font(FONT_SM)

    y = 140
    cmd = "pip install depfence"
    cw_lg = char_w(font_lg)
    tw = cw_lg * len(cmd)
    draw.text(((W - tw) // 2, y), cmd, font=font_lg, fill=GREEN)

    y += 60
    sub = "github.com/ericrihm/depfence"
    sw = char_w(font_sm) * len(sub)
    draw.text(((W - sw) // 2, y), sub, font=font_sm, fill=DIM)

    y += 40
    tag = "Catches what CVE scanners miss."
    ttw = char_w(font_sm) * len(tag)
    draw.text(((W - ttw) // 2, y), tag, font=font_sm, fill=ACCENT)

    return img


# ── Assembly ───────────────────────────────────────────────────────────────

def build_frames():
    return [
        (frame_title(),         120),   # 1.2s — what is this?
        (frame_command(),        80),   # 0.8s — how do I use it?
        (frame_scan_complete(), 100),   # 1.0s — it scans many things
        (frame_results(),       350),   # 3.5s — THE MONEY SHOT
        (frame_summary(),       200),   # 2.0s — severity breakdown
        (frame_cta(),           150),   # 1.5s — how to get it
    ]   # total: 10.0s, 6 frames


def save_gif(frames, path):
    images = []
    durations = []
    for img, delay_cs in frames:
        images.append(img.convert("P", palette=Image.ADAPTIVE, colors=256))
        durations.append(delay_cs * 10)

    images[0].save(
        path,
        save_all=True,
        append_images=images[1:],
        loop=0,
        duration=durations,
        optimize=True,
    )


def main():
    frames = build_frames()
    print(f"Built {len(frames)} frames")

    out = os.path.join(os.path.dirname(__file__), "../docs/demo.gif")
    out = os.path.normpath(out)
    save_gif(frames, out)

    size_kb = os.path.getsize(out) / 1024
    total_s = sum(d for _, d in frames) / 100
    print(f"Saved {out}  ({size_kb:.1f} KB, {total_s:.1f}s, {len(frames)} frames)")
    if size_kb > 300:
        print("WARNING: file exceeds 300KB target")


if __name__ == "__main__":
    main()
