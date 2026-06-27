#!/usr/bin/env python3
"""
Generate a synthetic demo GIF for depfence.
Uses Pillow to render terminal frames with ANSI-style colors and varied timing.
Output: docs/demo.gif (800x400, ~6-8s, <300KB)
"""

from PIL import Image, ImageDraw, ImageFont
import struct, zlib, os

# ── colour palette (Dracula-ish dark terminal) ──────────────────────────────
BG       = (25,  26,  32)   # near-black
FG       = (248, 248, 242)  # off-white
DIM      = (98,  114, 164)  # muted blue-grey (border chars, dim text)
GREEN    = (80,  250, 123)  # prompt $, scanner ticks
CYAN     = (139, 233, 253)  # header text
YELLOW   = (241, 250, 140)  # HIGH severity / warnings
RED      = (255,  85,  85)  # CRITICAL severity
MAGENTA  = (255, 121, 198)  # MEDIUM severity
BLUE_LT  = (98,  114, 164)  # LOW severity
WHITE    = (248, 248, 242)
ORANGE   = (255, 184, 108)  # package names

FONT_PATH = "/System/Library/Fonts/SFNSMono.ttf"
FONT_SIZE = 12
W, H = 800, 400
PAD_X, PAD_Y = 18, 14

# ── frame data ──────────────────────────────────────────────────────────────
# Each frame is a list of (x_col, y_row, text, color) tuples, plus a delay in ms.
# We work in character cells: col/row are character positions, rendered at font metrics.

def load_font(size=FONT_SIZE):
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except Exception:
        return ImageFont.load_default()

def char_size(font):
    bbox = font.getbbox("M")
    return bbox[2] - bbox[0], bbox[3] - bbox[1] + 2  # w, h

def render_frame(lines, font, cw, ch, delay_ms):
    """
    lines: list of list-of (text, color) segments per line.
    Returns PIL Image.
    """
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    for row, segments in enumerate(lines):
        x = PAD_X
        y = PAD_Y + row * ch
        for text, color in segments:
            draw.text((x, y), text, font=font, fill=color)
            x += len(text) * cw

    return img

# ── frame definitions ────────────────────────────────────────────────────────

def frame_command(font, cw, ch):
    """Frame 1: typing the command."""
    lines = [
        [],
        [("  ", FG), ("ops@studio", GREEN), (":", FG), ("~/dev/myproject", CYAN), ("$ ", FG), ("depfence scan .", WHITE)],
    ]
    return render_frame(lines, font, cw, ch, 500)

def frame_progress(font, cw, ch, tick=0):
    """Frame 2: scanning progress."""
    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    sp = spinners[tick % len(spinners)]
    scanners = [
        ("osv",               True),
        ("github_advisory",   True),
        ("malware_detect",    tick > 2),
        ("prompt_injection",  tick > 4),
        ("protestware",       tick > 6),
    ]
    lines = [
        [],
        [("  ", FG), ("ops@studio", GREEN), (":", FG), ("~/dev/myproject", CYAN), ("$ ", FG), ("depfence scan .", WHITE)],
        [],
        [("  ", FG), (f"{sp} ", GREEN), ("Scanning dependencies...", FG)],
        [],
    ]
    for name, done in scanners:
        if done:
            lines.append([("    ", FG), ("✓ ", GREEN), (f"{name:<22}", DIM), ("done", GREEN)])
        else:
            lines.append([("    ", FG), ("· ", DIM), (f"{name:<22}", DIM), ("waiting", DIM)])
    return render_frame(lines, font, cw, ch, 120)

def _sev_color(sev):
    return {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": MAGENTA, "LOW": BLUE_LT}.get(sev, FG)

def frame_results(font, cw, ch):
    """Frame 3: the money shot — results table.

    At font size 12, cw≈8px. Canvas=800px, PAD_X=18 each side → usable=764px → ~95 chars.
    4 columns: Severity(10) Type(18) Package(24) Title(36) = 88 chars of content
    + borders/padding: 5 vbars × 3 chars = 15 → total ≈ 103. Trim to fit.
    """
    INDENT = "  "  # 2-char left indent for all rows
    hbar  = "━"
    vbar  = "┃"
    tl, tc, tr = "┏", "┳", "┓"
    ml, mc, mr = "┡", "╇", "┩"
    bl, bc, br = "└", "┴", "┘"
    iv, ic     = "│", "┼"

    # widths chosen so total line fits in ~94 chars:
    # 2(indent) + 1(left-vbar) + sum(w+3 for w in ws) - 1 = 2+1 + (10+3)+(18+3)+(24+3)+(34+3) - 1 = 99 ✓
    ws = [10, 18, 24, 34]

    def hline(left, mid, right):
        parts = [INDENT, left]
        for i, w in enumerate(ws):
            parts.append(hbar * (w + 2))
            parts.append(mid if i < len(ws) - 1 else right)
        return "".join(parts)

    def trow(cells, colors):
        # returns a list of (text, color) segments including indent
        parts = [(INDENT + vbar + " ", DIM)]
        for i, (cell, col) in enumerate(zip(cells, colors)):
            w = ws[i]
            txt = cell[:w].ljust(w)
            parts.append((txt, col))
            parts.append((" " + vbar + " ", DIM))
        # strip trailing " " after last vbar to avoid overflow
        last = parts[-1]
        parts[-1] = (last[0].rstrip(), last[1])
        return parts

    findings = [
        ("CRITICAL", "prompt_injection", "git:myproject",            "Stealth approval in commit msg"),
        ("CRITICAL", "malware",          "pypi:event-stream 3.3",    "Cryptocurrency miner payload"),
        ("HIGH",     "cve",              "lodash 4.17.20",           "CVE-2021-23337: cmd injection"),
        ("HIGH",     "cve",              "axios 0.21.0",             "CVE-2021-3749: ReDoS"),
        ("MEDIUM",   "cve",              "requests 2.25.0",          "CVE-2023-32681: header leak"),
        ("LOW",      "outdated",         "debug 4.3.3",              "2 years behind latest release"),
    ]

    header_cells  = ["Severity", "Type", "Package", "Title"]
    header_colors = [CYAN, CYAN, CYAN, CYAN]

    top_line = hline(tl, tc, tr)
    sep_line = hline(ml, mc, mr)
    mid_line = hline(iv, ic, iv)
    bot_line = hline(bl, bc, br)

    lines = [
        [("  depfence scan: ", DIM), ("~/dev/myproject", CYAN)],
        [],
        [(top_line, DIM)],
        trow(header_cells, header_colors),
        [(sep_line, DIM)],
    ]

    for i, (sev, typ, pkg, title) in enumerate(findings):
        sc = _sev_color(sev)
        lines.append(trow([sev, typ, pkg, title], [sc, DIM, ORANGE, FG]))
        if i < len(findings) - 1:
            lines.append([(mid_line, DIM)])

    lines.append([(bot_line, DIM)])

    return render_frame(lines, font, cw, ch, 3000)

def frame_summary(font, cw, ch):
    """Frame 4: summary line."""
    lines = [
        [],
        [("  ", FG), ("ops@studio", GREEN), (":", FG), ("~/dev/myproject", CYAN), ("$ ", FG), ("depfence scan .", WHITE)],
        [],
        [("  ", DIM), ("Packages scanned: ", DIM), ("38", WHITE), ("  ", DIM),
         ("Findings: ", DIM), ("660", WHITE), ("  ", DIM),
         ("Critical: ", DIM), ("45", RED), ("  ", DIM),
         ("High: ", DIM), ("470", YELLOW)],
        [],
        [("  ", FG),
         ("■ ", RED),   ("2 critical  ", RED),
         ("■ ", YELLOW),("2 high  ",     YELLOW),
         ("■ ", MAGENTA),("1 medium  ",  MAGENTA),
         ("■ ", BLUE_LT),("1 low",       BLUE_LT)],
        [],
        [("  ", DIM), ("Run ", DIM), ("depfence scan --fix", CYAN), (" to auto-remediate", DIM)],
    ]
    return render_frame(lines, font, cw, ch, 2000)

def frame_exit(font, cw, ch):
    """Frame 5: clean prompt return."""
    lines = [
        [],
        [("  ", FG), ("ops@studio", GREEN), (":", FG), ("~/dev/myproject", CYAN), ("$ ", FG)],
    ]
    return render_frame(lines, font, cw, ch, 500)

# ── GIF assembly ─────────────────────────────────────────────────────────────

def build_frames(font, cw, ch):
    frames = []

    # Frame 1: command typed (hold 500ms)
    frames.append((frame_command(font, cw, ch), 50))  # 50 * 10ms = 500ms

    # Frame 2: progress — 8 ticks at 120ms each = ~1s
    for tick in range(8):
        frames.append((frame_progress(font, cw, ch, tick), 12))  # 12 * 10ms = 120ms

    # Frame 3: results table hold 3s = 300 * 10ms
    frames.append((frame_results(font, cw, ch), 300))

    # Frame 4: summary hold 2s = 200 * 10ms
    frames.append((frame_summary(font, cw, ch), 200))

    # Frame 5: exit prompt 0.5s = 50 * 10ms
    frames.append((frame_exit(font, cw, ch), 50))

    return frames

def save_gif(frames, path):
    """Save frames as animated GIF. frames = list of (PIL.Image, delay_centiseconds)."""
    images = []
    durations = []
    for img, delay_cs in frames:
        images.append(img.convert("P", palette=Image.ADAPTIVE, colors=256))
        durations.append(delay_cs * 10)  # PIL uses milliseconds

    images[0].save(
        path,
        save_all=True,
        append_images=images[1:],
        loop=0,
        duration=durations,
        optimize=True,
    )

def main():
    font = load_font(FONT_SIZE)
    cw, ch = char_size(font)
    print(f"Font cell: {cw}x{ch}px  Canvas: {W}x{H}")

    frames = build_frames(font, cw, ch)
    print(f"Built {len(frames)} frames")

    out = os.path.join(os.path.dirname(__file__), "../docs/demo.gif")
    out = os.path.normpath(out)
    save_gif(frames, out)

    size_kb = os.path.getsize(out) / 1024
    print(f"Saved {out}  ({size_kb:.1f} KB)")
    if size_kb > 300:
        print("WARNING: file exceeds 300KB target")

if __name__ == "__main__":
    main()
