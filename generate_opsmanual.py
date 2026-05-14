#!/usr/bin/env python3
"""
generate_opsmanual.py — Metis Operations Manual PDF

Produces OPERATIONS_MANUAL.pdf in the Apple-inspired technical documentation
aesthetic, matching the design language of generate_briefing.py and
generate_toolchain_docs.py.

Sections:
  §1   Introduction & System Overview
  §2   Installation
  §3   Quick Start (5-minute guide)
  §4   Operations — C2 RMT Screen
  §5   Operations — C3 Template Matching
  §6   Operations — C6 Taint Analysis
  §7   Operations — C1 Backbone Prioritisation
  §8   Interpreting Output
  §9   Output File Reference
  §10  API Reference
  §11  Maintenance
  §12  Troubleshooting
  §13  Appendix — Known Issues & Workarounds

Usage:
    /tmp/briefing_venv/bin/python3.13 generate_opsmanual.py
    # or any venv with: pip install reportlab
"""

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE = Path(__file__).parent
W, H = A4

# ═══════════════════════════════════════════════════════════════════════════════
# DESIGN TOKENS  —  matches generate_briefing.py and generate_toolchain_docs.py
# ═══════════════════════════════════════════════════════════════════════════════
ACCENT      = colors.HexColor('#1D4ED8')
ACCENT_LITE = colors.HexColor('#EFF4FF')
INK         = colors.HexColor('#1D1D1F')
INK2        = colors.HexColor('#3A3A3C')
CAPTION_C   = colors.HexColor('#6E6E73')
RULE_C      = colors.HexColor('#D2D2D7')
TABLE_HEAD  = colors.HexColor('#F2F2F7')
TABLE_ALT   = colors.HexColor('#FAFAFA')
NOTE_BG     = colors.HexColor('#F5F5F7')
WARN_BG     = colors.HexColor('#FFF8F0')
WARN_BAR    = colors.HexColor('#C65911')
ERR_BG      = colors.HexColor('#FFF0F0')
ERR_BAR     = colors.HexColor('#C00000')
GREEN_BAR   = colors.HexColor('#1A8038')
GREEN_BG    = colors.HexColor('#F0FFF4')
WHITE       = colors.white

ML  = 25*mm
MR  = 22*mm
MT  = 22*mm
MB  = 20*mm
TW  = W - ML - MR

T_DISPLAY = 32
T_TITLE   = 20
T_H1      = 14
T_H2      = 11
T_H3      = 10
T_BODY    = 9
T_SMALL   = 8
T_CAPTION = 7.5
T_MICRO   = 7

DATE_STR  = '2026-04-17'
DOC_TITLE = 'Metis'
DOC_SUB   = 'Installation, Operations & Maintenance Manual'
AUTHOR    = 'Stuart Thomas'
VERSION   = '1.0'


# ═══════════════════════════════════════════════════════════════════════════════
# LAYOUT PRIMITIVES  —  identical to generate_toolchain_docs.py
# ═══════════════════════════════════════════════════════════════════════════════

def header(c, page_num, section=''):
    y_rule = H - 14*mm
    c.setStrokeColor(RULE_C); c.setLineWidth(0.5)
    c.line(ML, y_rule, W-MR, y_rule)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', T_MICRO)
    c.drawString(ML, y_rule + 2.5*mm, DOC_TITLE.upper())
    c.drawRightString(W-MR, y_rule + 2.5*mm, section)

def footer(c, page_num):
    y_rule = MB - 2*mm
    c.setStrokeColor(RULE_C); c.setLineWidth(0.5)
    c.line(ML, y_rule, W-MR, y_rule)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', T_MICRO)
    c.drawCentredString(W/2, y_rule - 4.5*mm, str(page_num))
    c.drawString(ML, y_rule - 4.5*mm, AUTHOR)
    c.drawRightString(W-MR, y_rule - 4.5*mm, DATE_STR)

def h1(c, text, y):
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_H1)
    c.drawString(ML, y, text)
    c.setFillColor(ACCENT); c.setLineWidth(0); c.setStrokeColor(ACCENT)
    c.rect(ML, y - 1.5*mm, TW, 0.5*mm, fill=1, stroke=0)
    return y - 9*mm

def h2(c, text, y):
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_H2)
    c.drawString(ML, y, text)
    return y - 7.5*mm

def h3(c, text, y):
    c.setFillColor(INK2); c.setFont('Helvetica-BoldOblique', T_H3)
    c.drawString(ML, y, text)
    return y - 6.5*mm

def body(c, text, y, indent=0, colour=None, size=T_BODY, leading=6.0*mm):
    if colour:
        c.setFillColor(colour)
    else:
        c.setFillColor(INK2)
    c.setFont('Helvetica', size)
    x = ML + indent
    w = TW - indent
    words = text.split()
    line = ''
    for word in words:
        test = (line + ' ' + word).strip()
        if c.stringWidth(test, 'Helvetica', size) <= w:
            line = test
        else:
            if line:
                c.drawString(x, y, line)
                y -= leading
            line = word
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y

def mono(c, text, y, indent=4*mm, size=T_SMALL - 0.5):
    """Single monospaced code line."""
    c.setFillColor(INK2); c.setFont('Courier', size)
    c.drawString(ML + indent, y, text)
    return y - 5.5*mm

def bullet_item(c, text, y, indent=4*mm):
    c.setFillColor(ACCENT); c.setFont('Helvetica-Bold', T_BODY + 1)
    c.drawString(ML + indent - 3.5*mm, y, '\u2013')
    y = body(c, text, y, indent=indent + 1.5*mm)
    return y - 1*mm

def caption_text(c, text, y):
    c.setFillColor(CAPTION_C); c.setFont('Helvetica-Oblique', T_CAPTION)
    c.drawCentredString(W/2, y, text)
    return y - 5*mm

def callout(c, kind, title, lines, y):
    if kind == 'note':
        bar_c = ACCENT; bg_c = ACCENT_LITE
    elif kind == 'warning':
        bar_c = WARN_BAR; bg_c = WARN_BG
    elif kind == 'success':
        bar_c = GREEN_BAR; bg_c = GREEN_BG
    else:  # 'error'
        bar_c = ERR_BAR; bg_c = ERR_BG
    lh = 5.8*mm
    box_h = (len(lines) + 1.6) * lh + 2*mm
    c.setFillColor(bg_c)
    c.roundRect(ML, y - box_h, TW, box_h, 2*mm, fill=1, stroke=0)
    c.setFillColor(bar_c)
    c.rect(ML, y - box_h, 2.5*mm, box_h, fill=1, stroke=0)
    c.setFillColor(bar_c); c.setFont('Helvetica-Bold', T_SMALL)
    c.drawString(ML + 5*mm, y - lh * 0.95, title)
    c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
    for i, ln in enumerate(lines):
        c.drawString(ML + 5*mm, y - lh * 1.9 - i * lh, ln)
    return y - box_h - 3*mm

def code_block(c, lines, y, indent=0):
    """Render a monospaced code block with grey background."""
    lh = 5.2*mm
    box_h = len(lines) * lh + 4*mm
    c.setFillColor(colors.HexColor('#F5F5F7'))
    c.roundRect(ML + indent, y - box_h, TW - indent, box_h, 1.5*mm, fill=1, stroke=0)
    c.setStrokeColor(RULE_C); c.setLineWidth(0.4)
    c.roundRect(ML + indent, y - box_h, TW - indent, box_h, 1.5*mm, fill=0, stroke=1)
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            c.setFillColor(CAPTION_C)
        else:
            c.setFillColor(INK2)
        c.setFont('Courier', T_SMALL - 0.5)
        c.drawString(ML + indent + 3*mm, y - lh * (i + 0.85), line)
    return y - box_h - 3*mm

def table(c, headers, rows, col_widths, y, row_h=7.8*mm):
    x0 = ML
    c.setFillColor(TABLE_HEAD)
    c.rect(x0, y - row_h * 0.3, sum(col_widths), row_h * 0.85, fill=1, stroke=0)
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_SMALL)
    cx = x0 + 2*mm
    for h_txt, cw in zip(headers, col_widths):
        c.drawString(cx, y + 0.5*mm, h_txt); cx += cw
    c.setStrokeColor(RULE_C); c.setLineWidth(0.4)
    c.line(x0, y - row_h * 0.3, x0 + sum(col_widths), y - row_h * 0.3)
    y -= row_h
    for ri, row in enumerate(rows):
        bg = TABLE_ALT if ri % 2 == 0 else WHITE
        c.setFillColor(bg)
        c.rect(x0, y - row_h * 0.3, sum(col_widths), row_h * 0.85, fill=1, stroke=0)
        cx = x0 + 2*mm
        for cell, cw in zip(row, col_widths):
            cs = str(cell)
            col_txt = INK2; fw = 'Helvetica'
            if cs in ('ANOMALOUS',):
                col_txt = ERR_BAR; fw = 'Helvetica-Bold'
            elif cs in ('NORMAL',):
                col_txt = GREEN_BAR
            elif cs.startswith('Killed') or cs == 'Kill':
                col_txt = ERR_BAR
            elif cs.startswith('Keep'):
                col_txt = GREEN_BAR
            c.setFillColor(col_txt); c.setFont(fw, T_SMALL)
            while c.stringWidth(cs, fw, T_SMALL) > cw - 4*mm and len(cs) > 3:
                cs = cs[:-2] + '\u2026'
            c.drawString(cx, y + 0.5*mm, cs); cx += cw
        c.setStrokeColor(RULE_C); c.setLineWidth(0.3)
        c.line(x0, y - row_h * 0.3, x0 + sum(col_widths), y - row_h * 0.3)
        y -= row_h
    return y - 2*mm

def section_title_page(c, sec_id, title, pg):
    c.setFillColor(WHITE)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(colors.HexColor('#F0F4FF'))
    c.rect(0, H/2 - 25*mm, W, 80*mm, fill=1, stroke=0)
    c.setFillColor(ACCENT)
    c.setFont('Helvetica-Bold', 90)
    c.drawCentredString(W/2, H/2 + 20*mm, sec_id)
    c.setStrokeColor(ACCENT); c.setLineWidth(1.0)
    c.line(ML, H/2 + 14*mm, W-MR, H/2 + 14*mm)
    c.setFillColor(INK); c.setFont('Helvetica-Bold', 22)
    c.drawCentredString(W/2, H/2 - 2*mm, title)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', 10)
    c.drawCentredString(W/2, H/2 - 12*mm, DOC_SUB)
    footer(c, pg)

def cover_page(c):
    c.setFillColor(WHITE)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(ACCENT)
    c.rect(0, H - 4*mm, W, 4*mm, fill=1, stroke=0)

    ty = H - 55*mm
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_DISPLAY)
    c.drawCentredString(W/2, ty, DOC_TITLE)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', 14)
    c.drawCentredString(W/2, ty - 12*mm, 'Installation, Operations & Maintenance Manual')

    c.setStrokeColor(ACCENT); c.setLineWidth(1.2)
    c.line(ML + 20*mm, ty - 22*mm, W - MR - 20*mm, ty - 22*mm)

    meta = [
        ('Version',   VERSION),
        ('Author',    AUTHOR),
        ('Date',      DATE_STR),
        ('Platform',  'macOS 12+ (arm64e / x86_64)  \u00b7  Python 3.11 or 3.13'),
        ('Package',   'macos_vuln_toolchain/metis/'),
        ('Stages',    'C1, C2, C3, C6 operational  \u00b7  C4, C5 killed by design review'),
    ]
    y_meta = ty - 36*mm
    for lbl, val in meta:
        c.setFillColor(CAPTION_C); c.setFont('Helvetica-Bold', T_SMALL)
        c.drawString(ML + 15*mm, y_meta, lbl.upper())
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
        c.drawString(ML + 55*mm, y_meta, val)
        y_meta -= 8.5*mm

    c.setStrokeColor(RULE_C); c.setLineWidth(0.5)
    c.line(ML, y_meta - 2*mm, W-MR, y_meta - 2*mm)

    y_toc = y_meta - 12*mm
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_SMALL + 0.5)
    c.drawString(ML + 15*mm, y_toc, 'Contents')
    y_toc -= 8*mm
    sections = [
        ('\u00a71',   'Introduction & System Overview'),
        ('\u00a72',   'Installation'),
        ('\u00a73',   'Quick Start (5-minute guide)'),
        ('\u00a74',   'Operations \u2014 C2 RMT Screen'),
        ('\u00a75',   'Operations \u2014 C3 Template Matching'),
        ('\u00a76',   'Operations \u2014 C6 Taint Analysis'),
        ('\u00a77',   'Operations \u2014 C1 Backbone Prioritisation'),
        ('\u00a78',   'Interpreting Output'),
        ('\u00a79',   'Output File Reference'),
        ('\u00a710',  'API Reference'),
        ('\u00a711',  'Maintenance'),
        ('\u00a712',  'Troubleshooting'),
        ('\u00a713',  'Appendix \u2014 Known Issues & Workarounds'),
    ]
    for sec_id, sec_title in sections:
        c.setFillColor(ACCENT); c.setFont('Helvetica-Bold', T_SMALL)
        c.drawString(ML + 15*mm, y_toc, sec_id)
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
        c.drawString(ML + 38*mm, y_toc, sec_title)
        y_toc -= 7*mm

    c.setFillColor(colors.HexColor('#F5F5F7'))
    c.rect(0, 0, W, 18*mm, fill=1, stroke=0)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', T_MICRO)
    c.drawCentredString(W/2, 7*mm,
        'Security research toolchain \u2014 responsible disclosure via Apple ASB')
    c.drawCentredString(W/2, 3*mm, '1')


# ═══════════════════════════════════════════════════════════════════════════════
# BUILD PDF
# ═══════════════════════════════════════════════════════════════════════════════

def build_pdf(out_path):
    print('Building PDF...')
    c  = rl_canvas.Canvas(str(out_path), pagesize=A4)
    pg = [1]

    def end_page(sec=''):
        header(c, pg[0], sec)
        footer(c, pg[0])
        c.showPage(); pg[0] += 1

    def top():
        return H - MT - 6*mm

    # ── Cover ─────────────────────────────────────────────────────────────────
    cover_page(c); c.showPage(); pg[0] += 1

    # ── §1 Introduction & System Overview ─────────────────────────────────────
    section_title_page(c, '\u00a71', 'Introduction & System Overview', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a71  Introduction & System Overview'
    y = top()

    y = h1(c, '1.1  Purpose', y); y -= 1.5*mm
    y = body(c, ('Metis is a static binary analysis pipeline for macOS '
        '(and optionally Windows) target binaries. It triages compiled binaries \u2014 without '
        'source code or debug symbols \u2014 and identifies functions most likely to harbour '
        'memory safety vulnerabilities: out-of-bounds writes, use-after-free conditions, integer '
        'overflows flowing to allocators, and type-confusion bugs.'), y)
    y -= 4*mm

    y = h2(c, 'Pipeline stages', y); y -= 1.5*mm
    stage_rows = [
        ['C1', 'Backbone Prioritisation', 'Phase-transition symbolic execution state ranking', '32 ms/state avg'],
        ['C2', 'RMT Screen',              'Spectral anomaly detection on call graph',          '~30 s/binary'],
        ['C3', 'Template Matching',        'Call dataflow pattern matching (5 templates)',      '~60 s on top-N'],
        ['C4', 'TDA',                      'KILLED \u2014 homology redundant with cyclomatic M', '\u2014'],
        ['C5', 'Comp. Sensing',            'KILLED \u2014 RIP fails for coverage bitmaps',      '\u2014'],
        ['C6', 'Taint Analysis',           'Symbolic taint + PoC input synthesis',             'mins/function'],
    ]
    y = table(c, ['Stage', 'Name', 'Purpose', 'Runtime'], stage_rows,
              [12*mm, 38*mm, 85*mm, TW - 135*mm], y, row_h=9.5*mm)
    y -= 5*mm

    y = h1(c, '1.2  Operational Workflow', y); y -= 1.5*mm
    y = body(c, 'The standard engagement workflow runs three stages in sequence:', y)
    y -= 2*mm
    for b in [
        'C2 screen (run_c2_screen.py) \u2014 spectral triage of all target binaries, ~30 s per binary. '
         'Outputs c2_top_addrs.json with the top-ranked function addresses.',
        'C3 template scan (run_c3_screen.py) \u2014 pattern matching on the C2 top-N functions. '
         'Outputs c3_hits.json with template matches and confidence scores.',
        'C6 targeted symbolic execution \u2014 per-function, invoked manually for addresses in '
         'c3_hits.json. Outputs c6_alerts.json with taint labels and PoC inputs.',
    ]:
        y = bullet_item(c, b, y)
    y -= 3*mm

    y = body(c, ('C1 is not a standalone stage. It is an ExplorationTechnique composed '
        'inside the C6 symbolic execution loop to prioritise easy paths and defer hard ones.'), y)
    y -= 5*mm

    y = h1(c, '1.3  Package Structure', y); y -= 1.5*mm
    y = code_block(c, [
        'macos_vuln_toolchain/',
        '    metis/',
        '        __init__.py',
        '        exploration_technique.py   # C1: HardnessExplorationTechnique',
        '        semantic_backbone.py       # backbone fraction via Z3 assumptions',
        '        backbone_probe.py          # legacy: pysat Glucose3 path',
        '        dimacs_converter.py        # claripy -> DIMACS CNF',
        '        c2_rmt.py                  # C2: C2RMTAnalysis',
        '        c3_templates.py            # C3: C3TemplateAnalysis',
        '        c6_taint.py                # C6: C6TaintTechnique / C6Analysis',
        '        test_pipeline.py           # unit tests (5/5 passing)',
        '        validate_c3.py             # C3 regression validation',
        '        validate_c6.py             # C6 regression validation',
        '    run_c2_screen.py               # top-level C2 runner',
        '    run_c3_screen.py               # top-level C3 runner (reads c2_top_addrs.json)',
        '    TOOLCHAIN_DOCUMENTATION.md',
        '    OPERATIONS_MANUAL.md           # this document',
    ], y)

    end_page(SEC)

    # ── §2 Installation ────────────────────────────────────────────────────────
    section_title_page(c, '\u00a72', 'Installation', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a72  Installation'
    y = top()

    y = h1(c, '2.1  Prerequisites', y); y -= 1.5*mm
    prereq_rows = [
        ['macOS', '12+',          'Primary platform; arm64e or x86_64'],
        ['Python', '3.11 or 3.13', 'Avoid 3.12 \u2014 angr has known compatibility issues'],
        ['angr',   '>= 9.2',       'Pulls in pyvex, claripy, cle, archinfo, networkx'],
        ['numpy',  'recent',       'Spectral computation'],
        ['scipy',  'recent',       'Eigenvalue solver'],
        ['z3-solver', 'recent',    'Backbone probing via Z3 assumptions'],
        ['reportlab', 'optional',  'PDF generation only'],
        ['matplotlib','optional',  'PDF figure generation only'],
        ['pillow',    'optional',  'PDF image embedding only'],
    ]
    y = table(c, ['Package', 'Version', 'Notes'], prereq_rows,
              [30*mm, 28*mm, TW - 58*mm], y, row_h=8.5*mm)
    y -= 4*mm

    y = callout(c, 'warning', 'Do not use Python 3.12', [
        'angr has known compatibility issues with Python 3.12 that cause import failures',
        'and runtime errors. Use Python 3.11 or Python 3.13.',
    ], y)
    y -= 3*mm

    y = h1(c, '2.2  Virtual Environment Setup', y); y -= 1.5*mm
    y = code_block(c, [
        'python3.11 -m venv /tmp/angr_venv',
        'source /tmp/angr_venv/bin/activate',
        'pip install angr numpy scipy z3-solver',
        '',
        '# Verify installation:',
        'python3 -c "import angr; print(angr.__version__)"',
        'python3 -c "import angr, archinfo, claripy, numpy, scipy, z3; print(\'OK\')"',
        '',
        '# Optional: PDF generation',
        'pip install reportlab matplotlib pillow',
    ], y)
    y -= 3*mm

    y = h1(c, '2.3  Critical: Architecture Override', y); y -= 1.5*mm
    y = body(c, ('On macOS, angr defaults to x86_64 when loading universal Mach-O binaries, '
        'even on Apple Silicon hardware. This must always be overridden explicitly:'), y)
    y -= 2*mm
    y = code_block(c, [
        'import archinfo, angr',
        '',
        'proj = angr.Project(',
        '    \'/path/to/binary\',',
        '    auto_load_libs=False,',
        '    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')}',
        ')',
        '# NEVER pass arch as a bare string',
        '# NEVER rely on default slice selection from universal Mach-O',
        '# archinfo.arch_from_id() returns an Arch instance as required',
    ], y)
    y -= 3*mm

    y = callout(c, 'error', 'Common arch mistake', [
        'WRONG:  main_opts={"arch": "aarch64"}',
        'RIGHT:  main_opts={"arch": archinfo.arch_from_id("aarch64")}',
        'angr requires an archinfo.Arch instance, not a string.',
    ], y)
    y -= 3*mm

    y = h1(c, '2.4  Verify the Install', y); y -= 1.5*mm
    y = code_block(c, [
        'cd /path/to/macos_vuln_toolchain',
        'python3 -m pytest metis/test_pipeline.py -v',
        '# Expected: 5 passed, 0 errors, 0 failures',
    ], y)

    end_page(SEC)

    # ── §3 Quick Start ─────────────────────────────────────────────────────────
    section_title_page(c, '\u00a73', 'Quick Start (5-minute guide)', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a73  Quick Start'
    y = top()

    y = callout(c, 'note', 'Prerequisites for this guide', [
        'Target binary at /usr/libexec/targetd (adjust path as needed)',
        'Virtual environment at /tmp/angr_venv with angr installed',
        'Working directory: macos_vuln_toolchain/',
    ], y)
    y -= 4*mm

    y = h1(c, 'Step 1 \u2014 Activate the venv', y); y -= 1.5*mm
    y = code_block(c, [
        'source /tmp/angr_venv/bin/activate',
        'cd /path/to/macos_vuln_toolchain',
    ], y)
    y -= 4*mm

    y = h1(c, 'Step 2 \u2014 Run the C2 screen (~30 seconds)', y); y -= 1.5*mm
    y = body(c, 'Edit the TARGETS list in run_c2_screen.py, then run:', y)
    y -= 2*mm
    y = code_block(c, [
        'python3 run_c2_screen.py',
        '# Produces: c2_results.txt, c2_top_addrs.json',
    ], y)
    y -= 4*mm

    y = h1(c, 'Step 3 \u2014 Run the C3 template scan (~60 seconds)', y); y -= 1.5*mm
    y = code_block(c, [
        'python3 run_c3_screen.py --top 20',
        '# Reads:    c2_top_addrs.json',
        '# Produces: c3_results.txt, c3_hits.json',
    ], y)
    y -= 4*mm

    y = h1(c, 'Step 4 \u2014 Inspect the results', y); y -= 1.5*mm
    y = code_block(c, [
        'cat c2_results.txt   # anomaly verdict + top-ranked functions',
        'cat c3_results.txt   # template matches with confidence scores',
        'cat c3_hits.json     # machine-readable hits for downstream use',
    ], y)
    y -= 4*mm

    y = h1(c, 'Step 5 \u2014 Targeted symbolic execution (C6)', y); y -= 1.5*mm
    y = body(c, ('C6 is invoked per-function. Build a minimal driver targeting the addresses '
        'in c3_hits.json. See \u00a76 for full C6 usage details.'), y)
    y -= 2*mm
    y = code_block(c, [
        'from metis.c6_taint import C6TaintTechnique',
        'import archinfo, angr',
        '',
        'proj = angr.Project(\'/usr/libexec/targetd\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'state = proj.factory.call_state(0x10001234)  # addr from c3_hits.json',
        'simgr = proj.factory.simgr(state)',
        'simgr.use_technique(C6TaintTechnique())',
        'simgr.run()',
        'findings = simgr.one_deadended.globals.get(\'c6_findings\', [])',
        'for f in findings: print(f[\'vuln_class\'], f[\'poc_input\'])',
    ], y)

    end_page(SEC)

    # ── §4 C2 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '\u00a74', 'Operations \u2014 C2 RMT Screen', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a74  Operations \u2014 C2 RMT Screen'
    y = top()

    y = h1(c, '4.1  What C2 Does', y); y -= 1.5*mm
    y = body(c, ('C2 constructs the call graph of a Mach-O binary, computes three spectral '
        'statistics (spectral radius, graph energy, eigenvalue entropy), and compares them '
        'against a null distribution derived from 50 configuration-model replicates. Functions '
        'are ranked by a combined score weighting eigenvector centrality, cyclomatic complexity, '
        'and back-edge count. A binary is flagged ANOMALOUS if the absolute z-score on any of the '
        'three statistics exceeds 2.0.'), y)
    y -= 4*mm

    y = h2(c, 'Scoring formula', y); y -= 1.5*mm
    y = body(c, 'S = 0.4 \u00d7 ev + 0.35 \u00d7 log(1+M) + 0.25 \u00d7 log(1+B)', y,
             colour=ACCENT, size=T_BODY + 1)
    y -= 2*mm
    score_rows = [
        ['ev', 'Eigenvector centrality (0\u20131)', '0.4'],
        ['M',  'McCabe cyclomatic complexity = E \u2212 N + 2', '0.35'],
        ['B',  'Back-edge count (loop depth indicator)', '0.25'],
    ]
    y = table(c, ['Term', 'Definition', 'Weight'], score_rows,
              [12*mm, 100*mm, TW - 112*mm], y, row_h=8.5*mm)
    y -= 5*mm

    y = h1(c, '4.2  Running C2', y); y -= 1.5*mm
    y = h3(c, 'Command line', y)
    y = code_block(c, [
        'python3 run_c2_screen.py',
        '# Edit TARGETS list at the top of run_c2_screen.py to specify binaries',
    ], y)
    y -= 3*mm

    y = h3(c, 'Programmatic (from a path)', y)
    y = code_block(c, [
        'from metis.c2_rmt import C2RMTAnalysis',
        '',
        'result = C2RMTAnalysis(\'/usr/libexec/targetd\').run()',
        'result.print_report()',
    ], y)
    y -= 3*mm

    y = h3(c, 'Programmatic (from existing project, avoids double-loading)', y)
    y = code_block(c, [
        'import archinfo, angr',
        'from metis.c2_rmt import C2RMTAnalysis',
        '',
        'proj = angr.Project(\'/usr/libexec/targetd\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'result = C2RMTAnalysis.from_project(proj).run()',
    ], y)
    y -= 3*mm

    y = h1(c, '4.3  C2 Result Object', y); y -= 1.5*mm
    result_rows = [
        ['result.functions_ranked', 'list[(int, float)]', 'Top functions sorted by score, descending'],
        ['result.anomalous',        'bool',               'True if any |z| > 2.0'],
        ['result.z_radius',         'float',              'Z-score for spectral radius'],
        ['result.z_energy',         'float',              'Z-score for graph energy'],
        ['result.z_entropy',        'float',              'Z-score for eigenvalue entropy'],
        ['result.print_report()',   'method',             'Prints human-readable report to stdout'],
    ]
    y = table(c, ['Attribute', 'Type', 'Description'], result_rows,
              [52*mm, 28*mm, TW - 80*mm], y, row_h=8.5*mm)
    y -= 4*mm

    y = h1(c, '4.4  Anomaly Thresholds', y); y -= 1.5*mm
    thresh_rows = [
        ['All |z| \u2264 2.0',                  'NORMAL',    '\u2014'],
        ['Any |z| > 2.0',                        'ANOMALOUS', 'Primary triage signal'],
        ['Call graph N < 100 nodes',              'Low-confidence', 'Use function-level metrics only'],
    ]
    y = table(c, ['Condition', 'Verdict', 'Notes'], thresh_rows,
              [60*mm, 38*mm, TW - 98*mm], y, row_h=8.5*mm)
    y -= 3*mm
    y = body(c, ('Null distribution: 50 configuration-model replicates matching the observed '
        'in/out degree sequence. The configuration model (Bollob\u00e1s 1980, directed variant) '
        'is correct for call graphs. Marchenko-Pastur and Wigner semicircle law assume i.i.d. '
        'matrix entries and are incorrect for power-law degree distributions \u2014 do not use them.'), y)

    end_page(SEC)

    # ── §5 C3 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '\u00a75', 'Operations \u2014 C3 Template Matching', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a75  Operations \u2014 C3 Template Matching'
    y = top()

    y = h1(c, '5.1  What C3 Does', y); y -= 1.5*mm
    y = body(c, ('C3 scans the CFG of a binary looking for source-to-sink call chains that match '
        'known vulnerability patterns. Each template specifies source functions (attacker-controlled '
        'input entry points), sink functions (dangerous operations), and barrier functions that '
        'clear the match if present on the path. A match fires when a source-to-sink path exists '
        'in the call graph with no intervening barrier.'), y)
    y -= 4*mm

    y = h1(c, '5.2  The Five Templates', y); y -= 1.5*mm
    template_rows = [
        ['MACH_OOB',  'mach_msg recv buf field', 'malloc / calloc size', 'bounds check', '0.82'],
        ['XPC_TYPE',  'xpc_dictionary_get_value', 'typed XPC accessor',  'xpc_get_type', '0.65'],
        ['INT_OVF',   'XPC / mach value',         'arithmetic \u2192 allocator', 'bounds / saturation', '0.79'],
        ['PORT_UAF',  'mach_port_deallocate',      'mach port op same name', 'port epoch check', '0.71'],
        ['IOKIT_OOB', 'IOConnectCallMethod OOB',   'memcpy / alloc',     'bounds check', '0.88'],
    ]
    y = table(c, ['Template', 'Source', 'Sink', 'Barrier', 'Conf.'], template_rows,
              [26*mm, 42*mm, 38*mm, 36*mm, TW - 142*mm], y, row_h=9*mm)
    y -= 5*mm

    y = h1(c, '5.3  Running C3', y); y -= 1.5*mm
    y = h3(c, 'Command line', y)
    y = code_block(c, [
        'python3 run_c3_screen.py           # reads c2_top_addrs.json',
        'python3 run_c3_screen.py --top 20  # limit to top-20 C2 functions',
    ], y)
    y -= 3*mm

    y = h3(c, 'Programmatic', y)
    y = code_block(c, [
        'from metis.c3_templates import C3TemplateAnalysis',
        'import archinfo, angr',
        '',
        'proj = angr.Project(\'/usr/libexec/targetd\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'c3 = C3TemplateAnalysis(proj)',
        '',
        '# Whole binary:',
        'results = c3.run()',
        '',
        '# Targeted on C2 top function addresses:',
        'top_addrs = [0x10001234, 0x10002abc]',
        'results = c3.analyse_functions(top_addrs)',
        '',
        'for r in results:',
        '    print(r.template_name, r.confidence, r.source_fn, r.sink_fn)',
        '    print(\'barrier_present:\', r.barrier_present)',
    ], y)
    y -= 3*mm

    y = h1(c, '5.4  Adding a New C3 Template', y); y -= 1.5*mm
    y = body(c, ('Open metis/c3_templates.py and append a new entry to the '
        'TEMPLATE_BANK list:'), y)
    y -= 2*mm
    y = code_block(c, [
        'TEMPLATE_BANK.append(VulnTemplate(',
        '    name       = \'MY_TEMPLATE\',',
        '    sources    = [\'xpc_dictionary_get_int64\'],',
        '    sinks      = [\'memcpy\', \'bcopy\'],',
        '    barriers   = [\'my_bounds_check\', \'assert\'],',
        '    confidence = 0.75,',
        '    vuln_class = \'OOB_WRITE\',',
        '))',
    ], y)
    y -= 3*mm

    y = callout(c, 'warning', 'Stdlib filter', [
        'Do not add stdlib functions (memset, bzero, strncpy) as sources.',
        'C3 applies a stdlib caller filter. Paths through CRT routines only',
        'are suppressed automatically.',
    ], y)

    end_page(SEC)

    # ── §6 C6 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '\u00a76', 'Operations \u2014 C6 Taint Analysis', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a76  Operations \u2014 C6 Taint Analysis'
    y = top()

    y = h1(c, '6.1  What C6 Does', y); y -= 1.5*mm
    y = body(c, ('C6 is a symbolic taint analysis engine built on angr\'s ExplorationTechnique '
        'mechanism. It hooks 18 system functions with SimProcedure stubs that mark return values '
        'or output buffers as symbolic bitvectors with labelled taint names. As angr explores '
        'paths, claripy\'s AST tracks those bitvectors through arithmetic operations. When a path '
        'reaches a dangerous operation with a tainted operand and a satisfiable constraint system, '
        'C6 emits an alert with the taint label, the constraint path, and a solved PoC input.'), y)
    y -= 4*mm

    y = h1(c, '6.2  Hook Table (18 hooks)', y); y -= 1.5*mm
    hook_rows = [
        ['Allocation',         'malloc, calloc, realloc, valloc, mmap'],
        ['Network / IPC recv', 'recv, recvfrom, read, mach_msg_recv'],
        ['XPC',                'xpc_dictionary_get_value, xpc_array_get_value, xpc_copy'],
        ['IOKit',              'IOKit_copyScalar_64, IOKit_copyScalar_32, OSObject_getRef, io_connect_method'],
        ['Dealloc tracking',   'free, mach_port_deallocate'],
    ]
    y = table(c, ['Category', 'Hooks'], hook_rows,
              [42*mm, TW - 42*mm], y, row_h=9.5*mm)
    y -= 5*mm

    y = h1(c, '6.3  Running C6', y); y -= 1.5*mm
    y = body(c, ('C6 is used programmatically. There is no standalone runner script. '
        'Build a minimal driver for each target function:'), y)
    y -= 2*mm
    y = code_block(c, [
        'from metis.c6_taint import C6TaintTechnique',
        'from metis.exploration_technique import HardnessExplorationTechnique',
        'import archinfo, angr',
        '',
        'proj = angr.Project(\'/usr/libexec/targetd\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'state = proj.factory.call_state(0x10001234)  # from c3_hits.json',
        'simgr = proj.factory.simgr(state)',
        '',
        '# C6 taint technique:',
        'simgr.use_technique(C6TaintTechnique())',
        '',
        '# Optional: compose with C1 backbone prioritisation:',
        'simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))',
        '',
        'simgr.run()',
        'findings = simgr.one_deadended.globals.get(\'c6_findings\', [])',
        'for f in findings:',
        '    print(f[\'vuln_class\'], f[\'taint_label\'], f[\'poc_input\'])',
    ], y)
    y -= 3*mm

    y = callout(c, 'warning', 'C6 must be targeted, not whole-binary', [
        'Running C6 on a full binary without a targeted entry point causes state explosion.',
        'Always scope C6 to a specific function address from c3_hits.json.',
        'When composing with C1, add C6 first so hooks register before C1 begins ranking.',
    ], y)
    y -= 4*mm

    y = h1(c, '6.4  Adding a New C6 Hook', y); y -= 1.5*mm
    y = code_block(c, [
        '# In metis/c6_taint.py:',
        '',
        'class Hook_my_source(angr.SimProcedure):',
        '    def run(self, arg0, arg1):',
        '        tainted = self.state.solver.BVS(\'my_source_ret\', 64)',
        '        self.state.globals.setdefault(\'taint_labels\', {})',
        '            [tainted.args[0]] = \'MY_SOURCE\'',
        '        return tainted',
        '',
        '# Register in _HOOK_TABLE at the bottom of the file:',
        '_HOOK_TABLE[\'my_source_function\'] = Hook_my_source',
    ], y)

    end_page(SEC)

    # ── §7 C1 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '\u00a77', 'Operations \u2014 C1 Backbone Prioritisation', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a77  Operations \u2014 C1 Backbone Prioritisation'
    y = top()

    y = h1(c, '7.1  What C1 Does', y); y -= 1.5*mm
    y = body(c, ('C1 is an angr.ExplorationTechnique that ranks active simulation states by their '
        'backbone fraction \u2014 the proportion of symbolic variable bits that are forced to a '
        'single value by the current path constraints. States with high backbone fraction are near '
        'the 3-SAT phase transition (at clause/variable ratio \u03b1 \u2248 4.267) and will be '
        'slow for the Z3 solver. C1 defers those states to a hardness_deferred stash and explores '
        'easier states first.'), y)
    y -= 4*mm

    y = h2(c, 'Measured performance (angr crackme benchmark, n=50 symbolic bytes)', y); y -= 1.5*mm
    perf_rows = [
        ['Backbone probing time (avg)',   '32 ms per state'],
        ['State reduction',               '60% fewer states before solution path'],
        ['Test suite',                    '5/5 tests passing'],
        ['Spearman \u03c1 (backbone vs CDCL hardness)', '+0.43, p = 0.012'],
    ]
    y = table(c, ['Metric', 'Value'], perf_rows,
              [90*mm, TW - 90*mm], y, row_h=8.5*mm)
    y -= 5*mm

    y = h1(c, '7.2  C1 Parameters', y); y -= 1.5*mm
    param_rows = [
        ['threshold',          'float',      '0.8',   'Backbone fraction cutoff (fixed or adaptive percentile)'],
        ['deferred_stash',     'str',        'hardness_deferred', 'Stash name for deferred states'],
        ['probe_timeout_s',    'float',      '0.05',  'Z3 timeout per state probe (50 ms)'],
        ['score_interval',     'int',        '1',     'Score every N exploration steps'],
        ['min_constraints',    'int',        '3',     'Skip scoring states with fewer constraints'],
        ['max_score_per_step', 'int',        '16',    'Cap number of states scored per step'],
        ['adaptive_threshold', 'bool',       'True',  'Defer top 20% hardest (percentile mode)'],
        ['log_file',           'str | None', 'None',  'CSV log path for per-state backbone scores'],
    ]
    y = table(c, ['Parameter', 'Type', 'Default', 'Description'], param_rows,
              [40*mm, 20*mm, 36*mm, TW - 96*mm], y, row_h=8.5*mm)
    y -= 5*mm

    y = h1(c, '7.3  Using C1', y); y -= 1.5*mm
    y = code_block(c, [
        'from metis.exploration_technique import HardnessExplorationTechnique',
        'import archinfo, angr',
        '',
        'proj = angr.Project(\'/path/to/binary\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'state = proj.factory.entry_state()',
        'simgr = proj.factory.simgr(state)',
        '',
        'simgr.use_technique(HardnessExplorationTechnique(',
        '    threshold=0.8,',
        '    adaptive_threshold=True,',
        '    probe_timeout_s=0.05,',
        '    log_file=\'/tmp/hardness_log.csv\',',
        '))',
        '',
        'simgr.run(n=1000)',
        'print(f\'Active: {len(simgr.active)}, Deferred: {len(simgr.hardness_deferred)}\')',
    ], y)

    end_page(SEC)

    # ── §8 Interpreting Output ─────────────────────────────────────────────────
    section_title_page(c, '\u00a78', 'Interpreting Output', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a78  Interpreting Output'
    y = top()

    y = h1(c, '8.1  C2 Anomaly Verdicts', y); y -= 1.5*mm
    y = body(c, ('A C2 ANOMALOUS verdict means the call graph structure deviates significantly '
        'from what would be expected from a random graph with the same degree sequence. This is '
        'a triage signal, not a confirmation of vulnerability.'), y)
    y -= 3*mm

    anomaly_rows = [
        ['z_energy strongly negative',  'Massively structured internal complexity \u2014 many high-M functions'],
        ['z_radius strongly positive',  'Unusually strong cyclic structure \u2014 persistent loops'],
        ['z_entropy strongly positive', 'Noise-dominated spectrum \u2014 may be Swift/ObjC vtable noise (FP)'],
        ['z_entropy strongly negative', 'Rigid hierarchy \u2014 monolithic processing without abstraction'],
    ]
    y = table(c, ['Pattern', 'Likely meaning'], anomaly_rows,
              [58*mm, TW - 58*mm], y, row_h=9*mm)
    y -= 4*mm

    y = h2(c, 'Reference values from audit corpus', y); y -= 1.5*mm
    corpus_rows = [
        ['smbd',           '-3.56', '-3.01', '-0.30', 'ANOMALOUS'],
        ['opendirectoryd', '-2.50', '-1.88', '-1.10', 'ANOMALOUS'],
        ['mDNSResponder',  '-1.85', '-22.33', '-142.37', 'ANOMALOUS'],
        ['amfid',          '-0.10', '-0.08', '-0.05', 'NORMAL'],
    ]
    y = table(c, ['Binary', 'z_radius', 'z_energy', 'z_entropy', 'Verdict'], corpus_rows,
              [42*mm, 22*mm, 22*mm, 28*mm, TW - 114*mm], y, row_h=8.5*mm)
    y -= 5*mm

    y = h1(c, '8.2  C3 Confidence Scores', y); y -= 1.5*mm
    conf_rows = [
        ['\u2265 0.85', 'High', 'Source-to-sink path very likely unmitigated'],
        ['0.70\u20130.84', 'Medium', 'Worth manual review of the call chain'],
        ['< 0.70', 'Low', 'Barrier may exist; verify call chain manually'],
    ]
    y = table(c, ['Confidence', 'Level', 'Interpretation'], conf_rows,
              [26*mm, 22*mm, TW - 48*mm], y, row_h=8.5*mm)
    y -= 3*mm
    y = body(c, ('A C3 match with barrier_present=True is not a vulnerability finding. '
        'A barrier function was found on the source-to-sink path. Record and move on.'), y)
    y -= 5*mm

    y = h1(c, '8.3  C6 Alerts', y); y -= 1.5*mm
    alert_rows = [
        ['vuln_class',   'OOB_WRITE | OOB_READ | UAF | INT_OVF | TYPE_CONFUSION'],
        ['taint_label',  'Hook name that introduced the taint (e.g. recv_buf_3)'],
        ['constraint',   'The SMT constraint path that led to the vulnerable state'],
        ['poc_input',    'Concrete hex byte sequence (Z3-solved); valid attacker input'],
    ]
    y = table(c, ['Field', 'Meaning'], alert_rows,
              [30*mm, TW - 30*mm], y, row_h=8.5*mm)
    y -= 4*mm

    y = callout(c, 'warning', 'Manual verification required before filing', [
        'A C6 alert with a valid poc_input is the strongest finding the toolchain produces.',
        'Symbolic execution confirmed a satisfiable attacker-controlled path to a dangerous op.',
        'Nevertheless: always verify with a live PoC run before filing a vulnerability report.',
        '"Would produce" descriptions without terminal output are not accepted.',
    ], y)

    end_page(SEC)

    # ── §9 Output File Reference ───────────────────────────────────────────────
    section_title_page(c, '\u00a79', 'Output File Reference', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a79  Output File Reference'
    y = top()

    y = h1(c, '9.1  File Summary', y); y -= 1.5*mm
    file_rows = [
        ['c2_results.txt',    'Plain text', 'C2 report: anomaly verdict, z-scores, top-20 functions'],
        ['c2_top_addrs.json', 'JSON',       '{binary_label: [{addr, score, cyclomatic, back_edges, name}]}'],
        ['c3_results.txt',    'Plain text', 'C3 report: template hits with confidence and function names'],
        ['c3_hits.json',      'JSON',       '{binary_label: [{addr, template, confidence, source_fn, sink_fn}]}'],
        ['c6_alerts.json',    'JSON',       '[{addr, vuln_class, taint_label, constraint, poc_input}]'],
        ['hardness_log.csv',  'CSV',        'Per-state backbone scores (only if log_file set in C1)'],
    ]
    y = table(c, ['File', 'Format', 'Contents'], file_rows,
              [44*mm, 20*mm, TW - 64*mm], y, row_h=9*mm)
    y -= 5*mm

    y = h1(c, '9.2  c2_top_addrs.json Schema', y); y -= 1.5*mm
    y = code_block(c, [
        '{',
        '  "targetd": [',
        '    {',
        '      "addr": 4295012928,',
        '      "score": 2.341,',
        '      "cyclomatic": 155,',
        '      "back_edges": 12,',
        '      "name": "sub_100012340"',
        '    }',
        '  ]',
        '}',
    ], y)
    y -= 5*mm

    y = h1(c, '9.3  c3_hits.json Schema', y); y -= 1.5*mm
    y = code_block(c, [
        '{',
        '  "targetd": [',
        '    {',
        '      "addr": 4295012928,',
        '      "template": "MACH_OOB",',
        '      "confidence": 0.82,',
        '      "source_fn": "mach_msg",',
        '      "sink_fn": "malloc"',
        '    }',
        '  ]',
        '}',
    ], y)
    y -= 5*mm

    y = h1(c, '9.4  c6_alerts.json Schema', y); y -= 1.5*mm
    y = code_block(c, [
        '[',
        '  {',
        '    "addr": 4295012928,',
        '    "vuln_class": "OOB_WRITE",',
        '    "taint_label": "recv_buf_3",',
        '    "constraint": "BVS(recv_buf_3)[0:15] > malloc_size_BVS",',
        '    "poc_input": "ff 03 00 00 00 00 00 00"',
        '  }',
        ']',
    ], y)

    end_page(SEC)

    # ── §10 API Reference ──────────────────────────────────────────────────────
    section_title_page(c, '\u00a710', 'API Reference', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a710  API Reference'
    y = top()

    y = h1(c, '10.1  C1 \u2014 HardnessExplorationTechnique', y); y -= 1.5*mm
    y = code_block(c, [
        '# metis.exploration_technique.HardnessExplorationTechnique',
        '',
        'HardnessExplorationTechnique(',
        '    threshold=0.8,',
        '    deferred_stash=\'hardness_deferred\',',
        '    probe_timeout_s=0.05,',
        '    score_interval=1,',
        '    min_constraints=3,',
        '    max_score_per_step=16,',
        '    adaptive_threshold=True,',
        '    log_file=None,',
        ')',
        '',
        '# Methods called by angr automatically:',
        '# .setup(simgr)          -- called on attachment',
        '# .step(simgr, **kwargs) -- scores and defers states each step',
    ], y)
    y -= 5*mm

    y = h1(c, '10.2  C2 \u2014 C2RMTAnalysis', y); y -= 1.5*mm
    y = code_block(c, [
        '# metis.c2_rmt.C2RMTAnalysis',
        '',
        'C2RMTAnalysis(binary_path: str)',
        'C2RMTAnalysis.from_project(proj: angr.Project)  # class method',
        '',
        '.run() -> C2Result',
        '',
        '# C2Result attributes:',
        '.functions_ranked   list[(int, float)]   # (addr, score), sorted desc',
        '.anomalous          bool',
        '.z_radius           float',
        '.z_energy           float',
        '.z_entropy          float',
        '.print_report()     -> None   # human-readable to stdout',
    ], y)
    y -= 5*mm

    y = h1(c, '10.3  C3 \u2014 C3TemplateAnalysis', y); y -= 1.5*mm
    y = code_block(c, [
        '# metis.c3_templates.C3TemplateAnalysis',
        '',
        'C3TemplateAnalysis(proj: angr.Project)',
        '',
        '.run() -> list[C3Match]',
        '.analyse_functions(addrs: list[int]) -> list[C3Match]',
        '',
        '# C3Match attributes:',
        '.template_name    str',
        '.confidence       float',
        '.source_fn        str',
        '.sink_fn          str',
        '.barrier_present  bool',
        '.addr             int',
    ], y)
    y -= 5*mm

    y = h1(c, '10.4  C6 \u2014 C6TaintTechnique', y); y -= 1.5*mm
    y = code_block(c, [
        '# metis.c6_taint.C6TaintTechnique',
        '',
        'C6TaintTechnique()',
        '',
        '# Usage:',
        'simgr.use_technique(C6TaintTechnique())',
        'simgr.run()',
        'findings = simgr.one_deadended.globals.get(\'c6_findings\', [])',
        '',
        '# Finding dict keys:',
        '#   addr         int    -- instruction address of alert',
        '#   vuln_class   str    -- OOB_WRITE|OOB_READ|UAF|INT_OVF|TYPE_CONFUSION',
        '#   taint_label  str    -- hook name that introduced the taint',
        '#   constraint   str    -- claripy AST string',
        '#   poc_input    str    -- hex bytes (Z3-solved concrete input)',
    ], y)

    end_page(SEC)

    # ── §11 Maintenance ────────────────────────────────────────────────────────
    section_title_page(c, '\u00a711', 'Maintenance', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a711  Maintenance'
    y = top()

    y = h1(c, '11.1  Update Schedule', y); y -= 1.5*mm
    sched_rows = [
        ['Weekly',               'pip install --upgrade angr',
         'angr releases frequently; check changelog for CLE/pyvex regressions'],
        ['Before each engagement', 'Run test suite',
         'python3 -m pytest metis/test_pipeline.py -v'],
        ['After angr upgrade',   'Run validation scripts',
         'python3 metis/validate_c3.py && python3 metis/validate_c6.py'],
        ['Before major changes', 'Backup',
         'zip -r metis_backup_$(date +%Y%m%d).zip metis/'],
    ]
    y = table(c, ['Frequency', 'Action', 'Notes'], sched_rows,
              [40*mm, 40*mm, TW - 80*mm], y, row_h=10*mm)
    y -= 5*mm

    y = callout(c, 'warning', 'angr API stability', [
        'angr upgrades frequently change internal APIs in pyvex, cle, and claripy.',
        'After any pip upgrade angr, always run the full validation suite before',
        'using the toolchain on a live engagement.',
        'Silent regressions in hook resolution produce false negatives with no error output.',
    ], y)
    y -= 5*mm

    y = h1(c, '11.2  Test Suite Commands', y); y -= 1.5*mm
    y = code_block(c, [
        '# Full unit tests (must pass 5/5):',
        'python3 -m pytest metis/test_pipeline.py -v',
        '',
        '# C3 regression validation:',
        'python3 metis/validate_c3.py',
        '',
        '# C6 regression validation:',
        'python3 metis/validate_c6.py',
        '',
        '# Check angr version:',
        'python3 -c "import angr; print(angr.__version__)"',
        '',
        '# Verify all imports:',
        'python3 -c "import angr, archinfo, claripy, numpy, scipy, z3; print(\'OK\')"',
    ], y)
    y -= 5*mm

    y = h1(c, '11.3  Adding a New Binary Target', y); y -= 1.5*mm
    y = body(c, ('Edit the TARGETS list in run_c2_screen.py. Before adding a binary, '
        'verify CLE can load it cleanly:'), y)
    y -= 2*mm
    y = code_block(c, [
        'import archinfo, angr',
        'proj = angr.Project(\'/your/binary\', auto_load_libs=False,',
        '                    main_opts={\'arch\': archinfo.arch_from_id(\'aarch64\')})',
        'n = len(list(proj.kb.functions.values()))',
        'print(f\'{n} functions found\')',
        '# If n == 0: likely arm64e PAC CLE bug (see §13 Issue 2)',
    ], y)

    end_page(SEC)

    # ── §12 Troubleshooting ────────────────────────────────────────────────────
    section_title_page(c, '\u00a712', 'Troubleshooting', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a712  Troubleshooting'
    y = top()

    y = h1(c, '12.1  Error Messages and Fixes', y); y -= 1.5*mm

    errors = [
        (
            'SimEngineError: CLE could not find any executable sections',
            'Binary is encrypted, packed, or uses an unrecognised segment layout.',
            'Use otool / Ghidra for manual analysis. Skip in batch runs.',
        ),
        (
            'KeyError: \'Win32\' in SYSCALL_CC',
            'Windows ARM64 binary loaded without the SYSCALL_CC monkey-patch.',
            'Apply Windows ARM64 patch before any Project() construction (see \u00a713 Issue 4).',
        ),
        (
            'AngrMemoryError: Not enough memory',
            'Binary exceeds ~3.3 MB \u2014 CFGFast OOMs on 16 GB RAM hardware.',
            'Use sparse eigenvalue mode or skip. Subset CFG to region of interest.',
        ),
        (
            'archinfo error: arch must be an archinfo.Arch instance',
            'arch passed as a bare string to main_opts.',
            'Use archinfo.arch_from_id(\'aarch64\') \u2014 always an Arch object, never a string.',
        ),
        (
            'claripy.errors.BackendError: Cannot convert',
            'Constraint system too complex for Z3 within timeout.',
            'Reduce max_score_per_step in C1; narrow the entry state scope.',
        ),
        (
            'AttributeError: \'NoneType\' has no attribute \'variables\'',
            'C6 hook returned None instead of a BVS.',
            'Check hook\'s run() method \u2014 must always return a BVS, never None.',
        ),
        (
            'C3 returns empty results',
            'CFGFast missed the function (ObjC dispatch / Swift vtables).',
            'Use analyse_functions() with a manual address list from nm or otool.',
        ),
        (
            'z-scores all near 0',
            'Call graph has fewer than 100 nodes.',
            'Low-confidence result. Use function-level metrics (M, back-edges, ev) only.',
        ),
        (
            'All states immediately deferred by C1',
            'All paths are hard (backbone fraction > threshold).',
            'Lower threshold to 0.6 or set adaptive_threshold=True (percentile mode).',
        ),
    ]

    for err, cause, fix in errors:
        c.setFillColor(ERR_BAR); c.setFont('Courier-Bold', T_SMALL - 0.5)
        # Truncate long error messages to fit
        disp_err = err if len(err) < 70 else err[:68] + '\u2026'
        c.drawString(ML + 2*mm, y, disp_err)
        y -= 5*mm
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL - 0.5)
        c.drawString(ML + 4*mm, y, f'Cause: {cause}')
        y -= 4.5*mm
        c.setFillColor(GREEN_BAR); c.setFont('Helvetica', T_SMALL - 0.5)
        c.drawString(ML + 4*mm, y, f'Fix: {fix}')
        y -= 6*mm
        c.setStrokeColor(RULE_C); c.setLineWidth(0.3)
        c.line(ML, y + 2*mm, W-MR, y + 2*mm)
        y -= 2*mm
        if y < MB + 30*mm:
            end_page(SEC)
            y = top()

    end_page(SEC)

    # ── §13 Appendix ──────────────────────────────────────────────────────────
    section_title_page(c, '\u00a713', 'Appendix \u2014 Known Issues & Workarounds', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '\u00a713  Appendix \u2014 Known Issues'
    y = top()

    y = h1(c, 'Issue 1: angr CFG Size Limit (~3.3 MB Mach-O)', y); y -= 1.5*mm
    y = body(c, ('angr\'s CFGFast analysis will exhaust available memory on binaries larger than '
        'approximately 3.3 MB when running on a 16 GB RAM machine. This is a practical ceiling, '
        'not a hard limit; it varies with binary complexity. For large targets, subset the '
        'analysis to a region of interest by providing a list of function addresses to '
        'C3TemplateAnalysis.analyse_functions() rather than calling run() on the full binary.'), y)
    y -= 5*mm

    y = h1(c, 'Issue 2: arm64e PAC / Chained Fixup Relocations (airportd, biometrickitd)', y)
    y -= 1.5*mm
    y = body(c, ('CLE has a known bug handling binaries that use arm64e pointer authentication '
        'codes with chained fixup relocations. Affected binaries include airportd and biometrickitd. '
        'The symptom is an empty function list after CFGFast. Workaround: extract function '
        'addresses via nm or otool and pass them directly to analyse_functions():'), y)
    y -= 2*mm
    y = code_block(c, [
        '# Extract addresses:',
        'nm -n /System/Library/.../biometrickitd | grep \' T \' | awk \'{print $1}\' > addrs.txt',
        '',
        '# Use in C3:',
        'addrs = [int(x, 16) for x in open(\'addrs.txt\').read().splitlines()]',
        'results = c3.analyse_functions(addrs)',
    ], y)
    y -= 5*mm

    y = h1(c, 'Issue 3: Python 3.12 Compatibility', y); y -= 1.5*mm
    y = callout(c, 'error', 'Do not use Python 3.12', [
        'angr has known compatibility issues with Python 3.12 that cause import failures.',
        'Use Python 3.11 or Python 3.13. Do not attempt to diagnose 3.12 failures \u2014',
        'they are upstream angr issues not fixable in this codebase.',
    ], y)
    y -= 4*mm

    y = h1(c, 'Issue 4: Windows ARM64 SYSCALL_CC Patch', y); y -= 1.5*mm
    y = body(c, ('When analysing Windows ARM64 PE binaries, angr\'s calling convention registry is '
        'missing the Win32 entry for AARCH64. This must be patched before any Project() '
        'construction. Additionally, use pefile + capstone for IAT resolution rather than the '
        'unreliable angr KB function lookup:'), y)
    y -= 2*mm
    y = code_block(c, [
        '# Apply before ANY Project() construction:',
        'from angr.calling_conventions import SYSCALL_CC',
        'SYSCALL_CC[\'AARCH64\'][\'Win32\'] = SYSCALL_CC[\'AARCH64\'].get(\'Linux\')',
        '',
        '# IAT resolution (replaces unreliable angr KB for Windows PE):',
        'import pefile, capstone',
        'pe = pefile.PE(\'target.exe\')',
        'iat = {',
        '    imp.address: imp.name.decode()',
        '    for entry in pe.DIRECTORY_ENTRY_IMPORT',
        '    for imp in entry.imports if imp.name',
        '}',
    ], y)
    y -= 5*mm

    y = h1(c, 'Issue 5: VEX IR Constant-Folding (ARM64 Compiler Optimisation)', y)
    y -= 1.5*mm
    y = body(c, ('ARM64 compilers commonly fold pointer arithmetic into load immediates. This means '
        'Add64 nodes in VEX IR are absent even when the source code adds an attacker-controlled '
        'offset to a base pointer. The VEX Add64 scan produces false negatives. The production C3 '
        'implementation uses the otool sliding-window offset scan instead, which examines raw '
        'instruction sequences for LDRB/LDRH register-offset pairs.'), y)
    y -= 5*mm

    y = h1(c, 'Issue 6: ObjC Dispatch / Swift Vtables', y); y -= 1.5*mm
    y = body(c, ('CFGFast does not resolve objc_msgSend dispatch or Swift vtable calls. Any '
        'vulnerability path passing through an ObjC method boundary will appear as a dead end '
        'in the call graph, producing C3 false negatives. Workaround: use Frida or DTrace to '
        'collect a dynamic call trace and augment the static CFG. See '
        'metis/frida_func_fuzz.py for the Frida integration scaffolding.'), y)
    y -= 5*mm

    y = h1(c, 'Issue 7: Cross-Block VEX Temporaries', y); y -= 1.5*mm
    y = body(c, ('VEX IR temporaries (t0, t1, t2, \u2026) are SSA-scoped within a single IRSB '
        '(basic block). They do not carry meaning across block boundaries. Do not attempt to track '
        'tN temporaries across blocks in custom VEX analyses. Use angr\'s state.registers and '
        'state.memory interfaces instead.'), y)
    y -= 5*mm

    y = h1(c, 'Issue 8: angr KB Function Lookup \u2014 Windows PE', y); y -= 1.5*mm
    y = body(c, ('proj.kb.functions is unreliable across sessions for Windows PE binaries. Function '
        'addresses may differ between runs due to ASLR simulation. Use pefile + capstone for '
        'authoritative IAT resolution on Windows targets (see Issue 4 above).'), y)

    end_page(SEC)

    c.save()
    print(f'  PDF written to {out_path}')


if __name__ == '__main__':
    out = HERE / 'OPERATIONS_MANUAL.pdf'
    build_pdf(out)
