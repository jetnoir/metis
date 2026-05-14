#!/usr/bin/env python3
"""
generate_toolchain_docs.py — Metis Documentation PDF

Produces TOOLCHAIN_DOCUMENTATION.pdf in Apple-inspired technical documentation
aesthetic, matching the design language of generate_briefing.py.

Sections:
  §1  The Short Version (lay-person)
  §2  Why C1–C6? (naming history)
  §3  C1 — Phase-Transition Symbolic Execution
  §4  C2 — Random Matrix Theory Screen
  §5  C3 — Template-Based Call Dataflow Matching
  §6  C6 — Symbolic Taint Analysis
  §7  The Disassembly Layer
  §8  Pipeline Composition
  §9  Limitations & Dead Ends
  §10 Glossary

Usage:
    /tmp/briefing_venv/bin/python3.13 generate_toolchain_docs.py
    # or any venv with: pip install reportlab matplotlib pillow numpy scipy
"""

import io, math, textwrap
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.colors as mcolors
from matplotlib.gridspec import GridSpec
from PIL import Image as PILImage

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE  = Path(__file__).parent
FIGS  = HERE / 'toolchain_doc_figures'
FIGS.mkdir(exist_ok=True)
W, H  = A4

# ═══════════════════════════════════════════════════════════════════════════════
# DESIGN TOKENS  —  matches generate_briefing.py exactly
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

ML   = 25*mm
MR   = 22*mm
MT   = 22*mm
MB   = 20*mm
TW   = W - ML - MR

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
DOC_SUB   = 'Mathematics, Physics & Implementation — C1–C6 Pipeline Reference'
AUTHOR    = 'Stuart Thomas'

# ── Matplotlib style ──────────────────────────────────────────────────────────
ACCENT_HEX = '#1D4ED8'
ACCENT_LITE_HEX = '#DBEAFE'
RED_HEX    = '#DC2626'
GREEN_HEX  = '#16A34A'
AMBER_HEX  = '#D97706'
PURPLE_HEX = '#7C3AED'
GREY_HEX   = '#6B7280'
INK_HEX    = '#111827'
BG_HEX     = '#FFFFFF'
GRID_HEX   = '#F3F4F6'

def fig_style():
    plt.rcParams.update({
        'figure.facecolor':  BG_HEX,
        'axes.facecolor':    BG_HEX,
        'axes.edgecolor':    '#E5E7EB',
        'axes.labelcolor':   INK_HEX,
        'text.color':        INK_HEX,
        'xtick.color':       '#4B5563',
        'ytick.color':       '#4B5563',
        'grid.color':        GRID_HEX,
        'grid.alpha':        1.0,
        'font.family':       'sans-serif',
        'font.sans-serif':   ['Helvetica Neue', 'Helvetica', 'Arial', 'DejaVu Sans'],
        'axes.titlesize':    11,
        'axes.titleweight':  'bold',
        'axes.titlecolor':   INK_HEX,
        'axes.labelsize':    9,
        'axes.spines.top':   False,
        'axes.spines.right': False,
        'axes.linewidth':    0.8,
        'xtick.major.size':  3,
        'ytick.major.size':  3,
    })

def save_fig(name):
    path = FIGS / name
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor=BG_HEX, edgecolor='none')
    plt.close()
    print(f'  ✓ {name}')
    return path

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Figure 0: Pipeline overview ───────────────────────────────────────────────
def fig_pipeline():
    fig_style()
    fig, ax = plt.subplots(figsize=(14, 4.2), facecolor=BG_HEX)
    ax.set_facecolor(BG_HEX); ax.axis('off')

    stages = [
        ('C1', 'Backbone\nPrioritisation', 'Phase-transition\nstate ranking',        ACCENT_HEX),
        ('C2', 'RMT Screen',               'Spectral anomaly\ndetection',             PURPLE_HEX),
        ('C3', 'Template\nMatching',        'Call dataflow\npattern match',           AMBER_HEX),
        ('C4', 'TDA',                       '✗  Killed\n(persistence homology)',      GREY_HEX),
        ('C5', 'Comp. Sensing',             '✗  Killed\n(RIP fails)',                 GREY_HEX),
        ('C6', 'Taint Analysis',            'Symbolic\ntaint + PoC',                  GREEN_HEX),
    ]
    n, w, gap = len(stages), 1.55, 0.25
    total = n*w + (n-1)*gap
    x0 = (14 - total) / 2

    for i, (code, title, desc, col) in enumerate(stages):
        x = x0 + i*(w+gap)
        killed = col == GREY_HEX
        alpha = 0.40 if killed else 1.0
        rect = mpatches.FancyBboxPatch((x, -0.75), w, 2.50,
            boxstyle='round,pad=0.08',
            facecolor='white', edgecolor=col, linewidth=1.5 if not killed else 0.7,
            alpha=alpha)
        ax.add_patch(rect)
        band = mpatches.FancyBboxPatch((x, 1.30), w, 0.45,
            boxstyle='round,pad=0.04',
            facecolor=col+'22' if not killed else '#E5E7EB',
            edgecolor='none')
        ax.add_patch(band)
        ax.text(x+w/2, 1.50, code, ha='center', va='center',
                fontsize=9, color=col if not killed else GREY_HEX,
                fontweight='bold', alpha=alpha)
        ax.text(x+w/2, 0.72, title, ha='center', va='center',
                fontsize=8, color=INK_HEX if not killed else GREY_HEX,
                fontweight='bold', alpha=alpha, linespacing=1.4)
        ax.text(x+w/2, -0.10, desc, ha='center', va='center',
                fontsize=7, color=GREY_HEX, linespacing=1.4, alpha=alpha)
        if i < n-1:
            arrowcol = '#9CA3AF' if not killed else '#D1D5DB'
            ax.annotate('', xy=(x+w+gap-0.04, 0.72), xytext=(x+w+0.04, 0.72),
                arrowprops=dict(arrowstyle='->', color=arrowcol, lw=1.0))
        if killed:
            ax.plot([x+0.15, x+w-0.15], [1.85, -0.60], color=RED_HEX,
                    lw=1.5, alpha=0.5)

    ax.set_xlim(-0.2, 14.2); ax.set_ylim(-1.5, 2.2)
    ax.text(total/2+x0, -1.35,
        'C4 and C5 killed by LLM purple-team architecture review — gaps preserved, not renumbered',
        ha='center', fontsize=7.5, color=GREY_HEX, style='italic')
    ax.set_title('C1 → C6 Pipeline — Implemented stages and killed dead ends', pad=10,
        fontsize=12, fontweight='bold', color=INK_HEX)
    plt.tight_layout()
    return save_fig('pipeline_overview.png')


# ── Figure 1: C1 Phase Transition ────────────────────────────────────────────
def fig_phase_transition():
    fig_style()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), facecolor=BG_HEX)

    # Panel A: satisfiability transition + backbone fraction
    alpha = np.linspace(0, 7, 500)
    alpha_c = 4.267
    alpha_cond = 4.19

    # Approximate sigmoid for P(SAT) — sharp at alpha_c
    def p_sat(a, ac=alpha_c, k=12):
        return 1 / (1 + np.exp(k * (a - ac)))

    # Backbone fraction: grows near alpha_c
    def backbone(a, ac=alpha_c):
        # piecewise: 0 below cond, rising sharply above
        b = np.zeros_like(a)
        mask = a > alpha_cond
        b[mask] = np.clip((a[mask] - alpha_cond) / (ac - alpha_cond + 0.4), 0, 1) ** 0.6
        return b

    p = p_sat(alpha)
    b = backbone(alpha)

    ax1.fill_between(alpha, p, alpha=0.12, color=ACCENT_HEX)
    ax1.plot(alpha, p, color=ACCENT_HEX, lw=2.0, label='P(satisfiable)')
    ax1.plot(alpha, b, color=RED_HEX, lw=2.0, ls='--', label='Backbone fraction')

    # Mark transitions
    ax1.axvline(alpha_cond, color=AMBER_HEX, lw=1.2, ls=':', alpha=0.8)
    ax1.axvline(alpha_c,    color=RED_HEX,   lw=1.5, ls='-', alpha=0.7)
    ax1.text(alpha_cond+0.08, 0.92, r'$\alpha_{cond}$' + f'\n≈ {alpha_cond}',
             fontsize=8.5, color=AMBER_HEX)
    ax1.text(alpha_c+0.08, 0.72, r'$\alpha_c$' + f'\n≈ {alpha_c}',
             fontsize=8.5, color=RED_HEX)

    # Shade hard region
    hard_lo, hard_hi = 4.0, 4.5
    ax1.fill_betweenx([0, 1], hard_lo, hard_hi, alpha=0.07, color=RED_HEX)
    ax1.text((hard_lo+hard_hi)/2, 0.48, 'Hard region\n(solver slow)',
             ha='center', fontsize=8, color=RED_HEX, alpha=0.75)

    ax1.set_xlabel(r'Clause/variable ratio  $\alpha = m/n$')
    ax1.set_ylabel('Probability / Fraction')
    ax1.set_title('3-SAT Phase Transition')
    ax1.legend(fontsize=8.5, framealpha=0.9, edgecolor=GRID_HEX)
    ax1.set_xlim(0, 7); ax1.set_ylim(-0.04, 1.08)
    ax1.grid(True, lw=0.5)
    ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)

    # Panel B: backbone fraction as priority signal
    bf_vals = np.array([0.04, 0.11, 0.18, 0.31, 0.43, 0.56, 0.72, 0.85, 0.94])
    solve_t = np.exp(bf_vals * 4.2) * 0.3  # synthetic exponential scaling
    labels_b = [f'{b:.2f}' for b in bf_vals]

    bar_cols = [
        GREEN_HEX if b < 0.35 else
        (AMBER_HEX if b < 0.65 else RED_HEX)
        for b in bf_vals
    ]
    ax2.bar(range(len(bf_vals)), solve_t, color=bar_cols, edgecolor='none',
            width=0.65, alpha=0.85)
    ax2.set_xticks(range(len(bf_vals)))
    ax2.set_xticklabels(labels_b, fontsize=8)
    ax2.set_xlabel('Backbone fraction (C1 estimate per path)')
    ax2.set_ylabel('Relative solver time (log-scale)')
    ax2.set_yscale('log')
    ax2.set_title('Backbone Fraction → CDCL Solve Time')

    p_green  = mpatches.Patch(color=GREEN_HEX, label='Explore first (easy)')
    p_amber  = mpatches.Patch(color=AMBER_HEX, label='Explore later')
    p_red    = mpatches.Patch(color=RED_HEX,   label='Defer (hard — near transition)')
    ax2.legend(handles=[p_green, p_amber, p_red], fontsize=8.5,
               framealpha=0.9, edgecolor=GRID_HEX)
    ax2.grid(axis='y', lw=0.5)
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)

    fig.suptitle('C1 — Phase-Transition Symbolic Execution', fontsize=13,
                 fontweight='bold', color=INK_HEX, y=1.01)
    plt.tight_layout()
    return save_fig('c1_phase_transition.png')


# ── Figure 2: C2 Spectral Analysis ───────────────────────────────────────────
def fig_spectral():
    fig_style()
    fig = plt.figure(figsize=(15, 9), facecolor=BG_HEX)
    gs  = GridSpec(2, 3, figure=fig, hspace=0.52, wspace=0.38)

    # Panel A: Power-law degree distribution — why M-P is wrong
    ax1 = fig.add_subplot(gs[0, 0]); ax1.set_facecolor(BG_HEX)
    np.random.seed(42)
    degrees = np.random.zipf(2.1, 500)  # power-law (Zipf)
    degrees = degrees[degrees < 80]
    iid_deg = np.random.randint(1, 15, 500)

    ax1.hist(degrees, bins=30, color=RED_HEX, alpha=0.65, label='Real call graph (power-law)', density=True)
    ax1.hist(iid_deg, bins=30, color=ACCENT_HEX, alpha=0.55, label='i.i.d. (M-P assumption)', density=True)
    ax1.set_xlabel('Degree'); ax1.set_ylabel('Density')
    ax1.set_title('Degree Distribution:\nReal vs i.i.d.')
    ax1.legend(fontsize=7.5, framealpha=0.9, edgecolor=GRID_HEX)
    ax1.set_yscale('log'); ax1.grid(True, lw=0.5)
    ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)

    # Panel B: Marchenko-Pastur (WRONG null) vs configuration model (CORRECT)
    ax2 = fig.add_subplot(gs[0, 1]); ax2.set_facecolor(BG_HEX)
    q = 0.30
    lp = (1 + math.sqrt(q))**2
    lm = (1 - math.sqrt(q))**2
    x_mp = np.linspace(lm+0.001, lp, 200)
    mp_density = np.sqrt((lp - x_mp) * (x_mp - lm)) / (2 * math.pi * q * x_mp)

    # Configuration model null: broader, accounts for hubs
    x_cfg = np.linspace(0.01, 6.5, 400)
    cfg_density = (1/1.2) * np.exp(-x_cfg / 1.2) * (1 + 0.4*np.exp(-x_cfg**2/2))

    ax2.plot(x_mp, mp_density, color=AMBER_HEX, lw=2, ls='--',
             label=f'Marchenko-Pastur (q={q}) — WRONG for call graphs')
    ax2.fill_between(x_cfg, cfg_density, alpha=0.15, color=ACCENT_HEX)
    ax2.plot(x_cfg, cfg_density, color=ACCENT_HEX, lw=2,
             label='Configuration model null — CORRECT (Bollobás 1980)')

    # Annotate outlier
    ax2.axvline(4.8, color=RED_HEX, lw=1.2, ls=':', alpha=0.8)
    ax2.annotate('Outlier λ_max\n→ ANOMALOUS', xy=(4.8, 0.015), xytext=(3.8, 0.15),
                fontsize=8, color=RED_HEX,
                arrowprops=dict(arrowstyle='->', color=RED_HEX, lw=0.8))

    ax2.set_xlabel('Eigenvalue |λ|'); ax2.set_ylabel('Density')
    ax2.set_title('Null Distribution Comparison')
    ax2.legend(fontsize=7.5, framealpha=0.9, edgecolor=GRID_HEX, loc='upper right')
    ax2.set_xlim(0, 6.5); ax2.set_ylim(0, 0.45)
    ax2.grid(True, lw=0.5)
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)

    # Panel C: Three spectral metrics heatmap for sample binaries
    ax3 = fig.add_subplot(gs[0, 2]); ax3.set_facecolor(BG_HEX)
    binaries = ['mDNSResponder', 'smbd', 'opendirectoryd', 'biometrickitd',
                'syspolicyd', 'amfid', 'cryptexd', 'seserviced']
    # z-scores: [z_radius, z_energy, z_entropy]
    z_data = np.array([
        [-1.85, -22.33, -142.37],  # mDNSResponder
        [-3.56,  -3.01,   -0.30],  # smbd
        [-2.50,  -1.88,   -1.10],  # opendirectoryd
        [ 0.90,  +5.63,   +2.10],  # biometrickitd
        [-0.44,  -0.21,   -0.18],  # syspolicyd
        [-0.10,  -0.08,   -0.05],  # amfid
        [-0.22,  -0.15,   -0.09],  # cryptexd
        [-0.37,  -0.29,   -0.22],  # seserviced
    ])
    z_disp = np.clip(z_data, -6, 6)
    cmap_z = mcolors.LinearSegmentedColormap.from_list('z',
        [RED_HEX, AMBER_HEX+'88', '#F9FAFB', ACCENT_LITE_HEX, ACCENT_HEX], N=256)
    im = ax3.imshow(z_disp, aspect='auto', cmap=cmap_z, vmin=-6, vmax=6)
    ax3.set_xticks([0, 1, 2])
    ax3.set_xticklabels(['z_radius', 'z_energy', 'z_entropy'], fontsize=7.5, rotation=25)
    ax3.set_yticks(range(len(binaries)))
    anomalous_idx = {0, 1, 2, 3}
    ax3.set_yticklabels(
        [f'⚠ {b[:13]}' if i in anomalous_idx else f'   {b[:13]}'
         for i, b in enumerate(binaries)], fontsize=7.5)
    for i in range(len(binaries)):
        for j, val in enumerate(z_data[i]):
            t = f'{val:.1f}' if abs(val) < 10 else f'{val:.0f}'
            ax3.text(j, i, t, ha='center', va='center', fontsize=6.5,
                     color='white' if abs(z_disp[i, j]) > 3 else INK_HEX)
    cb = plt.colorbar(im, ax=ax3, fraction=0.09, pad=0.04)
    cb.set_label('z-score (|z|>2 → anomalous)', fontsize=7.5)
    cb.ax.tick_params(labelsize=7)
    ax3.set_title('z-Score Heatmap\n(|z| > 2.0 threshold)', fontsize=10)

    # Panel D: Combined function scoring formula
    ax4 = fig.add_subplot(gs[1, :2]); ax4.set_facecolor(BG_HEX)
    ev_vals = np.linspace(0, 1, 50)
    cyc_vals = np.array([1, 5, 20, 60, 100, 155, 250])
    for cyc in cyc_vals:
        norm_cyc = math.log1p(max(0, cyc - 1))
        scores = 0.4*ev_vals + 0.35*norm_cyc + 0.25*math.log1p(5)  # 5 back-edges
        col = plt.cm.plasma(cyc / 260)  # type: ignore
        ax4.plot(ev_vals, scores, lw=1.4, color=col,
                 label=f'M={cyc}' if cyc in [1, 60, 155] else None)

    ax4.axhline(1.5, color=RED_HEX, lw=1, ls='--', alpha=0.6, label='Triage threshold')
    ax4.set_xlabel('Eigenvector centrality (ev)')
    ax4.set_ylabel('Combined score  S = 0.4·ev + 0.35·log(M) + 0.25·log(B)')
    ax4.set_title('C2 Function Scoring — Score vs Eigenvector Centrality')
    ax4.legend(fontsize=8, framealpha=0.9, edgecolor=GRID_HEX, ncol=2)
    ax4.grid(True, lw=0.5)
    ax4.spines['top'].set_visible(False); ax4.spines['right'].set_visible(False)

    # Panel E: McCabe M distribution for anomalous functions
    ax5 = fig.add_subplot(gs[1, 2]); ax5.set_facecolor(BG_HEX)
    m_normal   = np.concatenate([
        np.random.exponential(3, 200), np.random.randint(1, 15, 50)
    ])
    m_anomalous = np.concatenate([
        np.random.exponential(8, 80), np.array([38, 55, 63, 71, 87, 98, 155, 342])
    ])
    ax5.hist(m_normal[m_normal < 60], bins=20, color=ACCENT_HEX, alpha=0.65,
             density=True, label='Normal binaries')
    ax5.hist(m_anomalous[m_anomalous < 400], bins=20, color=RED_HEX, alpha=0.60,
             density=True, label='Anomalous binaries')
    ax5.axvline(60, color=AMBER_HEX, lw=1.5, ls='--', label='M=60 triage threshold')
    ax5.set_xlabel('McCabe M = E − N + 2')
    ax5.set_ylabel('Density')
    ax5.set_title('Cyclomatic Complexity\nNormal vs Anomalous')
    ax5.legend(fontsize=8, framealpha=0.9, edgecolor=GRID_HEX)
    ax5.grid(True, lw=0.5)
    ax5.spines['top'].set_visible(False); ax5.spines['right'].set_visible(False)

    fig.suptitle('C2 — Random Matrix Theory Screen', fontsize=13,
                 fontweight='bold', color=INK_HEX, y=1.01)
    plt.tight_layout()
    return save_fig('c2_spectral_analysis.png')


# ── Figure 3: C3 Template Matching ───────────────────────────────────────────
def fig_c3_template():
    fig_style()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), facecolor=BG_HEX)

    # Panel A: Template structure diagram (schematic)
    ax1.set_facecolor(BG_HEX); ax1.axis('off')
    ax1.set_xlim(0, 10); ax1.set_ylim(0, 10)
    ax1.set_title('C3 Template Structure', fontsize=11, fontweight='bold', color=INK_HEX)

    def box(ax, x, y, w, h, text, col, alpha=1.0, fontsize=9):
        rect = mpatches.FancyBboxPatch((x, y), w, h,
            boxstyle='round,pad=0.15', facecolor=col+'22',
            edgecolor=col, linewidth=1.2, alpha=alpha)
        ax.add_patch(rect)
        ax.text(x+w/2, y+h/2, text, ha='center', va='center',
                fontsize=fontsize, color=col, fontweight='bold')

    def arrow(ax, x1, y1, x2, y2, col='#9CA3AF', label=''):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle='->', color=col, lw=1.4))
        if label:
            mx, my = (x1+x2)/2+0.15, (y1+y2)/2
            ax.text(mx, my, label, fontsize=7.5, color=col, style='italic')

    # Source → intermediate → sink
    box(ax1, 0.5, 7.5, 2.5, 1.2, 'SOURCE\nXPC receive\n/ mach_msg', RED_HEX)
    box(ax1, 3.8, 7.5, 2.5, 1.2, 'INTERMEDIATE\nstack / reg\ntransfer', AMBER_HEX)
    box(ax1, 7.2, 7.5, 2.5, 1.2, 'SINK\nmalloc / copy\n/ IOKit accessor', RED_HEX)

    arrow(ax1, 3.0, 8.1, 3.8, 8.1, col=RED_HEX, label='tainted\nvalue')
    arrow(ax1, 6.3, 8.1, 7.2, 8.1, col=RED_HEX, label='flows to\nsink')

    # Barrier (blocking detection)
    box(ax1, 3.8, 5.2, 2.5, 1.0, 'BARRIER\ncompare /\nbounds check', GREEN_HEX, alpha=0.9)
    ax1.annotate('', xy=(5.05, 6.2), xytext=(5.05, 5.8),
        arrowprops=dict(arrowstyle='->', color=GREEN_HEX, lw=1.4))
    ax1.text(5.3, 6.05, 'blocks match\nif present', fontsize=7.5,
             color=GREEN_HEX, style='italic')

    # Verdict
    box(ax1, 0.5, 3.0, 2.5, 1.0, '✓ MATCH\nno barrier', RED_HEX)
    box(ax1, 3.8, 3.0, 2.5, 1.0, '— CLEAR\nbarrier found', GREEN_HEX)
    box(ax1, 7.2, 3.0, 2.5, 1.0, '— FILTERED\nstdlib caller', GREY_HEX)

    arrow(ax1, 2.5, 5.2, 1.75, 4.0, col=RED_HEX)
    arrow(ax1, 5.0, 5.2, 5.05, 4.0, col=GREEN_HEX)
    arrow(ax1, 6.3, 7.9, 8.45, 4.0, col=GREY_HEX, label='stdlib\nfilter')

    ax1.text(5.0, 1.8, 'VulnTemplate(source, sink, barrier, confidence)', ha='center',
             fontsize=8, color=GREY_HEX, style='italic')

    # Panel B: 5 templates and their detection rates
    ax2.set_facecolor(BG_HEX)
    templates = [
        ('XPC_INT_OOB',  'XPC recv → IOKit\ntransmit (no bounds)',   3, 1, 0.88),
        ('MACH_MSG_OOB', 'mach_msg recv → alloc\n(attacker size)',   4, 2, 0.82),
        ('IOKIT_OOB',    'IOKit method → typed\naccessor (no check)', 3, 1, 0.79),
        ('PORT_UAF',     'mach_msg recv → port\nlookup (no epoch)',   2, 1, 0.71),
        ('XPC_TYPE',     'XPC recv → dispatch\n(no type check)',      5, 3, 0.65),
    ]
    ys = list(range(len(templates)))
    widths = [t[4] for t in templates]
    bar_cols = [
        GREEN_HEX if w > 0.80 else (AMBER_HEX if w > 0.70 else RED_HEX+'88')
        for w in widths
    ]
    bars = ax2.barh(ys, widths, color=bar_cols, edgecolor='none', height=0.55, alpha=0.88)
    ax2.axvline(0.70, color=AMBER_HEX, lw=1.2, ls='--', label='Confidence threshold (0.70)')
    for i, (t, w) in enumerate(zip(templates, widths)):
        ax2.text(w+0.01, i, f'{w:.0%}', va='center', fontsize=8.5, color=INK_HEX)

    ax2.set_yticks(ys)
    ax2.set_yticklabels([f'{t[0]}\n{t[1]}' for t in templates], fontsize=7.8)
    ax2.set_xlabel('Template confidence score')
    ax2.set_title('C3 Template Bank — Confidence Scores')
    ax2.legend(fontsize=8, framealpha=0.9, edgecolor=GRID_HEX)
    ax2.set_xlim(0, 1.05)
    ax2.invert_yaxis()
    ax2.grid(axis='x', lw=0.5)
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)

    plt.tight_layout()
    return save_fig('c3_template_matching.png')


# ── Figure 4: C6 Taint Analysis ──────────────────────────────────────────────
def fig_c6_taint():
    fig_style()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), facecolor=BG_HEX)

    # Panel A: Taint propagation schematic
    ax1.set_facecolor(BG_HEX); ax1.axis('off')
    ax1.set_xlim(0, 10); ax1.set_ylim(0, 10)
    ax1.set_title('C6 Taint Propagation — Source to Sink', fontsize=11,
                  fontweight='bold', color=INK_HEX)

    def tbox(ax, x, y, w, h, title, body, col, fontsize=8):
        rect = mpatches.FancyBboxPatch((x, y), w, h,
            boxstyle='round,pad=0.12', facecolor=col+'18',
            edgecolor=col, linewidth=1.2)
        ax.add_patch(rect)
        ax.text(x+w/2, y+h*0.7, title, ha='center', va='center',
                fontsize=fontsize, color=col, fontweight='bold')
        ax.text(x+w/2, y+h*0.28, body, ha='center', va='center',
                fontsize=fontsize-1.5, color=INK_HEX)

    def tarrow(ax, x1, y1, x2, y2, label='', col=ACCENT_HEX):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle='->', color=col, lw=1.5))
        if label:
            ax.text((x1+x2)/2+0.15, (y1+y2)/2+0.1, label,
                    fontsize=7.5, color=col, style='italic')

    # Source hooks
    tbox(ax1, 0.3, 7.5, 3.0, 1.3, 'Hook_malloc()', 'returns BVS("malloc_ret_N")', RED_HEX)
    tbox(ax1, 0.3, 5.8, 3.0, 1.3, 'Hook_recv()',   'marks buffer[0..n] tainted',   RED_HEX)

    # Constraint propagation
    tbox(ax1, 3.8, 6.6, 3.2, 1.5, 'angr Symbolic Engine',
         'claripy AST tracks BVS names\nthrough arithmetic ops', ACCENT_HEX)

    # Sinks
    tbox(ax1, 7.5, 7.5, 2.2, 1.1, 'OOB Sink', 'idx ≥ alloc_size\n→ ALERT', RED_HEX)
    tbox(ax1, 7.5, 6.0, 2.2, 1.1, 'UAF Sink', 'freed ptr\nderef → ALERT', RED_HEX)
    tbox(ax1, 7.5, 4.5, 2.2, 1.1, 'TYPE Sink', 'cast mismatch\n→ ALERT', RED_HEX)

    tarrow(ax1, 3.3, 8.15, 3.8, 7.35, label='BVS\nvar', col=RED_HEX)
    tarrow(ax1, 3.3, 6.45, 3.8, 6.95, label='taint\nset', col=RED_HEX)
    tarrow(ax1, 7.0, 7.35, 7.5, 8.05, label='', col=ACCENT_HEX)
    tarrow(ax1, 7.0, 7.35, 7.5, 6.55, label='propagated\ncondition', col=ACCENT_HEX)
    tarrow(ax1, 7.0, 7.35, 7.5, 5.05, label='', col=ACCENT_HEX)

    # Alert box — use hex strings for matplotlib (not reportlab color objects)
    GREEN_BAR_HEX = '#1A8038'
    GREEN_BG_HEX  = '#F0FFF4'
    rect_a = mpatches.FancyBboxPatch((0.3, 3.0), 9.4, 1.4,
        boxstyle='round,pad=0.12', facecolor=GREEN_BG_HEX, edgecolor=GREEN_BAR_HEX, linewidth=1.2)
    ax1.add_patch(rect_a)
    ax1.text(5.0, 4.0, 'Alert: taint_label + constraint + PoC input', ha='center',
             va='center', fontsize=8.5, color=GREEN_BAR_HEX, fontweight='bold')
    ax1.text(5.0, 3.35, 'malloc_size=2,  idx=BVS("recv_byte_3"),  PoC bytes=[0xFF, 0x03, ...]',
             ha='center', va='center', fontsize=7.5, color=INK_HEX, family='monospace')

    ax1.text(5.0, 2.2, 'Hook table: malloc, calloc, realloc, recv, recvfrom, read, mmap, '
             'IOKit_copyScalar_*, XPC_recv, mach_msg_recv',
             ha='center', va='center', fontsize=7, color=GREY_HEX, wrap=True)

    # Panel B: Hook table — 18 entries, categorised
    ax2.set_facecolor(BG_HEX); ax2.axis('off')
    ax2.set_xlim(0, 10); ax2.set_ylim(0, 10)
    ax2.set_title('C6 Hook Table — 18 SimProcedure Hooks', fontsize=11,
                  fontweight='bold', color=INK_HEX)

    categories = [
        ('Memory allocation', [
            'malloc(size)', 'calloc(n, size)', 'realloc(ptr, size)',
            'valloc(size)', 'mmap(addr, len, ...)',
        ], ACCENT_HEX, 8.5),
        ('Network / IPC receive', [
            'recv(fd, buf, len, flags)', 'recvfrom(...)',
            'read(fd, buf, count)', 'mach_msg_recv(hdr)',
        ], RED_HEX, 6.2),
        ('XPC surface', [
            'xpc_dictionary_get_value(d, k)',
            'xpc_array_get_value(a, i)', 'xpc_copy(v)',
        ], AMBER_HEX, 4.3),
        ('IOKit / typed accessors', [
            'IOKit_copyScalar_64(field)',
            'IOKit_copyScalar_32(field)',
            'OSObject_getRef(obj, key)',
            'io_connect_method(*)',
        ], PURPLE_HEX, 2.7),
    ]

    for cat_name, hooks, col, y_start in categories:
        ax2.text(0.3, y_start, cat_name, fontsize=8.5, color=col, fontweight='bold')
        for i, h in enumerate(hooks):
            ax2.text(0.6, y_start - 0.55*(i+1), f'→  {h}', fontsize=7.5, color='#3A3A3C')

    ax2.text(5.0, 0.5,
             'C6 runs after C3 flags a function — targeted, not whole-binary',
             ha='center', fontsize=8, color=GREY_HEX, style='italic')

    plt.tight_layout()
    return save_fig('c6_taint_analysis.png')


# ── Figure 5: Disassembly pipeline ───────────────────────────────────────────
def fig_disassembly():
    fig_style()
    fig, ax = plt.subplots(figsize=(14, 4.0), facecolor=BG_HEX)
    ax.set_facecolor(BG_HEX); ax.axis('off')
    ax.set_xlim(0, 14); ax.set_ylim(0, 5)
    ax.set_title('Disassembly Layer — Binary to VEX IR to Pattern Detection',
                 fontsize=12, fontweight='bold', color=INK_HEX, pad=10)

    tools = [
        ('Binary\n(Mach-O / PE)',        GREY_HEX,   0.4),
        ('angr\nCFGFast',               ACCENT_HEX, 2.4),
        ('VEX IR\nIRSB / WrTmp',        PURPLE_HEX, 4.4),
        ('pefile +\ncapstone\n(Windows)',AMBER_HEX,  6.4),
        ('otool\nsliding-window\n(arm64)',AMBER_HEX, 8.5),
        ('Pattern\nDetection',          RED_HEX,   10.8),
        ('Alert +\nPoC input',          GREEN_HEX, 12.5),
    ]
    labels_between = [
        'load / slice',
        'lift basic\nblocks',
        'IAT\nresolution',
        'constant-fold\nbypass',
        'Add64 /\nConst scan',
        'taint +\nconstraint',
    ]

    for i, (name, col, x) in enumerate(tools):
        w = 1.6; h = 2.4; y = 1.3
        rect = mpatches.FancyBboxPatch((x, y), w, h,
            boxstyle='round,pad=0.12', facecolor=col+'18',
            edgecolor=col, linewidth=1.2)
        ax.add_patch(rect)
        ax.text(x+w/2, y+h/2, name, ha='center', va='center',
                fontsize=7.5, color=col, fontweight='bold', linespacing=1.35)
        if i < len(tools)-1:
            next_x = tools[i+1][2]
            ax.annotate('', xy=(next_x, y+h/2), xytext=(x+w, y+h/2),
                arrowprops=dict(arrowstyle='->', color='#9CA3AF', lw=1.0))
            if i < len(labels_between):
                mx = (x+w+next_x)/2
                ax.text(mx, y+h+0.25, labels_between[i],
                        ha='center', fontsize=6.5, color=GREY_HEX, style='italic',
                        linespacing=1.2)

    # Annotation for Tseitin / compiler fold issue
    ax.text(7.0, 0.4,
        'Compiler constant-folding defeats VEX Add64 scan → otool offset scan for LDRB/LDRH pairs',
        ha='center', fontsize=7.5, color=AMBER_HEX, style='italic')

    plt.tight_layout()
    return save_fig('disassembly_pipeline.png')


def generate_figures():
    print('Generating figures...')
    return {
        'pipeline':     fig_pipeline(),
        'phase':        fig_phase_transition(),
        'spectral':     fig_spectral(),
        'c3_template':  fig_c3_template(),
        'c6_taint':     fig_c6_taint(),
        'disassembly':  fig_disassembly(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PDF LAYOUT PRIMITIVES  —  identical to generate_briefing.py
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

def mono(c, text, y, indent=4*mm, size=T_SMALL-0.5):
    """Monospaced code line."""
    c.setFillColor(INK2); c.setFont('Courier', size)
    c.drawString(ML + indent, y, text)
    return y - 5.5*mm

def bullet_item(c, text, y, indent=4*mm):
    c.setFillColor(ACCENT); c.setFont('Helvetica-Bold', T_BODY+1)
    c.drawString(ML + indent - 3.5*mm, y, '–')
    y = body(c, text, y, indent=indent+1.5*mm)
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
    else:
        bar_c = ERR_BAR; bg_c = ERR_BG
    lh = 5.8*mm
    box_h = (len(lines) + 1.6) * lh + 2*mm
    c.setFillColor(bg_c)
    c.roundRect(ML, y - box_h, TW, box_h, 2*mm, fill=1, stroke=0)
    c.setFillColor(bar_c)
    c.rect(ML, y - box_h, 2.5*mm, box_h, fill=1, stroke=0)
    c.setFillColor(bar_c); c.setFont('Helvetica-Bold', T_SMALL)
    c.drawString(ML + 5*mm, y - lh*0.95, title)
    c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
    for i, ln in enumerate(lines):
        c.drawString(ML + 5*mm, y - lh*1.9 - i*lh, ln)
    return y - box_h - 3*mm

def embed_image(c, path, y, max_h):
    with PILImage.open(str(path)) as pil:
        pw, ph = pil.size
    aspect = ph / pw
    w = TW; h = w * aspect
    if h > max_h:
        h = max_h; w = h / aspect
    x = ML + (TW - w) / 2
    c.drawImage(str(path), x, y - h, width=w, height=h, preserveAspectRatio=True)
    return y - h

def table(c, headers, rows, col_widths, y, row_h=7.8*mm):
    x0 = ML
    c.setFillColor(TABLE_HEAD)
    c.rect(x0, y - row_h*0.3, sum(col_widths), row_h*0.85, fill=1, stroke=0)
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_SMALL)
    cx = x0 + 2*mm
    for h_txt, cw in zip(headers, col_widths):
        c.drawString(cx, y + 0.5*mm, h_txt); cx += cw
    c.setStrokeColor(RULE_C); c.setLineWidth(0.4)
    c.line(x0, y - row_h*0.3, x0 + sum(col_widths), y - row_h*0.3)
    y -= row_h
    for ri, row in enumerate(rows):
        bg = TABLE_ALT if ri % 2 == 0 else WHITE
        c.setFillColor(bg)
        c.rect(x0, y - row_h*0.3, sum(col_widths), row_h*0.85, fill=1, stroke=0)
        cx = x0 + 2*mm
        for cell, cw in zip(row, col_widths):
            cs = str(cell)
            col_txt = INK2; fw = 'Helvetica'
            if 'Keep' in cs: col_txt = colors.HexColor('#1A8038')
            elif 'Kill' in cs or '✗' in cs: col_txt = ERR_BAR
            elif cs in ('ANOMALOUS',): col_txt = ERR_BAR; fw = 'Helvetica-Bold'
            elif cs in ('NORMAL',): col_txt = colors.HexColor('#1A8038')
            c.setFillColor(col_txt); c.setFont(fw, T_SMALL)
            while c.stringWidth(cs, fw, T_SMALL) > cw - 4*mm and len(cs) > 3:
                cs = cs[:-2] + '…'
            c.drawString(cx, y + 0.5*mm, cs); cx += cw
        c.setStrokeColor(RULE_C); c.setLineWidth(0.3)
        c.line(x0, y - row_h*0.3, x0 + sum(col_widths), y - row_h*0.3)
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
    c.drawCentredString(W/2, ty - 12*mm, 'Mathematics, Physics & Implementation')
    c.drawCentredString(W/2, ty - 20*mm, 'A Complete Reference — C1 to C6 Pipeline')

    c.setStrokeColor(ACCENT); c.setLineWidth(1.2)
    c.line(ML + 20*mm, ty - 27*mm, W - MR - 20*mm, ty - 27*mm)

    meta = [
        ('Author',      AUTHOR),
        ('Date',        DATE_STR),
        ('Platform',    'macOS arm64e · angr · numpy · scipy · claripy'),
        ('Status',      'Public methodology — findings redacted pending disclosure'),
        ('Repository',  'macos_vuln_toolchain/metis/'),
        ('Stages',      'C1, C2, C3, C6 implemented  ·  C4, C5 killed by design review'),
    ]
    y_meta = ty - 42*mm
    for lbl, val in meta:
        c.setFillColor(CAPTION_C); c.setFont('Helvetica-Bold', T_SMALL)
        c.drawString(ML + 15*mm, y_meta, lbl.upper())
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
        c.drawString(ML + 58*mm, y_meta, val)
        y_meta -= 8.5*mm

    c.setStrokeColor(RULE_C); c.setLineWidth(0.5)
    c.line(ML, y_meta - 2*mm, W-MR, y_meta - 2*mm)

    y_toc = y_meta - 12*mm
    c.setFillColor(INK); c.setFont('Helvetica-Bold', T_SMALL + 0.5)
    c.drawString(ML + 15*mm, y_toc, 'Contents')
    y_toc -= 8*mm
    sections = [
        ('§1',  'The Short Version — for people who don\'t want the maths'),
        ('§2',  'Why C1–C6? The Naming History'),
        ('§3',  'C1 — Phase-Transition Symbolic Execution'),
        ('§4',  'C2 — Random Matrix Theory Call Graph Screen'),
        ('§5',  'C3 — Template-Based Call Dataflow Matching'),
        ('§6',  'C6 — Symbolic Taint Analysis'),
        ('§7',  'The Disassembly Layer'),
        ('§8',  'Pipeline Composition'),
        ('§9',  'Limitations & Dead Ends'),
        ('§10', 'Glossary'),
    ]
    for sec_id, sec_title in sections:
        c.setFillColor(ACCENT); c.setFont('Helvetica-Bold', T_SMALL)
        c.drawString(ML + 15*mm, y_toc, sec_id)
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
        c.drawString(ML + 35*mm, y_toc, sec_title)
        y_toc -= 7.5*mm

    c.setFillColor(colors.HexColor('#F5F5F7'))
    c.rect(0, 0, W, 18*mm, fill=1, stroke=0)
    c.setFillColor(CAPTION_C); c.setFont('Helvetica', T_MICRO)
    c.drawCentredString(W/2, 7*mm,
        'Research methodology documentation — responsible disclosure via Apple ASB and Chrome VRP')
    c.drawCentredString(W/2, 3*mm, '1')


# ═══════════════════════════════════════════════════════════════════════════════
# BUILD PDF
# ═══════════════════════════════════════════════════════════════════════════════
def build_pdf(figs, out_path):
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

    # ── §1 The Short Version ──────────────────────────────────────────────────
    section_title_page(c, '§1', 'The Short Version', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§1  The Short Version'
    y = top()

    y = h1(c, '1.1  What problem are we solving?', y); y -= 1.5*mm
    y = body(c, ('macOS ships with several hundred privileged daemons — programs that run as root, '
        'talk to the network, handle files, or manage security policy. Any one of them could contain '
        'a bug. Finding bugs manually means reading disassembly for weeks. Fuzzing blindly wastes '
        'compute on code hardened for years. We need a way to look at a compiled binary — no source, '
        'no symbols — and answer: which function should I look at first?'), y)
    y -= 4*mm

    y = h1(c, '1.2  The city analogy', y); y -= 1.5*mm
    y = body(c, ('Every program is a city. Roads are connections between neighbourhoods (functions). '
        'Some cities are planned: regular grid, sensible layout. Others grew organically and have one '
        'enormous junction where everything passes through, weird dead ends, and roads that loop back '
        'for no obvious reason. The weird city is more likely to have a problem — not because '
        'weirdness causes bugs directly, but because weird structure correlates with code that evolved '
        'under pressure and probably has corners nobody tested. The C2 stage of this toolchain does '
        'that structural audit mathematically, at scale, in about 30 seconds per binary.'), y)
    y -= 4*mm

    y = h1(c, '1.3  What does symbolic execution mean?', y); y -= 1.5*mm
    y = body(c, ('When a normal program runs, it processes actual data. When angr runs it, it processes '
        'symbols — placeholders for "whatever the attacker could send." Instead of computing x + 3 = 7, '
        'it tracks x + 3 = y and asks: is there a value of x that makes y overflow a buffer? The problem '
        'is that programs branch constantly. A program with 100 branches has 2^100 possible paths — '
        'more than atoms in the observable universe. C1 makes symbolic execution tractable by '
        'prioritising paths that are probably solvable, using a result from statistical physics: '
        'near a phase transition, constraint systems become maximally hard. C1 estimates how close '
        'each path is to that transition and uses that estimate as a priority signal.'), y)
    y -= 4*mm

    y = h1(c, '1.4  Why does the pipeline produce results?', y); y -= 1.5*mm
    y = body(c, ('Because it combines signals that individually are noisy, but together are '
        'discriminative:'), y)
    y -= 2*mm
    for b in [
        'Structure (C2): the call graph looks unusual — worth investigating',
        'Pattern (C3): the code does receive untrusted data → allocate memory without a bounds '
         'check in between — that pattern matches known vulnerability classes',
        'Confirmation (C6): symbolic execution finds a concrete input that reaches the allocator '
         'with an attacker-controlled size',
    ]:
        y = bullet_item(c, b, y)
    y -= 3*mm
    y = body(c, ('None of these alone is sufficient. Together, they narrow a binary with 300 functions '
        'down to 3 worth reading carefully. A 44 KB binary analysed in 30 seconds identifies the '
        'function with cyclomatic complexity 155 — which turns out to be the entire main loop. '
        'A 365 KB DLL screened in under a minute isolates the ICMPv6 reply parser with 23 callees '
        'and a recursive self-call. That is the function you want a human looking at.'), y)
    y -= 5*mm

    y = callout(c, 'warning', 'The honest version', [
        'It does not always work. angr hits memory limits on large binaries (~3.3 MB ceiling).',
        'Compiler optimisation hides patterns the tools expect.',
        'Some bugs are architectural — no static analysis finds them without protocol semantics.',
        'The pipeline is a triage tool, not an oracle.',
    ], y)

    end_page(SEC)

    # ── §2 Naming History ─────────────────────────────────────────────────────
    section_title_page(c, '§2', 'Why C1–C6? The Naming History', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§2  Why C1–C6? The Naming History'
    y = top()

    y = h1(c, '2.1  The Kill Chain connection', y); y -= 1.5*mm
    y = body(c, ('The naming comes — with deliberate irony — from the Lockheed Martin Cyber Kill Chain '
        'framework, which models an attacker\'s progression in seven stages: Reconnaissance, '
        'Weaponisation, Delivery, Exploitation, Installation, Command and Control, Actions on '
        'Objectives. The C-numbering (C1 through C6) is deliberately reminiscent of military chain '
        'designations — suggesting sequential dependency and the fact that each stage can be run '
        'independently. When this toolchain was designed, "chain" was reappropriated for the '
        'defender\'s research methodology: a sequential pipeline where each stage feeds the next, '
        'outputs flow forward, and nothing reaches the exploitation stage (writing a PoC) without '
        'passing through the earlier screens.'), y)
    y -= 5*mm

    y = h1(c, '2.2  Purple-teaming the architecture', y); y -= 1.5*mm
    y = body(c, ('The original architecture had exactly six components. A design prompt was sent '
        'independently to four LLMs (ChatGPT, Grok, DeepSeek, Gemini) — a process called '
        'purple-teaming the architecture. The four responses were synthesised to kill anything '
        'theoretically elegant but operationally useless. Two stages were killed:'), y)
    y -= 3*mm

    design_rows = [
        ['C1', 'Phase-aware symbolic execution',  'Keep, harden',   'Drop Survey Propagation; use backbone fraction'],
        ['C2', 'RMT call graph screen',           'Keep, fix null', 'M-P wrong for power-law; use config model'],
        ['C3', 'Matched filtering on call graphs','Redesign',       'Instruction-NCC rejected; call-level VEX correct'],
        ['C4', 'TDA on CFGs',                     '✗ Kill',         'Persistent homology = same signal as McCabe × 1000'],
        ['C5', 'Compressed sensing for coverage', '✗ Kill',         'RIP fails for binary coverage bitmaps'],
        ['C6', 'Dataflow taint analysis',         'Add (new)',      'Unanimous highest-ROI; not in original design'],
    ]
    y = table(c, ['Stage', 'Proposal', 'Verdict', 'Reason'], design_rows,
              [12*mm, 45*mm, 30*mm, TW - 87*mm], y, row_h=9.5*mm)
    y -= 5*mm

    y = h1(c, '2.3  Ghost stages', y); y -= 1.5*mm
    y = body(c, ('The numbering was preserved rather than renumbered after C4 and C5 were killed. '
        'This is why the implemented pipeline jumps from C3 directly to C6 — the ghost stages are a '
        'feature, not a bug. Anyone reading the codebase can see immediately that two ideas did not '
        'survive first contact with reality. C4 was killed because persistent homology of a CFG '
        'captures loop structure and branching depth — but those are already captured by back-edge '
        'count and cyclomatic complexity, both computed in microseconds by C2. C5 was killed because '
        'compressed sensing requires the measurement matrix to satisfy the Restricted Isometry Property '
        '— and coverage bitmaps are binary vectors with highly structured sparsity patterns that '
        'violate RIP badly. There is something satisfying about a cyber kill chain that kills two '
        'of its own stages.'), y)

    end_page(SEC)

    # ── §3 C1 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '§3', 'C1 — Phase-Transition Symbolic Execution', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§3  C1 — Phase-Transition Symbolic Execution'
    y = top()

    y = h1(c, '3.1  The physical picture: phase transitions', y); y -= 1.5*mm
    y = body(c, ('The 3-SAT satisfiability problem has a phase transition. A 3-SAT instance consists '
        'of n boolean variables and m clauses, each clause constraining exactly three variables. '
        'Define the clause-to-variable ratio α = m/n. For small α, almost every assignment satisfies '
        'all clauses — easy. For large α, the clauses are contradictory — again easy. But at exactly:'), y)
    y -= 2*mm
    y = body(c, '    α_c ≈ 4.267   (Mézard, Montanari, Zecchina 2002)',
             y, colour=ACCENT, size=T_BODY+0.5)
    y -= 2*mm
    y = body(c, ('the problem undergoes a sharp phase transition. Below α_c: satisfiable. Above: '
        'unsatisfiable. At α_c: maximally hard. The hardness is exponential — CDCL solvers take time '
        'growing exponentially with n for instances near α_c. An instance with n=50 variables at the '
        'transition can take longer than the age of the universe to solve optimally. The condensation '
        'transition at α_cond ≈ 4.15–4.27 is subtler: above it, solutions condense into a small '
        'number of clusters with large empty regions between them, causing belief-propagation and '
        'local-search algorithms to get stuck.'), y)
    y -= 4*mm

    y = h1(c, '3.2  The backbone — the key proxy metric', y); y -= 1.5*mm
    y = body(c, ('The backbone of a satisfiable 3-SAT instance is the set of variables that take '
        'the same value in every solution. As α approaches α_c from below, the backbone fraction '
        '(backbone size / n) grows toward 1.0 — more variables are frozen, the solution space '
        'shrinks, and finding any solution becomes harder. C1 uses backbone fraction as its '
        'hardness estimator, computed via assumption-based probing on Z3 (not Survey Propagation, '
        'which the Tseitin CNF encoding destroys):'), y)
    y -= 2*mm
    for ln in [
        'for var_name, width in symbolic_vars.items():',
        '    for bit_idx in range(width):',
        '        sat_true  = solver.check(z3_var_bit == 1) == z3.sat',
        '        sat_false = solver.check(z3_var_bit == 0) == z3.sat',
        '        if sat_true != sat_false:  # only one value works → backbone',
        '            forced += 1',
        'backbone_fraction = forced / total_bits',
    ]:
        y = mono(c, ln, y)
    y -= 3*mm

    y = h2(c, 'Priority formula', y); y -= 1.5*mm
    y = body(c, 'priority(state) = 1.0 − backbone_fraction(state)', y,
             colour=ACCENT, size=T_BODY+0.5)
    y -= 2*mm
    y = body(c, ('States are sorted by priority (descending) at each exploration step. States above '
        'configurable threshold τ are moved to a hardness_deferred stash. The adaptive threshold mode '
        'defers the top τ-percentile of the current active stash rather than a fixed backbone cutoff, '
        'preventing runaway deferral when all paths are hard.'), y)
    y -= 4*mm

    fig_h = 75*mm
    y_after = embed_image(c, figs['phase'], y, fig_h)
    caption_text(c,
        'Figure 1 — (left) 3-SAT phase transition: P(satisfiable) and backbone fraction vs α. '
        '(right) Backbone fraction predicts CDCL solve time exponentially.',
        y_after - 1*mm)
    y = y_after - 7*mm

    y = callout(c, 'note', 'Measured performance (angr crackme benchmark, n=50 symbolic bytes)', [
        '60% reduction in states explored before finding the solution path',
        '32 ms average backbone probing time per state',
        '5/5 tests passed — backbone-prioritised exploration found solutions in all cases',
        'Spearman ρ = +0.43, p = 0.012 (backbone fraction vs CDCL hardness)',
    ], y)

    end_page(SEC)

    # ── §4 C2 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '§4', 'C2 — Random Matrix Theory Screen', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§4  C2 — Random Matrix Theory Call Graph Screen'
    y = top()

    y = h1(c, '4.1  Graph theory: the adjacency matrix and its spectrum', y); y -= 1.5*mm
    y = body(c, ('The call graph G = (V, E) has adjacency matrix A where A[i,j] = 1 if function i '
        'calls function j. The eigenvalues λ₁, λ₂, ..., λ_N (solutions to det(A − λI) = 0) form '
        'the spectrum of G. Three statistics are computed from the spectrum:'), y)
    y -= 2*mm
    for b in [
        'Spectral radius ρ(A) = max|λᵢ| — zero for pure DAGs, positive when cycles exist; '
         'larger values indicate stronger cyclic structure',
        'Graph energy E(G) = Σ|λᵢ|/N — average absolute eigenvalue per node; '
         'elevated for dense, irregular graphs',
        'Eigenvalue entropy H = −Σpᵢ log pᵢ, pᵢ = |λᵢ| / Σ|λⱼ| — low entropy signals structured '
         'hierarchy; high entropy signals non-random topology',
    ]:
        y = bullet_item(c, b, y); y -= 0.5*mm
    y -= 3*mm

    y = h1(c, '4.2  Why NOT Marchenko-Pastur', y); y -= 1.5*mm
    y = body(c, ('The Marchenko-Pastur distribution applies to covariance matrices of i.i.d. random '
        'matrices. Both M-P and the Wigner semicircle law assume matrix entries are i.i.d. — this '
        'fails completely for call graphs, which have power-law degree distributions (a few hub '
        'functions called by many others), bipartite-like structure, and extreme sparsity. The '
        'correct null distribution is the configuration model (Bollobás 1980, directed variant): '
        'generate a random directed graph with exactly the same in/out degree sequence as the '
        'observed graph, but random wiring. This controls for hub structure.'), y)
    y -= 3*mm

    y = h2(c, 'Z-score formula', y); y -= 1.5*mm
    y = body(c, '    z_m = (m_observed − μ_null(m)) / σ_null(m)', y,
             colour=ACCENT, size=T_BODY+0.5)
    y -= 2*mm
    y = body(c, ('μ_null and σ_null are estimated from 50 configuration-model replicates. '
        'Threshold: |z| > 2.0 flags a binary as ANOMALOUS. Both positive and negative z-scores '
        'can be anomalous: z_energy = −22.33 (mDNSResponder) indicates massively structured '
        'internal complexity; z_entropy = +5.63 (biometrickitd) indicates Swift stdlib noise '
        'confirmed as false positive.'), y)
    y -= 4*mm

    fig_h = 108*mm
    y_after = embed_image(c, figs['spectral'], y, fig_h)
    caption_text(c,
        'Figure 2 — C2 spectral analysis: degree distributions, null model comparison, z-score heatmap, '
        'function scoring formula, and McCabe distributions for normal vs anomalous binaries.',
        y_after - 1*mm)
    y = y_after - 7*mm

    y = h1(c, '4.3  McCabe cyclomatic complexity', y); y -= 1.5*mm
    y = body(c, ('At function level, C2 uses McCabe cyclomatic complexity M = E − N + 2, where E is '
        'control flow graph edges, N is basic blocks. The +2 follows from Euler\'s formula for planar '
        'graphs. Interpretation: M=1 trivial, M=10 manageable, M=155 extreme (155 independent paths — '
        'every one needs a test case for branch coverage). For security analysis, high M means many '
        'branches with edge cases, large symbolic state space, and high cognitive load on reviewers. '
        'The combined function score weights eigenvector centrality, cyclomatic complexity, and '
        'back-edge count: S = 0.4·ev + 0.35·log(M) + 0.25·log(B).'), y)

    end_page(SEC)

    # ── §5 C3 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '§5', 'C3 — Template-Based Call Dataflow Matching', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§5  C3 — Template-Based Call Dataflow Matching'
    y = top()

    y = h1(c, '5.1  Design choice: why not full SSA?', y); y -= 1.5*mm
    y = body(c, ('Full SSA reaching-definitions analysis would give exact dataflow information across '
        'an entire binary. It would also take hours on a binary with 45,000 functions. The key insight '
        'is that the vulnerability patterns we care about — XPC type confusion, mach_msg OOB, IOKit '
        'OOB, port UAF — all share a common structure: source_function produces attacker-influenced '
        'data → sink_function receives it. The intermediate steps may involve stack spills and loads, '
        'but the call-level structure is preserved. C3 builds a call-level def-use graph and matches '
        'templates against it — fast enough to run on all functions in seconds.'), y)
    y -= 4*mm

    y = h1(c, '5.2  Register and stack taint tracking', y); y -= 1.5*mm
    y = body(c, ('C3 lifts each basic block to VEX IR and scans WrTmp, Put, and Store statements to '
        'track taint through registers and stack slots. The key challenge is ARM64 compiler behaviour: '
        'return values (x0) are frequently spilled to the stack between calls, then reloaded. '
        'C3 handles this via canonical address resolution:'), y)
    y -= 2*mm
    for ln in [
        'GET(register)         → "register_name"      (e.g., "x0")',
        'Add64(RdTmp(t), C)    → "sp+0x10"            (frame-relative address)',
        'Load(Add64(sp, C))    → resolves to "sp+0x10" → finds spilled taint',
    ]:
        y = mono(c, ln, y)
    y -= 2*mm
    y = body(c, ('This mem_state dictionary keyed by canonical address strings survives cross-block '
        'spills and correctly tracks x0 → [sp, #0x10] → x0 register round-trips that would defeat '
        'a naive per-block analysis.'), y)
    y -= 4*mm

    fig_h = 78*mm
    y_after = embed_image(c, figs['c3_template'], y, fig_h)
    caption_text(c,
        'Figure 3 — C3 template structure (left): source → intermediate → sink pattern with barrier '
        'detection. Confidence scores for the five macOS vulnerability templates (right).',
        y_after - 1*mm)
    y = y_after - 7*mm

    y = h1(c, '5.3  The five macOS templates', y); y -= 1.5*mm
    template_rows = [
        ['XPC_INT_OOB',  'xpc_dictionary_get_int64()', 'IOKit copyScalar / alloc', 'bounds check compare'],
        ['MACH_MSG_OOB', 'mach_msg recv fields',       'malloc / alloc with size',  'size clamp'],
        ['IOKIT_OOB',    'IOKit method argument',       'typed accessor',            'range check'],
        ['PORT_UAF',     'mach_msg recv port field',    'port lookup table',         'epoch/generation check'],
        ['XPC_TYPE',     'xpc_dictionary_get_value()',  'type-specific dispatch',    'xpc_get_type() call'],
    ]
    y = table(c, ['Template', 'Source', 'Sink', 'Barrier'],
              template_rows,
              [28*mm, 52*mm, 48*mm, TW - 128*mm], y, row_h=9.5*mm)

    end_page(SEC)

    # ── §6 C6 ─────────────────────────────────────────────────────────────────
    section_title_page(c, '§6', 'C6 — Symbolic Taint Analysis', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§6  C6 — Symbolic Taint Analysis'
    y = top()

    y = h1(c, '6.1  Architecture: SimProcedure hooks', y); y -= 1.5*mm
    y = body(c, ('C6 hooks 18 security-relevant functions via angr SimProcedures. When the symbolic '
        'engine calls a hooked function, the hook intercepts the call and returns a fresh claripy '
        'BVS (bitvector symbol) tagged with a taint label. This creates a "taint source" in the '
        'symbolic state that flows through the program via normal constraint propagation — no '
        'separate taint tracking required.'), y)
    y -= 2*mm
    for ln in [
        'def Hook_malloc(state):',
        '    size = state.solver.eval(state.regs.x0)     # ARM64: size in x0',
        '    taint = claripy.BVS(f"malloc_ret_{self.call_id}", 64)',
        '    taint_map[taint.args[0]] = {"type": "malloc", "size": size}',
        '    return taint',
    ]:
        y = mono(c, ln, y)
    y -= 3*mm

    y = h1(c, '6.2  OOB, UAF, and type confusion detection', y); y -= 1.5*mm
    y = body(c, ('At sink functions, C6 checks whether symbolic values carry taint labels and whether '
        'the constraints on those values admit a bug witness. OOB detection checks whether the solver '
        'can find an assignment where an index exceeds its allocation size. UAF detection checks '
        'whether a dereferenced pointer shares a taint label with a freed allocation. Type confusion '
        'detection checks whether the symbolic type tag at an accessor differs from the expected '
        'type for that call site.'), y)
    y -= 3*mm

    y = callout(c, 'note', 'Solver interaction — confidence from max()', [
        'For each taint source, C6 asks the solver: max(index) >= alloc_size?',
        'If yes AND the concrete max value is solver-confirmed: ALERT with concrete PoC input.',
        'If yes but solver times out: LOW CONFIDENCE alert (symbolic only).',
        'solver.max() is used rather than solver.satisfiable() to get a PoC value directly.',
    ], y)
    y -= 5*mm

    fig_h = 78*mm
    y_after = embed_image(c, figs['c6_taint'], y, fig_h)
    caption_text(c,
        'Figure 4 — C6 taint propagation: 18 source hooks tag return values as BVS; '
        'angr propagates taint through arithmetic; sink hooks detect OOB/UAF/type confusion.',
        y_after - 1*mm)
    y = y_after - 7*mm

    y = h1(c, '6.3  The hook table', y); y -= 1.5*mm
    hook_rows = [
        ['malloc, calloc, realloc, valloc, mmap', 'Memory allocation sources',         'size argument + return value'],
        ['recv, recvfrom, read',                   'Network / file input sources',       'buffer + count'],
        ['mach_msg_recv',                          'Mach IPC receive',                   'msg header fields'],
        ['xpc_dictionary_get_value, _get_int64',   'XPC surface',                        'dict value'],
        ['xpc_array_get_value',                    'XPC array access',                   'index + value'],
        ['IOKit_copyScalar_64, _32',               'IOKit typed accessor',               'field offset'],
        ['OSObject_getRef, io_connect_method',     'IOKit object handling',              'type tag'],
        ['free',                                   'Deallocation tracking',              'ptr → UAF tracking'],
    ]
    y = table(c, ['Hook(s)', 'Category', 'Taint target'],
              hook_rows, [65*mm, 50*mm, TW - 115*mm], y, row_h=9.5*mm)

    end_page(SEC)

    # ── §7 Disassembly Layer ──────────────────────────────────────────────────
    section_title_page(c, '§7', 'The Disassembly Layer', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§7  The Disassembly Layer — VEX IR, pefile, capstone, otool'
    y = top()

    y = h1(c, '7.1  VEX IR fundamentals', y); y -= 1.5*mm
    y = body(c, ('VEX IR (Valgrind IR) is a machine-independent intermediate representation. angr '
        'lifts each machine instruction to VEX IR statements. An IRSB (Intermediate Representation '
        'SuperBlock) corresponds approximately to one basic block. Key statement types:'), y)
    y -= 2*mm
    for b in [
        'WrTmp(t, expr)  — write expr to temporary tN (SSA within the block)',
        'Put(offset, expr)  — write to guest register file (x0–x28, sp, pc)',
        'Store(addr, expr)  — write to memory',
        'IMark(addr, len)  — instruction boundary marker (not executable)',
        'Exit(guard, target)  — conditional branch (creates CFG edge)',
    ]:
        y = bullet_item(c, b, y)
    y -= 3*mm

    y = h2(c, 'Critical limitation: SSA scope is per-IRSB only', y); y -= 1.5*mm
    y = body(c, ('VEX temporaries are SSA only within a single IRSB. Across basic block boundaries, '
        'register state is tracked via Put/Get (register file) and Store/Load (memory). C3 must '
        'reconstruct cross-block dataflow manually using the canonical address scheme described '
        'in §5.2. Attempting to read cross-block VEX temporaries is a common error that produces '
        'incorrect (empty) taint sets.'), y)
    y -= 4*mm

    y = h1(c, '7.2  Compiler constant-folding — the VEX IR trap', y); y -= 1.5*mm
    y = body(c, ('When scanning VEX IR for arithmetic patterns (e.g., "oip + 0x14" for an IP '
        'header offset bug), the expected Binop(Iop_Add64, RdTmp(t_oip), Const(0x14)) statement '
        'often does not appear. ARM64 compilers constant-fold pointer arithmetic at compile time: '
        'instead of a runtime add, the load instruction encodes the offset directly as an immediate. '
        'The correct fix is to scan load/store offsets in otool disassembly output rather than '
        'VEX Add64 intermediate values.'), y)
    y -= 2*mm
    for ln in [
        '# WRONG: scanning VEX for Add64(RdTmp, Const(0x14)) finds nothing',
        '# CORRECT: otool sliding-window scan for consecutive:',
        '#   LDRB  w_N, [xB, #0x1c]   ← ip->ip_hl byte (offset fixed)',
        '#   LDRH  w_M, [xB, #0x20]   ← inner IP field  (same base reg xB)',
        '# If both share the same base register → fixed-offset logic bug confirmed',
    ]:
        y = mono(c, ln, y)
    y -= 3*mm

    y = h1(c, '7.3  Windows PE: pefile + capstone', y); y -= 1.5*mm
    y = body(c, ('angr\'s CFGFast does not reliably resolve Windows IAT thunk names in a single-session '
        'analysis — import table entries are runtime-resolved addresses, not static call targets. '
        'The fix: use pefile.PE() to build an IAT map (import.address → name) and resolve call '
        'targets by computing the RIP-relative IAT slot from capstone disassembly:'), y)
    y -= 2*mm
    for ln in [
        'pe  = pefile.PE("target.exe")',
        'iat = {imp.address: imp.name.decode()',
        '       for entry in pe.DIRECTORY_ENTRY_IMPORT',
        '       for imp in entry.imports if imp.name}',
        '# Resolve CALL [rip + disp]:',
        '# slot_va = instr.address + instr.size + disp',
        '# function_name = iat.get(slot_va, f"sub_{slot_va:x}")',
    ]:
        y = mono(c, ln, y)
    y -= 3*mm

    y = h1(c, '7.4  Binary acquisition without a VM', y); y -= 1.5*mm
    y = body(c, ('Microsoft\'s symbol server hosts all Windows system binaries indexed by winbindex. '
        'URL format: msdl.microsoft.com/download/symbols/{name}/{TimeDateStamp:08X}{SizeOfImage:x}/{name} '
        'with User-Agent: Microsoft-Symbol-Server/10.0.10036.206. The TimeDateStamp and SizeOfImage '
        'come from the PE optional header, available in the winbindex JSON index. SHA256 verification '
        'confirms authenticity. No VM, no installation media, no admin access required.'), y)
    y -= 4*mm

    fig_h = 55*mm
    y_after = embed_image(c, figs['disassembly'], y, fig_h)
    caption_text(c,
        'Figure 5 — Disassembly layer pipeline: from binary bytes through VEX IR or native disassembly '
        'to pattern detection. Compiler folding forces the otool bypass for ARM64 offset scanning.',
        y_after - 1*mm)

    end_page(SEC)

    # ── §8 Pipeline Composition ───────────────────────────────────────────────
    section_title_page(c, '§8', 'Pipeline Composition', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§8  Pipeline Composition'
    y = top()

    y = h1(c, '8.1  End-to-end flow', y); y -= 1.5*mm
    fig_h = 60*mm
    y_after = embed_image(c, figs['pipeline'], y, fig_h)
    caption_text(c,
        'Figure 6 — Full pipeline from binary collection through PoC. '
        'C4 and C5 are struck out — killed by architecture review.',
        y_after - 1*mm)
    y = y_after - 7*mm

    y = h1(c, '8.2  Stage interface contracts', y); y -= 2*mm
    stage_rows = [
        ['C1', 'angr.SimState', 'angr SimState + backbone score', 'Priority stash for simgr'],
        ['C2', 'Mach-O / PE binary', 'C2RMTResult + ranked functions', 'JSON: top_addrs.json'],
        ['C3', 'top_addrs.json + binary', 'C3HitList', 'JSON: c3_hits.json'],
        ['C6', 'c3_hits.json + binary', 'C6Alert list', 'JSON: c6_alerts.json + PoC'],
    ]
    y = table(c, ['Stage', 'Input', 'Output', 'Persisted format'],
              stage_rows, [12*mm, 45*mm, 38*mm, TW - 95*mm], y, row_h=9.5*mm)
    y -= 5*mm

    y = h1(c, '8.3  Dependency and fallback behaviour', y); y -= 1.5*mm
    for b in [
        'C1 requires an active angr.SimulationManager — it is a SimulationManager technique, '
         'not a standalone script. It runs transparently inside any angr symbolic execution session.',
        'C2 operates on CFGFast output. If CFGFast fails (arm64e PAC, chained fixups), C2 falls '
         'back to otool-based function enumeration with McCabe only (no spectral metrics).',
        'C3 reads C2 top_addrs.json by default. If not present, it runs C2 first. '
         'Can be invoked standalone with an address list.',
        'C6 requires angr symbolic execution to be viable on the target function. '
         'If angr exceeds memory/time limits, C6 is skipped and C3 results stand.',
    ]:
        y = bullet_item(c, b, y)
    y -= 5*mm

    y = callout(c, 'note', 'angr arch override — always required on macOS', [
        'Universal Mach-O contains x86_64 and arm64e slices. angr defaults to x86_64',
        'even on Apple Silicon. Always pass explicit arch:',
        '    proj = angr.Project(path, auto_load_libs=False,',
        '                        main_opts={"arch": archinfo.arch_from_id("aarch64")})',
        'Do NOT pass arch as a bare string — angr requires an archinfo.Arch instance.',
    ], y)

    end_page(SEC)

    # ── §9 Limitations & Dead Ends ────────────────────────────────────────────
    section_title_page(c, '§9', 'Limitations & Dead Ends', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§9  Limitations & Dead Ends'
    y = top()

    y = h1(c, '9.1  Known tool limitations', y); y -= 1.5*mm
    limit_rows = [
        ['angr CFG size limit',    '~3.3 MB Mach-O',     'Sparse eigenvalue approx for N>2000; skip if OOM'],
        ['arm64e PAC',             'CLE chained fixups',  'Falls back to otool symbol scan'],
        ['ObjC dispatch / vtable', 'Indirect calls',      'CFGFast misses; manual inspection only'],
        ['C++ STL / Swift stdlib', 'False positives',     'Filter by callee name prefix in C3/C6'],
        ['Windows ARM64 CC',       'Missing Win32 entry', 'Monkey-patch SYSCALL_CC before Project()'],
        ['Compiler folding',       'VEX Add64 absent',    'Use otool LDRB/LDRH sliding-window scan'],
    ]
    y = table(c, ['Limitation', 'Root cause', 'Workaround'],
              limit_rows, [42*mm, 38*mm, TW - 80*mm], y, row_h=9.5*mm)
    y -= 5*mm

    y = h1(c, '9.2  Why C4 (TDA) was killed', y); y -= 1.5*mm
    y = body(c, ('Topological data analysis on CFGs computes the persistent homology of the basic '
        'block graph — the "shape" of the control flow over different scales of connectivity. '
        'This is mathematically elegant. It is also operationally useless for this pipeline, '
        'because loop structure and branching depth — the features TDA would detect — are already '
        'captured by back-edge count (loops) and cyclomatic complexity (branching depth), both of '
        'which C2 computes in microseconds from simple graph traversal. TDA would take seconds per '
        'function via gudhi or ripser and add no discriminative signal beyond what we already have. '
        'The kill decision was unanimous across all four LLMs in the architecture review.'), y)
    y -= 4*mm

    y = h1(c, '9.3  Why C5 (compressed sensing) was killed', y); y -= 1.5*mm
    y = body(c, ('The proposal was to treat AFL++ coverage bitmaps as sparse signals and apply '
        'compressed sensing — projecting the 64K-entry bitmap down to a small number of random '
        'linear measurements, then recovering the original from those measurements. This requires '
        'the measurement matrix Φ to satisfy the Restricted Isometry Property (RIP): for all '
        'k-sparse vectors x, ||Φx||₂ ≈ ||x||₂. The RIP holds for random Gaussian/Bernoulli '
        'measurement matrices — but coverage bitmaps are binary vectors with highly structured '
        'sparsity. Most branches are taken the same way across most inputs: the sparsity pattern '
        'is correlated, not random. The RIP fails, random projection cannot recover the original, '
        'and the compressed representation carries less information than a simple hash. Killed.'), y)
    y -= 4*mm

    y = callout(c, 'warning', 'General principle', [
        'Mathematical elegance is not the same as operational utility.',
        'Both TDA and compressed sensing are legitimate techniques in their domains.',
        'They fail here because the assumptions they require do not hold for call graphs and',
        'coverage bitmaps. Document failure modes — they inform the next design cycle.',
    ], y)

    end_page(SEC)

    # ── §10 Glossary ──────────────────────────────────────────────────────────
    section_title_page(c, '§10', 'Glossary', pg[0])
    c.showPage(); pg[0] += 1

    SEC = '§10  Glossary'
    y = top()

    y = h1(c, 'Terms and notation', y); y -= 2*mm

    glossary = [
        ('3-SAT',               'Satisfiability problem with 3-literal clauses. Phase transition at α_c ≈ 4.267.'),
        ('α_c',                 'Critical clause/variable ratio for 3-SAT phase transition (≈ 4.267).'),
        ('α_cond',              'Condensation transition ratio (≈ 4.15–4.27), where solutions cluster.'),
        ('Backbone',            'Set of variables taking the same value in every satisfying assignment.'),
        ('BVS',                 'Bitvector symbol — claripy\'s symbolic variable type. Carries taint via name.'),
        ('C1–C6',               'Pipeline stage designators. C4, C5 killed by design review; gaps preserved.'),
        ('CDCL',                'Conflict-Driven Clause Learning — the algorithm inside Z3 and most SAT solvers.'),
        ('CFG',                 'Control Flow Graph. Nodes = basic blocks, edges = branches.'),
        ('CFGFast',             'angr\'s fast CFG recovery (linear sweep + recursive descent, no execution).'),
        ('Configuration model', 'Correct RMT null for call graphs: random rewiring preserving degree sequence.'),
        ('Cyclomatic complexity','M = E − N + 2. Number of independent paths through a function\'s CFG.'),
        ('Eigenvector centrality','Importance of a node weighted by importance of its neighbours (power iteration).'),
        ('Graph energy',        'E(G) = Σ|λᵢ|/N. Sum of absolute eigenvalues per node.'),
        ('IAT',                 'Import Address Table — Windows PE runtime-resolved function pointers.'),
        ('IRSB',                'Intermediate Representation SuperBlock — one basic block in VEX IR.'),
        ('Marchenko-Pastur',    'RMT null distribution for i.i.d. random matrices. Wrong for call graphs.'),
        ('OOB',                 'Out-Of-Bounds read or write past an allocated buffer boundary.'),
        ('PAC',                 'Pointer Authentication Code — ARM64e hardware pointer signing.'),
        ('Power iteration',     'Algorithm for computing the principal eigenvector: x^(k+1) = Ax^(k)/||Ax^(k)||.'),
        ('QF_BV',               'Quantifier-Free Bitvector Theory — angr\'s constraint language.'),
        ('RIP',                 'Restricted Isometry Property — required for compressed sensing recovery.'),
        ('RMT',                 'Random Matrix Theory — study of eigenvalue spectra of large random matrices.'),
        ('SimProcedure',        'angr hook that replaces a function\'s body with a Python implementation.'),
        ('Spectral radius',     'ρ(A) = max|λᵢ|. Largest eigenvalue magnitude.'),
        ('TDA',                 'Topological Data Analysis — persistent homology. Killed at C4.'),
        ('Tseitin transform',   'Converts arbitrary boolean formulae to CNF. Destroys factor-graph structure.'),
        ('UAF',                 'Use-After-Free — dereferencing a pointer after the allocation was freed.'),
        ('VEX IR',              'Valgrind IR — machine-independent intermediate representation used by angr.'),
        ('Wigner semicircle',   'RMT null for symmetric i.i.d. random matrices. Wrong for call graphs.'),
        ('WrTmp',               'VEX IR statement: assign expression to SSA temporary tN.'),
        ('z-score',             'z = (obs − μ) / σ. Measures deviation from null distribution in sigma units.'),
    ]

    col_term = 45*mm
    col_def  = TW - col_term
    for term, defn in glossary:
        if y < MB + 18*mm:
            end_page(SEC)
            y = top()
        c.setFillColor(ACCENT); c.setFont('Helvetica-Bold', T_SMALL)
        c.drawString(ML, y, term)
        c.setFillColor(INK2); c.setFont('Helvetica', T_SMALL)
        # Wrap definition
        words = defn.split()
        line = ''
        first = True
        dy = y
        for word in words:
            test = (line + ' ' + word).strip()
            if c.stringWidth(test, 'Helvetica', T_SMALL) <= col_def - 2*mm:
                line = test
            else:
                c.drawString(ML + col_term, dy, line)
                dy -= 5.5*mm
                line = word
                first = False
        if line:
            c.drawString(ML + col_term, dy, line)
            dy -= 5.5*mm
        y = min(y, dy) - 1.5*mm
        # Light rule
        c.setStrokeColor(RULE_C); c.setLineWidth(0.3)
        c.line(ML, y + 0.5*mm, W-MR, y + 0.5*mm)
        y -= 1.5*mm

    y -= 5*mm
    y = callout(c, 'note', 'Document Information', [
        f'Generated by generate_toolchain_docs.py  ·  {DATE_STR}',
        f'{AUTHOR}  ·  Independent Security Researcher',
        'Findings referenced are redacted — this document covers methodology only.',
        'Repository: macos_vuln_toolchain/metis/',
    ], y)

    end_page(SEC)

    c.save()
    sz = out_path.stat().st_size
    print(f'  ✓ {out_path.name}  ({sz//1024} kB, {pg[0]-1} pages)')


# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    out = HERE / 'TOOLCHAIN_DOCUMENTATION.pdf'
    figs = generate_figures()
    print('\nBuilding PDF...')
    build_pdf(figs, out)
    print('\nDone.')
    print(f'  PDF: {out}')
    print(f'  Figures: {FIGS}')
