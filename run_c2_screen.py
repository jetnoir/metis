#!/usr/bin/env python3
"""
run_c2_screen.py — C2 RMT screen across priority targets.

Runs C2RMTAnalysis on each binary in TARGETS, prints a consolidated
report, and saves top-ranked functions per binary for C3/C6 follow-up.

Usage: python3 run_c2_screen.py
Output: c2_results.txt  (summary + top-20 functions per binary)
        c2_top_addrs.json  (machine-readable: {binary: [[addr, score], ...]})
"""

import sys
import json
import traceback
from datetime import datetime
from pathlib import Path

# Ensure local metis package is importable
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import angr
import archinfo
from metis.c2_rmt import C2RMTAnalysis

TARGETS = [
    ("locationd",    "/usr/libexec/locationd",
     "Location services daemon. Root. GPS/WiFi location. 2.8MB."),

    ("sharingd",     "/usr/libexec/sharingd",
     "AirDrop/Handoff/continuity daemon. Root. Peer-to-peer network. 1.8MB."),

    ("rapportd",     "/usr/libexec/rapportd",
     "Continuity/Handoff transport. Root. TCP+BT. 1.2MB."),
]

TOP_N = 20
out_lines = []
top_addrs = {}

def log(s=""):
    print(s, flush=True)
    out_lines.append(s)

log(f"=== C2 RMT Screen — {datetime.now().strftime('%Y-%m-%d %H:%M')} ===")
log(f"Targets: {len(TARGETS)} host binaries")
log(f"Top-N functions per binary: {TOP_N}")
log()

for label, path, notes in TARGETS:
    log("=" * 70)
    log(f"[{label}]")
    log(f"  Path:  {path}")
    log(f"  Notes: {notes}")
    log()

    try:
        proj = angr.Project(
            path,
            auto_load_libs=False,
            main_opts={'arch': archinfo.arch_from_id('aarch64')},
        )
        result = C2RMTAnalysis.from_project(proj).run()

        # Binary-level verdict
        bs = result.binary_score
        obs = bs.observed
        log(f"  Call graph  : {obs.n_nodes} nodes, {obs.n_edges} edges")
        log(f"  RMT verdict : {'ANOMALOUS — flag for deeper review' if bs.flagged else 'within normal range'}")
        log(f"    λ_max (spectral radius)  z = {bs.z_radius:+.2f}")
        log(f"    Graph energy Σ|λ|/N      z = {bs.z_energy:+.2f}")
        log(f"    Eigenvalue entropy       z = {bs.z_entropy:+.2f}")
        log()

        # Top-N ranked functions
        ranked = result.functions_ranked[:TOP_N]
        top_addrs[label] = [[hex(f.addr), round(f.combined, 4)] for f in ranked]

        log(f"  Top {TOP_N} functions by combined score:")
        log(f"  {'#':<4} {'Address':<14} {'Score':>7}  {'Cyclomatic':>10}  {'BackEdges':>9}  {'Name'}")
        log(f"  {'-'*4} {'-'*14} {'-'*7}  {'-'*10}  {'-'*9}  {'-'*30}")

        for i, f in enumerate(ranked, 1):
            name = str(f.name)
            if len(name) > 40:
                name = name[:37] + '...'
            log(f"  {i:<4} 0x{f.addr:<12x} {f.combined:>7.4f}  {f.cyclomatic:>10}  {f.back_edges:>9}  {name}")

        log()

    except Exception as e:
        log(f"  ERROR: {e}")
        traceback.print_exc()
        log()

log("=" * 70)
log(f"Done. {len(top_addrs)} binaries screened.")
log()
log("Next steps:")
log("  1. Run C3 template scan on top functions for each binary")
log("  2. Run C6 taint analysis on highest-scoring functions in mDNSResponder + fskitd (VM)")
log("  3. Manually inspect syspolicyd sub flagged in toolchain_report")

# Save outputs
out_path = HERE / "c2_results.txt"
out_path.write_text("\n".join(out_lines))
log(f"\nReport saved: {out_path}")

json_path = HERE / "c2_top_addrs.json"
json_path.write_text(json.dumps(top_addrs, indent=2))
log(f"Addresses saved: {json_path}")
