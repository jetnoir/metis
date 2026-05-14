#!/usr/bin/env python3
"""
run_c3_screen.py — C3 template scan on C2 top-ranked functions.

Reads c2_top_addrs.json produced by run_c2_screen.py, then runs
C3TemplateAnalysis on the top-K functions per binary.

Usage: python3 run_c3_screen.py [--top N]   (default N=20)
Output: c3_results.txt
        c3_hits.json  ({binary: [{addr, template, confidence, ...}]})
"""

import sys
import json
import argparse
import traceback
from datetime import datetime
from pathlib import Path

import angr
import archinfo

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from metis.c3_templates import C3TemplateAnalysis

BINARY_PATHS = {
    "syspolicyd":     "/usr/libexec/syspolicyd",
    "mDNSResponder":  "/usr/sbin/mDNSResponder",
    "storagekitd":    "/usr/libexec/storagekitd",
    "kernelmanagerd": "/usr/libexec/kernelmanagerd",
    "fskitd":         "/tmp/fskitd_vm",
}

parser = argparse.ArgumentParser()
parser.add_argument("--top", type=int, default=20)
args = parser.parse_args()

addr_file = HERE / "c2_top_addrs.json"
if not addr_file.exists():
    print("ERROR: c2_top_addrs.json not found — run run_c2_screen.py first")
    sys.exit(1)

top_addrs = json.loads(addr_file.read_text())

out_lines = []
all_hits = {}

def log(s=""):
    print(s, flush=True)
    out_lines.append(s)

log(f"=== C3 Template Screen — {datetime.now().strftime('%Y-%m-%d %H:%M')} ===")
log(f"Top-K per binary: {args.top}")
log()

for label, addr_score_pairs in top_addrs.items():
    binary = BINARY_PATHS.get(label)
    if not binary:
        log(f"[{label}] — no binary path, skipping")
        continue

    log("=" * 70)
    log(f"[{label}]  {binary}")

    addrs = [int(a, 16) for a, _ in addr_score_pairs[:args.top]]
    log(f"  Scanning {len(addrs)} functions for 5 XPC/Mach templates...")
    log()

    try:
        proj = angr.Project(binary, auto_load_libs=False,
                            main_opts={'arch': archinfo.arch_from_id('aarch64')})
        c3 = C3TemplateAnalysis(proj)
        result = c3.analyse_functions(addrs)
        result.print_report()

        hits = []
        if hasattr(result, 'findings'):
            for f in result.findings:
                hits.append({
                    "addr":       hex(f.addr) if hasattr(f, 'addr') else "?",
                    "template":   str(f.template) if hasattr(f, 'template') else "?",
                    "confidence": f.confidence if hasattr(f, 'confidence') else "?",
                    "source":     str(f.source) if hasattr(f, 'source') else "?",
                    "sink":       str(f.sink) if hasattr(f, 'sink') else "?",
                })
        all_hits[label] = hits
        log(f"  Findings: {len(hits)}")
        log()

    except Exception as e:
        log(f"  ERROR: {e}")
        traceback.print_exc()
        log()

log("=" * 70)
log(f"Done. Total binaries with hits: {sum(1 for h in all_hits.values() if h)}")

(HERE / "c3_results.txt").write_text("\n".join(out_lines))
(HERE / "c3_hits.json").write_text(json.dumps(all_hits, indent=2))
log(f"\nSaved: c3_results.txt, c3_hits.json")
