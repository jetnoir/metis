#!/usr/bin/env python3
"""
displaypolicyd_c2c3.py — C2 RMT + C3 template scan on /usr/libexec/displaypolicyd

displaypolicyd is an x86_64-only binary (329KB, batch hit z=−8.27 — most anomalous
from libexec partial batch). Load with explicit x86_64 arch to bypass host
_host_arch() which returns aarch64 on Apple Silicon.

Usage (Mac):
    python3 displaypolicyd_c2c3.py

Usage (Dell — from ~/darwin_research/toolchain/):
    ~/.venv_angr/bin/python3 displaypolicyd_c2c3.py --binary ~/darwin_research/binaries/libexec/displaypolicyd
"""
import sys, json, io, argparse
from pathlib import Path

# Support both Mac (toolchain in place) and Dell (venv, different path layout)
_here = Path(__file__).parent
TOOLCHAIN = _here if (_here / 'metis').exists() else _here
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo

from metis.c2_rmt import C2RMTAnalysis
from metis.c3_templates import C3TemplateAnalysis

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='/usr/libexec/displaypolicyd')
parser.add_argument('--outdir', default=str(_here / 'findings'))
args = parser.parse_args()

BINARY  = args.binary
OUT_DIR = Path(args.outdir)
OUT_DIR.mkdir(parents=True, exist_ok=True)

print(f'[*] Loading {BINARY} as x86_64 (binary is x86_64-only)')
proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('x86_64')},
)
print(f'    arch:  {proj.arch.name}')
print(f'    entry: {proj.entry:#x}')

# ── C2 RMT Analysis ───────────────────────────────────────────────────────────
print('\n[*] Running C2 RMT analysis...')
c2     = C2RMTAnalysis(BINARY, project=proj)
result = c2.run()

buf = io.StringIO()
sys.stdout, old = buf, sys.stdout
result.print_report()
sys.stdout = old
report_text = buf.getvalue()
print(report_text)

c2_out = OUT_DIR / 'displaypolicyd_c2_results.txt'
c2_out.write_text(
    f'displaypolicyd C2 RMT Analysis\n'
    f'Binary: {BINARY}\n'
    f'Arch: x86_64 (explicit override)\n'
    f'{"="*60}\n\n'
    + report_text
)
print(f'[+] C2 results → {c2_out}')

top_addrs = [f.addr for f in result.functions_ranked[:20]]
top_data  = [
    {'addr': hex(f.addr), 'score': round(f.combined, 4),
     'cyclomatic': f.cyclomatic, 'back_edges': f.back_edges}
    for f in result.functions_ranked[:20]
]
addr_json = OUT_DIR / 'displaypolicyd_c2_top_addrs.json'
addr_json.write_text(json.dumps(top_data, indent=2))
print(f'[+] Top-{len(top_addrs)} addrs → {addr_json}')

# ── C3 Template Analysis ──────────────────────────────────────────────────────
print(f'\n[*] Running C3 template scan on top {len(top_addrs)} functions...')
c3       = C3TemplateAnalysis(proj)
c3_result = c3.analyse_functions(top_addrs)

hits_data = []
for match in c3_result.matches:
    entry = {
        'template':    match.template_name,
        'func_addr':   hex(match.func_addr),
        'source_call': match.source_call,
        'sink_call':   match.sink_call,
        'confidence':  round(match.confidence, 4),
    }
    hits_data.append(entry)
    print(f'  HIT  {match.template_name}  func={hex(match.func_addr)}'
          f'  {match.source_call} → {match.sink_call}  conf={match.confidence:.2f}')

if not hits_data:
    print('  (no template hits in top-20 functions)')

(OUT_DIR / 'displaypolicyd_c3_hits.json').write_text(json.dumps(hits_data, indent=2))

c3_lines = []
for h in hits_data:
    c3_lines += [
        f"[{h['template']}]  func={h['func_addr']}",
        f"  source: {h['source_call']}",
        f"  sink:   {h['sink_call']}",
        f"  confidence: {h['confidence']}\n",
    ]
(OUT_DIR / 'displaypolicyd_c3_results.txt').write_text(
    f'displaypolicyd C3 Template Analysis\n'
    f'Binary: {BINARY}  Arch: x86_64\n'
    f'Top-{len(top_addrs)} functions from C2\n'
    f'{"="*60}\n\n'
    + ('\n'.join(c3_lines) if c3_lines else 'No template hits.\n')
)

print(f'[+] C3 hits  → {OUT_DIR}/displaypolicyd_c3_hits.json')
print(f'[+] C3 text  → {OUT_DIR}/displaypolicyd_c3_results.txt')
print('\n[+] displaypolicyd analysis complete.')
