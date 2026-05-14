#!/usr/bin/env python3
"""
airplay_c2c3.py — C2 RMT spectral screen + C3 template scan on AirPlayXPCHelper.

AirPlayXPCHelper is stripped (2 exported symbols) — we rely on angr CFGFast
function recovery throughout. Target for 14 CVEs (4 HIGH): TYPE_CONFUSION,
UAF, NULL_DEREF across macOS 15.3.1 and 15.4 patches.

Run on Dell:
    ~/.venv_angr/bin/python3 ~/darwin_research/toolchain/airplay_c2c3.py \
        > ~/darwin_research/findings/airplay_c2c3.log 2>&1
"""
import sys, json, time
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
from metis.c2_rmt import C2RMTAnalysis
from metis.c3_templates import C3TemplateAnalysis

BINARY  = '/path/to/darwin_research/binaries/AirPlayXPCHelper'
OUT_DIR = Path('/path/to/darwin_research/findings')
TOP_N   = 30   # top functions to run C3 on

print('=' * 72)
print('AirPlayXPCHelper — C2 RMT + C3 Template Analysis')
print('=' * 72)
print(f'Binary: {BINARY}')
t0 = time.time()

# Load project once (arm64 slice)
print('\n[*] Loading binary with angr...')
proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'[*] Loaded in {time.time()-t0:.0f}s')

# ── C2: RMT spectral screen ──────────────────────────────────────────────────
print('\n[C2] Running RMT spectral analysis...')
c2_result = C2RMTAnalysis.from_project(proj).run()

bs     = c2_result.binary_score
ranked = c2_result.functions_ranked
print(f'[C2] {len(ranked)} functions recovered')
print(f'[C2] z_radius={bs.z_radius:.3f}  z_energy={bs.z_energy:.3f}  '
      f'z_entropy={bs.z_entropy:.3f}')
print(f'[C2] Flagged: {bs.flagged}')
print(f'\n[C2] Top {TOP_N} functions by RMT score:')
for i, f in enumerate(ranked[:TOP_N]):
    print(f'  {i+1:2d}. {f.addr:#x}  cyc={f.cyclomatic:4d}  be={f.back_edges:3d}  '
          f'score={f.combined:.3f}  {f.name or ""}')

# Save C2 results
c2_out = OUT_DIR / 'airplay_c2_results.txt'
with open(c2_out, 'w') as fh:
    fh.write('AirPlayXPCHelper C2 RMT Analysis\n')
    fh.write(f'Binary: {BINARY}\n')
    fh.write(f'Functions recovered: {len(ranked)}\n')
    fh.write(f'z_radius={bs.z_radius:.3f}  z_energy={bs.z_energy:.3f}  '
             f'z_entropy={bs.z_entropy:.3f}\n')
    fh.write(f'Flagged: {bs.flagged}\n\n')
    fh.write('Top functions:\n')
    for f in ranked[:TOP_N]:
        fh.write(f'  {f.addr:#x}  cyc={f.cyclomatic:4d}  be={f.back_edges:3d}  '
                 f'score={f.combined:.3f}  {f.name or ""}\n')

top_addrs = [f.addr for f in ranked[:TOP_N]]
json.dump({'binary': BINARY, 'top_addrs': [hex(a) for a in top_addrs]},
          open(OUT_DIR / 'airplay_c2_top_addrs.json', 'w'))
print(f'[C2] Written: {c2_out}  ({time.time()-t0:.0f}s elapsed)')

# ── C3: Template scan on top functions ────────────────────────────────────────
print(f'\n[C3] Running template scan on {TOP_N} functions...')
c3 = C3TemplateAnalysis(proj)
c3_result = c3.analyse_functions(top_addrs)

active = [m for m in c3_result.matches if not m.barrier_hit]
suppressed = [m for m in c3_result.matches if m.barrier_hit]
print(f'[C3] Functions scanned: {c3_result.functions_scanned}')
print(f'[C3] Active hits: {len(active)}  Suppressed: {len(suppressed)}')

hits_by_template = {}
for m in active:
    hits_by_template.setdefault(m.template.name, []).append(m)

for tname, hits in sorted(hits_by_template.items()):
    print(f'\n  [{tname}] {len(hits)} hit(s):')
    for h in hits[:5]:
        print(f'    {h.func_addr:#x}  {h.func_name}  '
              f'conf={h.confidence:.2f}  {h.source_node} → {h.sink_node}')

# Save C3 results
c3_out  = OUT_DIR / 'airplay_c3_results.txt'
c3_json = OUT_DIR / 'airplay_c3_hits.json'
with open(c3_out, 'w') as fh:
    fh.write('AirPlayXPCHelper C3 Template Analysis\n')
    fh.write(f'Functions scanned: {c3_result.functions_scanned}\n')
    fh.write(f'Active hits: {len(active)}  Suppressed: {len(suppressed)}\n\n')
    for tname, hits in sorted(hits_by_template.items()):
        fh.write(f'=== {tname} ({len(hits)} hits) ===\n')
        for h in hits:
            fh.write(f'  func={h.func_addr:#x}  {h.func_name}\n'
                     f'  conf={h.confidence:.2f}  {h.source_node} → {h.sink_node}\n'
                     f'  {h.template.description}\n\n')

json.dump([{
    'template': m.template.name,
    'func_addr': hex(m.func_addr),
    'func_name': m.func_name,
    'source_node': m.source_node,
    'sink_node': m.sink_node,
    'confidence': m.confidence,
    'barrier_hit': m.barrier_hit,
    'description': m.template.description,
} for m in c3_result.matches], open(c3_json, 'w'), indent=2)

print(f'\n[C3] Written: {c3_out}')
print(f'[C3] Written: {c3_json}')
print(f'\n[DONE] Total time: {time.time()-t0:.0f}s')
print(f'\n=== SUMMARY ===')
print(f'Binary: AirPlayXPCHelper (stripped, {len(ranked)} functions recovered)')
print(f'C2: z_radius={bs.z_radius:.3f}  flagged={bs.flagged}')
print(f'C3: {len(active)} active hits  {len(suppressed)} suppressed  '
      f'templates={list(hits_by_template.keys())}')
if active:
    print(f'HIGH INTEREST: {", ".join(hits_by_template.keys())}')
