#!/usr/bin/env python3
"""
bluetoothd_c2c3.py — C2 RMT screen + C3 template scan on bluetoothd.

bluetoothd is 23MB — use from_project() path (lief+capstone CFGFast).
Network-adjacent attack surface via BLE/BR+EDR.

Run on Dell:
    ~/.venv_angr/bin/python3 ~/darwin_research/toolchain/bluetoothd_c2c3.py \
        > ~/darwin_research/findings/bluetoothd_c2c3.log 2>&1
"""
import sys, json, time
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
from metis.c2_rmt import C2RMTAnalysis
from metis.c3_templates import C3TemplateAnalysis

BINARY  = '/path/to/darwin_research/binaries/bluetoothd'
OUT_DIR = Path('/path/to/darwin_research/findings')
TOP_N   = 25

print('=' * 72)
print('bluetoothd — C2 RMT + C3 Template Analysis')
print('=' * 72)
print(f'Binary: {BINARY}  (23MB)')
t0 = time.time()

# Pre-extract arm64 slice to avoid CLE universal2 bug with dyld chained fixups
import lief
import tempfile, os

fat = lief.MachO.parse(BINARY)
thin_path = BINARY + '_arm64_thin'
if not Path(thin_path).exists() or Path(thin_path).stat().st_size < 1_000_000:
    print(f'[*] Extracting arm64 thin slice → {thin_path}')
    arm64_binary = None
    for i in range(fat.size):
        b = fat.at(i)
        if b.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            arm64_binary = b
            break
    if arm64_binary is None:
        print('[!] No arm64 slice found in fat binary')
        sys.exit(1)
    arm64_binary.write(thin_path)
    print(f'[*] Thin slice written ({Path(thin_path).stat().st_size/1e6:.1f} MB)')
else:
    print(f'[*] Using cached thin slice: {thin_path}')

# Monkey-patch CLE Mach-O backend to gracefully handle dyld chained fixup
# IndexError (libOrdinal out of range on arm64e binaries with large import tables)
import cle.backends.macho.macho as _macho_mod
_orig_parse_dyld = _macho_mod.MachO._parse_dyld_chained_fixups
def _safe_parse_dyld(self):
    try:
        _orig_parse_dyld(self)
    except (IndexError, KeyError) as e:
        import logging
        logging.getLogger('cle').warning(
            f'_parse_dyld_chained_fixups failed ({e}): skipping relocs for this slice')
_macho_mod.MachO._parse_dyld_chained_fixups = _safe_parse_dyld

# Load thin slice with angr
print(f'\n[*] Loading arm64 thin binary with angr...')
proj = angr.Project(
    thin_path,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'[*] Loaded in {time.time()-t0:.0f}s')

# ── C2 ────────────────────────────────────────────────────────────────────────
print('\n[C2] Running RMT spectral analysis...')
c2_result = C2RMTAnalysis.from_project(proj).run()

bs     = c2_result.binary_score
ranked = c2_result.functions_ranked
print(f'[C2] {len(ranked)} functions recovered in {time.time()-t0:.0f}s')
print(f'[C2] z_radius={bs.z_radius:.3f}  z_energy={bs.z_energy:.3f}  '
      f'z_entropy={bs.z_entropy:.3f}')
print(f'[C2] Flagged: {bs.flagged}')
print(f'\n[C2] Top {TOP_N} functions:')
for i, f in enumerate(ranked[:TOP_N]):
    print(f'  {i+1:2d}. {f.addr:#x}  cyc={f.cyclomatic:4d}  be={f.back_edges:3d}  '
          f'score={f.combined:.3f}  {f.name or ""}')

# Save
c2_out = OUT_DIR / 'bluetoothd_c2_results.txt'
with open(c2_out, 'w') as fh:
    fh.write(f'bluetoothd C2 RMT\nBinary: {BINARY}\n')
    fh.write(f'Functions: {len(ranked)}\n')
    fh.write(f'z_radius={bs.z_radius:.3f}  z_energy={bs.z_energy:.3f}  '
             f'z_entropy={bs.z_entropy:.3f}\nFlagged: {bs.flagged}\n\n')
    for f in ranked[:TOP_N]:
        fh.write(f'  {f.addr:#x}  cyc={f.cyclomatic}  be={f.back_edges}  '
                 f'score={f.combined:.3f}  {f.name or ""}\n')

top_addrs = [f.addr for f in ranked[:TOP_N]]
json.dump({'binary': BINARY, 'top_addrs': [hex(a) for a in top_addrs]},
          open(OUT_DIR / 'bluetoothd_c2_top_addrs.json', 'w'))
print(f'[C2] Written: {c2_out}  ({time.time()-t0:.0f}s elapsed)')

# ── C3 ────────────────────────────────────────────────────────────────────────
print(f'\n[C3] Template scan on top {TOP_N} functions...')
c3 = C3TemplateAnalysis(proj)
c3_result = c3.analyse_functions(top_addrs)

active     = [m for m in c3_result.matches if not m.barrier_hit]
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

c3_out  = OUT_DIR / 'bluetoothd_c3_results.txt'
c3_json = OUT_DIR / 'bluetoothd_c3_hits.json'
with open(c3_out, 'w') as fh:
    fh.write(f'bluetoothd C3\n')
    fh.write(f'Functions scanned: {c3_result.functions_scanned}\n')
    fh.write(f'Active hits: {len(active)}  Suppressed: {len(suppressed)}\n\n')
    for tname, hits in sorted(hits_by_template.items()):
        fh.write(f'=== {tname} ({len(hits)}) ===\n')
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
print(f'\n=== SUMMARY ===')
print(f'bluetoothd: {len(ranked)} functions, {time.time()-t0:.0f}s total')
print(f'C2: z_radius={bs.z_radius:.3f}  flagged={bs.flagged}')
print(f'C3: {len(active)} active hits — {list(hits_by_template.keys())}')
