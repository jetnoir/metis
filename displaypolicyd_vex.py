#!/usr/bin/env python3
"""
displaypolicyd_vex.py — VEX IR deep analysis of top C2 functions in displaypolicyd

displaypolicyd is x86_64-only (329 KB, z_entropy=-8.81 — most anomalous from libexec batch).
Top function sub_100017eb5: cyclomatic=53, back_edges=28 — deep loop nesting, very suspicious.

Analysis goals:
  1. Scan VEX IR for dangerous constant patterns:
       - Fixed-offset memory accesses (potential OOB)
       - Length/size comparisons against constants
       - Shifts into array indices
  2. Detect memcpy/memmove/memset calls with size arguments derived from input
  3. Find integer arithmetic preceding memory operations (wrap potential)
  4. Look for stack buffer patterns: alloca-style operations (Sub64(RSP, Const))
  5. Summarise all dangerous sites with surrounding context

Usage (Dell):
  ~/.venv_angr/bin/python3 displaypolicyd_vex.py \
      --binary ~/darwin_research/binaries/libexec/displaypolicyd \
      --outdir ~/darwin_research/findings
"""
from __future__ import annotations
import sys, json, argparse
from pathlib import Path
from typing import Optional

_here = Path(__file__).parent
sys.path.insert(0, str(_here))

import angr, archinfo, pyvex

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='/path/to/darwin_research/binaries/libexec/displaypolicyd')
parser.add_argument('--outdir', default='/path/to/darwin_research/findings')
parser.add_argument('--top-addrs', default='/path/to/darwin_research/findings/displaypolicyd_c2_top_addrs.json')
parser.add_argument('--max-blocks', type=int, default=500, help='Max VEX blocks per function')
args = parser.parse_args()

BINARY   = args.binary
OUT_DIR  = Path(args.outdir)
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Load top addresses from C2
with open(args.top_addrs) as f:
    top_data = json.load(f)
TOP_FUNCS = top_data[:10]   # analyse top-10 by score

print(f'[*] displaypolicyd VEX IR Analysis')
print(f'    Binary : {BINARY}')
print(f'    Top-{len(TOP_FUNCS)} functions by C2 score')
print()

print(f'[*] Loading binary as x86_64...')
proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('x86_64')},
)
print(f'    Arch  : {proj.arch.name}')
print(f'    Entry : {hex(proj.entry)}')
print()

# ── VEX scanning helpers ──────────────────────────────────────────────────────

def iter_blocks(func_addr: int, max_blocks: int = 500):
    """Yield (block_addr, pyvex.IRSB) for up to max_blocks blocks from func_addr."""
    visited = set()
    queue   = [func_addr]
    count   = 0
    while queue and count < max_blocks:
        addr = queue.pop(0)
        if addr in visited:
            continue
        visited.add(addr)
        try:
            block = proj.factory.block(addr)
            irsb  = block.vex
            yield addr, irsb
            count += 1
            # Follow successors
            for succ in irsb.constant_jump_targets:
                if succ not in visited:
                    queue.append(succ)
            if irsb.default_exit_target and irsb.default_exit_target not in visited:
                queue.append(irsb.default_exit_target)
        except Exception:
            continue

def stmt_repr(stmt) -> str:
    """Best-effort string repr of a pyvex statement."""
    try:
        return str(stmt)
    except Exception:
        return repr(stmt)

def expr_consts(expr) -> list[int]:
    """Extract all integer constants from a pyvex expression tree."""
    results = []
    if hasattr(expr, 'con') and hasattr(expr.con, 'value'):
        results.append(expr.con.value)
    for attr in ('args', 'data', 'addr', 'guard', 'iftrue', 'iffalse'):
        child = getattr(expr, attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for c in child:
                results.extend(expr_consts(c))
        elif hasattr(child, '__class__'):
            results.extend(expr_consts(child))
    return results

def is_large_const(val: int, min_size: int = 0x10, max_size: int = 0x10000) -> bool:
    """True if val looks like a buffer size or array stride (not a code address)."""
    return min_size <= val <= max_size

def scan_function(func_addr: int, label: str, max_blocks: int = 500) -> dict:
    """
    Scan VEX IR of a function for dangerous patterns.
    Returns a dict of findings.
    """
    sites = []

    # Track: RSP subtract (stack allocation), memcpy calls, large constant accesses
    alloca_sites   = []   # SubN(RSP, Const) — stack buffer allocation
    oob_sites      = []   # Load/Store with suspiciously large constant offset
    memcpy_sites   = []   # Call to a PLT/GOT entry that looks like memcpy/memmove/memset
    arith_sites    = []   # Add/Mul with large const preceding a memory op
    cmp_sites      = []   # Compare with size-looking constant

    blocks_scanned = 0

    for blk_addr, irsb in iter_blocks(func_addr, max_blocks):
        blocks_scanned += 1
        stmts = irsb.statements
        for i, stmt in enumerate(stmts):
            st = stmt_repr(stmt)
            st_type = type(stmt).__name__

            # ── Stack allocation: PUT(RSP, Sub64(GET(RSP), Const(N))) ──────
            if st_type == 'IRStmt_Put' and 'Sub64' in st and 'rsp' in st.lower():
                # Check if subtracting a constant from RSP
                consts = expr_consts(stmt.data)
                for c in consts:
                    if 0x10 <= c <= 0x10000:
                        alloca_sites.append({
                            'block': hex(blk_addr),
                            'stmt_idx': i,
                            'desc': f'Stack alloc: SUB RSP, {hex(c)} ({c} bytes)',
                            'ir': st[:200],
                        })

            # ── Large constant in Load offset ────────────────────────────
            if st_type in ('IRStmt_Store',):
                consts = expr_consts(stmt)
                for c in consts:
                    if is_large_const(c, 0x100, 0x8000):
                        oob_sites.append({
                            'block': hex(blk_addr),
                            'stmt_idx': i,
                            'desc': f'Store with large const offset {hex(c)}',
                            'ir': st[:200],
                        })

            # ── WrTmp with Load — check offset constants ──────────────────
            if st_type == 'IRStmt_WrTmp':
                expr = stmt.data
                expr_type = type(expr).__name__
                if expr_type == 'IRExpr_Load':
                    # Check if load address involves a large constant
                    consts = expr_consts(expr.addr)
                    for c in consts:
                        if is_large_const(c, 0x100, 0x8000):
                            oob_sites.append({
                                'block': hex(blk_addr),
                                'stmt_idx': i,
                                'desc': f'Load with large const offset {hex(c)}',
                                'ir': st[:200],
                            })
                # ── Binop with large const ────────────────────────────────
                elif expr_type == 'IRExpr_Binop':
                    op = expr.op
                    if any(x in op for x in ('Add', 'Mul', 'Shl')):
                        consts = expr_consts(expr)
                        for c in consts:
                            if is_large_const(c, 0x100, 0x100000):
                                arith_sites.append({
                                    'block': hex(blk_addr),
                                    'stmt_idx': i,
                                    'op': op,
                                    'const': hex(c),
                                    'ir': st[:200],
                                })

            # ── Conditional compare with size-looking constant ────────────
            if st_type == 'IRStmt_WrTmp':
                expr = stmt.data
                if type(expr).__name__ == 'IRExpr_Binop' and 'Cmp' in expr.op:
                    consts = expr_consts(expr)
                    for c in consts:
                        if is_large_const(c, 0x100, 0x10000):
                            cmp_sites.append({
                                'block': hex(blk_addr),
                                'stmt_idx': i,
                                'op': expr.op,
                                'const': hex(c),
                                'ir': st[:200],
                            })

    return {
        'func_addr':   hex(func_addr),
        'label':       label,
        'blocks':      blocks_scanned,
        'alloca':      alloca_sites,
        'oob_loads':   oob_sites,
        'arith':       arith_sites,
        'cmp_size':    cmp_sites,
        'total_sites': len(alloca_sites) + len(oob_sites) + len(arith_sites),
    }

# ── Run analysis ──────────────────────────────────────────────────────────────

all_results = []
report_lines = [
    'displaypolicyd VEX IR Analysis',
    f'Binary: {BINARY}',
    f'Top-{len(TOP_FUNCS)} functions by C2 score',
    '=' * 70,
    '',
]

for entry in TOP_FUNCS:
    addr  = int(entry['addr'], 16)
    label = f'sub_{entry["addr"][2:]}'
    print(f'[*] Scanning {label} (cyclomatic={entry["cyclomatic"]}, back_edges={entry["back_edges"]})...')
    try:
        r = scan_function(addr, label, args.max_blocks)
    except Exception as e:
        r = {'func_addr': entry['addr'], 'label': label, 'error': str(e)}
    all_results.append(r)
    total = r.get('total_sites', 0)
    print(f'    {r.get("blocks", "?")} blocks  alloca={len(r.get("alloca",[]))}  '
          f'oob_loads={len(r.get("oob_loads",[]))}  arith={len(r.get("arith",[]))}  '
          f'cmp_size={len(r.get("cmp_size",[]))}')

# ── Write report ──────────────────────────────────────────────────────────────

for r in all_results:
    addr_str = r.get('func_addr', '?')
    label    = r.get('label', '?')
    report_lines.append(f'┌─ {label}  [{addr_str}]  blocks={r.get("blocks","?")}')

    if 'error' in r:
        report_lines.append(f'│  ERROR: {r["error"]}')
        report_lines.append('')
        continue

    alloca   = r.get('alloca', [])
    oob      = r.get('oob_loads', [])
    arith    = r.get('arith', [])
    cmp_size = r.get('cmp_size', [])

    if alloca:
        report_lines.append(f'│  STACK ALLOCS ({len(alloca)}):')
        for s in alloca[:5]:
            report_lines.append(f'│    @ {s["block"]}  {s["desc"]}')

    if oob:
        report_lines.append(f'│  LARGE-OFFSET LOADS/STORES ({len(oob)}):')
        for s in oob[:5]:
            report_lines.append(f'│    @ {s["block"]}  {s["desc"]}')

    if arith:
        report_lines.append(f'│  ARITHMETIC WITH LARGE CONST ({len(arith)}):')
        for s in arith[:5]:
            report_lines.append(f'│    @ {s["block"]}  op={s["op"]} const={s["const"]}')

    if cmp_size:
        report_lines.append(f'│  SIZE COMPARISONS ({len(cmp_size)}):')
        for s in cmp_size[:5]:
            report_lines.append(f'│    @ {s["block"]}  op={s["op"]} const={s["const"]}')

    if not any([alloca, oob, arith, cmp_size]):
        report_lines.append('│  (no dangerous patterns detected)')

    report_lines.append('')

# ── Save ──────────────────────────────────────────────────────────────────────

json_out = OUT_DIR / 'displaypolicyd_vex_results.json'
txt_out  = OUT_DIR / 'displaypolicyd_vex_report.txt'

json_out.write_text(json.dumps(all_results, indent=2))
txt_out.write_text('\n'.join(report_lines))

print(f'\n[+] JSON → {json_out}')
print(f'[+] Text → {txt_out}')
print('[+] displaypolicyd VEX analysis complete.')
