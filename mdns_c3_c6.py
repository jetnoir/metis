#!/usr/bin/env python3
"""
mdns_c3_c6.py — C3 template scan + C6 symbolic taint on mDNSResponder top functions.

mDNSResponder C2 result (2026-04-19):
  z_radius  = -3.27  z_energy = -22.64  z_entropy = -89.09  (FLAGGED / reliable)
  Top func  = 0x10001c6df  cyc=632  be=127  (main DNS packet parser candidate)
  n_funcs   = 15,924  engine=full

Top 10 addresses from C2 (by combined score):
  0x10001c6df  0x100043449  0x10006cc30  0x10003d6aa  0x1000722a5
  0x10000df64  0x100079f00  0x100017fd3  0x10006ca1c  0x1000ff402

Run on Dell:
    ~/.venv_angr/bin/python3 mdns_c3_c6.py > ~/darwin_research/findings/mdns_c3_c6_results.txt 2>&1
"""
import sys, json, re
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
import claripy
import pyvex

BINARY = '/path/to/darwin_research/binaries/mDNSResponder'

# C2 top-10 function addresses
TOP_ADDRS = [
    0x10001c6df,
    0x100043449,
    0x10006cc30,
    0x10003d6aa,
    0x1000722a5,
    0x10000df64,
    0x100079f00,
    0x100017fd3,
    0x10006ca1c,
    0x1000ff402,
]

print(f'[*] Loading {BINARY}')
proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'    arch={proj.arch.name}  entry={proj.entry:#x}')

# ── Phase 1: C3 template scan ─────────────────────────────────────────────────
print('\n[*] Phase 1: C3 template scan on top-10 C2 functions')
print('='*70)

from metis.c3_templates import C3TemplateAnalysis

c3 = C3TemplateAnalysis(proj)
result = c3.analyse_functions(TOP_ADDRS)
result.print_report(min_confidence=0.30)

# Save C3 hits for C6 targeting
c3_top_addrs = result.top_function_addrs
c3_matches = [(m.template.name, m.func_addr, m.func_name,
               m.source_node, m.sink_node, round(m.confidence, 3))
              for m in result.actionable]

print(f'\n[C3] Actionable matches: {len(result.actionable)}')
print(f'[C3] Top function addresses for C6: {[hex(a) for a in c3_top_addrs]}')

# ── Phase 2: VEX IR scan for interesting patterns ─────────────────────────────
print('\n[*] Phase 2: VEX IR scan — looking for recv/malloc/free call patterns')
print('='*70)

INTERESTING = {
    'recv', 'recvfrom', 'recvmsg', 'read',
    'malloc', 'calloc', 'realloc', 'free',
    'memcpy', 'memmove', 'memset',
    'ntohl', 'ntohs',
}

cfg = proj.analyses.CFGFast(normalize=False)

def get_func_calls(func_addr):
    """Return list of (call_site, callee_name) for a function."""
    try:
        func = proj.kb.functions.get(func_addr)
        if not func:
            return []
        calls = []
        for block in func.graph.nodes():
            try:
                irsb = proj.factory.block(block.addr).vex
                if irsb.jumpkind != 'Ijk_Call':
                    continue
                callee_addr = 0
                nxt = irsb.next
                if hasattr(nxt, 'con'):
                    callee_addr = nxt.con.value
                name = 'unknown'
                sym = proj.loader.find_symbol(callee_addr)
                if sym and sym.name:
                    name = sym.name.lstrip('_')
                else:
                    fn = proj.kb.functions.get(callee_addr)
                    if fn:
                        name = fn.name.lstrip('_')
                calls.append((block.addr, callee_addr, name))
            except Exception:
                continue
        return calls
    except Exception as e:
        return []


print(f'\nCall inventory for top-10 functions:')
func_call_map = {}
for addr in TOP_ADDRS:
    calls = get_func_calls(addr)
    interesting_calls = [(site, ca, n) for site, ca, n in calls
                         if any(kw in n for kw in INTERESTING)]
    func_call_map[addr] = calls
    if interesting_calls:
        print(f'\n  {addr:#x} ({len(calls)} total calls, {len(interesting_calls)} interesting):')
        for site, ca, n in interesting_calls:
            print(f'    {site:#x}  {n}  (callee={ca:#x})')

# ── Phase 3: C6 symbolic micro-execution on most promising function ───────────
print('\n[*] Phase 3: C6 symbolic taint — targeting top function 0x10001c6df')
print('='*70)

TARGET_FUNC = 0x10001c6df
TARGET_CALLS = func_call_map.get(TARGET_FUNC, [])

# Find recv/recvfrom call sites in the function
recv_sites = [(site, ca, n) for site, ca, n in TARGET_CALLS
              if any(kw in n for kw in ('recv', 'recvfrom', 'recvmsg', 'read'))]
malloc_sites = [(site, ca, n) for site, ca, n in TARGET_CALLS
                if any(kw in n for kw in ('malloc', 'calloc', 'realloc'))]
free_sites = [(site, ca, n) for site, ca, n in TARGET_CALLS
              if 'free' in n]
memcpy_sites = [(site, ca, n) for site, ca, n in TARGET_CALLS
                if any(kw in n for kw in ('memcpy', 'memmove', 'memset'))]

print(f'\n  recv/read sites  : {[(hex(s),n) for s,_,n in recv_sites]}')
print(f'  malloc/calloc    : {[(hex(s),n) for s,_,n in malloc_sites]}')
print(f'  free sites       : {[(hex(s),n) for s,_,n in free_sites]}')
print(f'  memcpy sites     : {[(hex(s),n) for s,_,n in memcpy_sites]}')

# Pick the first recv site as C6 start — we'll initialise a symbolic packet buffer
# and trace forward to see what reaches malloc/memcpy size arguments.
if recv_sites:
    start_addr, _, recv_name = recv_sites[0]
    print(f'\n  [C6] Start addr: {start_addr:#x}  (after {recv_name})')

    # Build initial state with symbolic recv buffer
    # ARM64 calling convention: x0=fd, x1=buf, x2=len, x3=flags
    # After recv returns, x0 = bytes_read (symbolic, attacker controlled)
    state = proj.factory.blank_state(addr=start_addr)

    # Symbolic receive size (attacker controls how many bytes were "received")
    sym_recv_len = claripy.BVS('recv_len', 64)
    state.regs.x0 = sym_recv_len      # return value = bytes read (attacker controlled)

    # Symbolic packet buffer — x1 holds the buffer pointer
    PKTBUF_SIZE = 0x10000
    pktbuf = claripy.BVS('packet_data', PKTBUF_SIZE * 8)
    pktbuf_addr = 0x4100000
    state.memory.store(pktbuf_addr, pktbuf)
    state.regs.x1 = pktbuf_addr

    # Mark recv return (x0) as tainted — this is our attacker-controlled source
    print(f'\n  [C6] Symbolic recv_len (x0 post-recv): {sym_recv_len}')
    print(f'  [C6] Packet buffer at {pktbuf_addr:#x} ({PKTBUF_SIZE} bytes symbolic)')

    # Step forward up to 500 instructions, collect all states
    simgr = proj.factory.simgr(state)
    MAX_STEPS = 500
    print(f'  [C6] Stepping forward (max {MAX_STEPS} instructions)...')

    try:
        simgr.run(n=MAX_STEPS)
    except Exception as e:
        print(f'  [C6] simgr stopped: {e}')

    all_states = (simgr.active or []) + (simgr.deadended or []) + (simgr.unsat or [])
    print(f'  [C6] States: active={len(simgr.active)}  deadended={len(simgr.deadended)}  '
          f'unsat={len(simgr.unsat)}  errored={len(simgr.errored)}')

    # Inspect final states for taint in x0 (malloc size arg) or x2 (memcpy size arg)
    print(f'\n  [C6] Checking final states for tainted size arguments:')
    hits = 0
    for i, st in enumerate(all_states[:20]):
        pc = st.regs.pc
        x0 = st.regs.x0
        x2 = st.regs.x2
        x0_syms = list(x0.variables)
        x2_syms = list(x2.variables)

        tainted_args = []
        if any('recv_len' in v or 'packet_data' in v for v in x0_syms):
            tainted_args.append(f'x0={x0} (malloc size / recv fd)')
        if any('recv_len' in v or 'packet_data' in v for v in x2_syms):
            tainted_args.append(f'x2={x2} (memcpy/recv size)')

        if tainted_args:
            hits += 1
            try:
                pc_val = st.solver.eval(pc)
                print(f'\n  *** TAINT HIT in state {i} at PC={pc_val:#x} ***')
            except Exception:
                print(f'\n  *** TAINT HIT in state {i} at PC=<symbolic> ***')
            for arg in tainted_args:
                print(f'      {arg}')

    if hits == 0:
        print('  No direct taint hits in final states (function may need longer trace '
              'or taint enters via struct field — check C3 matches above).')

    # Also check: is sym_recv_len still unconstrained at any malloc/calloc call site?
    print(f'\n  [C6] Checking for unconstrained sym_recv_len at malloc/calloc sites:')
    for site, ca, n in malloc_sites:
        print(f'    Malloc site {site:#x} ({n}) — C6 would need separate targeted run')

else:
    print('\n  [C6] No recv sites found in top function — check call inventory above.')
    print('  [C6] Falling back to most promising C3 hit function (if any).')
    if c3_top_addrs:
        print(f'  [C6] C3 suggests targeting: {[hex(a) for a in c3_top_addrs[:3]]}')

# ── Summary ───────────────────────────────────────────────────────────────────
print('\n' + '='*70)
print('[SUMMARY]')
print(f'  Binary   : {BINARY}')
print(f'  C2 score : z_radius=-3.27  z_energy=-22.64  z_entropy=-89.09  FLAGGED')
print(f'  C3 hits  : {len(result.actionable)} actionable matches')
for name, faddr, fname, src, snk, conf in c3_matches:
    print(f'    [{name}] @ {faddr:#x} {fname}  {conf:.0%}  {src} → {snk}')
print(f'  Top C2 func: 0x10001c6df  cyc=632  be=127')
print(f'  Next step: targeted C6 on C3-flagged functions above')
print()
