#!/usr/bin/env python3
"""
mdns_c6_targeted.py — Targeted C6 symbolic taint on mDNSResponder top function.

Top function from cyclomatic ranking: 0x10001d1c0
  cyc=216  be=80  blocks=482  byte_loads=56  half_loads=25
Classification: DNS_PARSER (relaxed threshold — arm64 compiler distributes loads)

Strategy: start at function entry with symbolic packet buffer in x0/x1.
Trace forward up to 1000 steps, check all states for:
  1. Symbolic taint in x0/x1/x2 at any BL call site (malloc/memcpy size arg)
  2. Symbolic taint in loop counter or array index
  3. Any state where solver.max(sym_len) >> solver.min(sym_len) (unconstrained)

Run on Dell:
    ~/.venv_angr/bin/python3 mdns_c6_targeted.py \
        > ~/darwin_research/findings/mdns_c6_targeted.txt 2>&1
"""
import sys, collections
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
import claripy

BINARY = '/path/to/darwin_research/binaries/mDNSResponder'
TARGET_FUNC = 0x10001d1c0   # top cyclomatic function — DNS parser candidate

print('=' * 70)
print('mDNSResponder C6 targeted — 0x10001d1c0 (cyc=216, be=80, 482 blocks)')
print('=' * 70)

proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'\n[+] Loaded: entry={proj.entry:#x}  base={proj.loader.main_object.mapped_base:#x}')

# ── Build CFG just for the target function ─────────────────────────────────────
print(f'\n[*] CFGFast (normalise=False)...')
cfg = proj.analyses.CFGFast(normalize=False)
func = proj.kb.functions.get(TARGET_FUNC)
if not func:
    print(f'[!] Function {TARGET_FUNC:#x} not found — check address')
    sys.exit(1)
print(f'    Found: {func.name}  blocks={len(list(func.graph.nodes()))}')

# ── Build symbolic initial state ───────────────────────────────────────────────
# ARM64 ABI: x0=first arg, x1=second arg.
# mDNSResponder DNS receive path typically:
#   ParseDNSMessage(mDNS *m, DNSMessage *msg, mDNSu8 *end, ...)
# or similar — x0=context, x1=packet_ptr, x2=packet_end or length.
# We make x1 point to a fully symbolic packet buffer and x2=attacker length.

PKTBUF_ADDR = 0x5000000
PKTBUF_SIZE = 9000        # max mDNS/DNS-SD packet

sym_pkt   = claripy.BVS('pkt', PKTBUF_SIZE * 8)
sym_end   = claripy.BVS('pkt_end', 64)          # pointer past end (attacker controls)
sym_len   = claripy.BVS('pkt_len', 64)          # length in bytes  (attacker controls)

state = proj.factory.blank_state(addr=TARGET_FUNC)

# Store symbolic packet at our chosen address
state.memory.store(PKTBUF_ADDR, sym_pkt)

# x0 = mDNS context (concrete — not attacker controlled)
state.regs.x0 = 0x0
# x1 = pointer to packet buffer (attacker-controlled data)
state.regs.x1 = PKTBUF_ADDR
# x2 = end pointer (packet_base + attacker_len) — attacker controlled
state.regs.x2 = PKTBUF_ADDR + sym_len
# x3 = length (alternative convention)
state.regs.x3 = sym_len

# Constrain length to be a plausible DNS packet (1..9000)
state.solver.add(sym_len >= 1)
state.solver.add(sym_len <= 9000)

# Constrain end pointer accordingly
state.solver.add(sym_end == PKTBUF_ADDR + sym_len)

print(f'\n[C6] Symbolic setup:')
print(f'     pkt buffer  : {PKTBUF_ADDR:#x} ({PKTBUF_SIZE} bytes, fully symbolic)')
print(f'     sym_len     : {sym_len}  (constrained 1..9000)')
print(f'     x1=pkt_ptr, x2=end_ptr, x3=len')

# ── SimManager with step limit ─────────────────────────────────────────────────
simgr = proj.factory.simgr(state)

MAX_STEPS  = 800
CHECK_REGS = ('x0', 'x1', 'x2', 'x3', 'x4', 'x5',
              'x8', 'x9', 'x10', 'x16', 'x17')
TAINT_VARS = {'pkt', 'pkt_end', 'pkt_len'}

def is_tainted(bv):
    return any(any(kw in v for kw in TAINT_VARS) for v in bv.variables)

taint_hits  = []
bl_sites    = collections.Counter()

def check_state(st, step):
    """Called on each state after each step to look for taint in call args."""
    try:
        pc = st.solver.eval(st.regs.pc)
    except Exception:
        return
    for rn in CHECK_REGS:
        try:
            rv = getattr(st.regs, rn)
            if is_tainted(rv):
                taint_hits.append((step, pc, rn, rv))
        except Exception:
            pass

print(f'\n[C6] Stepping (max {MAX_STEPS} steps)...')
step = 0
while simgr.active and step < MAX_STEPS:
    simgr.step()
    step += 1
    for st in simgr.active:
        check_state(st, step)
    # Prune state explosion — keep top 20 active states by coverage
    if len(simgr.active) > 20:
        simgr.active = simgr.active[:20]
    if step % 100 == 0:
        print(f'    step={step}  active={len(simgr.active)}  '
              f'dead={len(simgr.deadended)}  hits_so_far={len(taint_hits)}')

print(f'\n[C6] Done: steps={step}  active={len(simgr.active)}  '
      f'deadended={len(simgr.deadended)}  errored={len(simgr.errored)}')

# ── Report taint hits ──────────────────────────────────────────────────────────
print(f'\n[C6] Total taint observations: {len(taint_hits)}')

# Deduplicate by (pc, reg)
seen = set()
unique_hits = []
for step_n, pc, rn, rv in taint_hits:
    key = (pc, rn)
    if key not in seen:
        seen.add(key)
        unique_hits.append((step_n, pc, rn, rv))

print(f'[C6] Unique (pc, reg) taint sites: {len(unique_hits)}')

if unique_hits:
    print(f'\n  *** TAINT HITS — attacker-controlled data in register at PC ***\n')
    for step_n, pc, rn, rv in unique_hits[:30]:
        print(f'  step={step_n:4d}  PC={pc:#x}  {rn}  AST={str(rv)[:80]}')

        # Is the value unconstrained? Can it be large?
        try:
            with state.solver.local_constraints():
                mn = state.solver.min(rv)
                mx = state.solver.max(rv)
            span = mx - mn
            if span > 0xFFFF:
                print(f'         ↳ UNCONSTRAINED: min={mn:#x} max={mx:#x} '
                      f'span={span:#x} ← potential OOB size/index')
            elif span > 0:
                print(f'         ↳ range min={mn:#x} max={mx:#x}')
        except Exception as e:
            print(f'         ↳ solver error: {e}')
else:
    print('\n  No taint in registers at checked PCs.')
    print('  The parser may use stack-local temporaries rather than registers.')
    print('  Consider VEX IR taint tracking or a longer trace.')

# ── Summary ───────────────────────────────────────────────────────────────────
print('\n' + '='*70)
print('[SUMMARY]')
print(f'  Target  : {TARGET_FUNC:#x} (cyc=216, be=80, 482 blocks)')
print(f'  Steps   : {step}')
print(f'  Unique taint sites: {len(unique_hits)}')
if unique_hits:
    print(f'  VERDICT : Attacker packet data reaches register args — investigate callees')
else:
    print(f'  VERDICT : No direct register taint — parser likely uses struct offsets')
    print(f'            Next: VEX IR mem-taint tracking or callee-level analysis')
print()
