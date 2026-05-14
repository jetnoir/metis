#!/usr/bin/env python3
"""
mdns_c6_rr.py — Targeted C6 on _GetLargeResourceRecord (0x10003a878)

Prototype (from open-source mDNSResponder):
  mDNSu8 *GetLargeResourceRecord(
      mDNS *const m,           x0 — context (stub)
      const DNSMessage *msg,   x1 — packet base (symbolic)
      const mDNSu8 *ptr,       x2 — current position (symbolic)
      const mDNSu8 *const end, x3 — end of packet (ptr + attacker_len)
      mDNSInterfaceID ifid,    x4 — interface (concrete)
      mDNSu8 RecordType,       x5 — record type (concrete)
      LargeCacheRecord *largecr x6 — output buffer (concrete stub)
  )

Key question: does attacker-controlled RDLENGTH (16-bit field at *ptr+8)
reach a copy/allocation size argument unchecked?

Run on Dell:
    ~/.venv_angr/bin/python3 mdns_c6_rr.py \
        > ~/darwin_research/findings/mdns_c6_rr.txt 2>&1
"""
import sys, collections
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
import claripy

BINARY = '/path/to/darwin_research/binaries/mDNSResponder'

# Addresses from lief symbol extraction
TARGET_FUNC = 0x10003a878   # _GetLargeResourceRecord

print('=' * 72)
print('mDNSResponder C6 — _GetLargeResourceRecord (0x10003a878)')
print('=' * 72)

proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'[+] Loaded: entry={proj.entry:#x}  base={proj.loader.main_object.mapped_base:#x}')

cfg = proj.analyses.CFGFast(normalize=False)
func = proj.kb.functions.get(TARGET_FUNC)
if func:
    print(f'[+] CFG: {func.name}  blocks={len(list(func.graph.nodes()))}')
else:
    print(f'[!] Function not found in CFG at {TARGET_FUNC:#x} — using addr directly')

# ── DNS wire-format layout for an A record (simplest test case) ──────────────
# A resource record wire format:
#   2 bytes NAME (pointer 0xC000 + offset, or label sequence)
#   2 bytes TYPE  (e.g. 0x0001 = A)
#   2 bytes CLASS (e.g. 0x0001 = IN)
#   4 bytes TTL
#   2 bytes RDLENGTH  ← attacker controlled
#   N bytes RDATA     ← only RDLENGTH bytes available
#
# We place the ptr at the start of the RR (after NAME has been parsed).
# So at *ptr:   TYPE (2B) | CLASS (2B) | TTL (4B) | RDLENGTH (2B) | RDATA (...)

PKTBUF_ADDR  = 0x6000000
PKTBUF_SIZE  = 0x10000    # 64KB packet buffer
LARGECR_ADDR = 0x7000000  # stub LargeCacheRecord output
LARGECR_SIZE = 0x10000    # must be big enough for the struct

# Symbolic packet: attacker controls all bytes
sym_pkt = claripy.BVS('dns_pkt', PKTBUF_SIZE * 8)

# sym_rdlen: the 16-bit RDLENGTH field at ptr+8 (after TYPE+CLASS+TTL)
# We keep it unconstrained to see if it reaches any size argument
sym_rdlen = claripy.BVS('rdlen', 16)

# ptr points to start of RR TYPE field (ptr+8 = RDLENGTH)
RR_START = PKTBUF_ADDR + 0x100   # offset 0x100 into buffer

state = proj.factory.blank_state(addr=TARGET_FUNC)

# Store symbolic packet data
state.memory.store(PKTBUF_ADDR, sym_pkt)

# Overlay concrete TYPE+CLASS+TTL, then symbolic RDLENGTH at +8
# TYPE=A (0x0001), CLASS=IN (0x0001), TTL=120 (0x00000078)
state.memory.store(RR_START,     claripy.BVV(0x0001, 16))  # TYPE = A
state.memory.store(RR_START + 2, claripy.BVV(0x0001, 16))  # CLASS = IN
state.memory.store(RR_START + 4, claripy.BVV(120,    32))  # TTL = 120
state.memory.store(RR_START + 8, sym_rdlen)                 # RDLENGTH — symbolic!
# RDATA: only 4 bytes actually present in packet (but RDLENGTH may claim more)
state.memory.store(RR_START + 10, claripy.BVV(0x7f000001, 32))  # 127.0.0.1

# end pointer: just after the 4-byte RDATA (legitimate packet boundary)
pkt_end = RR_START + 10 + 4

# Zero out the LargeCacheRecord output buffer
state.memory.store(LARGECR_ADDR, claripy.BVV(0, LARGECR_SIZE * 8))

# Set up registers per ABI
state.regs.x0 = 0x0          # mDNS *m — null stub (will cause early return on deref)
state.regs.x1 = PKTBUF_ADDR  # DNSMessage *msg — packet base
state.regs.x2 = RR_START     # const mDNSu8 *ptr — start of RR
state.regs.x3 = pkt_end      # const mDNSu8 *end
state.regs.x4 = 0x1          # InterfaceID
state.regs.x5 = 0x01         # RecordType = kDNSRecordTypePacketAuth
state.regs.x6 = LARGECR_ADDR # LargeCacheRecord *largecr

print(f'\n[C6] Setup:')
print(f'     pkt buffer : {PKTBUF_ADDR:#x} ({PKTBUF_SIZE} bytes symbolic)')
print(f'     RR at      : {RR_START:#x}')
print(f'     pkt_end    : {pkt_end:#x}  (only 4 bytes of RDATA present)')
print(f'     sym_rdlen  : {sym_rdlen}  (UNCONSTRAINED — attacker may set to 65535)')
print(f'     LargeCR    : {LARGECR_ADDR:#x}')

# ── Run symbolic execution ──────────────────────────────────────────────────
simgr = proj.factory.simgr(state)
MAX_STEPS  = 600
TAINT_VARS = {'dns_pkt', 'rdlen'}
CHECK_REGS = ('x0','x1','x2','x3','x4','x5','x8','x9','x10')

def is_tainted(bv):
    return any(any(kw in v for kw in TAINT_VARS) for v in bv.variables)

taint_hits = []  # (step, pc, reg_name, ast)

print(f'\n[C6] Stepping (max {MAX_STEPS} steps, state cap 15)...')
for step in range(MAX_STEPS):
    if not simgr.active:
        break
    simgr.step()

    for st in simgr.active:
        try:
            pc = st.solver.eval(st.regs.pc)
        except Exception:
            continue
        for rn in CHECK_REGS:
            try:
                rv = getattr(st.regs, rn)
                if is_tainted(rv):
                    taint_hits.append((step, pc, rn, rv, st))
            except Exception:
                pass

    if len(simgr.active) > 15:
        simgr.active = simgr.active[:15]

    if (step+1) % 100 == 0:
        print(f'    step={step+1}  active={len(simgr.active)}  '
              f'dead={len(simgr.deadended)}  hits={len(taint_hits)}')

print(f'\n[C6] Done: steps={step+1}  active={len(simgr.active)}  '
      f'deadended={len(simgr.deadended)}  errored={len(simgr.errored)}')

# ── Report ──────────────────────────────────────────────────────────────────
seen = set()
unique_hits = []
for step_n, pc, rn, rv, st in taint_hits:
    key = (pc, rn)
    if key not in seen:
        seen.add(key)
        unique_hits.append((step_n, pc, rn, rv, st))

print(f'\n[C6] Unique taint sites: {len(unique_hits)}')

rdlen_hits = []
for step_n, pc, rn, rv, st in unique_hits[:40]:
    has_rdlen = any('rdlen' in v for v in rv.variables)
    tag = ' [RDLEN]' if has_rdlen else ' [pkt_data]'
    print(f'  step={step_n:4d}  PC={pc:#x}  {rn}  {tag}')
    print(f'           AST={str(rv)[:100]}')
    if has_rdlen:
        rdlen_hits.append((step_n, pc, rn, rv, st))
        try:
            mn = st.solver.min(rv)
            mx = st.solver.max(rv)
            span = mx - mn
            print(f'           min={mn:#x}  max={mx:#x}  span={span:#x}')
            if span > 0xFFFF:
                # Test if rdlen can exceed pkt_end - RR_START - 10 (= 4)
                oor_limit = pkt_end - RR_START - 10  # = 4
                can_oor = st.solver.satisfiable(
                    extra_constraints=[sym_rdlen > oor_limit])
                print(f'           can rdlen>{oor_limit} (OOB): {can_oor}')
                if can_oor:
                    print(f'           *** POTENTIAL OOB READ/ALLOC — rdlen flows to {rn} unchecked ***')
        except Exception as ex:
            print(f'           solver: {ex}')

print(f'\n[C6] RDLEN-tainted register hits: {len(rdlen_hits)}')

# ── Summary ─────────────────────────────────────────────────────────────────
print('\n' + '='*72)
print('[SUMMARY]')
print(f'  Target   : _GetLargeResourceRecord @ {TARGET_FUNC:#x}')
print(f'  sym_rdlen: attacker-controlled RDLENGTH field (16-bit, unconstrained)')
print(f'  pkt_end  : {pkt_end:#x} (only 4 bytes of RDATA actually present)')
print()
if rdlen_hits:
    print(f'  VERDICT: sym_rdlen flows into register arg(s) — likely size/alloc arg')
    print(f'  NEXT: check which callee at those PC values takes the tainted register')
    print(f'        as an allocation size (malloc/mDNSPlatformMemAllocate)')
else:
    print(f'  VERDICT: No direct rdlen register taint detected in {step+1} steps')
    print(f'  NOTE: function may validate rdlen early (end-ptr check)')
    print(f'        or use it only as a struct field offset → VEX IR taint needed')
print()
