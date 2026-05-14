#!/usr/bin/env python3
"""
mdns_c6_v2.py — C6 taint analysis on _GetLargeResourceRecord (fixed context stub)

Fix over v1: x0 (mDNS *m) is now a concrete non-null pointer to a zeroed stub
region so the function's prologue reads succeed. Also enables
SYMBOL_FILL_UNCONSTRAINED_REGISTERS + SYMBOL_FILL_UNCONSTRAINED_MEMORY so
callee-saved register restores from stack don't error.

Run on Dell:
    ~/.venv_angr/bin/python3 ~/darwin_research/toolchain/mdns_c6_v2.py \
        > ~/darwin_research/findings/mdns_c6_v2.txt 2>&1
"""
import sys, collections
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
ao = angr.options
import archinfo
import claripy

BINARY = '/path/to/darwin_research/binaries/mDNSResponder'
TARGET_FUNC = 0x10003a878   # _GetLargeResourceRecord (same in both versions)

# ── packet layout ──────────────────────────────────────────────────────────
PKTBUF_ADDR  = 0x0000_5000_0000   # concrete packet base
STUB_ADDR    = 0x0000_6000_0000   # mDNS *m context stub (zeroed)
LARGECR_ADDR = 0x0000_7000_0000   # LargeCacheRecord output buffer
STUB_SIZE    = 0x8000             # 32 KB of zeroed struct space

# An A-record RR wire format:
#   2B name-pointer  2B type  2B class  4B TTL  2B RDLENGTH  <RDATA>
RR_START = 0
PKT_HEADER_SIZE = 12  # DNS header before RRs
pkt_end = PKTBUF_ADDR + PKT_HEADER_SIZE + 2+2+2+4+2 + 4  # header + RR header + 4 B rdata

print('=' * 72)
print('mDNSResponder C6 v2 — _GetLargeResourceRecord (fixed context stub)')
print('=' * 72)

proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'[+] Loaded: base={proj.loader.main_object.mapped_base:#x}')

# ── initial state ──────────────────────────────────────────────────────────
init_opts = {
    ao.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    ao.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    ao.LAZY_SOLVES,
}
st = proj.factory.blank_state(
    addr=TARGET_FUNC,
    add_options=init_opts,
)

# Map a zeroed stub for mDNS *m (x0) so struct reads succeed
st.memory.store(STUB_ADDR, b'\x00' * STUB_SIZE)

# Map a zeroed output buffer for LargeCacheRecord (x6)
st.memory.store(LARGECR_ADDR, b'\x00' * 0x4000)

# Build a concrete DNS packet with symbolic RDLENGTH
pkt = bytearray(pkt_end - PKTBUF_ADDR)
# DNS header (12 bytes at offset 0): ID=0x1234, FLAGS=0x8000 (response), 1 answer
pkt[0:2]  = b'\x12\x34'  # ID
pkt[2:4]  = b'\x80\x00'  # FLAGS (response)
pkt[8:10] = b'\x00\x01'  # ANCOUNT = 1
# RR at offset 12: name=\xc0\x00 (pointer to offset 0), TYPE=A, CLASS=IN, TTL=60, RDLEN=sym
rr_off = PKT_HEADER_SIZE
pkt[rr_off:rr_off+2]   = b'\xc0\x00'        # name pointer
pkt[rr_off+2:rr_off+4] = b'\x00\x01'        # TYPE A
pkt[rr_off+4:rr_off+6] = b'\x00\x01'        # CLASS IN
pkt[rr_off+6:rr_off+10]= b'\x00\x00\x00\x3c' # TTL 60
# RDLENGTH (bytes 10-11 of RR) — symbolic
sym_rdlen = claripy.BVS('rdlen', 16)
# RDATA (4 bytes: 1.2.3.4)
pkt[rr_off+12:rr_off+16] = b'\x01\x02\x03\x04'

# Store concrete bytes then overlay symbolic rdlen
st.memory.store(PKTBUF_ADDR, bytes(pkt))
st.memory.store(PKTBUF_ADDR + rr_off + 10, sym_rdlen)

# Pointer passed as x2 = ptr to start of the RR (after DNS header)
rr_ptr = PKTBUF_ADDR + rr_off

# Set registers:
# x0 = mDNS *m  (non-null concrete stub)
# x1 = DNSMessage *msg (packet base)
# x2 = ptr (current position = start of RR)
# x3 = end (past last byte of packet)
# x4 = interfaceID (concrete 1)
# x5 = RecordType (concrete 0x20 = kDNSRecordTypePacketAns)
# x6 = LargeCacheRecord *largecr (output buffer)
st.regs.x0 = STUB_ADDR
st.regs.x1 = PKTBUF_ADDR
st.regs.x2 = rr_ptr
st.regs.x3 = pkt_end
st.regs.x4 = 1
st.regs.x5 = 0x20
st.regs.x6 = LARGECR_ADDR
# PAC / link register setup for arm64e
st.regs.x30 = 0xdead_beef_0000   # sentinel return address

print(f'[+] Initial state:')
print(f'    x0=mDNS*={STUB_ADDR:#x}  x1=pkt={PKTBUF_ADDR:#x}')
print(f'    x2=ptr={rr_ptr:#x}  x3=end={pkt_end:#x}')
print(f'    sym_rdlen = {sym_rdlen}  (16-bit, unconstrained)')

# ── taint helpers ──────────────────────────────────────────────────────────
TAINT_VARS = {'rdlen'}

def is_tainted(expr):
    try:
        return bool(TAINT_VARS & expr.variables)
    except Exception:
        return False

CHECK_REGS = ['x0','x1','x2','x3','x4','x5','x6','x7','x8']

# ── simulate ───────────────────────────────────────────────────────────────
simgr = proj.factory.simulation_manager(st)
taint_hits = []
MAX_STEPS = 400

print(f'\n[+] Simulating {MAX_STEPS} steps...')
for step in range(MAX_STEPS):
    if not simgr.active:
        break
    simgr.step()

    for st2 in simgr.active:
        try:
            pc = st2.solver.eval(st2.regs.pc)
        except Exception:
            continue
        for rn in CHECK_REGS:
            try:
                rv = getattr(st2.regs, rn)
                if is_tainted(rv):
                    taint_hits.append((step, pc, rn, rv, st2))
            except Exception:
                pass

    if len(simgr.active) > 20:
        simgr.active = simgr.active[:20]

    if len(simgr.errored) > 0 and step < 5:
        err = simgr.errored[0]
        print(f'  [!] Error state at step {step}: {err.error}')
        simgr.errored.clear()

    if (step+1) % 50 == 0:
        print(f'    step={step+1:4d}  active={len(simgr.active):3d}  '
              f'dead={len(simgr.deadended):3d}  hits={len(taint_hits)}')

print(f'\n[C6] Done: steps={step+1}  active={len(simgr.active)}  '
      f'deadended={len(simgr.deadended)}  errored={len(simgr.errored)}')

# ── report ─────────────────────────────────────────────────────────────────
seen = set()
unique_hits = []
for step_n, pc, rn, rv, st2 in taint_hits:
    key = (pc, rn)
    if key not in seen:
        seen.add(key)
        unique_hits.append((step_n, pc, rn, rv, st2))

print(f'\n[C6] Unique taint sites: {len(unique_hits)}')

rdlen_hits = []
for step_n, pc, rn, rv, st2 in unique_hits[:50]:
    has_rdlen = any('rdlen' in v for v in rv.variables)
    tag = ' [RDLEN]' if has_rdlen else ''
    print(f'  step={step_n:4d}  PC={pc:#x}  reg={rn}{tag}')
    print(f'           AST={str(rv)[:120]}')
    if has_rdlen:
        rdlen_hits.append((step_n, pc, rn, rv, st2))
        try:
            mn = st2.solver.min(rv)
            mx = st2.solver.max(rv)
            span = mx - mn
            print(f'           min={mn:#x}  max={mx:#x}  span={span:#x}')
            if span > 0xFFFF:
                can_oor = st2.solver.satisfiable(
                    extra_constraints=[sym_rdlen > 4])  # 4 bytes actual rdata
                print(f'           can rdlen > 4 (OOB): {can_oor}')
                if can_oor:
                    print(f'  *** POTENTIAL OOB — rdlen flows to {rn} unchecked ***')
        except Exception as ex:
            print(f'           solver: {ex}')

print(f'\n[C6] RDLEN-tainted sites: {len(rdlen_hits)}')
print('\n' + '='*72)
if rdlen_hits:
    print('VERDICT: sym_rdlen reaches register argument(s) — check callee at those PCs')
    print('         for malloc/mDNSPlatformMemAllocate calls taking tainted size')
else:
    print('VERDICT: No rdlen taint in checked registers')
    print('         Either validated early (end-ptr check) or flows via memory not regs')
print()
