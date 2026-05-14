#!/usr/bin/env python3
"""
mdns_func_audit.py — Deep manual inspection of mDNSResponder top functions.

Fix v2: handle angr address rebasing — angr loads Mach-O at Linux ELF base
(0x400000) rather than the Mach-O __TEXT base (0x100000000).
We find the top functions directly from angr's CFG by cyclomatic complexity
rather than using the pre-computed C2 addresses from a different load session.

Run on Dell:
    ~/.venv_angr/bin/python3 mdns_func_audit.py \
        > ~/darwin_research/findings/mdns_func_audit.txt 2>&1
"""
import sys, collections
from pathlib import Path

TOOLCHAIN = Path('/path/to/darwin_research/toolchain')
sys.path.insert(0, str(TOOLCHAIN))

import angr
import archinfo
import capstone
import networkx as nx

BINARY = '/path/to/darwin_research/binaries/mDNSResponder'
TOP_N  = 12   # audit top-N functions by cyclomatic complexity

print('=' * 72)
print('mDNSResponder function audit (v2 — cyclomatic ranking from live CFG)')
print('=' * 72)

proj = angr.Project(
    BINARY,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
print(f'\n[+] Loaded: entry={proj.entry:#x}  '
      f'base={proj.loader.main_object.mapped_base:#x}')

print('\n[*] Running CFGFast...')
cfg = proj.analyses.CFGFast(normalize=True)
print(f'    {len(proj.kb.functions)} functions recovered')

# ── Rank functions by cyclomatic complexity directly from angr ─────────────────
print('\n[*] Ranking all functions by cyclomatic complexity...')

def cyclomatic(func) -> int:
    g = func.graph
    return max(1, g.number_of_edges() - g.number_of_nodes() + 2)

ranked = []
for addr, func in proj.kb.functions.items():
    if func.is_plt or func.is_simprocedure or func.is_syscall:
        continue
    try:
        cyc = cyclomatic(func)
        be  = sum(1 for u, v in func.graph.edges()
                  if func.graph.has_edge(v, u) or v.addr <= u.addr)
        ranked.append((cyc, be, addr, func))
    except Exception:
        continue

ranked.sort(reverse=True)
print(f'    Ranked {len(ranked)} non-stub functions')
print(f'\n    Top-{TOP_N} by cyclomatic complexity:')
for i, (cyc, be, addr, func) in enumerate(ranked[:TOP_N]):
    print(f'    [{i+1:2d}] {addr:#x}  cyc={cyc:5d}  be={be:4d}  {func.name}')

TOP_FUNCS = ranked[:TOP_N]

# ── Capstone disassembler ──────────────────────────────────────────────────────
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# ── Symbol resolution ──────────────────────────────────────────────────────────
sym_map: dict[int, str] = {}
for sym in proj.loader.main_object.symbols:
    if sym.name and sym.rebased_addr:
        sym_map[sym.rebased_addr] = sym.name.lstrip('_')

def resolve(addr: int) -> str:
    if addr in sym_map:
        return sym_map[addr]
    fn = proj.kb.functions.get(addr)
    if fn and fn.name:
        return fn.name.lstrip('_')
    return f'sub_{addr:#x}'

INTERESTING = {
    'ntohl', 'ntohs', 'ntohll', 'htonl', 'htons',
    'malloc', 'calloc', 'realloc', 'reallocf', 'free',
    'memcpy', 'memmove', 'memset', 'memcmp', 'bcopy', 'bzero',
    'strcpy', 'strncpy', 'strlcpy', 'strcmp', 'strncmp',
    'strlen', 'strnlen', 'strlcat', 'strcat',
    'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'read', 'write',
    'xpc_', 'mach_msg',
    'LogMsg', 'LogInfo', 'os_log', 'assert', 'abort',
}

# ── Per-function deep audit ────────────────────────────────────────────────────
def audit_function(func, cyc: int, be: int) -> dict:
    addr     = func.addr
    blocks   = list(func.graph.nodes())
    call_sites    = []
    load_sizes    = []
    cmp_constants = []
    arith_shifts  = []

    for block in blocks:
        try:
            raw   = proj.loader.memory.load(block.addr, block.size)
            insns = list(md.disasm(raw, block.addr))
        except Exception:
            continue

        for insn in insns:
            m = insn.mnemonic
            o = insn.op_str

            # Calls
            if m in ('bl', 'blr', 'blraaz', 'blraa'):
                callee_addr = 0
                if m == 'bl':
                    try:
                        callee_addr = int(o.strip().replace('#',''), 16)
                    except Exception:
                        pass
                name = resolve(callee_addr) if callee_addr else f'blr({o})'
                call_sites.append((insn.address, callee_addr, name))

            # Load sizes
            if m.startswith('ldr') or m.startswith('ldur'):
                sz = 8
                if 'b' in m and 'bl' not in m: sz = 1
                elif 'h' in m: sz = 2
                elif 'sw' in m or 'w' in m: sz = 4
                load_sizes.append((insn.address, sz))

            # CMP with immediate
            if m == 'cmp' and '#' in o:
                try:
                    imm = int(o.split(',')[-1].strip().replace('#',''), 0)
                    if imm > 0:
                        cmp_constants.append((insn.address, imm, o))
                except Exception:
                    pass

            # Arithmetic with shift (size multiply)
            if m in ('add','sub','mul') and 'lsl' in o:
                arith_shifts.append((insn.address, m, o))

    interesting = [(s,ca,n) for s,ca,n in call_sites
                   if any(kw in n for kw in INTERESTING)]
    callee_freq = collections.Counter(n for _,_,n in call_sites)
    byte_loads  = sum(1 for _,sz in load_sizes if sz == 1)
    half_loads  = sum(1 for _,sz in load_sizes if sz == 2)

    return {
        'func_addr': addr, 'func_name': func.name,
        'cyc': cyc, 'be': be,
        'n_blocks': len(blocks), 'n_insns': sum(1 for _ in (
            insn for block in blocks
            for insn in md.disasm(
                proj.loader.memory.load(block.addr, block.size), block.addr
            )
        ) if True),
        'call_sites': call_sites, 'interesting': interesting,
        'callee_freq': callee_freq,
        'byte_loads': byte_loads, 'half_loads': half_loads,
        'cmp_constants': cmp_constants, 'arith_shifts': arith_shifts,
    }

def classify(r: dict) -> str:
    byte_lds = r['byte_loads']
    half_lds = r['half_loads']
    allocs   = [n for n in r['callee_freq'] if any(k in n for k in ('malloc','calloc','realloc'))]
    net_io   = [n for n in r['callee_freq'] if any(k in n for k in ('recv','recvfrom','recvmsg','read'))]
    frees    = [n for n in r['callee_freq'] if 'free' in n.lower()]
    memops   = [n for n in r['callee_freq'] if any(k in n for k in ('memcpy','memmove','memset'))]
    ntoh     = [n for n in r['callee_freq'] if any(k in n for k in ('ntohl','ntohs','ntohll'))]

    # Relaxed thresholds for arm64 stripped binaries (compiler unrolls loops,
    # distributes byte loads; symbols absent so call-based detection is blind)
    if byte_lds > 40 and half_lds > 15:
        return ('DNS_PARSER — byte+half load density matches '
                'RFC 1035 label/RR wire parsing (arm64 relaxed)')
    if byte_lds > 25 and half_lds > 10 and r['cyc'] > 60:
        return ('NETWORK_PARSER_CANDIDATE — moderate byte+half density, high cyc')
    if byte_lds > 40 and ntoh:
        return ('NETWORK_PARSER — byte loads + byte-order conversion calls')
    if allocs and memops and not net_io:
        return ('BUFFER_MANAGER — allocator + memcpy without direct network I/O')
    if r['cyc'] > 150 and byte_lds < 20:
        return ('STATE_MACHINE — high cyclomatic, low byte density → switch/dispatch')
    if r['cyc'] > 60 and r['be'] > 20 and byte_lds < 15 and half_lds < 10:
        return ('DISPATCH_LOOP — high cyc+back_edges, minimal memory ops → event loop')
    if frees and allocs and r['be'] > 50:
        return ('POOL_ALLOCATOR — alloc+free in loop structure')
    # Structural signature: large function with many blocks, mid byte density
    if r['n_blocks'] > 200 and byte_lds > 30:
        return ('LARGE_PARSER_CANDIDATE — block count + byte density, stripped binary')
    return 'UNCLASSIFIED — manual inspection required'

def print_audit(r: dict, rank: int):
    print(f'\n{"─" * 72}')
    print(f'[{rank}] {r["func_addr"]:#x}  {r["func_name"]}')
    print(f'    cyc={r["cyc"]}  be={r["be"]}  blocks={r["n_blocks"]}')
    print(f'    byte_loads={r["byte_loads"]}  half_loads={r["half_loads"]}')
    print()

    print('  Top-12 callees:')
    for name, cnt in r['callee_freq'].most_common(12):
        tag = ' *** INTERESTING ***' if any(kw in name for kw in INTERESTING) else ''
        print(f'    {cnt:4d}×  {name}{tag}')

    print()
    print('  Interesting call sites:')
    if r['interesting']:
        for site, ca, name in r['interesting'][:20]:
            print(f'    {site:#x}  {name}')
    else:
        print('    (none)')

    notable = [(a,v,o) for a,v,o in r['cmp_constants'] if v > 0xff]
    if notable:
        print()
        print(f'  Bounds-check candidates (CMP imm > 0xff):')
        for a,v,o in notable[:10]:
            print(f'    {a:#x}  {o}  ({v:#x}={v})')

    if r['arith_shifts']:
        print()
        print(f'  Arithmetic-with-shift (integer multiply patterns):')
        for a,m,o in r['arith_shifts'][:6]:
            print(f'    {a:#x}  {m}  {o}')

    print()
    print(f'  CLASSIFICATION: {classify(r)}')

# ── Run audit on top functions ─────────────────────────────────────────────────
print(f'\n[*] Deep-auditing top {TOP_N} functions...')
for rank, (cyc, be, addr, func) in enumerate(TOP_FUNCS, 1):
    print(f'  Auditing [{rank}/{TOP_N}] {addr:#x} (cyc={cyc})...', end=' ', flush=True)
    try:
        r = audit_function(func, cyc, be)
        print('done')
        print_audit(r, rank)
    except Exception as e:
        print(f'ERROR: {e}')

# ── Priority summary ───────────────────────────────────────────────────────────
print(f'\n\n{"=" * 72}')
print('[PRIORITY SUMMARY]')
print()
print('  Rank  Address      Cyc   Be    Classification')
print('  ' + '─' * 68)
for rank, (cyc, be, addr, func) in enumerate(TOP_FUNCS, 1):
    try:
        r = audit_function(func, cyc, be)
        cls = classify(r)[:55]
    except Exception:
        cls = 'ERROR'
    print(f'  [{rank:2d}]  {addr:#x}  {cyc:5d}  {be:4d}  {cls}')

print(f'\n[*] Done')
