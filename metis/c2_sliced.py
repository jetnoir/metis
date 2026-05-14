"""
c2_sliced.py — C2: Function-level sliced RMT screener (large-binary edition)
=============================================================================

Drop-in replacement for C2RMTAnalysis that handles binaries of any size by
skipping angr CFGFast and building the call graph via Capstone linear scan.

Architecture (4-LLM consensus — GPT-4o, Gemini, Grok, DeepSeek)
-----------------------------------------------------------------
Phase 1  cle.Loader standalone — load binary metadata, no CFGFast, ~1 s
Phase 2  Collect function starts: entry + symbol table (TYPE_FUNCTION)
Phase 3  Capstone linear scan of executable sections
           • Record direct CALL/BL targets → new function starts
           • Build nx.DiGraph: caller_func → callee_func
Phase 4  Filter IAT thunks and PLT stubs (tiny trampoline functions)
Phase 5  RMT spectral analysis identical to c2_rmt.py (same null model)
Phase 6  pyvex on top-N functions by call-graph degree
           → cyclomatic complexity + back-edge count
Phase 7  Combined score + rank → C2Result

Why this beats CFGFast for large binaries
-----------------------------------------
angr CFGFast builds a whole-binary CFG (all basic blocks + edges) before
returning control. That pass requires O(binary_size) memory and takes minutes
on 10+ MB binaries. This module needs only:
    • CLE metadata load  (O(binary_size))
    • One Capstone linear scan  (O(binary_size), ~1–2 s for 50 MB)
    • pyvex on top-N functions  (O(top_N × avg_func_size), ~1–5 s)
Total: typically 5–30 s on any realistic binary, vs. 5–60 min for CFGFast.

Trade-offs vs c2_rmt.py
------------------------
• Misses indirect calls (function pointers, ObjC msgSend, vtables).
  Call graph is sparser. z-scores may be slightly attenuated.
• Inlined functions and jump tables resolved by CFGFast are not recovered.
• Tail calls (B/JMP to another function) are detected heuristically only.
• When CFGFast is feasible (binary < ~3 MB), c2_rmt.py is more accurate.

When to use which
-----------------
    binary < 3 MB, Mach-O/ELF    → c2_rmt (more accurate call graph)
    binary > 3 MB or any PE       → c2_sliced (avoids OOM / timeout)
    batch screening overnight     → c2_sliced (faster per binary)

Usage
-----
    from metis.c2_sliced import C2SlicedAnalysis

    result = C2SlicedAnalysis('/usr/lib/libcurl.so').run()
    result.print_report()

    # Same interface as C2RMTAnalysis
    top_addrs = result.top_function_addrs[:10]

Requires: cle, capstone, pyvex, networkx, numpy, scipy
© 2026 Stuart Thomas, trading as TriageForge. Apache 2.0.
"""

from __future__ import annotations

import bisect
import logging
import platform
from typing import Optional

import archinfo
import capstone
import capstone.arm64
import capstone.x86
import cle
import networkx as nx
import numpy as np
import pyvex
import pyvex.expr
import pyvex.stmt

from metis.c2_rmt import (
    ANOMALY_Z_THRESHOLD,
    MIN_NODES_RMT,
    NULL_SAMPLES,
    BinaryRMTScore,
    C2Result,
    FunctionScore,
    SpectralMetrics,
    _count_back_edges,
    _function_combined_score,
    _spectral_metrics,
    _z,
)

log = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────────

TOP_N_PYVEX    = 40    # run pyvex on this many top-degree functions
MIN_FUNC_BYTES = 16    # skip functions shorter than this (nop padding)
THUNK_MAX_INSN = 5     # functions with ≤ this many instructions = thunk candidate
MAX_BLOCK_BYTES = 400  # max bytes to lift per pyvex block


# ── Architecture helpers ───────────────────────────────────────────────────────

def _host_arch() -> archinfo.Arch:
    """Return aarch64 on Apple Silicon, x86_64 otherwise."""
    if platform.machine().lower() in ('arm64', 'aarch64'):
        return archinfo.arch_from_id('aarch64')
    return archinfo.arch_from_id('x86_64')


def _capstone_for(arch: archinfo.Arch) -> capstone.Cs:
    """
    Build a Capstone disassembler for the given arch.

    detail=True  — operand access needed for call target extraction.
    skipdata=True — skip invalid/non-instruction bytes rather than stopping.
                    Essential for Mach-O: the __TEXT segment starts with the
                    Mach-O header (magic cffaedfe ...) which is not valid
                    ARM64; without skipdata, disasm returns 0 instructions.
    """
    name = arch.name.upper()
    if name in ('AARCH64', 'ARM64E'):
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif name == 'AMD64':
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif name == 'X86':
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif 'ARM' in name:
        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        raise ValueError(f'c2_sliced: unsupported arch {name!r}')
    cs.detail   = True
    cs.skipdata = True   # skip header bytes / data islands without stopping
    return cs


# ── Instruction classification ─────────────────────────────────────────────────

def _direct_call_target(insn: capstone.CsInsn, arch: archinfo.Arch) -> Optional[int]:
    """
    If `insn` is a direct function call, return the callee address.
    Returns None for indirect calls and non-call instructions.
    """
    name = arch.name.upper()

    if name in ('AARCH64', 'ARM64E'):
        # BL <imm> — Branch with Link (AArch64 direct call)
        if insn.id == capstone.arm64.ARM64_INS_BL and insn.operands:
            return insn.operands[0].imm

    elif name in ('AMD64', 'X86'):
        # CALL imm — direct call on x86/x86-64
        if insn.id == capstone.x86.X86_INS_CALL and insn.operands:
            op = insn.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm

    elif 'ARM' in name:
        # BL / BLX imm — direct call on ARM32
        if hasattr(capstone, 'arm'):
            if insn.id in (capstone.arm.ARM_INS_BL, capstone.arm.ARM_INS_BLX):
                if insn.operands and insn.operands[0].type == capstone.arm.ARM_OP_IMM:
                    return insn.operands[0].imm

    return None


def _unconditional_jump_target(insn: capstone.CsInsn, arch: archinfo.Arch) -> Optional[int]:
    """
    If `insn` is an unconditional direct jump (potential tail call), return target.
    """
    name = arch.name.upper()

    if name in ('AARCH64', 'ARM64E'):
        # B <imm> — unconditional branch (tail call if target is a function start)
        if insn.id == capstone.arm64.ARM64_INS_B and insn.operands:
            return insn.operands[0].imm

    elif name in ('AMD64', 'X86'):
        # JMP imm — unconditional direct jump
        if insn.id == capstone.x86.X86_INS_JMP and insn.operands:
            op = insn.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                return op.imm

    return None


def _is_mem_jump(insn: capstone.CsInsn, arch: archinfo.Arch) -> bool:
    """True if insn is an indirect jump through memory (IAT thunk signature)."""
    name = arch.name.upper()

    if name in ('AMD64', 'X86'):
        if insn.id == capstone.x86.X86_INS_JMP and insn.operands:
            return insn.operands[0].type == capstone.x86.X86_OP_MEM

    elif name in ('AARCH64', 'ARM64E'):
        # BR Xn or BRAA — indirect branch through register
        if insn.id in (capstone.arm64.ARM64_INS_BR,
                       capstone.arm64.ARM64_INS_BRAAZ,
                       capstone.arm64.ARM64_INS_BRABZ):
            return True

    return False


# ── Thunk detection ────────────────────────────────────────────────────────────

def _is_thunk(data: bytes, base_addr: int, arch: archinfo.Arch,
              cs: capstone.Cs) -> bool:
    """
    Heuristic: is this function a PLT stub or IAT thunk?

    Patterns matched:
      x86/x86-64 IAT:  JMP QWORD PTR [rip+offset]  (FF 25 ...)
      x86/x86-64 IAT:  MOV reg, [mem]; JMP reg      (≤ 3 insns)
      AArch64 stub:    ADRP; LDR; BR  (≤ 4 insns, ends in indirect branch)
    """
    insns = list(cs.disasm(data[:min(len(data), THUNK_MAX_INSN * 8)], base_addr))
    if not insns or len(insns) > THUNK_MAX_INSN:
        return False

    name = arch.name.upper()

    if name in ('AMD64', 'X86'):
        for insn in insns:
            if _is_mem_jump(insn, arch):
                return True

    elif name in ('AARCH64', 'ARM64E'):
        ids = [i.id for i in insns]
        if (ids and ids[0] == capstone.arm64.ARM64_INS_ADRP and
                any(i in ids for i in (capstone.arm64.ARM64_INS_BR,
                                       capstone.arm64.ARM64_INS_BRAAZ))):
            return True

    return False


# ── pyvex per-function CFG metrics ─────────────────────────────────────────────

def _pyvex_func_metrics(
    memory: 'cle.Clemory',
    arch: archinfo.Arch,
    start_addr: int,
    end_addr: int,
) -> tuple[int, int]:
    """
    Compute (cyclomatic_complexity, back_edges) for the function at start_addr.

    Iteratively lifts basic blocks from start_addr to end_addr via pyvex,
    building a local CFG from VEX IR exit statements. Falls back to (1, 0)
    on any error or if the function is trivial.
    """
    if end_addr <= start_addr + 4:
        return 1, 0

    func_range = range(start_addr, end_addr)
    local_cfg  = nx.DiGraph()
    worklist   = [start_addr]
    visited: set[int] = set()

    while worklist:
        addr = worklist.pop()
        if addr in visited or addr not in func_range:
            continue
        visited.add(addr)
        local_cfg.add_node(addr)

        max_bytes = min(MAX_BLOCK_BYTES, end_addr - addr)
        try:
            raw  = bytes(memory.load(addr, max_bytes))
            irsb = pyvex.lift(raw, addr, arch,
                               bytes_offset=0,
                               max_bytes=max_bytes,
                               opt_level=0)
        except Exception:
            continue

        jk        = irsb.jumpkind
        fall_addr = addr + irsb.size  # byte-after-block = fallthrough candidate

        # ARM64e / unrecognised instruction (pacibsp, blraa, blrab, retab, autibsp
        # etc.): pyvex returns Ijk_NoDecode. VEX does not model AArch64e PAC.
        #
        # Two sub-cases:
        #   size == 0 → NoDecode on the FIRST instruction; skip 4 bytes.
        #   size > 0  → NoDecode on the instruction at addr+size; we already
        #               decoded size bytes, and the undecoded instruction is at
        #               fall_addr. Skip it (+4) to continue traversal.
        #
        # This covers blraa/blrab (authenticated indirect call, fall-through to
        # +4 after PAC insn) and handles retab (authenticated RET) conservatively
        # by continuing — we may add a phantom edge but won't miss real paths.
        if jk == 'Ijk_NoDecode':
            # Skip past the undecoded instruction
            skip = (addr + 4) if irsb.size == 0 else (fall_addr + 4)
            if skip in func_range and skip != addr:
                local_cfg.add_edge(addr, skip)
                worklist.append(skip)
            # Also collect any intermediate Exit statements (conditional branches
            # pyvex DID decode before hitting the PAC instruction)
            for stmt in irsb.statements:
                if stmt.tag != 'Ist_Exit':
                    continue
                if not hasattr(stmt.dst, 'value'):
                    continue
                target = stmt.dst.value
                if target in func_range and target != addr:
                    local_cfg.add_edge(addr, target)
                    worklist.append(target)
            continue

        # Collect exits from intermediate statements (conditional branches).
        # Note: Ist_Exit.dst is pyvex.const.U64 / pyvex.const.U32 etc.
        # (NOT pyvex.expr.Const) — use hasattr to access .value safely.
        for stmt in irsb.statements:
            if stmt.tag != 'Ist_Exit':
                continue
            if not hasattr(stmt.dst, 'value'):
                continue
            target = stmt.dst.value
            if target in func_range and target != addr:
                local_cfg.add_edge(addr, target)
                worklist.append(target)

        # Final successor(s) from irsb.next.
        # irsb.next can be pyvex.expr.Const (unconditional direct branch) or
        # pyvex.expr.RdTmp (indirect / computed branch / fallthrough in VEX
        # IR for conditional branches). When it's RdTmp, fall_addr is the
        # correct sequential fallthrough address for non-call blocks.
        if jk == 'Ijk_Ret':
            pass  # terminal
        elif jk == 'Ijk_Call':
            # Call instruction: execution continues at fallthrough after return
            if fall_addr in func_range:
                local_cfg.add_edge(addr, fall_addr)
                worklist.append(fall_addr)
        elif hasattr(irsb.next, 'con') and hasattr(irsb.next.con, 'value'):
            # Unconditional direct branch target as a Const expression
            target = irsb.next.con.value
            if target in func_range and target != addr:
                local_cfg.add_edge(addr, target)
                worklist.append(target)
        elif hasattr(irsb.next, 'value'):
            # Const stored directly on .next (alt pyvex layout)
            target = irsb.next.value
            if target in func_range and target != addr:
                local_cfg.add_edge(addr, target)
                worklist.append(target)
        else:
            # RdTmp / indirect next — sequential fallthrough
            if fall_addr in func_range:
                local_cfg.add_edge(addr, fall_addr)
                worklist.append(fall_addr)

    n_nodes = local_cfg.number_of_nodes()
    n_edges = local_cfg.number_of_edges()

    if n_nodes < 2:
        return 1, 0

    cyclomatic = max(1, n_edges - n_nodes + 2)
    back_edges = _count_back_edges(local_cfg)
    return cyclomatic, back_edges


# ── Main analysis class ────────────────────────────────────────────────────────

class C2SlicedAnalysis:
    """
    C2 RMT screener using function-level slicing — no CFGFast required.

    Handles binaries of any size. Returns the same C2Result as C2RMTAnalysis.

    Parameters
    ----------
    binary_path     : path to binary (Mach-O, ELF, PE — any architecture)
    n_null_samples  : configuration-model null replicates (default 50)
    top_n_pyvex     : number of top functions to analyse with pyvex (default 40)
    arch_override   : archinfo.Arch to force (default: auto from binary/host)

    Example
    -------
    ::

        result = C2SlicedAnalysis('/usr/bin/openssl').run()
        result.print_report()
    """

    def __init__(
        self,
        binary_path: str,
        n_null_samples: int = NULL_SAMPLES,
        top_n_pyvex: int = TOP_N_PYVEX,
        arch_override: Optional[archinfo.Arch] = None,
    ) -> None:
        self.binary_path    = binary_path
        self.n_null_samples = n_null_samples
        self.top_n_pyvex    = top_n_pyvex
        self._arch_override = arch_override
        self._loader: Optional[cle.Loader] = None
        self._obj = None   # resolved backend (child_objects[0] for Universal2)

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load binary with CLE (no angr.Project, no CFGFast). Idempotent."""
        if self._loader is not None:
            return

        arch = self._arch_override or _host_arch()
        log.info('C2S: loading %s  arch=%s', self.binary_path, arch.name)

        self._loader = cle.Loader(
            self.binary_path,
            auto_load_libs=False,
            perform_relocations=False,
            main_opts={'arch': arch},
        )

        # Universal2 (Mach-O fat binary) wraps the actual arch-specific
        # object in child_objects[0]. The wrapper exposes empty
        # segments/sections — use the real child backend for all metadata.
        main = self._loader.main_object
        if hasattr(main, 'child_objects') and main.child_objects:
            self._obj = main.child_objects[0]
            log.info('C2S: Universal2 wrapper — using child: %s',
                     type(self._obj).__name__)
        else:
            self._obj = main

        log.info('C2S: loaded  mapped_base=%#x  arch=%s  range=[%#x:%#x]',
                 self._obj.mapped_base,
                 self._obj.arch.name,
                 self._obj.min_addr,
                 self._obj.max_addr)

    # ── Function discovery ─────────────────────────────────────────────────────

    def _initial_func_starts(self) -> set[int]:
        """
        Collect function start addresses from binary metadata.

        Sources:
          1. Entry point (always present)
          2. Symbol table — TYPE_FUNCTION / is_function symbols

        Note: for stripped binaries (common on macOS) only the entry point
        will be found here; the rest come from CALL targets in Phase 3.
        """
        obj    = self._obj
        starts: set[int] = set()

        if obj.entry:
            starts.add(obj.entry)

        in_range = range(obj.min_addr, obj.max_addr + 1)
        for sym in obj.symbols:
            addr = sym.rebased_addr
            if sym.is_function and addr in in_range:
                starts.add(addr)

        log.info('C2S: %d function starts from symbols + entry', len(starts))
        return starts

    def _symbol_name_map(self) -> dict[int, str]:
        """Build address → symbol name lookup for function scoring."""
        m: dict[int, str] = {}
        in_range = range(self._obj.min_addr, self._obj.max_addr + 1)
        for sym in self._obj.symbols:
            addr = sym.rebased_addr
            if addr in in_range and sym.name:
                m.setdefault(addr, sym.name)
        return m

    # ── Executable sections ────────────────────────────────────────────────────

    def _exec_segments(self) -> list[tuple[int, bytes]]:
        """
        Return [(base_addr, data), ...] for all executable segments/sections.

        Strategy (in order):
          1. Segments with is_executable=True (ELF PT_LOAD+PF_X, PE .text)
          2. Sections with is_executable=True (Mach-O __text, __stubs etc.)
          3. Sections named __text, __stubs, __stub_helper (Mach-O fallback)

        Segments are preferred over sections; sections used when segment list
        is empty or returns no executable regions (Mach-O universal binaries).
        """
        obj  = self._obj
        segs: list[tuple[int, bytes]] = []

        # Strategy 1: segments
        for seg in obj.segments:
            if not seg.is_executable or seg.filesize == 0:
                continue
            # seg.vaddr on a CLE object is already rebased for ELF/PE;
            # for Mach-O the seg.vaddr IS the final loaded address
            addr = seg.vaddr
            try:
                data = bytes(self._loader.memory.load(addr, seg.filesize))
                if data:
                    segs.append((addr, data))
            except Exception as exc:
                log.debug('C2S: segment read failed at %#x: %s', addr, exc)

        if segs:
            log.info('C2S: %d executable segment(s) from segment table', len(segs))
            return segs

        # Strategy 2+3: sections (common for Mach-O)
        _EXEC_NAMES = ('__text', '__stubs', '__stub_helper',
                       '__auth_stubs', '__picsymbolstub')
        seen: set[int] = set()
        for sec in getattr(obj, 'sections', []):
            is_exec = getattr(sec, 'is_executable', False)
            name    = getattr(sec, 'name', '')
            if not is_exec and name not in _EXEC_NAMES:
                continue
            size = getattr(sec, 'filesize', 0) or getattr(sec, 'vsize', 0)
            if size == 0:
                continue
            addr = sec.vaddr
            if addr in seen:
                continue
            seen.add(addr)
            try:
                data = bytes(self._loader.memory.load(addr, size))
                if data:
                    segs.append((addr, data))
            except Exception as exc:
                log.debug('C2S: section read failed at %#x (%s): %s', addr, name, exc)

        log.info('C2S: %d executable section(s)', len(segs))
        return segs

    # ── Capstone scan ──────────────────────────────────────────────────────────

    def _capstone_scan(
        self,
        func_starts: set[int],
        segments: list[tuple[int, bytes]],
        cs: capstone.Cs,
        arch: archinfo.Arch,
    ) -> tuple[nx.DiGraph, list[int], set[int]]:
        """
        Linear Capstone scan — discover call targets and build call graph.

        Two passes:
          Pass 1  Scan all executable bytes for direct CALL/BL → collect
                  new function starts not already in symbol table.
          Pass 2  Re-scan to build edges: for each CALL instruction, find
                  the containing function (binary search on sorted starts)
                  and add edge caller → callee.

        Tail calls (unconditional B/JMP to a known function start) are also
        treated as call-graph edges.

        Returns
        -------
        (call_graph, sorted_starts, all_starts)
        """
        # Build set of segment address ranges for fast "in executable?" check
        seg_ranges = [(base, base + len(data)) for base, data in segments]

        def in_exec(addr: int) -> bool:
            return any(lo <= addr < hi for lo, hi in seg_ranges)

        # ── Pass 1: discover CALL targets ────────────────────────────────────
        call_targets: set[int] = set()
        for base, data in segments:
            try:
                for insn in cs.disasm(data, base):
                    t = _direct_call_target(insn, arch)
                    if t is not None and in_exec(t):
                        call_targets.add(t)
            except Exception:
                continue

        all_starts   = func_starts | call_targets
        sorted_starts = sorted(all_starts)
        log.info('C2S: %d function starts (symbols=%d + CALL targets=%d)',
                 len(all_starts), len(func_starts), len(call_targets - func_starts))

        # ── Build call graph: all starts as nodes ────────────────────────────
        cg = nx.DiGraph()
        for addr in all_starts:
            cg.add_node(addr)

        # ── Pass 2: build edges ───────────────────────────────────────────────
        # func_for_addr: binary search — largest start ≤ instruction address
        def func_for_addr(addr: int) -> Optional[int]:
            idx = bisect.bisect_right(sorted_starts, addr) - 1
            return sorted_starts[idx] if idx >= 0 else None

        for base, data in segments:
            try:
                for insn in cs.disasm(data, base):
                    # Direct call
                    t = _direct_call_target(insn, arch)
                    if t is not None and t in all_starts:
                        caller = func_for_addr(insn.address)
                        if caller is not None and caller != t:
                            cg.add_edge(caller, t)
                        continue

                    # Tail call: unconditional jump to known function start
                    t2 = _unconditional_jump_target(insn, arch)
                    if t2 is not None and t2 in all_starts:
                        caller = func_for_addr(insn.address)
                        if caller is not None and caller != t2:
                            cg.add_edge(caller, t2)

            except Exception:
                continue

        return cg, sorted_starts, all_starts

    # ── Thunk filtering ────────────────────────────────────────────────────────

    def _filter_thunks(
        self,
        cg: nx.DiGraph,
        sorted_starts: list[int],
        all_starts: set[int],
        cs: capstone.Cs,
        arch: archinfo.Arch,
    ) -> nx.DiGraph:
        """
        Remove PLT stubs and IAT thunks from the call graph.

        Strategy: if a function is short (≤ THUNK_MAX_INSN instructions) and
        ends in an indirect branch through memory (IAT pattern) or register
        (AArch64 stub pattern), treat it as a thunk and remove it.
        """
        thunks: set[int] = set()

        for i, addr in enumerate(sorted_starts):
            end   = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else addr + 64
            size  = min(end - addr, THUNK_MAX_INSN * 12)  # 12 bytes / insn upper bound
            if size < 4:
                thunks.add(addr)
                continue

            try:
                raw = bytes(self._loader.memory.load(addr, size))
            except Exception:
                continue

            if _is_thunk(raw, addr, arch, cs):
                thunks.add(addr)

        if thunks:
            log.info('C2S: removing %d thunks/stubs from call graph', len(thunks))
            cg = cg.copy()
            cg.remove_nodes_from(t for t in thunks if t in cg)

        return cg

    # ── Null distribution ──────────────────────────────────────────────────────

    def _null_distribution(
        self, G: nx.DiGraph
    ) -> tuple[list[float], list[float], list[float]]:
        """Directed configuration-model null sampling (identical to c2_rmt.py)."""
        in_seq  = [G.in_degree(n)  for n in G.nodes()]
        out_seq = [G.out_degree(n) for n in G.nodes()]

        radii:     list[float] = []
        energies:  list[float] = []
        entropies: list[float] = []

        for _ in range(self.n_null_samples):
            try:
                G_null = nx.directed_configuration_model(
                    in_seq, out_seq, create_using=nx.MultiDiGraph()
                )
                G_s = nx.DiGraph(G_null)
                G_s.remove_edges_from(nx.selfloop_edges(G_s))
                m = _spectral_metrics(G_s)
                radii.append(m.spectral_radius)
                energies.append(m.graph_energy)
                entropies.append(m.eig_entropy)
            except Exception:
                continue

        return radii, energies, entropies

    # ── Function scoring ───────────────────────────────────────────────────────

    def _score_functions(
        self,
        cg: nx.DiGraph,
        sorted_starts: list[int],
        all_starts: set[int],
        sym_names: dict[int, str],
    ) -> list[FunctionScore]:
        """
        Score all non-thunk functions.

        Top-N by call-graph degree get pyvex cyclomatic + back-edge analysis.
        Remaining functions get conservative defaults (cyclomatic=1, back=0).
        """
        arch   = self._obj.arch
        memory = self._loader.memory

        # Eigenvector centrality over the filtered call graph
        try:
            ev = nx.eigenvector_centrality_numpy(cg, weight=None)
        except Exception:
            try:
                total_in = sum(dict(cg.in_degree()).values()) or 1
                ev = {n: cg.in_degree(n) / total_in for n in cg.nodes()}
            except Exception:
                ev = {n: 0.0 for n in cg.nodes()}

        # Top-N by total degree → pyvex priority set
        degree_sorted = sorted(
            cg.nodes(),
            key=lambda n: cg.in_degree(n) + cg.out_degree(n),
            reverse=True,
        )
        pyvex_set = set(degree_sorted[:self.top_n_pyvex])

        scores: list[FunctionScore] = []
        starts_list = sorted(all_starts)

        for i, addr in enumerate(starts_list):
            # Skip thunks that were removed from the call graph
            if addr not in cg:
                continue

            ev_score   = float(ev.get(addr, 0.0))
            cyclomatic = 1
            back_edges = 0

            if addr in pyvex_set:
                # Function end boundary: next function start or +64 KB cap
                end = starts_list[i + 1] if i + 1 < len(starts_list) else addr + 65536
                end = min(end, addr + 65536)
                try:
                    cyclomatic, back_edges = _pyvex_func_metrics(
                        memory, arch, addr, end
                    )
                except Exception as exc:
                    log.debug('C2S: pyvex failed at %#x: %s', addr, exc)

            name = sym_names.get(addr, f'sub_{addr:#x}')

            scores.append(FunctionScore(
                addr          = addr,
                name          = name,
                ev_centrality = ev_score,
                cyclomatic    = cyclomatic,
                back_edges    = back_edges,
                scc_count     = 1,
                combined      = _function_combined_score(ev_score, cyclomatic, back_edges),
            ))

        return sorted(scores, key=lambda s: s.combined, reverse=True)

    # ── Entry point ────────────────────────────────────────────────────────────

    def run(self) -> C2Result:
        """
        Run sliced C2 analysis: load → Capstone → RMT → pyvex → rank.

        Returns
        -------
        C2Result  (same structure as C2RMTAnalysis.run())
        """
        self._load()

        obj  = self._obj
        arch = obj.arch

        try:
            cs = _capstone_for(arch)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

        # Phase 1–2: function discovery + executable sections
        func_starts = self._initial_func_starts()
        segments    = self._exec_segments()
        sym_names   = self._symbol_name_map()

        if not segments:
            raise RuntimeError('C2SlicedAnalysis: no executable segments found')

        # Phase 3: Capstone scan → call graph
        cg, sorted_starts, all_starts = self._capstone_scan(
            func_starts, segments, cs, arch
        )
        log.info('C2S: raw call graph: %d nodes, %d edges',
                 cg.number_of_nodes(), cg.number_of_edges())

        # Phase 4: filter thunks
        cg = self._filter_thunks(cg, sorted_starts, all_starts, cs, arch)
        log.info('C2S: filtered: %d nodes, %d edges',
                 cg.number_of_nodes(), cg.number_of_edges())

        # Phase 5: RMT spectral analysis
        obs      = _spectral_metrics(cg)
        reliable = cg.number_of_nodes() >= MIN_NODES_RMT

        if reliable:
            radii, energies, entropies = self._null_distribution(cg)

            if radii:
                null_mean = SpectralMetrics(
                    spectral_radius = float(np.mean(radii)),
                    graph_energy    = float(np.mean(energies)),
                    eig_entropy     = float(np.mean(entropies)),
                    n_nodes         = obs.n_nodes,
                    n_edges         = obs.n_edges,
                )
                null_std = SpectralMetrics(
                    spectral_radius = float(np.std(radii)),
                    graph_energy    = float(np.std(energies)),
                    eig_entropy     = float(np.std(entropies)),
                    n_nodes         = 0,
                    n_edges         = 0,
                )
            else:
                log.warning('C2S: null sampling failed; z-scores set to 0')
                null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)

            z_radius  = _z(obs.spectral_radius, null_mean.spectral_radius,
                           null_std.spectral_radius)
            z_energy  = _z(obs.graph_energy,    null_mean.graph_energy,
                           null_std.graph_energy)
            z_entropy = _z(obs.eig_entropy,     null_mean.eig_entropy,
                           null_std.eig_entropy)
            flagged   = (abs(z_radius)  > ANOMALY_Z_THRESHOLD or
                         abs(z_energy)  > ANOMALY_Z_THRESHOLD or
                         abs(z_entropy) > ANOMALY_Z_THRESHOLD)
        else:
            log.warning('C2S: graph too small for RMT (N=%d < %d)',
                        cg.number_of_nodes(), MIN_NODES_RMT)
            null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)
            z_radius = z_energy = z_entropy = 0.0
            flagged = False

        binary_score = BinaryRMTScore(
            observed  = obs,
            null_mean = null_mean,
            null_std  = null_std,
            z_radius  = z_radius,
            z_energy  = z_energy,
            z_entropy = z_entropy,
            flagged   = flagged,
            reliable  = reliable,
        )

        log.info('C2S: z_radius=%.2f  z_energy=%.2f  z_entropy=%.2f  flagged=%s',
                 z_radius, z_energy, z_entropy, flagged)

        # Phase 6–7: per-function ranking
        log.info('C2S: scoring functions (pyvex top-%d)', self.top_n_pyvex)
        functions_ranked = self._score_functions(
            cg, sorted_starts, all_starts, sym_names
        )

        return C2Result(
            binary_score     = binary_score,
            functions_ranked = functions_ranked,
            n_functions      = cg.number_of_nodes(),
            binary_path      = self.binary_path,
        )
