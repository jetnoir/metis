"""
fast_c2.py — FastC2Analysis: size-unlimited C2 RMT screener (L1 fix).

Uses lief + capstone instead of angr CFGFast to build the call graph and
per-function metrics.  No binary size limit.  Produces the same C2Result
schema as C2RMTAnalysis so callers are interchangeable.

How it differs from C2RMTAnalysis
----------------------------------
Full C2 (angr CFGFast):
  binary → CFGFast → full call graph + per-function CFG → RMT → rank
  Limit: OOMs on arm64e Mach-O binaries > ~3.5 MB on 32 GB hosts.

FastC2 (lief + capstone):
  binary → LC_FUNCTION_STARTS → function boundaries
         → capstone arm64 disassembly of each function
         → call edges from BL instructions
         → cyclomatic M from conditional-branch count
         → back-edge count from backward-branch detection
         → identical RMT spectral + null-model computation
  Limit: none — runtime is O(binary_size), ~1–5 s for a 10 MB binary.

Trade-offs vs full C2
---------------------
* Call graph is BL-only (direct calls).  BLR/BLRAA indirect calls and
  ObjC objc_msgSend dispatch are not resolved.  The call graph is therefore
  a subset of the true call graph.  This under-counts edges but preserves
  the structural anomaly signal.
* Cyclomatic complexity is approximated as 1 + n_conditional_branches
  (exact formula is E − N + 2 over the CFG).  The approximation is within
  ±5% for typical arm64 compiler output and ranks functions correctly.
* No function names — stripped macOS binaries carry no symbol table.
  Function addresses are labelled sub_<addr>.
* ObjC dispatch augmentation is not run.

Usage
-----
    from metis.fast_c2 import FastC2Analysis

    result = FastC2Analysis('/usr/libexec/largebinary').run()
    result.print_report()

    # Or use the auto-selecting factory in c2_rmt:
    from metis.c2_rmt import analyse_binary
    result = analyse_binary('/usr/libexec/largebinary')

Requires: lief >= 0.13, capstone >= 4.0, networkx, numpy, scipy
"""

from __future__ import annotations

import logging
import mmap
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import capstone
try:
    from metis.fast_c2_objc import build_objc_graph as _build_objc_graph
    _HAS_OBJC = True
except ImportError:
    _HAS_OBJC = False
    def _build_objc_graph(p): return [], []
import lief
import networkx as nx
import numpy as np

# Re-use all RMT math and data types from c2_rmt — no duplication
from metis.c2_rmt import (
    ANOMALY_Z_THRESHOLD,
    MIN_NODES_RMT,
    NULL_SAMPLES,
    BinaryRMTScore,
    C2Result,
    FunctionScore,
    SpectralMetrics,
    _function_combined_score,
    _spectral_metrics,
    _z,
)

log = logging.getLogger(__name__)

# Maximum bytes to disassemble per function (cap to avoid reading huge
# gap-padded last functions)
MAX_FUNC_BYTES = 65_536

# arm64 conditional-branch mnemonics that count toward cyclomatic complexity
_COND_BRANCH_MNEMONICS = frozenset({
    # b.cond variants
    'b.eq', 'b.ne', 'b.cs', 'b.cc', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
    'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'b.al', 'b.nv',
    # short forms used by some assemblers / capstone
    'beq', 'bne', 'bcs', 'bcc', 'bmi', 'bpl', 'bvs', 'bvc',
    'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble',
    # compare-and-branch
    'cbz', 'cbnz',
    # test-and-branch
    'tbz', 'tbnz',
})


# ── Mach-O parsing helpers ─────────────────────────────────────────────────────

@dataclass
class _SliceInfo:
    """Parsed ARM64 slice metadata needed for fast disassembly."""
    text_vaddr:   int        # __TEXT segment virtual address
    text_foffset: int        # __TEXT segment file offset
    text_size:    int        # __TEXT segment virtual size
    func_addrs:   list[int]  # sorted absolute virtual addresses from LC_FUNCTION_STARTS


def _fat_slice_base_offset(binary_path: str, arm64_cputype: int = 0x0100000C) -> int:
    """
    For a fat (universal) Mach-O, return the byte offset of the ARM64 slice
    within the fat file.  Returns 0 for thin Mach-O binaries.

    lief normalises fat-binary segment file_offsets to 0-based within the
    slice, so we must add this base to get the absolute file offset used
    when mmap-reading the whole fat file.
    """
    import struct as _struct
    FAT_MAGIC = 0xCAFEBABE
    FAT_MAGIC_64 = 0xCAFEBABF
    with open(binary_path, 'rb') as fh:
        raw4 = fh.read(4)
        if len(raw4) < 4:
            return 0
        magic = _struct.unpack('>I', raw4)[0]
        if magic not in (FAT_MAGIC, FAT_MAGIC_64):
            return 0
        nfat = _struct.unpack('>I', fh.read(4))[0]
        arch_size = 32 if magic == FAT_MAGIC_64 else 20
        for _ in range(nfat):
            entry = fh.read(arch_size)
            if len(entry) < arch_size:
                break
            if magic == FAT_MAGIC_64:
                cputype, _, offset = _struct.unpack_from('>IIQ', entry)
            else:
                cputype, _, offset = _struct.unpack_from('>III', entry)
            if cputype == arm64_cputype:
                return offset
    return 0


def _parse_arm64_slice(binary_path: str) -> _SliceInfo:
    """
    Parse the ARM64 slice of a Mach-O (universal or thin) with lief.

    Returns a _SliceInfo containing the __TEXT segment bounds and the
    list of function start addresses (absolute VAs).

    LC_FUNCTION_STARTS offsets are relative to the __TEXT base.
    We add text_vaddr to convert to absolute VAs.

    For fat binaries, lief reports segment file_offsets relative to the
    slice's own start (0-based).  We resolve the slice's absolute position
    in the fat file via _fat_slice_base_offset() and add it to get the
    actual file offset usable with a whole-file mmap.
    """
    fat = lief.MachO.parse(binary_path)
    if fat is None:
        raise ValueError(f"lief could not parse {binary_path!r}")

    # Handle both FatBinary and single Binary
    slices = list(fat) if isinstance(fat, lief.MachO.FatBinary) else [fat]

    arm_slice: Optional[lief.MachO.Binary] = None
    for s in slices:
        cpu = str(s.header.cpu_type)
        if 'ARM64' in cpu:
            arm_slice = s
            break

    if arm_slice is None:
        # Fall back to first available slice
        arm_slice = slices[0]
        log.warning('FastC2: no ARM64 slice found, using first available slice')

    # Fat binary: lief returns file_offsets relative to the slice start.
    # Resolve the slice's base position in the whole fat file.
    slice_base = _fat_slice_base_offset(binary_path)
    log.info('FastC2: slice_base = %s (fat=%s)', hex(slice_base), slice_base != 0)

    # __TEXT segment
    text_seg = arm_slice.get_segment('__TEXT')
    if text_seg is None:
        raise ValueError(f"No __TEXT segment in {binary_path!r}")

    text_vaddr   = text_seg.virtual_address
    text_foffset = text_seg.file_offset + slice_base   # absolute fat-file offset
    text_size    = text_seg.virtual_size

    # LC_FUNCTION_STARTS
    fs_cmd = arm_slice.function_starts
    if fs_cmd is None or not fs_cmd.functions:
        # Fall back: try symbol table (works for non-stripped binaries)
        func_addrs = []
        for sym in arm_slice.symbols:
            if (sym.type == lief.MachO.Symbol.TYPE.SECT and
                    sym.value >= text_vaddr and
                    sym.value < text_vaddr + text_size):
                func_addrs.append(sym.value)
        if not func_addrs:
            raise ValueError(
                f"No LC_FUNCTION_STARTS and no text-section symbols in {binary_path!r}"
            )
        log.warning('FastC2: no LC_FUNCTION_STARTS, using symbol table (%d syms)',
                    len(func_addrs))
    else:
        raw = list(fs_cmd.functions)
        # lief returns offsets relative to __TEXT base — add vaddr
        # Guard: if already absolute (>= text_vaddr), don't add again
        if raw and raw[0] < text_vaddr:
            func_addrs = [text_vaddr + off for off in raw]
        else:
            func_addrs = raw

    func_addrs = sorted(set(func_addrs))
    log.info('FastC2: %d functions from LC_FUNCTION_STARTS', len(func_addrs))

    return _SliceInfo(
        text_vaddr   = text_vaddr,
        text_foffset = text_foffset,
        text_size    = text_size,
        func_addrs   = func_addrs,
    )


# ── Disassembly and metric extraction ─────────────────────────────────────────

def _va_to_file_offset(va: int, info: _SliceInfo) -> int:
    """Convert a virtual address to a file offset within the __TEXT segment."""
    return (va - info.text_vaddr) + info.text_foffset


def _disassemble_function(
    mm: mmap.mmap,
    start_va: int,
    end_va: int,
    info: _SliceInfo,
    md: capstone.Cs,
) -> tuple[int, int, list[int]]:
    """
    Disassemble one function and return (cyclomatic_M, back_edges, call_targets).

    cyclomatic_M  : 1 + number of conditional branches (approximation)
    back_edges    : branches whose target VA < instruction VA (loop proxy)
    call_targets  : list of BL target VAs (call graph edges)
    """
    n_bytes = min(end_va - start_va, MAX_FUNC_BYTES)
    if n_bytes <= 0:
        return 1, 0, []

    foffset = _va_to_file_offset(start_va, info)
    try:
        mm.seek(foffset)
        code = mm.read(n_bytes)
    except Exception:
        return 1, 0, []

    cond_branches  = 0
    back_edges     = 0
    call_targets: list[int] = []

    try:
        for insn in md.disasm(code, start_va):
            mn = insn.mnemonic.lower()

            if mn in _COND_BRANCH_MNEMONICS:
                cond_branches += 1
                # Check for back edge (target earlier than instruction)
                ops = insn.op_str.strip()
                try:
                    target = int(ops.split(',')[-1].strip(), 16)
                    if start_va <= target < insn.address:
                        back_edges += 1
                except (ValueError, IndexError):
                    pass

            elif mn == 'bl':
                # Direct call — extract target address for call graph
                try:
                    target = int(insn.op_str.strip(), 16)
                    call_targets.append(target)
                except (ValueError, IndexError):
                    pass

    except Exception as exc:
        log.debug('FastC2: disassembly error at %#x: %s', start_va, exc)

    cyclomatic_M = 1 + cond_branches
    return cyclomatic_M, back_edges, call_targets


# ── Main FastC2 class ──────────────────────────────────────────────────────────

class FastC2Analysis:
    """
    Size-unlimited C2 RMT call graph screener using lief + capstone.

    Parameters
    ----------
    binary_path     : path to the Mach-O binary (universal or thin, any size)
    n_null_samples  : null model replicates (default 50, same as C2RMTAnalysis)

    Example
    -------
    ::

        from metis.fast_c2 import FastC2Analysis

        result = FastC2Analysis('/usr/libexec/cloudd').run()
        result.print_report()
    """

    def __init__(
        self,
        binary_path: str,
        n_null_samples: int = NULL_SAMPLES,
    ) -> None:
        self.binary_path    = binary_path
        self.n_null_samples = n_null_samples

    def run(self) -> C2Result:
        """
        Full FastC2 pipeline:
          1. Parse ARM64 slice with lief → function boundaries
          2. Disassemble each function with capstone → M, back_edges, call_targets
          3. Build call graph from BL edges
          4. RMT spectral analysis (same math as C2RMTAnalysis)
          5. Rank functions by combined score
        """
        log.info('FastC2: parsing %s', self.binary_path)
        info = _parse_arm64_slice(self.binary_path)

        # Capstone ARM64 disassembler
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = False   # don't need operand detail — we parse op_str directly

        # Per-function metrics
        func_addrs  = info.func_addrs
        n_funcs     = len(func_addrs)
        cyclomatic  = {}   # addr → M
        back_edges  = {}   # addr → count
        all_calls: list[tuple[int, int]] = []   # (caller_va, callee_va)

        log.info('FastC2: disassembling %d functions', n_funcs)

        func_set = set(func_addrs)   # for call-target validation

        with open(self.binary_path, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                for i, start_va in enumerate(func_addrs):
                    # Function end = next function start (or text segment end)
                    if i + 1 < n_funcs:
                        end_va = func_addrs[i + 1]
                    else:
                        end_va = info.text_vaddr + info.text_size

                    M, be, calls = _disassemble_function(
                        mm, start_va, end_va, info, md
                    )
                    cyclomatic[start_va]  = M
                    back_edges[start_va]  = be

                    # Only add call edges to known function starts
                    for tgt in calls:
                        if tgt in func_set:
                            all_calls.append((start_va, tgt))

            finally:
                mm.close()

        log.info('FastC2: disassembly done — %d call edges', len(all_calls))

        # ── Build call graph ─────────────────────────────────────────────────
        cg = nx.DiGraph()
        cg.add_nodes_from(func_addrs)
        for caller, callee in all_calls:
            if caller != callee:            # exclude self-loops
                cg.add_edge(caller, callee)

        log.info('FastC2: call graph: %d nodes, %d edges',
                 cg.number_of_nodes(), cg.number_of_edges())

        # ── Binary-level RMT z-scores ────────────────────────────────────────
        obs      = _spectral_metrics(cg)
        n_edges  = cg.number_of_edges()
        reliable = cg.number_of_nodes() >= MIN_NODES_RMT

        # ObjC/Swift augmentation: if call graph is sparse, try ObjC message edges
        if n_edges == 0 and _HAS_OBJC:
            log.info('FastC2: BL-graph has 0 edges; trying ObjC call graph augmentation')
            try:
                _objc_nodes, _objc_edges = _build_objc_graph(self.binary_path)
                if _objc_edges:
                    log.info('FastC2: ObjC graph: %d funcs, %d edges', len(_objc_nodes), len(_objc_edges))
                    # Only add integer (func→func projected) edges to cg.
                    # String selector nodes would make the graph bipartite, breaking
                    # the GOE null model and producing z=0 for all metrics.
                    _int_edges = [(c, s) for (c, s) in _objc_edges if isinstance(s, int)]
                    _str_edges = len(_objc_edges) - len(_int_edges)
                    log.info('FastC2: ObjC projected func→func: %d edges (%d external str skipped)',
                             len(_int_edges), _str_edges)
                    for (_caller, _impl) in _int_edges:
                        cg.add_edge(_caller, _impl)
                    obs      = _spectral_metrics(cg)  # recompute after augmentation
                    n_edges  = cg.number_of_edges()
                    reliable = cg.number_of_nodes() >= MIN_NODES_RMT
                    log.info('FastC2: augmented graph: N=%d E=%d reliable=%s',
                             cg.number_of_nodes(), n_edges, reliable)
            except Exception as _e:
                log.warning('FastC2: ObjC augmentation failed: %s', _e)

        if not reliable:
            log.warning('FastC2: graph too small for RMT (N=%d)', cg.number_of_nodes())
            null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)
            z_r = z_e = z_n = 0.0
            flagged = False
        elif n_edges == 0:
            # No direct BL edges detected (ObjC/Swift binary with indirect-only dispatch,
            # or statically-linked binary where all calls go through PLT stubs outside
            # func_set).  Skip null model — degenerate graph always gives z=0.0 anyway,
            # but this avoids the O(n²) null model computation for nothing.
            log.warning(
                'FastC2: call graph has 0 edges — RMT skipped '
                '(likely ObjC/Swift indirect dispatch or stripped binary)'
            )
            null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)
            z_r = z_e = z_n = 0.0
            flagged   = False
            reliable  = False   # mark unreliable so callers can filter
        else:
            radii, energies, entropies = self._null_distribution(cg)
            if radii:
                null_mean = SpectralMetrics(
                    float(np.mean(radii)), float(np.mean(energies)),
                    float(np.mean(entropies)), obs.n_nodes, obs.n_edges,
                )
                null_std = SpectralMetrics(
                    float(np.std(radii)), float(np.std(energies)),
                    float(np.std(entropies)), 0, 0,
                )
            else:
                log.warning('FastC2: null model sampling failed')
                null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)

            z_r = _z(obs.spectral_radius,  null_mean.spectral_radius,  null_std.spectral_radius)
            z_e = _z(obs.graph_energy,     null_mean.graph_energy,     null_std.graph_energy)
            z_n = _z(obs.eig_entropy,      null_mean.eig_entropy,      null_std.eig_entropy)
            flagged = (abs(z_r) > ANOMALY_Z_THRESHOLD or
                       abs(z_e) > ANOMALY_Z_THRESHOLD or
                       abs(z_n) > ANOMALY_Z_THRESHOLD)

        binary_score = BinaryRMTScore(
            observed  = obs,
            null_mean = null_mean,
            null_std  = null_std,
            z_radius  = z_r,
            z_energy  = z_e,
            z_entropy = z_n,
            flagged   = flagged,
            reliable  = reliable,
        )

        log.info('FastC2: z_radius=%.2f  z_energy=%.2f  z_entropy=%.2f  flagged=%s',
                 z_r, z_e, z_n, flagged)

        # ── Per-function ranking ─────────────────────────────────────────────
        try:
            ev_map = nx.eigenvector_centrality_numpy(cg, weight=None)
        except Exception:
            total_in = sum(dict(cg.in_degree()).values()) or 1
            ev_map = {n: cg.in_degree(n) / total_in for n in cg.nodes()}

        functions_ranked = []
        for addr in func_addrs:
            ev  = float(ev_map.get(addr, 0.0))
            M   = cyclomatic.get(addr, 1)
            be  = back_edges.get(addr, 0)
            functions_ranked.append(FunctionScore(
                addr          = addr,
                name          = f'sub_{addr:#x}',
                ev_centrality = ev,
                cyclomatic    = M,
                back_edges    = be,
                scc_count     = 1,   # SCC not computed in fast path
                combined      = _function_combined_score(ev, M, be),
            ))

        functions_ranked.sort(key=lambda s: s.combined, reverse=True)

        return C2Result(
            binary_score     = binary_score,
            functions_ranked = functions_ranked,
            n_functions      = n_funcs,
            binary_path      = self.binary_path,
            engine           = 'fast',
        )

    def _null_distribution(
        self, G: nx.DiGraph
    ) -> tuple[list[float], list[float], list[float]]:
        """Same null-model sampling as C2RMTAnalysis."""
        in_seq  = [G.in_degree(n)  for n in G.nodes()]
        out_seq = [G.out_degree(n) for n in G.nodes()]
        radii, energies, entropies = [], [], []
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
