"""
c3_templates.py — C3: Full-SSA call dataflow template matching for macOS binaries.

Detects forbidden def-use topologies at the call graph level using VEX IR
analysis with full memory tracking (store/load through general registers).

Design
------
v1 tracked taint only through registers and frame-relative stack slots (sp+N,
fp+N). v2 adds:

  1. General register-relative memory tracking  (fixes L2 — struct field flows)
     _canonical_addr now returns 'r{vex_offset}+{delta}' for ANY register, not
     just SP/FP. When a register is overwritten (Put), all its memory entries
     are invalidated. This handles:
         t3 = Get(x0)                   # x0 = struct ptr
         t5 = Add(t3, 0x8)             # t5 = &struct->field
         t7 = LDle(t5)                  # t7 = struct->field
         CALL malloc(t7)                # struct field reaches allocator ← CATCH

  2. Pointer-taint tracking  (output-buffer sources like mach_msg, IOKit)
     _ptr_taint maps register offset → frozenset[source labels]. This says
     "this register holds a pointer to memory that contains tainted data."
     Set when:
       a) A tainted value is stored through a general register (store_mem)
       b) A Source call fills an output buffer (output_args template field):
            mach_msg(&msg, ...)  → msg buffer is attacker-controlled
            IOConnectCallMethod(..., &output, &size) → output is tainted
     Propagated when:
            Load(addr_expr)  → if the base register of addr is ptr_tainted,
                               the loaded value inherits those labels

  3. Put-side invalidation
     On every Put(reg_offset, new_value):
       - Clear all _mem_state entries keyed 'r{reg_offset}+*'
       - Clear _ptr_taint[reg_offset]
     Prevents stale tracking after a pointer register is reused.

Preserved from v1
-----------------
- Frame-relative stack slot tracking (sp+N, fp+N) — unchanged
- Call-level dataflow graph (DiGraph edge A→B = return of A taints arg of B)
- Template bank with source/sink/barrier matching
- All public interfaces (C3TemplateAnalysis, C3Result, TemplateMatch)

Five macOS-specific templates
------------------------------
MACH_OOB   — mach_msg receive buffer field → malloc/calloc size (no bound)
XPC_TYPE   — xpc_dictionary_get_value → typed XPC accessor without xpc_get_type
XPC_SIZE_ALLOC — XPC length/count → allocator (no bounds check)
PORT_UAF   — mach_port_deallocate → any mach port operation on same name
IOKIT_OOB  — IOConnectCallMethod out-of-band data → memory copy/alloc

Limitations (v2)
----------------
1. Intra-function only — does not track taint across function boundaries.
   Interprocedural flows remain covered by C6 symbolic execution.
2. Alias conservatism — two different registers pointing to the same struct
   are not unified. A store through x0 is not visible via x1 even if both
   hold the same address. This may produce false negatives for aliased accesses.
3. Multi-path union — at CFG merge points, taint is the union of all incoming
   paths (may-taint, not must-taint). Can produce false positives suppressed by
   reduced confidence score.

Integration with C2 and C6
---------------------------
C3 runs as a static pre-filter before C6. Pass C2's top-ranked function
addresses to C3.analyse_functions(), then pass C3's high-confidence hits
to C6 for confirmation via symbolic execution.

Usage
-----
    from metis.c3_templates import C3TemplateAnalysis

    proj    = angr.Project(binary, auto_load_libs=False)
    c3      = C3TemplateAnalysis(proj)
    results = c3.run()
    for r in results:
        print(r)

    # Targeted on C2 top functions:
    results = c3.analyse_functions(top_addrs)

Requires: angr >= 9.2, networkx, pyvex (bundled with angr)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

import networkx as nx
import pyvex

import angr

log = logging.getLogger(__name__)


# ── Vulnerability taxonomy (shared with C6) ────────────────────────────────────

class TemplateVulnClass(Enum):
    OOB   = auto()
    UAF   = auto()
    XTYPE = auto()


# ── Template definitions ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class VulnTemplate:
    """
    A forbidden call-level def-use pattern.

    source_substrings  : if a resolved call name contains any of these, it is
                         a potential taint source
    sink_substrings    : if a resolved call name contains any of these, it is
                         a potential sink (vulnerability site)
    barrier_substrings : if a call with any of these names appears on a path
                         from source to sink, the finding is suppressed
    sink_arg           : which argument index (0-based) of the sink must be
                         tainted, or -1 to accept any argument
    vuln_class         : OOB, UAF, or XTYPE
    description        : template description for reports
    confidence         : base confidence before path-count adjustment
    output_args        : argument indices (0-based) of the source call that
                         receive tainted OUTPUT data (output buffers filled by
                         the callee).  After the source call, the memory
                         pointed to by these arg registers is marked tainted.
                         E.g. (0,) for mach_msg (&msg is arg0, filled by kernel).
    """
    name               : str
    source_substrings  : tuple[str, ...]
    sink_substrings    : tuple[str, ...]
    barrier_substrings : tuple[str, ...]
    sink_arg           : int
    vuln_class         : TemplateVulnClass
    description        : str
    confidence         : float = 0.75
    output_args        : tuple[int, ...] = ()


# macOS-specific template bank
TEMPLATE_BANK: list[VulnTemplate] = [

    VulnTemplate(
        name               = 'MACH_OOB',
        source_substrings  = ('mach_msg', 'mach_msg_trap'),
        sink_substrings    = ('malloc', 'calloc', 'realloc', 'valloc', 'alloc'),
        barrier_substrings = (),                 # bounds checks are branches, not calls
        sink_arg           = 0,                  # size is arg0 for malloc
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'mach_msg receive → allocator: message field reaches malloc size '
            'argument. Potential OOB if size is not validated before the call.'
        ),
        confidence         = 0.70,
        output_args        = (0,),               # arg0 = &msg buffer (filled by kernel)
    ),

    VulnTemplate(
        name               = 'XPC_TYPE',
        source_substrings  = ('xpc_dictionary_get_value', 'xpc_array_get_value'),
        sink_substrings    = (
            'xpc_int64_get_value', 'xpc_uint64_get_value',
            'xpc_double_get_value', 'xpc_bool_get_value',
            'xpc_string_get_string_ptr', 'xpc_data_get_bytes_ptr',
            'xpc_data_get_length', 'xpc_array_get_count',
        ),
        barrier_substrings = ('xpc_get_type',),  # type guard
        sink_arg           = 0,                  # xpc_object is arg0 for typed accessors
        vuln_class         = TemplateVulnClass.XTYPE,
        description        = (
            'XPC type confusion: xpc_dictionary_get_value result reaches a '
            'type-specific accessor without xpc_get_type() on this path.'
        ),
        confidence         = 0.80,
    ),

    VulnTemplate(
        name               = 'XPC_SIZE_ALLOC',
        source_substrings  = ('xpc_data_get_length', 'xpc_array_get_count',
                              'xpc_dictionary_get_count', 'xpc_uint64_get_value'),
        sink_substrings    = ('malloc', 'calloc', 'realloc', 'alloc'),
        barrier_substrings = (),
        sink_arg           = 0,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'XPC-derived length/count reaches allocator size without bounds check. '
            'Potential OOB if the XPC value is attacker-controlled.'
        ),
        confidence         = 0.72,
    ),

    VulnTemplate(
        name               = 'PORT_UAF',
        source_substrings  = ('mach_port_deallocate', 'mach_port_destroy'),
        sink_substrings    = (
            'mach_port_', 'mach_msg',
            'IOServiceOpen', 'IOConnectCall',
        ),
        barrier_substrings = (),
        sink_arg           = -1,                 # port can appear in any arg
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Mach port right used after mach_port_deallocate on this path. '
            'Potential port-right use-after-free.'
        ),
        confidence         = 0.65,
    ),

    VulnTemplate(
        name               = 'IOKIT_OOB',
        source_substrings  = ('IOConnectCallMethod', 'IOConnectCallStructMethod',
                              'IOConnectCallScalarMethod'),
        sink_substrings    = ('memcpy', 'memmove', 'malloc', 'calloc',
                              'bcopy', 'IOMemoryDescriptor'),
        barrier_substrings = (),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'IOConnectCallMethod out-parameter reaches memory copy or allocator. '
            'Potential OOB if output size is not validated.'
        ),
        confidence         = 0.68,
        # IOConnectCallMethod(conn, sel, input, inputCnt, inputStruct, inputStructCnt,
        #                     output*, outputCnt*, outputStruct*, outputStructCnt*)
        # output buffer ptr is arg6, outputCnt ptr is arg7 (both caller-supplied)
        output_args        = (6, 7),
    ),
]


# ── Call record and dataflow graph ─────────────────────────────────────────────

@dataclass
class CallRecord:
    """One resolved function call at a specific call site."""
    call_site   : int          # address of the call instruction
    callee_addr : int          # resolved callee address (may be PLT stub)
    callee_name : str          # resolved name or 'sub_<addr>'
    tainted_args: set[int]     # argument indices that carry taint at call time
    # Index into the function's call sequence (for ordering)
    seq_idx     : int = 0


# ── VEX register taint tracker ────────────────────────────────────────────────

class _RegTaint:
    """
    Tracks which VEX register offsets carry taint from a named call.

    State:  {vex_offset: frozenset_of_call_labels}
    Labels: strings of the form '<callee_name>@<call_site_hex>'

    Also tracks frame-pointer-relative stack slots to survive the ARM64
    compiler pattern:
        GET(x0) → t5 ; STle(sp+0x10) = t5 ; t2 = LDle(sp+0x10) ; Put(x0) = t2
    without which every stack spill breaks the taint chain.
    """

    # VEX offsets for stack-pointer and frame-pointer registers
    _SP_OFFSETS: frozenset[int] = frozenset({
        264,   # ARM64 SP  (x28 slot in VEX layout for AArch64)
        248,   # ARM64 x29 (frame pointer)
        48,    # AMD64 RSP
        56,    # AMD64 RBP
    })

    def __init__(self):
        self._state:     dict[int, frozenset[str]] = {}
        self._mem_state: dict[str, frozenset[str]] = {}   # canonical key → labels
        self._ptr_taint: dict[int, frozenset[str]] = {}   # reg_offset → labels ("this reg points to tainted mem")

    # ── register interface ────────────────────────────────────────────────────

    def put(self, offset: int, labels: frozenset[str]) -> None:
        if labels:
            self._state[offset] = labels
        else:
            self._state.pop(offset, None)

    def get(self, offset: int) -> frozenset[str]:
        return self._state.get(offset, frozenset())

    # ── memory interface (stack slots) ────────────────────────────────────────

    def _canonical_addr(
        self,
        expr,
        tmp_taint: dict[int, frozenset[str]],
        tmp_addr:  dict[int, 'str | None'],
    ) -> 'str | None':
        """
        If *expr* resolves to a frame-relative stack address, return a
        canonical string key ('sp+0xN' or 'fp+0xN').  Otherwise None.

        Resolves recursively so multi-level temporaries work:
          t0 = GET(sp)          →  'sp+0x0'
          t3 = Add64(t0, 0x10)  →  'sp+0x10'   (via tmp_addr[0])
          t5 = LDle(t3)         →  looks up 'sp+0x10' in _mem_state

        Handles signed 64-bit offsets (negative VEX constants for sub-word
        stack arithmetic on ARM64/AMD64).
        """
        t = type(expr).__name__
        if t == 'RdTmp':
            return tmp_addr.get(expr.tmp)
        if t == 'Get':
            if expr.offset in self._SP_OFFSETS:
                base = 'fp' if expr.offset in (248, 56) else 'sp'
                return f'{base}+0x0'
            # General register: key 'r{vex_offset}+0x0' — valid within one register epoch
            # (invalidated by Put-side clearing when the register is overwritten).
            return f'r{expr.offset}+0x0'
        if t == 'Binop':
            op = getattr(expr, 'op', '')
            if 'Add' not in op:
                return None
            args = expr.args if hasattr(expr, 'args') else []
            if len(args) != 2:
                return None
            # Try both orderings: one arm should be a frame-relative base,
            # the other a compile-time constant offset.
            for base_expr, off_expr in ((args[0], args[1]), (args[1], args[0])):
                off_t = type(off_expr).__name__
                if off_t != 'Const':
                    continue
                base_canonical = self._canonical_addr(base_expr, tmp_taint, tmp_addr)
                if base_canonical is None:
                    continue
                try:
                    base_reg, base_hex = base_canonical.split('+', 1)
                    base_offset = int(base_hex, 16)
                    raw = off_expr.con.value
                    # Interpret as signed 64-bit (VEX constants are unsigned)
                    if raw >= (1 << 63):
                        raw -= (1 << 64)
                    total = (base_offset + raw) & 0xFFFF_FFFF_FFFF_FFFF
                    return f'{base_reg}+{total:#x}'
                except Exception:
                    continue
        return None

    def store_mem(
        self,
        addr_expr,
        labels:    frozenset[str],
        tmp_taint: dict[int, frozenset[str]],
        tmp_addr:  dict[int, 'str | None'],
    ) -> None:
        key = self._canonical_addr(addr_expr, tmp_taint, tmp_addr)
        if key is None:
            return
        if labels:
            self._mem_state[key] = labels
            # If storing tainted data through a general register, mark that
            # register as ptr_tainted.  This means subsequent loads through the
            # same register at ANY field offset will propagate the taint —
            # conservative struct-field modelling (may-taint).
            if key.startswith('r'):
                try:
                    reg_offset = int(key[1:].split('+')[0])
                    existing = self._ptr_taint.get(reg_offset, frozenset())
                    self._ptr_taint[reg_offset] = existing | labels
                except (ValueError, IndexError):
                    pass
        else:
            self._mem_state.pop(key, None)

    def load_mem(
        self,
        addr_expr,
        tmp_taint: dict[int, frozenset[str]],
        tmp_addr:  dict[int, 'str | None'],
    ) -> frozenset[str]:
        key = self._canonical_addr(addr_expr, tmp_taint, tmp_addr)
        if key is None:
            return frozenset()
        # Direct taint from this exact memory slot, OR ptr_taint propagation
        # (register known to point to tainted memory → all field loads are tainted).
        return self._mem_state.get(key, frozenset()) | self._ptr_labels_for_canonical(key)

    # ── invalidation and pointer-taint helpers ────────────────────────────────

    def _invalidate_reg_mem(self, reg_offset: int) -> None:
        """
        Call on every Put(reg_offset, new_value).

        Clears all _mem_state entries keyed 'r{reg_offset}+*' and removes
        _ptr_taint[reg_offset].  This prevents stale tracking after a pointer
        register is reused for a different value.

        SP/FP are never invalidated — they are stable frame anchors throughout
        a function's lifetime.
        """
        if reg_offset in self._SP_OFFSETS:
            return
        prefix = f'r{reg_offset}+'
        stale = [k for k in self._mem_state if k.startswith(prefix)]
        for k in stale:
            del self._mem_state[k]
        self._ptr_taint.pop(reg_offset, None)

    def _ptr_labels_for_canonical(self, key: str) -> frozenset[str]:
        """
        If *key* is 'r{vex_offset}+{delta}', return the ptr_taint labels for
        that base register.  Propagates to every field load through a register
        that is known to point into tainted memory (conservative may-taint).
        """
        if not key or not key.startswith('r'):
            return frozenset()
        try:
            reg_offset = int(key[1:].split('+')[0])
            return self._ptr_taint.get(reg_offset, frozenset())
        except (ValueError, IndexError):
            return frozenset()

    def set_ptr_taint(self, offset: int, labels: frozenset[str]) -> None:
        """Mark register *offset* as pointing to memory that contains tainted data."""
        if labels:
            self._ptr_taint[offset] = labels
        else:
            self._ptr_taint.pop(offset, None)

    def get_ptr_taint(self, offset: int) -> frozenset[str]:
        """Return ptr_taint labels for register *offset*."""
        return self._ptr_taint.get(offset, frozenset())

    # ── expression taint propagation ──────────────────────────────────────────

    def taint_of_expr(self, expr) -> frozenset[str]:
        """Public entry — for callers that have no tmp context."""
        return self._taint_expr(expr, {}, {})

    def _taint_expr(
        self,
        expr,
        tmp_taint: dict[int, frozenset[str]],
        tmp_addr:  dict[int, 'str | None'],
    ) -> frozenset[str]:
        t = type(expr).__name__
        if t == 'RdTmp':
            return tmp_taint.get(expr.tmp, frozenset())
        if t == 'Get':
            return self.get(expr.offset)
        if t in ('Unop', 'Binop', 'Triop', 'Qop'):
            result: frozenset[str] = frozenset()
            for arg in (expr.args if hasattr(expr, 'args') else []):
                result = result | self._taint_expr(arg, tmp_taint, tmp_addr)
            return result
        if t == 'ITE':
            return (self._taint_expr(expr.iftrue,  tmp_taint, tmp_addr) |
                    self._taint_expr(expr.iffalse, tmp_taint, tmp_addr))
        if t == 'Load':
            # Resolve load through stack slot if address is frame-relative
            return self.load_mem(expr.addr, tmp_taint, tmp_addr)
        # Const, CCall — no taint propagated
        return frozenset()

    # ── copy / merge ──────────────────────────────────────────────────────────

    def copy(self) -> '_RegTaint':
        c = _RegTaint()
        c._state     = dict(self._state)
        c._mem_state = dict(self._mem_state)
        c._ptr_taint = dict(self._ptr_taint)
        return c

    def merge(self, other: '_RegTaint') -> None:
        """Join two taint states at a CFG merge point (union of labels)."""
        all_offsets = set(self._state) | set(other._state)
        for off in all_offsets:
            merged = self.get(off) | other.get(off)
            if merged:
                self._state[off] = merged
            else:
                self._state.pop(off, None)
        all_keys = set(self._mem_state) | set(other._mem_state)
        for key in all_keys:
            merged = self._mem_state.get(key, frozenset()) | other._mem_state.get(key, frozenset())
            if merged:
                self._mem_state[key] = merged
            else:
                self._mem_state.pop(key, None)
        all_regs = set(self._ptr_taint) | set(other._ptr_taint)
        for reg in all_regs:
            merged = self._ptr_taint.get(reg, frozenset()) | other._ptr_taint.get(reg, frozenset())
            if merged:
                self._ptr_taint[reg] = merged
            else:
                self._ptr_taint.pop(reg, None)


# ── Intra-function call dataflow extraction ────────────────────────────────────

def _resolve_callee(proj: angr.Project, callee_addr: int) -> str:
    """Return a human-readable name for a callee address."""
    try:
        sym = proj.loader.find_symbol(callee_addr)
        if sym and sym.name:
            return sym.name.lstrip('_')
    except Exception:
        pass
    try:
        func = proj.kb.functions.get(callee_addr)
        if func and func.name:
            return func.name.lstrip('_')
    except Exception:
        pass
    return f'sub_{callee_addr:#x}'


def _arg_offsets(proj: angr.Project) -> list[int]:
    """Return VEX register offsets for argument registers (arch-specific)."""
    arch = proj.arch.name
    if arch == 'AARCH64':
        # x0..x7 at offsets 16, 24, 32, 40, 48, 56, 64, 72
        return [16 + 8 * i for i in range(8)]
    else:
        # AMD64 System V: rdi=72, rsi=64, rdx=32, rcx=24, r8=72?, r9=...
        # angr AMD64: rdi=72, rsi=64, rdx=32, rcx=24, r8=40, r9=48
        try:
            return list(sorted(proj.arch.argument_registers))[:8]
        except Exception:
            return [72, 64, 32, 24, 40, 48]


def extract_call_dataflow(
    proj: angr.Project,
    func: angr.knowledge_plugins.Function,
    interesting_names: set[str],
    output_arg_map: 'dict[str, tuple[int, ...]] | None' = None,
) -> tuple[list[CallRecord], nx.DiGraph]:
    """
    Extract the call-level def-use graph for *func*.

    Parameters
    ----------
    proj             : angr.Project (pre-loaded)
    func             : function to analyse
    interesting_names: set of name substrings for calls to track
    output_arg_map   : mapping from source name substring → tuple of argument
                       indices that the callee fills with attacker-controlled
                       output data (e.g. {'mach_msg': (0,)} for the msg buffer).
                       After each matching source call the pointed-to memory slot
                       and the arg register's ptr_taint are marked tainted.

    Returns
    -------
    calls   : list of CallRecord for calls to interesting functions
    graph   : DiGraph where an edge (A, B) means "return of A tainted arg of B"
    """
    ret_offset  = proj.arch.ret_offset
    arg_offsets = _arg_offsets(proj)

    # Walk basic blocks in topological order of the function's CFG
    try:
        ordered_blocks = list(nx.topological_sort(func.graph))
    except nx.NetworkXUnfeasible:
        # Has cycles (loops) — fall back to addr order
        ordered_blocks = sorted(func.graph.nodes(), key=lambda b: b.addr)

    reg_taint  = _RegTaint()
    calls: list[CallRecord] = []
    cg = nx.DiGraph()

    # reg_canonical[vex_offset] = canonical addr of the VALUE placed into that
    # register by the most recent Put.  Used by output_arg_map to find the
    # memory buffer that an arg register points to.
    reg_canonical: dict[int, 'str | None'] = {}

    for block in ordered_blocks:
        try:
            irsb = proj.factory.block(block.addr).vex
        except Exception:
            continue

        tmp_taint: dict[int, frozenset[str]] = {}
        tmp_addr:  dict[int, 'str | None']  = {}   # tmp → canonical stack addr
        is_call_block = (irsb.jumpkind == 'Ijk_Call')

        for stmt in irsb.statements:
            stype = type(stmt).__name__

            if stype == 'WrTmp':
                # Propagate taint through temporaries (intra-block only)
                labels = reg_taint._taint_expr(stmt.data, tmp_taint, tmp_addr)
                if labels:
                    tmp_taint[stmt.tmp] = labels
                # Also record if this tmp holds a frame-relative address
                canonical = reg_taint._canonical_addr(stmt.data, tmp_taint, tmp_addr)
                tmp_addr[stmt.tmp] = canonical

            elif stype == 'Put':
                # Invalidate stale memory tracking for this register epoch before
                # assigning the new value (prevents false positives after pointer reuse).
                reg_taint._invalidate_reg_mem(stmt.offset)
                # Register write — propagate taint to register state
                labels = reg_taint._taint_expr(stmt.data, tmp_taint, tmp_addr)
                reg_taint.put(stmt.offset, labels)
                # Track the canonical address of what was placed into this register.
                # Needed to identify output buffer locations for output_arg_map.
                reg_canonical[stmt.offset] = reg_taint._canonical_addr(
                    stmt.data, tmp_taint, tmp_addr
                )

            elif stype == 'Store':
                # Memory write — propagate taint to memory slot (and ptr_taint if
                # tainted data is stored through a general register pointer).
                labels = reg_taint._taint_expr(stmt.data, tmp_taint, tmp_addr)
                reg_taint.store_mem(stmt.addr, labels, tmp_taint, tmp_addr)

        if is_call_block:
            # Resolve callee
            next_expr = irsb.next
            callee_addr = 0
            try:
                if hasattr(next_expr, 'con'):
                    callee_addr = next_expr.con.value
                elif type(next_expr).__name__ == 'Const':
                    callee_addr = next_expr.con.value
            except Exception:
                pass

            callee_name = _resolve_callee(proj, callee_addr) if callee_addr else 'unknown'

            # Only record calls to interesting functions
            if any(sub in callee_name for sub in interesting_names):
                tainted_args: set[int] = set()
                taint_sources: frozenset[str] = frozenset()

                for idx, off in enumerate(arg_offsets):
                    arg_taint = reg_taint.get(off)
                    if arg_taint:
                        tainted_args.add(idx)
                        taint_sources = taint_sources | arg_taint

                label = f'{callee_name}@{block.addr:#x}'
                rec   = CallRecord(
                    call_site    = block.addr,
                    callee_addr  = callee_addr,
                    callee_name  = callee_name,
                    tainted_args = tainted_args,
                    seq_idx      = len(calls),
                )
                calls.append(rec)
                cg.add_node(label, rec=rec)

                # Add edges from taint sources to this call
                for src_label in taint_sources:
                    if src_label in cg.nodes:
                        cg.add_edge(src_label, label)

                # After the call: mark return register as tainted by this call
                reg_taint.put(ret_offset, frozenset({label}))

                # Output-buffer marking (sources that fill caller-supplied buffers).
                # For each output arg index: mark the pointed-to memory slot and
                # the arg register's ptr_taint so subsequent field loads propagate.
                if output_arg_map:
                    for sub, out_args in output_arg_map.items():
                        if sub not in callee_name:
                            continue
                        for arg_idx in out_args:
                            if arg_idx >= len(arg_offsets):
                                continue
                            arg_off = arg_offsets[arg_idx]
                            # If the arg register held a tracked canonical address
                            # (e.g. 'sp+0x10' for a stack-allocated msg buffer),
                            # mark that memory slot directly as tainted.
                            buf_canonical = reg_canonical.get(arg_off)
                            if buf_canonical is not None:
                                existing = reg_taint._mem_state.get(
                                    buf_canonical, frozenset()
                                )
                                reg_taint._mem_state[buf_canonical] = (
                                    existing | frozenset({label})
                                )
                            # Also set ptr_taint on the arg register so that
                            # if the compiler keeps the buffer ptr in this
                            # register post-call, field loads through it are tainted.
                            reg_taint.set_ptr_taint(arg_off, frozenset({label}))

    return calls, cg


# ── Template matching ──────────────────────────────────────────────────────────

@dataclass
class TemplateMatch:
    """
    A template match found in one function.

    template    : the VulnTemplate that matched
    func_addr   : address of the function containing the match
    func_name   : name of the function
    source_node : call label of the source (taint origin)
    sink_node   : call label of the sink (vulnerability site)
    barrier_hit : True if a barrier call was found (suppresses finding)
    path_length : number of hops from source to sink
    confidence  : adjusted confidence (base * path_length penalty)
    """
    template    : VulnTemplate
    func_addr   : int
    func_name   : str
    source_node : str
    sink_node   : str
    barrier_hit : bool
    path_length : int
    confidence  : float

    def __str__(self) -> str:
        status = '(suppressed — barrier present)' if self.barrier_hit else ''
        return (
            f'[C3/{self.template.name}] @ {self.func_name} '
            f'({self.func_addr:#x})  {self.confidence:.0%} confidence  '
            f'{self.source_node} → [{self.path_length} hops] → {self.sink_node} '
            f'{status}\n'
            f'  {self.template.description}'
        )


def _match_template(
    template: VulnTemplate,
    calls:    list[CallRecord],
    cg:       nx.DiGraph,
    func_addr: int,
    func_name: str,
) -> list[TemplateMatch]:
    """
    Check whether *template* matches anywhere in the call dataflow graph.

    Source nodes: calls whose name contains any source_substring
    Sink nodes  : calls whose name contains any sink_substring
    A match exists when there is a directed path from any source to any sink.
    If any node on that path contains a barrier_substring, confidence is
    reduced to 0.10 (suppressed in report).
    """
    matches: list[TemplateMatch] = []

    sources: list[str] = []
    sinks:   list[str] = []

    for node_label in cg.nodes():
        rec: CallRecord = cg.nodes[node_label]['rec']
        if any(sub in rec.callee_name for sub in template.source_substrings):
            sources.append(node_label)
        if any(sub in rec.callee_name for sub in template.sink_substrings):
            # Check sink_arg constraint
            if template.sink_arg == -1 or rec.tainted_args:
                sinks.append(node_label)

    # Pre-compute: set of all barrier node labels in the CG for this template
    barrier_nodes: set[str] = set()
    for node_label in cg.nodes():
        rec: CallRecord = cg.nodes[node_label]['rec']
        if any(b in rec.callee_name for b in template.barrier_substrings):
            barrier_nodes.add(node_label)

    for src in sources:
        # All nodes reachable from src (the taint's "sphere of influence")
        src_reachable: set[str] = set(nx.descendants(cg, src)) | {src}

        for snk in sinks:
            if src == snk:
                continue
            try:
                path = nx.shortest_path(cg, src, snk)
            except nx.NetworkXNoPath:
                continue

            # Check for barrier: either on the direct path OR anywhere reachable
            # from the source (sibling calls that perform the guard check).
            # This catches the common pattern:
            #   val = source()
            #   if (barrier(val) == TYPE) { sink(val) }   ← barrier is sibling
            barrier_hit = False
            # 1. On-path barriers
            for mid_label in path[1:-1]:
                mid_rec: CallRecord = cg.nodes[mid_label]['rec']
                if any(b in mid_rec.callee_name
                       for b in template.barrier_substrings):
                    barrier_hit = True
                    break
            # 2. Off-path barrier: barrier called with taint from same source
            if not barrier_hit and template.barrier_substrings:
                for b_node in barrier_nodes:
                    if b_node in src_reachable and b_node != snk:
                        barrier_hit = True
                        break

            # Penalty for long paths (each extra hop reduces confidence 10%)
            hops       = len(path) - 1
            hop_factor = max(0.5, 1.0 - 0.10 * max(0, hops - 1))
            conf       = template.confidence * hop_factor
            if barrier_hit:
                conf = 0.10   # suppressed but still recorded for audit

            matches.append(TemplateMatch(
                template    = template,
                func_addr   = func_addr,
                func_name   = func_name,
                source_node = src,
                sink_node   = snk,
                barrier_hit = barrier_hit,
                path_length = hops,
                confidence  = conf,
            ))

    return matches


# ── Main analysis class ────────────────────────────────────────────────────────

@dataclass
class C3Result:
    """Full C3 analysis result."""
    matches          : list[TemplateMatch]
    functions_scanned: int
    binary_path      : str

    def print_report(self, min_confidence: float = 0.40) -> None:
        active = [m for m in self.matches
                  if not m.barrier_hit and m.confidence >= min_confidence]
        suppressed = [m for m in self.matches if m.barrier_hit]

        print(f'\nC3 Template Report — {self.binary_path}')
        print('=' * 70)
        print(f'Functions scanned    : {self.functions_scanned}')
        print(f'Active findings      : {len(active)} '
              f'(confidence >= {min_confidence:.0%})')
        print(f'Suppressed (barrier) : {len(suppressed)}')
        print()

        if not active:
            print('No active findings.')
        for i, m in enumerate(active, 1):
            print(f'[{i:02d}] {m}')
            print()

    @property
    def actionable(self) -> list[TemplateMatch]:
        """Active, non-suppressed matches above 40% confidence."""
        return [m for m in self.matches
                if not m.barrier_hit and m.confidence >= 0.40]

    @property
    def top_function_addrs(self) -> list[int]:
        """Unique function addresses with actionable findings, highest-confidence first."""
        seen: set[int] = set()
        addrs: list[int] = []
        for m in sorted(self.actionable, key=lambda m: m.confidence, reverse=True):
            if m.func_addr not in seen:
                seen.add(m.func_addr)
                addrs.append(m.func_addr)
        return addrs


class C3TemplateAnalysis:
    """
    C3 SSA-level call dataflow template matching driver.

    Parameters
    ----------
    project      : angr.Project (pre-loaded; reuse from C2 to avoid double load)
    templates    : list of VulnTemplate (defaults to TEMPLATE_BANK)
    max_functions: cap on how many functions to scan (0 = all); for speed

    Example
    -------
    ::

        import angr
        from metis.c3_templates import C3TemplateAnalysis

        proj   = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
        c3     = C3TemplateAnalysis(proj)
        result = c3.run()
        result.print_report()

    Composing with C2 (scan only top-ranked functions)
    --------------------------------------------------
    ::

        c2_result = C2RMTAnalysis.from_project(proj).run()
        c3_result = c3.analyse_functions(c2_result.top_function_addrs[:50])
    """

    def __init__(
        self,
        project:       angr.Project,
        templates:     Optional[list[VulnTemplate]] = None,
        max_functions: int = 0,
    ) -> None:
        self.proj          = project
        self.templates     = templates or TEMPLATE_BANK
        self.max_functions = max_functions
        self._cfg          = None

        # Build the set of all interesting function name substrings from templates
        self._interesting: set[str] = set()
        for t in self.templates:
            self._interesting.update(t.source_substrings)
            self._interesting.update(t.sink_substrings)
            self._interesting.update(t.barrier_substrings)

        # Build output_arg_map: source_substring → output arg indices.
        # If multiple templates share a source substring with different output_args,
        # the union of arg indices is used (conservative).
        self._output_arg_map: dict[str, tuple[int, ...]] = {}
        for t in self.templates:
            if not t.output_args:
                continue
            for sub in t.source_substrings:
                existing = set(self._output_arg_map.get(sub, ()))
                combined = tuple(sorted(existing | set(t.output_args)))
                self._output_arg_map[sub] = combined

    def _ensure_cfg(self) -> None:
        if self._cfg is None:
            log.info('C3: running CFGFast')
            self._cfg = self.proj.analyses.CFGFast(normalize=False)

    def analyse_functions(
        self, func_addrs: Optional[list[int]] = None
    ) -> C3Result:
        """
        Run template matching on a subset of functions.

        Parameters
        ----------
        func_addrs : list of function addresses to scan. If None, scan all.

        Returns C3Result with all matches found.
        """
        self._ensure_cfg()

        if func_addrs is None:
            funcs = [
                (addr, func)
                for addr, func in list(self.proj.kb.functions.items())
                if not func.is_plt and not func.is_simprocedure
            ]
        else:
            funcs = []
            for addr in func_addrs:
                try:
                    func = self.proj.kb.functions.get(addr)
                    if func and not func.is_plt:
                        funcs.append((addr, func))
                except Exception:
                    pass

        if self.max_functions and len(funcs) > self.max_functions:
            funcs = funcs[:self.max_functions]

        log.info('C3: scanning %d functions', len(funcs))
        all_matches: list[TemplateMatch] = []

        for addr, func in funcs:
            try:
                calls, cg = extract_call_dataflow(
                    self.proj, func, self._interesting,
                    output_arg_map=self._output_arg_map or None,
                )
            except Exception as e:
                log.debug('C3: skipping %s @ %#x: %s', func.name, addr, e)
                continue

            if not calls or cg.number_of_nodes() < 2:
                continue

            for template in self.templates:
                matches = _match_template(
                    template, calls, cg,
                    func_addr = addr,
                    func_name = func.name or f'sub_{addr:#x}',
                )
                all_matches.extend(matches)

        # Sort: active findings first, then by confidence descending
        all_matches.sort(
            key=lambda m: (m.barrier_hit, -m.confidence)
        )

        log.info('C3: %d total matches (%d active)',
                 len(all_matches),
                 sum(1 for m in all_matches if not m.barrier_hit))

        return C3Result(
            matches           = all_matches,
            functions_scanned = len(funcs),
            binary_path       = str(self.proj.filename),
        )

    def run(self) -> C3Result:
        """Run template matching on all non-stub functions."""
        return self.analyse_functions(func_addrs=None)
