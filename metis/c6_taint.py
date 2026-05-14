"""
c6_taint.py — C6: Dataflow taint analysis for XPC/Mach port vulnerability patterns.

Implements the C6 component of the cross-disciplinary macOS binary vulnerability
toolchain. Detects three forbidden def-use topologies by hooking key macOS
runtime functions with angr SimProcedures and propagating symbolic taint labels
through the execution:

  OOB   — A field from a mach_msg receive buffer (or XPC payload) reaches the
           size argument of malloc/calloc/realloc without an intervening branch
           that constrains the value below a safe limit.

  UAF   — A mach port right that has been passed to mach_port_deallocate is
           subsequently used in another mach operation (double-consume). Also
           detects double-free of heap allocations.

  XTYPE — An XPC object value obtained from xpc_dictionary_get_value reaches a
           type-specific accessor (xpc_int64_get_value, xpc_data_get_length,
           etc.) without xpc_get_type() appearing on the same execution path
           (approximated as: not called since the last get_value for that label).

Taint mechanism
---------------
Taint is carried via claripy symbolic variable *names*. When mach_msg receives
a message, the buffer is filled with a fresh BVS named
``mach_taint_mach_msg_<addr>`` — one wide symbol covering the whole buffer.
Because claripy propagates variable sets through all operations (concat, extract,
add, load, etc.), any derived value retains the variable name in its ``.variables``
set. ``_is_tainted()`` checks that set; no separate taint map is needed.

State tracking
--------------
Per-execution-path state is stored in angr's ``state.globals`` dict, which is
deep-copied at every symbolic branch:

  c6_tainted_regions : list[(start_addr, size_bytes, label)]
  c6_allocations     : {addr: {size, tainted_size, freed}}
  c6_freed_ports     : set of port names (ints) that have been deallocated
  c6_xpc_untyped     : set of taint labels not yet type-checked on this path
  c6_type_checked    : set of taint labels that passed xpc_get_type
  c6_findings        : list[VulnFinding]

Integration with C1 (HardnessExplorationTechnique)
---------------------------------------------------
C6TaintTechnique composes cleanly with C1:

    simgr.use_technique(C6TaintTechnique())
    simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))

Both operate on the same stash; C1 defers hard paths, C6 instruments every step.

PAC (Pointer Authentication, ARM64e)
-------------------------------------
angr does not model PAC instructions natively. This module treats all pointer
loads as unconstrained — effectively assuming PAC keys are unknown and stripping
PAC from all pointers before analysis. On ARM64e targets compiled with
``-fptrauth-calls``, this means some call targets will be symbolic; angr will
fork at indirect calls, which inflates the state count but is conservative.

Known limitations
-----------------
1. Hook coverage: only the symbols listed in ``_HOOK_TABLE`` are intercepted.
   Inlined versions of malloc/free (common at -O2+) will be missed. For
   production use, supplement with a CFG-level pass that identifies inlined
   allocator code using angr's ``CFGFast`` + ``Identifier`` analysis.

2. State explosion: mach_msg receive creates one wide symbolic variable for
   the entire buffer. angr will fork at every branch that tests any byte of
   that buffer. For large receive buffers (>256 bytes), set ``max_steps``
   conservatively and use C1 to defer hard paths first.

3. Inter-process flows: mach_msg models a *single* receive call. If the target
   daemon processes messages in a loop, you may need to hook the loop dispatch
   entry point manually and call ``_taint_mach_msg_buffer()`` directly.

4. Objective-C / Swift: ``objc_msgSend`` is hooked via ``ObjCDispatchResolver``
   (v2). The hook resolves the selector pointer in x1 to an IMP address and
   jumps there, making ObjC dispatch transparent to C6. Unresolvable selectors
   (symbolic x1, missing selref entry) return a tainted BVS. Swift method
   dispatch via Swift vtables is not yet modelled.

Example usage
-------------
    import angr
    from metis.c6_taint import C6Analysis

    proj  = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
    c6    = C6Analysis(proj)
    state = proj.factory.entry_state(args=['/usr/libexec/targetd'])
    result = c6.run(state, max_steps=800)
    result.print_report()

    # Compose with C1 hardness scoring:
    from metis.exploration_technique import HardnessExplorationTechnique
    result = c6.run(state, max_steps=800,
                    extra_techniques=[HardnessExplorationTechnique()])

Requires
--------
    angr >= 9.2  (pip install angr)
    claripy       (bundled with angr)
    Python >= 3.11

Author: generated as part of the C6 component of the macOS binary vuln toolchain.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional

import angr
import claripy

log = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────────

MACH_RCV_MSG        = 0x00000002   # option bit: receive operation
MACH_SEND_MSG       = 0x00000001   # option bit: send operation

# mach_msg_header_t field offsets (bytes) — from XNU osfmk/mach/message.h
MSGH_BITS           = 0
MSGH_SIZE           = 4
MSGH_REMOTE_PORT    = 8
MSGH_LOCAL_PORT     = 12
MSGH_VOUCHER_PORT   = 16
MSGH_ID             = 20
MSGH_HEADER_SIZE    = 24

# Taint variable name prefix — must be unique and not clash with angr internals
TAINT_PREFIX        = 'c6_taint'

# Maximum receive buffer size we will taint (safety cap)
MAX_RCV_TAINT_BYTES = 0x4000   # 16 KiB


# ── Vulnerability taxonomy ─────────────────────────────────────────────────────

class VulnClass(Enum):
    OOB   = auto()   # tainted value reaches allocator size without bounds check
    UAF   = auto()   # freed resource (port right or heap) reused
    XTYPE = auto()   # XPC value used by typed accessor without type guard


@dataclass
class VulnFinding:
    """
    A single detected vulnerability candidate.

    Attributes
    ----------
    vuln_class  : OOB, UAF, or XTYPE
    description : human-readable explanation of the finding
    site_addr   : instruction address of the sink where the violation was detected
    taint_label : the claripy variable name that traced back to the taint source
    state       : the angr SimState at the point of detection (use for replay)
    confidence  : 0.0–1.0; reduced when the path relies on unconstrained branches
    """
    vuln_class  : VulnClass
    description : str
    site_addr   : int
    taint_label : str
    state       : object = field(repr=False)
    confidence  : float  = 1.0

    def __str__(self) -> str:
        return (
            f'[{self.vuln_class.name}] @ {self.site_addr:#010x} '
            f'({self.confidence:.0%} confidence)\n'
            f'  {self.description}'
        )


# ── Taint helpers ──────────────────────────────────────────────────────────────

def _is_tainted(expr: claripy.ast.Base) -> bool:
    """
    Return True if *expr* contains any claripy variable introduced by C6.

    Relies on claripy's variable propagation: every operation on a symbolic
    value carries the union of all ancestor variable names. Checking the
    ``.variables`` frozenset is O(1) in the common (cache-hit) case.
    """
    try:
        return any(v.startswith(TAINT_PREFIX) for v in expr.variables)
    except AttributeError:
        return False


def _taint_label(expr: claripy.ast.Base) -> str:
    """Return the first C6 taint label found in *expr*, or empty string."""
    try:
        for v in expr.variables:
            if v.startswith(TAINT_PREFIX):
                return v
    except AttributeError:
        pass
    return ''


def _fresh_taint(label: str, bits: int) -> claripy.ast.BV:
    """
    Create a fresh tainted bitvector.

    The variable name encodes the taint origin so that any derived value
    retains the origin in its .variables set.
    """
    return claripy.BVS(f'{TAINT_PREFIX}_{label}', bits)


# ── State globals ──────────────────────────────────────────────────────────────

def _ensure_c6_globals(state: angr.SimState) -> None:
    """
    Initialise C6 tracking structures in state.globals.

    Safe to call repeatedly; idempotent after the first call.
    state.globals is deep-copied by angr at every symbolic branch, so all
    structures here are path-local.
    """
    if state.globals.get('c6_init'):
        return
    state.globals['c6_init']            = True
    state.globals['c6_tainted_regions'] = []   # [(start, size, label)]
    state.globals['c6_allocations']     = {}   # {addr: {size, tainted_size, freed}}
    state.globals['c6_freed_ports']     = set()
    state.globals['c6_xpc_untyped']     = set()
    state.globals['c6_type_checked']    = set()
    state.globals['c6_findings']        = []


def _record_finding(state: angr.SimState, finding: VulnFinding) -> None:
    """Append a finding to state-local list, deduplicating within the path."""
    existing = state.globals['c6_findings']
    key = (finding.vuln_class, finding.site_addr, finding.taint_label)
    if not any(
        (f.vuln_class, f.site_addr, f.taint_label) == key
        for f in existing
    ):
        existing.append(finding)
        log.warning('C6/%s @ %#x: %s', finding.vuln_class.name,
                    finding.site_addr, finding.description[:120])


# ── Internal helpers ───────────────────────────────────────────────────────────

def _taint_mach_msg_buffer(
    state: angr.SimState,
    buf_addr: int,
    buf_size: int,
    label: str,
) -> None:
    """
    Fill *buf_addr..(buf_addr+buf_size)* with a single wide symbolic variable.

    Using one symbol rather than per-byte symbols keeps the constraint set
    manageable. Any slice extracted from it retains the taint label.
    """
    buf_size = min(buf_size, MAX_RCV_TAINT_BYTES)
    tainted = _fresh_taint(label, buf_size * 8)
    state.memory.store(
        buf_addr, tainted,
        endness=state.arch.memory_endness,
    )
    state.globals['c6_tainted_regions'].append((buf_addr, buf_size, label))
    log.info('C6: tainted mach_msg buffer @ %#x (%d bytes, label=%s)',
             buf_addr, buf_size, label)


def _eval_concrete(state: angr.SimState, expr, default: int = 0) -> int:
    """
    Try to concretise *expr*. Returns *default* if solver raises or is symbolic.
    """
    try:
        return state.solver.eval(expr, cast_to=int)
    except Exception:
        return default


# ── SimProcedures ──────────────────────────────────────────────────────────────

class Hook_mach_msg(angr.SimProcedure):
    """
    SimProcedure for ``mach_msg`` and ``mach_msg_trap``.

    When the option word includes MACH_RCV_MSG, taint the receive buffer with
    a named symbolic bitvector. This models the fact that the message content
    is attacker-controlled (sent from an unprivileged sender).

    C prototype::

        kern_return_t mach_msg(
            mach_msg_header_t *msg,       // arg0
            mach_msg_option_t  option,    // arg1
            mach_msg_size_t    send_size, // arg2
            mach_msg_size_t    rcv_size,  // arg3
            mach_port_t        rcv_name,  // arg4
            mach_msg_timeout_t timeout,   // arg5
            mach_port_t        notify     // arg6
        );
    """

    IS_FUNCTION = True
    NUM_ARGS    = 7

    def run(self, msg_ptr, option, send_size, rcv_size,
            rcv_name, timeout, notify):
        _ensure_c6_globals(self.state)

        # Resolve option — treat symbolic option conservatively as receive
        opt_val = _eval_concrete(self.state, option, default=MACH_RCV_MSG)

        if opt_val & MACH_RCV_MSG:
            buf_addr = _eval_concrete(self.state, msg_ptr)
            buf_size = _eval_concrete(self.state, rcv_size, default=64)
            if buf_addr:
                label = f'mach_msg_{buf_addr:#x}'
                _taint_mach_msg_buffer(self.state, buf_addr, buf_size, label)

        # Return KERN_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)


class Hook_malloc(angr.SimProcedure):
    """
    SimProcedure for ``malloc``.

    Detects C6/OOB: tainted ``size`` argument reaching the allocator.
    Also tracks the returned allocation for downstream UAF detection.

    C prototype::

        void *malloc(size_t size);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 1

    # Size values bounded below this by path constraints are considered safe.
    # 64 KiB is conservative; real IPC messages are bounded by MACH_MSG_SIZE_MAX.
    SAFE_MAX = 0x10000

    def run(self, size):
        _ensure_c6_globals(self.state)

        if _is_tainted(size):
            label = _taint_label(size)
            # Check whether path constraints have already bounded the size.
            # If solver.max(size) < SAFE_MAX the bounds check is on this path.
            confidence = 0.85
            description_note = 'no bounds check on this path'
            try:
                max_val = self.state.solver.max(size)
                if max_val < self.SAFE_MAX:
                    # Size is constrained — this path went through a guard.
                    # Record with low confidence (informational only).
                    confidence = 0.20
                    description_note = (
                        f'bounded to max {max_val:#x} by path constraints '
                        f'(guard likely present but size still attacker-influenced)'
                    )
            except Exception:
                pass  # symbolic max unavailable — keep default confidence

            if confidence >= 0.40:  # suppress low-confidence informational hits
                _record_finding(self.state, VulnFinding(
                    vuln_class  = VulnClass.OOB,
                    description = (
                        f'malloc() called with tainted size ({description_note}). '
                        f'Taint origin: {label}'
                    ),
                    site_addr   = self.state.addr,
                    taint_label = label,
                    state       = self.state,
                    confidence  = confidence,
                ))

        # Simulate allocation; use a concrete size to avoid heap explosion
        alloc_size = _eval_concrete(self.state, size, default=64)
        alloc_size = max(1, min(alloc_size, MAX_RCV_TAINT_BYTES))

        try:
            ret_addr = self.state.heap.allocate(alloc_size)
        except Exception:
            ret_addr = 0x10000000  # fallback concrete address

        alloc_addr = ret_addr if isinstance(ret_addr, int) else _eval_concrete(
            self.state, ret_addr, default=0x10000000
        )
        self.state.globals['c6_allocations'][alloc_addr] = {
            'size':         size,
            'tainted_size': _is_tainted(size),
            'freed':        False,
        }
        return claripy.BVV(alloc_addr, self.state.arch.bits)


class Hook_calloc(angr.SimProcedure):
    """
    SimProcedure for ``calloc``.

    Detects C6/OOB for tainted ``count`` or ``size`` arguments.

    C prototype::

        void *calloc(size_t count, size_t size);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 2

    def run(self, count, size):
        _ensure_c6_globals(self.state)

        for arg, argname in [(count, 'count'), (size, 'element_size')]:
            if _is_tainted(arg):
                label = _taint_label(arg)
                _record_finding(self.state, VulnFinding(
                    vuln_class  = VulnClass.OOB,
                    description = (
                        f'calloc() {argname} argument is tainted (no bounds '
                        f'check on this path). Taint origin: {label}'
                    ),
                    site_addr   = self.state.addr,
                    taint_label = label,
                    state       = self.state,
                    confidence  = 0.85,
                ))

        n  = _eval_concrete(self.state, count,  default=1)
        sz = _eval_concrete(self.state, size,   default=64)
        total = max(1, min(n * sz, MAX_RCV_TAINT_BYTES))

        try:
            ret_addr = self.state.heap.allocate(total)
        except Exception:
            ret_addr = 0x10000000

        alloc_addr = ret_addr if isinstance(ret_addr, int) else _eval_concrete(
            self.state, ret_addr, default=0x10000000
        )
        self.state.globals['c6_allocations'][alloc_addr] = {
            'size':         count * size,
            'tainted_size': _is_tainted(count) or _is_tainted(size),
            'freed':        False,
        }
        return claripy.BVV(alloc_addr, self.state.arch.bits)


class Hook_realloc(angr.SimProcedure):
    """
    SimProcedure for ``realloc``.

    Detects C6/OOB for tainted new size. Marks the old allocation as freed.

    C prototype::

        void *realloc(void *ptr, size_t new_size);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 2

    def run(self, ptr, new_size):
        _ensure_c6_globals(self.state)

        if _is_tainted(new_size):
            label = _taint_label(new_size)
            _record_finding(self.state, VulnFinding(
                vuln_class  = VulnClass.OOB,
                description = (
                    f'realloc() new_size argument is tainted (no bounds check '
                    f'on this path). Taint origin: {label}'
                ),
                site_addr   = self.state.addr,
                taint_label = label,
                state       = self.state,
                confidence  = 0.82,
            ))

        # Mark old allocation freed
        old_addr = _eval_concrete(self.state, ptr)
        allocs = self.state.globals['c6_allocations']
        if old_addr in allocs:
            allocs[old_addr]['freed'] = True

        sz = max(1, min(_eval_concrete(self.state, new_size, 64),
                        MAX_RCV_TAINT_BYTES))
        try:
            ret_addr = self.state.heap.allocate(sz)
        except Exception:
            ret_addr = 0x20000000

        new_addr = ret_addr if isinstance(ret_addr, int) else _eval_concrete(
            self.state, ret_addr, default=0x20000000
        )
        allocs[new_addr] = {
            'size':         new_size,
            'tainted_size': _is_tainted(new_size),
            'freed':        False,
        }
        return claripy.BVV(new_addr, self.state.arch.bits)


class Hook_free(angr.SimProcedure):
    """
    SimProcedure for ``free``.

    Marks the allocation as freed. On double-free, records a C6/UAF finding.

    C prototype::

        void free(void *ptr);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 1

    def run(self, ptr):
        _ensure_c6_globals(self.state)

        addr = _eval_concrete(self.state, ptr)
        if addr == 0:
            return  # free(NULL) is a no-op

        allocs = self.state.globals['c6_allocations']
        if addr in allocs:
            if allocs[addr]['freed']:
                _record_finding(self.state, VulnFinding(
                    vuln_class  = VulnClass.UAF,
                    description = f'double-free of heap allocation @ {addr:#x}',
                    site_addr   = self.state.addr,
                    taint_label = '',
                    state       = self.state,
                    confidence  = 0.95,
                ))
            allocs[addr]['freed'] = True


class Hook_mach_port_deallocate(angr.SimProcedure):
    """
    SimProcedure for ``mach_port_deallocate``.

    Marks the port right as consumed. If the same port name is deallocated
    twice on the same execution path, records a C6/UAF finding.

    C prototype::

        kern_return_t mach_port_deallocate(
            ipc_space_t      task,   // arg0 (usually mach_task_self())
            mach_port_name_t name    // arg1 — the port right to release
        );
    """

    IS_FUNCTION = True
    NUM_ARGS    = 2

    def run(self, task, name):
        _ensure_c6_globals(self.state)

        port_name = _eval_concrete(self.state, name)
        freed = self.state.globals['c6_freed_ports']

        if port_name and port_name in freed:
            _record_finding(self.state, VulnFinding(
                vuln_class  = VulnClass.UAF,
                description = (
                    f'mach_port_deallocate called twice on port {port_name:#x} '
                    f'on this path (port right use-after-free)'
                ),
                site_addr   = self.state.addr,
                taint_label = '',
                state       = self.state,
                confidence  = 0.92,
            ))

        if port_name:
            freed.add(port_name)

        return claripy.BVV(0, 32)  # KERN_SUCCESS


class Hook_xpc_dictionary_get_value(angr.SimProcedure):
    """
    SimProcedure for ``xpc_dictionary_get_value``.

    Returns a tainted symbolic value representing the untyped XPC object.
    Marks the return value's taint label as *untyped* — it must pass through
    xpc_get_type() before reaching a typed accessor.

    C prototype::

        xpc_object_t xpc_dictionary_get_value(
            xpc_object_t  xdict,  // arg0
            const char   *key     // arg1
        );
    """

    IS_FUNCTION = True
    NUM_ARGS    = 2

    def run(self, xdict, key):
        _ensure_c6_globals(self.state)

        label = f'xpc_val_{self.state.addr:#x}'
        ret   = _fresh_taint(label, self.state.arch.bits)
        # Use the full claripy variable name (includes _0_bits suffix) as key
        # so that _taint_label() matches it consistently everywhere.
        full_label = _taint_label(ret)
        self.state.globals['c6_xpc_untyped'].add(full_label)
        return ret


class Hook_xpc_get_type(angr.SimProcedure):
    """
    SimProcedure for ``xpc_get_type``.

    Records that the XPC object's taint label has been type-checked on this
    path. Removes the label from the *untyped* set.

    C prototype::

        xpc_type_t xpc_get_type(xpc_object_t object);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 1

    def run(self, xpc_obj):
        _ensure_c6_globals(self.state)

        if _is_tainted(xpc_obj):
            label = _taint_label(xpc_obj)
            self.state.globals['c6_xpc_untyped'].discard(label)
            self.state.globals['c6_type_checked'].add(label)

        # Return a symbolic type tag (the caller will branch on it)
        return _fresh_taint(f'xpc_type_{self.state.addr:#x}',
                            self.state.arch.bits)


class Hook_xpc_typed_accessor(angr.SimProcedure):
    """
    Generic SimProcedure for XPC type-specific value accessors.

    If the xpc_object argument is tainted *and* its label has not appeared
    in a xpc_get_type() call on this path, records a C6/XTYPE finding.

    Parameters
    ----------
    accessor_name : str
        Human-readable name for error messages (e.g. 'xpc_int64_get_value').
    ret_bits : int
        Width of the return value in bits (64 for most accessors).

    C prototype example::

        int64_t xpc_int64_get_value(xpc_object_t object);
    """

    IS_FUNCTION = True
    NUM_ARGS    = 1

    def __init__(self, accessor_name: str, ret_bits: int = 64):
        super().__init__()
        self._accessor_name = accessor_name
        self._ret_bits      = ret_bits

    def run(self, xpc_obj):
        _ensure_c6_globals(self.state)

        if _is_tainted(xpc_obj):
            label   = _taint_label(xpc_obj)
            untyped = self.state.globals['c6_xpc_untyped']
            checked = self.state.globals['c6_type_checked']

            if label in untyped and label not in checked:
                _record_finding(self.state, VulnFinding(
                    vuln_class  = VulnClass.XTYPE,
                    description = (
                        f'{self._accessor_name}() reached with XPC object that '
                        f'has not been type-checked (xpc_get_type not on this '
                        f'path). Taint origin: {label}'
                    ),
                    site_addr   = self.state.addr,
                    taint_label = label,
                    state       = self.state,
                    confidence  = 0.80,
                ))

        # Return a tainted value so downstream taint propagates
        return _fresh_taint(
            f'{self._accessor_name}_{self.state.addr:#x}', self._ret_bits
        )


# ── Hook table ────────────────────────────────────────────────────────────────
#
# Maps symbol names (including underscore-prefixed MachO variants) to the
# SimProcedure class or factory that should replace them.
#
# Format: (symbol_name_with_underscore, SimProcedure_instance)
#
# XPC typed accessors follow at the bottom.

_HOOK_TABLE: list[tuple[str, angr.SimProcedure]] = [
    # Mach IPC
    ('_mach_msg',                Hook_mach_msg()),
    ('_mach_msg_trap',           Hook_mach_msg()),
    ('_mach_port_deallocate',    Hook_mach_port_deallocate()),

    # Heap allocators
    ('_malloc',                  Hook_malloc()),
    ('_calloc',                  Hook_calloc()),
    ('_realloc',                 Hook_realloc()),
    ('_free',                    Hook_free()),

    # XPC dictionary read
    ('_xpc_dictionary_get_value', Hook_xpc_dictionary_get_value()),

    # XPC type guard
    ('_xpc_get_type',            Hook_xpc_get_type()),
]

# XPC typed accessors — (mangled_symbol, return_bits)
_XPC_TYPED_ACCESSORS: list[tuple[str, int]] = [
    ('_xpc_int64_get_value',       64),
    ('_xpc_uint64_get_value',      64),
    ('_xpc_double_get_value',      64),
    ('_xpc_bool_get_value',         8),
    ('_xpc_string_get_string_ptr', 64),   # → char*
    ('_xpc_data_get_bytes_ptr',    64),   # → void*
    ('_xpc_data_get_length',       64),
    ('_xpc_array_get_count',       64),
    ('_xpc_dictionary_get_count',  64),
]

for _sym, _bits in _XPC_TYPED_ACCESSORS:
    _name = _sym.lstrip('_')
    _HOOK_TABLE.append((_sym, Hook_xpc_typed_accessor(_name, _bits)))


# ── Exploration technique ──────────────────────────────────────────────────────

class C6TaintTechnique(angr.exploration_techniques.ExplorationTechnique):
    """
    angr ExplorationTechnique that drives C6 taint tracking.

    Does not modify which states are explored — that is left to C1
    (HardnessExplorationTechnique). This technique only ensures that:

    * C6 tracking structures are initialised in every new state.
    * After exploration completes, findings can be collected via
      ``collect_findings(simgr)``.

    Use with ``simgr.use_technique(C6TaintTechnique())``.
    """

    def setup(self, simgr: angr.SimulationManager) -> None:
        for stash in simgr.stashes.values():
            for state in stash:
                _ensure_c6_globals(state)

    def step(self, simgr: angr.SimulationManager,
             stash: str = 'active', **kwargs):
        simgr.step(stash=stash, **kwargs)
        # Ensure any newly created states have C6 globals
        for state in simgr.stashes.get(stash, []):
            _ensure_c6_globals(state)
        return simgr

    def collect_findings(
        self, simgr: angr.SimulationManager
    ) -> list[VulnFinding]:
        """
        Gather and deduplicate all VulnFinding objects across every stash.

        Returns findings sorted by (VulnClass, site_addr).
        """
        seen:    set[tuple]        = set()
        results: list[VulnFinding] = []

        for stash_states in simgr.stashes.values():
            for state in stash_states:
                for f in state.globals.get('c6_findings', []):
                    key = (f.vuln_class, f.site_addr, f.taint_label)
                    if key not in seen:
                        seen.add(key)
                        results.append(f)

        return sorted(results, key=lambda f: (f.vuln_class.value, f.site_addr))


# ── Main analysis driver ───────────────────────────────────────────────────────

@dataclass
class C6Result:
    """
    Return value from ``C6Analysis.run()``.

    Attributes
    ----------
    findings : list of VulnFinding, sorted by (class, site_addr)
    simgr    : the angr SimulationManager after exploration completed
               (use for manual replay: ``simgr.found``, ``simgr.deadended``, …)
    """
    findings : list[VulnFinding]
    simgr    : object  # angr.SimulationManager

    def print_report(self) -> None:
        """Print a human-readable summary to stdout."""
        if not self.findings:
            print('C6: no findings on any explored path.')
            return
        print(f'\nC6 Findings — {len(self.findings)} candidate(s)')
        print('=' * 70)
        for i, f in enumerate(self.findings, 1):
            print(f'[{i:02d}] {f}')
            print()

    @property
    def by_class(self) -> dict[VulnClass, list[VulnFinding]]:
        """Group findings by VulnClass for easy iteration."""
        groups: dict[VulnClass, list[VulnFinding]] = {c: [] for c in VulnClass}
        for f in self.findings:
            groups[f.vuln_class].append(f)
        return groups


class C6Analysis:
    """
    C6 taint analysis driver for macOS Mach-O binaries.

    Installs SimProcedure hooks for mach_msg, XPC, and allocator functions,
    then runs angr symbolic exploration collecting VulnFinding instances.

    Parameters
    ----------
    project : angr.Project
        The already-loaded angr project. ``auto_load_libs=False`` is
        recommended to avoid loading all of libSystem.

    Example
    -------
    ::

        import angr
        from metis.c6_taint import C6Analysis

        proj   = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
        c6     = C6Analysis(proj)
        state  = proj.factory.entry_state()
        result = c6.run(state, max_steps=500)
        result.print_report()

    Composing with C1 (hardness-aware path prioritisation)
    -------------------------------------------------------
    ::

        from metis.exploration_technique import HardnessExplorationTechnique
        result = c6.run(
            state, max_steps=1000,
            extra_techniques=[HardnessExplorationTechnique(threshold=0.75)]
        )
    """

    def __init__(self, project: angr.Project) -> None:
        self.proj = project
        self._hooked: list[str] = []
        self._objc_resolver = None   # set by _install_objc_hook if ObjC binary
        self._install_hooks()
        self._install_objc_hook()

    def _install_objc_hook(self) -> None:
        """
        If the binary contains ObjC runtime sections, install a SimProcedure
        hook on _objc_msgSend that resolves dispatch to concrete IMP addresses.

        The hook is a factory closure bound to an ObjCDispatchResolver instance
        so it can look up selector → IMP mappings at symbolic execution time.
        """
        try:
            from metis.objc_dispatch import (
                ObjCDispatchResolver, make_objcMsgSend_hook)
            resolver = ObjCDispatchResolver(self.proj)
            result   = resolver.resolve()
            if not result.is_objc_binary:
                return
            self._objc_resolver = resolver
            HookClass = make_objcMsgSend_hook(resolver)
            for sym in ('_objc_msgSend', 'objc_msgSend',
                        '_objc_msgSend_stret', 'objc_msgSend_stret'):
                if self._symbol_exists(sym):
                    self.proj.hook_symbol(sym, HookClass())
                    self._hooked.append(sym)
                    log.info('C6: ObjC hook installed on %s '
                             '(%d selectors, %d edges)',
                             sym, result.selector_count,
                             len(result.synthetic_edges))
        except Exception as exc:
            log.warning('C6: ObjC hook installation failed: %s', exc)

    def _install_hooks(self) -> None:
        """
        Install all SimProcedure hooks on self.proj.

        Each symbol is attempted with both the underscore-prefixed MachO form
        (``_malloc``) and the plain form (``malloc``). Only installed if the
        symbol is present in the binary or its loaded stubs.

        Uses hook_symbol with ``replace=True`` so existing hooks (e.g. from a
        prior SimProcedure library) are overridden.

        Note: CLE's find_symbol API varies across versions — we use a wrapper
        that handles IndexError from empty-list returns in newer CLE builds.
        """
        for sym_with_underscore, proc in _HOOK_TABLE:
            for sym in (sym_with_underscore, sym_with_underscore.lstrip('_')):
                if self._symbol_exists(sym):
                    self.proj.hook_symbol(sym, proc)
                    self._hooked.append(sym)
                    log.info('C6: hooked %s', sym)
                    break  # don't double-hook both variants

        if not self._hooked:
            log.warning(
                'C6: no hook targets found in binary. Check symbol names with: '
                'nm -u <binary> | grep -E "mach_msg|malloc|xpc_"'
            )

    def _symbol_exists(self, sym_name: str) -> bool:
        """
        Return True if *sym_name* exists in the loaded binary or its stubs.

        Handles both old CLE (find_symbol returns None on miss) and new CLE
        (find_symbol raises IndexError on empty result).
        """
        try:
            result = self.proj.loader.find_symbol(sym_name)
            return result is not None
        except (IndexError, AttributeError):
            # Newer CLE versions raise IndexError when the symbol list is empty
            pass
        # Fallback: search by iterating main_object symbols
        try:
            return any(
                s.name == sym_name
                for s in self.proj.loader.main_object.symbols
            )
        except Exception:
            return False

    def taint_entry_state_buffer(
        self,
        state: angr.SimState,
        buf_addr: int,
        buf_size: int,
        label: str = 'manual',
    ) -> None:
        """
        Manually taint a buffer in *state* before starting exploration.

        Use this when the target function is a message-handler called directly
        (not via mach_msg), or when you have a specific struct to mark as
        attacker-controlled.

        Parameters
        ----------
        state    : the angr SimState to modify (must be pre-exploration)
        buf_addr : start address of the buffer to taint
        buf_size : number of bytes to taint
        label    : short name embedded in the taint variable (for reporting)
        """
        _ensure_c6_globals(state)
        _taint_mach_msg_buffer(state, buf_addr, buf_size, label)

    def run(
        self,
        initial_state: angr.SimState,
        max_steps: int = 1000,
        find: Optional[Callable[[angr.SimState], bool]] = None,
        avoid: Optional[Callable[[angr.SimState], bool]] = None,
        extra_techniques: Optional[list] = None,
    ) -> C6Result:
        """
        Run symbolic exploration with C6 taint tracking active.

        Parameters
        ----------
        initial_state    : angr SimState to start from
        max_steps        : maximum exploration steps (not path depth)
        find             : optional predicate — exploration stops when a state
                           satisfies ``find(state) == True``
        avoid            : optional predicate — states satisfying
                           ``avoid(state) == True`` are pruned
        extra_techniques : additional ExplorationTechniques to compose, e.g.
                           ``[HardnessExplorationTechnique(threshold=0.8)]``

        Returns
        -------
        C6Result
        """
        _ensure_c6_globals(initial_state)
        simgr = self.proj.factory.simgr(initial_state)

        # C6 technique first so it can initialise globals before C1 scores them
        c6_tech = C6TaintTechnique()
        simgr.use_technique(c6_tech)

        for tech in (extra_techniques or []):
            simgr.use_technique(tech)

        explore_kwargs: dict = {}
        if find:
            explore_kwargs['find']  = find
        if avoid:
            explore_kwargs['avoid'] = avoid

        log.info('C6: starting exploration (max_steps=%d, hooks=%d)',
                 max_steps, len(self._hooked))
        simgr.explore(n=max_steps, **explore_kwargs)
        log.info('C6: exploration complete — deadended=%d, active=%d',
                 len(simgr.deadended), len(simgr.active))

        findings = c6_tech.collect_findings(simgr)
        log.info('C6: %d finding(s) collected', len(findings))
        return C6Result(findings=findings, simgr=simgr)

    def hooked_symbols(self) -> list[str]:
        """Return the list of symbol names that were successfully hooked."""
        return list(self._hooked)
