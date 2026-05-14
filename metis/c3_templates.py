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

Nine macOS-specific templates
------------------------------
MACH_OOB        — mach_msg receive buffer field → malloc/calloc size (no bound)
XPC_TYPE        — xpc_dictionary_get_value → typed XPC accessor without xpc_get_type
XPC_SIZE_ALLOC  — XPC length/count → allocator (no bounds check)
PORT_UAF        — mach_port_deallocate → any mach port operation on same name
IOKIT_OOB       — IOConnectCallMethod out-of-band data → memory copy/alloc
INT_OVERFLOW_ALLOC — attacker int × element_size → calloc/realloc (overflow underalloc)
OOB_INDEX       — attacker-controlled index/offset → pwrite/pread/lseek/array accessor
UAF_STORE_FREE  — free/CFRelease on heap ptr → subsequent use of same ptr value
ARGV_GLOBAL_WRITE — getopt/optarg/environ attacker value → fixed-size global buffer write

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

import bisect
import logging
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

import networkx as nx
import pyvex

import angr

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Substring matching helpers
# ---------------------------------------------------------------------------

# Short POSIX syscall names that must be matched with a word-boundary rule to
# avoid false positives.  For example 'read' in source_substrings would
# naively match 'pthread_mutex_unlock' (contains 'thread' → 'read') and
# 'send' would match 'send_fail_response'.  For these names we require:
#   - The callee name (after stripping leading '_') must START with the sub, AND
#   - The character immediately following must be either end-of-string OR an
#     alpha character (no underscore).  This allows 'recv'→'recvfrom',
#     'send'→'sendmsg', 'read'→'read', but rejects 'send_fail_response' and
#     'pthread_mutex_unlock'.
_SYSCALL_SUBS: frozenset[str] = frozenset(
    {'read', 'write', 'send', 'recv', 'free', 'mmap', 'open', 'close'}
)


def _sub_in_name(sub: str, callee: str) -> bool:
    """Return True if template substring *sub* matches callee name *callee*.

    For short generic syscall names (see _SYSCALL_SUBS) a word-boundary rule
    is applied to prevent false positives.  For all other patterns the standard
    ``sub in callee`` substring check is used.
    """
    if sub not in _SYSCALL_SUBS:
        return sub in callee
    # Strip leading underscores (PLT stub names include the leading '_').
    bare = callee.lstrip('_')
    if not bare.startswith(sub):
        return False
    rest = bare[len(sub):]
    # Accept exact match or alphanumeric continuation (e.g. recvfrom, sendmsg)
    # but NOT underscore-separated suffix (e.g. send_fail_response).
    return not rest or rest[0].isalpha()


# Optional: lief + capstone for arm64e PLT stub name resolution and
# capstone-based block recovery fallback.  Both are available in the venv.
try:
    import lief as _lief
    import capstone as _capstone
    _LIEF_CAPSTONE_OK = True
except ImportError:
    _LIEF_CAPSTONE_OK = False
    log.debug('c3_templates: lief/capstone not available — arm64e PLT map disabled')


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
    # Callee name fragments that veto a source/sink match even when the
    # primary substrings match.  Prevents false positives from zone-creation
    # APIs (malloc_create_zone, malloc_set_zone_name) being treated as heap
    # allocator sinks, and ObjC metadata symbols being treated as sources.
    source_exclusions  : tuple[str, ...] = ()
    sink_exclusions    : tuple[str, ...] = (
        'create_zone', 'set_zone_name', 'zone_from_ptr',   # malloc zone mgmt
        'OBJC_CLASS_$', 'OBJC_METACLASS_$',                # ObjC class objects
        'ImmortalRefCount', 'swiftImmortal',               # Swift immortal refs
    )
    # If True, only fire this template when taint was tracked by the VEX IR
    # path (not the capstone fallback).  The capstone fallback marks ALL args
    # tainted (conservative), which causes self-referential templates (source ≈
    # sink, e.g. DOUBLE_FREE) to fire on every cleanup function.  Set this flag
    # on templates where source and sink overlap and identity of the tainted
    # value matters — the VEX IR tracker preserves per-register taint labels.
    require_vex        : bool = False


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

    # ── New high-value templates ───────────────────────────────────────────────

    VulnTemplate(
        name               = 'INT_OVERFLOW_ALLOC',
        source_substrings  = (
            # Attacker-controlled integer sources (network / XPC / IPC)
            'xpc_uint64_get_value', 'xpc_int64_get_value',
            'xpc_data_get_length', 'xpc_array_get_count',
            'xpc_dictionary_get_count',
            'recv', 'recvfrom', 'recvmsg',
            'ntohl', 'ntohs', 'ntohll',
            'mach_msg',
            'IOConnectCallMethod', 'IOConnectCallScalarMethod',
            'read',
        ),
        sink_substrings    = (
            # calloc(count, size) is the canonical overflow site.
            # realloc(ptr, new_size) with unchecked count * element_size also.
            'calloc', 'realloc', 'reallocf',
            # malloc/valloc if the tainted value was produced by arithmetic
            'malloc', 'valloc',
        ),
        barrier_substrings = (
            # os_mul_overflow / __builtin_mul_overflow are compiler intrinsics and
            # not PLT-visible, so we cannot barrier on them here.
            # However, explicit size-cap helpers are sometimes PLT-callable:
            'os_add_overflow', 'checked_add', 'safe_mul',
        ),
        sink_arg           = 0,      # size is arg0 for malloc; count is arg0 for calloc
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Attacker-controlled integer value reaches an allocator (calloc/realloc/malloc) '
            'without a visible multiplication-overflow check. If the value is used as a '
            'count in calloc(count, elem_size), or multiplied by an element size before '
            'malloc(), integer wrap-around produces an underallocated buffer leading to '
            'heap overflow on the first write past the buffer end. Classic pattern: '
            'n = xpc_uint64_get_value(msg, "count"); buf = calloc(n, sizeof(item)); '
            'memcpy(buf, src, n * sizeof(item));'
        ),
        confidence         = 0.73,
    ),

    VulnTemplate(
        name               = 'OOB_INDEX',
        source_substrings  = (
            # Attacker-controlled integer/offset sources
            'xpc_uint64_get_value', 'xpc_int64_get_value',
            'xpc_array_get_count', 'xpc_data_get_length',
            'recv', 'recvfrom', 'recvmsg',
            'ntohl', 'ntohs', 'ntohll',
            'mach_msg', 'read',
        ),
        sink_substrings    = (
            # File offset ops — attacker-controlled seek position
            'pwrite', 'pread', 'lseek',
            # Array / collection accessors that take an integer index
            'CFArrayGetValueAtIndex', 'CFArraySetValueAtIndex',
            'CFArrayRemoveValueAtIndex', 'CFArrayInsertValueAtIndex',
            'CFDictionaryGetValueAtIndex',
            # memset/memmove with attacker-controlled count/offset
            'memset', 'memmove', 'bzero',
            # Dispatch time-after with attacker value (not OOB but interesting)
            'dispatch_after',
        ),
        barrier_substrings = (
            # CFIndex bounds checks show up as comparisons (branch), not calls.
            # The only PLT-visible guards are range-check helpers:
            'CFRangeMake',   # building a validated range struct is a soft barrier
        ),
        sink_arg           = -1,     # index/offset can land in any argument position
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Attacker-controlled integer value used as an array index, file offset, or '
            'memory operation size/count without a visible bounds check on the call path. '
            'Direct OOB read or write if the value exceeds the buffer or file limits. '
            'Covers: unchecked XPC count → CFArrayGetValueAtIndex; recv-derived length → '
            'pwrite offset; ntohl count → memset size. Requires manual confirmation that '
            'the source and index reach the same array/buffer in the same function.'
        ),
        confidence         = 0.68,
    ),

    VulnTemplate(
        name               = 'UAF_STORE_FREE',
        source_substrings  = (
            # Deallocation functions — after these, the pointer arg is "freed"
            'free', 'CFRelease', 'dispatch_release',
            'objc_release', 'os_release',
            'IOObjectRelease',
        ),
        sink_substrings    = (
            # Any subsequent use of memory through the freed pointer
            'memcpy', 'memset', 'memmove', 'bcopy',
            'read', 'write', 'send', 'recv',
            # Re-retain or casting — type confusion after free
            'CFRetain', 'CFBridgingRetain',
            # Reallocating the same size is UAF-adjacent (double-use)
            'malloc', 'calloc',
            # Port/kernel ops that dereference object ptr
            'IOServiceOpen', 'IOConnectCallMethod',
        ),
        barrier_substrings = (
            # If a new allocation is made and assigned to the same name,
            # the freed pointer should have been overwritten — soft barrier.
            # We cannot detect NULL-assignment (it's a MOV not a call).
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Heap object freed via free()/CFRelease()/dispatch_release() and then used on '
            'the same intra-function call path. After the deallocation, the freed pointer '
            'register and any struct fields loaded through it are marked tainted. A '
            'subsequent call that receives a tainted value as an argument is a potential '
            'use-after-free. Note: the framework cannot detect explicit NULL-assignment '
            'after free() (that is a MOV, not a call), so false positives are possible '
            'when the freed pointer is immediately zeroed. Requires manual confirmation '
            'that source and sink reference the same pointer.'
        ),
        confidence         = 0.62,
        output_args        = (0,),   # arg0 of free() is the freed ptr — mark its memory
        require_vex        = True,   # capstone can't track which pointer arg was freed
    ),

    VulnTemplate(
        name               = 'ARGV_GLOBAL_WRITE',
        source_substrings  = (
            # CLI option / environment sources — setuid/privileged binary class
            'getopt', 'getopt_long', 'getsubopt',
            # Direct argv / environ access shows as these helpers:
            'atoi', 'atol', 'atoll', 'atof',
            'strtol', 'strtoul', 'strtoll', 'strtoull', 'strtod',
            # Also: getenv() for environment variable injection
            'getenv',
        ),
        sink_substrings    = (
            # Fixed-size buffer write operations — target: BSS/stack globals
            'memcpy', 'memmove', 'bcopy',
            'strcpy', 'strncpy', 'strlcpy',
            'sprintf', 'snprintf',
            'strcat', 'strncat', 'strlcat',
            # Raw writes into fixed buffers
            'write',
        ),
        barrier_substrings = (
            # Explicit bounds-check helper calls only.  Note: strlcpy/snprintf
            # are intentionally NOT listed here — they are write operations that
            # appear in sink_substrings and their presence on a SIBLING path
            # (off-path barrier) would incorrectly suppress real findings via
            # the off-path reachability check.  Only pure guard functions belong.
            'fitsInRange', 'boundsCheck', 'bounds_check',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Attacker-controlled value from getopt/getenv/argv reaches a fixed-size '
            'buffer write (memcpy, strcpy, strncpy, sprintf) without a visible length '
            'cap on the call path. Covers the PING-01 class: setuid/privileged binaries '
            'where a CLI option supplies a count or size that is written into a '
            'statically declared BSS or stack buffer without bounds checking. '
            'High-value when the binary is setuid root or runs as a system daemon. '
            'Requires manual confirmation of buffer size vs attacker-supplied value range.'
        ),
        confidence         = 0.67,
    ),

    # ── Wrapper allocator templates (framework-specific patterns) ────────────────
    # These catch allocation patterns hidden behind framework APIs, enabling
    # C3 to detect memory safety issues in daemons using non-stdlib allocators.

    VulnTemplate(
        name               = 'MDNS_SIZE_ALLOC',
        source_substrings  = (
            'mDNSPlatformMemAllocate',  # mDNS custom allocator
            'GetLargeResourceRecord', 'GetRRSet',  # mDNS data structure sizes
            'rdlen',  # Resource record length (mDNS DNS packet parsing)
        ),
        sink_substrings    = (
            'memcpy', 'memmove', 'bcopy',  # Direct memory operations on allocated data
            'malloc', 'calloc', 'realloc',  # Subsequent allocation based on parsed size
            'CFDataCreateWithBytesNoCopy',  # CoreFoundation wrapper on mDNS data
        ),
        barrier_substrings = (
            'mDNSCoreValidate', 'CheckRRValidity',  # mDNS validation helpers
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'mDNS resource record size (rdlen or similar) from network data reaches '
            'memory allocation or copy without validation. mDNSResponder parses untrusted '
            'DNS packets; if rdlen or derived size is not validated against packet boundary, '
            'OOB read/write possible. Covers CVE patterns in mDNSResponder.'
        ),
        confidence         = 0.70,
    ),

    VulnTemplate(
        name               = 'CPP_NEW_SIZE_ALLOC',
        source_substrings  = (
            'operator new',  # C++ new operator (mangled: _Zn*)
            'new ',  # Direct new syntax (may appear in disasm as call to new)
            'std::vector', 'std::string',  # STL container operations that allocate
        ),
        sink_substrings    = (
            'memcpy', 'memmove', 'bcopy', 'std::copy',
            'malloc', 'calloc',  # underlying malloc calls from new
            '__cpp_sized_deallocate',  # Deallocate with size (UAF pattern)
        ),
        barrier_substrings = (),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'C++ new operator or STL container allocation reaches memory operation. '
            'C++ runtime allocation hidden from C3 by operator new mangling; if tainted '
            'size flows to new/std::vector, integer overflow or allocation size mismatch '
            'possible. Covers C++ daemons (IOKit services, XPC servers).'
        ),
        confidence         = 0.68,
    ),

    VulnTemplate(
        name               = 'CF_DATA_ALLOC',
        source_substrings  = (
            'CFDataCreateWithBytesNoCopy', 'CFDataCreateMutable', 'CFDataCreateCopy',
            'CFDataGetLength', 'CFDataGetBytePtr',  # Size/pointer accessors
            'CFDataAppendBytes',  # Length parameter
        ),
        sink_substrings    = (
            'memcpy', 'memmove', 'bcopy',
            'CFDataSetLength',  # Resizing with untrusted length
            'malloc', 'calloc', 'realloc',
            'CFRetain', 'CFRelease',  # UAF on CF objects
        ),
        barrier_substrings = (
            'CFDataGetLength', 'CFDataGetMaxLength',  # Length guards
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'CoreFoundation CFData allocation or length manipulation with untrusted size. '
            'If CFDataCreateMutable(size) receives attacker-controlled size, or '
            'CFDataSetLength/CFDataAppendBytes uses untrusted length without validation, '
            'OOB write possible. High-value in Objective-C daemons and system services.'
        ),
        confidence         = 0.70,
    ),

    VulnTemplate(
        name               = 'GCD_DATA_ALLOC',
        source_substrings  = (
            'dispatch_data_create', 'dispatch_data_create_concat',
            'dispatch_data_get_size',  # Size accessor
            'dispatch_data_apply',  # Iteration with untrusted bounds
        ),
        sink_substrings    = (
            'memcpy', 'memmove', 'bcopy',
            'malloc', 'calloc',  # Size reaching allocator
            'dispatch_release', 'dispatch_retain',  # UAF pattern
        ),
        barrier_substrings = (),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Grand Central Dispatch (GCD) data allocation with untrusted size. '
            'dispatch_data_create(buf, size) if size is from untrusted source, '
            'or dispatch_data_apply iteration over untrusted bounds, can cause OOB. '
            'Common in async I/O handlers and system services.'
        ),
        confidence         = 0.67,
    ),

    # ── Explicit Use-After-Free (UAF) patterns ────────────────────────────────────

    VulnTemplate(
        name               = 'UAF_REALLOC_REUSE',
        source_substrings  = (
            # Deallocations: after these, the pointer is invalid
            'free', 'CFRelease', 'dispatch_release',
            'objc_release', 'os_release',
            'IOObjectRelease',
            # Then reallocation attempts to "recover"
            'malloc', 'calloc', 'realloc',
        ),
        sink_substrings    = (
            # But the old pointer is used before or without proper re-assignment:
            # Reading from old pointer after free + realloc (different sizes)
            'memcpy', 'memmove', 'bcopy',
            'strlen', 'strnlen',  # Length operations on freed memory
            'CFGetTypeID', 'CFGetRetainCount',  # Object introspection on freed memory
            # Or the reallocated block is used with old size
            'memset', 'read', 'write', 'send', 'recv',
        ),
        barrier_substrings = (
            # Reassignment to allocated block (implicit barrier, but hard to detect)
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Pointer deallocated (free/CFRelease/etc.) and then reused. Unlike the '
            'UAF_STORE_FREE pattern which catches immediate use-after-free on the freed '
            'pointer, this pattern detects when a reallocation attempt (malloc/calloc) '
            'tries to "recover" the block but the code uses the old pointer size or '
            'structure. Typical AirPlayXPCHelper pattern: allocate ObjC object → free → '
            'realloc new object → use old pointer to access freed memory. High confidence '
            'on AirPlayXPCHelper (CVE-2025-24137 class UAF).'
        ),
        confidence         = 0.75,
        output_args        = (0,),  # realloc arg0 is the reused pointer
        require_vex        = True,  # capstone can't track pointer identity through realloc
    ),

    VulnTemplate(
        name               = 'CAST_NO_CHECK',
        source_substrings  = (
            # Untrusted object/pointer sources
            'xpc_dictionary_get_value', 'xpc_array_get_value',
            'CFDictionaryGetValue', 'CFArrayGetValueAtIndex',
            'objc_msgSend', 'objc_msgSendSuper',  # Dynamic dispatch
            'malloc', 'calloc',  # Uninitialized memory
            'mach_msg',  # Message data (attacker-controlled)
            'recv', 'recvfrom', 'recvmsg',  # Network data
        ),
        sink_substrings    = (
            # CoreFoundation type-specific operations (caller must know the CF type)
            'CFNumberGetValue', 'CFStringGetLength', 'CFStringGetCStringPtr',
            'CFStringGetCharacters', 'CFArrayGetCount',
            'CFDataGetBytePtr', 'CFDataGetLength',
            # DER/ASN.1 decoder — parses raw bytes as structured data
            'ccder_decode', 'SecAsn1Decode',
            # ObjC type-specific property/method calls (NOT type-checkers)
            # Note: 'NSIs*' functions are TYPE CHECKS and go in sink_exclusions below
            # Note: 'NSStringFromClass' intentionally NOT here — it takes a Class object
            # (returned by objc_opt_class/object_getClass), not a typed CF value; using
            # it on a valid Class is safe and generates FPs on every ObjC super-dispatch.
            'NSNumberDecimalValue',
            # NOTE: CFArrayGetValueAtIndex intentionally NOT here — it is already
            # a source substring; having it as both source and sink creates
            # self-loop FPs whenever a function calls it twice.
            # NOTE: IOServiceGetMatchingService NOT here — it is a registry lookup
            # that takes a dict and returns a service handle, not a type-cast op.
        ),
        sink_exclusions    = (
            # NSIsNS* functions are runtime type validators — they ARE the type check.
            # They contain 'NSString'/'NSNumber' substrings but must not be sinks.
            'NSIsNSString', 'NSIsNSNumber', 'NSIsNSArray', 'NSIsNSDictionary',
            'NSIsNSData', 'NSIsNSDate', 'NSIsNSOrderedSet', 'NSIsNSSet',
            # ObjC class/metaclass symbols that match 'class' substring
            'OBJC_CLASS_$', 'OBJC_METACLASS_$',
            # C++ standard library
            'std::',
        ),
        barrier_substrings = (
            # Type validation before cast — these functions confirm the type is safe
            'CFGetTypeID', 'CFNumberGetTypeID', 'CFStringGetTypeID',
            'CFArrayGetTypeID', 'CFDataGetTypeID', 'CFDictionaryGetTypeID',
            'xpc_get_type',       # XPC type guard
            'isKindOf',           # ObjC type checks (matches isKindOfClass)
            'NSIsNSString', 'NSIsNSNumber', 'NSIsNSArray', 'NSIsNSDictionary',
            'dynamic_cast',       # C++ safe cast
            'objc_opt_isKindOfClass',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.XTYPE,
        description        = (
            'Untrusted object cast to a specific type without runtime type validation. '
            'Attacker-controlled data (XPC dict, mach message, network packet) is cast '
            'to a concrete struct or ObjC class without calling CFGetTypeID(), xpc_get_type(), '
            'or isinstance(). If the attacker sends a different type, struct member/method '
            'calls on the mistyped object cause type confusion. Covers AirPlayXPCHelper '
            'CVE-2025-24129 (TYPE_CONFUSION in message parsing).'
        ),
        confidence         = 0.78,
    ),

    VulnTemplate(
        name               = 'DOUBLE_FREE',
        source_substrings  = (
            # Deallocation function calls
            'free', 'CFRelease', 'dispatch_release',
            'objc_release', 'os_release',
            'IOObjectRelease',
        ),
        sink_substrings    = (
            # Same deallocation function called again on the same path
            'free', 'CFRelease', 'dispatch_release',
            'objc_release', 'os_release',
            'IOObjectRelease',
        ),
        barrier_substrings = (
            # NULL assignment between frees (hard to detect symbolically)
            # Reassignment / reuse barrier (implicit)
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Same pointer deallocated twice on the same call path. Double-free is a '
            'critical memory safety bug: the heap allocator corrupts its metadata when '
            'the same block is freed twice, enabling arbitrary write/code execution. '
            'Pattern: free(ptr); [...] free(ptr); or CFRelease(obj); CFRelease(obj). '
            'Framework-agnostic: detects double-free across malloc/CFRelease/dispatch_release '
            'family. High-value finding with direct exploitability.'
        ),
        confidence         = 0.85,
        require_vex        = True,   # capstone can't verify same pointer freed twice
    ),

    # ── Swift runtime templates ─────────────────────────────────────────────────
    # Swift binaries use a different allocator / RC family.  These templates
    # mirror the C/ObjC patterns but target the Swift runtime ABI symbols that
    # appear as undefined imports in arm64e Mach-O slices.

    VulnTemplate(
        name               = 'SWIFT_OOB_ALLOC',
        source_substrings  = (
            # XPC / IPC data sources (same as C templates — XPC API is C even
            # from Swift)
            'xpc_dictionary_get_value', 'xpc_array_get_value',
            'xpc_data_get_length', 'xpc_uint64_get_value', 'xpc_int64_get_value',
            'xpc_array_get_count',
            # Network sources
            'recv', 'recvfrom', 'recvmsg', 'read',
            'ntohl', 'ntohs', 'ntohll',
            # Mach
            'mach_msg',
        ),
        sink_substrings    = (
            # Swift runtime heap allocator — appears as PLT stub
            'swift_allocObject',
            'swift_slowAlloc',
            'swift_bufferAllocate',
            'swift_bufferAllocateOnStack',
            # If size flows into a standard allocator through Swift bridging:
            'malloc', 'calloc', 'realloc',
            # Swift Array / Data buffer growth
            '_swift_arrayInitWithCopy',
            '_swift_arrayForceCast',
            'withUnsafeMutableBufferPointer',
        ),
        barrier_substrings = (
            # Swift standard library bounds guards (mangled names visible in PLT)
            '_swift_stdlib_reportRangeOverflow',
            '_swift_stdlib_reportOverflow',
            # os_mul_overflow / checked arithmetic
            'os_add_overflow', 'os_mul_overflow',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Attacker-controlled XPC/IPC/network integer reaches swift_allocObject or '
            'a standard allocator called from Swift code without visible overflow/bounds '
            'check on the call path. Swift Array and Data types resize their backing '
            'buffers via swift_allocObject; if the element count is attacker-controlled '
            'and not range-checked, the backing buffer is underallocated and subsequent '
            'writes past the end corrupt heap metadata.'
        ),
        confidence         = 0.71,
    ),

    VulnTemplate(
        name               = 'SWIFT_UAF',
        source_substrings  = (
            # Swift reference-count release — object may be destroyed
            'swift_release',
            'swift_bridgeObjectRelease',
            'swift_unknownObjectRelease',
            '_swift_release_dealloc',
            # ARC-bridged ObjC release
            'objc_release',
            'CFRelease',
        ),
        sink_substrings    = (
            # Method dispatch on the freed object — genuine UAF if same object
            'objc_msgSend',
            # Memory operations directly on the freed buffer
            'memcpy', 'memmove', 'memset',
            # Swift unowned-reference check — exact UAF pattern: unowned refs
            # bypass ARC safety; swift_unownedCheck on a freed object is a
            # real UAF (crashes with EXC_BAD_ACCESS in debug, silent in release).
            'swift_unownedCheck',
            'swift_unownedRetain',
            # NOTE: swift_retain / swift_allocObject / malloc intentionally
            # EXCLUDED: retaining a *new* object or allocating *new* memory after
            # releasing an *old* object is normal Swift ARC and generates massive
            # false positives (every release→alloc in a Swift function matches).
        ),
        barrier_substrings = (
            # No barriers: Swift nil-checks are branch-based, not call-based.
            # A nil check will show as a conditional branch in the CFG (edge not
            # taken → no path to sink) so the engine handles it structurally.
        ),
        sink_exclusions    = (
            # Exclude cleanup/logging functions that legitimately follow release
            'os_log', 'NSLog', 'printf',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Swift/ObjC object released and then used via objc_msgSend or memory '
            'operation on the same intra-function call path without an intervening '
            'retain. NOTE: high FP rate unless pointer-identity is confirmed via '
            'manual triage — this template cannot track that source and sink operate '
            'on the same register without VEX taint-propagation across the full CFG.'
        ),
        confidence         = 0.73,
        require_vex        = True,
    ),

    VulnTemplate(
        name               = 'SWIFT_TYPE_CONFUSION',
        source_substrings  = (
            # Force/unconditional Swift casts — these NEVER check the cast succeeded.
            # Swift 'as!' emits swift_dynamicCast with an unconditional flag (trap on fail).
            # unsafeBitCast is always unconditional.
            'swift_dynamicCast',
            'swift_dynamicCastClass',
            'swift_dynamicCastObjCClass',
            'swift_dynamicCastUnknownClass',
            # Untyped XPC/IPC data bridged into Swift — caller must check the type
            'xpc_dictionary_get_value', 'xpc_array_get_value',
            # Unsafe pointer construction
            'withUnsafePointer',
            'unsafeBitCast',
            # NOTE: 'objc_msgSend' intentionally NOT here — ObjC dynamic dispatch is NOT
            # type confusion. Adding it generates massive FPs on any ObjC super dispatch
            # or normal method call chain (confirmed: promotedcontentd, locationd FPs).
        ),
        sink_substrings    = (
            # Protocol method dispatch on the (potentially wrong) type
            'swift_conformsToProtocol',
            'swift_getObjectType',
            # Unsafe pointer dereference after cast
            'memcpy', 'memmove',
            # NOTE: 'objc_msgSend' intentionally NOT here — calling any ObjC method after
            # an innocent msgSend creates spurious source→sink edges (confirmed FPs in
            # promotedcontentd and locationd runs). The real signal requires a force cast
            # (source) feeding a type-specific field access or memory operation (sink).
        ),
        barrier_substrings = (
            # Safe cast guard — Swift 'as?' emits swift_dynamicCast and branches on nil
            # If swift_dynamicCast appears as a barrier it means the guard IS present
            'swift_dynamicCastClass',
            'swift_dynamicCastObjCClass',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.XTYPE,
        description        = (
            'Swift type cast (swift_dynamicCast / unsafeBitCast) result used without '
            'checking the cast succeeded. In Swift, "as!" force-cast emits no guard '
            'branch — a wrong runtime type crashes. In bridged XPC handlers, an '
            'attacker-supplied XPC value bridged to a typed Swift object without a '
            'type check enables type confusion leading to memory corruption on field '
            'access. unsafeBitCast is unconditional and never safe on attacker data.'
        ),
        confidence         = 0.76,
    ),

    VulnTemplate(
        name               = 'SWIFT_UNMANAGED_BUFFER',
        source_substrings  = (
            # UnsafeRawPointer / UnsafeMutableRawPointer construction from network/XPC
            'xpc_data_get_bytes_ptr', 'xpc_string_get_string_ptr',
            'CFDataGetBytePtr',
            'recv', 'recvfrom', 'read',
            # Swift bridging to raw bytes
            'withUnsafeBytes',
            'withUnsafeMutableBytes',
            '_swift_stdlib_memcpy',
        ),
        sink_substrings    = (
            # Raw memory writes through unmanaged pointer
            'memcpy', 'memmove', 'bcopy', 'memset',
            '_swift_stdlib_memcpy',
            'strlcpy', 'strcpy', 'strncpy',
            # Writes via UnsafeRawPointer.storeBytes — shows as PLT stub
            'storeBytes',
            # XPC reply with raw bytes — info disclosure if over-read
            'xpc_data_create',
        ),
        barrier_substrings = (
            # Length cap check
            'xpc_data_get_length',
            'CFDataGetLength',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Raw byte pointer from XPC/network data used in an unsafe memory write '
            'without a visible length check. Swift UnsafeRawPointer / '
            'withUnsafeBytes closures bypass Swift\'s memory safety guarantees; if '
            'the destination buffer is fixed-size and the source length is not '
            'validated, OOB write is possible. Also covers info-disclosure via '
            'xpc_data_create(ptr, n) where n is not bounded by the actual buffer size.'
        ),
        confidence         = 0.74,
    ),

    # ── XPC / Swift deserialization boundary ─────────────────────────────────
    VulnTemplate(
        name               = 'XPC_DESERIALISE_SWIFT',
        source_substrings  = (
            # XPC dictionary / array getters — direct attacker-controlled data
            'xpc_dictionary_get_data',
            'xpc_dictionary_get_string',
            'xpc_dictionary_get_value',
            'xpc_array_get_value',
            'xpc_array_get_data',
            # NSKeyedUnarchiver / NSCoder decode paths
            'decodeObjectForKey',
            'decodeObjectOfClass',
            'decodeDataObject',
            'unarchiveObjectWithData',
            'unarchivedObjectOfClass',
            # Swift Codable decode entry points (mangled prefixes)
            'init(from',          # matches Swift Codable init(from:) demangle
            'decode(type',        # matches decode(type:forKey:)
            # Low-level XPC connection input
            'xpc_connection_recv',
        ),
        sink_substrings    = (
            # C-level memory operations — where Swift hands off to unsafe land
            'memcpy', 'memmove', 'memset', 'bcopy',
            # Unsafe heap alloc with attacker-controlled size
            'malloc', 'calloc', 'realloc',
            # Swift unsafe pointer APIs (appear as stdlib symbols)
            'withUnsafeMutableBytes',
            'withUnsafeBytes',
            'assumingMemoryBound',
            'storeBytes',
            'copyBytes',
            # CF buffer operations
            'CFDataGetBytePtr',
            'CFStringGetCStringPtr',
            # XPC reply that may expose internal memory
            'xpc_data_create',
        ),
        barrier_substrings = (
            # Explicit length checks before the unsafe op
            'xpc_data_get_length',
            'CFDataGetLength',
            'checkBounds',
            'boundsCheck',
        ),
        source_exclusions  = (),
        sink_exclusions    = (
            'create_zone', 'set_zone_name',
            'OBJC_CLASS_$', 'OBJC_METACLASS_$',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.OOB,
        description        = (
            'Attacker-controlled data from an XPC/Codable deserialization boundary '
            'reaches an unsafe memory operation without a visible bounds check. '
            'Swift XPC daemons frequently bridge decoded data to C APIs using '
            'withUnsafeBytes / withUnsafeMutableBytes; if the length from the XPC '
            'dictionary is used directly as an allocation size or copy count without '
            'validation, OOB read or write is possible even in otherwise-safe Swift code.'
        ),
        confidence         = 0.72,
    ),

    # ── Unmanaged<T> / manual retain-release across ARC boundary ─────────────
    VulnTemplate(
        name               = 'ARC_BRIDGE_UAF',
        source_substrings  = (
            # Swift Unmanaged: explicit retain/release without ARC
            'passUnretained',
            'takeUnretainedValue',
            'takeRetainedValue',
            # ObjC manual bridge casts that bypass ARC
            '__bridge_transfer',
            '__bridge_retained',
            # CFBridge
            'CFBridgingRelease',
            'CFBridgingRetain',
        ),
        sink_substrings    = (
            # Using the object after potential release
            'objc_msgSend',
            'objc_retain',
            'swift_retain',
            'swift_bridgeObjectRetain',
            # Memory operations on the bridged buffer
            'memcpy', 'memmove',
            'CFDataGetBytePtr',
            'CFStringGetCStringPtr',
        ),
        barrier_substrings = (
            # Explicit lifetime extension
            'withExtendedLifetime',
        ),
        source_exclusions  = (),
        sink_exclusions    = (
            'create_zone', 'OBJC_CLASS_$',
        ),
        sink_arg           = -1,
        vuln_class         = TemplateVulnClass.UAF,
        description        = (
            'Manual ARC bridge (Unmanaged<T> or __bridge_transfer) creates a '
            'window where an object may be released on one side of the Swift/ObjC '
            'boundary while a raw pointer to it remains live on the other side. '
            'If the released object\'s memory is then used (objc_msgSend, memcpy, '
            'CFData access) before ARC can reclaim it safely, a use-after-free '
            'or type-confusion bug is possible.'
        ),
        confidence         = 0.68,
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
    # True when this record came from the capstone CFG fallback rather than
    # VEX IR analysis.  The fallback sets tainted_args = {0..7} conservatively
    # and cannot track pointer identity; templates with require_vex=True skip
    # matches that originate entirely from capstone records.
    from_capstone: bool = False


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


# ── arm64e PLT map and function boundary helpers ───────────────────────────────

def build_plt_map(binary_path: str) -> 'dict[int, str]':
    """
    Build a {stub_va → symbol_name} map for arm64e Mach-O binaries.

    arm64e uses __auth_stubs (16-byte: ADRP+ADD/LDR+…+BRAA) and __auth_got
    instead of the traditional __stubs + __got.  CLE 9.x does not resolve
    these stubs so _resolve_callee() returns 'sub_0xXXX' for every PLT call.

    Algorithm
    ---------
    1. Parse __auth_got: each 8-byte entry has bit[62]=1 (bind) with
       bits[23:0] giving the import ordinal.  Build got_va → symbol_name
       from macho.imported_symbols (ordinal-indexed).
    2. Disassemble __auth_stubs 16 bytes at a time (ADRP + ADD/LDR + ...):
       stub_va → got_va (via ADRP page + ADD/LDR displacement) → symbol_name.

    Returns empty dict if lief/capstone unavailable or binary not arm64e.
    """
    if not _LIEF_CAPSTONE_OK:
        return {}
    try:
        return _build_plt_map_impl(binary_path)
    except Exception as e:
        log.debug('build_plt_map: failed for %s: %s', binary_path, e)
        return {}


def _build_plt_map_impl(binary_path: str) -> 'dict[int, str]':
    fat = _lief.MachO.parse(binary_path)
    if fat is None:
        return {}

    # Select arm64 / arm64e slice
    ARM64 = _lief.MachO.Header.CPU_TYPE.ARM64
    macho = next((b for b in fat if b.header.cpu_type == ARM64), None)
    if macho is None:
        return {}

    # Build GOT VA → symbol name.
    #
    # Preferred path (arm64e chained fixups): use dyld_chained_fixups.bindings
    # which gives binding.address (absolute GOT VA) → binding.symbol.name.
    # This is correct because chained fixup ordinals are indices into the
    # per-binary imports table, NOT into lief's imported_symbols list (which
    # is ordered differently and causes name corruption for LOCAL stubs).
    #
    # Fallback path (older LC_DYLD_INFO binaries): reconstruct from __auth_got
    # raw entries using imported_symbols enumeration (imprecise but often OK).
    got_va_to_name: dict[int, str] = {}

    try:
        if getattr(macho, 'has_dyld_chained_fixups', False):
            cf = macho.dyld_chained_fixups
            for binding in cf.bindings:
                if binding.has_symbol and binding.symbol and binding.address:
                    got_va_to_name[binding.address] = binding.symbol.name.lstrip('_')
    except Exception:
        pass

    if not got_va_to_name:
        # Fallback: ordinal-indexed approach for LC_DYLD_INFO binaries
        try:
            ord_to_name: dict[int, str] = {}
            for i, sym in enumerate(macho.imported_symbols):
                ord_to_name[i] = sym.name.lstrip('_')
            auth_got = macho.get_section('__auth_got')
            if auth_got and ord_to_name:
                auth_got_va   = auth_got.virtual_address
                auth_got_data = bytes(auth_got.content)
                for i in range(len(auth_got_data) // 8):
                    (val,) = struct.unpack_from('<Q', auth_got_data, i * 8)
                    if (val >> 62) & 1:          # bind bit
                        ordinal = val & 0xFFFFFF
                        if ordinal in ord_to_name:
                            got_va_to_name[auth_got_va + i * 8] = ord_to_name[ordinal]
        except Exception:
            pass

    if not got_va_to_name:
        return {}

    # Disassemble __auth_stubs (16-byte: ADRP + ADD/LDR + ... + BRAA)
    auth_stubs = macho.get_section('__auth_stubs')
    if not auth_stubs:
        return {}

    stub_data = bytes(auth_stubs.content)
    stub_base = auth_stubs.virtual_address

    md = _capstone.Cs(_capstone.CS_ARCH_ARM64, _capstone.CS_MODE_ARM)
    md.detail = True

    plt_map: dict[int, str] = {}
    for i in range(0, len(stub_data), 16):
        chunk = stub_data[i:i + 16]
        va    = stub_base + i
        insns = list(md.disasm(chunk, va))
        if len(insns) < 2 or insns[0].mnemonic != 'adrp':
            continue
        adrp_page = insns[0].operands[1].imm
        insn1 = insns[1]
        if insn1.mnemonic == 'add' and len(insn1.operands) >= 3:
            got_va = adrp_page + insn1.operands[2].imm
        elif insn1.mnemonic == 'ldr' and len(insn1.operands) >= 2:
            got_va = adrp_page + insn1.operands[1].mem.disp
        else:
            continue
        if got_va in got_va_to_name:
            plt_map[va] = got_va_to_name[got_va]

    log.debug('build_plt_map: %s → %d stubs resolved', binary_path, len(plt_map))
    return plt_map


def build_func_boundaries(binary_path: str) -> 'dict[int, int]':
    """
    Build {func_start_va → func_end_va} from lief LC_FUNCTION_STARTS.

    Used by the capstone block-recovery fallback: when angr CFGFast recovers
    only 1 block for a function (arm64e mDNSResponder pattern), we need the
    real function extent to disassemble the full body.

    Returns empty dict if lief unavailable or no function starts found.
    """
    if not _LIEF_CAPSTONE_OK:
        return {}
    try:
        return _build_func_boundaries_impl(binary_path)
    except Exception as e:
        log.debug('build_func_boundaries: failed: %s', e)
        return {}


def _build_func_boundaries_impl(binary_path: str) -> 'dict[int, int]':
    fat = _lief.MachO.parse(binary_path)
    if fat is None:
        return {}
    ARM64 = _lief.MachO.Header.CPU_TYPE.ARM64
    macho = next((b for b in fat if b.header.cpu_type == ARM64), None)
    if macho is None:
        return {}

    # lief macho.functions returns addresses as offsets from the file base
    # (equivalent to VM addr - __TEXT.vmaddr + __TEXT.fileoff).
    # For typical macOS main executables __TEXT.fileoff == 0 so the raw
    # address equals the file offset. We must add __TEXT.vmaddr to get the
    # actual in-memory address that angr uses.
    text_base = 0
    for seg in macho.segments:
        if seg.name == '__TEXT':
            text_base = seg.virtual_address
            break

    raw_starts = [f.address for f in macho.functions if f.address > 0]
    if not raw_starts:
        return {}

    starts = sorted(va + text_base for va in raw_starts)

    boundaries: dict[int, int] = {}
    for i, va in enumerate(starts):
        end_va = starts[i + 1] if i + 1 < len(starts) else va + 0x20000
        boundaries[va] = end_va
    log.debug('build_func_boundaries: %s → %d functions (text_base=%#x)',
              binary_path, len(boundaries), text_base)
    return boundaries


def _extract_calls_capstone(
    proj:             'angr.Project',
    func_addr:        int,
    func_end:         int,
    plt_map:          'dict[int, str]',
    interesting_names: 'set[str]',
) -> 'tuple[list[CallRecord], nx.DiGraph]':
    """
    Capstone-based call extraction fallback with basic-block-aware CFG.

    For functions where angr CFGFast recovers fewer than 3 blocks (arm64e
    arm64e pattern), we disassemble the raw bytes with Capstone and build a
    proper control-flow graph:

      1. Full disassembly to find BB boundaries (branch targets, fall-throughs).
      2. Build BB CFG: {bb_start → [successor_bb_starts]}.
      3. Compute BB reachability with BFS from function entry.
      4. Emit CallRecord edges only between calls where the sink's BB is
         reachable from the source's BB in the CFG.

    This replaces the old flat sequential chain (every call → next call in
    text order) which caused false positives whenever a backward branch existed
    between the source call site and the sink call site.
    """
    if not _LIEF_CAPSTONE_OK:
        return [], nx.DiGraph()

    size = func_end - func_addr
    if size <= 0 or size > 0x80000:
        return [], nx.DiGraph()

    try:
        raw = bytes(proj.loader.memory.load(func_addr, size))
    except Exception:
        return [], nx.DiGraph()

    md = _capstone.Cs(_capstone.CS_ARCH_ARM64, _capstone.CS_MODE_ARM)
    md.detail = True

    insns = list(md.disasm(raw, func_addr))
    if not insns:
        return [], nx.DiGraph()

    # ── ARM64 branch mnemonic classification ─────────────────────────────
    # Terminators: instructions that end a basic block.
    # BL/BLR are CALLS (not terminators) — execution continues after return.
    _UNCOND   = frozenset({'b', 'br', 'braa', 'braaz', 'brab', 'brabz',
                           'ret', 'retab', 'retaab', 'retaasppc'})
    _COND_BR  = frozenset({'cbz', 'cbnz', 'tbz', 'tbnz'})
    _RETURNS  = frozenset({'ret', 'retab', 'retaab', 'retaasppc'})
    _IND_JUMP = frozenset({'br', 'braa', 'braaz', 'brab', 'brabz'})

    def _is_terminator(mnem: str) -> bool:
        return (mnem in _UNCOND or mnem in _COND_BR
                or mnem.startswith('b.'))

    def _is_call(mnem: str) -> bool:
        return mnem in ('bl', 'blr', 'blraa', 'blraaz', 'blrab', 'blrabz')

    # ── Phase 1: collect BB start addresses ──────────────────────────────
    bb_starts: set[int] = {func_addr}

    for insn in insns:
        if not _is_terminator(insn.mnemonic):
            continue
        # Unconditional forward/backward branches: target starts new BB
        if insn.mnemonic not in _RETURNS and insn.mnemonic not in _IND_JUMP:
            if insn.operands:
                try:
                    tgt = insn.operands[0].imm
                    if func_addr <= tgt < func_end:
                        bb_starts.add(tgt)
                except (IndexError, AttributeError):
                    pass
        # Fall-through after conditional branches (not after unconditionals)
        if insn.mnemonic not in _UNCOND:
            ft = insn.address + insn.size
            if func_addr <= ft < func_end:
                bb_starts.add(ft)

    sorted_starts: list[int] = sorted(bb_starts)

    # ── Phase 2: assign each instruction to a BB ─────────────────────────
    # bisect_right gives index of first start > addr; subtract 1 for owner BB
    def _bb_of(addr: int) -> int:
        idx = bisect.bisect_right(sorted_starts, addr) - 1
        return sorted_starts[idx] if idx >= 0 else func_addr

    # ── Phase 3: build BB call list and successor map ─────────────────────
    # {bb_start: [(call_va, callee_addr, callee_name)]}
    bb_calls: dict[int, list] = {s: [] for s in sorted_starts}
    # {bb_start: set[successor_bb_start]}  — populated at terminators
    bb_succs: dict[int, set[int]] = {s: set() for s in sorted_starts}
    # Track whether each BB has had its successors explicitly set
    bb_terminated: set[int] = set()

    for insn in insns:
        bb_va = _bb_of(insn.address)
        mnem  = insn.mnemonic

        if _is_call(mnem):
            callee_addr = 0
            if mnem == 'bl' and insn.operands:
                try:
                    callee_addr = insn.operands[0].imm
                except (IndexError, AttributeError):
                    pass
            if callee_addr and callee_addr in plt_map:
                callee_name = plt_map[callee_addr]
            elif callee_addr:
                callee_name = _resolve_callee(proj, callee_addr)
            else:
                callee_name = 'unknown'
            if (callee_name and callee_name != 'unknown'
                    and not callee_name.startswith('sub_')
                    and any(sub in callee_name for sub in interesting_names)):
                bb_calls[bb_va].append((insn.address, callee_addr, callee_name))

        if _is_terminator(mnem):
            bb_terminated.add(bb_va)
            if mnem in _RETURNS or mnem in _IND_JUMP:
                pass  # no known successors
            else:
                if mnem not in _UNCOND:
                    # Conditional: fall-through is a successor
                    ft = insn.address + insn.size
                    if ft in bb_starts:
                        bb_succs[bb_va].add(ft)
                if insn.operands:
                    try:
                        tgt = insn.operands[0].imm
                        if tgt in bb_starts:
                            bb_succs[bb_va].add(tgt)
                    except (IndexError, AttributeError):
                        pass

    # For BBs that end with a non-terminator (e.g. end of a call-only block):
    # add implicit fall-through to next BB if it exists.
    for i, bb_va in enumerate(sorted_starts):
        if bb_va not in bb_terminated and i + 1 < len(sorted_starts):
            bb_succs[bb_va].add(sorted_starts[i + 1])

    # ── Phase 4: BFS reachability from function entry ─────────────────────
    reachable_bbs: set[int] = set()
    queue: list[int] = [func_addr]
    while queue:
        bb = queue.pop()
        if bb in reachable_bbs:
            continue
        reachable_bbs.add(bb)
        queue.extend(bb_succs.get(bb, ()))

    # ── Phase 5: per-BB reachability (for edge building) ─────────────────
    def _bbs_reachable_from(start: int) -> set[int]:
        visited: set[int] = set()
        q: list[int] = [start]
        while q:
            b = q.pop()
            if b in visited:
                continue
            visited.add(b)
            q.extend(bb_succs.get(b, ()))
        return visited

    # ── Phase 6: collect calls in CFG order, build CG ────────────────────
    # Ordered: (bb_va, call_va, callee_addr, callee_name)
    all_calls: list[tuple[int, int, int, str]] = [
        (bb_va, cva, caddr, cname)
        for bb_va in sorted_starts
        if bb_va in reachable_bbs
        for cva, caddr, cname in bb_calls[bb_va]
    ]

    if not all_calls:
        return [], nx.DiGraph()

    records:   list[CallRecord] = []
    labels:    list[str]        = []
    call_bbs:  list[int]        = []
    cg = nx.DiGraph()

    for idx, (bb_va, cva, caddr, cname) in enumerate(all_calls):
        label = f'{cname}@{cva:#x}'
        rec   = CallRecord(
            call_site     = cva,
            callee_addr   = caddr,
            callee_name   = cname,
            tainted_args  = {0, 1, 2, 3, 4, 5, 6, 7},
            seq_idx       = idx,
            from_capstone = True,
        )
        records.append(rec)
        labels.append(label)
        call_bbs.append(bb_va)
        cg.add_node(label, rec=rec)

    # Add edges: source call A → sink call B iff
    #   (a) same BB and B is later in text, OR
    #   (b) B's BB is in the reachable set of A's BB (and different BB).
    bb_reach_cache: dict[int, set[int]] = {}
    for i, (bb_i, lbl_i) in enumerate(zip(call_bbs, labels)):
        if bb_i not in bb_reach_cache:
            bb_reach_cache[bb_i] = _bbs_reachable_from(bb_i)
        reach_i = bb_reach_cache[bb_i]
        for j, (bb_j, lbl_j) in enumerate(zip(call_bbs, labels)):
            if i == j:
                continue
            if bb_i == bb_j and all_calls[j][1] > all_calls[i][1]:
                cg.add_edge(lbl_i, lbl_j)
            elif bb_i != bb_j and bb_j in reach_i:
                cg.add_edge(lbl_i, lbl_j)

    return records, cg


# ── Intra-function call dataflow extraction ────────────────────────────────────

def _resolve_callee(
    proj:        angr.Project,
    callee_addr: int,
    plt_map:     'dict[int, str] | None' = None,
) -> str:
    """Return a human-readable name for a callee address."""
    # arm64e PLT stub map (highest priority — CLE does not resolve auth_stubs)
    if plt_map and callee_addr in plt_map:
        return plt_map[callee_addr]
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
    proj:              angr.Project,
    func:              angr.knowledge_plugins.Function,
    interesting_names: 'set[str]',
    output_arg_map:    'dict[str, tuple[int, ...]] | None' = None,
    plt_map:           'dict[int, str] | None'             = None,
    func_boundaries:   'dict[int, int] | None'             = None,
) -> 'tuple[list[CallRecord], nx.DiGraph]':
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
    plt_map          : {stub_va → symbol_name} built by build_plt_map().
                       Passed to _resolve_callee() so arm64e __auth_stubs are
                       resolved (CLE 9.x leaves them as 'sub_0xXXX').
    func_boundaries  : {func_start_va → func_end_va} built by build_func_boundaries().
                       Enables the capstone block-recovery fallback when angr
                       CFGFast recovers fewer than 3 blocks (arm64e pattern).

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

            callee_name = _resolve_callee(proj, callee_addr, plt_map) if callee_addr else 'unknown'

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

    # ── Capstone fallback ────────────────────────────────────────────────────
    # When angr CFGFast recovers only 1–2 blocks for a function (arm64e
    # mDNSResponder pattern), the VEX-IR pass above sees almost nothing.
    # If we recovered fewer than 3 interesting calls AND we have both a
    # plt_map and func_boundaries, fall back to capstone disassembly of the
    # full function body.  This loses precise taint tracking (all args are
    # treated as tainted) but catches source→sink pairs that VEX missed.
    if len(calls) < 3 and plt_map and func_boundaries:
        func_addr = func.addr
        func_end  = func_boundaries.get(func_addr, 0)
        if func_end > func_addr:
            cs_calls, cs_cg = _extract_calls_capstone(
                proj, func_addr, func_end, plt_map, interesting_names
            )
            if len(cs_calls) > len(calls):
                log.debug(
                    'extract_call_dataflow: capstone fallback for %s@%#x '
                    '(%d VEX calls → %d capstone calls)',
                    func.name, func_addr, len(calls), len(cs_calls),
                )
                return cs_calls, cs_cg

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
        name = rec.callee_name
        if (any(_sub_in_name(sub, name) for sub in template.source_substrings)
                and not any(ex in name for ex in template.source_exclusions)):
            sources.append(node_label)
        if (any(_sub_in_name(sub, name) for sub in template.sink_substrings)
                and not any(ex in name for ex in template.sink_exclusions)):
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
        src_rec: CallRecord = cg.nodes[src]['rec']

        # All nodes reachable from src (the taint's "sphere of influence")
        src_reachable: set[str] = set(nx.descendants(cg, src)) | {src}

        for snk in sinks:
            if src == snk:
                continue
            snk_rec: CallRecord = cg.nodes[snk]['rec']

            # require_vex: skip if BOTH source and sink are from the capstone
            # fallback (all-args-tainted).  This prevents self-referential
            # templates (DOUBLE_FREE, UAF) from firing on every cleanup function
            # where two CFRelease calls appear — capstone can't verify they share
            # the same pointer.
            if (template.require_vex
                    and src_rec.from_capstone
                    and snk_rec.from_capstone):
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

        # arm64e PLT map: {stub_va → symbol_name}
        # Resolves __auth_stubs calls that CLE leaves as 'sub_0xXXX'.
        binary_path = getattr(project, 'filename', None) or ''
        self._plt_map:        dict[int, str] = build_plt_map(binary_path)
        self._func_boundaries: dict[int, int] = build_func_boundaries(binary_path)
        if self._plt_map:
            log.info('C3: arm64e PLT map loaded (%d stubs)', len(self._plt_map))
        if self._func_boundaries:
            log.info('C3: function boundaries loaded (%d functions)', len(self._func_boundaries))

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
                    output_arg_map  = self._output_arg_map or None,
                    plt_map         = self._plt_map or None,
                    func_boundaries = self._func_boundaries or None,
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

    def find_source_callers(
        self,
        extra_source_subs: 'tuple[str, ...] | None' = None,
        cap_per_source:    int = 200,
        max_total:         int = 0,
    ) -> set[int]:
        """
        Return the set of function start addresses that contain at least one
        direct call (BL instruction) to a template source function.

        This is a fast O(bytes) pre-filter that supplements the C2 top-N
        selection.  C2 ranks by cyclomatic complexity (algorithmic functions);
        this pass adds the XPC/IPC message-handler functions that have low
        complexity but high attack-surface relevance — e.g. functions that call
        xpc_dictionary_get_data, recv, mach_msg, IOConnectCallMethod.

        Parameters
        ----------
        extra_source_subs : additional source substrings to search for beyond
            the template bank (optional).
        cap_per_source : maximum functions to return per source substring,
            to avoid returning thousands of functions in a large binary.
        max_total : if > 0, stop collecting once this many functions have been
            found regardless of cap_per_source.  Useful to bound C3 analysis
            time on very large daemons (e.g. locationd has 3,900+ callers).

        Returns
        -------
        Set of function start addresses.  May include addresses not in
        func_boundaries (CLE-discovered functions) — callers pass these to
        analyse_functions which handles unknown addresses gracefully.
        """
        # Build the union of all source substrings from all templates
        source_subs: set[str] = set()
        for t in self.templates:
            source_subs.update(t.source_substrings)
        if extra_source_subs:
            source_subs.update(extra_source_subs)

        # Which PLT stubs are "source" stubs?
        source_stub_vas: set[int] = {
            va
            for va, name in self._plt_map.items()
            if any(s in name for s in source_subs)
        }
        if not source_stub_vas:
            log.debug('find_source_callers: no source stubs in PLT map, returning empty set')
            return set()

        log.debug('find_source_callers: %d source stubs from %d total PLT stubs',
                  len(source_stub_vas), len(self._plt_map))

        # Disassemble every function body looking for BL to a source stub.
        # Use the function boundaries from lief (faster than angr's kb.functions).
        try:
            import capstone as _cs
            md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)
            md.detail = True
        except ImportError:
            log.warning('find_source_callers: capstone not available')
            return set()

        # Use the global loader memory, not main_obj.memory.
        # main_obj may be a CLE Universal2 (fat binary container) which has no
        # .memory attribute — only the arch-specific sub-backend does.
        # proj.loader.memory (a flat Clemory) works for all binary types.
        loader_memory = self.proj.loader.memory
        result: set[int] = set()
        MAX_FUNC_BYTES = 256 * 1024   # skip pathological functions > 256 KB

        for func_start, func_end in self._func_boundaries.items():
            if max_total > 0 and len(result) >= max_total:
                log.debug('find_source_callers: hit max_total=%d, stopping early', max_total)
                break
            size = func_end - func_start
            if size <= 0 or size > MAX_FUNC_BYTES:
                continue
            try:
                func_bytes = loader_memory.load(func_start, size)
            except Exception:
                continue
            for insn in md.disasm(func_bytes, func_start):
                if insn.mnemonic == 'bl' and insn.operands:
                    try:
                        target = insn.operands[0].imm
                    except (IndexError, AttributeError):
                        continue
                    if target in source_stub_vas:
                        result.add(func_start)
                        break  # found in this function, move on

        log.debug('find_source_callers: found %d callers of source functions', len(result))
        return result

    def run(self) -> C3Result:
        """Run template matching on all non-stub functions."""
        return self.analyse_functions(func_addrs=None)
