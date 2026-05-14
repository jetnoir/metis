"""
objc_dispatch.py — C3/L3: Objective-C runtime dispatch resolution
=================================================================

Pre-analysis pass for Mach-O Objective-C binaries.  Resolves
``objc_msgSend(receiver, selector, ...)`` indirect calls to concrete
method implementations by parsing ObjC runtime metadata sections in the
binary, then inserting synthetic call edges into the C2 call graph and
providing an angr SimProcedure hook for C6 symbolic taint analysis.

Pipeline integration
--------------------
C2 (call graph):
    resolver = ObjCDispatchResolver(proj)
    result   = resolver.resolve()
    result.inject_into_callgraph(cg)   # patches nx.DiGraph in-place

C6 (symbolic execution):
    Hook_objcMsgSend is added to _HOOK_TABLE in c6_taint.py.
    At run time it reads x1 (SEL pointer), resolves to an IMP address,
    and jumps there — turning an opaque indirect call into a traceable
    execution path.

Algorithm
---------
1. Parse ``__objc_methnames`` section  → offset-keyed string table
2. Parse ``__objc_selrefs`` section    → (VA → selector_name) map
3. Invoke ``otool -arch arm64e -ov``   → (selector → IMP addr) map
   otool handles small-method relative format (macOS 12+) and PAC on our behalf.
4. Scan ``__TEXT,__text`` with capstone → all ``bl _objc_msgSend`` sites
5. For each call site: backward-scan the preceding instructions to find the
   ``adrp xN, PAGE; ldr x1, [xN, #off]`` pair that loads the selector
   reference — resolves to a selref VA → selector name → IMP address(es).
6. Unresolved sites are recorded but not connected (conservative — no false edges).

Supported architectures
-----------------------
- arm64 / arm64e (primary — adrp/ldr selref pattern)
- x86_64 (partial — sites located but selector resolution not yet implemented)

macOS method format support
---------------------------
- "Big" method_t (macOS <12, Xcode <13): absolute 64-bit SEL and IMP pointers
- "Small" method_t (macOS 12+, Xcode 13+): 32-bit relative offsets; handled
  by otool -ov, not by this module's direct parser

Author : Stuart Thomas
Date   : 2026-04-17
Licence: Apache 2.0
© 2026 Stuart Thomas, trading as TriageForge
"""

from __future__ import annotations

import logging
import re
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr
    import networkx as nx

log = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ObjCMethod:
    """One Objective-C method extracted from binary metadata."""
    class_name:      str
    selector:        str    # e.g. "handleXPCMessage:fromClient:"
    imp_addr:        int    # implementation VM address (loaded base)
    is_class_method: bool = False   # True for + methods


@dataclass
class ObjCEdge:
    """Synthetic call graph edge: msgSend call site → implementation(s)."""
    call_site:  int
    selector:   str
    impl_addrs: list[int] = field(default_factory=list)


@dataclass
class ObjCDispatchResult:
    """Summary output from ObjCDispatchResolver.resolve()."""
    is_objc_binary:    bool
    selector_count:    int                   # unique selectors in binary
    impl_count:        int                   # total method implementations
    synthetic_edges:   list[ObjCEdge]        # edges to inject into call graph
    resolved_sites:    int                   # msgSend sites with known selector
    unresolved_sites:  int                   # msgSend sites with unknown selector
    selector_to_impls: dict[str, list[int]]  # selector name → [IMP, ...]

    def print_report(self) -> None:
        if not self.is_objc_binary:
            print('ObjC dispatch: not an ObjC binary — skipped')
            return
        print(f'ObjC dispatch: {self.selector_count} selectors, '
              f'{self.impl_count} implementations')
        print(f'  msgSend sites: {self.resolved_sites} resolved, '
              f'{self.unresolved_sites} unresolved')
        print(f'  Synthetic call graph edges: {len(self.synthetic_edges)}')
        for edge in self.synthetic_edges[:10]:
            print(f'    0x{edge.call_site:x} → [{", ".join(hex(a) for a in edge.impl_addrs)}]'
                  f'  [{edge.selector}]')
        if len(self.synthetic_edges) > 10:
            print(f'    … ({len(self.synthetic_edges) - 10} more)')


# ── Main resolver ──────────────────────────────────────────────────────────────

class ObjCDispatchResolver:
    """
    Resolves ObjC msgSend indirect calls to concrete method implementations.

    Usage::

        resolver = ObjCDispatchResolver(proj)
        result   = resolver.resolve()
        result.inject_into_callgraph(cg)    # C2 integration
        # result.selector_to_impls passed to C6 hook
    """

    _SELREF_NAMES   = ('__objc_selrefs',)
    _METHNAME_NAMES = ('__objc_methnames',)
    _MSGSENDSYMS    = ('_objc_msgSend', 'objc_msgSend')

    def __init__(self, proj: 'angr.Project') -> None:
        self._proj   = proj
        self._binary = str(proj.loader.main_object.binary)
        self._arch   = proj.arch.name                # 'AARCH64' / 'AMD64'
        self._ptr_sz = proj.arch.bytes               # 8 for 64-bit

        # CLE wraps Universal2 (fat) Mach-O binaries in a Universal2 loader
        # object whose mapped_base is a small placeholder address (~0x400000).
        # The actual architecture slice sits in child_objects[0] and is mapped
        # at the Mach-O's preferred address (0x100000000 for macOS arm64 PIE).
        # We need the slice base for decoding dyld chained-fixup selref values.
        mo = proj.loader.main_object
        children = list(getattr(mo, 'child_objects', []))
        self._base: int = (children[0].mapped_base
                           if children else mo.mapped_base)

        self._result:    ObjCDispatchResult | None = None
        self._selref_map: dict[int, str]           = {}   # cached after resolve()

    # ── Public API ─────────────────────────────────────────────────────────────

    def resolve(self) -> ObjCDispatchResult:
        """Run the full ObjC resolution pass (idempotent)."""
        if self._result is not None:
            return self._result

        mo = self._proj.loader.main_object
        if not self._is_objc_binary(mo):
            log.debug('objc_dispatch: not an ObjC binary')
            self._result = ObjCDispatchResult(
                is_objc_binary=False, selector_count=0, impl_count=0,
                synthetic_edges=[], resolved_sites=0, unresolved_sites=0,
                selector_to_impls={})
            return self._result

        log.info('objc_dispatch: parsing ObjC metadata in %s', self._binary)

        # Step 1 — selector name string table
        methname_table = self._parse_methnames(mo)   # VA → selector_name

        # Step 2 — selref → selector_name map
        selref_map = self._build_selref_map(mo, methname_table)
        self._selref_map = selref_map   # cache for get_impl_for_selref
        log.debug('objc_dispatch: %d selrefs resolved', len(selref_map))

        # Step 3 — method list: selector → [IMP address]
        # Pass selref_map so the otool parser can resolve modern relative-method
        # format where name lines show only a selref VA (not the string itself).
        methods = self._parse_methods_otool(selref_map)
        sel_to_impls: dict[str, list[int]] = {}
        for m in methods:
            sel_to_impls.setdefault(m.selector, []).append(m.imp_addr)
        log.debug('objc_dispatch: %d selectors, %d impls',
                  len(sel_to_impls), len(methods))

        # Step 4 — find ObjC dispatch call sites
        #
        # Two dispatch models exist in the wild:
        #
        # MODERN (macOS 12+, arm64e Xcode 14+):
        #   The linker emits one stub per unique selector in __TEXT,__objc_stubs.
        #   Each stub loads its selector into x1 then branches via the ObjC
        #   method cache.  Callers use ``bl <stub_addr>`` — no backward selector
        #   scan needed; the selector is known from which stub was called.
        #
        # LEGACY (macOS <12, or older ObjC ABI):
        #   All ObjC calls go through a single ``_objc_msgSend`` PLT stub.
        #   The selector is loaded into x1 by the CALLER via adrp/ldr.  We
        #   must backward-scan each call site to find the selref.

        edges:    list[ObjCEdge] = []
        resolved   = 0
        unresolved = 0

        # Try modern path first
        stub_to_sel = self._parse_objc_stubs(mo, selref_map)

        if stub_to_sel:
            log.debug('objc_dispatch: %d ObjC stubs (modern dispatch)',
                      len(stub_to_sel))
            call_sites = self._find_call_sites_to(set(stub_to_sel.keys()), mo)
            log.debug('objc_dispatch: %d call sites across %d stubs',
                      len(call_sites), len(stub_to_sel))

            for site_addr, target_addr in call_sites:
                sel = stub_to_sel.get(target_addr)
                if sel and sel in sel_to_impls:
                    edges.append(ObjCEdge(
                        call_site=site_addr,
                        selector=sel,
                        impl_addrs=sel_to_impls[sel],
                    ))
                    resolved += 1
                else:
                    unresolved += 1
                    log.debug('objc_dispatch: unresolved stub site 0x%x '
                              '(stub=0x%x, sel=%r)', site_addr, target_addr, sel)

        else:
            # Fall back to legacy: single _objc_msgSend + backward selector scan
            msgSend_addr = self._find_msgSend_stub()
            if msgSend_addr is not None:
                sites = self._find_msgSend_sites(msgSend_addr, mo)
                log.debug('objc_dispatch: %d legacy msgSend call sites', len(sites))

                for site in sites:
                    sel = self._resolve_selector_at_site(site, selref_map)
                    if sel and sel in sel_to_impls:
                        edges.append(ObjCEdge(
                            call_site=site,
                            selector=sel,
                            impl_addrs=sel_to_impls[sel],
                        ))
                        resolved += 1
                    else:
                        unresolved += 1
                        log.debug('objc_dispatch: unresolved site 0x%x (sel=%r)',
                                  site, sel)

        self._result = ObjCDispatchResult(
            is_objc_binary=True,
            selector_count=len(sel_to_impls),
            impl_count=len(methods),
            synthetic_edges=edges,
            resolved_sites=resolved,
            unresolved_sites=unresolved,
            selector_to_impls=sel_to_impls,
        )
        log.info('objc_dispatch: %d edges (resolved=%d, unresolved=%d)',
                 len(edges), resolved, unresolved)
        return self._result

    def inject_into_callgraph(self, cg: 'nx.DiGraph') -> int:
        """
        Add synthetic ObjC dispatch edges to a NetworkX DiGraph.
        Call after C2's _build_call_graph(). Returns count of edges added.
        """
        r = self.resolve()
        if not r.synthetic_edges:
            return 0
        added = 0
        for edge in r.synthetic_edges:
            for impl in edge.impl_addrs:
                if not cg.has_edge(edge.call_site, impl):
                    cg.add_edge(edge.call_site, impl,
                                label=f'objc:{edge.selector}')
                    added += 1
        log.info('objc_dispatch: injected %d call graph edges', added)
        return added

    def get_impl_for_selref(self, selref_addr: int) -> list[int]:
        """
        Return IMP addresses for the selector loaded from selref_addr.
        Used by the C6 Hook_objcMsgSend SimProcedure at run time.
        """
        r = self.resolve()   # ensures _selref_map is populated
        sel = self._selref_map.get(selref_addr)
        if sel:
            return r.selector_to_impls.get(sel, [])
        return []

    # ── ObjC binary detection ──────────────────────────────────────────────────

    def _is_objc_binary(self, mo) -> bool:
        for sec in self._all_sections(mo):
            sname = sec.name
            # Match both __objc_methnames (older format) and __objc_methname
            # (newer macOS 15 format). Also match classlist / selrefs.
            if any(n in sname for n in (
                    '__objc_methname', '__objc_classlist', '__objc_selrefs')):
                return True
        return False

    # ── Methnames section ──────────────────────────────────────────────────────

    def _parse_methnames(self, mo) -> dict[int, str]:
        """
        Parse __objc_methname[s] — concatenated null-terminated selector strings.
        Section name is '__objc_methname' on macOS 15+ or '__objc_methnames' on
        older SDKs; the fragment '__objc_methname' matches both.
        Returns {VA → selector_name}.
        """
        sec = self._find_section(mo, '__objc_methname')
        if sec is None:
            return {}

        try:
            data = self._proj.loader.memory.load(sec.vaddr, sec.filesize)
        except Exception as exc:
            log.warning('objc_dispatch: failed to read methnames: %s', exc)
            return {}

        table: dict[int, str] = {}
        i = 0
        while i < len(data):
            end = data.find(b'\x00', i)
            if end == -1:
                break
            name = data[i:end].decode('utf-8', errors='replace')
            if name:
                table[sec.vaddr + i] = name
            i = end + 1
        return table

    # ── Selref map ─────────────────────────────────────────────────────────────

    def _build_selref_map(
        self, mo, methname_table: dict[int, str],
    ) -> dict[int, str]:
        """
        Build {selref_VA → selector_name} from __objc_selrefs.

        Each entry in __objc_selrefs is a pointer into __objc_methnames.
        On arm64e with chained fixups, the pointer may have PAC bits in the
        upper 16 bits — mask those off before the lookup.
        """
        sec = self._find_section(mo, '__objc_selrefs')
        if sec is None:
            return {}

        try:
            data = self._proj.loader.memory.load(sec.vaddr, sec.filesize)
        except Exception as exc:
            log.warning('objc_dispatch: failed to read selrefs: %s', exc)
            return {}

        result: dict[int, str] = {}
        for i in range(0, len(data) - self._ptr_sz + 1, self._ptr_sz):
            raw = struct.unpack_from('<Q', data, i)[0]
            # Strip PAC / chained-fixup metadata bits.
            # macOS arm64e binaries compiled with the small method list ABI
            # (Xcode 13+) store dyld chained-fixup encoded pointers in
            # __objc_selrefs.  The on-disk encoding has:
            #   bits 51-0: target as a slide-relative offset (file offset-like)
            #   bits 63-52: chained-fixup metadata (next, bind, high8)
            # At runtime, dyld adds the slide to produce the actual VA.
            # CLE loads the binary without applying chained fixups, so we must
            # reconstruct the VA ourselves.
            #
            # Strategy: mask to 48 bits (strips PAC + chained-fixup high bits),
            # then try both the raw masked value AND (masked + image_base).
            # This covers:
            #   - Old format (non-chained): raw value IS the absolute VA already
            #   - New format (chained fixup): masked value is the file-offset-like
            #     target; add image base to get the absolute VA.
            ptr_lower = raw & 0x0000_FFFF_FFFF_FFFF
            name = (methname_table.get(ptr_lower)
                    or methname_table.get(ptr_lower + self._base))
            if name:
                result[sec.vaddr + i] = name
        return result

    # ── Method list via otool ──────────────────────────────────────────────────

    def _parse_methods_otool(
        self, selref_map: 'dict[int, str] | None' = None,
    ) -> list[ObjCMethod]:
        """
        Extract (class, selector, IMP) triples using ``otool -ov``.

        otool handles both big-method (absolute pointers) and small-method
        (relative offsets, macOS 12+) formats, and arm64e PAC stripping.

        ``selref_map`` is the VA→selector mapping built from __objc_selrefs /
        __objc_methnames.  It is required to resolve selector names in the
        modern relative-method format where otool only prints the selref VA,
        not the selector string.
        """
        arch = 'arm64e' if 'AARCH64' in self._arch else 'x86_64'
        try:
            proc = subprocess.run(
                ['otool', '-arch', arch, '-ov', self._binary],
                capture_output=True, text=True, timeout=180,
            )
        except FileNotFoundError:
            log.warning('objc_dispatch: otool not found — method list unavailable')
            return []
        except subprocess.TimeoutExpired:
            log.warning('objc_dispatch: otool timed out on %s', self._binary)
            return []

        return self._parse_otool_ov(proc.stdout, selref_map or {})

    # ── otool -ov parser ───────────────────────────────────────────────────────
    #
    # otool -ov output has changed across Xcode/macOS versions:
    #
    # OLD format (macOS <12, absolute method_t pointers):
    #   name   0x1000ABCD  -[ClassName selector:]
    #   types  0x...       ...
    #   imp    0x100012340
    #
    # NEW format (macOS 12+, relative method_t aka "small method"):
    #   name   0xd2f8  (0x100038120)        ← relative offset + abs selref VA
    #   types  0x52b1  (0x1000300dd) ...
    #   imp    0xffffd6ac  (0x1000284dc)    ← relative offset + abs IMP VA
    #
    # Swift/ObjC hybrid binaries show imp=0x0 for Swift-implemented methods
    # (Swift vtable stubs). These are skipped — they have no concrete IMP.
    #
    # Class names in the ro_t always appear with the string on the same line:
    #   name   0x1000300b1  OS_firehose_client
    #
    # These three name-line variants are mutually exclusive:
    #   class name:    name  0xVA  [A-Za-z_]IDENT     (plain identifier, no parens)
    #   old method:    name  0xVA  [-+][ClassName ...]  (method syntax)
    #   new method:    name  0xREL  (0xABS)             (parens around absolute VA)

    # Old-style absolute method (macOS <12):
    # "name  0x1000ABCD -[ClassName selector:]"
    _PAT_METHOD_OLD = re.compile(
        r'^\s+name\s+\S+\s+([+\-])\[(\S+)\s+(.+?)\]\s*$')

    # New-style relative method (macOS 12+, small method_t):
    # "name  0xd2f8 (0x100038120)"
    # Captures the absolute selref VA in group(1).
    _PAT_METHOD_REL = re.compile(
        r'^\s+name\s+0x[0-9a-fA-F]+\s+\(0x([0-9a-fA-F]+)\)\s*$')

    # IMP — new relative format: "imp  0xffffd6ac (0x1000284dc)"
    # Captures the ABSOLUTE address in group(1) — must be checked FIRST.
    _PAT_IMP_REL = re.compile(
        r'^\s+imp\s+0x[0-9a-fA-F]+\s+\(0x([0-9a-fA-F]+)\)')

    # IMP — old absolute format: "imp  0x100012340"  (no trailing parens)
    # The $ anchor ensures this does NOT match the new-format lines.
    _PAT_IMP_ABS = re.compile(r'^\s+imp\s+(0x[0-9a-fA-F]+)\s*$')

    # Class name from ro_t "name" field: "name  0xVA  ClassName"
    # (starts with a letter/underscore after the hex, no brackets, no parens)
    _PAT_CLASSNAME = re.compile(
        r'^\s+name\s+0x[0-9a-fA-F]+\s+([A-Za-z_]\S*)\s*$')

    # Section dividers for instance vs. class methods
    _PAT_BASE_METHODS = re.compile(r'\bbaseMethods\b')
    _PAT_META_METHODS = re.compile(r'\bbaseMetaMethods\b|\bclassMethods\b')

    def _parse_otool_ov(
        self,
        text: str,
        selref_map: 'dict[int, str] | None' = None,
    ) -> list[ObjCMethod]:
        """
        Parse ``otool -arch arm64e -ov`` output into ObjCMethod triples.

        ``selref_map`` is required for the modern relative-method format
        (macOS 12+).  Each method's ``name`` line carries only the selref VA;
        the actual selector string must be resolved via selref_map.

        Swift-vtable stubs (imp == 0x0) are silently skipped — they have no
        concrete IMP address in the ObjC metadata.
        """
        if selref_map is None:
            selref_map = {}

        methods:      list[ObjCMethod] = []
        pending_sel:  str | None       = None   # resolved selector name
        pending_va:   int | None       = None   # selref VA (new format, before resolution)
        pending_class: str | None      = None
        pending_plus:  bool            = False
        current_class: str             = 'Unknown'
        is_class_meth: bool            = False

        for line in text.splitlines():

            # ── Track instance vs. class method context ──────────────────────
            if self._PAT_META_METHODS.search(line):
                is_class_meth = True
                continue
            if self._PAT_BASE_METHODS.search(line):
                is_class_meth = False
                continue

            # ── Class name from ro_t ─────────────────────────────────────────
            m = self._PAT_CLASSNAME.match(line)
            if m:
                name = m.group(1)
                if not name.startswith('0x') and '[' not in name:
                    current_class = name
                continue

            # ── Method name line — OLD format ────────────────────────────────
            m = self._PAT_METHOD_OLD.match(line)
            if m:
                pending_plus  = (m.group(1) == '+')
                pending_class = m.group(2)
                pending_sel   = m.group(3).strip()
                pending_va    = None
                current_class = pending_class
                continue

            # ── Method name line — NEW relative format ───────────────────────
            m = self._PAT_METHOD_REL.match(line)
            if m:
                selref_va   = int(m.group(1), 16)
                pending_va  = selref_va
                pending_sel = selref_map.get(selref_va)  # may be None
                continue

            # ── IMP line — NEW relative format (check before ABS) ───────────
            m = self._PAT_IMP_REL.match(line)
            if m:
                if pending_sel is not None or pending_va is not None:
                    imp_abs = int(m.group(1), 16)
                    # Skip Swift vtable stubs (imp == 0x0) and
                    # binary-base placeholders used by some class/meta entries.
                    if imp_abs != 0 and imp_abs != self._base:
                        sel_name = (pending_sel
                                    or (f'sel@0x{pending_va:x}'
                                        if pending_va else 'unknown'))
                        methods.append(ObjCMethod(
                            class_name=pending_class or current_class,
                            selector=sel_name,
                            imp_addr=imp_abs,
                            is_class_method=pending_plus or is_class_meth,
                        ))
                pending_sel = pending_va = pending_class = None
                continue

            # ── IMP line — OLD absolute format ──────────────────────────────
            m = self._PAT_IMP_ABS.match(line)
            if m:
                if pending_sel is not None:
                    imp_raw = int(m.group(1), 16)
                    if imp_raw < 0x10000000:
                        imp_raw += self._base
                    # Skip null and binary-base placeholder IMPs
                    if imp_raw != 0 and imp_raw != self._base:
                        methods.append(ObjCMethod(
                            class_name=pending_class or current_class,
                            selector=pending_sel,
                            imp_addr=imp_raw,
                            is_class_method=pending_plus or is_class_meth,
                        ))
                pending_sel = pending_va = pending_class = None

        return methods

    # ── msgSend stub location ──────────────────────────────────────────────────

    def _find_msgSend_stub(self) -> int | None:
        """Return the VM address of the _objc_msgSend stub, or None."""
        proj = self._proj
        mo   = proj.loader.main_object

        # Check KB functions first
        for fn in proj.kb.functions.values():
            fn_name = fn.name or ''
            if ('objc_msgSend' in fn_name
                    and 'Stret' not in fn_name
                    and 'Super' not in fn_name):
                return fn.addr

        # Check symbol table
        for sym in mo.symbols:
            sym_name = sym.name or ''
            if ('objc_msgSend' in sym_name
                    and 'Stret' not in sym_name
                    and 'Super' not in sym_name
                    and sym.rebased_addr):
                return sym.rebased_addr

        return None

    # ── Modern ObjC stub table ─────────────────────────────────────────────────

    def _parse_objc_stubs(
        self,
        mo,
        selref_map: dict[int, str],
    ) -> dict[int, str]:
        """
        Parse ``__TEXT,__objc_stubs`` (modern arm64e dispatch model, macOS 12+).

        In this model the linker emits one 32-byte stub per unique selector.
        Each stub starts with the pair::

            adrp  x1, <page>      ; load selref page base
            ldr   x1, [x1, #off]  ; load selector pointer from selref

        We extract the selref VA from these two instructions and resolve the
        selector name via selref_map.

        Returns ``{stub_addr → selector_name}``.
        Returns ``{}`` if the section is absent (legacy binary).
        """
        sec = self._find_section(mo, '__objc_stubs')
        if sec is None:
            return {}

        try:
            import capstone
            from capstone.arm64 import ARM64_REG_X1
        except ImportError:
            log.warning('objc_dispatch: capstone not available — stub parse skipped')
            return {}

        try:
            code = self._proj.loader.memory.load(sec.vaddr, sec.filesize)
        except Exception as exc:
            log.warning('objc_dispatch: failed to read __objc_stubs: %s', exc)
            return {}

        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        cs.detail = True

        stubs: dict[int, str] = {}
        insns = list(cs.disasm(code, sec.vaddr))

        i = 0
        while i < len(insns) - 1:
            insn0 = insns[i]
            insn1 = insns[i + 1]

            # Expect: adrp x1, PAGE_IMM  then  ldr x1, [x1, #DISP]
            if insn0.mnemonic == 'adrp' and insn1.mnemonic == 'ldr':
                ops0 = insn0.operands
                ops1 = insn1.operands
                if (ops0 and ops0[0].reg == ARM64_REG_X1
                        and ops1 and ops1[0].reg == ARM64_REG_X1
                        and len(ops1) >= 2):
                    page_addr  = ops0[1].imm
                    disp       = ops1[1].mem.disp
                    selref_va  = page_addr + disp
                    sel_name   = selref_map.get(selref_va,
                                               f'sel@0x{selref_va:x}')
                    stubs[insn0.address] = sel_name
            i += 1

        log.info('objc_dispatch: parsed %d stubs from __objc_stubs', len(stubs))
        return stubs

    # ── Multi-target call site scan ────────────────────────────────────────────

    def _find_call_sites_to(
        self,
        target_addrs: set[int],
        mo,
    ) -> list[tuple[int, int]]:
        """
        Scan ``__TEXT,__text`` for ``bl`` instructions targeting any address in
        ``target_addrs``.

        Returns a list of ``(call_site_addr, target_addr)`` tuples.
        Used for the modern ObjC stub dispatch model where each ``bl`` to a
        stub address encodes a specific selector.
        """
        try:
            import capstone
        except ImportError:
            log.warning('objc_dispatch: capstone unavailable — call site scan skipped')
            return []

        text_sec = self._find_section(mo, '__text')
        if text_sec is None:
            all_secs = list(self._all_sections(mo))
            text_sec = max(
                (s for s in all_secs if s.filesize > 0),
                key=lambda s: s.filesize,
                default=None,
            )
        if text_sec is None:
            return []

        try:
            code = self._proj.loader.memory.load(text_sec.vaddr, text_sec.filesize)
        except Exception as exc:
            log.warning('objc_dispatch: failed to read text section: %s', exc)
            return []

        if 'AARCH64' in self._arch:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        results: list[tuple[int, int]] = []
        for insn in cs.disasm(code, text_sec.vaddr):
            if insn.mnemonic == 'bl':
                op = insn.op_str.lstrip('#')
                try:
                    target = int(op, 16)
                except ValueError:
                    continue
                if target in target_addrs:
                    results.append((insn.address, target))
        return results

    # ── Call site discovery (legacy single-entry msgSend) ──────────────────────

    def _find_msgSend_sites(self, msgSend_addr: int, mo) -> list[int]:
        """
        Scan __TEXT,__text for ``bl <msgSend_addr>`` instructions.
        Returns list of call site addresses.
        """
        try:
            import capstone
        except ImportError:
            log.warning('objc_dispatch: capstone not available — site scan skipped')
            return []

        text_sec = self._find_section(mo, '__text')
        if text_sec is None:
            # Fallback: largest section heuristic (covers Universal2 case)
            all_secs = list(self._all_sections(mo))
            text_sec = max(
                (s for s in all_secs if s.filesize > 0),
                key=lambda s: s.filesize,
                default=None,
            )
        if text_sec is None:
            return []

        try:
            code = self._proj.loader.memory.load(text_sec.vaddr, text_sec.filesize)
        except Exception as exc:
            log.warning('objc_dispatch: failed to read text section: %s', exc)
            return []

        if 'AARCH64' in self._arch:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        sites: list[int] = []
        for insn in cs.disasm(code, text_sec.vaddr):
            if insn.mnemonic == 'bl':
                op = insn.op_str.lstrip('#')
                try:
                    target = int(op, 16)
                except ValueError:
                    continue
                if target == msgSend_addr:
                    sites.append(insn.address)
        return sites

    # ── Per-site selector resolution ───────────────────────────────────────────

    def _resolve_selector_at_site(
        self,
        site_addr: int,
        selref_map: dict[int, str],
        window_insns: int = 40,
    ) -> str | None:
        """
        Determine which selector is passed in x1 at site_addr.

        ARM64 compiler pattern (most common):
            adrp  xN,   PAGE          ; xN = page-aligned address
            ldr   x1,  [xN, #off]    ; x1 = selref pointer
            ...
            bl    _objc_msgSend

        Strategy: disassemble window_insns instructions before site_addr,
        scan backwards. Track:
          - pending_ldr: (base_reg, disp) from the most recent ``ldr x1, [xN, #d]``
          - When we find ``adrp xN, PAGE`` whose dst matches pending_ldr.base_reg:
            selref_VA = PAGE + disp → lookup in selref_map

        Returns selector name string or None.
        """
        if 'AARCH64' not in self._arch:
            return None   # x86_64 pattern not yet implemented

        try:
            import capstone
            from capstone.arm64 import (
                ARM64_REG_X1, ARM64_REG_SP, ARM64_REG_XZR,
            )
        except ImportError:
            return None

        # Read window before the call site
        read_start = max(site_addr - window_insns * 4, 0)
        read_size  = site_addr - read_start
        if read_size <= 0:
            return None

        try:
            code = self._proj.loader.memory.load(read_start, read_size)
        except Exception:
            return None

        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        cs.detail = True
        insns = list(cs.disasm(code, read_start))

        # pending_ldr: (base_reg_id, displacement) from ldr x1, [xN, #d]
        pending_ldr: tuple[int, int] | None = None

        for insn in reversed(insns):
            mnem = insn.mnemonic
            ops  = insn.operands

            if mnem == 'ldr' and ops:
                dst = ops[0].reg
                if dst == ARM64_REG_X1 and len(ops) >= 2:
                    mem = ops[1].mem
                    # Record: which register holds the base, and the offset
                    pending_ldr = (mem.base, mem.disp)

            elif mnem == 'adrp' and ops and pending_ldr is not None:
                dst = ops[0].reg
                if dst == pending_ldr[0] and len(ops) >= 2:
                    page_addr   = ops[1].imm
                    selref_addr = page_addr + pending_ldr[1]
                    sel = selref_map.get(selref_addr)
                    if sel:
                        return sel
                    # Page address matched but not in selref_map —
                    # could be a dynamic selref; stop searching.
                    pending_ldr = None

            elif mnem in ('mov', 'movz', 'movn', 'str', 'stp') and ops:
                # If x1 is overwritten, the pending ldr is now stale
                if ops and ops[0].reg == ARM64_REG_X1:
                    pending_ldr = None

        return None

    # ── Section lookup helper ──────────────────────────────────────────────────

    @staticmethod
    def _find_section(mo, name_fragment: str):
        """
        Return the first section whose name contains name_fragment.

        Handles CLE Universal2 fat-binary loading: on macOS arm64e, CLE wraps
        the selected architecture slice in a ``child_objects[0]`` Mach-O backend
        while ``mo.sections`` is empty. We try both layers.
        """
        # Try direct sections first (non-fat, or older CLE)
        for sec in mo.sections:
            if name_fragment in sec.name:
                return sec
        # Fall back to child_objects (Universal2 / fat Mach-O on arm64e)
        for child in getattr(mo, 'child_objects', []):
            for sec in getattr(child, 'sections', []):
                if name_fragment in sec.name:
                    return sec
        return None

    def _all_sections(self, mo):
        """
        Return an iterable of all sections from mo, including child_objects.
        Used where we need to iterate all sections rather than find one by name.
        """
        yield from mo.sections
        for child in getattr(mo, 'child_objects', []):
            yield from getattr(child, 'sections', [])


# ── C6 SimProcedure hook for objc_msgSend ─────────────────────────────────────

def make_objcMsgSend_hook(resolver: ObjCDispatchResolver):
    """
    Factory: returns a Hook_objcMsgSend SimProcedure class bound to resolver.

    At symbolic execution time, the hook:
      1. Evaluates x1 (SEL pointer) concretely if possible.
      2. Looks up the selector in the resolver's selref map.
      3. If one implementation found: jumps there (follows ObjC dispatch).
      4. If multiple: jumps to the first (conservative — avoids state explosion).
      5. If unresolvable: returns a tainted BVS (marks return value as attacker-
         influenced, propagates taint through the call).

    Usage (in C6Analysis.__init__)::

        from metis.objc_dispatch import ObjCDispatchResolver, make_objcMsgSend_hook
        resolver = ObjCDispatchResolver(proj)
        hook = make_objcMsgSend_hook(resolver)
        proj.hook_symbol('_objc_msgSend', hook())
    """
    import angr
    import claripy

    _resolver = resolver  # captured in closure

    class Hook_objcMsgSend(angr.SimProcedure):
        """SimProcedure hook for _objc_msgSend / _objc_msgSend_stret."""

        def run(self, receiver, selector, *args):
            # Attempt to evaluate the selector pointer concretely
            sel_addr: int | None = None
            try:
                if not selector.symbolic:
                    sel_addr = self.state.solver.eval(selector)
                else:
                    # Try to get a single concrete value under current constraints
                    vals = self.state.solver.eval_upto(selector, 2)
                    if len(vals) == 1:
                        sel_addr = vals[0]
            except Exception:
                pass

            # Resolve to implementation address(es)
            impls: list[int] = []
            if sel_addr is not None:
                impls = _resolver.get_impl_for_selref(sel_addr)

            if impls:
                target = impls[0]   # conservative: pick first impl
                if len(impls) > 1:
                    log.debug(
                        'objcMsgSend hook: %d impls for selref 0x%x, '
                        'using 0x%x', len(impls), sel_addr or 0, target)
                # Jump to implementation — it will ret back to our caller
                # (LR was set by the original bl _objc_msgSend in the binary)
                self.jump(target)
            else:
                # Unresolvable dispatch — return a tainted symbolic value
                # so downstream taint analysis is conservative.
                tainted = self.state.solver.BVS(
                    f'c6_taint_objcmsg_{sel_addr or 0:#x}', 64)
                log.debug(
                    'objcMsgSend hook: unresolvable selref 0x%x — '
                    'returning tainted BVS', sel_addr or 0)
                return tainted

    return Hook_objcMsgSend
