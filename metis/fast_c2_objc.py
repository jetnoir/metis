"""
fast_c2_objc.py — ObjC/Swift call graph extractor for FastC2
Implements approach D (B+C hybrid) as recommended by Grok/ChatGPT/Gemini:
  Layer C: ObjC classlist → method_imp → function node mapping
  Layer B: BL _objc_msgSend + x1 backtracking → caller → selector edges
  Swift:   BLR x16/x17 → synthetic swift_indirect_<n> pseudo-nodes

Handles ARM64e chained fixups (LC_DYLD_CHAINED_FIXUPS) by using lief's
relocation iterator which gives pre-resolved target VAs. Strips PAC bits
from IMP pointers with mask 0x0000000fffffffff.

Usage:
    from fast_c2_objc import build_objc_graph
    nodes, edges = build_objc_graph(binary_path)
    # edges: list of (caller_func_va, callee_node) where callee is int or str
"""
import struct, mmap, logging
from pathlib import Path
from typing import Optional

try:
    import lief
    import capstone
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

log = logging.getLogger(__name__)

PAC_MASK = 0x0000_000f_ffff_ffff   # strip PAC high bits from arm64e pointers
MAX_BACKTRACK = 6                   # instructions to search back from BL msgSend


# ─── helpers ──────────────────────────────────────────────────────────────────

def _strip_pac(ptr: int) -> int:
    return ptr & PAC_MASK


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


class _BinaryInfo:
    __slots__ = ("b", "reloc_map", "sel_map", "imp_map",
                 "msgSend_addrs", "va_to_offset", "segments", "stub_map")

    def __init__(self):
        self.b            = None   # lief.MachO.Binary
        self.reloc_map    = {}     # VA → resolved target VA
        self.sel_map      = {}     # selref VA → selector string
        self.imp_map      = {}     # imp VA → (class_name, sel_name)
        self.msgSend_addrs = set() # VAs of _objc_msgSend stubs
        self.stub_map      = {}     # stub_VA → selector string (modern ObjC ABI)
        self.va_to_offset = []     # list of (seg_va, seg_end, file_offset) sorted
        self.segments     = []


def _va_to_file_off(info: _BinaryInfo, va: int) -> Optional[int]:
    for (seg_va, seg_end, file_off) in info.va_to_offset:
        if seg_va <= va < seg_end:
            return file_off + (va - seg_va)
    return None


def _build_reloc_map(info: _BinaryInfo):
    for r in info.b.relocations:
        info.reloc_map[r.address] = r.target


def _build_segment_map(info: _BinaryInfo):
    for seg in info.b.segments:
        if seg.file_size > 0:
            info.va_to_offset.append(
                (seg.virtual_address,
                 seg.virtual_address + seg.virtual_size,
                 seg.file_offset)
            )
    info.va_to_offset.sort(key=lambda x: x[0])


def _build_sel_map(info: _BinaryInfo):
    """Build selref_VA → selector_string using lief relocations."""
    selrefs   = next((s for s in info.b.sections if s.name == "__objc_selrefs"),  None)
    methnames = next((s for s in info.b.sections if s.name == "__objc_methname"), None)
    if not selrefs or not methnames:
        return
    mn_va   = methnames.virtual_address
    mn_data = bytes(methnames.content)
    sel_va  = selrefs.virtual_address
    sel_data = bytes(selrefs.content)
    for i in range(len(sel_data) // 8):
        addr     = sel_va + i * 8
        raw      = _read_u64(sel_data, i * 8)
        resolved = info.reloc_map.get(addr, raw)
        resolved = _strip_pac(resolved)
        if mn_va <= resolved < mn_va + methnames.size:
            off  = resolved - mn_va
            end  = mn_data.index(0, off) if 0 in mn_data[off:] else off + 256
            info.sel_map[addr] = mn_data[off:end].decode("ascii", errors="replace")


def _build_imp_map(info: _BinaryInfo):
    """
    Parse __objc_classlist + __objc_const to map IMP address → (class, selector).

    Handles two method_list_t formats:
      Traditional (arm64, pre-macOS 12): 24-byte entries with absolute u64 pointers.
        entsize_and_flags bit 31 = 0; entsize & 0xFFFC ≈ 24.
        method_t { u64 name_ptr; u64 types_ptr; u64 imp_ptr }
      Relative (arm64e, macOS 12+): 12-byte entries with int32_t relative offsets.
        entsize_and_flags bit 31 = 1; entsize & 0xFFFC = 12.
        relative_method_t { i32 nameOff; i32 typesOff; i32 impOff }
        Actual values: name_selref_va = (meth_va + 0) + nameOff (relative from field addr)
                       imp_va         = (meth_va + 8) + impOff
    """
    classlist = next((s for s in info.b.sections if s.name == "__objc_classlist"), None)
    methnames = next((s for s in info.b.sections if s.name == "__objc_methname"), None)
    if not classlist or not methnames:
        return

    mn_va   = methnames.virtual_address
    mn_data = bytes(methnames.content)

    def read_name(va):
        if not va: return "?"
        va = _strip_pac(va)
        try:
            raw = bytes(info.b.get_content_from_virtual_address(va, 256))
            end = raw.index(0) if 0 in raw else 256
            return raw[:end].decode("ascii", errors="replace")
        except Exception:
            return "?"

    cl_va   = classlist.virtual_address
    cl_data = bytes(classlist.content)
    n_cls   = len(cl_data) // 8

    for i in range(n_cls):
        cls_ptr = _strip_pac(info.reloc_map.get(cl_va + i*8, _read_u64(cl_data, i*8)))
        if not cls_ptr: continue

        # class_t: data (rodata ptr) is at offset 32 (8 bytes)
        data_ptr_va = cls_ptr + 32
        ro_ptr      = _strip_pac(info.reloc_map.get(data_ptr_va, 0))
        if not ro_ptr: continue

        # class_ro_t: name @ off 24, baseMethods @ off 32
        class_name_ptr = _strip_pac(info.reloc_map.get(ro_ptr + 24, 0))
        class_name     = read_name(class_name_ptr) if class_name_ptr else "?"
        base_methods_ptr = _strip_pac(info.reloc_map.get(ro_ptr + 32, 0))
        if not base_methods_ptr: continue

        # method_list_t header: entsize_and_flags @ 0 (u32), count @ 4 (u32)
        try:
            hdr = bytes(info.b.get_content_from_virtual_address(base_methods_ptr, 8))
            if len(hdr) < 8: continue
            entsize_and_flags = _read_u32(hdr, 0)
            count             = _read_u32(hdr, 4)
            if count == 0 or count > 10000: continue

            # Detect relative method list format (bit 31 of entsize_and_flags)
            is_relative = bool(entsize_and_flags & 0x80000000)
            entsize     = (entsize_and_flags & 0x7FFC)  # low 14 bits, 4-byte aligned
            if entsize == 0:
                entsize = 12 if is_relative else 24  # sensible defaults

            for j in range(count):
                meth_va = base_methods_ptr + 8 + j * entsize

                if is_relative:
                    # Relative method list: 3 × int32_t (relative from each field's address)
                    meth_raw = bytes(info.b.get_content_from_virtual_address(meth_va, 12))
                    if len(meth_raw) < 12: continue

                    name_off  = struct.unpack_from("<i", meth_raw, 0)[0]  # signed int32
                    imp_off   = struct.unpack_from("<i", meth_raw, 8)[0]  # signed int32

                    # nameOff is relative from the field address → selref VA
                    selref_va = meth_va + 0 + name_off
                    # Resolve selref VA → selector string via sel_map
                    sel_name  = info.sel_map.get(selref_va)
                    if not sel_name:
                        # Try resolving the selref pointer itself to methnames
                        sel_ptr = _strip_pac(info.reloc_map.get(selref_va, 0))
                        if mn_va <= sel_ptr < mn_va + methnames.size:
                            off = sel_ptr - mn_va
                            end = mn_data.index(0, off) if 0 in mn_data[off:] else off + 256
                            sel_name = mn_data[off:end].decode("ascii", errors="replace")
                    if not sel_name:
                        continue

                    # impOff relative from the imp field address (meth_va + 8)
                    imp_va = (meth_va + 8) + imp_off
                    imp_va = imp_va & PAC_MASK  # strip PAC just in case

                else:
                    # Traditional absolute pointer method list
                    meth_raw = bytes(info.b.get_content_from_virtual_address(meth_va, 24))
                    if len(meth_raw) < 24: continue

                    name_ptr = _strip_pac(info.reloc_map.get(meth_va, _read_u64(meth_raw, 0)))
                    imp_raw  = _read_u64(meth_raw, 16)
                    imp_va   = _strip_pac(info.reloc_map.get(meth_va + 16, imp_raw))

                    # Selector name from methnames section
                    if mn_va <= name_ptr < mn_va + methnames.size:
                        off = name_ptr - mn_va
                        end = mn_data.index(0, off) if 0 in mn_data[off:] else off + 256
                        sel_name = mn_data[off:end].decode("ascii", errors="replace")
                    else:
                        sel_name = read_name(name_ptr)

                if imp_va and sel_name:
                    info.imp_map[imp_va] = (class_name, sel_name)
        except Exception:
            continue


def _find_msgSend_stubs(info: _BinaryInfo):
    """
    Build two structures for ObjC dispatch detection:
      info.msgSend_addrs: VAs of _objc_msgSend* stubs in __auth_stubs / __stubs
                          (for traditional ABI: BL <stub>; backtrack x1)
      info.stub_map:      stub_VA → selector_string (modern ABI:
                          __objc_stubs, each stub pre-loads x1 then calls msgSend)
    """
    import capstone as _cs

    # Collect msgSend GOT/binding addresses
    msgSend_got = set()
    for binding in info.b.bindings:
        sym = getattr(binding, "symbol", None)
        if sym and "objc_msgSend" in getattr(sym, "name", ""):
            msgSend_got.add(binding.address)

    md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)
    md.detail = True

    # ── Scan auth_stubs / stubs to find msgSend code VAs ─────────────────
    for sect_name in ("__auth_stubs", "__stubs"):
        sect = next((s for s in info.b.sections if s.name == sect_name), None)
        if not sect:
            continue
        code  = bytes(sect.content)
        va    = sect.virtual_address
        insns = list(md.disasm(code, va))
        i = 0
        while i < len(insns):
            stub_va   = insns[i].address
            adrp_page = None
            got_match = False
            j = i
            while j < len(insns) and j - i < 8:
                mn   = insns[j].mnemonic.lower()
                ops  = insns[j].op_str
                parts = [p.strip() for p in ops.split(",")]
                if mn == "adrp":
                    try: adrp_page = int(parts[1].lstrip("#"), 16)
                    except: pass
                elif mn == "add" and adrp_page is not None and len(parts) >= 3:
                    try:
                        off = int(parts[-1].lstrip("#"), 16)
                        if adrp_page + off in msgSend_got:
                            got_match = True
                    except: pass
                if mn in ("braa", "braaz", "br", "ret"):
                    j += 1; break
                j += 1
            if got_match:
                info.msgSend_addrs.add(stub_va)
            i = j

    # ── Parse __objc_stubs → stub_VA → selector string (modern ABI) ───────
    # Each objc_stub: [BRK] [BRK] ADRP x1 + LDR x1,[x1,#off] → selref VA
    #                        ADRP x17 + ADD x17,x17,#got_off + LDR x16 + BRAA
    objc_stubs = next((s for s in info.b.sections if s.name == "__objc_stubs"), None)
    if objc_stubs:
        code  = bytes(objc_stubs.content)
        va    = objc_stubs.virtual_address
        insns = list(md.disasm(code, va))
        i = 0
        while i < len(insns):
            stub_start = insns[i].address
            adrp_x1   = None
            x1_va     = None
            j = i
            while j < len(insns) and j - i < 10:
                mn   = insns[j].mnemonic.lower()
                ops  = insns[j].op_str
                parts = [p.strip() for p in ops.split(",")]
                if mn == "adrp" and len(parts) >= 2 and parts[0] == "x1":
                    try: adrp_x1 = int(parts[1].lstrip("#"), 16)
                    except: pass
                elif mn == "ldr" and adrp_x1 is not None and len(parts) >= 2:
                    if parts[0] == "x1" and "[x1" in ops:
                        # LDR x1, [x1, #off]
                        try:
                            off_str = ops.split("#")[-1].rstrip("]")
                            off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
                            x1_va = adrp_x1 + off
                        except: pass
                if mn in ("braa", "braaz", "br", "ret"):
                    j += 1; break
                j += 1
            # Key on the ADRP x1 address (the actual BL target, past BRK padding)
            if x1_va:
                # Find the address of the first ADRP x1 instruction in this stub
                key_va = stub_start
                for _ki in range(j - i):
                    if i + _ki < j and insns[i + _ki].mnemonic.lower() == "adrp":
                        ops_parts = [p.strip() for p in insns[i + _ki].op_str.split(",")]
                        if ops_parts and ops_parts[0] == "x1":
                            key_va = insns[i + _ki].address
                            break
                sel = info.sel_map.get(x1_va, f"sel_{hex(x1_va)}")
                info.stub_map[key_va] = sel
                if key_va != stub_start:
                    info.stub_map[stub_start] = sel  # also key on group start
            i = j


def _extract_msgSend_edges(start_va: int, end_va: int, info: _BinaryInfo,
                           md: "capstone.Cs") -> list:
    """
    Scan one function for BL _objc_msgSend sites, backtrack to recover x1
    (selector address), resolve to selector string. Return edges as list of
    selector name strings.
    """
    if not info.msgSend_addrs and not info.sel_map:
        return []

    n_bytes = min(end_va - start_va, 65536)
    if n_bytes <= 0: return []

    try:
        code = bytes(info.b.get_content_from_virtual_address(start_va, n_bytes))
        if not code: return []
    except Exception:
        return []

    # Disassemble with detail to get operands
    insns = list(md.disasm(code, start_va))
    edges = []

    for idx, insn in enumerate(insns):
        mn = insn.mnemonic.lower()
        if mn not in ("bl", "blr"): continue

        if mn == "bl":
            try:
                tgt = int(insn.op_str.strip().lstrip("#"), 16)
            except (ValueError, TypeError):
                continue

            # ── Modern ObjC ABI: BL to __objc_stubs entry ────────────────
            if tgt in info.stub_map:
                edges.append(info.stub_map[tgt])
                continue

            # ── Traditional ABI: BL to msgSend + backtrack x1 ────────────
            if tgt not in info.msgSend_addrs:
                continue
            x1_va = None
            adrp_page = None
            for back in range(1, min(MAX_BACKTRACK + 1, idx + 1)):
                prev = insns[idx - back]
                pmn  = prev.mnemonic.lower()
                ops  = prev.op_str
                parts = [p.strip() for p in ops.split(",")]
                if pmn == "adrp" and len(parts) >= 2 and parts[0] == "x1":
                    try:
                        adrp_page = int(parts[1].lstrip("#"), 16)
                    except (ValueError, TypeError):
                        pass
                elif pmn in ("add", "ldr") and adrp_page is not None and parts[0] == "x1":
                    try:
                        off_str = parts[-1].rstrip("]").lstrip("#")
                        off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
                        x1_va = adrp_page + off
                        break
                    except (ValueError, TypeError):
                        adrp_page = None
            if x1_va and x1_va in info.sel_map:
                edges.append(info.sel_map[x1_va])
            elif x1_va:
                edges.append(f"sel_{hex(x1_va)}")

        else:
            # BLR x16/x17 — Swift indirect dispatch or ObjC tail-call
            reg = insn.op_str.strip().lower()
            if reg in ("x16", "x17"):
                edges.append("swift_indirect")

    return edges


# ─── public API ───────────────────────────────────────────────────────────────

def build_objc_graph(binary_path: str) -> tuple:
    """
    Build an ObjC/Swift call graph for the given Mach-O binary.

    Returns:
        (nodes, edges) where
        nodes = list of (func_va, label) — label is selector name for ObjC methods
        edges = list of (caller_va, callee_node) where callee_node is int VA or str selector
    """
    if not HAS_DEPS:
        raise ImportError("lief and capstone required")

    log.info("ObjC graph: parsing %s", binary_path)
    # Always select arm64e slice — lief.parse() defaults to first slice (x86_64)
    # on universal binaries; same rule as angr arch selection.
    _fat = lief.MachO.parse(binary_path)
    if _fat is None:
        raise ValueError(f"lief cannot parse {binary_path}")
    b = None
    for _s in _fat:
        if "ARM64" in str(_s.header.cpu_type):
            b = _s
            break
    if b is None:
        b = list(_fat)[0]
        log.warning("No arm64e slice found, using first slice")

    info = _BinaryInfo()
    info.b = b

    _build_segment_map(info)
    _build_reloc_map(info)
    _build_sel_map(info)
    _find_msgSend_stubs(info)

    log.info("ObjC graph: %d selrefs, %d msgSend stubs",
             len(info.sel_map), len(info.msgSend_addrs))

    # Parse class implementations and edge data using lief content API
    _build_imp_map(info)
    log.info("ObjC graph: %d method IMPs mapped", len(info.imp_map))

    # Build reverse map: sel_name → set of known impl VAs (for function→function projection)
    sel_to_impls: dict = {}
    for imp_va, (cls_name, sel_name) in info.imp_map.items():
        sel_to_impls.setdefault(sel_name, set()).add(imp_va)

    # Get function boundaries from LC_FUNCTION_STARTS (reuse FastC2's approach)
    func_starts = next((c for c in b.commands
                            if c.command == lief.MachO.LoadCommand.TYPE.FUNCTION_STARTS),
                           None)
    if func_starts is None:
                return [], []

    # FastC2-compatible: parse function boundaries
    # Use lief's function_starts if available
    text_seg = next((s for s in b.segments if s.name == "__TEXT"), None)
    if text_seg is None:
                return [], []

    # Use lief's built-in b.functions (parsed from LC_FUNCTION_STARTS + symbols)
    # On fat-binary slices, lief returns offsets from text base, not VAs.
    # Detect and normalise: if max addr < text_base, treat as file offsets.
    text_start = text_seg.virtual_address
    text_size  = text_seg.virtual_size
    raw_addrs  = [f.address for f in b.functions]
    # lief may return file offsets instead of VAs for fat-binary slices.
    # Heuristic: normalise any address < text_start as an offset; keep VAs as-is.
    func_set = set()
    for a in raw_addrs:
            if 0 < a < text_size:          # looks like an offset into __TEXT
                func_set.add(text_start + a)
            elif text_start <= a < text_start + text_size:  # already a VA
                func_set.add(a)
    func_addrs = sorted(func_set)

    func_addrs.sort()
    n_funcs   = len(func_addrs)
    text_end  = text_seg.virtual_address + text_seg.virtual_size

    # Capstone ARM64 with detail=True for operand backtracking
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    nodes = list(func_addrs)
    edges = []
    func_set = set(func_addrs)

    # Layer C: IMP → function edges
    for imp_va, (cls_name, sel_name) in info.imp_map.items():
            if imp_va in func_set:
                nodes.append(imp_va)  # already there as node

    # Layer B: msgSend edge extraction per function
    # Project function→selector edges through sel_to_impls to get function→function edges.
    # For selectors with known implementations (in-binary), emit (caller_va, impl_va) int edges.
    # For external/unresolved selectors, emit (caller_va, sel_str) as fallback (excluded from RMT).
    n_projected = 0
    n_external  = 0
    for i, start_va in enumerate(func_addrs):
            end_va = func_addrs[i+1] if i+1 < n_funcs else text_end
            sel_edges = _extract_msgSend_edges(start_va, end_va, info, md)
            for sel in sel_edges:
                if isinstance(sel, str) and not sel.startswith("swift"):
                    impls = sel_to_impls.get(sel)
                    if impls:
                        for impl_va in impls:
                            edges.append((start_va, impl_va))  # func → func (RMT-compatible)
                        n_projected += len(impls)
                    else:
                        edges.append((start_va, sel))  # external — string fallback
                        n_external += 1
                else:
                    edges.append((start_va, sel))  # swift_indirect or direct int

    log.info("ObjC graph: %d funcs, %d edges (%d projected func→func, %d external str)",
             len(func_addrs), len(edges), n_projected, n_external)
    return func_addrs, edges


if __name__ == "__main__":
    import sys, time, logging
    logging.basicConfig(level=logging.INFO)

    path = sys.argv[1] if len(sys.argv) > 1 else \
           "/path/to/darwin_research/binaries/securityd_system"

    t0 = time.time()
    nodes, edges = build_objc_graph(path)
    elapsed = time.time() - t0

    print(f"\nObjC graph for {path}")
    print(f"  Functions : {len(nodes)}")
    print(f"  Edges     : {len(edges)}")
    print(f"  Time      : {elapsed:.2f}s")

    from collections import Counter
    sel_counts = Counter(e[1] for e in edges if isinstance(e[1], str) and not e[1].startswith("swift"))
    print(f"\nTop 20 most-called selectors:")
    for sel, cnt in sel_counts.most_common(20):
        print(f"  {cnt:4d}x  {sel}")

    swift_ct = sum(1 for e in edges if isinstance(e[1], str) and e[1].startswith("swift"))
    print(f"\nSwift indirect edges: {swift_ct}")
    direct_ct = sum(1 for e in edges if isinstance(e[1], int))
    print(f"Direct BL edges    : {direct_ct}")
