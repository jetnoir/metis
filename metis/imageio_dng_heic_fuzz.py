#!/usr/bin/env python3
"""
imageio_dng_heic_fuzz.py — Structure-aware fuzzer for ImageIO DNG/TIFF and HEIC.

Targets the historically productive attack surface based on CVE analysis:
  - CVE-2025-43300: SamplesPerPixel vs JPEG SOF3 component count disagreement
  - CVE-2023-41064: HEIC/BLASTPASS buffer overflow
  - Project Zero: exotic format parsing bugs

DNG/TIFF mutations target:
  - TIFF IFD tag value contradictions (SamplesPerPixel vs BitsPerSample count)
  - Strip/tile offset pointing past EOF
  - Compression type mismatch with actual data
  - Recursive IFD chains (IFD pointing to itself)
  - Extreme image dimensions with small strip data
  - Integer overflow in dimension × samples calculations

HEIC/ISOBMFF mutations target:
  - Box size contradictions (claimed vs actual)
  - Nested box depth explosion
  - ispe (image spatial extents) vs actual coded image disagreement
  - Invalid codec configuration (hvcC box corruption)
  - Item reference loops
"""

import struct
import subprocess
import sys
import os
import time
import random
import shutil
import zlib

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imageio_harness')
CRASH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'crashes')
TIFF_SEED = '/tmp/mini_tiff_seed.tiff'
HEIC_SEED = '/tmp/mini_heic_seed.heic'


# ═══════════════════════════════════════════════════════════════════
#  TIFF/DNG mutations
# ═══════════════════════════════════════════════════════════════════

def read_tiff(data):
    """Parse TIFF IFD entries. Returns (byte_order, ifd_entries, pixel_offset)."""
    if data[:2] == b'II':
        bo = '<'
    elif data[:2] == b'MM':
        bo = '>'
    else:
        return None, [], 0
    magic, ifd_off = struct.unpack(bo + 'HI', data[2:8])
    n_entries = struct.unpack(bo + 'H', data[ifd_off:ifd_off+2])[0]
    entries = []
    for i in range(n_entries):
        off = ifd_off + 2 + i * 12
        tag, dtype, count, val = struct.unpack(bo + 'HHII', data[off:off+12])
        entries.append({'tag': tag, 'type': dtype, 'count': count, 'value': val, 'offset': off})
    return bo, entries, ifd_off


def set_tiff_tag(data, bo, entries, tag_id, new_value):
    """Set a TIFF tag's value in-place. Returns modified data."""
    data = bytearray(data)
    for e in entries:
        if e['tag'] == tag_id:
            struct.pack_into(bo + 'I', data, e['offset'] + 8, new_value)
            return bytes(data)
    return bytes(data)


def add_tiff_tag(data, bo, ifd_off, tag_id, dtype, count, value):
    """Add a new IFD entry (rebuilds the IFD)."""
    data = bytearray(data)
    n_entries = struct.unpack(bo + 'H', data[ifd_off:ifd_off+2])[0]
    # Insert new entry at end of existing entries
    insert_off = ifd_off + 2 + n_entries * 12
    new_entry = struct.pack(bo + 'HHII', tag_id, dtype, count, value)
    data[insert_off:insert_off] = new_entry
    # Update entry count
    struct.pack_into(bo + 'H', data, ifd_off, n_entries + 1)
    # Fix next-IFD pointer (now shifted by 12 bytes)
    next_ifd_off = ifd_off + 2 + (n_entries + 1) * 12
    if next_ifd_off + 4 <= len(data):
        struct.pack_into(bo + 'I', data, next_ifd_off, 0)
    return bytes(data)


def tiff_mutations(seed_data):
    """Generate TIFF/DNG mutation variants."""
    bo, entries, ifd_off = read_tiff(seed_data)
    if bo is None:
        return []

    mutations = []

    # 1. SamplesPerPixel = 3 but only 1 channel of data (CVE-2025-43300 pattern)
    m = set_tiff_tag(seed_data, bo, entries, 277, 3)
    mutations.append((m, "tiff_spp3_data1"))

    # 2. SamplesPerPixel = 255 (extreme)
    m = set_tiff_tag(seed_data, bo, entries, 277, 255)
    mutations.append((m, "tiff_spp255"))

    # 3. BitsPerSample = 32 but 8-bit data
    m = set_tiff_tag(seed_data, bo, entries, 258, 32)
    mutations.append((m, "tiff_bps32_data8"))

    # 4. Width = 0xFFFF, Height = 0xFFFF but small strip
    m = set_tiff_tag(seed_data, bo, entries, 256, 0xFFFF)
    m = set_tiff_tag(m, bo, entries, 257, 0xFFFF)
    mutations.append((m, "tiff_huge_dims"))

    # 5. Width × Height × SamplesPerPixel overflows 32-bit
    m = set_tiff_tag(seed_data, bo, entries, 256, 65536)
    m = set_tiff_tag(m, bo, entries, 257, 65536)
    m = set_tiff_tag(m, bo, entries, 277, 4)
    mutations.append((m, "tiff_dim_overflow"))

    # 6. StripOffset past EOF
    m = set_tiff_tag(seed_data, bo, entries, 273, 0xFFFFFFFF)
    mutations.append((m, "tiff_strip_past_eof"))

    # 7. StripByteCount = 0
    m = set_tiff_tag(seed_data, bo, entries, 279, 0)
    mutations.append((m, "tiff_strip_zero"))

    # 8. StripByteCount = 0xFFFFFFFF
    m = set_tiff_tag(seed_data, bo, entries, 279, 0xFFFFFFFF)
    mutations.append((m, "tiff_strip_huge"))

    # 9. Compression = 7 (JPEG) but data is raw pixels
    m = set_tiff_tag(seed_data, bo, entries, 259, 7)
    mutations.append((m, "tiff_comp_jpeg_raw_data"))

    # 10. Compression = 8 (Deflate/zlib) but data is raw
    m = set_tiff_tag(seed_data, bo, entries, 259, 8)
    mutations.append((m, "tiff_comp_deflate_raw"))

    # 11. Compression = 34892 (JPEG Lossless — the CVE-2025-43300 format)
    m = set_tiff_tag(seed_data, bo, entries, 259, 34892)
    mutations.append((m, "tiff_comp_jpeglossless"))

    # 12. Recursive IFD: next IFD points to same offset
    m = bytearray(seed_data)
    next_off = ifd_off + 2 + len(entries) * 12
    if next_off + 4 <= len(m):
        struct.pack_into(bo + 'I', m, next_off, ifd_off)
    mutations.append((bytes(m), "tiff_recursive_ifd"))

    # 13. IFD offset = 0 (invalid)
    m = bytearray(seed_data)
    struct.pack_into(bo + 'I', m, 4, 0)
    mutations.append((bytes(m), "tiff_ifd_zero"))

    # 14. IFD offset past EOF
    m = bytearray(seed_data)
    struct.pack_into(bo + 'I', m, 4, 0xFFFFFFFF)
    mutations.append((bytes(m), "tiff_ifd_past_eof"))

    # 15. PhotometricInterpretation = 32803 (CFA — DNG raw)
    m = set_tiff_tag(seed_data, bo, entries, 262, 32803)
    mutations.append((m, "tiff_photometric_cfa"))

    # 16. SamplesPerPixel=2, Compression=34892, small image
    # (exact CVE-2025-43300 trigger pattern)
    m = set_tiff_tag(seed_data, bo, entries, 277, 2)
    m = set_tiff_tag(m, bo, entries, 259, 34892)
    mutations.append((m, "tiff_spp2_jpeglossless"))

    # 17. BitsPerSample = 0
    m = set_tiff_tag(seed_data, bo, entries, 258, 0)
    mutations.append((m, "tiff_bps_zero"))

    # 18. Negative-ish dimension (0x80000000 — MSB set)
    m = set_tiff_tag(seed_data, bo, entries, 256, 0x80000000)
    mutations.append((m, "tiff_width_msb"))

    # 19. Width=1, Height=0x7FFFFFFF (tall thin image — alloc calc risk)
    m = set_tiff_tag(seed_data, bo, entries, 256, 1)
    m = set_tiff_tag(m, bo, entries, 257, 0x7FFFFFFF)
    mutations.append((m, "tiff_1xMAX"))

    # 20. Add DNG-specific tags with conflicting values
    m = add_tiff_tag(seed_data, bo, ifd_off, 50706, 1, 4, 0x01040000)  # DNGVersion 1.4
    m = add_tiff_tag(m, bo, ifd_off + 12, 50707, 1, 4, 0x01060000)  # DNGBackwardVersion 1.6 > 1.4!
    mutations.append((m, "dng_version_conflict"))

    return mutations


# ═══════════════════════════════════════════════════════════════════
#  HEIC/ISOBMFF mutations
# ═══════════════════════════════════════════════════════════════════

def read_boxes(data, offset=0, end=None):
    """Parse ISOBMFF boxes. Returns [(type, offset, size, data)]."""
    if end is None:
        end = len(data)
    boxes = []
    pos = offset
    while pos + 8 <= end:
        size = struct.unpack('>I', data[pos:pos+4])[0]
        btype = data[pos+4:pos+8]
        if size == 0:
            size = end - pos
        elif size == 1 and pos + 16 <= end:
            size = struct.unpack('>Q', data[pos+8:pos+16])[0]
        if size < 8 or pos + size > end:
            break
        boxes.append((btype, pos, size, data[pos+8:pos+size]))
        pos += size
    return boxes


def heic_mutations(seed_data):
    """Generate HEIC/ISOBMFF mutation variants."""
    boxes = read_boxes(seed_data)
    if not boxes:
        return []

    mutations = []

    # 1. ftyp box with wrong brand
    m = bytearray(seed_data)
    # Replace 'heic' brand with 'xxxx'
    ftyp_pos = seed_data.find(b'ftyp')
    if ftyp_pos > 0:
        m[ftyp_pos+4:ftyp_pos+8] = b'xxxx'
    mutations.append((bytes(m), "heic_bad_brand"))

    # 2. Box size = 0 for meta box (extends to EOF — legal but tricky)
    m = bytearray(seed_data)
    meta_pos = seed_data.find(b'meta')
    if meta_pos > 0:
        struct.pack_into('>I', m, meta_pos - 4, 0)
    mutations.append((bytes(m), "heic_meta_size_zero"))

    # 3. Box size mismatch (claimed larger than file)
    m = bytearray(seed_data)
    if meta_pos > 0:
        struct.pack_into('>I', m, meta_pos - 4, 0xFFFFFFFF)
    mutations.append((bytes(m), "heic_meta_size_huge"))

    # 4. Box size = 1 (extended size) but no 64-bit size follows
    m = bytearray(seed_data)
    if meta_pos > 0:
        struct.pack_into('>I', m, meta_pos - 4, 1)
    mutations.append((bytes(m), "heic_meta_extended_nosize"))

    # 5. Truncate file mid-box
    for pct in [25, 50, 75]:
        cut = len(seed_data) * pct // 100
        mutations.append((seed_data[:cut], f"heic_truncate_{pct}pct"))

    # 6. Duplicate ftyp box
    ftyp_end = 0
    for btype, pos, size, _ in boxes:
        if btype == b'ftyp':
            ftyp_end = pos + size
            break
    if ftyp_end > 0:
        ftyp_data = seed_data[:ftyp_end]
        m = ftyp_data + ftyp_data + seed_data[ftyp_end:]
        mutations.append((m, "heic_dup_ftyp"))

    # 7. Corrupt ispe (image spatial extents) if present
    ispe_pos = seed_data.find(b'ispe')
    if ispe_pos > 0 and ispe_pos + 16 <= len(seed_data):
        # ispe: version(4) + width(4) + height(4)
        m = bytearray(seed_data)
        struct.pack_into('>II', m, ispe_pos + 8, 0xFFFFFFFF, 0xFFFFFFFF)
        mutations.append((bytes(m), "heic_ispe_huge"))

        m = bytearray(seed_data)
        struct.pack_into('>II', m, ispe_pos + 8, 0, 0)
        mutations.append((bytes(m), "heic_ispe_zero"))

    # 8. Corrupt hvcC (HEVC config) if present
    hvcc_pos = seed_data.find(b'hvcC')
    if hvcc_pos > 0:
        m = bytearray(seed_data)
        # Corrupt the first 16 bytes of hvcC data
        for i in range(min(16, len(m) - hvcc_pos - 4)):
            m[hvcc_pos + 4 + i] = 0xFF
        mutations.append((bytes(m), "heic_hvcc_corrupt"))

    # 9. Random byte flips in the coded image data (mdat box)
    mdat_pos = seed_data.find(b'mdat')
    if mdat_pos > 0:
        for i in range(5):
            m = bytearray(seed_data)
            off = mdat_pos + 8 + random.randint(0, max(1, len(m) - mdat_pos - 16))
            if off < len(m):
                m[off] ^= 0xFF
            mutations.append((bytes(m), f"heic_mdat_flip_{i}"))

    # 10. Inject unknown box type between ftyp and meta
    if ftyp_end > 0:
        fake_box = struct.pack('>I', 16) + b'FUZZ' + b'\xDE\xAD\xBE\xEF'
        m = seed_data[:ftyp_end] + fake_box + seed_data[ftyp_end:]
        mutations.append((m, "heic_inject_unknown_box"))

    return mutations


# ═══════════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════════

def run_harness(path, timeout_s=5):
    try:
        r = subprocess.run([HARNESS, path], capture_output=True, timeout=timeout_s)
        return r.returncode, r.returncode < 0, r.stderr.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"


def main():
    random.seed(42)
    os.makedirs(CRASH_DIR, exist_ok=True)
    tmp = '/tmp/imageio_dng_heic_fuzz.tmp'

    print("=" * 65)
    print("  ImageIO DNG/TIFF + HEIC Fuzzer")
    print("  Targeting CVE-2025-43300 pattern (metadata disagreement)")
    print("=" * 65)

    crashes = 0
    total = 0
    t0 = time.monotonic()

    # ── TIFF/DNG mutations ──
    if os.path.exists(TIFF_SEED):
        with open(TIFF_SEED, 'rb') as f:
            tiff_data = f.read()
        tiff_muts = tiff_mutations(tiff_data)
        print(f"\n[TIFF/DNG] {len(tiff_muts)} mutations from {len(tiff_data)}B seed\n")

        for data, name in tiff_muts:
            with open(tmp, 'wb') as f:
                f.write(data)
            rc, crashed, stderr = run_harness(tmp)
            total += 1
            status = "CRASH!" if crashed else f"rc={rc}"
            print(f"  [{total:3d}] {name:35s} {len(data):6d}B  {status}")
            if crashed:
                crashes += 1
                cp = os.path.join(CRASH_DIR, f"crash_{total}_{name}.tiff")
                shutil.copy(tmp, cp)
                print(f"        *** SAVED: {cp} (signal {-rc})")
    else:
        print(f"\n[TIFF/DNG] SKIPPED — no seed at {TIFF_SEED}")

    # ── HEIC mutations ──
    if os.path.exists(HEIC_SEED):
        with open(HEIC_SEED, 'rb') as f:
            heic_data = f.read()
        heic_muts = heic_mutations(heic_data)
        print(f"\n[HEIC] {len(heic_muts)} mutations from {len(heic_data)}B seed\n")

        for data, name in heic_muts:
            with open(tmp, 'wb') as f:
                f.write(data)
            rc, crashed, stderr = run_harness(tmp)
            total += 1
            status = "CRASH!" if crashed else f"rc={rc}"
            print(f"  [{total:3d}] {name:35s} {len(data):6d}B  {status}")
            if crashed:
                crashes += 1
                cp = os.path.join(CRASH_DIR, f"crash_{total}_{name}.heic")
                shutil.copy(tmp, cp)
                print(f"        *** SAVED: {cp} (signal {-rc})")
    else:
        print(f"\n[HEIC] SKIPPED — no seed at {HEIC_SEED}")

    # ── Combo phase: random cross-format stacking ──
    print(f"\n[COMBO] 500 random TIFF mutations\n")
    if os.path.exists(TIFF_SEED):
        with open(TIFF_SEED, 'rb') as f:
            tiff_data = f.read()
        bo, entries, ifd_off = read_tiff(tiff_data)

        for i in range(500):
            m = bytearray(tiff_data)
            names = []

            # Random tag value mutations (2-4 per iteration)
            for _ in range(random.randint(2, 4)):
                tag_choices = [256, 257, 258, 259, 262, 273, 277, 278, 279]
                tag = random.choice(tag_choices)
                val_choices = [0, 1, 2, 3, 7, 8, 255, 0x7FFF, 0xFFFF,
                               0x7FFFFFFF, 0xFFFFFFFF, 0x80000000,
                               34892, 32803, 65535]
                val = random.choice(val_choices)
                m_bytes = set_tiff_tag(bytes(m), bo, entries, tag, val)
                m = bytearray(m_bytes)
                names.append(f"t{tag}={val}")

            with open(tmp, 'wb') as f:
                f.write(bytes(m))
            rc, crashed, stderr = run_harness(tmp)
            total += 1

            if crashed:
                crashes += 1
                combo = '+'.join(names)
                cp = os.path.join(CRASH_DIR, f"crash_{total}_tiff_combo.tiff")
                shutil.copy(tmp, cp)
                print(f"  [{total:3d}] {combo[:55]:55s} CRASH! → {cp}")
            elif total % 50 == 0:
                combo = '+'.join(names)
                print(f"  [{total:3d}] {combo[:55]:55s} rc={rc}")

    if os.path.exists(tmp):
        os.unlink(tmp)

    elapsed = time.monotonic() - t0
    print()
    print("=" * 65)
    print(f"  Complete: {total} tests, {crashes} crashes, {elapsed:.1f}s")
    print(f"  Rate: {total/elapsed:.1f} tests/sec")
    if crashes:
        print(f"  CRASHES SAVED TO: {CRASH_DIR}/")
    print("=" * 65)

    return 0 if crashes == 0 else 2


if __name__ == '__main__':
    sys.exit(main())
