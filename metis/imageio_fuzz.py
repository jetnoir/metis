#!/usr/bin/env python3
"""
imageio_fuzz.py — Structure-aware PNG fuzzer for Apple ImageIO.

Targets the CVE-pattern attack surface:
  1. IHDR field disagreement (width/height/bitdepth/colortype contradictions)
  2. iDOT Apple-proprietary chunk injection (various sizes including 0)
  3. Chunk length/CRC mismatch (parser confusion)
  4. iCCP profile corruption (embedded ICC parsing)
  5. eXIf metadata corruption
  6. IDAT decompression bombs (truncated/corrupted zlib)
  7. Duplicate/out-of-order critical chunks

Based on patterns from CVE-2023-41064, CVE-2025-43300 (metadata disagreement),
and the iDOT zero-length crash.
"""

import struct
import subprocess
import sys
import os
import time
import random
import zlib
import shutil

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imageio_harness')
CRASH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'crashes')
SEED = '/tmp/mini_seed.png'


def read_png_chunks(data):
    """Parse PNG into (type, data, crc, offset) tuples."""
    chunks = []
    pos = 8  # skip signature
    while pos + 8 <= len(data):
        length = struct.unpack('>I', data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        if pos + 12 + length > len(data):
            break
        cdata = data[pos+8:pos+8+length]
        crc = data[pos+8+length:pos+12+length]
        chunks.append((ctype, cdata, crc, pos))
        pos += 12 + length
    return chunks


def make_chunk(ctype, cdata):
    """Build a PNG chunk with correct CRC."""
    length = struct.pack('>I', len(cdata))
    crc = struct.pack('>I', zlib.crc32(ctype + cdata) & 0xffffffff)
    return length + ctype + cdata + crc


def make_chunk_bad_crc(ctype, cdata, crc_val=0xDEADBEEF):
    """Build a PNG chunk with deliberately wrong CRC."""
    length = struct.pack('>I', len(cdata))
    crc = struct.pack('>I', crc_val & 0xffffffff)
    return length + ctype + cdata + crc


def make_chunk_bad_length(ctype, cdata, claimed_length):
    """Build a chunk where length field doesn't match actual data."""
    length = struct.pack('>I', claimed_length & 0xffffffff)
    crc = struct.pack('>I', zlib.crc32(ctype + cdata) & 0xffffffff)
    return length + ctype + cdata + crc


def reassemble_png(chunks):
    """Reassemble PNG from chunk list. Each chunk is (type_bytes, data_bytes)."""
    sig = b'\x89PNG\r\n\x1a\n'
    out = sig
    for ctype, cdata in chunks:
        out += make_chunk(ctype, cdata)
    return out


# ── Mutation strategies ──────────────────────────────────────────────

def mut_ihdr_width_zero(seed_chunks):
    """IHDR width = 0 (invalid)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = b'\x00\x00\x00\x00' + cdata[4:]  # width=0
        chunks.append((ctype, cdata))
    return chunks, "ihdr_width_zero"

def mut_ihdr_width_huge(seed_chunks):
    """IHDR width = 0xFFFFFFFF (overflow risk)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = b'\xff\xff\xff\xff' + cdata[4:]
        chunks.append((ctype, cdata))
    return chunks, "ihdr_width_huge"

def mut_ihdr_height_zero(seed_chunks):
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = cdata[:4] + b'\x00\x00\x00\x00' + cdata[8:]
        chunks.append((ctype, cdata))
    return chunks, "ihdr_height_zero"

def mut_ihdr_colortype_invalid(seed_chunks):
    """Invalid color type (e.g., 5 which doesn't exist)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = cdata[:9] + bytes([5]) + cdata[10:]
        chunks.append((ctype, cdata))
    return chunks, "ihdr_colortype_5"

def mut_ihdr_bitdepth_mismatch(seed_chunks):
    """Bit depth 3 (invalid for any color type)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = cdata[:8] + bytes([3]) + cdata[9:]
        chunks.append((ctype, cdata))
    return chunks, "ihdr_bitdepth_3"

def mut_ihdr_colortype_bitdepth_disagree(seed_chunks):
    """Color type 2 (truecolor) with bit depth 1 (only valid for grayscale)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = cdata[:8] + bytes([1, 2]) + cdata[10:]  # bitdepth=1, colortype=2
        chunks.append((ctype, cdata))
    return chunks, "ihdr_ct2_bd1"

def mut_inject_idot_zero(seed_chunks):
    """Inject iDOT chunk with length 0 (known crash pattern)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            chunks.append((b'iDOT', b''))  # zero-length iDOT
    return chunks, "idot_zero"

def mut_inject_idot_huge(seed_chunks):
    """iDOT with large claimed size."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            chunks.append((b'iDOT', b'\x00' * 1024))
    return chunks, "idot_1024"

def mut_inject_idot_negative(seed_chunks):
    """iDOT with data that could cause signed interpretation issues."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            chunks.append((b'iDOT', b'\xff' * 28))  # all 0xFF
    return chunks, "idot_0xff"

def mut_inject_idot_partial(seed_chunks):
    """iDOT with only 4 bytes (partial struct)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            chunks.append((b'iDOT', b'\x00\x00\x00\x01'))
    return chunks, "idot_4bytes"

def mut_duplicate_ihdr(seed_chunks):
    """Two IHDR chunks with different parameters."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            # Second IHDR with different dimensions
            alt = struct.pack('>II', 9999, 9999) + cdata[8:]
            chunks.append((b'IHDR', alt))
    return chunks, "dup_ihdr"

def mut_idat_truncated(seed_chunks):
    """Truncate IDAT data (corrupt zlib stream)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IDAT':
            cdata = cdata[:len(cdata)//4]  # keep only first quarter
        chunks.append((ctype, cdata))
    return chunks, "idat_truncated"

def mut_idat_random(seed_chunks):
    """Replace IDAT with random data (invalid zlib)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IDAT':
            cdata = bytes(random.getrandbits(8) for _ in range(len(cdata)))
        chunks.append((ctype, cdata))
    return chunks, "idat_random"

def mut_iccp_corrupt(seed_chunks):
    """Corrupt the ICC profile data."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'iCCP':
            # Keep the name but corrupt the profile data
            null_pos = cdata.find(b'\x00')
            if null_pos > 0:
                header = cdata[:null_pos+2]  # name + null + compression method
                cdata = header + b'\xff' * 256
        chunks.append((ctype, cdata))
    return chunks, "iccp_corrupt"

def mut_iccp_huge(seed_chunks):
    """Oversized ICC profile."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'iCCP':
            null_pos = cdata.find(b'\x00')
            if null_pos > 0:
                header = cdata[:null_pos+2]
                # Compress a large payload
                big = zlib.compress(b'\x00' * 65536)
                cdata = header + big
        chunks.append((ctype, cdata))
    return chunks, "iccp_huge"

def mut_exif_corrupt(seed_chunks):
    """Corrupt eXIf data."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'eXIf':
            cdata = b'\xff' * len(cdata)
        chunks.append((ctype, cdata))
    return chunks, "exif_corrupt"

def mut_chunk_order_reversed(seed_chunks):
    """Reverse non-critical chunk order (keep IHDR first, IEND last)."""
    ihdr = None
    iend = None
    middle = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            ihdr = (ctype, cdata)
        elif ctype == b'IEND':
            iend = (ctype, cdata)
        else:
            middle.append((ctype, cdata))
    middle.reverse()
    chunks = [ihdr] + middle + [iend]
    return chunks, "chunk_reversed"

def mut_idat_before_ihdr(seed_chunks):
    """Move IDAT before IHDR (invalid ordering)."""
    ihdr = None
    idat_list = []
    other = []
    iend = None
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            ihdr = (ctype, cdata)
        elif ctype == b'IDAT':
            idat_list.append((ctype, cdata))
        elif ctype == b'IEND':
            iend = (ctype, cdata)
        else:
            other.append((ctype, cdata))
    chunks = idat_list + [ihdr] + other + [iend]
    return chunks, "idat_before_ihdr"

def mut_no_iend(seed_chunks):
    """Remove IEND (missing terminator)."""
    chunks = [(ctype, cdata) for ctype, cdata, _, _ in seed_chunks if ctype != b'IEND']
    return chunks, "no_iend"

def mut_multiple_idot(seed_chunks):
    """Multiple iDOT chunks with different data."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        chunks.append((ctype, cdata))
        if ctype == b'IHDR':
            for i in range(5):
                chunks.append((b'iDOT', struct.pack('>7I', *[i*100+j for j in range(7)])))
    return chunks, "multi_idot_5"

def mut_bad_crc_ihdr(seed_chunks):
    """IHDR with wrong CRC — does ImageIO validate?"""
    # Special: return raw bytes instead of chunk list
    data = b'\x89PNG\r\n\x1a\n'
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            data += make_chunk_bad_crc(ctype, cdata, 0x00000000)
        else:
            data += make_chunk(ctype, cdata)
    return None, "bad_crc_ihdr", data

def mut_length_overflow_ihdr(seed_chunks):
    """IHDR with length field claiming 0xFFFFFFFF but only 13 bytes of data."""
    data = b'\x89PNG\r\n\x1a\n'
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            data += make_chunk_bad_length(ctype, cdata, 0xFFFFFFFF)
        else:
            data += make_chunk(ctype, cdata)
    return None, "length_overflow_ihdr", data

def mut_width_height_overflow(seed_chunks):
    """Width * height overflows 32-bit (width=65536, height=65536)."""
    chunks = []
    for ctype, cdata, _, _ in seed_chunks:
        if ctype == b'IHDR':
            cdata = struct.pack('>II', 65536, 65536) + cdata[8:]
        chunks.append((ctype, cdata))
    return chunks, "wh_overflow"


# ── Mutation registry ────────────────────────────────────────────────

MUTATIONS = [
    mut_ihdr_width_zero,
    mut_ihdr_width_huge,
    mut_ihdr_height_zero,
    mut_ihdr_colortype_invalid,
    mut_ihdr_bitdepth_mismatch,
    mut_ihdr_colortype_bitdepth_disagree,
    mut_inject_idot_zero,
    mut_inject_idot_huge,
    mut_inject_idot_negative,
    mut_inject_idot_partial,
    mut_duplicate_ihdr,
    mut_idat_truncated,
    mut_idat_random,
    mut_iccp_corrupt,
    mut_iccp_huge,
    mut_exif_corrupt,
    mut_chunk_order_reversed,
    mut_idat_before_ihdr,
    mut_no_iend,
    mut_multiple_idot,
    mut_width_height_overflow,
]

# These return raw bytes (special CRC/length mutations)
RAW_MUTATIONS = [
    mut_bad_crc_ihdr,
    mut_length_overflow_ihdr,
]


def run_harness(png_path, timeout_s=5):
    """Run the ImageIO harness. Returns (returncode, crashed, stderr)."""
    try:
        r = subprocess.run(
            [HARNESS, png_path],
            capture_output=True, timeout=timeout_s,
        )
        crashed = r.returncode < 0  # negative = killed by signal
        return r.returncode, crashed, r.stderr.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"


def main():
    random.seed(42)

    if not os.path.exists(HARNESS):
        print(f"ERROR: harness not found at {HARNESS}")
        print("Compile: cc -o imageio_harness imageio_harness.c "
              "-framework CoreGraphics -framework ImageIO -framework CoreFoundation")
        return 1

    os.makedirs(CRASH_DIR, exist_ok=True)

    with open(SEED, 'rb') as f:
        seed_data = f.read()
    seed_chunks = read_png_chunks(seed_data)

    print("=" * 65)
    print("  ImageIO PNG Fuzzer — structure-aware mutations")
    print(f"  Seed: {SEED} ({len(seed_data)} bytes, {len(seed_chunks)} chunks)")
    print(f"  Harness: {HARNESS}")
    print(f"  Mutations: {len(MUTATIONS) + len(RAW_MUTATIONS)} deterministic")
    print("=" * 65)
    print()

    tmp_path = '/tmp/imageio_fuzz_test.png'
    crashes = 0
    errors = 0
    total = 0
    t0 = time.monotonic()

    # Phase 1: Deterministic mutations
    print("[Phase 1] Deterministic mutations\n")

    for mut_fn in MUTATIONS:
        result = mut_fn(seed_chunks)
        chunk_list, name = result[0], result[1]
        png_data = reassemble_png(chunk_list)

        with open(tmp_path, 'wb') as f:
            f.write(png_data)

        rc, crashed, stderr = run_harness(tmp_path)
        total += 1

        status = "CRASH!" if crashed else f"rc={rc}"
        print(f"  [{total:3d}] {name:30s} {len(png_data):6d}B  {status}")

        if crashed:
            crashes += 1
            crash_path = os.path.join(CRASH_DIR, f"crash_{total}_{name}.png")
            shutil.copy(tmp_path, crash_path)
            print(f"        *** SAVED: {crash_path}")
            print(f"        *** Signal: {-rc}, stderr: {stderr[:200]}")

    # Raw mutations (special CRC/length)
    for mut_fn in RAW_MUTATIONS:
        _, name, png_data = mut_fn(seed_chunks)

        with open(tmp_path, 'wb') as f:
            f.write(png_data)

        rc, crashed, stderr = run_harness(tmp_path)
        total += 1

        status = "CRASH!" if crashed else f"rc={rc}"
        print(f"  [{total:3d}] {name:30s} {len(png_data):6d}B  {status}")

        if crashed:
            crashes += 1
            crash_path = os.path.join(CRASH_DIR, f"crash_{total}_{name}.png")
            shutil.copy(tmp_path, crash_path)
            print(f"        *** SAVED: {crash_path}")

    # Phase 2: Random combinations (2-3 mutations stacked)
    print(f"\n[Phase 2] Random combinations (500 iterations)\n")

    for i in range(500):
        # Start from seed
        current_chunks = list(seed_chunks)
        names = []

        n_muts = random.randint(2, 3)
        for _ in range(n_muts):
            mut_fn = random.choice(MUTATIONS)
            try:
                result = mut_fn(current_chunks)
                new_chunks, name = result[0], result[1]
                if new_chunks is None:
                    continue
                names.append(name)
                current_chunks = [(ct, cd, b'', 0) for ct, cd in new_chunks
                                  if ct is not None]
            except Exception:
                continue

        png_data = reassemble_png([(ct, cd) for ct, cd, _, _ in current_chunks])

        with open(tmp_path, 'wb') as f:
            f.write(png_data)

        rc, crashed, stderr = run_harness(tmp_path)
        total += 1

        if crashed:
            crashes += 1
            combo = '+'.join(names)
            crash_path = os.path.join(CRASH_DIR, f"crash_{total}_combo.png")
            shutil.copy(tmp_path, crash_path)
            print(f"  [{total:3d}] {combo[:50]:50s} CRASH! → {crash_path}")
        elif total % 50 == 0:
            combo = '+'.join(names)
            print(f"  [{total:3d}] {combo[:50]:50s} rc={rc}")

    elapsed = time.monotonic() - t0
    os.unlink(tmp_path)

    print()
    print("=" * 65)
    print(f"  Complete: {total} tests, {crashes} crashes, {elapsed:.1f}s")
    print(f"  Rate: {total/elapsed:.1f} tests/sec")
    if crashes:
        print(f"  Crashes saved to: {CRASH_DIR}/")
    print("=" * 65)

    return 0 if crashes == 0 else 2


if __name__ == '__main__':
    sys.exit(main())
