#!/usr/bin/env python3
"""
imageio_tiff_disagree.py — TIFF tag pair disagreement fuzzer for Apple ImageIO.

Instead of single-tag corruption (already tested) or the known CVE-2025-43300
pattern (patched), this targets UNEXPLORED tag PAIR contradictions where two
TIFF tags interact during decompression/rendering and may produce unexpected
buffer sizes.

Tag pair attack surface:
  - PlanarConfiguration vs SamplesPerPixel (chunky vs planar layout)
  - TileWidth/TileLength vs ImageWidth/ImageLength (tiled vs stripped)
  - RowsPerStrip vs ImageLength (strip count calculation)
  - StripByteCounts vs computed expected size
  - BitsPerSample array vs SamplesPerPixel count
  - SubIFDs with conflicting dimensions
  - JPEGTables vs actual JPEG stream headers
  - Predictor tag with incompatible compression
  - ExtraSamples count vs SamplesPerPixel
  - SampleFormat vs BitsPerSample
"""

import struct
import subprocess
import os
import sys
import time
import random
import shutil

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imageio_harness')
CRASH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'crashes')


def make_tiff(entries_dict, pixel_data=b'\x80' * 64, byte_order='<'):
    """
    Build a TIFF from a dictionary of tag_id → (type, count, value_or_data).

    Types: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL
    For values that fit in 4 bytes, stored inline.
    For larger data, stored after IFD with offset pointer.
    """
    header = (b'II' if byte_order == '<' else b'MM')
    header += struct.pack(byte_order + 'HI', 42, 8)  # magic + IFD offset

    # Sort tags (TIFF spec requires sorted IFD)
    sorted_tags = sorted(entries_dict.keys())
    n_entries = len(sorted_tags)

    # IFD starts at offset 8
    ifd_size = 2 + n_entries * 12 + 4  # count + entries + next_ifd
    data_offset = 8 + ifd_size  # overflow data starts after IFD

    # We need pixel data after overflow data
    overflow_data = b''
    ifd_entries = []

    for tag in sorted_tags:
        dtype, count, value = entries_dict[tag]

        # Calculate byte size
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
        total_bytes = count * type_sizes.get(dtype, 1)

        if total_bytes <= 4:
            # Value fits inline
            if dtype == 3 and count == 1:
                val_bytes = struct.pack(byte_order + 'HH', value, 0)
            elif dtype == 4 and count == 1:
                val_bytes = struct.pack(byte_order + 'I', value)
            elif dtype == 1 and count <= 4:
                if isinstance(value, (list, tuple)):
                    val_bytes = bytes(value) + b'\x00' * (4 - count)
                else:
                    val_bytes = struct.pack(byte_order + 'I', value)
            else:
                val_bytes = struct.pack(byte_order + 'I', value if isinstance(value, int) else 0)

            ifd_entries.append(struct.pack(byte_order + 'HHII', tag, dtype, count,
                                           struct.unpack(byte_order + 'I', val_bytes)[0]))
        else:
            # Value needs offset pointer
            actual_offset = data_offset + len(overflow_data)
            ifd_entries.append(struct.pack(byte_order + 'HHII', tag, dtype, count, actual_offset))
            if isinstance(value, bytes):
                overflow_data += value
            elif isinstance(value, (list, tuple)):
                for v in value:
                    if dtype == 3:
                        overflow_data += struct.pack(byte_order + 'H', v)
                    elif dtype == 4:
                        overflow_data += struct.pack(byte_order + 'I', v)
                    elif dtype == 5:
                        overflow_data += struct.pack(byte_order + 'II', v[0], v[1])
                    else:
                        overflow_data += struct.pack('B', v)

    # Build IFD
    ifd = struct.pack(byte_order + 'H', n_entries)
    for e in ifd_entries:
        ifd += e
    ifd += struct.pack(byte_order + 'I', 0)  # next IFD

    # Pixel data offset
    pixel_offset = data_offset + len(overflow_data)

    # Fix StripOffsets to point to pixel data
    # Re-scan entries to find tag 273 and update its value
    result = header + ifd + overflow_data + pixel_data
    result = bytearray(result)

    # Find and fix StripOffsets (tag 273) and TileOffsets (tag 324)
    for i, tag in enumerate(sorted_tags):
        if tag in (273, 324):
            entry_offset = 8 + 2 + i * 12 + 8  # offset to value field
            dtype, count, _ = entries_dict[tag]
            if count == 1:
                struct.pack_into(byte_order + 'I', result, entry_offset, pixel_offset)

    return bytes(result)


def generate_disagreement_mutations():
    """Generate TIFF files with conflicting tag pairs."""
    mutations = []

    base_pixel = b'\x80' * 256  # enough for small images

    # ── 1. PlanarConfiguration vs SamplesPerPixel ──
    # PlanarConfig=2 (planar) but SPP=1 (grayscale — can't be planar)
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 2),  # RGB
        273: (4, 1, 0), 277: (3, 1, 1),  # SPP=1
        278: (3, 1, 8), 279: (4, 1, 64),
        284: (3, 1, 2),  # PlanarConfig=Planar — but SPP=1!
    }, base_pixel), "planar_spp1"))

    # PlanarConfig=2 (planar) with SPP=3 but only 1 strip (expects 3 strips)
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 3, [8, 8, 8]),
        259: (3, 1, 1), 262: (3, 1, 2),  # RGB
        273: (4, 1, 0), 277: (3, 1, 3),  # SPP=3
        278: (3, 1, 8), 279: (4, 1, 64), # 1 strip, 64 bytes
        284: (3, 1, 2),  # Planar → expects 3 separate planes
    }, base_pixel), "planar_spp3_1strip"))

    # PlanarConfig=1 (chunky) with SPP=3 but BitsPerSample has only 1 entry
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),  # BPS: 1 entry
        259: (3, 1, 1), 262: (3, 1, 2),
        273: (4, 1, 0), 277: (3, 1, 3),  # SPP=3
        278: (3, 1, 8), 279: (4, 1, 64),
        284: (3, 1, 1),  # Chunky
    }, base_pixel), "chunky_spp3_bps1entry"))

    # ── 2. Tiled vs Stripped contradictions ──
    # TileWidth + TileLength present (tiled) but also StripOffsets (stripped)
    mutations.append((make_tiff({
        256: (3, 1, 16), 257: (3, 1, 16), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0),   # StripOffsets (stripped!)
        277: (3, 1, 1), 278: (3, 1, 16), 279: (4, 1, 256),
        322: (3, 1, 8),   # TileWidth (tiled!)
        323: (3, 1, 8),   # TileLength (tiled!)
    }, base_pixel), "tiled_AND_stripped"))

    # TileWidth > ImageWidth
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        277: (3, 1, 1),
        322: (3, 1, 65535),  # TileWidth >> ImageWidth
        323: (3, 1, 65535),  # TileLength >> ImageLength
        324: (4, 1, 0),      # TileOffsets
        325: (4, 1, 256),    # TileByteCounts
    }, base_pixel), "tile_gt_image"))

    # TileWidth = 0
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1), 277: (3, 1, 1),
        322: (3, 1, 0),   # TileWidth = 0 (division by zero?)
        323: (3, 1, 8),
        324: (4, 1, 0), 325: (4, 1, 256),
    }, base_pixel), "tile_width_zero"))

    # ── 3. RowsPerStrip contradictions ──
    # RowsPerStrip > ImageLength
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1),
        278: (3, 1, 65535),  # RowsPerStrip >> ImageLength
        279: (4, 1, 64),
    }, base_pixel), "rps_gt_height"))

    # RowsPerStrip = 0
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1),
        278: (3, 1, 0),     # RowsPerStrip = 0 (division by zero?)
        279: (4, 1, 64),
    }, base_pixel), "rps_zero"))

    # ── 4. StripByteCounts contradictions ──
    # StripByteCounts much larger than actual data
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8),
        279: (4, 1, 0x7FFFFFFF),  # Claims 2GB of strip data
    }, base_pixel), "stripbc_2gb"))

    # StripByteCounts = 0 but image has data
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8),
        279: (4, 1, 0),  # 0 bytes
    }, base_pixel), "stripbc_zero"))

    # ── 5. Predictor with incompatible compression ──
    # Predictor=2 (horizontal diff) but Compression=1 (none)
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8), 279: (4, 1, 64),
        317: (3, 1, 2),  # Predictor=horizontal differencing
    }, base_pixel), "predictor2_nocomp"))

    # Predictor=3 (floating point) with 8-bit integer data
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 8), 262: (3, 1, 1),  # Deflate compression
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8), 279: (4, 1, 64),
        317: (3, 1, 3),  # Predictor=floating point
    }, base_pixel), "predictor3_int8"))

    # ── 6. ExtraSamples contradictions ──
    # ExtraSamples says 2 extra but SPP=1
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1),  # SPP=1
        278: (3, 1, 8), 279: (4, 1, 64),
        338: (3, 2, [1, 2]),  # ExtraSamples: 2 extra (assoc alpha + unassoc alpha)
    }, base_pixel), "extra2_spp1"))

    # ── 7. SampleFormat contradictions ──
    # SampleFormat=3 (IEEE float) but BitsPerSample=8
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8), 279: (4, 1, 64),
        339: (3, 1, 3),  # SampleFormat = IEEE float
    }, base_pixel), "samplefmt_float_bps8"))

    # SampleFormat=4 (undefined) — parser may assume integer
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 277: (3, 1, 1), 278: (3, 1, 8), 279: (4, 1, 64),
        339: (3, 1, 4),  # SampleFormat = undefined
    }, base_pixel), "samplefmt_undefined"))

    # ── 8. PhotometricInterpretation contradictions ──
    # Photometric=6 (YCbCr) but SPP=1 (expects 3)
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 6),  # YCbCr
        273: (4, 1, 0), 277: (3, 1, 1),  # SPP=1 — but YCbCr needs 3!
        278: (3, 1, 8), 279: (4, 1, 64),
    }, base_pixel), "ycbcr_spp1"))

    # Photometric=5 (CMYK) but SPP=3 (expects 4)
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 3, [8, 8, 8]),
        259: (3, 1, 1), 262: (3, 1, 5),  # CMYK
        273: (4, 1, 0), 277: (3, 1, 3),  # SPP=3 — but CMYK needs 4!
        278: (3, 1, 8), 279: (4, 1, 192),
    }, base_pixel), "cmyk_spp3"))

    # ── 9. Multiple strips with wrong count ──
    # 4 StripOffsets but only 1 StripByteCount
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 4, [0, 64, 128, 192]),   # 4 strip offsets
        277: (3, 1, 1), 278: (3, 1, 2),   # 2 rows per strip → 4 strips
        279: (4, 1, 16),                    # But only 1 byte count!
    }, base_pixel), "4strips_1bc"))

    # ── 10. Orientation with pixel layout ──
    # Orientation=8 (left-bottom) changes how pixels are laid out
    mutations.append((make_tiff({
        256: (3, 1, 8), 257: (3, 1, 8), 258: (3, 1, 8),
        259: (3, 1, 1), 262: (3, 1, 1),
        273: (4, 1, 0), 274: (3, 1, 8),  # Orientation = left-bottom
        277: (3, 1, 1), 278: (3, 1, 8), 279: (4, 1, 64),
    }, base_pixel), "orientation_8"))

    return mutations


def run_harness(path, timeout_s=5):
    try:
        r = subprocess.run([HARNESS, path], capture_output=True, timeout=timeout_s)
        return r.returncode, r.returncode < 0, r.stderr.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"


def main():
    random.seed(42)
    os.makedirs(CRASH_DIR, exist_ok=True)

    mutations = generate_disagreement_mutations()

    print("=" * 65)
    print("  ImageIO TIFF Tag Pair Disagreement Fuzzer")
    print(f"  {len(mutations)} deterministic mutations")
    print("=" * 65)
    print()

    tmp = '/tmp/tiff_disagree_test.tiff'
    crashes = 0
    total = 0
    t0 = time.monotonic()

    for data, name in mutations:
        with open(tmp, 'wb') as f:
            f.write(data)
        rc, crashed, stderr = run_harness(tmp)
        total += 1
        status = "CRASH!" if crashed else f"rc={rc}"
        print(f"  [{total:3d}] {name:40s} {len(data):5d}B  {status}")
        if crashed:
            crashes += 1
            cp = os.path.join(CRASH_DIR, f"crash_{total}_{name}.tiff")
            shutil.copy(tmp, cp)
            print(f"        *** CRASH SAVED: {cp} (signal {-rc})")
            print(f"        *** stderr: {stderr[:200]}")

    # Phase 2: random combos of tag values
    print(f"\n[Phase 2] 500 random tag pair combos\n")

    tag_pool = {
        256: [1, 8, 256, 65535, 0x7FFFFFFF],
        257: [1, 8, 256, 65535, 0x7FFFFFFF],
        258: [1, 4, 8, 16, 32],
        259: [1, 2, 5, 7, 8, 32773, 34892],
        262: [0, 1, 2, 3, 5, 6, 8, 32803],
        277: [1, 2, 3, 4, 255],
        278: [0, 1, 8, 255, 65535],
        279: [0, 1, 64, 256, 0x7FFFFFFF],
        284: [1, 2],
        317: [1, 2, 3],
        338: [0, 1, 2],
        339: [1, 2, 3, 4],
    }

    for i in range(500):
        entries = {}
        # Pick 6-10 random tags with random values
        tags = random.sample(list(tag_pool.keys()), random.randint(6, min(10, len(tag_pool))))
        for tag in tags:
            val = random.choice(tag_pool[tag])
            entries[tag] = (3 if val <= 65535 else 4, 1, val)
        # Ensure mandatory tags
        entries.setdefault(256, (3, 1, 8))
        entries.setdefault(257, (3, 1, 8))
        entries.setdefault(258, (3, 1, 8))
        entries.setdefault(273, (4, 1, 0))

        try:
            data = make_tiff(entries, b'\x80' * 256)
        except Exception as e:
            continue

        with open(tmp, 'wb') as f:
            f.write(data)
        rc, crashed, stderr = run_harness(tmp)
        total += 1

        if crashed:
            crashes += 1
            desc = '+'.join(f"t{t}={entries[t][2]}" for t in sorted(entries.keys()))
            cp = os.path.join(CRASH_DIR, f"crash_{total}_combo.tiff")
            shutil.copy(tmp, cp)
            print(f"  [{total:3d}] {desc[:55]:55s} CRASH! → {cp}")
        elif total % 50 == 0:
            desc = '+'.join(f"t{t}={entries[t][2]}" for t in sorted(entries.keys())[:4])
            print(f"  [{total:3d}] {desc[:55]:55s} rc={rc}")

    base_pixel = b'\x80' * 256

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
