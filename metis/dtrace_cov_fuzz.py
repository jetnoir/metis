#!/usr/bin/env python3
"""
dtrace_cov_fuzz.py — DTrace-based coverage-guided fuzzer for Apple ImageIO.

Novel approach: uses macOS DTrace pid provider for function-level coverage
inside closed-source dyld shared cache libraries. No binary patching,
no Frida, no SIP workaround on the target binary needed.

The DTrace pid provider resolves function addresses through the shared
cache natively, giving real coverage inside ImageIO, libPng, libTIFF,
libJPEG, AppleJPEG, and CoreGraphics.

Run on macOS VM with SIP disabled (DTrace needs root + SIP off for
pid provider on system frameworks).

Usage: sudo python3 dtrace_cov_fuzz.py [iterations]
"""

import subprocess
import os
import sys
import time
import random
import shutil
import tempfile

HARNESS = "/tmp/imageio_harness"
SEED_DIR = "/tmp/imageio_seeds"
CRASH_DIR = "/tmp/imageio_crashes"
COV_DIR = "/tmp/imageio_dtrace_corpus"

# DTrace script: counts unique function entry points hit
# Covers ImageIO + all sub-libraries
DTRACE_SCRIPT = """
pid$target::*CGImageSource*:entry,
pid$target::*IIO_Reader*:entry,
pid$target::*IIOImage*:entry,
pid$target::*PNGRead*:entry,
pid$target::*TIFFRead*:entry,
pid$target::*JPEGRead*:entry,
pid$target::*_cg_png_*:entry,
pid$target::*_cg_tiff_*:entry,
pid$target::*AppleJPEG*:entry,
pid$target::*CGImage*:entry,
pid$target::*ImageProvider*:entry,
pid$target::*CGColorSpace*:entry,
pid$target::*CGDataProvider*:entry,
pid$target::*png_read*:entry,
pid$target::*png_set*:entry,
pid$target::*png_get*:entry,
pid$target::*png_process*:entry,
pid$target::*Tiff*:entry,
pid$target::*TIFF*:entry,
pid$target::*tiff*:entry,
pid$target::*HEIF*:entry,
pid$target::*heif*:entry,
pid$target::*HEIC*:entry,
pid$target::*avif*:entry,
pid$target::*RawCamera*:entry,
pid$target::*DNG*:entry,
pid$target::*ICC*:entry,
pid$target::*icc*:entry,
pid$target::*Exif*:entry,
pid$target::*exif*:entry
{
    @[probefunc] = count();
}
"""


def run_with_dtrace(image_path, timeout=10):
    """
    Run imageio_harness under DTrace coverage.
    Returns (set of function names hit, crashed bool, stderr).
    """
    try:
        result = subprocess.run(
            ["sudo", "/tmp/dtrace_run.sh", image_path],
            capture_output=True, text=True, timeout=timeout,
        )

        # DTrace outputs aggregation to STDERR in format:
        #   funcname                               count
        # Parse both stdout and stderr
        functions_hit = set()
        for output in [result.stdout, result.stderr]:
            for line in output.splitlines():
                line = line.strip()
                # Skip DTrace status lines
                if not line or line.startswith("dtrace:") or line.startswith("HIT"):
                    continue
                # Function lines have format: "funcname    count"
                # The function name is the first non-empty token, count is the last
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    fname = parts[0].strip()
                    try:
                        int(parts[1])  # verify last token is a number
                        if fname and not fname.startswith("#") and len(fname) > 2:
                            functions_hit.add(fname)
                    except ValueError:
                        pass

        # Check for crash
        crashed = False
        combined = result.stdout + result.stderr
        if "core dumped" in combined.lower() or "signal" in combined.lower():
            crashed = True
        if result.returncode < 0 or result.returncode > 128:
            crashed = True

        return functions_hit, crashed, result.stderr

    except subprocess.TimeoutExpired:
        return set(), False, "TIMEOUT"
    except Exception as e:
        return set(), False, str(e)


def mutate_file(seed_path, out_path):
    """Mutate a seed file with multiple strategies."""
    with open(seed_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < 8:
        return False

    n_muts = random.randint(1, 8)
    for _ in range(n_muts):
        s = random.randint(0, 7)

        if s == 0:  # bit flip
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= (1 << random.randint(0, 7))

        elif s == 1:  # byte overwrite
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)

        elif s == 2:  # multi-byte overwrite
            pos = random.randint(0, max(1, len(data) - 8))
            n = random.randint(1, 8)
            for j in range(min(n, len(data) - pos)):
                data[pos + j] = random.randint(0, 255)

        elif s == 3:  # insert bytes
            pos = random.randint(0, len(data) - 1)
            n = random.randint(1, 4)
            data[pos:pos] = bytes(random.randint(0, 255) for _ in range(n))

        elif s == 4 and len(data) > 16:  # delete bytes
            pos = random.randint(0, len(data) - 4)
            n = random.randint(1, min(4, len(data) - pos - 1))
            del data[pos:pos + n]

        elif s == 5:  # boundary value at random offset
            pos = random.randint(0, max(1, len(data) - 4))
            data[pos] = random.choice([0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE])

        elif s == 6:  # 32-bit boundary value
            pos = random.randint(0, max(1, len(data) - 4))
            val = random.choice([0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFF])
            for j in range(min(4, len(data) - pos)):
                data[pos + j] = (val >> (j * 8)) & 0xFF

        elif s == 7:  # copy a chunk from one position to another
            if len(data) > 32:
                src = random.randint(0, len(data) - 16)
                dst = random.randint(0, len(data) - 16)
                n = random.randint(4, 16)
                chunk = data[src:src + n]
                data[dst:dst + len(chunk)] = chunk

    with open(out_path, "wb") as f:
        f.write(data)
    return True


def main():
    random.seed(int(time.time()))

    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 500

    os.makedirs(COV_DIR, exist_ok=True)
    os.makedirs(CRASH_DIR, exist_ok=True)

    # Gather seeds
    seeds = [os.path.join(SEED_DIR, f) for f in sorted(os.listdir(SEED_DIR))
             if os.path.isfile(os.path.join(SEED_DIR, f))]
    if not seeds:
        print(f"No seeds in {SEED_DIR}")
        return

    print("=" * 65)
    print("  DTrace Coverage-Guided ImageIO Fuzzer")
    print(f"  Seeds: {len(seeds)}, Iterations: {iterations}")
    print(f"  uid={os.getuid()}")
    print("=" * 65)
    print()

    all_functions = set()

    # ── Baseline: run each seed to establish coverage ──
    print("[Baseline] Measuring seed coverage...")
    for seed in seeds:
        hit, crashed, stderr = run_with_dtrace(seed)
        prev = len(all_functions)
        all_functions.update(hit)
        gained = len(all_functions) - prev
        name = os.path.basename(seed)

        if gained > 0 or crashed:
            print(f"  {name:35s} +{gained:3d} funcs (total: {len(all_functions)})")

        if crashed:
            cp = os.path.join(CRASH_DIR, f"seed_crash_{name}")
            shutil.copy(seed, cp)
            print(f"  *** SEED CRASH: {cp}")

    print(f"\nBaseline: {len(all_functions)} unique functions across {len(seeds)} seeds\n")

    # ── Fuzzing loop ──
    new_cov_count = 0
    crashes = 0
    tmp = os.path.join(tempfile.gettempdir(), f"dtrace_fuzz_{os.getpid()}.bin")
    t0 = time.time()

    print(f"[Fuzzing] {iterations} iterations...\n")

    for i in range(iterations):
        seed = random.choice(seeds)
        if not mutate_file(seed, tmp):
            continue

        hit, crashed, stderr = run_with_dtrace(tmp)

        prev = len(all_functions)
        all_functions.update(hit)
        gained = len(all_functions) - prev

        if gained > 0:
            new_cov_count += 1
            save_path = os.path.join(COV_DIR, f"cov_{i:04d}_{gained}f.bin")
            shutil.copy(tmp, save_path)
            seeds.append(save_path)  # add to corpus for further mutation
            print(f"  [{i+1:4d}] +{gained:2d} new funcs! "
                  f"(total: {len(all_functions)}) -> {os.path.basename(save_path)}")

        if crashed:
            crashes += 1
            cp = os.path.join(CRASH_DIR, f"crash_{i:04d}.bin")
            shutil.copy(tmp, cp)
            print(f"  [{i+1:4d}] *** CRASH *** -> {cp}")
            if stderr and "TIMEOUT" not in stderr:
                print(f"         stderr: {stderr[:200]}")

        if (i + 1) % 25 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{i+1:4d}] funcs={len(all_functions)} "
                  f"new_cov={new_cov_count} crashes={crashes} "
                  f"{elapsed:.0f}s ({rate:.1f}/s)")

    # Cleanup
    if os.path.exists(tmp):
        os.unlink(tmp)

    elapsed = time.time() - t0
    rate = iterations / elapsed if elapsed > 0 else 0

    print()
    print("=" * 65)
    print(f"  Complete: {iterations} iterations in {elapsed:.0f}s ({rate:.1f}/s)")
    print(f"  Functions discovered: {len(all_functions)}")
    print(f"  New coverage inputs: {new_cov_count}")
    print(f"  Crashes: {crashes}")
    if crashes:
        print(f"  Crash files: {CRASH_DIR}/")
    if new_cov_count:
        print(f"  Coverage corpus: {COV_DIR}/")
    print("=" * 65)

    # Dump final function list
    func_list = os.path.join(COV_DIR, "functions_hit.txt")
    with open(func_list, "w") as f:
        for fn in sorted(all_functions):
            f.write(fn + "\n")
    print(f"\n  Function list written to {func_list}")


if __name__ == "__main__":
    main()
