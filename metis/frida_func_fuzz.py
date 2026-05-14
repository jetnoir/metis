#!/usr/bin/env python3
"""Frida function-level coverage fuzzer for ImageIO on macOS VM (SIP disabled)."""
import frida
import os
import time
import random
import shutil

HARNESS = "/tmp/imageio_harness"
SEED_DIR = "/tmp/imageio_seeds"
CRASH_DIR = "/tmp/imageio_crashes"
COV_DIR = "/tmp/imageio_cov_corpus"

all_functions = set()

FRIDA_SCRIPT = r"""
const hit = new Set();
const targets = ["ImageIO", "libPng.dylib", "libTIFF.dylib", "libJPEG.dylib",
                 "CoreGraphics", "AppleJPEG"];

rpc.exports = {
    setup: function() {
        let total = 0;
        targets.forEach(function(name) {
            var mod = Process.findModuleByName(name);
            if (!mod) return;
            var exports = mod.enumerateExports();
            var toHook = exports.slice(0, 500);
            toHook.forEach(function(exp) {
                if (exp.type === "function") {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) { hit.add(exp.name); }
                        });
                        total++;
                    } catch(e) {}
                }
            });
            send({type:"mod", name:name, exports:exports.length, hooked:toHook.length});
        });
        send({type:"info", total:total});
    },
    getHit: function() {
        var result = Array.from(hit);
        hit.clear();
        return result;
    }
};
"""


def run_with_frida(image_path, timeout=5):
    try:
        pid = frida.spawn([HARNESS, image_path])
        session = frida.attach(pid)
        script = session.create_script(FRIDA_SCRIPT)
        mods = []
        def on_msg(msg, data):
            if msg["type"] == "send":
                mods.append(msg["payload"])
        script.on("message", on_msg)
        script.load()
        script.exports_sync.setup()
        frida.resume(pid)

        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                ret = os.waitpid(pid, os.WNOHANG)
                if ret[0] != 0:
                    break
            except ChildProcessError:
                break
            except Exception:
                break
            time.sleep(0.02)

        try:
            result = set(script.exports_sync.get_hit())
        except Exception:
            result = set()

        crashed = False
        try:
            ret = os.waitpid(pid, os.WNOHANG)
            if ret[0] != 0 and os.WIFSIGNALED(ret[1]):
                crashed = True
        except Exception:
            pass

        session.detach()
        return result, crashed, mods
    except Exception as e:
        print(f"  frida error: {e}")
        return set(), False, []


def mutate_file(seed_path, out_path):
    with open(seed_path, "rb") as f:
        data = bytearray(f.read())
    if len(data) < 8:
        return False
    for _ in range(random.randint(1, 5)):
        s = random.randint(0, 4)
        if s == 0:
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= (1 << random.randint(0, 7))
        elif s == 1:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        elif s == 2:
            pos = random.randint(0, len(data) - 1)
            data[pos:pos] = bytes([random.randint(0, 255)])
        elif s == 3 and len(data) > 10:
            pos = random.randint(0, len(data) - 2)
            del data[pos]
        elif s == 4:
            pos = random.randint(0, max(1, len(data) - 4))
            data[pos] = random.choice([0, 0xFF, 0x7F, 0x80])
    with open(out_path, "wb") as f:
        f.write(data)
    return True


def main():
    os.makedirs(COV_DIR, exist_ok=True)
    os.makedirs(CRASH_DIR, exist_ok=True)

    seeds = [os.path.join(SEED_DIR, f) for f in sorted(os.listdir(SEED_DIR))
             if os.path.isfile(os.path.join(SEED_DIR, f))]
    if not seeds:
        print("No seeds in", SEED_DIR)
        return

    print(f"Frida function-coverage ImageIO fuzzer")
    print(f"Seeds: {len(seeds)}, uid={os.getuid()}")
    print()

    # Baseline
    print("[Baseline] Running first 10 seeds...")
    for seed in seeds[:10]:
        hit, crashed, mods = run_with_frida(seed)
        prev = len(all_functions)
        all_functions.update(hit)
        gained = len(all_functions) - prev
        name = os.path.basename(seed)
        print(f"  {name:35s} +{gained:3d} funcs (total: {len(all_functions)})")
        if mods and gained == 0 and len(all_functions) == 0:
            # Print module info for debugging
            for m in mods:
                if isinstance(m, dict) and m.get("type") == "mod":
                    print(f"    module: {m.get('name')} exports={m.get('exports')} hooked={m.get('hooked')}")
        if crashed:
            shutil.copy(seed, os.path.join(CRASH_DIR, f"seed_crash_{name}"))
            print(f"  *** CRASH on seed!")

    print(f"\nBaseline: {len(all_functions)} unique functions")
    print()

    # Fuzz
    iters = 300
    new_cov = 0
    crashes = 0
    tmp = "/tmp/fuzz_tmp_img"
    t0 = time.time()
    print(f"[Fuzzing] {iters} iterations...")

    for i in range(iters):
        seed = random.choice(seeds)
        if not mutate_file(seed, tmp):
            continue
        hit, crashed, _ = run_with_frida(tmp)
        prev = len(all_functions)
        all_functions.update(hit)
        gained = len(all_functions) - prev

        if gained > 0:
            new_cov += 1
            save = os.path.join(COV_DIR, f"cov_{i}_{gained}f.bin")
            shutil.copy(tmp, save)
            seeds.append(save)
            print(f"  [{i:4d}] +{gained:2d} new funcs! (total: {len(all_functions)}) -> saved")

        if crashed:
            crashes += 1
            cp = os.path.join(CRASH_DIR, f"crash_{i}.bin")
            shutil.copy(tmp, cp)
            print(f"  [{i:4d}] *** CRASH -> {cp}")

        if (i + 1) % 100 == 0:
            el = time.time() - t0
            print(f"  [{i+1:4d}] funcs={len(all_functions)} new={new_cov} "
                  f"crashes={crashes} {el:.0f}s")

    el = time.time() - t0
    if os.path.exists(tmp):
        os.unlink(tmp)

    print(f"\nDone: {iters}i, {len(all_functions)} funcs, "
          f"{new_cov} new cov, {crashes} crashes, {el:.0f}s")
    if crashes:
        print(f"CRASHES in: {CRASH_DIR}/")


if __name__ == "__main__":
    main()
