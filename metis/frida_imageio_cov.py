#!/usr/bin/env python3
"""
frida_imageio_cov.py — Frida-based coverage tracer for ImageIO fuzzing.

Attaches to the imageio_harness process and instruments:
  - ImageIO.framework (CGImageSource* functions)
  - libPng.dylib (PNG parsing internals)
  - libTIFF.dylib (TIFF parsing internals)

Logs basic block coverage for correlation with mutation inputs.
"""
import frida
import sys
import subprocess
import time
import os

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'imageio_harness')

FRIDA_SCRIPT = """
'use strict';

// Track unique basic blocks hit
const coverage = new Set();
let moduleRanges = {};

function instrumentModule(name) {
    const mod = Process.findModuleByName(name);
    if (!mod) {
        send({type: 'info', msg: 'Module not found: ' + name});
        return 0;
    }
    moduleRanges[name] = {base: mod.base, size: mod.size};
    send({type: 'module', name: name, base: mod.base.toString(), size: mod.size});

    // Use Stalker for basic block coverage
    return mod.size;
}

rpc.exports = {
    init: function() {
        const modules = [
            'ImageIO',
            'libPng.dylib',
            'libTIFF.dylib',
            'CoreGraphics',
        ];
        let total = 0;
        modules.forEach(function(name) {
            total += instrumentModule(name);
        });
        send({type: 'info', msg: 'Instrumented ' + Object.keys(moduleRanges).length + ' modules'});
    },

    getCoverage: function() {
        return coverage.size;
    },

    startStalker: function() {
        const tid = Process.enumerateThreads()[0].id;

        Stalker.follow(tid, {
            events: { compile: true },
            onReceive: function(events) {
                const dominated = Stalker.parse(events, {stringify: false, annotate: false});
                dominated.forEach(function(ev) {
                    if (ev.length >= 2) {
                        coverage.add(ev[0].toString());
                    }
                });
            }
        });
        send({type: 'info', msg: 'Stalker started on thread ' + tid});
    },

    stopStalker: function() {
        Process.enumerateThreads().forEach(function(t) {
            Stalker.unfollow(t.id);
        });
        return coverage.size;
    }
};
"""

def run_with_coverage(image_path):
    """Run imageio_harness on an image with Frida coverage tracking."""
    # Spawn the process suspended
    pid = frida.spawn([HARNESS, image_path])
    session = frida.attach(pid)

    script = session.create_script(FRIDA_SCRIPT)

    messages = []
    def on_message(msg, data):
        if msg['type'] == 'send':
            messages.append(msg['payload'])

    script.on('message', on_message)
    script.load()

    # Initialize instrumentation
    script.exports_sync.init()
    script.exports_sync.start_stalker()

    # Resume and let it run
    frida.resume(pid)

    # Wait for process to finish (with timeout)
    t0 = time.time()
    while time.time() - t0 < 10:
        try:
            os.kill(pid, 0)  # check if alive
            time.sleep(0.1)
        except OSError:
            break

    # Get coverage
    try:
        n_blocks = script.exports_sync.stop_stalker()
    except:
        n_blocks = 0

    session.detach()
    return n_blocks, messages


def main():
    if len(sys.argv) < 2:
        print("Usage: frida_imageio_cov.py <image_file_or_directory>")
        return 1

    target = sys.argv[1]

    if os.path.isdir(target):
        files = sorted([os.path.join(target, f) for f in os.listdir(target)
                        if f.endswith(('.png', '.tiff', '.heic', '.dng'))])
    else:
        files = [target]

    print(f"Tracing {len(files)} files through ImageIO with Frida coverage\n")

    for f in files:
        name = os.path.basename(f)
        try:
            n_blocks, msgs = run_with_coverage(f)
            modules = [m for m in msgs if isinstance(m, dict) and m.get('type') == 'module']
            print(f"  {name:40s} blocks={n_blocks:5d}  modules={len(modules)}")
        except Exception as e:
            print(f"  {name:40s} ERROR: {e}")

    print("\nDone")


if __name__ == '__main__':
    main()
