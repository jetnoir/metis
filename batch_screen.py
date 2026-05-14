#!/usr/bin/env python3
"""
batch_screen.py — TriageForge v2: parallel C2 batch screener
=============================================================

Screens a directory of binaries using multiprocessing.Pool.
Each worker runs C2RMTAnalysis independently — embarrassingly parallel.

Usage
-----
    python3 batch_screen.py /path/to/binaries/
    python3 batch_screen.py /path/to/binaries/ --workers 4
    python3 batch_screen.py /path/to/binaries/ --extensions .exe .dll

Output
------
    ~/triageforge/results/batch_YYYYMMDD_HHMMSS.json
    Live progress printed to stdout.

Part of TriageForge v2 — Priority 1, Small effort (ROADMAP_V2.md §1.5)
© 2026 Stuart Thomas, trading as TriageForge. Apache 2.0.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from multiprocessing import Pool, cpu_count
from pathlib import Path


# ── Worker (must be module-level for multiprocessing pickle) ──────────────────

def _screen_one(binary_path: str) -> dict:
    """
    C2 screen a single binary. Returns a serialisable result dict.
    Runs in a subprocess — import angr here to avoid fork issues.
    """
    import logging
    # Silence angr before import — unicorn warning fires during module load
    for _log in ('angr', 'cle', 'pyvex', 'angr.state_plugins.unicorn_engine'):
        logging.getLogger(_log).setLevel(logging.CRITICAL)

    from metis.c2_rmt import C2RMTAnalysis

    t0 = time.time()
    result: dict = {
        'binary':     binary_path,
        'name':       Path(binary_path).name,
        'status':     'error',
        'error':      None,
        'elapsed_s':  0.0,
        'verdict':    'ERROR',
        'n_functions': 0,
        'reliable':   False,
        'z_radius':   None,
        'z_energy':   None,
        'z_entropy':  None,
        'top_functions': [],
    }

    try:
        c2 = C2RMTAnalysis(binary_path)
        r  = c2.run()

        bs = r.binary_score
        verdict = 'ANOMALOUS' if bs.flagged else 'NORMAL'

        top = []
        for fn in r.functions_ranked[:5]:
            top.append({
                'addr':       hex(fn.addr),
                'name':       fn.name,
                'combined':   round(fn.combined, 4),
                'cyclomatic': fn.cyclomatic,
                'back_edges': fn.back_edges,
            })

        result.update({
            'status':      'ok',
            'verdict':     verdict,
            'n_functions': r.n_functions,
            'reliable':    bs.reliable,
            'z_radius':    round(bs.z_radius, 3),
            'z_energy':    round(bs.z_energy, 3),
            'z_entropy':   round(bs.z_entropy, 3),
            'top_functions': top,
        })

    except Exception as exc:
        import traceback
        result['error'] = str(exc)
        result['traceback'] = traceback.format_exc()

    result['elapsed_s'] = round(time.time() - t0, 1)
    return result


# ── Binary discovery ──────────────────────────────────────────────────────────

_TEXT_SUFFIXES = {
    '.py', '.txt', '.md', '.rst', '.json', '.csv',
    '.c', '.h', '.cpp', '.hpp', '.s', '.asm',
    '.sh', '.yaml', '.yml', '.toml', '.cfg', '.ini',
}

def _collect_binaries(binary_dir: Path, extensions: list[str] | None) -> list[Path]:
    if extensions:
        binaries = []
        for ext in extensions:
            ext = ext if ext.startswith('.') else '.' + ext
            binaries.extend(binary_dir.glob(f'*{ext}'))
        return sorted(set(binaries))

    # No filter: take everything that isn't obviously a text/source file
    return sorted(
        p for p in binary_dir.iterdir()
        if p.is_file() and p.suffix.lower() not in _TEXT_SUFFIXES
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='TriageForge v2 — parallel C2 batch screener',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('binary_dir',
                        help='Directory of binaries to screen')
    parser.add_argument('--workers', type=int, default=None,
                        help='Parallel workers (default: min(cpu_count, 8))')
    parser.add_argument('--output', default=None,
                        help='Results directory (default: ~/triageforge/results/)')
    parser.add_argument('--extensions', nargs='+', default=None,
                        help='Only screen files with these extensions, e.g. .exe .dll .elf')
    args = parser.parse_args()

    binary_dir = Path(args.binary_dir).expanduser().resolve()
    if not binary_dir.is_dir():
        print(f'Error: {binary_dir} is not a directory', file=sys.stderr)
        sys.exit(1)

    binaries = _collect_binaries(binary_dir, args.extensions)
    if not binaries:
        print(f'No binaries found in {binary_dir}', file=sys.stderr)
        sys.exit(1)

    # Worker count: cap at 8 to leave headroom; each angr process uses 2–4 GB
    n_workers = args.workers or min(cpu_count(), 8)

    output_dir = Path(args.output).expanduser() if args.output \
                 else Path.home() / 'triageforge' / 'results'
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Header ────────────────────────────────────────────────────────────────
    print()
    print('TriageForge v2 — Parallel C2 Batch Screen')
    print('──────────────────────────────────────────')
    print(f'  Directory : {binary_dir}')
    print(f'  Binaries  : {len(binaries)}')
    print(f'  Workers   : {n_workers}')
    print(f'  Output    : {output_dir}')
    print()
    print(f'  {"#":>4}  {"Binary":<40}  {"Verdict":<12}  {"z_entropy":>9}  {"t(s)":>5}')
    print(f'  {"─"*4}  {"─"*40}  {"─"*12}  {"─"*9}  {"─"*5}')

    # ── Parallel run ──────────────────────────────────────────────────────────
    t_start  = time.time()
    results  = []
    paths    = [str(p) for p in binaries]

    with Pool(processes=n_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(_screen_one, paths), 1):
            results.append(result)
            z_ent = (f'{result["z_entropy"]:+.2f}'
                     if result['z_entropy'] is not None else '   n/a')
            print(f'  {i:4d}  {result["name"][:40]:<40}  '
                  f'{result["verdict"]:<12}  {z_ent:>9}  {result["elapsed_s"]:5.1f}')

    total_elapsed = time.time() - t_start

    # ── Summary ───────────────────────────────────────────────────────────────
    ok         = [r for r in results if r['status'] == 'ok']
    anomalous  = [r for r in ok      if r['verdict'] == 'ANOMALOUS']
    normal     = [r for r in ok      if r['verdict'] == 'NORMAL']
    errors     = [r for r in results if r['status'] == 'error']

    print()
    print('── Summary ──────────────────────────────────────────────')
    print(f'  Screened   : {len(ok)} / {len(results)}')
    print(f'  ANOMALOUS  : {len(anomalous)}')
    print(f'  NORMAL     : {len(normal)}')
    print(f'  Errors     : {len(errors)}')
    print(f'  Total time : {total_elapsed:.1f}s  '
          f'({total_elapsed/len(results):.1f}s avg)')

    if anomalous:
        print()
        print('── Anomalous binaries — investigate with C3/C6 ─────────')
        for r in sorted(anomalous, key=lambda x: abs(x.get('z_entropy') or 0), reverse=True):
            print(f'  {r["name"]}  '
                  f'z_entropy={r["z_entropy"]:+.2f}  '
                  f'z_energy={r["z_energy"]:+.2f}')
            for fn in r['top_functions'][:3]:
                print(f'    → {fn["addr"]}  score={fn["combined"]:.3f}  '
                      f'cyclo={fn["cyclomatic"]}  {fn["name"]}')

    if errors:
        print()
        print('── Errors ───────────────────────────────────────────────')
        for r in errors:
            print(f'  {r["name"]}: {r["error"]}')
            if r.get('traceback'):
                print(r['traceback'])

    # ── Save JSON ─────────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path  = output_dir / f'batch_{timestamp}.json'

    payload = {
        'timestamp':      timestamp,
        'binary_dir':     str(binary_dir),
        'n_binaries':     len(results),
        'n_workers':      n_workers,
        'total_elapsed_s': round(total_elapsed, 1),
        'results': sorted(
            results,
            key=lambda r: abs(r.get('z_entropy') or 0),
            reverse=True,
        ),
    }
    with open(out_path, 'w') as fh:
        json.dump(payload, fh, indent=2)

    print()
    print(f'  Results → {out_path}')
    print()


if __name__ == '__main__':
    main()
