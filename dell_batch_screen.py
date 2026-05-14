#!/usr/bin/env python3
"""
dell_batch_screen.py — Batch C2 RMT screen for macOS Mach-O binaries on Dell (x86_64 Linux)

Reads Mach-O binaries from a directory, forces x86_64 slice selection (correct for
macOS universal binaries analyzed from a non-Apple-Silicon host), and writes a ranked
results file. Designed to run on the Dell Debian box (192.168.1.55).

Usage:
    ~/.venv_angr/bin/python3 dell_batch_screen.py --target ~/darwin_research/binaries/sbin --label sbin
    ~/.venv_angr/bin/python3 dell_batch_screen.py --target ~/darwin_research/binaries/libexec --label libexec
"""
import sys, json, time, argparse, traceback, signal
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import angr
import archinfo
from metis.c2_rmt import C2RMTAnalysis

TIMEOUT_PER_BINARY = 300   # seconds — kill hung angr jobs
WORKERS            = 3     # leave 1 core free

parser = argparse.ArgumentParser()
parser.add_argument('--target', required=True, help='Directory of binaries to screen')
parser.add_argument('--label',  default='batch', help='Label for output files')
parser.add_argument('--outdir', default=str(HERE / 'findings'), help='Output directory')
parser.add_argument('--resume', action='store_true', help='Skip already-completed binaries')
args = parser.parse_args()

TARGET  = Path(args.target)
OUT_DIR = Path(args.outdir)
OUT_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE  = OUT_DIR / f'dell_batch_{args.label}.log'
JSON_FILE = OUT_DIR / f'dell_batch_{args.label}_results.json'
DONE_FILE = OUT_DIR / f'dell_batch_{args.label}_done.txt'

done_set = set()
if args.resume and DONE_FILE.exists():
    done_set = set(DONE_FILE.read_text().splitlines())

def is_macho(path: Path) -> bool:
    try:
        magic = path.read_bytes()[:4]
        return magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                         b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                         b'\xca\xfe\xba\xbe')
    except Exception:
        return False

def screen_one(binary_path: str) -> dict:
    """
    Run C2 on a single binary — called in subprocess.

    Uses analyse_binary() which auto-selects FastC2Analysis (lief+capstone)
    for binaries > 3.5 MB and C2RMTAnalysis (angr CFGFast) for smaller ones.
    No binary size limit.
    """
    sys.path.insert(0, str(HERE))
    from metis.c2_rmt import analyse_binary
    import os

    size_mb = os.path.getsize(binary_path) / (1024 * 1024)
    try:
        result = analyse_binary(binary_path)
        top5 = [
            {'addr': hex(f.addr), 'score': round(f.combined, 4),
             'cyclomatic': f.cyclomatic, 'back_edges': f.back_edges}
            for f in result.functions_ranked[:5]
        ]
        bs = result.binary_score
        return {
            'binary':    binary_path,
            'status':    'ok',
            'engine':    'fast' if size_mb > 3.5 else 'full',
            'size_mb':   round(size_mb, 2),
            'anomalous': bs.flagged,
            'z_radius':  round(bs.z_radius,  4) if bs.z_radius  is not None else None,
            'z_energy':  round(bs.z_energy,  4) if bs.z_energy  is not None else None,
            'z_entropy': round(bs.z_entropy, 4) if bs.z_entropy is not None else None,
            'n_funcs':   len(result.functions_ranked),
            'top5':      top5,
        }
    except Exception as e:
        return {'binary': binary_path, 'status': 'error', 'size_mb': round(size_mb, 2),
                'error': str(e)[:300]}

# Collect targets
binaries = sorted([
    p for p in TARGET.iterdir()
    if p.is_file() and not p.name.startswith('.')
    and str(p) not in done_set
    and is_macho(p)
])

print(f'[*] Dell batch screen — {args.label}')
print(f'    Target:  {TARGET}  ({len(binaries)} Mach-O binaries)')
print(f'    Workers: {WORKERS}  Timeout: {TIMEOUT_PER_BINARY}s')
print(f'    Output:  {OUT_DIR}')
print()

results = []
done_fh  = open(DONE_FILE, 'a')
log_fh   = open(LOG_FILE,  'a')

def log(msg):
    print(msg)
    log_fh.write(msg + '\n')
    log_fh.flush()

with ProcessPoolExecutor(max_workers=WORKERS) as pool:
    futures = {pool.submit(screen_one, str(b)): b for b in binaries}
    n_done  = 0
    for fut in as_completed(futures):
        b = futures[fut]
        n_done += 1
        try:
            r = fut.result(timeout=TIMEOUT_PER_BINARY)
        except TimeoutError:
            r = {'binary': str(b), 'status': 'timeout'}
        except Exception as e:
            r = {'binary': str(b), 'status': 'error', 'error': str(e)[:200]}

        results.append(r)
        done_fh.write(str(b) + '\n')
        done_fh.flush()

        status = r['status']
        flag   = '*** ANOMALOUS' if r.get('anomalous') else ''
        if status == 'ok':
            log(f'[{n_done:3d}/{len(binaries)}] {b.name:<40s}  '
                f'z=({r["z_radius"]},{r["z_energy"]},{r["z_entropy"]})  '
                f'{flag}')
        else:
            log(f'[{n_done:3d}/{len(binaries)}] {b.name:<40s}  {status}')

done_fh.close()
log_fh.close()

# Save JSON results
anomalous = [r for r in results if r.get('anomalous')]
anomalous.sort(key=lambda r: min(
    r.get('z_radius', 0) or 0,
    r.get('z_energy', 0) or 0,
), reverse=False)

summary = {
    'label':     args.label,
    'target':    str(TARGET),
    'n_total':   len(results),
    'n_anomalous': len(anomalous),
    'n_errors':  sum(1 for r in results if r['status'] != 'ok'),
    'anomalous': anomalous,
    'all':       results,
}
JSON_FILE.write_text(json.dumps(summary, indent=2))

print(f'\n[+] Done. {len(anomalous)}/{len(results)} anomalous')
print(f'[+] Results → {JSON_FILE}')
print(f'\nTop anomalous binaries:')
for r in anomalous[:10]:
    print(f'  {Path(r["binary"]).name:<40s}  '
          f'z=({r["z_radius"]},{r["z_energy"]},{r["z_entropy"]})')
