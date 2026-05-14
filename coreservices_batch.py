#!/usr/bin/env python3
"""
coreservices_batch.py — C2 batch sweep for nested CoreServices binary tree on Dell.

Recursively finds all Mach-O binaries under the target directory (handles
app bundles, nested .bundle etc.) and runs C2 on each with timeout.

Usage (on Dell):
    ~/.venv_angr/bin/python3 coreservices_batch.py \
        --target ~/darwin_research/binaries/coreservices \
        --label coreservices
"""
import sys, json, time, argparse, traceback
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

TIMEOUT_PER_BINARY = 360   # CoreServices has large binaries (Finder ~25MB)
WORKERS            = 3

parser = argparse.ArgumentParser()
parser.add_argument('--target',  required=True)
parser.add_argument('--label',   default='coreservices')
parser.add_argument('--outdir',  default=str(HERE / 'findings'))
parser.add_argument('--resume',  action='store_true')
parser.add_argument('--workers', type=int, default=WORKERS)
args = parser.parse_args()

TARGET  = Path(args.target)
OUT_DIR = Path(args.outdir)
OUT_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE  = OUT_DIR / f'dell_batch_{args.label}.log'
JSON_FILE = OUT_DIR / f'dell_batch_{args.label}_results.json'
DONE_FILE = OUT_DIR / f'dell_batch_{args.label}_done.txt'

SKIP_SUFFIXES = {'.dylib', '.plist', '.nib', '.car', '.strings', '.png',
                 '.icns', '.tiff', '.pdf', '.html', '.js', '.css', '.json',
                 '.rtf', '.xml', '.xib', '.lproj', '.metallib', '.bundle',
                 '.framework', '.kext'}

MACHO_MAGIC = {
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',  # big-endian 32/64
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',  # little-endian 32/64
    b'\xca\xfe\xba\xbe',                         # fat universal
}

done_set = set()
if args.resume and DONE_FILE.exists():
    done_set = set(DONE_FILE.read_text().splitlines())


def is_macho(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] in MACHO_MAGIC
    except Exception:
        return False


def collect_binaries(root: Path):
    results = []
    for p in sorted(root.rglob('*')):
        if not p.is_file():
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        if p.name.startswith('.'):
            continue
        if str(p) in done_set:
            continue
        if is_macho(p):
            results.append(p)
    return results


def screen_one(binary_path: str) -> dict:
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


# ── Main ──────────────────────────────────────────────────────────────────────
binaries = collect_binaries(TARGET)

print(f'[*] CoreServices batch screen — {args.label}')
print(f'    Target:  {TARGET}  ({len(binaries)} Mach-O binaries)')
print(f'    Workers: {args.workers}  Timeout: {TIMEOUT_PER_BINARY}s')
print(f'    Output:  {OUT_DIR}')
print()

results   = []
done_fh   = open(DONE_FILE, 'a')
log_fh    = open(LOG_FILE,  'a')
n_anomaly = 0
start     = time.time()


def log(msg):
    print(msg)
    log_fh.write(msg + '\n')
    log_fh.flush()


with ProcessPoolExecutor(max_workers=args.workers) as pool:
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

        name = Path(r['binary']).name
        elapsed = time.time() - start

        if r['status'] == 'ok':
            flag = '⚠ ANOMALOUS' if r['anomalous'] else 'ok'
            if r['anomalous']:
                n_anomaly += 1
            log(f'  [{n_done:3d}/{len(binaries)}] {name:40s}  '
                f'z_r={r["z_radius"] or "n/a":>8}  '
                f'z_e={r["z_energy"] or "n/a":>8}  '
                f'z_ent={r["z_entropy"] or "n/a":>8}  '
                f'{flag}  ({elapsed:.0f}s)')
        elif r['status'] == 'timeout':
            log(f'  [{n_done:3d}/{len(binaries)}] {name:40s}  TIMEOUT')
        else:
            log(f'  [{n_done:3d}/{len(binaries)}] {name:40s}  ERROR: {r.get("error","?")[:60]}')

# Save full results
JSON_FILE.write_text(json.dumps(results, indent=2))

# Summary
elapsed = time.time() - start
ok = [r for r in results if r['status'] == 'ok']
anomalous = [r for r in ok if r.get('anomalous')]

print()
print(f'[+] Done — {len(ok)}/{len(binaries)} succeeded in {elapsed/60:.1f} min')
print(f'[+] ANOMALOUS: {len(anomalous)}')
print()
if anomalous:
    print('  Binary                                   z_radius   z_energy  z_entropy')
    print('  ' + '-'*75)
    for r in sorted(anomalous, key=lambda x: abs(x.get('z_entropy') or 0), reverse=True):
        print(f'  {Path(r["binary"]).name:40s}  '
              f'{r["z_radius"] or "n/a":>8}  '
              f'{r["z_energy"] or "n/a":>8}  '
              f'{r["z_entropy"] or "n/a":>8}')
print()
print(f'Full results: {JSON_FILE}')
print(f'Log:          {LOG_FILE}')
