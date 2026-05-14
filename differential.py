#!/usr/bin/env python3
"""
differential.py — TriageForge v2: batch differential analysis
=============================================================

Compares two batch_screen.py JSON snapshots (e.g., macOS 15.3 vs 15.4)
and surfaces binaries whose structural anomaly score increased, changed
verdict, or disappeared/appeared between releases.

This is the enterprise headline feature: "which daemons changed in this
OS update AND are now structurally more suspicious?"

Usage
-----
    python3 differential.py baseline.json update.json
    python3 differential.py baseline.json update.json --threshold 0.3
    python3 differential.py baseline.json update.json --output delta.json

Matching
--------
Functions are matched by name across snapshots.  Stripped functions
(``sub_ADDR`` names) are excluded from function-level diffing — only
named (symbolicated) functions are compared.  Binary-level z-score
delta is always computed regardless.

Output
------
    Console: verdict changes, score-increase binaries, new anomalous binaries
    JSON: delta_YYYYMMDD_HHMMSS.json in ~/triageforge/results/

Part of TriageForge v2 — Priority 3, Small effort (ROADMAP_V2.md §3.2)
© 2026 Stuart Thomas, trading as TriageForge. Apache 2.0.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


# ── Loader ────────────────────────────────────────────────────────────────────

def _load_batch(path: Path) -> tuple[dict, dict[str, dict]]:
    """Load a batch_screen.py JSON file. Returns (meta, {name: result})."""
    with open(path) as fh:
        data = json.load(fh)
    by_name: dict[str, dict] = {}
    for r in data.get('results', []):
        by_name[r['name']] = r
    return data, by_name


# ── Function-level diff ───────────────────────────────────────────────────────

def _diff_functions(
    before_fns: list[dict],
    after_fns:  list[dict],
    threshold:  float = 0.2,
) -> list[dict]:
    """
    Match top-functions lists by name and return score-change records.

    Only named functions (not ``sub_ADDR`` stubs) are matched.
    Returns records sorted by |delta| descending.
    """
    def _named(fns: list[dict]) -> dict[str, dict]:
        return {
            f['name']: f for f in fns
            if f.get('name') and not f['name'].startswith('sub_')
        }

    bmap = _named(before_fns)
    amap = _named(after_fns)

    records: list[dict] = []

    # Changed / stable functions
    for name in set(bmap) & set(amap):
        delta = amap[name]['combined'] - bmap[name]['combined']
        if abs(delta) >= threshold:
            records.append({
                'name':   name,
                'before': round(bmap[name]['combined'], 4),
                'after':  round(amap[name]['combined'], 4),
                'delta':  round(delta, 4),
            })

    # New functions (only in after snapshot)
    for name in set(amap) - set(bmap):
        f = amap[name]
        records.append({
            'name':   name,
            'before': None,
            'after':  round(f['combined'], 4),
            'delta':  round(f['combined'], 4),
            'new':    True,
        })

    # Removed functions
    for name in set(bmap) - set(amap):
        f = bmap[name]
        records.append({
            'name':    name,
            'before':  round(f['combined'], 4),
            'after':   None,
            'delta':   round(-f['combined'], 4),
            'removed': True,
        })

    return sorted(records, key=lambda x: abs(x['delta']), reverse=True)


# ── Binary-level comparison ───────────────────────────────────────────────────

def _compare_binary(
    name:         str,
    b:            dict | None,
    a:            dict | None,
    z_threshold:  float,
    fn_threshold: float,
) -> dict | None:
    """
    Compare one binary across before/after snapshots.
    Returns a finding dict or None if the binary is unchanged/boring.
    """
    if b is None:
        if a and a['status'] == 'ok':
            return {
                'binary':          name,
                'change':          'NEW',
                'after_verdict':   a['verdict'],
                'after_z_entropy': a.get('z_entropy'),
                'after_z_energy':  a.get('z_energy'),
                'function_deltas': [],
            }
        return None

    if a is None:
        if b['status'] == 'ok':
            return {
                'binary':           name,
                'change':           'REMOVED',
                'before_verdict':   b['verdict'],
                'before_z_entropy': b.get('z_entropy'),
                'function_deltas':  [],
            }
        return None

    if b['status'] != 'ok' or a['status'] != 'ok':
        return None   # errors on one or both sides — skip

    b_z = b.get('z_entropy') or 0.0
    a_z = a.get('z_entropy') or 0.0
    delta_z = a_z - b_z

    verdict_changed = (b['verdict'] != a['verdict'])
    score_up        = delta_z >= z_threshold

    if not verdict_changed and not score_up:
        return None   # boring — no change worth reporting

    fn_deltas = _diff_functions(
        b.get('top_functions', []),
        a.get('top_functions', []),
        threshold=fn_threshold,
    )

    change_type = 'VERDICT_CHANGE' if verdict_changed else 'SCORE_INCREASE'

    return {
        'binary':           name,
        'change':           change_type,
        'before_verdict':   b['verdict'],
        'after_verdict':    a['verdict'],
        'before_z_entropy': b.get('z_entropy'),
        'after_z_entropy':  a.get('z_entropy'),
        'delta_z_entropy':  round(delta_z, 3),
        'before_z_energy':  b.get('z_energy'),
        'after_z_energy':   a.get('z_energy'),
        'delta_z_energy':   round((a.get('z_energy') or 0) - (b.get('z_energy') or 0), 3),
        'before_n_functions': b.get('n_functions'),
        'after_n_functions':  a.get('n_functions'),
        'function_deltas':  fn_deltas[:20],
    }


# ── Reporting helpers ─────────────────────────────────────────────────────────

def _print_finding(f: dict) -> None:
    change = f['change']

    if change == 'NEW':
        verdict = f.get('after_verdict', '?')
        marker  = '***' if verdict == 'ANOMALOUS' else '   '
        print(f'  {marker} [NEW] {f["binary"]}  verdict={verdict}  '
              f'z_entropy={f.get("after_z_entropy") or "n/a"}')
        return

    if change == 'REMOVED':
        print(f'       [REMOVED] {f["binary"]}  was {f.get("before_verdict")}')
        return

    bv = f.get('before_verdict', '?')
    av = f.get('after_verdict',  '?')
    dz = f.get('delta_z_entropy', 0.0)

    if change == 'VERDICT_CHANGE':
        marker = '***'
        label  = f'{bv} → {av}'
    else:
        marker = ' ↑ ' if dz > 0 else ' ↓ '
        label  = f'{bv} (Δz={dz:+.3f})'

    bze = f.get('before_z_entropy')
    aze = f.get('after_z_entropy')
    z_str = (f'{bze:+.2f} → {aze:+.2f}'
             if bze is not None and aze is not None else 'n/a')

    print(f'  {marker} {f["binary"]:<40}  {label}  z_entropy: {z_str}')

    for fn in f.get('function_deltas', [])[:3]:
        tag = ' [NEW]' if fn.get('new') else (' [GONE]' if fn.get('removed') else '')
        b_s = f'{fn["before"]:.3f}' if fn['before'] is not None else '  new '
        a_s = f'{fn["after"]:.3f}'  if fn['after']  is not None else 'gone  '
        print(f'         fn {fn["name"]:<40}  {b_s} → {a_s}  Δ={fn["delta"]:+.4f}{tag}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='TriageForge v2 — differential analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('before',
                        help='Baseline batch JSON (earlier OS / first run)')
    parser.add_argument('after',
                        help='Updated batch JSON (newer OS / second run)')
    parser.add_argument('--threshold', type=float, default=0.30,
                        help='Min |Δz_entropy| to flag a binary (default 0.30)')
    parser.add_argument('--fn-threshold', type=float, default=0.20,
                        help='Min |Δcombined| to flag a function (default 0.20)')
    parser.add_argument('--output', default=None,
                        help='Output JSON path (default: ~/triageforge/results/delta_...json)')
    parser.add_argument('--top', type=int, default=30,
                        help='Max findings to print per category (default 30)')
    args = parser.parse_args()

    before_meta, before_by_name = _load_batch(Path(args.before))
    after_meta,  after_by_name  = _load_batch(Path(args.after))

    all_names = sorted(set(before_by_name) | set(after_by_name))

    findings: list[dict] = []
    for name in all_names:
        f = _compare_binary(
            name,
            before_by_name.get(name),
            after_by_name.get(name),
            z_threshold  = args.threshold,
            fn_threshold = args.fn_threshold,
        )
        if f:
            findings.append(f)

    # Sort: verdict changes first, then by |Δz_entropy| descending
    findings.sort(key=lambda x: (
        0 if x['change'] == 'VERDICT_CHANGE' else
        1 if x['change'] == 'SCORE_INCREASE' else
        2 if x['change'] == 'NEW' else 3,
        -abs(x.get('delta_z_entropy') or 0),
    ))

    # ── Console report ─────────────────────────────────────────────────────────
    print()
    print('TriageForge v2 — Differential Analysis')
    print('═══════════════════════════════════════')
    print(f'  Before : {args.before}')
    print(f'           {before_meta.get("binary_dir", "?")}  '
          f'({len(before_by_name)} binaries,  '
          f'{before_meta.get("timestamp", "?")})')
    print(f'  After  : {args.after}')
    print(f'           {after_meta.get("binary_dir", "?")}  '
          f'({len(after_by_name)} binaries,  '
          f'{after_meta.get("timestamp", "?")})')
    print(f'  Δ threshold : z_entropy ≥ {args.threshold}  |  fn_combined ≥ {args.fn_threshold}')
    print()

    verdict_changes = [f for f in findings if f['change'] == 'VERDICT_CHANGE']
    score_increases = [f for f in findings if f['change'] == 'SCORE_INCREASE']
    new_bins        = [f for f in findings if f['change'] == 'NEW']
    removed_bins    = [f for f in findings if f['change'] == 'REMOVED']

    print(f'  Findings : {len(findings)} total  '
          f'({len(verdict_changes)} verdict changes, '
          f'{len(score_increases)} score increases, '
          f'{len(new_bins)} new, {len(removed_bins)} removed)')
    print()

    if verdict_changes:
        print(f'── Verdict changes ({len(verdict_changes)}) '
              f'— highest priority ─────────────────────────')
        for f in verdict_changes[:args.top]:
            _print_finding(f)
        if len(verdict_changes) > args.top:
            print(f'  … ({len(verdict_changes) - args.top} more)')
        print()

    if score_increases:
        print(f'── Score increases (Δz_entropy ≥ +{args.threshold}) '
              f'({len(score_increases)}) ──────────────────')
        for f in score_increases[:args.top]:
            _print_finding(f)
        if len(score_increases) > args.top:
            print(f'  … ({len(score_increases) - args.top} more)')
        print()

    anomalous_new = [f for f in new_bins if f.get('after_verdict') == 'ANOMALOUS']
    if anomalous_new:
        print(f'── New ANOMALOUS binaries ({len(anomalous_new)}) ──────────────────────────')
        for f in anomalous_new[:args.top]:
            _print_finding(f)
        print()

    # ── Save JSON ──────────────────────────────────────────────────────────────
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = (Path(args.output) if args.output
                else Path.home() / 'triageforge' / 'results' / f'delta_{ts}.json')
    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        'timestamp':          datetime.now().isoformat(),
        'before_file':        str(args.before),
        'after_file':         str(args.after),
        'before_dir':         before_meta.get('binary_dir'),
        'after_dir':          after_meta.get('binary_dir'),
        'before_timestamp':   before_meta.get('timestamp'),
        'after_timestamp':    after_meta.get('timestamp'),
        'threshold_z':        args.threshold,
        'threshold_fn':       args.fn_threshold,
        'n_before':           len(before_by_name),
        'n_after':            len(after_by_name),
        'n_findings':         len(findings),
        'verdict_changes':    len(verdict_changes),
        'score_increases':    len(score_increases),
        'new_binaries':       len(new_bins),
        'removed_binaries':   len(removed_bins),
        'findings':           findings,
    }
    with open(out_path, 'w') as fh:
        json.dump(payload, fh, indent=2)

    print(f'  Delta report → {out_path}')
    print()


if __name__ == '__main__':
    main()
