#!/usr/bin/env python3
"""
benchmark_crackme.py — Benchmark hardness-guided vs vanilla angr
on crackme_hard (path explosion stress test).

Compares:
  A) Vanilla angr (DFS, no hardness scoring)
  B) Hardness-guided (backbone probe, defer hard states)

Metrics:
  - States explored per second
  - Peak active states (path explosion indicator)
  - Time to first deadended state
  - Total deadended states after N steps
"""

import os
import sys
import time

import angr
import claripy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from metis.exploration_technique import HardnessExplorationTechnique
from metis.dimacs_converter import claripy_to_dimacs
from metis.backbone_probe import quick_hardness_score


BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'crackme_mixed')
MAX_STEPS = 25
TIMEOUT_S = 90


def find_verify(proj):
    for name in ['_verify', 'verify']:
        sym = proj.loader.find_symbol(name)
        if sym:
            return sym.rebased_addr
    return None


def run_vanilla(n_steps=MAX_STEPS):
    """Run angr without hardness technique."""
    proj = angr.Project(BINARY, auto_load_libs=False)
    addr = find_verify(proj)
    if not addr:
        print("  Cannot find verify()")
        return None

    key = claripy.BVS('key', 8 * 8)
    state = proj.factory.call_state(addr, key)
    simgr = proj.factory.simgr(state)

    stats = {
        'steps': 0, 'peak_active': 0, 'deadended': 0,
        'first_dead_step': None, 'time': 0,
        'scores_at_step': [],
    }

    t0 = time.monotonic()
    for step in range(n_steps):
        if time.monotonic() - t0 > TIMEOUT_S:
            print(f"    TIMEOUT at step {step}")
            break

        simgr.step()
        n_active = len(simgr.active)
        n_dead = len(simgr.deadended)

        stats['steps'] = step + 1
        stats['peak_active'] = max(stats['peak_active'], n_active)
        stats['deadended'] = n_dead

        if n_dead > 0 and stats['first_dead_step'] is None:
            stats['first_dead_step'] = step

        # Sample scores every 5 steps for analysis
        if step % 5 == 0 and simgr.active:
            sample_scores = []
            for s in simgr.active[:5]:
                try:
                    dr = claripy_to_dimacs(s.solver.constraints)
                    sc = quick_hardness_score(dr.clauses, dr.n_vars, timeout_s=0.1)
                    sample_scores.append(sc)
                except Exception:
                    pass
            stats['scores_at_step'].append((step, sample_scores))

        print(f"    step {step:2d}: active={n_active:3d} dead={n_dead:3d}", end='')
        if step % 5 == 0 and stats['scores_at_step']:
            scores = stats['scores_at_step'][-1][1]
            if scores:
                print(f"  backbone=[{min(scores):.2f}..{max(scores):.2f}]", end='')
        print()

        if not simgr.active:
            break

    stats['time'] = time.monotonic() - t0
    return stats


def run_hardness(n_steps=MAX_STEPS, threshold=0.75):
    """Run angr with hardness-guided exploration."""
    proj = angr.Project(BINARY, auto_load_libs=False)
    addr = find_verify(proj)
    if not addr:
        print("  Cannot find verify()")
        return None

    key = claripy.BVS('key', 8 * 8)
    state = proj.factory.call_state(addr, key)
    simgr = proj.factory.simgr(state)

    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'benchmark_hardness.csv')
    simgr.use_technique(HardnessExplorationTechnique(
        threshold=threshold,
        probe_timeout_s=0.05,
        min_constraints=2,
        log_file=log_file,
    ))

    stats = {
        'steps': 0, 'peak_active': 0, 'deadended': 0,
        'first_dead_step': None, 'time': 0, 'peak_deferred': 0,
    }

    t0 = time.monotonic()
    for step in range(n_steps):
        if time.monotonic() - t0 > TIMEOUT_S:
            print(f"    TIMEOUT at step {step}")
            break

        simgr.step()
        n_active = len(simgr.active)
        n_dead = len(simgr.deadended)
        n_deferred = len(simgr.stashes.get('hardness_deferred', []))

        stats['steps'] = step + 1
        stats['peak_active'] = max(stats['peak_active'], n_active)
        stats['peak_deferred'] = max(stats['peak_deferred'], n_deferred)
        stats['deadended'] = n_dead

        if n_dead > 0 and stats['first_dead_step'] is None:
            stats['first_dead_step'] = step

        print(f"    step {step:2d}: active={n_active:3d} dead={n_dead:3d} "
              f"deferred={n_deferred:3d}")

        if not simgr.active and not simgr.stashes.get('hardness_deferred'):
            break

    stats['time'] = time.monotonic() - t0
    return stats


def main():
    print("=" * 65)
    print("  crackme_hard benchmark: vanilla vs hardness-guided angr")
    print("=" * 65)
    print(f"  Binary: {BINARY}")
    print(f"  Max steps: {MAX_STEPS}, Timeout: {TIMEOUT_S}s")
    print()

    print("--- VANILLA (no hardness scoring) ---")
    vanilla = run_vanilla()
    print()

    print("--- HARDNESS-GUIDED (backbone probe, threshold=0.95) ---")
    hardness = run_hardness()
    print()

    if vanilla and hardness:
        print("=" * 65)
        print("  RESULTS COMPARISON")
        print("=" * 65)
        print(f"  {'Metric':<30s} {'Vanilla':>12s} {'Hardness':>12s}")
        print(f"  {'-'*30} {'-'*12} {'-'*12}")
        print(f"  {'Steps completed':<30s} {vanilla['steps']:>12d} {hardness['steps']:>12d}")
        print(f"  {'Wall time (s)':<30s} {vanilla['time']:>12.2f} {hardness['time']:>12.2f}")
        print(f"  {'Peak active states':<30s} {vanilla['peak_active']:>12d} {hardness['peak_active']:>12d}")
        print(f"  {'Deadended states':<30s} {vanilla['deadended']:>12d} {hardness['deadended']:>12d}")
        print(f"  {'First dead at step':<30s} {str(vanilla['first_dead_step']):>12s} {str(hardness['first_dead_step']):>12s}")
        if hardness.get('peak_deferred'):
            print(f"  {'Peak deferred states':<30s} {'N/A':>12s} {hardness['peak_deferred']:>12d}")

        v_rate = vanilla['deadended'] / vanilla['time'] if vanilla['time'] > 0 else 0
        h_rate = hardness['deadended'] / hardness['time'] if hardness['time'] > 0 else 0
        print(f"  {'Dead states/second':<30s} {v_rate:>12.1f} {h_rate:>12.1f}")
        print("=" * 65)


if __name__ == '__main__':
    main()
