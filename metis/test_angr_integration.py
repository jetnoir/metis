#!/usr/bin/env python3
"""
test_angr_integration.py — Test the hardness probe against a real binary.

Runs angr symbolic execution on test_binary with and without the
HardnessExplorationTechnique, comparing coverage and timing.
"""

import os
import sys
import time

import angr
import claripy

# Add parent dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metis.dimacs_converter import claripy_to_dimacs
from metis.backbone_probe import backbone_probe, quick_hardness_score
from metis.exploration_technique import HardnessExplorationTechnique
from metis.offline_analysis import analyze_clauses


def find_check_password(proj):
    """Find the check_password function address."""
    sym = proj.loader.find_symbol('_check_password')
    if sym:
        return sym.rebased_addr
    sym = proj.loader.find_symbol('check_password')
    if sym:
        return sym.rebased_addr
    return None


def test_offline_scoring():
    """Score individual states during manual exploration."""
    print("=" * 60)
    print("  TEST 1: Offline scoring of individual states")
    print("=" * 60)

    binary = os.path.join(os.path.dirname(__file__), 'test_binary')
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = find_check_password(proj)
    if not func_addr:
        print("  Cannot find check_password — trying entry_state")
        state = proj.factory.entry_state()
    else:
        print(f"  check_password at {hex(func_addr)}")
        # Create a state at check_password with symbolic input
        input_sym = claripy.BVS('input', 10 * 8)  # 10 bytes
        state = proj.factory.call_state(func_addr, input_sym)

    simgr = proj.factory.simgr(state)
    print(f"  Initial: {len(simgr.active)} active states\n")

    # Step a few times and score each state
    for step in range(8):
        simgr.step()
        if not simgr.active:
            print(f"  Step {step}: no active states left")
            break

        print(f"  Step {step}: {len(simgr.active)} active, "
              f"{len(simgr.deadended)} dead")

        for i, s in enumerate(simgr.active[:3]):  # score first 3
            n_cons = len(s.solver.constraints)
            if n_cons < 1:
                print(f"    state[{i}]: {n_cons} constraints (skip)")
                continue

            try:
                dr = claripy_to_dimacs(s.solver.constraints)
                score = quick_hardness_score(dr.clauses, dr.n_vars)
                print(f"    state[{i}]: {n_cons} constraints → "
                      f"{dr.n_vars} vars, {dr.n_clauses} clauses, "
                      f"backbone={score:.2f}")
            except Exception as e:
                print(f"    state[{i}]: {n_cons} constraints → ERROR: {e}")

    print()


def test_exploration_technique():
    """Run symbolic execution with the HardnessExplorationTechnique."""
    print("=" * 60)
    print("  TEST 2: Exploration with HardnessExplorationTechnique")
    print("=" * 60)

    binary = os.path.join(os.path.dirname(__file__), 'test_binary')
    proj = angr.Project(binary, auto_load_libs=False)

    func_addr = find_check_password(proj)
    if not func_addr:
        print("  Cannot find check_password — using entry_state")
        state = proj.factory.entry_state()
    else:
        print(f"  check_password at {hex(func_addr)}")
        input_sym = claripy.BVS('input', 10 * 8)
        state = proj.factory.call_state(func_addr, input_sym)

    log_file = os.path.join(os.path.dirname(__file__), 'hardness_log.csv')

    simgr = proj.factory.simgr(state)
    technique = HardnessExplorationTechnique(
        threshold=0.95,
        probe_timeout_s=0.1,
        score_interval=1,
        min_constraints=2,
        log_file=log_file,
    )
    simgr.use_technique(technique)

    print(f"  Running with hardness threshold=0.95...\n")

    t0 = time.monotonic()
    for step in range(20):
        simgr.step()
        n_active = len(simgr.active)
        n_dead = len(simgr.deadended)
        n_deferred = len(simgr.stashes.get('hardness_deferred', []))

        print(f"  step {step:2d}: active={n_active} dead={n_dead} "
              f"deferred={n_deferred}")

        if not simgr.active and not simgr.stashes.get('hardness_deferred'):
            break

    elapsed = time.monotonic() - t0
    print(f"\n  Completed in {elapsed:.2f}s")
    print(f"  Final: {len(simgr.active)} active, "
          f"{len(simgr.deadended)} deadended, "
          f"{len(simgr.stashes.get('hardness_deferred', []))} deferred")

    if os.path.exists(log_file):
        with open(log_file) as f:
            lines = f.readlines()
        print(f"  Log: {len(lines)-1} entries written to hardness_log.csv")

        # Show a few entries
        for line in lines[:6]:
            print(f"    {line.rstrip()}")
        if len(lines) > 6:
            print(f"    ... ({len(lines)-6} more)")

    print()


def test_baseline_comparison():
    """Compare with and without the technique."""
    print("=" * 60)
    print("  TEST 3: Baseline comparison (with vs without)")
    print("=" * 60)

    binary = os.path.join(os.path.dirname(__file__), 'test_binary')
    proj = angr.Project(binary, auto_load_libs=False)
    func_addr = find_check_password(proj)

    if not func_addr:
        print("  Cannot find check_password — skipping comparison")
        return

    n_steps = 15

    # Without technique
    input1 = claripy.BVS('input1', 10 * 8)
    s1 = proj.factory.call_state(func_addr, input1)
    sm1 = proj.factory.simgr(s1)

    t0 = time.monotonic()
    for _ in range(n_steps):
        sm1.step()
        if not sm1.active:
            break
    t_baseline = time.monotonic() - t0

    # With technique
    input2 = claripy.BVS('input2', 10 * 8)
    s2 = proj.factory.call_state(func_addr, input2)
    sm2 = proj.factory.simgr(s2)
    sm2.use_technique(HardnessExplorationTechnique(
        threshold=0.95, probe_timeout_s=0.05, min_constraints=2,
    ))

    t0 = time.monotonic()
    for _ in range(n_steps):
        sm2.step()
        if not sm2.active and not sm2.stashes.get('hardness_deferred'):
            break
    t_hardness = time.monotonic() - t0

    print(f"  Baseline:  {len(sm1.deadended)} deadended in {t_baseline:.2f}s")
    print(f"  Hardness:  {len(sm2.deadended)} deadended + "
          f"{len(sm2.stashes.get('hardness_deferred', []))} deferred "
          f"in {t_hardness:.2f}s")
    print()


def main():
    print("\nmetis integration test\n")

    tests = [
        test_offline_scoring,
        test_exploration_technique,
        test_baseline_comparison,
    ]

    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"  {test.__name__}: FAILED — {e}")
            import traceback
            traceback.print_exc()
            print()

    print("Done.")


if __name__ == '__main__':
    main()
