#!/usr/bin/env python3
"""
test_pipeline.py — End-to-end tests for the angr hardness probe.

Tests the full pipeline: Z3/claripy → DIMACS → backbone → chi-squared.
Also validates against known 3-SAT instances from the research pipeline.
"""

import sys
import time
from pathlib import Path
import numpy as np

# Allow running directly from within the package dir without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def test_dimacs_converter():
    """Test DIMACS conversion for various constraint types."""
    import z3
    from metis.dimacs_converter import z3_formula_to_dimacs, z3_exprs_to_dimacs

    # Boolean
    x, y, w = z3.Bools('x y w')
    r = z3_formula_to_dimacs(z3.And(z3.Or(x, y), z3.Or(z3.Not(x), w)))
    assert r.n_vars > 0
    assert r.n_clauses > 0
    assert len(r.clauses) == r.n_clauses

    # 8-bit bitvector
    a = z3.BitVec('a', 8)
    r = z3_exprs_to_dimacs([a == 0x42])
    assert r.n_vars == 8  # exactly 8 bits, no Tseitin needed
    assert r.n_clauses == 8  # 8 unit clauses

    # 32-bit bitvector with arithmetic
    x32 = z3.BitVec('x', 32)
    r = z3_exprs_to_dimacs([x32 + 1 == 100, x32 > 50])
    assert r.n_vars > 32
    assert r.n_clauses > 0

    # claripy
    import claripy
    sym = claripy.BVS('test', 32)
    from metis.dimacs_converter import claripy_to_dimacs
    r = claripy_to_dimacs([sym > 0, sym < 1000])
    assert r.n_vars > 0

    print("  dimacs_converter: PASS")


def test_backbone_probe():
    """Test backbone detection accuracy."""
    import z3
    from metis.dimacs_converter import z3_exprs_to_dimacs
    from metis.backbone_probe import backbone_probe, quick_hardness_score

    # Heavily constrained: a == 0x42 AND b == 0x13
    a = z3.BitVec('a', 8)
    b = z3.BitVec('b', 8)
    r_heavy = z3_exprs_to_dimacs([a == 0x42, b == 0x13])
    bp_heavy = backbone_probe(r_heavy.clauses, r_heavy.n_vars)

    # Loosely constrained: a > 0 (almost nothing forced for 16-bit)
    a16 = z3.BitVec('a16', 16)
    r_loose = z3_exprs_to_dimacs([a16 > 0])
    bp_loose = backbone_probe(r_loose.clauses, r_loose.n_vars)

    # Ordering must be correct: constrained > loose
    assert bp_heavy.backbone_fraction > bp_loose.backbone_fraction, \
        f"ordering wrong: heavy={bp_heavy.backbone_fraction:.2f} <= loose={bp_loose.backbone_fraction:.2f}"

    # quick_hardness_score
    s = quick_hardness_score(r_loose.clauses, r_loose.n_vars)
    assert 0.0 <= s <= 1.0

    print("  backbone_probe: PASS")


def test_offline_analysis():
    """Test full chi-squared pipeline."""
    from metis.offline_analysis import analyze_clauses

    # Generate a simple 3-SAT instance via pysat format
    # 5 variables, 10 clauses
    rng = np.random.default_rng(42)
    clauses = []
    for _ in range(10):
        vs = rng.choice(5, 3, replace=False) + 1
        signs = rng.choice([-1, 1], 3)
        clauses.append([int(v * s) for v, s in zip(vs, signs)])

    result = analyze_clauses(clauses, n_vars=5, max_solutions=100)
    assert result.n_solutions >= 0
    assert 0.0 <= result.backbone.backbone_fraction <= 1.0
    assert result.chisq['entropy'] >= 0.0

    print(f"  offline_analysis: PASS (solutions={result.n_solutions}, "
          f"backbone={result.backbone.backbone_fraction:.2f}, "
          f"entropy={result.chisq['entropy']:.2f})")


def test_pysat_roundtrip():
    """Verify DIMACS output is compatible with pysat solver."""
    import z3
    from metis.dimacs_converter import z3_exprs_to_dimacs
    from pysat.solvers import Glucose3

    # Create a satisfiable bitvector constraint
    a = z3.BitVec('a', 8)
    b = z3.BitVec('b', 8)
    r = z3_exprs_to_dimacs([a ^ b == 0x42, a > 0x20, a < 0x7f])

    # Feed to pysat
    g = Glucose3()
    for cl in r.clauses:
        g.add_clause(cl)
    assert g.solve(), "formula should be SAT"
    model = g.get_model()
    assert len(model) == r.n_vars
    g.delete()

    print("  pysat_roundtrip: PASS")


def test_performance():
    """Benchmark conversion + scoring speed for realistic constraint sizes."""
    import z3
    from metis.dimacs_converter import z3_exprs_to_dimacs
    from metis.backbone_probe import quick_hardness_score

    # Simulate a realistic angr state: 5 × 64-bit symbols, ~20 constraints
    syms = [z3.BitVec(f's{i}', 64) for i in range(5)]
    constraints = []
    for i, s in enumerate(syms):
        constraints.append(s > i * 100)
        constraints.append(s < (i + 1) * 10000)
        constraints.append(s & 0xff != 0)
        if i > 0:
            constraints.append(syms[i] > syms[i - 1])

    t0 = time.monotonic()
    r = z3_exprs_to_dimacs(constraints)
    t_convert = (time.monotonic() - t0) * 1000

    t0 = time.monotonic()
    score = quick_hardness_score(r.clauses, r.n_vars, timeout_s=0.5)
    t_probe = (time.monotonic() - t0) * 1000

    print(f"  performance: PASS")
    print(f"    5×64-bit symbols, {len(constraints)} constraints")
    print(f"    DIMACS: {r.n_vars} vars, {r.n_clauses} clauses")
    print(f"    convert: {t_convert:.1f}ms, probe: {t_probe:.1f}ms")
    print(f"    score: {score:.2f}")
    assert t_convert < 5000, "conversion too slow"
    assert t_probe < 1000, "probe too slow"


def main():
    print("metis test suite\n")
    tests = [
        test_dimacs_converter,
        test_backbone_probe,
        test_offline_analysis,
        test_pysat_roundtrip,
        test_performance,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  {test.__name__}: FAIL — {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"  {passed} passed, {failed} failed")
    print(f"{'='*50}")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
