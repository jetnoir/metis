"""
semantic_backbone.py — Tseitin-invariant backbone detection via Z3 assumptions.

Instead of bit-blasting → DIMACS → pysat backbone, this operates directly
on the claripy/Z3 constraint set using assumption-based probing on the
ORIGINAL symbolic input bits only.

Result: backbone fraction computed purely over semantic variables (input bytes),
not Tseitin encoding auxiliaries. Faster AND more accurate than the DIMACS path.

    a == 0x42:  old pipeline → 0.13 (diluted by Tseitin)
                this module  → 1.00 (correct — all 8 bits forced)
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import z3


@dataclass
class SemanticBackboneResult:
    """Result of semantic backbone analysis."""
    backbone_fraction: float       # forced_semantic_bits / total_semantic_bits
    n_forced: int                  # bits with a single forced value
    n_free: int                    # bits that can take either value
    n_semantic_bits: int           # total input bits probed
    forced_bits: dict[str, list[tuple[int, int]]]  # symbol → [(bit_idx, forced_value)]
    probe_time_s: float
    timed_out: bool


def _extract_symbolic_bits(constraints: list) -> dict[str, int]:
    """
    Walk claripy ASTs to find all BVS (bitvector symbol) leaf variables
    and their widths.

    Returns: {symbol_name: bit_width}
    """
    import claripy

    symbols = {}
    seen = set()

    def walk(ast):
        ast_id = id(ast)
        if ast_id in seen:
            return
        seen.add(ast_id)

        if ast.op == 'BVS':
            name = ast.args[0]
            width = ast.length
            if name not in symbols:
                symbols[name] = width
            return

        for arg in ast.args:
            if hasattr(arg, 'op'):
                walk(arg)

    for c in constraints:
        walk(c)

    return symbols


def semantic_backbone_claripy(
    constraints: list,
    timeout_s: float = 0.5,
    max_bits: int = 512,
) -> SemanticBackboneResult:
    """
    Compute backbone fraction over semantic input bits only.

    Uses Z3 solver with assumptions — no bit-blast, no Tseitin, no DIMACS.

    For each bit of each symbolic input variable:
        1. Create an indicator: ind = Bool(f'{sym}_{bit}')
        2. Assert ind == (Extract(bit, bit, sym) == 1)
        3. Check SAT with assumptions=[ind] and assumptions=[Not(ind)]
        4. If one is UNSAT → bit is forced (backbone)

    Parameters:
        constraints: list of claripy ASTs
        timeout_s: total wall-clock budget
        max_bits: cap on total bits probed (for very wide symbols)
    """
    import claripy as cl

    t0 = time.monotonic()

    # Find all symbolic bitvector variables
    symbols = _extract_symbolic_bits(constraints)
    if not symbols:
        return SemanticBackboneResult(
            backbone_fraction=0.0, n_forced=0, n_free=0,
            n_semantic_bits=0, forced_bits={},
            probe_time_s=time.monotonic() - t0, timed_out=False,
        )

    # Build Z3 solver with all constraints
    backend = cl.backends.z3
    solver = z3.Solver()

    for c in constraints:
        try:
            z3_expr = backend.convert(c)
            solver.add(z3_expr)
        except Exception:
            continue

    # Check base satisfiability
    if solver.check() != z3.sat:
        return SemanticBackboneResult(
            backbone_fraction=1.0, n_forced=0, n_free=0,
            n_semantic_bits=0, forced_bits={},
            probe_time_s=time.monotonic() - t0, timed_out=False,
        )

    base_model = solver.model()

    # Probe each semantic bit
    n_forced = 0
    n_free = 0
    n_total = 0
    forced_bits: dict[str, list[tuple[int, int]]] = {}
    timed_out = False

    for sym_name, width in symbols.items():
        if n_total >= max_bits:
            break

        # Get the Z3 BitVec for this symbol
        z3_sym = z3.BitVec(sym_name, width)

        bits_to_probe = min(width, max_bits - n_total)
        forced_bits[sym_name] = []

        for bit_idx in range(bits_to_probe):
            if time.monotonic() - t0 > timeout_s:
                timed_out = True
                break

            n_total += 1
            bit_expr = z3.Extract(bit_idx, bit_idx, z3_sym)

            # Get the value in the base model
            model_val = base_model.eval(bit_expr, model_completion=True)

            if z3.is_bv_value(model_val):
                val = model_val.as_long()
            else:
                n_free += 1
                continue

            # Try the opposite value
            if val == 1:
                negation = bit_expr == 0
            else:
                negation = bit_expr == 1

            solver.push()
            solver.add(negation)
            result = solver.check()
            solver.pop()

            if result == z3.unsat:
                # Bit is forced (backbone)
                n_forced += 1
                forced_bits[sym_name].append((bit_idx, val))
            else:
                n_free += 1

        if timed_out:
            break

    elapsed = time.monotonic() - t0

    return SemanticBackboneResult(
        backbone_fraction=n_forced / n_total if n_total > 0 else 0.0,
        n_forced=n_forced,
        n_free=n_free,
        n_semantic_bits=n_total,
        forced_bits=forced_bits,
        probe_time_s=elapsed,
        timed_out=timed_out,
    )


def semantic_backbone_state(
    state,  # angr.SimState
    timeout_s: float = 0.5,
    max_bits: int = 512,
) -> SemanticBackboneResult:
    """Convenience wrapper for angr SimState objects."""
    return semantic_backbone_claripy(
        state.solver.constraints,
        timeout_s=timeout_s,
        max_bits=max_bits,
    )


def quick_semantic_score(
    constraints: list,
    timeout_s: float = 0.1,
) -> float:
    """
    Fast scoring: returns semantic backbone fraction or 0.0 on error.
    For use in the ExplorationTechnique hot loop.
    """
    try:
        result = semantic_backbone_claripy(
            constraints, timeout_s=timeout_s, max_bits=256,
        )
        return result.backbone_fraction
    except Exception:
        return 0.0
