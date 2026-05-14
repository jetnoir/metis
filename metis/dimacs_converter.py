"""
dimacs_converter.py — Convert claripy/Z3 constraints to DIMACS CNF.

The bridge between angr's symbolic execution (claripy ASTs) and
SAT-based hardness analysis (pysat DIMACS format).

Pipeline:
    claripy AST → Z3 expr → bit-blast → Tseitin CNF → DIMACS → pysat clauses
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import z3


@dataclass
class DIMACSResult:
    """Result of converting symbolic constraints to DIMACS CNF."""
    clauses: list[list[int]]                          # pysat format: [[1, -2, 3], ...]
    n_vars: int                                       # total variables after bit-blasting
    n_clauses: int                                    # len(clauses)
    var_map: dict[int, str] = field(default_factory=dict)  # DIMACS var → Z3 name
    symbol_bits: dict[str, list[int]] = field(default_factory=dict)  # symbol → DIMACS var IDs
    original_n_symbols: int = 0
    conversion_time_s: float = 0.0


def parse_dimacs_string(dimacs_str: str) -> tuple[list[list[int]], int, dict[int, str]]:
    """
    Parse a DIMACS CNF string into pysat clause format.

    Returns:
        clauses: list of lists of signed ints (1-indexed)
        n_vars: int
        var_map: dict mapping DIMACS variable int → Z3 name
    """
    clauses = []
    n_vars = 0
    var_map = {}

    for line in dimacs_str.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('c '):
            # Comment line — may contain variable name mapping
            # Format: "c <var_id> <name>"
            parts = line.split(None, 2)
            if len(parts) == 3:
                try:
                    var_id = int(parts[1])
                    var_map[var_id] = parts[2]
                except ValueError:
                    pass
        elif line.startswith('p cnf'):
            parts = line.split()
            n_vars = int(parts[2])
        elif line[0] in '0123456789-':
            # Clause line — space-separated literals terminated by 0
            lits = list(map(int, line.split()))
            if lits and lits[-1] == 0:
                lits = lits[:-1]
            if lits:
                clauses.append(lits)

    return clauses, n_vars, var_map


def build_symbol_bit_map(var_map: dict[int, str]) -> dict[str, list[int]]:
    """
    Reconstruct which DIMACS variables correspond to which bits of
    which original claripy symbols.

    Z3 names bit-blasted vars as "symbolname#bitindex" (e.g., "reg_rax#7").
    Tseitin auxiliary variables get names like "k!123".
    """
    symbol_bits: dict[str, list[int]] = {}
    bit_pattern = re.compile(r'^(.+)#(\d+)$')

    for var_id, name in var_map.items():
        m = bit_pattern.match(name)
        if m:
            symbol = m.group(1)
            symbol_bits.setdefault(symbol, []).append(var_id)
        # Skip Tseitin auxiliaries (k!N) and unnamed vars

    # Sort bit lists by var_id for consistency
    for bits in symbol_bits.values():
        bits.sort()

    return symbol_bits


def _extract_clauses_from_goal(goal) -> tuple[list[list[int]], int, dict[int, str]]:
    """
    Extract DIMACS clauses from a Z3 Goal containing CNF formulas.

    After tseitin-cnf, each formula in the goal is either:
    - A literal (Bool variable or its negation)
    - An OR of literals (a clause)

    We assign DIMACS variable IDs by collecting all Z3 Bool constants.
    """
    # Collect all Boolean variables and assign DIMACS IDs
    var_to_id: dict[int, int] = {}  # Z3 ast id → DIMACS id
    id_to_name: dict[int, str] = {}
    next_id = 1

    def get_var_id(v) -> int:
        nonlocal next_id
        aid = v.get_id()
        if aid not in var_to_id:
            var_to_id[aid] = next_id
            name = str(v)
            id_to_name[next_id] = name
            next_id += 1
        return var_to_id[aid]

    def formula_to_clause(f) -> list[int]:
        """Convert a single Z3 formula (literal or OR-of-literals) to a clause."""
        if z3.is_not(f):
            # Negated literal
            inner = f.arg(0)
            return [-get_var_id(inner)]
        elif z3.is_or(f):
            # OR of literals
            clause = []
            for i in range(f.num_args()):
                arg = f.arg(i)
                if z3.is_not(arg):
                    clause.append(-get_var_id(arg.arg(0)))
                elif z3.is_const(arg) and arg.sort() == z3.BoolSort():
                    if z3.is_true(arg):
                        return []  # trivially true clause — skip
                    elif z3.is_false(arg):
                        continue   # false literal — skip from clause
                    else:
                        clause.append(get_var_id(arg))
                else:
                    # Complex sub-expression — treat as a new variable
                    clause.append(get_var_id(arg))
            return clause
        elif z3.is_and(f):
            # AND at top level — should not happen after CNF, but handle it
            # by recursing and flattening
            return None  # signal to caller to recurse
        elif z3.is_const(f) and f.sort() == z3.BoolSort():
            if z3.is_true(f):
                return []  # trivially true
            elif z3.is_false(f):
                return [0]  # unsatisfiable marker
            else:
                return [get_var_id(f)]  # unit clause
        else:
            # Unknown — wrap as a new variable
            return [get_var_id(f)]

    clauses = []
    for i in range(goal.size()):
        f = goal.get(i)
        if z3.is_and(f):
            # Flatten top-level AND
            for j in range(f.num_args()):
                c = formula_to_clause(f.arg(j))
                if c is None:
                    # Nested AND — shouldn't happen but handle
                    pass
                elif c:
                    clauses.append(c)
        else:
            c = formula_to_clause(f)
            if c is not None and c:
                clauses.append(c)

    n_vars = next_id - 1
    return clauses, n_vars, id_to_name


def z3_exprs_to_dimacs(z3_exprs: list, timeout_ms: int = 5000) -> DIMACSResult:
    """
    Convert a list of Z3 Boolean expressions to DIMACS CNF via bit-blasting.

    Pipeline: Z3 expr → simplify → bit-blast → tseitin-cnf → extract clauses.
    """
    t0 = time.monotonic()

    goal = z3.Goal()
    for expr in z3_exprs:
        goal.add(expr)

    # Apply tactics: simplify → bit-blast bitvectors → Tseitin CNF encoding
    tactic = z3.Then(
        z3.Tactic('simplify'),
        z3.Tactic('bit-blast'),
        z3.Tactic('tseitin-cnf'),
    )

    try:
        subgoals = tactic(goal)
    except z3.Z3Exception as e:
        raise RuntimeError(f"Z3 tactic application failed: {e}") from e

    if len(subgoals) == 0:
        return DIMACSResult(
            clauses=[], n_vars=0, n_clauses=0,
            conversion_time_s=time.monotonic() - t0,
        )

    # Extract clauses from the first subgoal
    sg = subgoals[0]

    # Try DIMACS string method first (fastest, preserves Z3 naming)
    try:
        dimacs_str = sg.dimacs(include_names=True)
        clauses, n_vars, var_map = parse_dimacs_string(dimacs_str)
    except z3.Z3Exception:
        try:
            dimacs_str = sg.dimacs()
            clauses, n_vars, var_map = parse_dimacs_string(dimacs_str)
        except z3.Z3Exception:
            # Fallback: manual extraction from goal formulas
            clauses, n_vars, var_map = _extract_clauses_from_goal(sg)

    symbol_bits = build_symbol_bit_map(var_map)

    return DIMACSResult(
        clauses=clauses,
        n_vars=n_vars,
        n_clauses=len(clauses),
        var_map=var_map,
        symbol_bits=symbol_bits,
        original_n_symbols=len(symbol_bits),
        conversion_time_s=time.monotonic() - t0,
    )


# ── Cache for claripy AST → Z3 expr conversions ──────────────────────────

class CachingConverter:
    """Cache individual claripy AST → Z3 expr conversions."""

    def __init__(self):
        self._cache: dict[int, object] = {}
        self._backend = None

    def _get_backend(self):
        if self._backend is None:
            import claripy
            self._backend = claripy.backends.z3
        return self._backend

    def convert_constraints(self, constraints: list) -> list:
        """Convert list of claripy ASTs to Z3 exprs, caching previously seen ones."""
        z3_exprs = []
        backend = self._get_backend()
        for c in constraints:
            h = c.__hash__()
            if h not in self._cache:
                self._cache[h] = backend.convert(c)
            z3_exprs.append(self._cache[h])
        return z3_exprs

    @property
    def cache_size(self) -> int:
        return len(self._cache)


# ── Singleton converter for repeated use ──────────────────────────────────
_converter = CachingConverter()


def claripy_to_dimacs(
    constraints: list,
    timeout_ms: int = 5000,
) -> DIMACSResult:
    """
    Convert a list of claripy constraint ASTs into DIMACS CNF.

    Uses cached AST→Z3 conversion, then Z3 bit-blast → Tseitin → DIMACS.
    """
    z3_exprs = _converter.convert_constraints(constraints)
    return z3_exprs_to_dimacs(z3_exprs, timeout_ms=timeout_ms)


def state_to_dimacs(
    state,  # angr.SimState
    timeout_ms: int = 5000,
) -> DIMACSResult:
    """
    Extract constraints from an angr SimState and convert to DIMACS CNF.
    """
    constraints = state.solver.constraints
    return claripy_to_dimacs(constraints, timeout_ms=timeout_ms)


# ── Standalone Z3 helper (no claripy/angr dependency) ─────────────────────

def z3_formula_to_dimacs(formula) -> DIMACSResult:
    """
    Convert a Z3 formula (BoolRef) directly to DIMACS CNF.

    Useful for testing without angr:
        x, y = z3.Bools('x y')
        result = z3_formula_to_dimacs(z3.And(x, z3.Or(y, z3.Not(x))))
    """
    if isinstance(formula, list):
        exprs = formula
    else:
        exprs = [formula]
    return z3_exprs_to_dimacs(exprs)
