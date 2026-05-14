"""
offline_analysis.py — Full chi-squared analysis pipeline for extracted constraints.

Connects the DIMACS converter and backbone probe to the existing SAT
hardness research pipeline (pysat enumeration + chi-squared statistics).

NOT for real-time use during exploration — this is for benchmarking and
research: "how hard is this particular path constraint set?"
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np
from pysat.solvers import Glucose3

from .dimacs_converter import claripy_to_dimacs, DIMACSResult
from .backbone_probe import backbone_probe, BackboneResult


# ── Chi-squared stats (duplicated from sat_pipeline_n50.py for stability) ──

def enumerate_solutions(
    clauses: list[list[int]],
    n_vars: int,
    max_solutions: int = 500,
    timeout_s: float = 10.0,
) -> np.ndarray:
    """
    Enumerate solutions via Glucose3 blocking clauses.
    Returns binary array (n_solutions, n_vars) where 1=true, 0=false.
    """
    solver = Glucose3()
    for cl in clauses:
        solver.add_clause(cl)

    solutions = []
    t0 = time.monotonic()

    while len(solutions) < max_solutions:
        if time.monotonic() - t0 > timeout_s:
            break
        if not solver.solve():
            break
        model = solver.get_model()
        sol = np.array([1 if lit > 0 else 0 for lit in model], dtype=np.int8)
        solutions.append(sol)
        # Block this solution
        solver.add_clause([-lit for lit in model])

    solver.delete()

    if not solutions:
        return np.empty((0, n_vars), dtype=np.int8)
    return np.array(solutions, dtype=np.int8)


def compute_chisq_stats(
    solutions: np.ndarray,
    n_vars: int,
) -> dict:
    """
    Compute marginal and pairwise chi-squared statistics over a solution set.

    Returns dict with:
        marginal_chisq: sum of (count_i - n/2)^2 / (n/2) across all variables
        marginal_chisq_norm: marginal_chisq / (n_solutions * n_vars)
        pairwise_chisq: mean of corr^2 * n_solutions across all variable pairs
        entropy: mean Shannon entropy (bits) per variable
    """
    n_solutions = solutions.shape[0]
    if n_solutions < 2:
        return {
            'marginal_chisq': 0.0,
            'marginal_chisq_norm': 0.0,
            'pairwise_chisq': 0.0,
            'entropy': 0.0,
        }

    # Marginal chi-squared
    counts = solutions.sum(axis=0)
    expected = n_solutions / 2.0
    marginal_chisq = float(np.sum((counts - expected) ** 2 / expected))
    marginal_chisq_norm = marginal_chisq / (n_solutions * n_vars) if n_vars > 0 else 0.0

    # Pairwise chi-squared via correlation matrix
    X = solutions.astype(np.float64)
    X_centered = X - X.mean(axis=0)
    cov = X_centered.T @ X_centered / n_solutions
    std = np.sqrt(np.diag(cov))
    std[std == 0] = 1.0  # avoid division by zero
    corr = cov / np.outer(std, std)
    np.fill_diagonal(corr, 0)
    # Upper triangle only
    triu = np.triu_indices(n_vars, k=1)
    n_pairs = len(triu[0])
    pairwise_chisq = float(np.sum(corr[triu] ** 2 * n_solutions)) / n_pairs if n_pairs > 0 else 0.0

    # Entropy
    p = counts / n_solutions
    p = np.clip(p, 1e-10, 1 - 1e-10)
    entropy_per_var = -(p * np.log2(p) + (1 - p) * np.log2(1 - p))
    entropy = float(np.mean(entropy_per_var))

    return {
        'marginal_chisq': marginal_chisq,
        'marginal_chisq_norm': marginal_chisq_norm,
        'pairwise_chisq': pairwise_chisq,
        'entropy': entropy,
    }


@dataclass
class FullAnalysisResult:
    """Complete analysis of a constraint set."""
    dimacs: DIMACSResult
    backbone: BackboneResult
    n_solutions: int
    chisq: dict
    analysis_time_s: float


def analyze_clauses(
    clauses: list[list[int]],
    n_vars: int,
    max_solutions: int = 500,
    enum_timeout_s: float = 10.0,
) -> FullAnalysisResult:
    """Full offline analysis on raw DIMACS clauses."""
    t0 = time.monotonic()

    bp = backbone_probe(clauses, n_vars, timeout_s=1.0)

    solutions = enumerate_solutions(clauses, n_vars,
                                     max_solutions=max_solutions,
                                     timeout_s=enum_timeout_s)
    n_solutions = solutions.shape[0]

    if n_solutions >= 2:
        chisq = compute_chisq_stats(solutions, n_vars)
    else:
        chisq = {
            'marginal_chisq': 0.0, 'marginal_chisq_norm': 0.0,
            'pairwise_chisq': 0.0, 'entropy': 0.0,
        }

    return FullAnalysisResult(
        dimacs=DIMACSResult(clauses=clauses, n_vars=n_vars, n_clauses=len(clauses)),
        backbone=bp,
        n_solutions=n_solutions,
        chisq=chisq,
        analysis_time_s=time.monotonic() - t0,
    )


def analyze_state(
    state,  # angr.SimState
    max_solutions: int = 500,
    enum_timeout_s: float = 10.0,
) -> FullAnalysisResult:
    """Full offline analysis of an angr SimState's constraints."""
    t0 = time.monotonic()

    dimacs = claripy_to_dimacs(state.solver.constraints)
    bp = backbone_probe(dimacs.clauses, dimacs.n_vars, timeout_s=1.0)

    solutions = enumerate_solutions(dimacs.clauses, dimacs.n_vars,
                                     max_solutions=max_solutions,
                                     timeout_s=enum_timeout_s)
    n_solutions = solutions.shape[0]

    if n_solutions >= 2:
        chisq = compute_chisq_stats(solutions, dimacs.n_vars)
    else:
        chisq = {
            'marginal_chisq': 0.0, 'marginal_chisq_norm': 0.0,
            'pairwise_chisq': 0.0, 'entropy': 0.0,
        }

    return FullAnalysisResult(
        dimacs=dimacs, backbone=bp, n_solutions=n_solutions,
        chisq=chisq, analysis_time_s=time.monotonic() - t0,
    )
