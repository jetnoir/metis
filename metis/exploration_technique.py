"""
exploration_technique.py — angr ExplorationTechnique that prioritises
easier-to-solve states using backbone fraction scoring.

States with lower backbone fraction (more solution freedom) are explored
first. States above a hardness threshold are deferred.

Usage:
    import angr
    from metis.exploration_technique import HardnessExplorationTechnique

    proj = angr.Project('./binary')
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))
    simgr.run()
"""

from __future__ import annotations

import csv
import time
from pathlib import Path

import angr

from .dimacs_converter import claripy_to_dimacs
from .backbone_probe import quick_hardness_score


class HardnessExplorationTechnique(angr.exploration_techniques.ExplorationTechnique):
    """
    Rank symbolic execution paths by constraint hardness.

    Backbone fraction is used as the hardness proxy:
    - Low backbone = many free variables = easy path = explore first
    - High backbone = rigid constraints = hard path = defer
    """

    def __init__(
        self,
        threshold: float = 0.8,
        deferred_stash: str = 'hardness_deferred',
        probe_timeout_s: float = 0.05,
        score_interval: int = 1,
        min_constraints: int = 3,
        max_score_per_step: int = 16,
        adaptive_threshold: bool = True,
        log_file: str | None = None,
    ):
        """
        Parameters:
            threshold: backbone fraction above this → defer the state.
                       If adaptive_threshold=True, this is the percentile
                       cutoff (0.8 = defer top 20% hardest).
            deferred_stash: name of the stash for deferred states
            probe_timeout_s: time budget per state scoring
            score_interval: score every N steps (1 = every step)
            min_constraints: skip scoring states with fewer constraints
            max_score_per_step: cap on states scored per step (0 = unlimited)
            adaptive_threshold: if True, defer the hardest N% instead of
                                using a fixed backbone cutoff
            log_file: path to CSV log for offline analysis (None = no log)
        """
        super().__init__()
        self._threshold = threshold
        self._deferred = deferred_stash
        self._probe_timeout = probe_timeout_s
        self._score_interval = score_interval
        self._min_constraints = min_constraints
        self._max_score = max_score_per_step
        self._adaptive = adaptive_threshold
        self._log_file = log_file

        self._score_cache: dict[int, float] = {}
        self._step_count = 0
        self._csv_writer = None
        self._csv_handle = None

    def setup(self, simgr):
        """Initialise deferred stash and optional CSV logger."""
        if self._deferred not in simgr.stashes:
            simgr.stashes[self._deferred] = []

        if self._log_file:
            self._csv_handle = open(self._log_file, 'w', newline='')
            self._csv_writer = csv.writer(self._csv_handle)
            self._csv_writer.writerow([
                'step', 'state_addr', 'n_constraints', 'n_dimacs_vars',
                'n_dimacs_clauses', 'backbone_fraction', 'action',
                'convert_ms', 'probe_ms',
            ])

    def step(self, simgr, stash='active', **kwargs):
        """Score active states after each step and defer hard ones."""
        simgr.step(stash=stash, **kwargs)

        self._step_count += 1
        if self._step_count % self._score_interval != 0:
            return simgr

        active = simgr.stashes.get(stash, [])
        if not active:
            self._recover(simgr, stash)
            return simgr

        # Score states — cap to max_score_per_step for performance
        scored = []
        unscored = []

        if self._max_score and len(active) > self._max_score:
            # Score a sample: the newest states (last in list) are most
            # likely to have changed constraints, so prioritise those
            to_score = active[-self._max_score:]
            unscored = active[:-self._max_score]
        else:
            to_score = active

        for state in to_score:
            score = self._score_state(state)
            scored.append((score, state))

        # Determine cutoff
        if self._adaptive and scored:
            scores_only = sorted(s for s, _ in scored)
            cutoff_idx = int(len(scores_only) * self._threshold)
            cutoff = scores_only[min(cutoff_idx, len(scores_only) - 1)]
            # Only defer if there's actual variance (spread > 0.1)
            score_spread = scores_only[-1] - scores_only[0]
            if score_spread < 0.1:
                cutoff = 2.0  # effectively disable deferral — all similar
        else:
            cutoff = self._threshold

        keep = []
        defer = []
        for score, state in scored:
            if score > cutoff:
                defer.append((score, state))
            else:
                keep.append((score, state))

        # Sort scored states: easiest first
        keep.sort(key=lambda x: x[0])
        # Unscored states go at the end (will be scored next time)
        simgr.stashes[stash] = [s for _, s in keep] + unscored

        for score, state in defer:
            simgr.stashes[self._deferred].append(state)

        if not simgr.stashes[stash]:
            self._recover(simgr, stash)

        return simgr

    def _score_state(self, state) -> float:
        """Compute backbone-based hardness score for a state."""
        constraints = state.solver.constraints
        n_cons = len(constraints)

        # Skip trivial states
        if n_cons < self._min_constraints:
            return 0.0

        # Cache check
        cache_key = hash(tuple(c.__hash__() for c in constraints))
        if cache_key in self._score_cache:
            cached = self._score_cache[cache_key]
            self._log(state, n_cons, 0, 0, cached, 'cached', 0, 0)
            return cached

        try:
            t0 = time.monotonic()
            dimacs = claripy_to_dimacs(constraints)
            t_convert = (time.monotonic() - t0) * 1000

            t0 = time.monotonic()
            score = quick_hardness_score(
                dimacs.clauses, dimacs.n_vars,
                timeout_s=self._probe_timeout,
            )
            t_probe = (time.monotonic() - t0) * 1000

            if score != score:  # NaN check
                score = 0.0

            action = 'defer' if score > self._threshold else 'keep'
            self._log(state, n_cons, dimacs.n_vars, dimacs.n_clauses,
                      score, action, t_convert, t_probe)

        except Exception:
            score = 0.0
            self._log(state, n_cons, 0, 0, score, 'error', 0, 0)

        self._score_cache[cache_key] = score
        return score

    def _recover(self, simgr, stash):
        """Move the easiest deferred state back to active."""
        deferred = simgr.stashes.get(self._deferred, [])
        if not deferred:
            return

        best_idx = 0
        best_score = float('inf')
        for i, state in enumerate(deferred):
            score = self._score_state(state)
            if score < best_score:
                best_score = score
                best_idx = i

        state = deferred.pop(best_idx)
        simgr.stashes[stash].append(state)

    def _log(self, state, n_cons, n_vars, n_clauses, score, action,
             convert_ms, probe_ms):
        """Write a row to the CSV log."""
        if not self._csv_writer:
            return
        try:
            addr = hex(state.addr) if hasattr(state, 'addr') else '?'
            self._csv_writer.writerow([
                self._step_count, addr, n_cons, n_vars, n_clauses,
                f'{score:.4f}', action, f'{convert_ms:.1f}', f'{probe_ms:.1f}',
            ])
            self._csv_handle.flush()
        except Exception:
            pass

    def complete(self, simgr):
        """Never signal completion — let normal exploration decide."""
        return False

    def __del__(self):
        if self._csv_handle:
            self._csv_handle.close()
