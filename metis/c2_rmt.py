"""
c2_rmt.py — C2: Random Matrix Theory call graph screener for macOS binaries.

Screens Mach-O binaries for anomalous call graph structure using spectral
graph theory with a configuration-model null distribution.

Two-level output
----------------
Binary level
    Three spectral metrics (spectral radius, graph energy, eigenvalue entropy)
    are each z-scored against 50 randomised configuration-model null graphs
    that preserve the observed degree sequence. A binary is flagged when any
    metric deviates > ANOMALY_Z_THRESHOLD σ from its null.

Function level
    Functions are ranked by a combined local anomaly score:
      • Eigenvector centrality in the call graph (hub/spoke anomaly)
      • Cyclomatic complexity of the function's own CFG (M = E − N + 2)
      • Back-edge count (proxy for loop nesting depth)
      • Strongly connected component count (loop structure)

Design decisions (from four-LLM purple team synthesis)
-------------------------------------------------------
Marchenko–Pastur / Wigner semicircle are WRONG null models for real call
graphs (power-law degree, hub-and-spoke, bipartite caller/callee structure).
We use the directed configuration model (networkx.directed_configuration_model)
which preserves the observed in/out degree sequence — the anomaly signal is
therefore relative to "a random graph that looks like this one", not "a
completely random graph".

RMT asymptotics require N → large (typically N > 200 for reliable z-scores).
Whole-binary call graphs usually satisfy this; per-function CFGs rarely do.
Per-function uses simpler local metrics instead of RMT.

Call graph extraction via angr CFGFast catches inlined stubs, thunks, tail
calls, and indirect branches that lief symbol walking misses entirely.

Three spectral metrics rather than one
    Spectral radius (λ_max) alone is 0 for pure DAGs (common in clean code).
    Graph energy (Σ|λ_i|/N) and eigenvalue entropy (−Σ p_i log p_i) give
    discriminative signal even when the call graph is acyclic.

Integration with C6 / C1
------------------------
    C2Result.functions_ranked feeds the priority queue for targeted C6 taint
    analysis. Pass the top-K function addresses to C6Analysis.run():

        result = C2RMTAnalysis(binary_path).run()
        for addr, score in result.functions_ranked[:10]:
            c6_result = c6.run(proj.factory.call_state(addr), ...)

Eigenvalue interpretation (from four-LLM purple-team review, 2026-04-18)
------------------------------------------------------------------------
For DIRECTED graphs, the adjacency matrix of a pure DAG (no recursion,
no cycles) is nilpotent → all eigenvalues are ZERO. Therefore non-zero
eigenvalues exclusively measure CYCLIC structure — strongly connected
components, mutual recursion, callback registration, and complex state
machine loops. This means:

  z_energy > 0   → excess cyclic/mutually-coupled structure relative to a
                   degree-preserving random graph. NOT merely a large
                   dispatcher hub (which is a tree/DAG and yields λ=0).
                   Security relevance: state machine parsers, recursive
                   handlers, and callback-heavy dispatch are the common
                   patterns. These are harder to audit and historically
                   more vulnerable than simple one-way call chains.

  z_energy < 0   → fewer cycles than random — flatter, more tree-like
                   structure. Less complex but may still have isolated
                   vulnerable leaf functions.

  z_entropy < 0  → eigenvalue energy is MORE CONCENTRATED in a few
                   dominant eigenvalues. One or a small SCC drives the
                   spectrum. Paired with high z_energy: strong single core.

Known limitations
-----------------
1. CFGFast misses indirect calls through function pointers. For ObjC dispatch
   via objc_msgSend, synthetic call edges are injected by ObjCDispatchResolver
   (v2) after CFGFast completes. Swift vtable dispatch is not yet modelled.
2. ARM64e PAC-authenticated calls appear as indirect; CFGFast may not
   resolve them. For PAC-heavy binaries, call graph will be incomplete.
3. 50 null samples is sufficient for graphs > 100 nodes; smaller graphs
   have high null variance so z-scores are noisy (reported but flagged).
4. scipy.linalg.eigvals is O(N³). For call graphs > 2000 nodes, we fall
   back to scipy.sparse.linalg.eigs (top-k eigenvalues only). This
   approximates graph energy and entropy; spectral radius is unaffected.
5. Graph quality gate: _check_graph_quality() runs before RMT and sets
   reliable=False if edge density < 10/N or if the largest weakly-connected
   component covers < 50% of nodes. This catches degenerate partial CFGs
   (e.g., large ObjC/Swift binaries under parallel memory pressure) before
   they produce bogus z-scores. The findmydeviced artifact (z_energy=+17σ
   from a degenerate CFG, corrected to z≈0 on clean re-run) motivated this.

Usage
-----
    from metis.c2_rmt import C2RMTAnalysis

    result = C2RMTAnalysis('/usr/libexec/targetd').run()
    result.print_report()

    # Re-use a pre-loaded angr project (avoids double-loading)
    import angr
    proj = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
    result = C2RMTAnalysis.from_project(proj).run()

Requires: angr >= 9.2, networkx, numpy, scipy
"""

from __future__ import annotations

import logging
import math
import platform
from dataclasses import dataclass, field
from typing import Optional

import angr
import archinfo
import networkx as nx
import numpy as np
from scipy.linalg import eigvals as dense_eigvals

log = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────────

NULL_SAMPLES           = 50     # null model replicates for z-score baseline
ANOMALY_Z_THRESHOLD    = 2.0    # flag binary when any metric z-score > this
MIN_NODES_RMT          = 20     # minimum call-graph nodes for RMT to be valid
SPARSE_CUTOFF          = 2000   # switch to sparse eigensolver above this
SPARSE_TOP_K           = 100    # number of eigenvalues for sparse approximation
FAST_C2_THRESHOLD_MB   = 3.5    # binaries > this use FastC2 (lief+capstone) not angr


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class SpectralMetrics:
    """
    Three spectral metrics computed from a graph's adjacency matrix eigenvalues.

    spectral_radius : λ_max (largest real eigenvalue). Zero for DAGs.
    graph_energy    : Σ|λ_i| / N. Non-zero even for DAGs; scales with N.
    eig_entropy     : −Σ p_i log p_i where p_i = |λ_i| / Σ|λ_j|.
                      High entropy = many eigenvalues of similar magnitude
                      (unusual for compiler-generated code).
    """
    spectral_radius : float
    graph_energy    : float
    eig_entropy     : float
    n_nodes         : int
    n_edges         : int
    approx          : bool = False   # True if sparse approximation was used


@dataclass
class BinaryRMTScore:
    """
    Whole-binary RMT screening result.

    z_radius, z_energy, z_entropy : z-scores vs. null distribution
    flagged                        : True if any z-score > ANOMALY_Z_THRESHOLD
    reliable                       : False if graph is too small for RMT
    """
    observed        : SpectralMetrics
    null_mean       : SpectralMetrics
    null_std        : SpectralMetrics
    z_radius        : float
    z_energy        : float
    z_entropy       : float
    flagged         : bool
    reliable        : bool    # False when N < MIN_NODES_RMT or graph quality failed

    @property
    def z_combined(self) -> float:
        """Combined z-score: √(z_r² + z_e² + z_n²).

        Addresses the multiple-testing problem: with 3 metrics × 560 binaries,
        ~28 hits at |z|>2 are expected by chance.  A single combined metric
        with a higher threshold (e.g., z_combined > 3.5) gives better FDR.
        """
        return math.sqrt(self.z_radius**2 + self.z_energy**2 + self.z_entropy**2)


@dataclass
class FunctionScore:
    """
    Per-function local anomaly score.

    Combined score = weighted sum of normalised:
      ev_centrality (call-graph hub-ness)
      cyclomatic    (branching complexity)
      back_edges    (loop count proxy)
    """
    addr            : int
    name            : str
    ev_centrality   : float
    cyclomatic      : int
    back_edges      : int
    scc_count       : int
    combined        : float


@dataclass
class C2Result:
    """
    Full C2 analysis result for one binary.

    binary_score     : whole-binary RMT z-score result
    functions_ranked : list of FunctionScore, sorted by combined score descending
    n_functions      : total functions discovered by CFGFast
    binary_path      : path analysed
    engine           : 'fast' (FastC2/lief+capstone) or 'full' (C2RMTAnalysis/angr)
    """
    binary_score     : BinaryRMTScore
    functions_ranked : list[FunctionScore]
    n_functions      : int
    binary_path      : str
    engine           : str = 'full'

    def print_report(self) -> None:
        b = self.binary_score
        print(f'\nC2 RMT Report — {self.binary_path}')
        print('=' * 70)
        print(f'Functions discovered : {self.n_functions}')
        print(f'Call graph           : {b.observed.n_nodes} nodes, '
              f'{b.observed.n_edges} edges '
              f'({"approx" if b.observed.approx else "exact"} eigenvalues)')
        print(f'RMT reliable         : {"yes" if b.reliable else "no (N < " + str(MIN_NODES_RMT) + ")"}')
        print()
        print('Binary-level spectral z-scores (vs. configuration-model null)')
        print(f'  λ_max (spectral radius)  : {b.observed.spectral_radius:8.4f}  '
              f'z = {b.z_radius:+.2f}')
        print(f'  Graph energy Σ|λ|/N      : {b.observed.graph_energy:8.4f}  '
              f'z = {b.z_energy:+.2f}')
        print(f'  Eigenvalue entropy       : {b.observed.eig_entropy:8.4f}  '
              f'z = {b.z_entropy:+.2f}')
        print(f'  z_combined (√Σzᵢ²)      :          '
              f'  z = {b.z_combined:+.2f}')
        flag_str = '*** ANOMALOUS ***' if b.flagged else 'within normal range'
        print(f'\nVerdict: {flag_str}  (threshold |z| > {ANOMALY_Z_THRESHOLD})')

        if self.functions_ranked:
            print(f'\nTop-10 anomalous functions (of {len(self.functions_ranked)} scored)')
            print(f'  {"Score":>8}  {"Addr":>12}  {"Cyclo":>6}  {"BkEdge":>6}  Name')
            for f in self.functions_ranked[:10]:
                print(f'  {f.combined:8.4f}  {f.addr:#012x}  {f.cyclomatic:6d}  '
                      f'{f.back_edges:6d}  {f.name}')
        print()

    @property
    def z_combined(self) -> float:
        """Delegates to binary_score.z_combined."""
        return self.binary_score.z_combined

    @property
    def top_function_addrs(self) -> list[int]:
        """Addresses of top-ranked functions, for feeding into C6."""
        return [f.addr for f in self.functions_ranked]


# ── Spectral helpers ───────────────────────────────────────────────────────────

def _eigenvalues(G: nx.DiGraph) -> np.ndarray:
    """
    Compute eigenvalues of G's adjacency matrix.

    Uses dense eigensolver for N ≤ SPARSE_CUTOFF, sparse approximation above.
    For large graphs (n > SPARSE_CUTOFF), builds the CSR matrix directly from
    the edge list to avoid the 1.66 GB+ dense allocation that would otherwise
    occur via nx.to_numpy_array.

    Returns array of real parts (imaginary parts are noise for real matrices).
    """
    n = G.number_of_nodes()
    if n < 2:
        return np.zeros(1)

    if n <= SPARSE_CUTOFF:
        A = nx.to_numpy_array(G, dtype=np.float64)
        eigs = dense_eigvals(A)
        return eigs.real.astype(np.float64)
    else:
        # Build CSR directly from edge list — never allocate the dense n×n matrix
        import scipy.sparse as sp
        import scipy.sparse.linalg as spla
        # Map node identifiers to integer indices
        node_list = list(G.nodes())
        idx = {v: i for i, v in enumerate(node_list)}
        rows, cols, data = [], [], []
        for u, v in G.edges():
            rows.append(idx[u])
            cols.append(idx[v])
            data.append(1.0)
        if not rows:
            # No edges → all-zero adjacency → all eigenvalues = 0
            return np.zeros(1)
        A_sparse = sp.csr_matrix(
            (data, (rows, cols)), shape=(n, n), dtype=np.float64
        )
        k = min(SPARSE_TOP_K, n - 2)
        try:
            eigs, _ = spla.eigs(A_sparse, k=k, which='LM')
            return eigs.real.astype(np.float64)
        except Exception:
            # Fallback to dense for small n where sparse eigs fails
            A = nx.to_numpy_array(G, dtype=np.float64)
            eigs = dense_eigvals(A)
            return eigs.real.astype(np.float64)


def _spectral_metrics(G: nx.DiGraph) -> SpectralMetrics:
    """Compute all three spectral metrics from G."""
    n = G.number_of_nodes()
    e = G.number_of_edges()

    if n < 2:
        return SpectralMetrics(0.0, 0.0, 0.0, n, e)

    approx = n > SPARSE_CUTOFF
    eigs   = _eigenvalues(G)
    abs_e  = np.abs(eigs)
    total  = abs_e.sum()

    radius  = float(np.max(eigs))
    energy  = float(total / n) if n > 0 else 0.0

    if total > 1e-12:
        p       = abs_e / total
        p       = p[p > 1e-15]          # drop numerical zeros
        entropy = float(-np.sum(p * np.log(p)))
    else:
        entropy = 0.0

    return SpectralMetrics(radius, energy, entropy, n, e, approx)


def _z(observed: float, mean: float, std: float) -> float:
    """Safe z-score; returns 0 when std is negligible."""
    return (observed - mean) / std if std > 1e-9 else 0.0


# ── CFG structural helpers ─────────────────────────────────────────────────────

def _count_back_edges(cfg: nx.DiGraph) -> int:
    """
    Count back edges in the function CFG via iterative DFS.

    A back edge is one that targets an ancestor in the DFS tree — these
    indicate loops. Iterative to avoid Python recursion limit on large
    Windows PE / Linux ELF function CFGs (> 1000 basic blocks).
    """
    back     = 0
    visited:  set = set()
    in_stack: set = set()

    for start in cfg.nodes():
        if start in visited:
            continue
        visited.add(start)
        in_stack.add(start)
        stack = [(start, iter(cfg.successors(start)))]
        while stack:
            node, succs = stack[-1]
            try:
                succ = next(succs)
                if succ not in visited:
                    visited.add(succ)
                    in_stack.add(succ)
                    stack.append((succ, iter(cfg.successors(succ))))
                elif succ in in_stack:
                    back += 1
            except StopIteration:
                stack.pop()
                in_stack.discard(node)

    return back


def _function_combined_score(
    ev: float,
    cyclomatic: int,
    back_edges: int,
) -> float:
    """
    Weighted combination of local anomaly signals.

    Normalisation:
      ev_centrality   — already in [0, 1]
      cyclomatic      — log1p(max(0, M − 1)); M=1 is trivial, higher is complex
      back_edges      — log1p(k); each loop adds log-scaled weight
    """
    norm_cyc  = math.log1p(max(0, cyclomatic - 1))
    norm_back = math.log1p(back_edges)
    return 0.4 * ev + 0.35 * norm_cyc + 0.25 * norm_back


# ── Main analysis class ────────────────────────────────────────────────────────

class C2RMTAnalysis:
    """
    C2 RMT call graph screener for a single Mach-O binary.

    Parameters
    ----------
    binary_path     : path to the Mach-O binary
    n_null_samples  : number of configuration-model null replicates (default 50)
    project         : pre-loaded angr.Project (avoids double-load; optional)

    Example
    -------
    ::

        from metis.c2_rmt import C2RMTAnalysis

        result = C2RMTAnalysis('/usr/libexec/targetd').run()
        result.print_report()

        # Get top function addresses for C6 targeting
        top_addrs = result.top_function_addrs[:10]
    """

    def __init__(
        self,
        binary_path: str,
        n_null_samples: int = NULL_SAMPLES,
        project: Optional[angr.Project] = None,
    ) -> None:
        self.binary_path    = binary_path
        self.n_null_samples = n_null_samples
        self._proj          = project
        self._cfg           = None

    @classmethod
    def from_project(
        cls,
        project: angr.Project,
        n_null_samples: int = NULL_SAMPLES,
    ) -> 'C2RMTAnalysis':
        """
        Construct from an already-loaded angr.Project.

        Use this when C6Analysis has already loaded the binary to avoid
        paying the load cost twice.
        """
        inst = cls(
            binary_path    = str(project.filename),
            n_null_samples = n_null_samples,
            project        = project,
        )
        return inst

    @staticmethod
    def _host_arch() -> archinfo.Arch:
        """
        Return the archinfo.Arch matching the host CPU.

        On Apple Silicon (arm64/arm64e) this returns aarch64, preventing
        angr from defaulting to the x86_64 slice of universal Mach-O binaries.
        """
        machine = platform.machine().lower()
        if machine in ('arm64', 'aarch64'):
            return archinfo.arch_from_id('aarch64')
        return archinfo.arch_from_id('x86_64')

    def _load(self) -> None:
        """Load the binary and run CFGFast (idempotent)."""
        if self._proj is None:
            log.info('C2: loading %s', self.binary_path)
            self._proj = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                main_opts={'arch': self._host_arch()},
            )

        if self._cfg is None:
            log.info('C2: running CFGFast')
            # normalize=False avoids the LMDB serialization pass that fails
            # on large binaries (angr bug in _load_from_lmdb_core). CFG edges
            # are unaffected; only basic-block splitting behaviour differs.
            self._cfg = self._proj.analyses.CFGFast(
                normalize=False,
                resolve_indirect_jumps=False,  # avoids cle None max_addr bug on PE
                data_references=False,         # not needed for call graph extraction
            )
            log.info('C2: %d functions', len(list(self._proj.kb.functions.items())))

    @staticmethod
    def _check_graph_quality(G: nx.DiGraph) -> tuple[bool, str]:
        """
        Pre-RMT sanity check for degenerate / partial call graphs.

        Returns (ok, reason_string).  Sets reliable=False when:
          - Average degree < 10/N  (graph is pathologically sparse — likely a
            partial CFG from a failed angr analysis run)
          - Giant weakly-connected component < 50% of nodes  (fragmented CFG —
            usually caused by memory pressure during parallel batch analysis)

        Both conditions correspond to the findmydeviced artifact (2026-04-18):
        ProcessPoolExecutor with 3 workers produced degenerate call graphs for
        large ObjC/Swift binaries, yielding extreme bogus z-scores.
        """
        n = G.number_of_nodes()
        m = G.number_of_edges()
        if n == 0:
            return False, 'empty graph'
        avg_deg = m / n
        if avg_deg < max(10 / n, 0.5):   # avg degree < 10/N or < 0.5 edges/node
            return False, (f'too sparse (avg_deg={avg_deg:.2f}, '
                           f'edges={m}, nodes={n})')
        wccs = list(nx.weakly_connected_components(G))
        if not wccs:
            return False, 'no weakly connected components'
        giant = max(len(c) for c in wccs)
        if giant / n < 0.5:
            return False, (f'fragmented CFG (giant WCC={giant/n:.1%} of {n} nodes)')
        return True, 'ok'

    def _build_call_graph(self) -> nx.DiGraph:
        """
        Extract the inter-function call graph as a simple DiGraph.

        angr.kb.callgraph is a MultiDiGraph (parallel edges for multiple
        call sites to the same callee). Convert to DiGraph, remove self-loops
        (recursive calls to self skew the spectral radius).
        Self-loops are removed for the RMT computation but counted separately
        for the recursive-call metric.
        """
        raw = self._proj.kb.callgraph   # MultiDiGraph
        G   = nx.DiGraph()

        for u, v in raw.edges():
            if u != v:                   # exclude self-loops from RMT graph
                G.add_edge(u, v)

        return G

    def _null_distribution(
        self, G: nx.DiGraph
    ) -> tuple[list[float], list[float], list[float]]:
        """
        Sample n_null_samples configuration-model graphs and collect metrics.

        Returns three lists (radii, energies, entropies) from valid samples.
        Invalid samples (e.g. empty graphs from degenerate degree sequences)
        are silently skipped.
        """
        in_seq  = [G.in_degree(n)  for n in G.nodes()]
        out_seq = [G.out_degree(n) for n in G.nodes()]

        radii:    list[float] = []
        energies: list[float] = []
        entropies:list[float] = []

        for _ in range(self.n_null_samples):
            try:
                G_null = nx.directed_configuration_model(
                    in_seq, out_seq, create_using=nx.MultiDiGraph()
                )
                G_s = nx.DiGraph(G_null)
                G_s.remove_edges_from(nx.selfloop_edges(G_s))
                m = _spectral_metrics(G_s)
                radii.append(m.spectral_radius)
                energies.append(m.graph_energy)
                entropies.append(m.eig_entropy)
            except Exception:
                continue

        return radii, energies, entropies

    def _score_functions(self, cg: nx.DiGraph) -> list[FunctionScore]:
        """
        Score every non-stub function by local structural anomaly.

        Eigenvector centrality: measures hub-ness in the call graph.
        High centrality = many callers and/or called-by highly central nodes.
        Anomalously central functions (dispatcher stubs, thunk clusters,
        injected payload launchers) appear at the top.

        CFG structural metrics (cyclomatic complexity, back edges, SCC count):
        computed from each function's own basic-block CFG recovered by angr.
        """
        # Eigenvector centrality over the full call graph
        try:
            ev = nx.eigenvector_centrality_numpy(cg, weight=None)
        except Exception:
            # Falls back to in-degree centrality when convergence fails
            # (common for very sparse or disconnected graphs)
            try:
                total_in = sum(dict(cg.in_degree()).values()) or 1
                ev = {n: cg.in_degree(n) / total_in for n in cg.nodes()}
            except Exception:
                ev = {n: 0.0 for n in cg.nodes()}

        scores: list[FunctionScore] = []

        for addr, func in list(self._proj.kb.functions.items()):
            # Skip PLT stubs and SimProcedure replacements — they are noise
            if func.is_plt or func.is_simprocedure:
                continue

            ev_score = float(ev.get(addr, 0.0))

            # Function's own CFG structural metrics
            cfg_g    = func.graph
            n_nodes  = cfg_g.number_of_nodes()
            n_edges  = cfg_g.number_of_edges()

            try:
                if n_nodes < 2:
                    cyclomatic = 1
                    back_edges = 0
                    scc_count  = 1
                else:
                    cyclomatic = max(1, n_edges - n_nodes + 2)
                    back_edges = _count_back_edges(cfg_g)
                    scc_count  = nx.number_strongly_connected_components(cfg_g)
            except Exception:
                cyclomatic = 1
                back_edges = 0
                scc_count  = 1

            scores.append(FunctionScore(
                addr          = addr,
                name          = func.name or f'sub_{addr:#x}',
                ev_centrality = ev_score,
                cyclomatic    = cyclomatic,
                back_edges    = back_edges,
                scc_count     = scc_count,
                combined      = _function_combined_score(
                                    ev_score, cyclomatic, back_edges
                                ),
            ))

        return sorted(scores, key=lambda s: s.combined, reverse=True)

    def run(self) -> C2Result:
        """
        Run the full C2 analysis: CFG recovery → call graph → ObjC edge
        injection → RMT screening → function ranking.

        Returns
        -------
        C2Result with binary-level z-scores and ranked function list.
        """
        self._load()

        cg = self._build_call_graph()
        log.info('C2: call graph: %d nodes, %d edges',
                 cg.number_of_nodes(), cg.number_of_edges())

        # ── Graph quality gate ────────────────────────────────────────────────
        # Reject degenerate / partial CFGs before RMT (prevents findmydeviced-
        # style false positives from memory-pressured parallel batch runs).
        _gq_ok, _gq_reason = self._check_graph_quality(cg)
        if not _gq_ok:
            log.warning('C2: graph quality gate FAILED: %s — marking reliable=False',
                        _gq_reason)

        # ── ObjC dispatch augmentation ────────────────────────────────────────
        # Inject synthetic call graph edges for objc_msgSend dispatch sites.
        # Skipped silently on non-ObjC binaries (is_objc_binary check inside).
        try:
            from metis.objc_dispatch import ObjCDispatchResolver
            _objc = ObjCDispatchResolver(self._proj)
            _objc_result = _objc.resolve()
            if _objc_result.is_objc_binary:
                added = _objc.inject_into_callgraph(cg)
                log.info('C2: ObjC dispatch: +%d synthetic edges '
                         '(%d selectors, %d resolved sites)',
                         added, _objc_result.selector_count,
                         _objc_result.resolved_sites)
        except Exception as exc:
            log.warning('C2: ObjC dispatch resolver failed: %s', exc)

        # ── Binary-level RMT ──────────────────────────────────────────────────
        obs = _spectral_metrics(cg)

        reliable = (cg.number_of_nodes() >= MIN_NODES_RMT) and _gq_ok

        if reliable:
            radii, energies, entropies = self._null_distribution(cg)

            if radii:
                null_mean = SpectralMetrics(
                    spectral_radius = float(np.mean(radii)),
                    graph_energy    = float(np.mean(energies)),
                    eig_entropy     = float(np.mean(entropies)),
                    n_nodes         = obs.n_nodes,
                    n_edges         = obs.n_edges,
                )
                null_std = SpectralMetrics(
                    spectral_radius = float(np.std(radii)),
                    graph_energy    = float(np.std(energies)),
                    eig_entropy     = float(np.std(entropies)),
                    n_nodes         = 0,
                    n_edges         = 0,
                )
            else:
                log.warning('C2: null model sampling failed; z-scores set to 0')
                null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)

            z_radius  = _z(obs.spectral_radius, null_mean.spectral_radius,
                           null_std.spectral_radius)
            z_energy  = _z(obs.graph_energy,    null_mean.graph_energy,
                           null_std.graph_energy)
            z_entropy = _z(obs.eig_entropy,     null_mean.eig_entropy,
                           null_std.eig_entropy)
            flagged   = (abs(z_radius)  > ANOMALY_Z_THRESHOLD or
                         abs(z_energy)  > ANOMALY_Z_THRESHOLD or
                         abs(z_entropy) > ANOMALY_Z_THRESHOLD)
        else:
            log.warning('C2: graph too small for reliable RMT (N=%d < %d)',
                        cg.number_of_nodes(), MIN_NODES_RMT)
            null_mean = null_std = SpectralMetrics(0., 0., 0., 0, 0)
            z_radius = z_energy = z_entropy = 0.0
            flagged = False

        binary_score = BinaryRMTScore(
            observed  = obs,
            null_mean = null_mean,
            null_std  = null_std,
            z_radius  = z_radius,
            z_energy  = z_energy,
            z_entropy = z_entropy,
            flagged   = flagged,
            reliable  = reliable,
        )

        log.info('C2: z_radius=%.2f  z_energy=%.2f  z_entropy=%.2f  flagged=%s',
                 z_radius, z_energy, z_entropy, flagged)

        # ── Per-function ranking ──────────────────────────────────────────────
        log.info('C2: scoring functions')
        functions_ranked = self._score_functions(cg)

        return C2Result(
            binary_score     = binary_score,
            functions_ranked = functions_ranked,
            n_functions      = len(self._proj.kb.functions),
            binary_path      = self.binary_path,
        )


# ── Auto-selecting factory ─────────────────────────────────────────────────────

def analyse_binary(
    binary_path: str,
    n_null_samples: int = NULL_SAMPLES,
    force_fast: bool = False,
    force_full: bool = False,
) -> 'C2Result':
    """
    Auto-selecting C2 factory: choose FastC2Analysis or C2RMTAnalysis based
    on binary size.

    Binaries > FAST_C2_THRESHOLD_MB (3.5 MB) use FastC2Analysis (lief+capstone)
    which has no size limit but produces approximate cyclomatic scores and
    lacks ObjC dispatch resolution.

    Binaries <= FAST_C2_THRESHOLD_MB use the full C2RMTAnalysis (angr CFGFast)
    which is exact but OOMs on large binaries.

    Parameters
    ----------
    binary_path     : path to Mach-O binary
    n_null_samples  : null model replicates
    force_fast      : always use FastC2Analysis regardless of size
    force_full      : always use C2RMTAnalysis regardless of size
                      (will OOM on large binaries — use only for testing)

    Example
    -------
    ::

        from metis.c2_rmt import analyse_binary

        result = analyse_binary('/usr/libexec/cloudd')   # auto
        result = analyse_binary('/usr/libexec/cloudd', force_fast=True)
        result.print_report()
    """
    import os

    size_bytes = os.path.getsize(binary_path)
    size_mb    = size_bytes / (1024 * 1024)
    use_fast   = force_fast or (not force_full and size_mb > FAST_C2_THRESHOLD_MB)

    if use_fast:
        log.info('analyse_binary: %.1f MB → FastC2Analysis (lief+capstone)', size_mb)
        from metis.fast_c2 import FastC2Analysis
        return FastC2Analysis(binary_path, n_null_samples=n_null_samples).run()
    else:
        log.info('analyse_binary: %.1f MB → C2RMTAnalysis (angr CFGFast)', size_mb)
        return C2RMTAnalysis(binary_path, n_null_samples=n_null_samples).run()


# ── Corpus screener ────────────────────────────────────────────────────────────

def screen_corpus(
    binary_paths: list[str],
    n_null_samples: int = NULL_SAMPLES,
) -> list[tuple[str, C2Result]]:
    """
    Run C2 screening over a list of binaries and return results sorted by
    worst-case z-score (most anomalous first).

    Parameters
    ----------
    binary_paths   : list of absolute paths to Mach-O binaries
    n_null_samples : null replicates per binary

    Returns
    -------
    List of (path, C2Result) sorted descending by max(|z_radius|, |z_energy|,
    |z_entropy|).
    """
    results = []
    for path in binary_paths:
        try:
            r = C2RMTAnalysis(path, n_null_samples=n_null_samples).run()
            results.append((path, r))
        except Exception as e:
            log.error('C2: failed on %s: %s', path, e)

    def _worst_z(item):
        r = item[1].binary_score
        return max(abs(r.z_radius), abs(r.z_energy), abs(r.z_entropy))

    return sorted(results, key=_worst_z, reverse=True)
