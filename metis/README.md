# Metis — Vulnerability Research Pipeline

Automated binary vulnerability triage for macOS, Linux, and Windows targets.
Pipeline: spectral call graph screening (C2), template dataflow matching with full SSA
memory taint (C3), symbolic taint analysis (C6), and on-device dynamic validation (C7).
C1 provides hardness-aware path ranking inside C6's symbolic execution loop, using SAT
backbone fraction to defer paths near the phase transition.

## Pipeline stages

| Stage | File | What it does |
|-------|------|-------------|
| C1 | `exploration_technique.py` | Backbone-fraction path prioritiser (inside C6) |
| C2 | `c2_rmt.py` | Random Matrix Theory call graph screen — spectral anomaly detection |
| C3 | `c3_templates.py` | Template dataflow matching with full SSA memory taint (v2) |
| C6 | `c6_taint.py` | Symbolic taint + PoC synthesis via angr + Z3 |
| C7 | `c7_dynamic.py` | On-device validation: SUBPROCESS / LLDB / DTrace (v2) |

## What C1 does

When angr explores a binary with multiple branching paths, it typically uses
DFS/BFS with no awareness of how hard each path's constraints are to solve.
C1 adds a **hardness probe** that scores each active state by measuring
how many symbolic input bits are forced (backbone) vs free.

- **High backbone** = most input bits forced = rigid constraints = hard path → defer
- **Low backbone** = many free bits = flexible constraints = easy path → explore first

Result: **60% reduction in peak active states** on mixed-difficulty binaries,
with hard/trap paths automatically deferred.

## Architecture

```
metis/
├── c2_rmt.py                ← C2: C2RMTAnalysis — spectral call graph screen
├── c3_templates.py          ← C3: C3TemplateAnalysis — template matching (v2: full SSA)
├── c6_taint.py              ← C6: C6TaintTechnique / C6Analysis — symbolic taint
├── c7_dynamic.py            ← C7: C7Analysis — dynamic validation (v2)
├── exploration_technique.py ← C1: HardnessExplorationTechnique — backbone path ranking
├── semantic_backbone.py     ← Production backbone path: Z3 assumption probing (32ms)
├── dimacs_converter.py      ← Legacy: claripy → Z3 bit-blast → DIMACS CNF
├── backbone_probe.py        ← Legacy: pysat Glucose3 backbone detection
├── offline_analysis.py      ← Full chi-squared analysis pipeline
├── test_pipeline.py         ← Unit tests (5/5 passing)
├── benchmark_crackme.py     ← Benchmark harness
└── crackme_mixed.c          ← Test binary with mixed-difficulty paths
```

## Quick start — full pipeline

```python
import angr, archinfo
from metis.c2_rmt import C2RMTAnalysis
from metis.c3_templates import C3TemplateAnalysis
from metis.c6_taint import C6Analysis
from metis.c7_dynamic import C7Analysis, extract_poc_from_c6, C7DeliveryMode
from metis.exploration_technique import HardnessExplorationTechnique

BINARY = '/usr/sbin/smbd'
proj = angr.Project(BINARY, auto_load_libs=False,
                    main_opts={'arch': archinfo.arch_from_id('aarch64')})

# C2 — structural screen
c2_result = C2RMTAnalysis.from_project(proj).run()
c2_result.print_report()                               # z_radius, z_energy, z_entropy

# C3 — template match on top-20 functions
c3_result = C3TemplateAnalysis(proj).analyse_functions(
    c2_result.top_function_addrs[:20])
c3_result.print_report()                               # template hits + confidence

# C6 — symbolic taint on high-confidence C3 hits
for addr in c3_result.top_function_addrs[:5]:
    result = C6Analysis(proj).run(
        proj.factory.call_state(addr), max_steps=800,
        extra_techniques=[HardnessExplorationTechnique(threshold=0.75)])
    if result.findings:
        # C7 — on-device validation
        poc = extract_poc_from_c6(result.findings[0], proj=proj)
        evidence = C7Analysis(binary=BINARY).validate(
            poc, mode=C7DeliveryMode.DTRACE, timeout_s=60)
        evidence.write(f'/tmp/c7_{hex(addr)}')
        print(evidence.asb_text)          # paste into Apple ASB / MSRC / Chrome VRP
```

## Quick start — C1 (backbone prioritiser only)

```python
import angr
from metis.exploration_technique import HardnessExplorationTechnique

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

simgr.use_technique(HardnessExplorationTechnique(
    threshold=0.75,          # defer top 25% hardest (adaptive percentile)
    probe_timeout_s=0.05,    # 50ms budget per state
    max_score_per_step=16,   # cap scoring for large state counts
))

simgr.run()
```

## Standalone backbone analysis

```python
import claripy
from metis.semantic_backbone import semantic_backbone_claripy

sym = claripy.BVS('input', 64)
constraints = [sym[7:0] == 0x41, sym > 0x4141414141414141]

result = semantic_backbone_claripy(constraints)
print(f"backbone: {result.backbone_fraction:.2f}")  # 0.12
print(f"forced: {result.n_forced}/{result.n_semantic_bits}")
print(f"time: {result.probe_time_s*1000:.0f}ms")
```

## Performance

### C1 backbone probing (semantic path vs legacy)

| Metric | DIMACS path (legacy) | Semantic path (current) |
|--------|---------------------|------------------------|
| `a == 0x42` backbone | 0.02 (wrong) | 1.00 (correct) |
| `x > 0` backbone | 0.06 (noisy) | 0.00 (correct) |
| 5×64-bit, 19 constraints | 338 ms | 32 ms |
| Tseitin dilution | Yes | None |

### C1 state reduction

| Binary | Vanilla peak states | Hardness peak states | Improvement |
|--------|-------------------|--------------------|-------------|
| Linear crackme | 3 | 3 | — (no path explosion) |
| Explosion (2^N) | 256 | 256 | — (uniform hardness, correctly no-ops) |
| **Mixed difficulty** | **20** | **8** | **60% reduction** |

### Pipeline stage timings

| Stage | Typical time | Notes |
|-------|-------------|-------|
| C2 — single macOS binary (~1 MB) | ~30 s | CFGFast + 50 null replicates |
| C2 — batch 300 binaries, 8 workers | ~15 min | `batch_screen.py` |
| C3 — top-20 functions | ~60 s | Register + memory SSA taint |
| C6 — simple function | 2–5 min | Tight path constraints |
| C6 — complex function | 10–30 min | Many branches |
| C7 — DTrace confirm | 5–15 s | Attach + sink probe |
| C7 — LLDB crash capture | 15–60 s | LLDB startup + crash wait |

## Theory

Based on empirical P vs NP research on the random 3-SAT phase transition:
- Backbone fraction correlates with CDCL solver hardness (Spearman ρ = +0.43, p = 0.012)
- This is a proxy for marginal χ²/nv (variable freezing), which is what Survey Propagation computes analytically
- The correlation is computation-class-specific: 3-SAT shows monotonic rise, 3-XORSAT (poly-time) shows flat until threshold

## Dependencies

```bash
pip install angr z3-solver numpy scipy
# pysat: only required for legacy backbone_probe.py path (not production)
```

**C7 runtime dependencies** (no pip install needed — all system tools):

| Tool | Mode | macOS availability |
|------|------|--------------------|
| `lldb` | LLDB mode | Bundled with Xcode / CLT |
| `dtrace` | DTRACE mode | Bundled with macOS (requires SIP disabled or entitlement) |
| `subprocess` | SUBPROCESS mode | stdlib — always available |

**Note:** Python 3.12 is not supported (angr compatibility issue). Use Python 3.11 or 3.13.

## Tests

```bash
python3 -m pytest metis/test_pipeline.py -v   # 5/5 expected
python3 -m metis.benchmark_crackme
```
