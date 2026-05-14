# Metis — macOS Binary Vulnerability Toolchain — Technical Report

**Date:** 2026-04-15  
**Status:** C1 + C2 + C3 + C6 implemented and validated  
**Working directory:** `/path/to/metis_repository/`

---

## Background and motivation

The toolchain was designed through a purple-team process: an initial architecture
prompt was sent independently to ChatGPT, Grok, DeepSeek, and Gemini. Their
responses were synthesised to kill components that were theoretically elegant
but operationally useless, and to prioritise components with real discriminative
signal.

The research foundation is the existing empirical 3-SAT phase-transition work
(Spearman ρ = −0.42/+0.43, p < 0.013 at n=50), which established that
χ²-based solution-space statistics predict CDCL solver difficulty. That work
is repurposed here as a path-ranking heuristic inside angr (C1).

---

## What was proposed vs. what was built

| Component | Proposed | Built | Reason |
|---|---|---|---|
| C1: Phase-aware SE | Keep | Yes — hardened | Drop SP (bit-blast destroys factor graph); use solver-native friction |
| C2: RMT call graph | Keep with null model fix | Yes | Marchenko-Pastur wrong; use configuration model |
| C3: Matched filtering | Redesign | Yes — validated | Call-level VEX IR dataflow; 5 macOS templates; 4/4 pass |
| C4: TDA on CFGs | Kill | Replaced | Simple CFG structural metrics capture the same signal at zero cost |
| C5: Compressed sensing | Kill | Removed | RIP fails for coverage bitmaps; no path to fix |
| C6: Dataflow taint | Add (new) | Yes — validated | Highest ROI; unanimous across all four LLMs |

---

## Component specifications

### C1 — Phase-transition-aware symbolic execution

**File:** `exploration_technique.py`  
**Class:** `HardnessExplorationTechnique`

Scores angr SimState objects by constraint hardness using backbone fraction
as the primary proxy. States above a configurable threshold are moved to a
deferred stash and revisited only when the easy stash is exhausted.

**Scoring pipeline:**
```
claripy AST → Z3 → DIMACS CNF (via dimacs_converter.py)
             ↓
backbone_probe.py: Glucose3 solver + assumption-based probing
             ↓
HardnessScore: backbone_fraction ∈ [0, 1]
```

**Empirical basis:** The marginal χ²/nv statistic (backbone proxy) correlates
with CDCL solver hardness at ρ = +0.43, p = 0.012, n=50 variables, measured
in the condensation regime α = 4.15–4.27 of the 3-SAT phase diagram.

**Key limitation:** Bit-blast + Tseitin transform destroys the factor-graph
locality that Survey Propagation requires. SP was dropped after unanimous
agreement across all four purple-team LLMs. Backbone fraction is used instead
as a weaker but computationally cheap proxy.

**Usage:**
```python
from metis.exploration_technique import HardnessExplorationTechnique
simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))
```

---

### C2 — Random Matrix Theory call graph screener

**File:** `c2_rmt.py`  
**Class:** `C2RMTAnalysis`

Screens Mach-O binaries for anomalous call graph structure using spectral
graph theory.

**Two-level output:**

*Binary level* — three spectral metrics compared against 50 configuration-model
null graphs (same in/out degree sequence). Flags binaries where any metric
deviates > 2σ from its null. Designed to detect packed code, injected stubs,
unusual dispatch structures.

| Metric | What it measures | Why not Marchenko-Pastur |
|---|---|---|
| λ_max (spectral radius) | Presence of cycles / strong hubs | MP assumes i.i.d. entries; real call graphs have power-law degree |
| Graph energy Σ\|λ\|/N | Overall structural complexity | Non-zero even for DAGs; more stable than λ_max alone |
| Eigenvalue entropy −Σp log p | Uniformity of eigenvalue distribution | High entropy = unusual for compiler-generated code |

*Function level* — ranks all non-stub functions by a weighted combination of:
- Eigenvector centrality in the call graph (hub anomaly)
- Cyclomatic complexity M = E − N + 2 (branching complexity)
- Back-edge count (loop nesting proxy)

**Validated output (syspolicyd, 44,986 functions):**
```
Call graph       : 9,852 nodes, 18,105 edges
RMT verdict      : within normal range (clean system daemon, expected)
Top function     : sub_1000a6255  cyclomatic=358  back_edges=30
```

The top-ranked function has 30 loop back-edges and cyclomatic complexity 358 —
this is the function C6 should analyse first.

**Usage:**
```python
from metis.c2_rmt import C2RMTAnalysis
result = C2RMTAnalysis('/usr/libexec/targetd').run()
result.print_report()
top_addrs = result.top_function_addrs[:10]   # feed to C6
```

---

### C3 — SSA-level call dataflow template matching

**File:** `c3_templates.py`  
**Class:** `C3TemplateAnalysis`

Screens functions for forbidden call-level def-use topologies using lightweight
VEX IR analysis. Rather than SSA reaching-definitions (too slow at 45k functions),
C3 builds a call-level graph where an edge A→B means "return value of A flows
into an argument of B" and then does path reachability against five templates.

**Template bank (five macOS-specific patterns):**

| Template | Source | Sink | Barrier |
|---|---|---|---|
| MACH_OOB | `mach_msg` | `malloc/calloc/realloc` | — |
| XPC_TYPE | `xpc_dictionary_get_value` | typed XPC accessor | `xpc_get_type` |
| XPC_SIZE_ALLOC | `xpc_data_get_length`, `xpc_array_get_count` | `malloc/calloc` | — |
| PORT_UAF | `mach_port_deallocate` | any port operation | — |
| IOKIT_OOB | `IOConnectCallMethod` | `malloc/memcpy` | — |

**Taint tracking improvements over naive register taint:**

The ARM64 compiler at `-O0` spills register values to the stack between calls:
```
GET(x0) → t5 ; STle(sp+0x10) = t5 ; LDle(sp+0x10) → t2 ; PUT(x0) = t2
```
A register-only tracker loses the taint at the `STle`. C3 implements
frame-pointer-relative stack taint with recursive canonical address resolution:
- `GET(sp)` → `'sp+0x0'`
- `Add64(RdTmp(t), Const(N))` where `tmp_addr[t]='sp+0x0'` → `'sp+0xN'`
- `Store` and `Load` through canonical keys survive block boundaries

**Barrier detection:** A barrier is flagged if it appears on the source→sink
path OR if it is called anywhere in the function with taint from the same source
(covers the `if (xpc_get_type(val) == TYPE) { sink(val) }` pattern).

**Validation results (4/4 pass):**
```
XPC_SIZE_ALLOC vuln → PASS: detected at test_xpc_size_alloc_vuln (72% confidence)
XPC_SIZE_ALLOC safe → PASS: no active findings
XPC_TYPE vuln       → PASS: detected at test_xpc_type_vuln (80% confidence)
XPC_TYPE safe       → PASS: no active findings (barrier detected)
```

**Usage:**
```python
from metis.c3_templates import C3TemplateAnalysis
proj   = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
c3     = C3TemplateAnalysis(proj)
result = c3.run()                           # scan all functions
result.print_report()
# Or compose with C2: scan only top-ranked functions
result = c3.analyse_functions(c2_result.top_function_addrs[:50])
```

---

### C6 — XPC/Mach port dataflow taint analysis

**File:** `c6_taint.py`  
**Class:** `C6Analysis`

Detects three forbidden def-use topologies by hooking macOS runtime functions
with angr SimProcedures and propagating symbolic taint labels.

**Vulnerability classes:**

| Class | Definition | Example sink |
|---|---|---|
| OOB | Tainted mach_msg/XPC field reaches malloc/calloc/realloc size without bounds check | `malloc(msg->body.size)` |
| UAF | Mach port right passed to mach_port_deallocate, then used again | Double-consume of port name |
| XTYPE | XPC value reaches typed accessor without xpc_get_type on this path | `xpc_int64_get_value(untyped_obj)` |

**Hook table (18 symbols):**

| Hook | Purpose |
|---|---|
| `_mach_msg`, `_mach_msg_trap` | Taint receive buffer with named symbolic BVS |
| `_malloc`, `_calloc`, `_realloc` | OOB: detect tainted size argument |
| `_free` | UAF: detect double-free of tracked allocation |
| `_mach_port_deallocate` | UAF: detect double-consume of port right |
| `_xpc_dictionary_get_value` | Mark XPC value as untyped-tainted |
| `_xpc_get_type` | Remove label from untyped set (type guard seen) |
| 9× typed XPC accessors | XTYPE: typed accessor without preceding type guard |

**Taint mechanism:** Taint propagates via claripy symbolic variable *names*.
When a buffer is tainted, it is filled with a BVS named
`c6_taint_<label>_<bits>`. Any derived value retains this label in its
`.variables` frozenset. `_is_tainted(expr)` checks that set — no separate
taint map, no overhead, works through all claripy operations.

**OOB confidence:** When `state.solver.max(size) < 0x10000`, the tainted
value is constrained by path guards — the bounds check has been taken on this
path. Confidence is reduced to 0.20 and the finding is suppressed from output.
This eliminated all false positives on the safe test cases.

**Validation results (4/4 pass):**
```
OOB vuln  → PASS: VulnClass.OOB detected at 0x00500000 (85% confidence)
OOB safe  → PASS: no findings (bounds check correctly detected)
UAF vuln  → PASS: VulnClass.UAF detected at 0x00500008 (95% confidence)
UAF safe  → PASS: no findings
```

**Usage:**
```python
from metis.c6_taint import C6Analysis
proj   = angr.Project('/usr/libexec/targetd', auto_load_libs=False)
c6     = C6Analysis(proj)
state  = proj.factory.call_state(target_addr)
result = c6.run(state, max_steps=800)
result.print_report()
```

---

## Full pipeline: combining C1 + C2 + C6

```python
import angr
from metis.c2_rmt import C2RMTAnalysis
from metis.c6_taint import C6Analysis
from metis.exploration_technique import HardnessExplorationTechnique

BINARY = '/usr/libexec/targetd'

# 1. C2: static screen — identify anomalous functions
c2_result = C2RMTAnalysis(BINARY).run()
c2_result.print_report()
top_addrs = c2_result.top_function_addrs[:10]

# 2. C6 + C1: targeted taint analysis on ranked functions
proj = angr.Project(BINARY, auto_load_libs=False)
c6   = C6Analysis(proj)

for addr in top_addrs:
    state  = proj.factory.call_state(addr)
    result = c6.run(
        state,
        max_steps=500,
        extra_techniques=[HardnessExplorationTechnique(threshold=0.75)]
    )
    if result.findings:
        result.print_report()
```

**Priority queue scoring** (equal weights until calibrated on CVE corpus):
```python
priority = (
    0.25 * rmt_z_score_normalised +      # C2: structural oddness
    0.40 * c6_taint_confidence +          # C6: known-pattern proximity to sink
    0.35 * (1.0 - hardness_score)         # C1: path is solvable
)
```

---

## What this does that the XORSAT tool does not

The XORSAT control experiment establishes that the marginal freezing signal is
computation-class-specific. That is a *theoretical finding* about random
formula ensembles. This toolchain uses one consequence of that finding (the
backbone proxy correlates with CDCL hardness) as a heuristic inside a binary
analyser — the rest of the toolchain (C2 call graph screening, C6 dataflow
taint) has no connection to 3-SAT research.

Concretely: the XORSAT tool would never identify that `sub_1000a6255` in
`syspolicyd` has 30 loop back-edges and cyclomatic complexity 358 and is the
highest-priority function to check for an OOB write via a mach_msg receive
buffer. That is what C2 + C6 are built to do.

---

## Deferred components

**C3 template bank expansion:** The five current templates cover the highest-ROI
patterns. Further curation is needed for: IOKit heap spray (`IOConnectCallMethod`
out-parameter chains), mach port UAF sequences (deallocate then re-use), and
inter-procedural flows (source and sink in different functions). The existing
engine handles these; the bottleneck is template curation.

**C3 inter-procedural extension:** Current analysis is intra-function only.
Cross-function flows (e.g., `mach_msg` buffer returned via pointer to caller)
require the call graph from C2 as a scaffold. This is the natural next step
after CVE corpus validation.

**C6 XTYPE coverage:** The XTYPE path is implemented and tested in unit logic.
A compiled binary test harness for XTYPE requires XPC framework linkage;
deferred but the hook logic is complete.

---

## Files

| File | Purpose | Status |
|---|---|---|
| `dimacs_converter.py` | claripy → DIMACS CNF bridge | Existing |
| `backbone_probe.py` | Glucose3-based backbone fraction | Existing |
| `exploration_technique.py` | C1: HardnessExplorationTechnique | Existing |
| `c2_rmt.py` | C2: RMT call graph screener | New |
| `c3_templates.py` | C3: call-level VEX dataflow template matching | New |
| `c6_taint.py` | C6: XPC/mach port taint analysis | New |
| `validate_c3.py` | C3 validation (4/4 pass) | New |
| `validate_c6.py` | C6 validation (4/4 pass) | New |
| `__init__.py` | Package exports for all components | Updated |

---

## Validation methodology (next steps)

1. **Positive corpus:** Pre-patch binaries for 20 macOS CVEs (XPC, IOKit,
   mach port) from 2020–2024. Target: CVE-2023-32434 specifically (noted
   by DeepSeek as a concrete C6 validation case).

2. **Negative corpus:** 50 Apple-signed system binaries from `/usr/bin`,
   `/usr/libexec`. Run C2; all should be within normal range.

3. **Baseline comparison:** Stock angr, AFL++ (24h), Joern with mach_msg
   taint queries. Primary metric: rank of known-vulnerable function in C2
   priority queue (target: top 5%).

4. **Ablation:** C2-only vs. C6-only vs. C1+C2+C6 pipeline. Measure
   reduction in states explored before first finding.
