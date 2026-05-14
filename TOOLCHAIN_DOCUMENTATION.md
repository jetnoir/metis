# Metis — The Vulnerability Research Toolchain
## Mathematics, Physics, and Implementation — A Complete Reference

**Author:** Stuart Thomas  
**Date:** 2026-04-18  
**Version:** 2.1  
**Repository:** `macos_vuln_toolchain/metis/`  
**Status:** Public methodology — findings redacted pending disclosure  
**Licence (documentation):** Creative Commons Attribution 4.0 International (CC BY 4.0)  
**Licence (code):** MIT (Non-Commercial) / Paid (Commercial)

© 2026 Stuart Thomas. All rights reserved.

---

> **Legal Notice — Authorised Use Only**  
> This toolchain is intended exclusively for use on systems you own or have received
> explicit written authorisation to test. Unauthorised use of this software against
> systems you do not own or do not have permission to test may constitute a criminal
> offence under the Computer Misuse Act 1990 (England and Wales), the Computer Fraud
> and Abuse Act (United States), or equivalent legislation in other jurisdictions.
> The author accepts no liability for use of this software outside the scope of
> legitimate, authorised security research.

> **Statutory basis for binary analysis:** Analysis of macOS system software in this
> toolchain is conducted in accordance with the Copyright, Designs and Patents Act 1988
> (UK) ss.50B and 50BA, which permit decompilation and study of computer programs for
> the purposes of interoperability and security research. Apple's macOS Software License
> Agreement terms purporting to prohibit such analysis are unenforceable in England and
> Wales to the extent they conflict with these statutory provisions.

---

## Abstract

This document describes a seven-stage automated vulnerability research pipeline for macOS
system binaries. The toolchain applies ideas from random matrix theory, statistical
mechanics, graph spectral analysis, and formal verification to rank binary functions by
their likelihood of containing security-relevant bugs — before a human analyst reads a
single line of disassembly.

Two stages were killed during design (C4: topological data analysis, C5: compressed
sensing). Five stages are implemented and validated (C1, C2, C3, C6, C7); C3 carries six templates. The pipeline has produced multiple
accepted Apple Security Bounty submissions from a standing start with no source code
and no symbols.

**v2 additions:** Full SSA memory taint in C3 (struct-field and stack-slot flows),
C7 dynamic validation (on-device crash capture and ASB-ready evidence generation),
parallel batch screening for multi-binary campaigns.

---

## Contents

1. [The Short Version](#the-short-version) — for people who don't want the maths  
2. [Why C1–C6? The Naming History](#why-c1c6-the-naming-history)  
3. [C1 — Phase-Transition Symbolic Execution](#c1--phase-transition-symbolic-execution)  
4. [C2 — Random Matrix Theory Call Graph Screen](#c2--random-matrix-theory-call-graph-screen)  
5. [C3 — Template-Based Call Dataflow Matching](#c3--template-based-call-dataflow-matching)  
   5a. [C3 v2 — Full SSA Memory Taint](#c3-v2--full-ssa-memory-taint)  
6. [C6 — Symbolic Taint Analysis](#c6--symbolic-taint-analysis)  
7. [C7 — Dynamic Validation](#c7--dynamic-validation)  
8. [The Disassembly Layer](#the-disassembly-layer) — VEX IR, pefile, capstone, otool  
9. [Pipeline Composition](#pipeline-composition)  
10. [Case Studies](#case-studies) — methodology, findings redacted  
11. [Limitations](#limitations)  
12. [Glossary](#glossary)  

---

## The Short Version

*If equations make your eyes glaze over, start here. Everything in the rest of this
document is just the formal version of this.*

### What problem are we solving?

macOS ships with several hundred privileged daemons — programs that run as root, talk
to the network, handle your files, or manage security policy. Any one of them could
contain a bug. Finding bugs manually means reading disassembly for weeks. Fuzzing
blindly wastes compute on code that's been hardened for years. We need a way to look at
a compiled binary — no source, no symbols — and answer the question: *which function
should I look at first?*

### The analogy

Imagine every program is a city. Roads are the connections between neighbourhoods
(functions). Some cities are planned: regular grid, sensible road layout, easy to
navigate. Others grew organically and have one enormous junction in the middle where
everything passes through, weird dead ends, and roads that loop back on themselves for
no obvious reason.

The weird city is more likely to have a problem. Not because weirdness causes bugs
directly — but because weird structure correlates with code that evolved under
pressure, handles edge cases nobody fully understood, and probably has a corner
nobody tested.

The C2 stage of this toolchain does exactly that structural audit — mathematically,
at scale, in about 30 seconds per binary.

### What does "symbolic execution" mean?

When a normal program runs, it processes actual data. When a symbolic execution engine
(like angr) runs a program, it processes *symbols* — placeholders that represent
"whatever the attacker could send." Instead of computing `x + 3 = 7`, it tracks the
relationship `x + 3 = y` and asks: "is there a value of x that makes y large enough
to overflow a buffer?"

The problem is that symbolic execution is slow. Programs branch constantly — every
`if` statement creates two possible worlds the engine has to explore. A program with
100 branches has 2¹⁰⁰ possible paths. That's more paths than atoms in the observable
universe.

The C1 stage makes symbolic execution tractable by prioritising paths that are
*probably solvable* and deferring ones that are *probably intractable*. It does this
using a result from statistical physics: near a phase transition, constraint systems
become maximally hard to solve. C1 estimates how close each execution path is to that
transition, and uses that estimate as a priority signal.

### Why does the pipeline produce results?

Because it combines signals that individually are noisy, but together are
discriminative:

- **Structure** (C2): the call graph looks unusual — worth investigating
- **Pattern** (C3): the code does `receive untrusted data → allocate memory` without
  a bounds check call in between — that pattern matches known vulnerability classes
- **Confirmation** (C6): symbolic execution actually finds a concrete input that
  reaches the allocator with an attacker-controlled size

None of these alone is sufficient. Together, they narrow a binary with 300 functions
down to 3 worth reading carefully.

### The honest version

It doesn't always work. angr hits memory limits on large binaries. Compiler
optimisation hides patterns that the tools expect. Some bugs are architectural —
no static analysis finds them without understanding the protocol semantics. The
pipeline is a *triage* tool, not an oracle.

But when it works, it's remarkably effective. A 44KB binary analysed in 30 seconds
identifies the function with cyclomatic complexity 155 — which turns out to be the
entire ping main loop. A 365KB DLL screened in under a minute isolates the ICMPv6
reply parser with 23 callees and a recursive self-call. That's the function you'd
want a human looking at.

---

## Why C1–C6? The Naming History

### The Kill Chain connection

The naming comes — with deliberate irony — from the Lockheed Martin **Cyber Kill
Chain®** framework, which models an attacker's progression in seven stages:
Reconnaissance, Weaponisation, Delivery, Exploitation, Installation, Command and
Control, Actions on Objectives.

*Cyber Kill Chain® is a registered trademark of Lockheed Martin Corporation (USPTO
Reg. No. 4,409,609). Use of the name here is purely descriptive of the conceptual
inspiration for the C1–C6 naming convention and does not imply any endorsement by
or affiliation with Lockheed Martin Corporation.*

When I designed this toolchain, I reappropriated "chain" for the defender's research
methodology: a sequential pipeline where each stage feeds the next, outputs flow
forward, and nothing reaches the exploitation stage (here: writing a PoC) without
passing through the earlier screens.

The C-numbering (C1 through C6) is deliberately reminiscent of military chain
designations — suggesting both sequential dependency and the fact that each stage can
be run independently as a standalone tool.

### The design process

The original architecture had exactly six components. A design prompt was sent
independently to four LLMs (ChatGPT, Grok, DeepSeek, Gemini) — a process I call
**purple-teaming the architecture**. The four responses were synthesised to kill
anything theoretically elegant but operationally useless.

The original C4 (topological data analysis on CFGs — computing persistent homology of
the basic block graph) and C5 (compressed sensing for coverage bitmaps — applying the
Restricted Isometry Property to fuzzing outputs) were both killed:

| Component | Proposal | Verdict | Reason |
|---|---|---|---|
| C1 | Phase-aware symbolic execution | **Keep, harden** | Drop Survey Propagation (Tseitin destroys factor-graph locality); use backbone fraction |
| C2 | RMT call graph screen | **Keep, fix null model** | Marchenko-Pastur wrong for power-law graphs; use configuration model |
| C3 | Matched filtering on call graphs | **Redesign** | Instruction-sequence pattern matching rejected; call-level VEX IR dataflow correct framing |
| C4 | TDA on CFGs | **Kill** | Persistent homology captures same signal as McCabe at 1000× cost |
| C5 | Compressed sensing for coverage | **Kill** | RIP fails for binary coverage bitmaps; no tractable fix |
| C6 | Dataflow taint analysis | **Add (new)** | Unanimous highest-ROI addition; not in original design |

The numbering was preserved rather than renumbered after C4 and C5 were killed. This
is why the implemented pipeline jumps from C3 directly to C6 — the ghost stages are a
feature, not a bug. Anyone reading the codebase can see immediately that two ideas
didn't survive first contact with reality.

### The chain that killed C4 and C5

There's something satisfying about a *cyber kill chain* that kills two of its own
stages. C4 and C5 were eliminated because they failed the fundamental test: would
this actually find bugs that the other stages miss? The answer in both cases was no.

Persistent homology of a CFG captures loop structure and branching depth — but those
are already captured by back-edge count and cyclomatic complexity, both of which C2
computes in microseconds. TDA would take seconds per function and add nothing.

Compressed sensing requires the measurement matrix to satisfy the Restricted Isometry
Property — informally, that the measurements are "spread out enough" to recover the
original signal. Coverage bitmaps are binary vectors with highly structured sparsity
patterns (most branches are taken the same way most of the time). The RIP fails badly
for this structure. A coverage bitmap can't be recovered from random projections.

Both dead ideas are documented here as a reminder that mathematical elegance is not
the same as operational utility.

---

## C1 — Phase-Transition Symbolic Execution

**File:** `exploration_technique.py`  
**Class:** `HardnessExplorationTechnique`  
**Empirical basis:** Spearman ρ = +0.43, p = 0.012 (backbone fraction vs. CDCL solve time, n=50 variables, condensation regime)

### The physical picture: phase transitions

The classic example of a phase transition is water turning to ice at exactly 0°C. At
that precise boundary, the system changes its qualitative behaviour — not gradually,
but abruptly. Statistical physicists study phase transitions because they reveal
universal behaviour: very different physical systems undergo qualitatively identical
transitions, governed by the same mathematics.

The 3-SAT satisfiability problem has a phase transition. A 3-SAT instance consists of
n boolean variables and m clauses, each clause constraining exactly three variables.
Define the clause-to-variable ratio:

```
α = m / n
```

For small α (few clauses, many variables), almost every assignment satisfies all
clauses — the problem is easy. For large α (many clauses), the clauses are
contradictory — again easy (just return UNSAT). But at exactly:

```
α_c ≈ 4.267   (Mézard, Parisi, Zecchina 2002)
```

the problem undergoes a sharp phase transition. Below α_c: satisfiable. Above α_c:
unsatisfiable. *At* α_c: maximally hard.

This is not a mere curiosity. The hardness at the phase transition is exponential —
CDCL solvers (the algorithms used by angr's constraint solver) take time that grows
exponentially with n for instances near α_c. An instance with n=50 variables at the
transition can take longer than the age of the universe to solve optimally.

### The condensation transition

There is a subtler transition below α_c, at approximately:

```
α_cond ≈ 4.15–4.27
```

called the **condensation transition**. Below α_cond, solutions are spread across many
well-separated clusters in solution space. Above α_cond, solutions condense into a
small number of clusters with large empty regions between them.

This matters for solver algorithms. Above the condensation transition, algorithms that
explore by local moves (like belief propagation and survey propagation) get stuck in
empty regions. CDCL solvers also slow dramatically.

The **backbone** of a satisfiable 3-SAT instance is the set of variables that take
the same value in *every* solution:

```
backbone = { v : v = 0 in all solutions } ∪ { v : v = 1 in all solutions }
```

As α approaches α_c from below, the backbone fraction (backbone size / n) grows
toward 1.0 — more and more variables are frozen to a single value, the solution
space shrinks, and finding any solution becomes harder.

### Why this matters for symbolic execution

When angr explores a program path, it accumulates **path constraints** — a
conjunction of boolean conditions derived from branch outcomes. Each branch that the
engine resolves adds one or more clauses to the constraint set.

The path constraints are, from the solver's perspective, a SAT instance. If that
instance is near the condensation/phase-transition point, the solver will be slow
— possibly very slow. If it's far from the transition (either trivially satisfiable
or obviously contradictory), the solver is fast.

C1 estimates where each path's constraint set sits relative to the transition, and
uses that estimate to prioritise exploration:

```
low backbone fraction  →  far from transition  →  easy path  →  explore first
high backbone fraction →  near transition      →  hard path  →  defer
```

### Implementation: backbone fraction via Z3

The naive approach to computing backbone fraction is NP-hard (it requires enumerating
all solutions). C1 uses an approximation via assumption-based probing on the Z3
solver:

```python
# For each bit b of each symbolic input variable:
# Force b = 0, check satisfiability
# Force b = 1, check satisfiability
# If only one value is satisfiable, b is backbone
forced = 0
for var_name, width in symbolic_vars.items():
    for bit_idx in range(width):
        assumption_true  = z3_var_bit == 1
        assumption_false = z3_var_bit == 0
        sat_true  = solver.check(assumption_true)  == z3.sat
        sat_false = solver.check(assumption_false) == z3.sat
        if sat_true != sat_false:   # exactly one value works
            forced += 1

backbone_fraction = forced / total_bits
```

This approach operates directly on semantic input variables — not on the Tseitin
auxiliary variables introduced by CNF encoding. The Tseitin transform (which converts
arbitrary boolean formulae to CNF by introducing auxiliary variables for each gate)
was rejected because it destroys the factor-graph structure that Survey Propagation
requires, and dilutes the backbone fraction signal with structural artefacts.

Survey Propagation itself was dropped: it requires belief propagation on a factor
graph, which is destroyed by the Tseitin encoding. The backbone fraction approximation
via Z3 assumptions is weaker but computationally cheap (32ms measured on a typical
angr path constraint set) and still correlates with CDCL hardness.

### The formula for combined score

C1 uses the backbone fraction as a priority signal within angr's simulation manager:

```
priority(state) = 1.0 - backbone_fraction(state)
```

States are sorted by priority (descending) at each exploration step. States above a
configurable threshold `τ` are moved to a deferred stash:

```
if backbone_fraction > τ:
    move state to 'hardness_deferred'
else:
    keep in 'active', explore next
```

The adaptive threshold mode (`adaptive_threshold=True`) defers the top τ-percentile
of the current active stash rather than using a fixed backbone cutoff. This prevents
runaway deferral when all paths are hard.

### Measured performance

On the angr benchmark crackme (n=50 symbolic input bytes, 5 binary targets):
- **60% reduction in states explored** before finding the solution path
- **32ms average backbone probing time** per state
- **5/5 tests passed** — backbone-prioritised exploration found solutions in all cases

---

## C2 — Random Matrix Theory Call Graph Screen

**File:** `c2_rmt.py`  
**Class:** `C2RMTAnalysis`  
**Dependencies:** angr, networkx, numpy, scipy

### What we're computing and why

The call graph of a compiled binary encodes its structure: who calls whom, how
complex each function is, which functions are hubs. For well-maintained,
security-conscious code, call graphs tend to be sparse, hierarchical, and
locally tree-like. For code with structural problems — packed executables, injected
stubs, functions that grew organically over years — the call graph looks different.

The question is: **different how, precisely?** Random Matrix Theory (RMT) gives us
a rigorous answer.

### Graph theory fundamentals

A call graph is a **directed graph** G = (V, E) where:

- V = set of functions (vertices)
- E = set of call relationships: (u, v) ∈ E iff function u calls function v

From this graph we construct the **adjacency matrix** A, where:

```
A[i,j] = 1  if function i calls function j
A[i,j] = 0  otherwise
```

For a call graph with N functions, A is an N×N matrix. The **eigenvalues** of A
are the solutions λ to:

```
det(A - λI) = 0
```

Equivalently, they satisfy Av = λv for some non-zero vector v (the corresponding
eigenvector). The set of all eigenvalues {λ₁, λ₂, ..., λ_N} is the **spectrum** of G.

### Why the spectrum tells us something

The eigenvalue spectrum encodes structural properties of the graph:

**Spectral radius** ρ(A) = max|λᵢ|:
- Zero for pure DAGs (directed acyclic graphs — no cycles, no recursion)
- Positive when cycles exist; larger values indicate stronger cyclic structure
- For a hub-and-spoke graph with one node connected to all others: ρ ≈ √N

**Graph energy** E(G) = Σ|λᵢ|/N:
- Average absolute eigenvalue magnitude per node
- Non-zero even for DAGs (unlike spectral radius)
- Captures overall structural complexity; elevated for dense, irregular graphs

**Eigenvalue entropy** H = −Σ pᵢ log pᵢ, where pᵢ = |λᵢ| / Σ|λⱼ|:
- Treats the normalised absolute eigenvalues as a probability distribution
- High entropy: many eigenvalues of similar magnitude → unusual, non-hierarchical
- Low entropy: spectrum dominated by a few large eigenvalues → structured hierarchy

These three metrics together characterise the spectrum more robustly than any single
one. A binary is flagged ANOMALOUS when any of the three deviates significantly from
the null expectation.

### Why NOT Marchenko-Pastur (and why NOT Wigner)

The two canonical RMT null distributions are:

**Wigner semicircle law**: applies to symmetric random matrices with i.i.d. entries
drawn from a distribution with zero mean and finite variance. The eigenvalue density
converges to a semicircle as N → ∞.

**Marchenko-Pastur distribution**: applies to the covariance matrix of a random
matrix X with i.i.d. entries. The eigenvalue density converges to:

```
ρ_MP(λ) = (1/2πqλ) √[(λ+ - λ)(λ - λ-)]
for λ ∈ [λ-, λ+]
where λ± = (1 ± √q)², q = N/M (ratio of dimensions)
```

Both of these are **wrong** for call graphs. The key assumption — that matrix entries
are i.i.d. — fails completely for real call graphs:

- Call graphs have **power-law degree distributions**: a few functions are called by
  many others (hubs); most functions are called rarely. This is structurally similar
  to social networks, the internet's link graph, and citation networks — all of which
  are known to deviate dramatically from i.i.d. random graphs.
- Call graphs are **bipartite-like**: a caller is different from a callee in
  structure (callers tend to be complex, callees tend to be specialised).
- Call graphs are **sparse**: most function pairs have no direct calling relationship.
  Dense random matrix theory doesn't apply.

This is not a minor correction. The briefing.py script (an earlier version) plots the
Marchenko-Pastur distribution for illustrative purposes only. The actual screening
uses the **configuration model null** throughout.

### The configuration model null

The correct null distribution for call graph analysis is generated by the
**directed configuration model** (Bollobás 1980, directed variant):

Given the observed in-degree sequence {dᵢⁿ} and out-degree sequence {dᵢᵒᵘᵗ},
generate a random directed graph that:
1. Has *exactly* the same in-degree and out-degree for each node
2. Has *random* wiring (subject to that constraint)

This is the maximally random graph consistent with the observed degree sequence.
The null hypothesis is: "the anomaly we observe is not just explained by the fact that
some functions have many callers." The configuration model controls for that.

```python
# In c2_rmt.py:
in_seq  = [G.in_degree(n)  for n in G.nodes()]
out_seq = [G.out_degree(n) for n in G.nodes()]

for _ in range(50):   # 50 null replicates
    G_null = nx.directed_configuration_model(
        in_seq, out_seq, create_using=nx.MultiDiGraph()
    )
    G_s = nx.DiGraph(G_null)   # collapse multi-edges
    G_s.remove_edges_from(nx.selfloop_edges(G_s))
    # compute spectral metrics of G_s
```

**Fifty replicates** gives sufficient precision for z-score estimates when N > 100
(the minimum call graph size for reliable RMT). For smaller graphs, z-scores are
flagged as unreliable.

### The z-score

For each spectral metric m ∈ {spectral_radius, graph_energy, eig_entropy}:

```
z_m = (m_observed - μ_null(m)) / σ_null(m)
```

where μ_null and σ_null are the mean and standard deviation across the 50 null
replicates.

**Interpretation:**
- |z| < 2.0: within 2σ of null — not anomalous
- |z| > 2.0: more than 2σ from null — flagged ANOMALOUS
- z > 0: metric exceeds null expectation (more complex/irregular than expected)
- z < 0: metric below null expectation (more structured/hierarchical than expected)

Note that z < 0 can also be anomalous. A binary with very low entropy
(z_entropy = −9.87, observed on `iphlpapi.dll` ARM64) is more hierarchical than
even its own degree sequence would predict — which can indicate a deliberately
structured dispatch architecture or an optimiser's aggressive inlining.

### Eigenvalue computation

For graphs with N ≤ 2000 nodes, exact eigenvalues are computed via `scipy.linalg.eigvals`
(O(N³) dense algorithm). For larger graphs, a sparse approximation uses
`scipy.sparse.linalg.eigs` to compute the top-100 eigenvalues by magnitude.

Note: the adjacency matrix of a call graph is **not symmetric** (A ≠ Aᵀ — calling
is not symmetric). The eigenvalues are therefore complex in general. We use the real
parts only (imaginary parts arise from the antisymmetric component and are noise for
this analysis).

Self-loops (recursive calls) are excluded from the RMT computation but recorded
separately. Self-loops inflate the spectral radius artificially and would dominate
the z-score for any binary with deep recursion.

### McCabe cyclomatic complexity

At the **function level**, C2 does not use RMT (individual function CFGs are too
small — N < 20 is typical — for reliable spectral statistics). Instead it uses
**McCabe's cyclomatic complexity**:

```
M = E − N + 2
```

where:
- E = number of edges in the function's control flow graph
- N = number of nodes (basic blocks)
- The +2 accounts for the two implicit edges to/from the function's entry/exit

**Interpretation:**
- M = 1: linear function, no branches — trivially simple
- M = 10: 10 independent paths through the function — complex but manageable
- M = 155: 155 independent paths — extreme. Every path needs a test case for full coverage.

McCabe's theorem (1976) established that M equals the minimum number of test cases
needed for branch coverage. For security analysis, high M means:

1. Many branches → many edge cases → higher probability that one was not tested
2. Many paths → large state space for symbolic execution
3. High cognitive load → reviewers miss things

The formula M = E − N + 2 follows from Euler's formula for planar graphs (V − E + F = 2),
adapted for CFGs where F (faces) corresponds to independent cycles.

### Eigenvector centrality

In the call graph, **eigenvector centrality** measures how important a function is —
not just by how many others call it, but by whether those callers are themselves
important.

Formally, if x is the principal eigenvector of the adjacency matrix A (corresponding
to the largest eigenvalue λ_max):

```
Ax = λ_max · x
```

Then xᵢ is the eigenvector centrality of node i. The power iteration algorithm
(applied by `networkx.eigenvector_centrality_numpy`) converges to x:

```
x^(k+1) = A · x^(k) / ||A · x^(k)||
```

Functions with high eigenvector centrality are structurally anomalous hubs — the kind
that show up in dispatch tables, vtable implementations, injected stubs, and
security-relevant receive handlers.

### Combined function score

Each function is scored by a weighted combination of three local metrics:

```python
def _function_combined_score(ev, cyclomatic, back_edges):
    norm_cyc  = log1p(max(0, cyclomatic - 1))   # M=1 trivial; log-scale above
    norm_back = log1p(back_edges)               # each loop adds log-weight
    return 0.4 * ev + 0.35 * norm_cyc + 0.25 * norm_back
```

**Weights are provisional** (equal weighting would also be defensible without a
CVE training corpus). The log1p scaling on cyclomatic and back-edges prevents a
single function with M=355 from dominating the ranking to the exclusion of everything
else. Functions are sorted descending by combined score.

---

## C3 — Template-Based Call Dataflow Matching

**File:** `c3_templates.py`  
**Class:** `C3TemplateAnalysis`

### The design choice: why not SSA reaching definitions?

Full SSA (Static Single Assignment) reaching-definitions analysis would give exact
dataflow information across an entire binary. It would also take hours on a binary
with 45,000 functions. For triage purposes, we need something faster.

The key insight is that the vulnerability patterns we care about — XPC type confusion,
mach_msg OOB, IOKit OOB, port UAF — all share a common structure:

```
value = source_function(...)  →  [intermediate steps]  →  sink_function(value, ...)
```

where source_function produces attacker-influenced data (from the network, from XPC,
from a Mach message) and sink_function is where the exploit happens (allocator, typed
accessor, memory copy). The "intermediate steps" may involve stack spills and loads,
but the *call-level* structure is preserved.

C3 builds a **call-level def-use graph** (not a full SSA graph) and matches patterns
against it. This is fast enough to run on all functions in a binary in a few seconds,
and accurately detects the patterns we care about.

### VEX IR: the lifting layer

C3 analyses functions by lifting their machine code to **VEX IR** via pyvex (bundled
with angr). VEX IR is the Valgrind project's platform-independent intermediate
representation. It was designed for dynamic analysis but is equally useful for static
analysis.

Key VEX IR concepts:

| Concept | Machine code equivalent | Example |
|---|---|---|
| `t0`, `t1`, ... | Temporaries (SSA form within a block) | `t5 = GET(x0)` |
| `GET(offset)` | Read from register | `t3 = GET(16)` → read x0 (ARM64) |
| `PUT(offset, expr)` | Write to register | `PUT(16, t3)` → write x0 |
| `Load(ty, addr)` | Memory load | `t7 = Load(Ity_I64, t6)` |
| `Store(addr, data)` | Memory store | `Store(t4, t5)` |
| `Binop(op, a, b)` | Binary operation | `Add64(t3, Const(0x1c))` |
| `Ijk_Call` | Jump kind: function call | End of call block |
| `Ijk_Ret` | Jump kind: return | End of return block |

One VEX IRSB (Intermediate Representation SuperBlock) corresponds roughly to one
basic block. Temporaries (t0, t1, ...) are in SSA form *within* a block but do not
persist across blocks. Registers and memory persist.

### Register taint propagation

C3 tracks **taint labels** — string identifiers marking which call's return value
has reached which registers. The `_RegTaint` class maintains:

```python
state:     dict[int, frozenset[str]]   # VEX register offset → set of taint labels
mem_state: dict[str, frozenset[str]]   # canonical stack address → set of taint labels
```

Taint propagates through VEX statements as follows:

**WrTmp** (temporary write): propagate taint through the expression
```
t_new = expr(t_old, ...)  →  taint[t_new] |= taint[t_old]
```

**Put** (register write): propagate to register state
```
PUT(offset, expr)  →  reg_state[offset] = taint_of(expr)
```

**Store** (memory write): propagate to stack slot (if frame-relative)
```
Store(addr, data)  →  if addr == canonical(sp+N): mem_state[sp+N] = taint_of(data)
```

**Load** (memory read): retrieve from stack slot
```
Load(ty, addr)  →  if addr == canonical(sp+N): result_taint = mem_state[sp+N]
```

### Surviving stack spills: the canonical address resolution

ARM64 calling conventions frequently spill function arguments to the stack between
calls — a pattern C3 would lose without explicit handling:

```asm
; ARM64 compiler output at -O0:
BL   xpc_dictionary_get_value    ; return value in x0
STR  x0, [sp, #0x10]             ; spill to stack
...
LDR  x0, [sp, #0x10]             ; reload from stack
BL   xpc_int64_get_value         ; pass to typed accessor
```

In VEX IR, this becomes:
```
t5 = GET(16)        ; read x0 (return from get_value)
Store(sp+0x10, t5)  ; spill
...
t2 = Load(sp+0x10)  ; reload
PUT(16, t2)          ; put back in x0
```

C3's `_canonical_addr()` resolves frame-pointer-relative addresses recursively:

```python
# GET(sp) → 'sp+0x0'
# Add64(RdTmp(t), Const(0x10)) where tmp_addr[t]='sp+0x0' → 'sp+0x10'
# Load address sp+0x10 → look up mem_state['sp+0x10']
```

This handles nested arithmetic: `Add64(Add64(GET(sp), Const(0x10)), Const(0x08))`
resolves to `'sp+0x18'`. Signed 64-bit constants (negative VEX constants for
sub-word stack arithmetic) are handled by treating values ≥ 2⁶³ as negative.

### The template bank

Each template defines a **forbidden taint topology**:

```python
@dataclass(frozen=True)
class VulnTemplate:
    name               : str
    source_substrings  : tuple[str, ...]   # functions that produce tainted data
    sink_substrings    : tuple[str, ...]   # functions that consume it dangerously
    barrier_substrings : tuple[str, ...]   # functions that guard the taint flow
    sink_arg           : int               # which argument must be tainted (-1 = any)
    vuln_class         : TemplateVulnClass
    confidence         : float             # base confidence before path penalty
```

**MACH_OOB** — Mach message buffer reaches allocator size argument:
```
source: mach_msg, mach_msg_trap
  sink: malloc, calloc, realloc, valloc, alloc
  (any)
→ OOB vulnerability if size field is attacker-controlled
```

**XPC_TYPE** — XPC value reaches typed accessor without type guard:
```
source: xpc_dictionary_get_value, xpc_array_get_value
  sink: xpc_int64_get_value, xpc_uint64_get_value, xpc_data_get_length, ...
  barrier: xpc_get_type
→ Type confusion: caller assumes type without checking
```

**XPC_SIZE_ALLOC** — XPC-derived length reaches allocator:
```
source: xpc_data_get_length, xpc_array_get_count, xpc_uint64_get_value
  sink: malloc, calloc, realloc, alloc
  (none)
→ OOB if attacker controls the XPC payload size
```

**PORT_UAF** — Mach port deallocated then reused:
```
source: mach_port_deallocate, mach_port_destroy
  sink: mach_port_*, mach_msg, IOServiceOpen, IOConnectCall
  (none)
→ Port right use-after-free on this execution path
```

**IOKIT_OOB** — IOConnectCallMethod out-parameter reaches memory copy:
```
source: IOConnectCallMethod, IOConnectCallStructMethod, IOConnectCallScalarMethod
  sink: memcpy, memmove, malloc, calloc, bcopy, IOMemoryDescriptor
  (none)
→ OOB if kernel writes more data than the buffer expects
```

**ICMP_IHL_SKIP** — ICMP receive path reaches print/compare with fixed-offset inner-header pointer (logic bug, not stack overflow):
```
source: recvmsg, recvfrom, recv, read, pr_pack, icmp_input
  sink: printf, fprintf, syslog, memcmp, memcpy, memmove
  barrier: ip_hl, ntohs, ntohl
→ Confidence 0.60 — fires when inner-ICMP pointer derived without ip_hl shift
```

### Confidence scoring

Base confidence is template-specific (0.65–0.80). Two adjustments are applied:

**Path length penalty**: each hop beyond 1 reduces confidence by 10%:
```python
hop_factor = max(0.5, 1.0 - 0.10 * max(0, hops - 1))
confidence  = template.confidence * hop_factor
```

**Barrier suppression**: if a barrier function is found on any path from source to
sink, OR anywhere in the call-level graph reachable from the same source, confidence
is reduced to 0.10 and the finding is marked as suppressed.

The barrier detection is conservative: a function that calls `xpc_get_type` on the
*same* value anywhere in its body (not necessarily on the direct source→sink path)
counts as a barrier. This catches the common pattern:

```c
xpc_object_t val = xpc_dictionary_get_value(dict, key);
if (xpc_get_type(val) != XPC_TYPE_INT64) return;   // barrier
int64_t n = xpc_int64_get_value(val);               // sink
```

**Validation results**: 4/4 test cases pass (XPC_SIZE_ALLOC vuln/safe, XPC_TYPE
vuln/safe). Zero false positives on the safe cases with barriers present.

---

## C3 v2 — Full SSA Memory Taint

**Added in v2. File:** `c3_templates.py` (class `_RegTaint`)

### The v1 limitation

v1 C3 tracked taint at the register level only. When attacker-controlled data was
written to a struct field or stack slot and later read back through a different
register, the taint was lost. This was the primary source of false negatives on
patterns like:

```c
// XPC receive: msg.size set from untrusted xpc_dictionary_get_uint64
msg.size = xpc_dictionary_get_uint64(dict, "size");    // x0 tainted

// ... many instructions later in a different basic block ...

// msg passed by pointer: x8 = &msg
size_t buf = malloc(msg->size);    // load through x8+offset — v1 missed this
```

### The SSA memory model

v2 replaces the flat register map with a three-layer taint state:

```
_state      : dict[vex_reg_offset → frozenset[label]]   # register taint (as before)
_mem_state  : dict[canonical_key  → frozenset[label]]   # memory slot taint
_ptr_taint  : dict[vex_reg_offset → frozenset[label]]   # pointer-register taint
```

**Canonical memory keys** encode every addressable slot in the frame:

| Pattern | Key | Meaning |
|---------|-----|---------|
| Stack slot | `sp+0x18` | 8 bytes at offset 0x18 from SP |
| Frame slot | `fp+0x10` | 8 bytes at offset 0x10 from FP |
| Struct field through x0 | `r{offset_of_x0}+0x8` | field at byte 8 of value in x0 |
| Struct field through x1 | `r{offset_of_x1}+0x18` | field at byte 24 of value in x1 |

The last two patterns (general register-relative addressing) are new in v2. Every
VEX `Load(addr)` where `addr = Get(reg) + Const(delta)` maps to `r{reg}+{delta}`,
enabling taint tracking through arbitrary struct field accesses.

### Pointer-taint propagation

When a tainted value is stored through a register:

```
Store(Add(Get(x0), Const(0x8)), tainted_val)
```

v2 also sets `_ptr_taint[x0] = {label}`. This means that *all subsequent loads*
through x0 (i.e., any `r{x0}+*` key) inherit the taint — a conservative may-taint
approximation that handles the common pattern where a pointer to a tainted struct is
passed to a sink.

### Put-side invalidation

Every VEX `Put(reg, val)` statement clears all `r{reg}+*` entries from `_mem_state`
and removes `reg` from `_ptr_taint`. This prevents stale tracking when a register is
reused for a different purpose in a later basic block.

### Output-args marking

Some sources fill output buffers rather than returning a value directly. `mach_msg`
writes to the receive buffer passed in arg0; `IOConnectCallMethod` writes output
scalars to the pointer in arg6. v2 C3 templates declare these via `output_args`:

```python
VulnTemplate(
    name        = 'MACH_OOB',
    sources     = ['mach_msg', 'mach_msg_trap'],
    sinks       = ['malloc', 'calloc', 'realloc'],
    output_args = (0,),         # arg0 = &msg buffer — filled by kernel
    ...
)
```

When the source call is detected, the canonical address of the output arg register
is immediately marked tainted, even before any explicit load instruction.

### Expected improvement

Estimated 30–50% reduction in false negatives on struct-field and stack-slot taint
patterns, based on analysis of XPC dictionary parsing patterns in macOS daemons.
Patterns that were invisible to v1 C3 (taint through mach_msg receive buffer → struct
field extraction → allocator call via pointer argument) are now tracked end-to-end.

---

## C6 — Symbolic Taint Analysis

**File:** `c6_taint.py`  
**Class:** `C6Analysis`

### Symbolic execution: the formal model

Symbolic execution (King 1976) generalises concrete execution by allowing program
variables to take **symbolic values** — expressions rather than concrete numbers.
Instead of executing `x = read_input(); if (x > 10) { ... }` with a specific x, the
symbolic engine tracks both branches, constraining x > 10 in one world and x ≤ 10
in the other.

Formally, a symbolic execution state is a triple:

```
s = (σ, μ, π)
```

where:
- σ: register environment, mapping register names to symbolic expressions
- μ: memory, mapping symbolic addresses to symbolic values  
- π: path condition, a conjunction of boolean constraints satisfied on this path

At each branch point `if (expr)`, the engine forks:
- Left child: s with π ∧ (expr = true)
- Right child: s with π ∧ (expr = false)

A state is **feasible** if π is satisfiable. Infeasible states are discarded.

The **vulnerability query** at a sink (e.g., malloc) is: "does there exist a concrete
input I such that, when executed, the program reaches this state with size(I) > safe?"

This is a satisfiability query over the path condition plus the vulnerability
predicate. angr submits it to the Z3 SMT solver via the claripy interface.

### Bitvector theory (QF_BV)

angr uses **Quantifier-Free Bitvector theory** (QF_BV) as its constraint language.
Bitvectors are sequences of bits with fixed width, and operations over them model
machine arithmetic exactly — including overflow behaviour, signed vs. unsigned
comparison, and bitwise operations.

Key operations in QF_BV:
- `BVS(name, width)`: create a fresh symbolic variable ("unknown input")
- `BVV(value, width)`: create a concrete constant
- `Extract(hi, lo, bv)`: extract bits [lo:hi] from a bitvector
- `Concat(a, b)`: concatenate two bitvectors
- `bv + c`: bitvector addition (may overflow — wraps modulo 2^width)
- `ULT(a, b)`: unsigned less-than comparison
- `SLT(a, b)`: signed less-than comparison

This matters for OOB detection: a 16-bit size field compared as *unsigned* may wrap
around. `0xFFFF + 1 = 0x0000` (unsigned), which passes a `< 0x10000` bounds check
but then causes a 0-byte allocation while the code uses it as 65535.

### Taint via symbolic variable names

C6 propagates taint through claripy's symbolic variable system. When a mach_msg
receive buffer is tainted:

```python
def _taint_mach_msg_buffer(state, buf_addr, buf_size, label):
    buf_size = min(buf_size, MAX_RCV_TAINT_BYTES)   # 16 KiB cap
    tainted = claripy.BVS(f'c6_taint_{label}', buf_size * 8)
    state.memory.store(buf_addr, tainted, ...)
```

The entire buffer is replaced by a single wide symbolic variable. Any value derived
from it — by reading bytes, extracting fields, doing arithmetic — inherits the taint
label via claripy's variable propagation:

```python
def _is_tainted(expr):
    return any(v.startswith('c6_taint') for v in expr.variables)
```

`expr.variables` is a frozenset of all symbolic variable names that appear anywhere
in the expression tree — updated automatically by claripy through all operations.
This is O(1) in the common (cache-hit) case.

Using variable names rather than a separate taint map eliminates the synchronisation
problem between the taint map and angr's state-forking: when angr forks a state at a
branch point, it deep-copies the path condition and memory — and the symbolic variable
names are already embedded in those structures. No explicit taint map copy is needed.

### The hook table: 18 SimProcedures

angr allows replacing library functions with **SimProcedures** — Python code that
models the function's behaviour symbolically. C6 installs hooks on 18 symbols:

| Category | Symbols | Action |
|---|---|---|
| Mach IPC | `_mach_msg`, `_mach_msg_trap` | On MACH_RCV_MSG: taint receive buffer |
| Heap alloc | `_malloc`, `_calloc`, `_realloc` | Check if size arg is tainted; record allocation |
| Heap free | `_free` | Mark allocation freed; detect double-free |
| Port release | `_mach_port_deallocate` | Record port right as consumed; detect re-use |
| XPC read | `_xpc_dictionary_get_value` | Return tainted symbolic value; mark as untyped |
| XPC type | `_xpc_get_type` | Remove label from untyped set (guard seen) |
| XPC accessors (×9) | `_xpc_int64_get_value`, etc. | Detect access without type guard |

The hook for `malloc` is representative:

```python
class Hook_malloc(angr.SimProcedure):
    SAFE_MAX = 0x10000   # 64 KiB — sizes bounded below this are considered safe

    def run(self, size):
        if _is_tainted(size):
            label = _taint_label(size)
            confidence = 0.85
            try:
                max_val = self.state.solver.max(size)
                if max_val < self.SAFE_MAX:
                    # Path constraints already bound the size — guard present
                    confidence = 0.20   # suppressed
            except Exception:
                pass

            if confidence >= 0.40:
                _record_finding(self.state, VulnFinding(
                    vuln_class  = VulnClass.OOB,
                    description = f'malloc() tainted size (no bounds check). Origin: {label}',
                    site_addr   = self.state.addr,
                    taint_label = label,
                    confidence  = confidence,
                ))
```

The `state.solver.max(size)` call queries the SMT solver for the maximum value of
`size` consistent with the path condition. If the path went through a bounds check
(`if (size > 65535) return;`), then `max_val < 0x10000` and confidence drops. This
eliminated all false positives on the safe test cases.

### Vulnerability classes

| Class | Trigger condition | Example |
|---|---|---|
| OOB | Tainted value reaches allocator size without path-constraint bound | `malloc(msg->size)` where msg is attacker-controlled |
| UAF | `mach_port_deallocate` called twice on same port name on one path | Port right double-consumed in error path |
| XTYPE | XPC typed accessor reached with label not yet in `type_checked` set | `xpc_int64_get_value(untyped_obj)` |

**Validation**: 4/4 test cases pass:
- OOB vuln → `VulnClass.OOB` detected at 85% confidence ✓
- OOB safe (bounds check present) → no finding ✓  
- UAF vuln → `VulnClass.UAF` detected at 95% confidence ✓
- UAF safe (single deallocate) → no finding ✓

---

## C7 — Dynamic Validation

**Added in v2. File:** `c7_dynamic.py`  
**Class:** `C7Analysis`

### Why dynamic validation?

C6 produces a *symbolic* PoC: a concrete byte sequence that Z3 proves satisfies the
path constraints needed to reach the vulnerable sink. But Apple's ASB team requires
on-device execution evidence — a static argument that a path is theoretically reachable
is insufficient for submission. C7 closes this gap by actually running the PoC and
capturing proof of impact.

This is the stage that converts a "possible vulnerability" into a "submittable finding."

### C7 architecture

```
C6 finding → C7Analysis
                │
                ├── [PoC extraction]   extract_poc_from_c6()
                │       state.globals['c6_tainted_regions'] → concrete bytes
                │
                ├── [Payload delivery] C7DeliveryMode
                │       STDIN  — pipe bytes to process stdin
                │       FILE   — write to temp file, pass path as argv[1]
                │       MACH_MSG — generate and save a sender script (ctypes)
                │       MANUAL — save PoC and pause for manual delivery
                │
                └── [Validation runner] validate()
                        SUBPROCESS — subprocess + exit code + DiagnosticReports scan
                        LLDB       — LLDB batch mode crash capture
                        DTRACE     — pid$ probe confirming sink reached (non-destructive)
```

### Delivery modes

| Mode | Description | When to use |
|------|-------------|-------------|
| `STDIN` | Pipe payload bytes to target's stdin | CLI tools, read-from-stdin servers |
| `FILE` | Write payload to tempfile, pass path as argv | File parsers, image decoders |
| `MACH_MSG` | Generate ctypes Mach msg sender; save as `.py` | Mach IPC services (smbd, launchd clients) |
| `MANUAL` | Save payload to file, pause and print instructions | Services requiring special auth or entitlements |

### Validation runners

#### SUBPROCESS mode

Runs the target binary as a subprocess, feeds the PoC payload, waits for exit. Scans
`~/Library/Logs/DiagnosticReports/` for crash reports by binary name written after
the run started.

```
Result: CONFIRMED (crash report found) | NO_IMPACT (clean exit) | TIMEOUT
```

#### LLDB mode

Attaches LLDB in batch mode with a Python script that:
1. Launches the target under LLDB
2. Feeds the PoC payload via stdin or file
3. Waits for SIGSEGV / SIGABRT / EXC_BAD_ACCESS
4. Captures: crash type, faulting address, full register state, backtrace (20 frames)
5. Exits with evidence

LLDB mode requires the target to be debuggable (SIP disabled or `get-task-allow`
entitlement, or running in the macOS VM at 192.168.64.2 with SIP disabled).

#### DTRACE mode (preferred for production)

Non-destructive. Instead of inducing a crash, a DTrace script probes the sink function
to confirm it was reached with attacker-controlled arguments:

```
# DTrace script (OOB template):
pid$target::malloc:entry /arg0 > {threshold}/ {
    printf("C7_SINK_HIT malloc(%lu) ucallerpc=%p\n", arg0, ucallerpc);
    ustack(12); exit(0);
}
tick-30s { printf("C7_TIMEOUT\n"); exit(1); }
```

The sentinel string `C7_SINK_HIT` in DTrace output is the confirmation signal.
DTrace mode requires SIP disabled or the `dtrace` entitlement.

### Evidence output

C7 writes two files:

**`c7_evidence.txt`** — ASB-ready plain text block:

```
TriageForge C7 Dynamic Validation Evidence
==========================================
Platform : Darwin arm64e  macOS 26.4.1 25E5195e
Binary   : /usr/sbin/smbd
Function : 0x10006f098
Template : MACH_OOB
Payload  : 80 bytes (label: mach_msg_rcv_buf)
PoC hex  : 00 00 00 00 ff ff 00 00 ...

Result   : CONFIRMED
Evidence : CRASH_REPORT
Crash    : EXC_BAD_ACCESS (SIGSEGV)
Fault    : 0x00000000deadbeef
Registers:
  x0=... x1=... x2=...
Backtrace:
  frame 0: smbd`0x10006f220
  frame 1: smbd`0x10006f0b4
  ...

Conclusion:
  PoC payload produced a crash in smbd (pid XXXXX) at function 0x10006f098.
  The crash confirms attacker-controlled data from mach_msg reached an
  unsafe allocator call (malloc) and caused memory corruption.
  Submitted to Apple Security Bounty as: Userland → Daemons and Frameworks.
```

**`c7_evidence.json`** — machine-readable companion with all fields.

### PoC extraction from C6 state

```python
from metis.c7_dynamic import extract_poc_from_c6, C7PoC, C7DeliveryMode

poc = extract_poc_from_c6(c6_finding, proj=proj)
# poc.payload: bytes — the concrete PoC input
# poc.delivery: C7DeliveryMode.STDIN (inferred from template)
# poc.label: str — which taint source produced this payload

c7 = C7Analysis(binary='/usr/sbin/smbd')
evidence = c7.validate(poc, mode=C7DeliveryMode.DTRACE, timeout_s=60)
evidence.write('/tmp/c7_evidence')
print(evidence.asb_text)   # paste directly into ASB submission
```

### Mathematics: why DTrace is preferred

DTrace probes execute in kernel context with zero modification to process state —
the target binary is unaware it is being observed. This means:

1. Crash reports are not generated for DTRACE mode runs (no false positives from the
   probe itself)
2. The `C7_SINK_HIT` signal can be captured on production systems where inducing
   crashes would be disruptive
3. Multiple DTRACE runs can be combined to measure *probability* of reaching the sink
   under different network conditions (relevant for race conditions)

The trade-off: DTrace only confirms the sink was *reached*, not that an exploit would
*succeed*. For ASB submissions, DTrace evidence is typically sufficient to establish
security impact when combined with the C6 symbolic argument for exploitability.

---

## The Disassembly Layer

*This section covers how we actually get from binary bytes to analysable structure —
the practical plumbing that makes the rest of the pipeline work.*

### angr CFGFast: what it does and what it misses

`CFGFast` is angr's fast control flow graph recovery. It works by:

1. **Linear sweep**: disassemble from every function entry point discovered via symbols,
   ELF/Mach-O function starts, and heuristic patterns (function prologues)
2. **Recursive descent**: follow direct branches; record indirect branches as unresolved
3. **Function boundary detection**: detect function ends via returns and tail calls
4. **Tail call resolution**: detect `JMP target` where target is another function entry

`CFGFast` is fast because it doesn't execute the program — it works purely statically.
It misses:

- **Indirect calls through function pointers**: `CALL [rax]` where rax is computed at runtime
- **ObjC message sends**: `objc_msgSend` is an indirect call through a vtable
- **ARM64e PAC-authenticated calls**: pointer authentication codes are stripped by
  the hardware at runtime; angr doesn't model PAC so these appear as indirect
- **Position-independent thunks**: some compilers generate trampolines that confuse
  the disassembler

For the ICMP/ping case studies, `CFGFast` was sufficient — the binaries use direct
calls throughout. For Objective-C daemons (e.g., XPC service implementations), the
call graph recovered by `CFGFast` is incomplete and should be supplemented by
`CFGEmulated` (which actually executes) or by parsing the ObjC method dispatch table.

### pefile + capstone: Windows PE IAT resolution

angr's knowledge base (KB) function resolution fails for Windows PE binaries because
Import Address Table (IAT) entries are resolved at load time by the OS loader —
the static PE on disk contains placeholder addresses, not the actual import addresses.

For Windows binaries, IAT resolution requires:

```python
import pefile, capstone

pe  = pefile.PE("ping_w11_24h2_x64.exe")
iat = {imp.address: imp.name.decode()
       for entry in pe.DIRECTORY_ENTRY_IMPORT
       for imp in entry.imports if imp.name}

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

def resolve_call(insn):
    # CALL [rip + disp] pattern for x86_64 IAT calls
    if insn.mnemonic == 'call' and insn.op_str.startswith('[rip'):
        # capstone gives us the absolute target address
        target = insn.operands[0].mem.disp + insn.address + insn.size
        return iat.get(target, f'sub_{target:#x}')
    # Direct CALL — absolute target
    if insn.mnemonic == 'call':
        return f'sub_{int(insn.op_str, 16):#x}'
    return None
```

For ARM64 Windows, the same principle applies but with `BL` (branch-and-link)
instructions. ARM64 capstone represents `BL` operands with a `#` prefix that needs
stripping: `int(insn.op_str.lstrip('#'), 16)`.

Windows ARM64 loading also requires a monkey-patch for angr's missing SYSCALL_CC entry:

```python
import angr.calling_conventions as _cc
if 'AARCH64' in _cc.SYSCALL_CC and 'Win32' not in _cc.SYSCALL_CC['AARCH64']:
    _cc.SYSCALL_CC['AARCH64']['Win32'] = _cc.SYSCALL_CC['AARCH64'].get('Linux')
```

This patches the `WindowsSimOS.__init__` call that tries `SYSCALL_CC[arch]['Win32']`
before angr has any entry for that architecture combination.

### VEX IR: what it captures and what compilers hide

pyvex lifts machine code blocks to VEX IR with high fidelity. For straightforward
code, this is excellent for taint analysis. Two classes of code defeat naive
VEX scanning:

**Class 1: Compiler constant-folding**

The C expression `oicmp = (struct icmp *)(oip + 1)` (where oip is a `struct ip *`)
computes:

```
oicmp = oip + sizeof(struct ip) = oip + 20 = oip + 0x14
```

In VEX IR, we expect to find:

```
Binop(Iop_Add64, t_oip, Const(0x14))
```

But Apple clang at optimization level -O2 constant-folds the entire chain:

```c
oip   = icp->icmp_data      // = outer_icmp_ptr + 8
oicmp = oip + 1             // = outer_icmp_ptr + 8 + 20 = outer_icmp_ptr + 28
```

The compiler emits:

```asm
LDRB  w9, [x23, #0x1c]   ; 0x1c = 28 — the 0x14 is folded into the immediate
```

The VEX lift of this is:

```
WrTmp(t9, Load(Ity_I8, Add64(GET(x23), Const(0x1c))))
```

Scanning for `Const(0x14)` finds nothing. The fix: scan for **load/store offsets**,
not intermediate arithmetic. The pattern `ldrb [xN, #0x1c]` followed by
`ldrh [xN, #0x20]` (same base register, within a sliding window) is the compiled
signature of the `oip+1` bug.

```python
FOLDED_ICMP_TYPE_OFFSET = 0x1c   # icmp_data(8) + sizeof(struct ip)(20)
FOLDED_ICMP_ID_OFFSET   = 0x20   # icmp_data(8) + sizeof(struct ip)(20) + 4

for i, (addr, asm) in enumerate(instructions):
    if 'ldrb' in asm and '#0x1c' in asm:
        m = re.search(r'\[(\w+),\s*#0x1c\]', asm)
        if not m: continue
        base_reg = m.group(1)
        for j in range(i+1, min(i+12+1, len(instructions))):
            fwd = instructions[j][1]
            if 'ldrh' in fwd and '#0x20' in fwd and f'[{base_reg},' in fwd:
                # Bug confirmed: oip+1 fixed offset at addr
```

**Lesson**: when hunting compiler-optimised pointer arithmetic bugs, scan the
**resulting load/store offsets** in disassembly, not the intermediate operations in
VEX IR.

**Class 2: Inlined allocators and library code**

At high optimisation levels, `malloc` may be inlined by the compiler. The inlined
version doesn't appear as a `BL _malloc` instruction — there is no call to hook.
C6's hook table only catches library calls through the PLT/stub mechanism. Inlined
allocators are invisible to C6 without a CFG-level pass to identify inlined allocator
patterns by their instruction sequences.

### otool sliding-window scan

For ARM64 Mach-O binaries, `otool -arch arm64e -tV` provides annotated disassembly
suitable for offline scanning. The sliding-window technique:

```python
import subprocess, re

def run_otool(binary_path, arch='arm64e'):
    result = subprocess.run(
        ['otool', f'-arch', arch, '-tV', binary_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    # Parse: "    address    instruction operands"
    pattern = re.compile(r'^\s*([0-9a-f]{8,16})\s+(.+)')
    insns = []
    for line in lines:
        m = pattern.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).lower()))
    return insns
```

Note: otool outputs addresses without `0x` prefix. The pattern `r'^\s*(0x[0-9a-f]+)'`
fails — use `r'^\s*([0-9a-f]{8,16})'` instead.

### Universal Mach-O and the arm64e arch override

macOS system binaries are universal (fat) Mach-O files containing multiple architecture
slices. Without an explicit arch override, angr defaults to x86_64 *even on Apple
Silicon hardware*. This produces incorrect analysis on M-series Macs.

**Always** pass the arch explicitly:

```python
import archinfo
proj = angr.Project(
    binary_path,
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')},
)
```

`archinfo.arch_from_id('aarch64')` returns an `archinfo.Arch` instance. Passing the
string `'aarch64'` directly raises `TypeError: arch must be an archinfo.Arch instance`.

Auto-detection from the host:

```python
import platform
machine = platform.machine().lower()
arch = archinfo.arch_from_id('aarch64' if machine in ('arm64', 'aarch64') else 'x86_64')
```

### Microsoft Symbol Server acquisition

For Windows binaries, the Microsoft Symbol Server (MSDL) provides all Windows system
binaries indexed by build. No VM or installation media required.

**URL format:**
```
https://msdl.microsoft.com/download/symbols/{name}/{TimeDateStamp:08X}{SizeOfImage:x}/{name}
```

Where `TimeDateStamp` and `SizeOfImage` come from the PE optional header, available
via the winbindex JSON index at `https://winbindex.m417z.com`.

**Required User-Agent:**
```
Microsoft-Symbol-Server/10.0.10036.206
```

The server rejects requests without this header. SHA256 verification against the
winbindex index confirms authenticity.

---

## Pipeline Composition

### The flow

```
Binary → C2 (structural screen) → C3 (template triage) → C6 (taint confirmation) → C7 (dynamic validation)
                                         ↑
                                    C1 (path prioritiser, runs inside C6)

For multi-binary campaigns:
batch_screen.py → Pool(C2) → ranked JSON → C3/C6/C7 on top hits
```

C2 outputs a ranked list of function addresses. C3 takes the top-N and checks for
template matches. C6 takes C3's high-confidence hits and runs symbolic taint analysis.
C1 runs inside C6's exploration loop, deferring hard paths. C7 takes a C6 finding and
validates it on-device, producing ASB-ready evidence.

### Integration in code

```python
import angr, archinfo
from metis.c2_rmt import C2RMTAnalysis
from metis.c3_templates import C3TemplateAnalysis
from metis.c6_taint import C6Analysis
from metis.c7_dynamic import C7Analysis, extract_poc_from_c6, C7DeliveryMode
from metis.exploration_technique import HardnessExplorationTechnique

BINARY = '/usr/libexec/targetd'

# 1. C2 screen — identify structurally anomalous functions
proj = angr.Project(BINARY, auto_load_libs=False,
                    main_opts={'arch': archinfo.arch_from_id('aarch64')})
c2 = C2RMTAnalysis.from_project(proj)
c2_result = c2.run()
c2_result.print_report()

# Top addresses: feed to C3
top_addrs = c2_result.top_function_addrs[:50]

# 2. C3 template match — check for forbidden def-use topologies
c3 = C3TemplateAnalysis(proj)
c3_result = c3.analyse_functions(top_addrs)
c3_result.print_report()

# High-confidence hits: feed to C6
c6_targets = c3_result.top_function_addrs[:10]

# 3. C6 taint analysis — symbolic confirmation
c6 = C6Analysis(proj)

for addr in c6_targets:
    state  = proj.factory.call_state(addr)
    result = c6.run(
        state,
        max_steps=800,
        extra_techniques=[HardnessExplorationTechnique(threshold=0.75)]
    )
    if result.findings:
        result.print_report()

        # 4. C7 dynamic validation — on-device evidence
        poc = extract_poc_from_c6(result.findings[0], proj=proj)
        c7  = C7Analysis(binary=BINARY)
        evidence = c7.validate(poc, mode=C7DeliveryMode.DTRACE, timeout_s=60)
        evidence.write(f'/tmp/c7_{hex(addr)}')
        print(evidence.asb_text)
```

### Parallel batch screening

For overnight multi-binary campaigns, `batch_screen.py` runs C2 on an entire
directory in parallel:

```bash
python3 batch_screen.py /usr/libexec/ --workers 8 --output ~/triageforge/results/
```

Each worker is an independent subprocess. On 8 cores, 300 macOS daemons complete in
approximately 15 minutes (vs. 2.5 hours sequential). Results are written to a
timestamped JSON in the output directory, sorted by `|z_entropy|` descending.

### Priority scoring

When multiple signals are available, a composite priority score guides investigation:

```python
priority = (
    0.25 * rmt_z_score_normalised +   # C2: structural anomaly
    0.40 * c6_taint_confidence     +   # C6: proximity to confirmed sink
    0.35 * (1.0 - hardness_score)      # C1: path is solvable
)
```

Weights are provisional. The 0.40 weight on C6 confidence reflects the fact that a
confirmed symbolic taint path is the strongest signal — a C2 anomaly alone could be
explained by legitimate complexity (e.g., a parser).

---

## Case Studies

### Case Study 1: macOS ping — CVE-2022-23093 Assessment

**Target:** `/sbin/ping`, macOS 26.4.1, arm64e  
**Question:** Is Apple's ping vulnerable to the FreeBSD pr_pack() stack buffer overflow?

**Pipeline execution:**

**C2 result:** 304 functions discovered. Top function by combined score: `sub_1000007f0`
(cyclomatic=34, back_edges=9). Binary z-scores within normal range — this is a
well-structured binary, which is expected.

**Lesson learned — C2:** The highest-complexity function was `main()` (argument-parsing
loop with many `strcasecmp` comparisons for traffic class names), not the ICMP receive
handler. C2 ranks by structural anomaly; `pr_pack` is complex but not the *most*
complex function. Validate function identity before investing in VEX scanning.

**C3 result:** Zero hits on the five XPC/Mach/IOKit templates (MACH_OOB, XPC_TYPE,
XPC_SIZE_ALLOC, PORT_UAF, IOKIT_OOB). Expected — `ping` uses POSIX raw sockets, not
XPC or Mach messages. The sixth template, **ICMP_IHL_SKIP** (added in v2.1, source:
recvmsg/pr_pack, sink: printf/memcmp, barrier: ip_hl/ntohs), fires on `pr_pack` at
confidence 0.60 — confirms the fixed-offset logic bug path from network receive to
print is present and lacks the ip_hl shift barrier.

**VEX IR result (Step 4):** Scan for `Binop(Iop_Add64, _, Const(0x14))` — the
expected signature of `oip + sizeof(struct ip)` — returned zero matches. The compiler
folded the pointer arithmetic into load immediates.

**Supplementary disassembly (Step 5):** otool scan for the constant-folded pair
confirmed the secondary logic bug at `0x10000300c` / `0x100003018`:

```
000000010000300c    ldrb    w9, [x23, #0x1c]    ← oicmp->icmp_type (FIXED offset)
0000000100003018    ldrh    w9, [x23, #0x20]    ← oicmp->icmp_id   (FIXED offset)
```

The offset `0x1c = 28 = 8 (icmp_data) + 20 (sizeof struct ip)` is the compiled form
of `oip + 1` — a fixed-sizeof offset rather than the correct `oip + (oip->ip_hl << 2)`.
With `ip_hl = 0x0F` (60-byte header): the code reads 40 bytes before the real inner
ICMP header.

**Primary finding:** macOS ping NOT vulnerable to CVE-2022-23093. Apple uses pointer
arithmetic directly into the receive buffer — no `memcpy()` into a fixed-size stack
`struct ip`. Structurally immune.

**Secondary finding (low severity):** The `oip+1` logic bug causes incorrect packet
matching when inner IP headers carry options. Effect: type mismatch → early exit,
ICMP error silently discarded. No memory corruption, no code execution path.

**Disposition:** Not filed. Logic bug has no meaningful security impact.

---

### Case Study 2: Windows ping — Allocation Adequacy Analysis

**Target:** `ping_w11_24h2_x64.exe`, Windows 11 24H2, x86_64  
**Source:** Microsoft Symbol Server (SHA256 verified)  
**Question:** Does Windows ping allocate sufficient buffer space for IcmpSendEcho2Ex?

**C2 result:** 138 functions. Top function `sub_140002890` (cyclomatic=155,
back_edges=25, score=2.58) — extreme outlier in a 44KB binary. IAT resolution via
pefile+capstone confirmed this is `main()` plus the entire ping loop (WSAStartup,
IcmpCreateFile, IcmpSendEcho2Ex, GetNameInfoW, fwprintf, exit).

**Allocation analysis:** Two-tier hardcoded LocalAlloc at `0x14000333b`:

```asm
0x140003320  mov  eax, 0x1ff8      ; 8184 bytes (small data path, ≤32 bytes send)
0x140003325  mov  ecx, 0x10047     ; 65607 bytes (large data path, >32 bytes send)
0x14000332a  cmp  r15d, 0x20       ; is send data > 32 bytes?
0x14000332e  cmova eax, ecx        ; conditional select
0x14000333b  call LocalAlloc
```

**Required buffer formula:**
```
sizeof(ICMP_ECHO_REPLY)   =  40 bytes
+ RequestDataSize          =  up to 65499 bytes (-l max)
+ ICMP error overhead      =  8 bytes
+ IO_STATUS_BLOCK          =  16 bytes (async variant)
+ MaxIpOptionsSize         =  40 bytes (IPv4 IHL ceiling: 4-bit field, max 60-byte header)
────────────────────────────────────────────────────────
Worst case (-l 65499 -r 9): 65602 bytes
```

**Verdict:**

| Scenario | Required | Allocated | Margin |
|---|---|---|---|
| Default (`-l 32 -r 9`) | ~135 bytes | 8184 bytes | +8049 bytes |
| Maximum (`-l 65499 -r 9`) | 65602 bytes | 65607 bytes | +5 bytes |

Both allocations adequate. The constants 8184 = 8192 − 8 (two OS pages minus heap
header) and 65607 = 65535 + 72 are deliberate conservative ceilings — a known
Microsoft technique. Validated by four independent LLMs (Gemini 2.5 Pro, ChatGPT o3,
Grok 3, DeepSeek R2).

**Primary finding:** User-mode surface CLEAN. Real Windows ICMP attack surface is
in `tcpip.sys` (kernel driver). Pursuing `ping.exe` past this point is diminishing
returns without a kernel debugger.

---

## Limitations

### angr operational limits

**Binary size:** `CFGFast` reliably handles binaries up to approximately 3.3 MB on
typical hardware (16 GB RAM). Larger binaries — kernel extensions, large frameworks —
trigger out-of-memory conditions. Workaround: use `CFGFast` with a function address
list (targeted mode) rather than whole-binary analysis.

**ARM64e pointer authentication:** `BLRAAZ`, `BLRAA`, `BRAA` instructions encode
PAC-authenticated indirect calls. angr does not model PAC — these appear as indirect
branches with unknown targets, creating gaps in the call graph. The impact is
conservative: missed edges mean some functions have lower eigenvector centrality
than they should, but no false positives are introduced.

**Chained fixups (LC 0x80000034):** Some binaries use Apple's chained-fixups loader
format (`LC_DYLD_EXPORTS_TRIE` + `LC_DYLD_CHAINED_FIXUPS`). angr's CLE loader does
not fully handle the page-table-style relocation encoding in this format, causing
`KeyError` in the load pipeline. Affected binaries cannot be analysed without a CLE
patch.

**Objective-C dispatch:** `objc_msgSend` is an indirect call resolved by the runtime.
C3 cannot trace taint through ObjC message sends without an ObjC metadata parser that
maps selectors to implementation addresses.

### C1 limitations

The backbone fraction approximation via Z3 assumptions is O(B × T) where B is the
number of input bits and T is the solver time per query. For states with large symbolic
inputs (e.g., a mach_msg receive buffer of 4 KB = 32,768 bits), the probe time
becomes significant. The `max_bits=512` cap limits probing to the first 512 bits of
symbolic input, which may miss backbone structure in later bits.

The correlation ρ = +0.43 (backbone fraction vs. CDCL solve time) was measured on
randomly generated 3-SAT instances. Real program path conditions are not random —
they have algebraic structure from the program logic. The correlation may be higher
or lower on real workloads.

### C3 limitations

C3 operates intra-procedurally: source and sink must be in the same function, or
the template will not match. The common pattern of `mach_msg()` in a receive loop
that passes the buffer to a handler function by pointer is invisible to C3. The
handler function does not call `mach_msg` directly, so no source node exists in its
call-level graph.

Register taint only — memory flows through struct fields, heap allocations, and global
variables are not tracked. This is a known false-negative source, supplemented by C6.

### C6 limitations

State explosion: a mach_msg buffer of 256 bytes produces a symbolic variable of 2048
bits. Every branch that tests any byte of that buffer forks the exploration. With 100
such branches, angr must explore up to 2¹⁰⁰ states — infeasible without aggressive
pruning via C1 or `max_steps`.

Hook coverage: only the 18 symbols in `_HOOK_TABLE` are intercepted. Inlined
allocators, wrapper functions, and indirect dispatch (ObjC, vtables) bypass the hooks
entirely. For production use, supplement with a CFG-level inlined-allocator detector.

---

## Glossary

**Adjacency matrix:** A square matrix A where A[i,j] = 1 if node i connects to node j
in a graph. The eigenvalue spectrum of A characterises the graph's structure.

**Backbone (SAT):** The set of variables that take the same value in every satisfying
assignment. A large backbone means the solution space is small and the problem is hard.

**Bitvector theory (QF_BV):** The logical theory used by angr/Z3 for constraint
solving. Variables are fixed-width sequences of bits; operations model machine
arithmetic exactly including overflow.

**CFGFast:** angr's fast static control flow graph recovery — linear sweep plus
recursive descent. Fast but misses indirect calls.

**Claripy:** angr's constraint solving library; provides symbolic bitvectors and
interfaces to Z3.

**Configuration model (graph theory):** A null distribution for random graphs that
preserves the in-degree and out-degree sequence of the observed graph. The maximally
random graph consistent with the observed degree distribution.

**Cyclomatic complexity (McCabe's M):** M = E − N + 2, where E = CFG edges, N = CFG
nodes. Equals the minimum number of test cases for branch coverage; a proxy for code
complexity.

**Directed configuration model:** The directed version of the configuration model,
preserving both in-degree and out-degree sequences separately.

**Eigenvector centrality:** A node importance measure where a node is important if it
is connected to other important nodes. Computed as the principal eigenvector of the
adjacency matrix.

**Eigenvalue entropy:** H = −Σ pᵢ log pᵢ, where pᵢ = |λᵢ| / Σ|λⱼ|. Measures the
uniformity of the eigenvalue spectrum; high entropy indicates many eigenvalues of
similar magnitude.

**Graph energy:** E(G) = Σ|λᵢ|/N. The sum of absolute eigenvalue magnitudes per node.
Non-zero even for DAGs; captures overall structural complexity.

**Hook table:** C6's list of (symbol_name, SimProcedure) pairs. Each hook replaces a
library function with Python code that models its behaviour symbolically.

**IAT (Import Address Table):** Windows PE mechanism for importing functions from DLLs.
IAT entries contain the runtime address of each imported function. Static binaries
contain placeholders that are filled in by the OS loader.

**IRSB (Intermediate Representation SuperBlock):** A VEX basic block. Contains a
sequence of VEX statements, a jump condition, and a jump kind (`Ijk_Call`, `Ijk_Ret`, etc.).

**Marchenko-Pastur distribution:** The limiting eigenvalue density for the covariance
matrix of a large random matrix with i.i.d. entries. **Inappropriate** for call graph
analysis due to power-law degree distributions.

**McCabe's theorem:** The cyclomatic complexity M equals the minimum number of test
cases required for full branch coverage of a function.

**Path condition:** The conjunction of all branch constraints accumulated along a
symbolic execution path. A state is feasible if its path condition is satisfiable.

**Phase transition (3-SAT):** At clause-to-variable ratio α ≈ 4.267, random 3-SAT
instances transition sharply from satisfiable to unsatisfiable. Instances near this
ratio are maximally hard to solve.

**Power-law degree distribution:** A graph where degree k nodes occur with frequency
proportional to k^(−γ). Real call graphs have power-law degree distributions —
a few functions are called by many others.

**pyvex:** Python bindings for the VEX IR lifter. Takes a sequence of machine code
bytes at an address and returns a VEX IRSB.

**QF_BV:** Quantifier-Free Bitvector theory. The fragment of first-order logic with
fixed-width bitvectors and machine arithmetic operations, but no quantifiers (∀, ∃).
Decidable and efficiently handled by SMT solvers.

**RMT (Random Matrix Theory):** The mathematical study of matrices with random entries.
The eigenvalue statistics of large random matrices follow universal laws (Wigner
semicircle, Marchenko-Pastur) that depend only on the symmetry class of the matrix,
not the specific distribution of entries.

**SimProcedure (angr):** A Python class that replaces a binary function during
symbolic execution. Used to model library functions (malloc, mach_msg, xpc_*) whose
source is not available or whose symbolic execution would be intractable.

**Spectral radius:** ρ(A) = max|λᵢ| — the largest absolute eigenvalue. Zero for
directed acyclic graphs; positive when cycles exist.

**SSA (Static Single Assignment):** An intermediate representation where each variable
is assigned exactly once. VEX IR temporaries (t0, t1, ...) are in SSA form within a
basic block.

**Taint analysis:** Program analysis that tracks which values are derived from
attacker-controlled sources ("tainted") and checks whether they reach dangerous sinks.
C6 implements taint via symbolic variable names propagated through claripy expressions.

**Tseitin transform:** A polynomial-time algorithm to convert an arbitrary boolean
formula to conjunctive normal form (CNF) by introducing auxiliary variables for each
gate. Preserves satisfiability but destroys the factor-graph structure required by
Survey Propagation.

**VEX IR:** The intermediate representation developed by the Valgrind instrumentation
framework (© 2000–2024 Julian Seward and the Valgrind Developers; GPL v2). Used in
this toolchain via the pyvex library (bundled with angr). Lifts x86, ARM64, MIPS,
and other architectures to a common SSA-based IR for static analysis.

**Wigner semicircle law:** The limiting eigenvalue density for large symmetric random
matrices with i.i.d. entries: a semicircle of radius 2√N. **Inappropriate** for
directed call graph adjacency matrices (asymmetric) with power-law degree structure.

**Z-score:** z = (observed − μ) / σ. Measures how many standard deviations the
observed value is from the mean of the null distribution. |z| > 2.0 corresponds
approximately to a 5% significance level (two-tailed).

---

## References

**Theoretical foundations:**

- Mézard M., Parisi G., Zecchina R. (2002). "Analytic and algorithmic solution of
  random satisfiability problems." *Science* 297(5582):812–815. — Phase transition location.

- Krzakala F. et al. (2007). "Gibbs states and the set of solutions of random
  constraint satisfaction problems." *PNAS* 104(25):10318–10323. — Condensation transition.

- McCabe T.J. (1976). "A Complexity Measure." *IEEE Transactions on Software Engineering*
  2(4):308–320. — Cyclomatic complexity definition.

- Marchenko V., Pastur L. (1967). "Distribution of eigenvalues for some sets of random
  matrices." *Math. USSR-Sb.* 1:457–483. — MP distribution (cited to note it's the wrong null).

- Bollobás B. (1980). "A probabilistic proof of an asymptotic formula for the number
  of labelled regular graphs." *European Journal of Combinatorics* 1(4):311–316. — Configuration model.

- Newman M.E.J., Strogatz S.H., Watts D.J. (2001). "Random graphs with arbitrary
  degree distributions and their applications." *Physical Review E* 64(2):026118. — Directed configuration model (canonical reference for the null used in C2).

**Implementation foundations:**

- Shoshitaishvili Y. et al. (2016). "SoK: (State of) The Art of War: Offensive
  Techniques in Binary Analysis." *IEEE S&P 2016*. — angr framework paper.

- Brumley D. et al. (2011). "BAP: A Binary Analysis Platform." *CAV 2011*. — VEX IR
  in binary analysis context.

- King J.C. (1976). "Symbolic Execution and Program Testing." *CACM* 19(7):385–394. — Symbolic execution.

**Case study references:**

- FreeBSD Security Advisory FreeBSD-SA-22:15 (2022). CVE-2022-23093. `pr_pack()` stack buffer overflow.

- Microsoft MSDN: IcmpSendEcho2Ex function documentation. `iphlpapi.h`.

- Winbindex (m417z): Windows binary index at https://winbindex.m417z.com

---

*This document describes a research methodology. Specific vulnerability findings
referenced in the case studies have been redacted or described at the methodology
level only. Active reports are under responsible disclosure with the relevant vendors.*

*Public repository: methodology code only. No unpublished PoC code included.*
