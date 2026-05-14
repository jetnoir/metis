# TriageForge v2 — Roadmap
## What comes after the foundation works

**Author:** Stuart Thomas  
**Date:** 2026-04-18  
**Status:** Planning — v1.0 is the baseline everything here improves on

---

## The v1 honest picture first

v1 does one thing well: it narrows 300 functions to 3 in under two minutes on a
C/C++/Objective-C macOS binary under ~3 MB. The benchmarks are real. The findings
are real. But there are six places where it breaks, and those six places are the
entire v2 agenda.

---

## The six v1 limitations that drive v2

| # | Limitation | Impact |
|---|---|---|
| L1 | Binary size cap (~3 MB Mach-O) | Can't screen large daemons like `cloudd`, `nsurlsessiond` |
| L2 | C3 is register-level taint only — misses flows through memory | False negatives on struct-field and stack-slot taint paths |
| L3 | `objc_msgSend` is a black box — C6 can't follow ObjC dispatch | Whole class of macOS vulnerabilities invisible to C6 |
| L4 | No dynamic validation — C6 output is untested | ASB submissions need on-device evidence; currently manual |
| L5 | Sequential only — one binary at a time | Can't screen 300 daemons overnight |
| L6 | Go and Rust binaries not tested | Windows and Linux server attack surface largely untouched |

v2 fixes L1 through L5 directly. L6 is the v2 research frontier.

---

## Priority 1 — Core engine improvements

### 1.1 Function-level slicing (fixes L1)

**The problem:** angr builds a whole-binary CFG before analysis. For large binaries
(> 3 MB Mach-O, > 10 MB PE) this causes memory exhaustion before a single function
is ranked.

**The fix:** Analyse functions in isolation. C2 only needs the call graph topology,
not the full CFG. Build the call graph from the IAT and symbol table first, then lift
individual function blocks to VEX only when C3/C6 needs them.

```
Current:   whole-binary CFGFast → rank functions → analyse top-N
v2:        call graph from IAT/symbols (~1s) → rank → lift top-N only
```

**Effort:** Medium  
**Status: ✅ Implemented 2026-04-18** — `metis/fast_c2.py` (lief + capstone).
`analyse_binary()` in `c2_rmt.py` selects FastC2 for binaries > 3.5 MB automatically.
Known trade-off: C/C++ binaries produce valid RMT z-scores; pure ObjC/Swift binaries
with BLR-only cross-function dispatch produce z=0 (no BL edges detected — degenerate
null model). This is documented and expected; the conservative `anomalous=False` result
avoids false positives.

**Expected gain:** Removes binary size cap for C/C++ daemons. ObjC/Swift daemons
require L3 (ObjC dispatch modelling) before FastC2 can rank them usefully.

---

### 1.2 Full SSA / ReachingDefinitions for C3 (fixes L2)

**The problem:** v1 C3 tracks taint at the register level only. Taint through memory
(struct fields written in one function, read in another; stack slots passed by
pointer) is invisible. This is the main source of false negatives.

**The fix:** Replace the register taint map with VEX IR's native SSA form.
pyvex exposes `IRSB.statements` including `WrTmp`, `Put`, `Store`, `Load` — a full
def-use chain. v2 C3 tracks taint through `Store`/`Load` pairs using a symbolic
memory model (address-keyed taint map, symbolic addresses treated conservatively).

**Effort:** Large  
**Expected gain:** Estimated 30–50% reduction in false negatives on struct-passing
patterns (e.g., XPC dictionary fields passed as pointers through multiple frames).

---

### 1.3 ObjC dispatch modelling (fixes L3)

**The problem:** `objc_msgSend(receiver, selector, ...)` is an indirect call resolved
at runtime via the ObjC runtime's method cache. angr cannot follow it. Every ObjC
method call is a dead end in C6's taint graph.

**The fix:** Pre-analysis pass that:
1. Scans the `__objc_methnames` section to extract all method selectors
2. Resolves each selector to its implementation address via the method list
3. Inserts a synthetic call edge in the call graph for each `objc_msgSend` site
4. Passes a hook table to C6 so it can follow ObjC dispatch symbolically

**Effort:** Large  
**Expected gain:** Opens the ObjC runtime layer of macOS daemons — most modern
macOS daemons use ObjC or Swift/ObjC hybrid. This is where the interesting
daemons live.

---

### 1.4 C7 — Dynamic validation pass (fixes L4)

**The new stage:** After C6 synthesises a PoC input, C7 validates it on-device.

```
C6 output:  concrete PoC input (e.g., ICMP packet bytes)
C7 input:   PoC input + target binary + expected sink address
C7 output:  crash report / LLDB register state / DTrace probe output
```

**Implementation:**
- Spin up the target binary under LLDB (or a test harness)
- Feed the C6 PoC input via stdin / network socket / mach_msg
- Watch for crash, signal, or OOB memory access
- Capture: crash type, faulting address, register state, backtrace
- Output: `c7_evidence.txt` in ASB-submission-ready format

**Why this matters:** Apple's ASB team explicitly requires on-device execution
evidence. Nick (Apple reviewer) closed one early submission with: *"Actionable
reports need evidence of security impact from on-device execution."* C7 produces
that evidence automatically.

**Effort:** Medium  
**Expected gain:** Closes the loop from binary to ASB-ready report automatically.
Removes the manual step that currently takes hours.

---

### 1.5 Parallel screening (fixes L5)

**The problem:** Screening 300 macOS daemons sequentially takes 300 × 30s = 2.5
hours. Overnight batch jobs need parallel execution.

**The fix:**

```python
# v2 batch runner — trivial to implement
from multiprocessing import Pool
with Pool(processes=cpu_count()) as pool:
    results = pool.map(run_c2_screen, binary_paths)
```

C2 is embarrassingly parallel — each binary is independent. C3 and C6 can be
parallelised at the function level within a binary.

**Effort:** Small  
**Expected gain:** On a 10-core machine: 300 daemons in ~15 minutes instead of
2.5 hours. On the analysis cloud VM (e2-standard-4, 4 vCPUs): ~45 minutes.

---

## Priority 2 — Expanded attack surface

### 2.1 Windows PE full support

**Current status:** pefile + capstone for IAT resolution, partial C2. C3 and C6 are
macOS-template-only.

**v2 target:**
- Full C2+C3+C6 on Windows PE (x64 and ARM64)
- New C3 templates for Windows vulnerability classes:
  - `WIN_IPC`: RPC/COM call → untrusted size → HeapAlloc
  - `WIN_LPE`: SeImpersonatePrivilege check → privileged operation
  - `WIN_UAF`: CloseHandle → handle reuse in race window
- Symbol resolution via Microsoft Symbol Server (MSDL) already implemented in v1;
  v2 extends this to populate the call graph with resolved names

**Effort:** Medium  
**Expected gain:** Windows attack surface (system services, RPC endpoints, COM
servers) is largely unscreened by existing tools. Direct path to Chrome VRP and
Microsoft MSRC submissions.

---

### 2.2 Linux ELF support

**v2 target:** Basic C2+C3 on Linux ELF binaries (x86_64 and ARM64).

**Why:** Cloud server daemons (`sshd`, `systemd` services, container runtimes) are
the highest-value Linux targets. ELF support opens the cloud/server security market
and enables screening of open-source daemon builds before upstream patches.

**Effort:** Medium (angr already supports ELF natively)  
**New C3 templates needed:**
- `LINUX_PRIV`: `setuid`/`capset` → privileged operation without credential drop
- `LINUX_OOB`: `read()`/`recv()` → `memcpy()` without explicit bounds check
- `LINUX_UAF`: `free()` → pointer dereference without NULL check

---

### 2.3 Go binary support (research)

**The challenge:** Go binaries are structurally different from C binaries:
- Goroutine scheduler introduces non-obvious concurrency
- Different calling convention (`GOARCH=arm64` uses register-based ABI)
- `runtime.morestack` appears in almost every function — massively inflates call graph
- Memory model: garbage collector, escape analysis, non-trivial allocation patterns

**v2 target (conservative):** C2 structural screen only — identify anomalous Go
binaries. C3/C6 on Go is a v3 problem.

**Required work:**
- Filter `runtime.*` functions from call graph before RMT analysis
- Calibrate null model for Go's characteristic call graph shape
- Validate against known Go CVEs (e.g., `net/http` path traversal patterns)

**Effort:** Large (research, not engineering)

---

## Priority 3 — Product features

### 3.1 Web dashboard

**The problem:** TriageForge v1 outputs JSON. Selling to consultancy managers who
review deliverables — not security engineers who read JSON — requires a visual.

**v2 dashboard:**
- Interactive call graph (D3.js, force-directed layout)
- Anomalous nodes highlighted in red (> |z| = 2.0)
- Click function → see cyclomatic score, template hits, VEX IR snippet
- Download PDF report (one click)
- Side-by-side diff view for differential analysis (2.2 below)

**Effort:** Medium (frontend work, not research)  
**Commercial impact:** High — this is the feature that converts Team plan demos.

---

### 3.2 Differential analysis

**The idea:** Compare two versions of the same binary. "What changed between macOS
15.3 and 15.4 that's worth looking at?"

**Why this is powerful:**
- Every OS patch introduces new code paths and modifies existing ones
- Manual patch diffing takes a skilled analyst 1–2 days per update
- TriageForge differential: which functions changed AND are structurally anomalous?

**Implementation:**
- Run C2 on both versions, produce two ranked lists
- Diff the combined score of each function across versions
- Flag: functions that (a) changed and (b) score increased significantly
- Output: `delta_report.json` with before/after scores for each changed function

**Effort:** Small (algorithmic diff on existing C2 output)  
**Commercial impact:** Very high — this is the premium feature for enterprise
product security teams who screen every OS release.

---

### 3.3 Automated ASB/VRP report generation

**The idea:** C7 produces on-device evidence. v2 takes that evidence and
auto-drafts a vendor submission report.

**Template fields auto-populated:**
- Binary name, version, affected macOS/Windows version
- Function address and name (from C2 top-rank)
- Template match (C3: which vulnerability class)
- VEX IR snippet showing the vulnerable pattern
- C6 PoC input (hex + annotated)
- C7 on-device evidence (crash type, faulting address, registers)
- CVSS v3.1 score estimate (based on template class + privilege level)

**Output:** Markdown + PDF, ready to paste into ASB / MSRC / Chrome VRP portal.

**Effort:** Small (template engine + existing output fields)  
**Commercial impact:** This is the v2 headline feature for the SaaS pitch.
"Submit-ready report in one pipeline run."

---

### 3.4 CI/CD integration

**GitHub Action:**

```yaml
- name: TriageForge binary screen
  uses: triageforge/action@v2
  with:
    binary: build/output/MyDaemon
    threshold: 2.0
    templates: MACH_OOB,XPC_TYPE,INT_OVF
  env:
    TRIAGEFORGE_API_KEY: ${{ secrets.TF_KEY }}
```

Fails the build if the binary is structurally anomalous AND a template matches at
HIGH confidence. Security gate in CI, not post-release.

**Effort:** Medium  
**Commercial impact:** Unlocks enterprise product security teams (FAANG scale).
This is the feature that justifies the Team/Enterprise pricing tier.

---

## Priority 4 — Research frontier

### 4.1 Survey Propagation for C1 (open research problem)

**The current limitation:** v1 C1 uses Z3 assumption-based probing — a weaker
approximation of backbone fraction. True Survey Propagation (SP) would give a more
accurate signal.

**The obstacle:** Tseitin CNF encoding destroys the factor-graph locality that SP
requires. The sparse factor graph of the original propositional formula becomes dense
after CNF transformation, breaking the SP message-passing assumptions.

**The research question:** Can SP be applied to the original propositional form of
the path constraints (before Tseitin), or can a locality-preserving CNF encoding be
found?

**Why it matters academically:** A practical SP implementation for path constraints
in symbolic execution would be a publishable result in formal methods / SAT research.
It would also improve the Spearman ρ from +0.43 toward a theoretically achievable
~0.7.

**Effort:** Very large (PhD-level research)  
**Suggested approach:** Collaborate with an academic group. This is the kind of
problem that gets a joint paper.

---

### 4.2 Corpus-calibrated thresholds

**The gap in v1:** The |z| > 2.0 threshold and the C3 confidence scoring weights
were set by manual inspection, not optimisation against a labelled corpus.

**v2 approach:**
1. Assemble a corpus of binaries with confirmed CVEs (public NVD entries with
   function-level detail) as positive labels
2. Assemble a corpus of known-clean binaries (extensively audited, no known CVEs)
   as negative labels
3. Optimise the z-score threshold, combined score weights, and C3 confidence
   levels to maximise F1 score against this corpus
4. Publish the corpus (public CVEs only — no confidential findings)

**Expected result:** Formal false positive / false negative rates. This is the
number NCC Group and enterprise buyers will ask for. Having it is the difference
between a research demo and a commercial product.

**Effort:** Medium (corpus assembly is the hard part)

---

### 4.3 Protocol-aware XPC template generation

**The idea:** Instead of 5 generic templates, generate templates automatically from
XPC interface definitions.

**How:** Parse `.xpc` bundles and `.idl`/`.defs` files from macOS frameworks to
extract:
- Method names and argument types
- Expected entitlement checks before dispatch
- Known-dangerous argument combinations (e.g., `NSData` with attacker-controlled
  length)

Then auto-generate C3 templates specific to that interface.

**Why powerful:** Each macOS subsystem (CloudKit, HomeKit, XPC services) has its own
interface. Generic templates miss interface-specific patterns. Auto-generated
templates catch them.

**Effort:** Large  
**Publishable:** Yes — "automated vulnerability template generation from XPC
interface specifications" is a novel contribution.

---

## Summary — v2 in one table

| Feature | Priority | Effort | Fixes | Status | Notes |
|---|---|---|---|---|---|
| Function-level slicing | ✅ Done | Medium | L1 | **Done 2026-04-18** | `fast_c2.py` — lief+capstone, no size cap. Trade-off: z=0 on pure ObjC/Swift (BLR-only call graph); works correctly on C binaries |
| Parallel screening | ✅ Done | Small | L5 | **Done (Dell batch)** | `dell_batch_screen.py` — ProcessPoolExecutor, 3 workers, `--resume` |
| Full SSA C3 | 🔴 Not started | Large | L2 | Backlog | Still register-level taint in `c3_templates.py` |
| ObjC dispatch modelling | 🔴 Not started | Large | L3 | Backlog | CFGFast cannot resolve `objc_msgSend`; no synthetic edges yet |
| C7 dynamic validation | 🔴 Not started | Medium | L4 | Backlog | `run_poc_evidence.py` is finding-specific; no general C7 framework |
| Windows PE full support | 🟡 P2 | Medium | — | Backlog | |
| Linux ELF support | 🟡 P2 | Medium | — | Backlog | |
| Go binary support | 🟡 P2 | Large | L6 | Backlog | |
| Web dashboard | 🟠 P3 | Medium | — | Backlog | |
| Differential analysis | 🟠 P3 | Small | — | Backlog | |
| Auto report generation | 🟠 P3 | Small | — | Backlog | |
| CI/CD integration | 🟠 P3 | Medium | — | Backlog | |
| Survey Propagation C1 | 🔵 P4 | Very large | — | Research | |
| Corpus calibration | 🔵 P4 | Medium | — | Backlog | |
| Protocol-aware templates | 🔵 P4 | Large | — | Backlog | |

---

## What v2 looks like as a pitch

**v1:** "We narrow 300 functions to 3 in 90 seconds."

**v2:** "We screen your entire binary estate overnight, validate findings on-device
automatically, and deliver submit-ready vendor reports. Works on macOS, Windows, and
Linux. Integrates into your CI/CD pipeline. Quantified false positive rate."

That is a commercial product. v1 is a very impressive research tool.
v2 is what NCC Group signs a £100k licence for.

---

## Suggested sequence

Don't try to build all of this at once. The ADHD trap is starting everything and
finishing nothing. Suggested order:

```
Month 1–2:   Parallel screening (small) + Function slicing (medium)
             → removes the two most visible v1 limitations

Month 3–4:   C7 dynamic validation
             → unlocks automated ASB evidence, directly supports active portfolio

Month 5–6:   Web dashboard + Auto report generation
             → makes the product demoable to non-engineers, first real sales tool

Month 7–9:   Full SSA C3 + ObjC dispatch
             → the big technical lift, do it when the product is generating revenue

Month 10–12: Windows full support + Differential analysis
             → doubles the market, enterprise feature that justifies Team/Enterprise pricing
```

By month 12, TriageForge v2 is a fundable company.

---

*© 2026 Stuart Thomas, trading as TriageForge. Licensed CC BY 4.0.*  
*"The pipeline that killed C4 and C5 is still killing the right ideas." — keep that discipline.*
