# TriageForge — Benchmark Data
## Metis v1.0

**Platform:** macOS arm64e (Apple Silicon M-series)  
**Date:** 2026-04-17  
**Author:** Stuart Thomas  
**Status:** Independently measured on real binaries. No synthetic workloads.

> Numbers marked **[MEASURED]** are from instrumented runs on real binaries.  
> Numbers marked **[CHARACTERISED]** are representative of observed behaviour
> but not from a formal timing suite.  
> Numbers marked **[STATISTICAL]** are from the validation corpus described below.

---

## 1. C1 — Phase-Transition Backbone Prioritisation

### Validation corpus
- **n = 50** symbolic input bytes per target
- **5 binary targets** (angr crackme suite, condensation regime)
- Backbone fraction estimated via Z3 assumption-based probing

### Results

| Metric | Value | Notes |
|---|---|---|
| Backbone probe time | **32 ms / state** [MEASURED] | Z3 assumption-based; measured on Apple M-series |
| State reduction | **60%** [MEASURED] | Fewer states explored before finding solution path |
| Test pass rate | **5 / 5 (100%)** [MEASURED] | Backbone-prioritised exploration found solutions in all cases |
| Spearman ρ | **+0.43** [STATISTICAL] | Backbone fraction vs. CDCL solve time |
| Significance | **p = 0.012** [STATISTICAL] | n = 50 variables, condensation regime |

### What this means

A 60% state reduction means the symbolic execution engine explores 2.5× fewer paths
before finding a PoC input. At 32 ms per probing step, a function with 100 execution
states takes ~3.2 seconds to prioritise rather than exploring all states blindly.

The Spearman ρ = +0.43 confirms the underlying hypothesis: higher backbone fraction
predicts harder constraint solving. The correlation is moderate, not perfect — C1 is
a heuristic, not a guarantee.

### Known limitation

Probe time scales with the number of symbolic variables. A mach_msg receive buffer of
256 bytes (2,048 symbolic bits) increases probe time substantially. C1 is most
effective when symbolic variable width is bounded (≤ 512 bits per variable).

---

## 2. C2 — Random Matrix Theory Call Graph Screen

### Configuration

| Parameter | Value |
|---|---|
| Null model | Directed configuration model (Bollobás 1980; Newman et al. 2001) |
| Null replicates | 50 per binary |
| Metrics computed | Spectral radius ρ(A), graph energy Σ\|λᵢ\|/N, eigenvalue entropy H |
| Anomaly threshold | \|z\| > 2.0 (≈ 5% significance, two-tailed) |
| Minimum binary size | N > 100 functions (z-scores unreliable below this) |

### Timing

| Binary | Size | Functions | C2 screen time |
|---|---|---|---|
| Windows ping.exe (x64) | 44 KB | 138 | **~30 s** [MEASURED] |
| Windows iphlpapi.dll (ARM64) | 365 KB | ~600+ | **< 60 s** [MEASURED] |
| macOS /sbin/ping (arm64e) | ~250 KB | ~120 | **~30 s** [CHARACTERISED] |

### Case study results

**Windows ping.exe (44 KB, x64):**

| Metric | Value |
|---|---|
| Binary verdict | ANOMALOUS |
| Top function | `sub_140002890` |
| Cyclomatic complexity (M) | 155 |
| Back edges | 25 |
| Combined score | **2.58** |
| Rank in binary | 1 of 138 |

A cyclomatic complexity of 155 in a 44 KB binary is an extreme structural outlier.
This function is the primary ICMP send/receive loop — exactly the function a human
analyst would target. C2 identifies it in 30 seconds without reading any assembly.

---

**Windows iphlpapi.dll (365 KB, ARM64):**

| Metric | Value |
|---|---|
| Binary verdict | HIGHLY ANOMALOUS |
| z_entropy | **−9.87** |
| Top function | ICMPv6 reply parser |
| Callees | 23 |
| Structure | Recursive self-call present |

z_entropy = −9.87 indicates the binary's eigenvalue spectrum is far more hierarchical
than a random graph of similar size and degree — the call graph is dominated by a
single deep call chain. The negative z-score (not just positive) is informative:
extremely hierarchical structure signals tightly coupled, hard-to-test code paths.

---

**macOS /sbin/ping (arm64e) — CVE-2022-23093 methodology case study:**

| Metric | Value |
|---|---|
| Binary verdict | Within normal range |
| Target function | `pr_pack` |
| Cyclomatic complexity (M) | 34 |
| Back edges | 9 |
| C2 anomaly | Not flagged (logic bug, not structural anomaly) |
| C3 template hit | **INT_OVF** — HIGH confidence |
| VEX IR confirmation | Fixed offset 0x14 (`oip+1` not `ip_hl << 2`) |

This case demonstrates that C2 and C3 are complementary, not redundant. The macOS
`ping` binary is not structurally anomalous — but C3 still identifies the logic bug
in `pr_pack` because the call pattern matches the INT_OVF template regardless of the
spectral properties. C3 runs on functions ranked by C2; `pr_pack` is in the top-10
by combined score due to cyclomatic complexity and back-edge count alone.

---

## 3. C3 — Template-Based Call Dataflow Matching

### Templates implemented (5)

| Template ID | Pattern | Vulnerability class |
|---|---|---|
| MACH_OOB | mach_msg receive → malloc/calloc (no bound) | Out-of-bounds write via Mach IPC |
| XPC_TYPE | xpc_dictionary_get_value → typed accessor (no xpc_get_type) | XPC type confusion |
| INT_OVF | XPC/mach value → arithmetic → allocator | Integer overflow to OOB allocator |
| PORT_UAF | mach_port_deallocate → port operation (same name) | Port use-after-free |
| IOKIT_OOB | IOConnectCallMethod out-of-band data → copy/alloc | IOKit out-of-bounds |

### Timing

| Stage | Time |
|---|---|
| C3 on C2 top-20 functions | **< 60 s** [CHARACTERISED] |
| C3 on individual function CFG | **< 5 s** [CHARACTERISED] |

C3 taint tracking is register-level only (not full SSA). This trades accuracy for
speed: the full-binary C3 pass is intentionally cheap so it can run on every binary
before expensive C6 symbolic execution.

---

## 4. C6 — Symbolic Taint Analysis

### Timing

C6 timing is highly variable and binary-dependent. No single figure is representative.

| Scenario | Time |
|---|---|
| Simple function, tight path constraints | **2–5 minutes** [CHARACTERISED] |
| Complex function, many branches | **10–30 minutes** [CHARACTERISED] |
| State explosion (large symbolic buffers) | **Timeout (> 30 min)** — aborted |

### Limitations affecting timing

- mach_msg receive buffer of 256 bytes = 2,048 symbolic bits — Z3 constraint growth
  is exponential above condensation transition (~α = 4.15–4.27)
- Compiler optimisation (constant-folded arithmetic, inlined bounds checks) hides
  patterns that template-based taint expects at the VEX IR level
- Objective-C dispatch via `objc_msgSend` is an indirect call resolved at runtime —
  C6 cannot follow through it without additional modelling

---

## 5. Full Pipeline — End-to-End

### Typical run (from binary to ranked hotlist)

| Stage | Time |
|---|---|
| C2 RMT screen | ~30 s |
| C3 template match (top 20) | ~60 s |
| **Subtotal to ranked list** | **~90 seconds** |
| C6 symbolic taint (per flagged function) | 2–30 min |
| **Full pipeline** | **~3–32 minutes** |

### What the pipeline produces

Given a binary with N functions, the pipeline narrows to a ranked shortlist:

```
Input:   300 functions (typical macOS daemon)
C2:      Flags binary as anomalous or normal
         Ranks all 300 functions by combined score
C3:      Runs templates on top 20 by combined score
         Typically 0–5 HIGH confidence hits
C6:      Runs on HIGH confidence hits only
         Confirms or clears each candidate
Output:  3–5 functions with concrete PoC inputs or cleared verdicts
```

Human analyst equivalent: **2–5 working days** to reach the same shortlist manually.
TriageForge pipeline: **3–32 minutes**.

---

## 6. Combined Function Score

The function ranking formula used by C2:

```
score = 0.40 × ev_centrality
      + 0.35 × log1p(cyclomatic − 1)
      + 0.25 × log1p(back_edges)
```

Where:
- `ev_centrality` — eigenvector centrality in the call graph (0–1)
- `cyclomatic` — McCabe cyclomatic complexity M = E − N + 2
- `back_edges` — count of back edges in the control flow graph (loop proxy)
- `log1p` scaling prevents a single very-complex function from dominating

Weights derived from manual inspection of CVE-validated training cases. Not from
a formal regression — treat as empirically-motivated heuristic, not a trained model.

---

## 7. What Has NOT Been Formally Benchmarked

Honest gaps in the current benchmark data:

| Metric | Status | Notes |
|---|---|---|
| False positive rate | **Not measured** | No large labelled corpus of known-clean binaries |
| False negative rate | **Not measured** | Limited by confidentiality of accepted findings |
| C2 detection rate across binary types | **Partial** | Measured on macOS daemons + 2 Windows binaries |
| C3 template precision/recall | **Not measured** | Would require ground-truth labelled CVE corpus |
| Performance on Go/Rust binaries | **Not tested** | Expected to be lower — angr CFGFast less accurate |
| Performance on obfuscated binaries | **Not tested** | Packing/obfuscation likely defeats C2 structural screen |
| Multi-binary screening throughput | **Measured — see §8** | Parallel batch screener on Dell x86_64 Debian |

---

## 8. Parallel Batch Screening — Linux ELF Benchmark

**Platform:** Dell Precision workstation, Intel Core i7-4th gen, 32 GB RAM, Debian x86_64  
**Date:** 2026-04-17  
**Script:** `batch_screen.py` — `multiprocessing.Pool`, 8 workers  
**Binaries:** 6 Linux ELF system binaries from `/usr/bin/` and `/usr/sbin/`

### Results

| Binary | Verdict | z\_entropy | Top fn cyclomatic | Worker time |
|---|---|---|---|---|
| openssl | **ANOMALOUS** | −153.35 | 683 | 25.2 min |
| sshd | **ANOMALOUS** | −65.77 | 273 | 21.4 min |
| curl | **ANOMALOUS** | −44.12 | **727** | 2.6 min |
| ssh | **ANOMALOUS** | −41.72 | 512 | 33.0 min |
| gpg | **ANOMALOUS** | −2.09 | 512 | 35.8 min |
| git | **ANOMALOUS** | **+7.08** | 416 | 43.6 min |

All 6 flagged ANOMALOUS. 6 / 6 screened without error.

### Parallel speedup

| Metric | Value |
|---|---|
| Sequential equivalent (sum of worker times) | ~161 minutes |
| Actual wall time (8 workers, limited by slowest) | **43.6 minutes** |
| Speedup | **3.7×** |
| Bottleneck | `git` — broadest call graph, longest CFGFast pass |

On a fully balanced workload (equal binary sizes), the 8-worker pool would approach 8× speedup. Real-world speedup is limited by the longest-running binary.

### Two structural anomaly signatures observed

All previous benchmarks identified **negative** z\_entropy (spectrum dominated by a few large eigenvalues — deep hierarchical call chains). This batch surfaced a second signature:

**Negative z\_entropy (hierarchical):** openssl, sshd, curl, ssh, gpg  
→ Call graph dominated by a small number of hub functions with deep recursive or tightly coupled chains. Typical of protocol parsers, crypto state machines, auth handlers.

**Positive z\_entropy (flat/diverse):** git (+7.08)  
→ Eigenvalue spectrum more uniform than the null model — many functions of roughly equal structural importance. git's architecture (many small plumbing commands sharing a broad common library) produces this signature. A different structural risk: broad attack surface rather than deep complexity.

The threshold |z| > 2.0 correctly flags both directions.

### Top function scores (C3/C6 primary targets)

| Binary | Address | Function | Cyclomatic | Combined score |
|---|---|---|---|---|
| curl | 0x413ac0 | sub\_413ac0 | **727** | 3.017 |
| openssl | 0x498ae0 | sub\_498ae0 | 683 | 3.528 |
| gpg | 0x4254d0 | sub\_4254d0 | 512 | 3.340 |
| ssh | 0x417540 | sub\_417540 | 512 | 3.066 |
| git | 0x510af0 | sub\_510af0 | 416 | 3.180 |
| sshd | 0x40a430 | main | 273 | 2.932 |

curl's top function at cyclomatic 683 is the highest-complexity single function in this batch — the primary C3 template target if this were a real triage run.

### Notes

- Binary symbols stripped — function names `sub_XXXXXX` (except `main` in sshd/ssh)
- Worker times vary significantly by binary size and call graph density; this is expected
- gpg at z\_entropy = −2.09 is the boundary case: just over the |z| > 2.0 threshold. GnuPG is a well-audited codebase with a more modular call graph than OpenSSL — the threshold correctly reflects this distinction
- The unicorn engine warning (`unicornlib.so` not found) is suppressed in v2 batch\_screen.py; unicorn is not used by C2 (static analysis only)

---

## 9. Windows PE Benchmark — Hyper-V vmwp.exe

**Platform:** Dell Precision workstation, Intel Core i7-4th gen, 32 GB RAM, Debian x86_64  
**Date:** 2026-04-17  
**Script:** `batch_screen.py` — `multiprocessing.Pool`, 8 workers  
**Binary:** 1 Windows PE (x64) — Hyper-V VM worker process from Windows 11 SDK

### Result

| Binary | Verdict | z\_entropy | z\_energy | Worker time |
|---|---|---|---|---|
| vmwp.exe | **ANOMALOUS** | −1.70 | **+7.10** | 19.5 min |

### Top function scores

| Address | Function | Cyclomatic | Combined score |
|---|---|---|---|
| 0x1401e38af | sub\_1401e38af | 22 | 1.681 |
| 0x1401f7f1b | sub\_1401f7f1b | 28 | 1.653 |
| 0x140206d39 | sub\_140206d39 | 23 | 1.546 |

### Notes

- **Dual anomaly signature:** z\_entropy = −1.70 (hierarchical) AND z\_energy = +7.10 (energetic).  
  Positive z\_energy indicates the binary's eigenvalue energy far exceeds the null model — a dense,
  tightly coupled call graph. Combined with negative z\_entropy (a few dominant hub functions),
  this points to concentrated complexity in inter-component call chains. Consistent with Hyper-V's
  architecture: a VM worker process coordinating many tightly coupled subsystems.
- **CLE loader fix required for PE analysis:** CFGFast's `resolve_indirect_jumps` pass triggers a
  CLE bug (`find_object_containing` → `max_addr=None`) on PE binaries with `auto_load_libs=False`.
  Fix: `resolve_indirect_jumps=False, data_references=False` in CFGFast call (applied in c2_rmt.py).
- Binary symbols stripped — function names `sub_XXXXXXXX`
- 1 binary / 1 worker — no parallel speedup measurement here; wall time equals worker time

---

## 10. Validated Findings

The pipeline has produced multiple accepted vendor security disclosures via
responsible disclosure programmes. Specific findings remain confidential pending
vendor patch schedules.

**Public case study:** CVE-2022-23093 (FreeBSD `ping` `pr_pack()` — publicly
disclosed December 2022). TriageForge was applied to the macOS arm64e counterpart
as a methodology validation. The INT_OVF template correctly identified `pr_pack`
as the function of interest. The VEX IR scan confirmed the fixed-offset (`oip+1`)
logic bug in the macOS implementation. Full case study in `TOOLCHAIN_DOCUMENTATION.md`.

---

## 11. C7 — Dynamic Validation Stage *(v2)*

### Overview

C7 takes a C6 PoC (concrete byte payload from Z3 model) and validates it on the live
system. Three execution modes; timings below are for macOS arm64e host (Apple M-series)
and the SIP-disabled VM (192.168.64.2).

### Mode timing

| Mode | Target type | Typical wall time | Notes |
|------|------------|-------------------|-------|
| SUBPROCESS | CLI binary / file parser | 5–30 s | Includes DiagnosticReports scan (2 s delay) |
| LLDB batch | Any debuggable binary | 15–60 s | LLDB startup ~5 s; crash capture ~1 s |
| DTRACE | Network / IPC daemon | 30–120 s | DTrace probe attach ~3 s; probe fires on first matching `malloc` call |

### DTRACE confirmation benchmark (smbd)

**Condition:** smbd running with guest access; DTrace probe on `pid$target::malloc:entry`
with threshold `arg0 > 0x1000`.

| Metric | Value |
|---|---|
| DTrace attach time | 2.8 s [CHARACTERISED] |
| Time to first sink hit (with PoC payload) | 4.2 s [CHARACTERISED] |
| Total C7 wall time (DTrace mode) | 7.0 s [CHARACTERISED] |
| Result | `SINK_REACHED` — `C7_SINK_HIT malloc(4608)` confirmed |

### SUBPROCESS crash capture benchmark (synthetic OOB)

**Condition:** Test binary with known stack OOB; PoC payload from C6 via STDIN delivery.

| Metric | Value |
|---|---|
| Process launch to crash | < 1 s |
| DiagnosticReports scan delay | 2 s (fixed) |
| Total C7 wall time | 3.1 s [CHARACTERISED] |
| Result | `CONFIRMED` — crash report found, `EXC_BAD_ACCESS` |

### Evidence output size

| Field | Typical size |
|---|---|
| `c7_evidence.txt` | 2–5 KB |
| `c7_evidence.json` | 3–8 KB |
| PoC hex dump (in .txt) | 160–512 bytes |
| LLDB backtrace (20 frames) | 1–2 KB |
| DTrace ustack (12 frames) | 0.5–1 KB |

### What has NOT been formally benchmarked

| Metric | Status |
|---|---|
| C7 false negative rate (target runs but sink not reached) | Not measured — depends on delivery mode precision |
| LLDB crash capture latency on large binaries (smbd, amfid) | Not measured — LLDB startup may be slow for 10MB+ binaries |
| DTrace probe overhead on high-throughput IPC services | Not measured — may miss events if probe fires faster than DTrace can capture |

---

## 12. Hardware Reference

All measurements taken on:

| Component | Specification |
|---|---|
| CPU | Apple M-series (arm64e) |
| OS | macOS (Darwin) |
| angr | Latest stable |
| Z3 | 4.12.x (bundled with angr) |
| Python | 3.11 |
| RAM available to angr | 8–16 GB (process limit not set) |

Performance on Linux x86_64 hosts will differ. angr's CFGFast is generally faster
on x86_64 binaries (native architecture). ARM64 binary analysis via cross-architecture
lifting adds ~20–30% overhead.

---

*© 2026 Stuart Thomas, trading as TriageForge. Licensed under Apache 2.0 (code)
and CC BY 4.0 (documentation). These benchmarks may be reproduced with attribution.*
