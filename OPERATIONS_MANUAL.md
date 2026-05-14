# Metis — Installation, Operations & Maintenance Manual

Version 2.2 | 2026-04-23 | Stuart Thomas

© 2026 Stuart Thomas.  
**Documentation licence:** Creative Commons Attribution 4.0 International (CC BY 4.0)  
**Code licence:** MIT (Non-Commercial) / Paid (Commercial)

---

> **Legal Notice — Authorised Use Only**  
> This toolchain is intended exclusively for use on systems you own or have received
> explicit written authorisation to test. Unauthorised use of this software against
> systems you do not own or do not have permission to test may constitute a criminal
> offence under the Computer Misuse Act 1990 (England and Wales), the Computer Fraud
> and Abuse Act (United States), or equivalent legislation in other jurisdictions.
> The author accepts no liability for use of this software outside the scope of
> legitimate, authorised security research.

---

## Contents
1.  Introduction & System Overview
2.  Installation
3.  Quick Start (5-minute guide)
4.  Operations — C2 RMT Screen
5.  Operations — C3 Template Matching (v2: full SSA memory taint)
6.  Operations — C6 Taint Analysis
7.  Operations — C7 Dynamic Validation *(v2)*
8.  Operations — C1 Backbone Prioritisation
9.  Operations — Parallel Batch Screening *(v2)*
9a. Operations — Dell Batch Campaign & Per-Finding Orchestration *(v2)*
10. Interpreting Output
11. Output File Reference
12. API Reference
13. Maintenance
14. Troubleshooting
15. Appendix — Known Issues & Workarounds
16. FINDINGS_GUIDE.html — Architecture & Maintenance Guide

---

## 1. Introduction & System Overview

Metis is a static binary analysis pipeline for macOS (and optionally Windows) target binaries. It triages compiled binaries — without source code or debug symbols — and identifies functions most likely to harbour memory safety vulnerabilities: out-of-bounds writes, use-after-free conditions, integer overflows flowing to allocators, and type-confusion bugs.

The pipeline is composed of four operational stages (C1, C2, C3, C6) and two killed stages (C4, C5) that were retired after an LLM purple-team architecture review. The gap in numbering is preserved intentionally.

### Pipeline Summary

| Stage | Name | Purpose | Runtime |
|-------|------|---------|---------|
| C1 | Backbone Prioritisation | Phase-transition symbolic execution state ranking | Per-path: 32 ms avg |
| C2 | RMT Screen | Spectral anomaly detection on call graph | ~30 s per binary |
| C3 | Template Matching | Call dataflow pattern matching (6 templates, full SSA v2) | ~60 s on C2 top-N |
| C4 | TDA | **Killed** — persistent homology redundant with cyclomatic M | — |
| C5 | Compressed Sensing | **Killed** — RIP fails for binary coverage bitmaps | — |
| C6 | Taint Analysis | Symbolic taint + PoC input synthesis | Per-function: minutes |
| C7 | Dynamic Validation | On-device crash capture + ASB-ready evidence *(v2)* | 30–120 s |
| — | batch_screen.py | Parallel C2 sweep over binary directory *(v2)* | ~15 min / 300 bins |

### Operational Workflow

```
Binary target(s)
    │
    ├── Single binary:
    │       [C2] run_c2_screen.py      ← spectral triage, ~30s/binary
    │           │   c2_top_addrs.json
    │           ▼
    │       [C3] run_c3_screen.py      ← pattern match on C2 top-20 functions
    │           │   c3_hits.json
    │           ▼
    │       [C6] targeted symbolic exec ← per flagged function, manual invocation
    │           │   c6_alerts.json
    │           ▼
    │       [C7] c7_dynamic.py         ← on-device validation + ASB evidence
    │               c7_evidence.txt / .json
    │
    └── Multi-binary campaign:
            [batch_screen.py]           ← parallel C2 on directory, 8 workers
                batch_YYYYMMDD.json     ← sorted by |z_entropy|, top hits to C3/C6/C7
```

C1 is composed with C6 — it is an `ExplorationTechnique` used inside C6's symbolic execution loop, not a standalone runner.

### Package Structure

```
macos_vuln_toolchain/
├── metis/
│   ├── __init__.py
│   ├── exploration_technique.py   ← C1: HardnessExplorationTechnique
│   ├── semantic_backbone.py       ← backbone fraction via Z3 assumptions
│   ├── backbone_probe.py          ← legacy: pysat Glucose3 path
│   ├── dimacs_converter.py        ← claripy → DIMACS CNF
│   ├── c2_rmt.py                  ← C2: C2RMTAnalysis
│   ├── c3_templates.py            ← C3: C3TemplateAnalysis (v2: full SSA memory taint)
│   ├── c6_taint.py                ← C6: C6TaintTechnique / C6Analysis
│   ├── c7_dynamic.py              ← C7: C7Analysis / dynamic validation (v2)
│   ├── test_pipeline.py           ← unit tests (5/5 passing)
│   └── validate_c3.py / validate_c6.py
├── run_c2_screen.py               ← top-level C2 runner (single binary)
├── run_c3_screen.py               ← top-level C3 runner (reads c2_top_addrs.json)
├── batch_screen.py                ← parallel C2 batch runner (v2)
└── TOOLCHAIN_DOCUMENTATION.md
```

### Research Environment

The toolchain operates across three machines with distinct roles. **Do not cross role boundaries.**

| Machine | Host | User | Key | Role |
|---------|------|------|-----|------|
| **Local Mac** | localhost | stuart | — | Code, TriageForge dashboard, triage decisions, filing |
| **Dell** | 192.168.1.55 | stuart | `~/.ssh/id_ed25519_dell` | All batch sweeps, C2 RMT, angr symbolic execution |
| **macOS VM** | 192.168.64.2 | test | `~/.ssh/id_ed25519_vm` | C7 on-device PoC validation, DTrace, XPC fuzzing |

**Local Mac:**
- Base dir: `~/Documents/Work/darwin_security_research/`
- Toolchain source: `macos_vuln_toolchain/metis/`
- Dell findings cache: `dell_findings/` (rsync'd every 10 min)
- TriageForge dashboard: `triageforge_web/` — Flask on port 5001 (`triageforge` alias)
- XNU source: `xnu/` branch `rel/xnu-12377` (macOS 26 / Tahoe)
- **Does NOT run:** angr batch sweeps, DTrace, fuzzing campaigns, PoC execution

**Dell (`ssh dell`):**
- Home dir: `~/` — toolchain at `~/darwin_research/toolchain/metis/`
- venv: `~/.venv_angr/bin/python3`
- C2 output: `~/darwin_research/findings/<binary>_c2_results.txt`
- Batch logs: `~/darwin_research/batch_libexec.log`, `batch_sbin.log`
- tmux jobs: named `c2_<binary>` — check with `ssh dell tmux ls`
- Load threshold: launch new analysis only when load < 20
- **Does NOT run:** PoC execution, DTrace on macOS targets

**macOS VM:**
- SSH: `ssh -i ~/.ssh/id_ed25519_vm -o IdentitiesOnly=yes test@192.168.64.2`
- OS: macOS 26.4.1 ARM64 (Parallels) — SIP disabled, NOPASSWD sudo
- Research dir: `~/darwin_research/` — toolchain, findings, DTrace logs
- Crash reports: `~/Library/Logs/DiagnosticReports/`
- **SSH note:** Use `IdentitiesOnly=yes` — too many keys causes MaxAuthTries exhaustion. Serialize SSH calls (3–5 s gaps).
- **Does NOT run:** batch sweeps, C2 screens (those are Dell's job)

---

## 2. Installation

### Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| macOS | 12+ | Primary platform; arm64e or x86_64 |
| Python | 3.11 or 3.13 | **Avoid 3.12** — angr has known compatibility issues |
| angr | >= 9.2 | Pulls in pyvex, claripy, cle, archinfo, networkx |
| numpy | any recent | Spectral computation |
| scipy | any recent | Eigenvalue solver |
| z3-solver | any recent | Backbone probing via Z3 assumptions |
| reportlab | optional | PDF generation only |
| matplotlib | optional | PDF figure generation only |
| pillow | optional | PDF image embedding only |

> **Warning:** Do not use Python 3.12. angr has known compatibility issues with Python 3.12 that cause import failures and runtime errors. Use Python 3.11 or Python 3.13.

### Virtual Environment Setup

```bash
python3.11 -m venv /tmp/angr_venv
source /tmp/angr_venv/bin/activate
pip install angr numpy scipy z3-solver

# Verify installation:
python3 -c "import angr; print(angr.__version__)"
python3 -c "import angr, archinfo, claripy, numpy, scipy, z3; print('all imports OK')"
```

For PDF generation (optional):

```bash
pip install reportlab matplotlib pillow
```

> **Warning:** Do not install the `pysat` package unless you intend to use the legacy `backbone_probe.py` path. The current production path uses Z3 via `semantic_backbone.py`. The pysat Glucose3 solver is retained as a fallback only.

### Verifying the Install

```bash
cd /path/to/metis_repository
python3 -m pytest metis/test_pipeline.py -v
```

Expected output: `5 passed` — no failures, no errors.

---

## 3. Quick Start (5-minute guide)

> **Note:** This guide assumes you have a target binary at `/usr/libexec/targetd` and the venv activated at `/tmp/angr_venv`. Adjust paths as needed.

**Step 1 — Activate the venv:**

```bash
source /tmp/angr_venv/bin/activate
cd /path/to/metis_repository
```

**Step 2 — Run the C2 screen:**

```bash
python3 run_c2_screen.py
```

This produces `c2_results.txt` (human-readable report) and `c2_top_addrs.json` (machine-readable top function addresses with scores).

**Step 3 — Run the C3 template scan on the C2 results:**

```bash
python3 run_c3_screen.py --top 20
```

This reads `c2_top_addrs.json` and scans the top 20 functions for the six vulnerability templates. Produces `c3_results.txt` and `c3_hits.json`.

**Step 4 — Inspect the results:**

```bash
cat c2_results.txt       # anomaly verdict + top-ranked functions
cat c3_results.txt       # template matches with confidence scores
cat c3_hits.json         # machine-readable hits for downstream scripting
```

**Step 5 — Targeted symbolic execution for flagged functions:**

C6 is invoked per-function. Build a minimal driver (see §6) targeting the addresses in `c3_hits.json`.

**Step 6 — Dynamic validation (v2):**

```python
from metis.c7_dynamic import C7Analysis, extract_poc_from_c6, C7DeliveryMode

poc      = extract_poc_from_c6(c6_finding, proj=proj)
evidence = C7Analysis(binary='/usr/libexec/targetd').validate(
               poc, mode=C7DeliveryMode.DTRACE, timeout_s=60)
evidence.write('/tmp/c7_evidence')   # writes .txt and .json
print(evidence.asb_text)             # paste into Apple ASB submission
```

**Step 7 — Multi-binary campaign (v2):**

```bash
# Screen an entire directory overnight:
python3 batch_screen.py /usr/libexec/ --workers 8
# Output: ~/triageforge/results/batch_YYYYMMDD_HHMMSS.json
```

---

## 4. Operations — C2 RMT Screen

### What C2 Does

C2 constructs the call graph of a Mach-O binary, computes three spectral statistics (spectral radius, graph energy, eigenvalue entropy), and compares them against a null distribution derived from 50 configuration-model replicates. Functions are then ranked by a combined score weighting eigenvector centrality, cyclomatic complexity, and back-edge count.

A binary is flagged **ANOMALOUS** if the absolute z-score on any of the three spectral statistics exceeds 2.0.

### Running C2

**From the command line (using `run_c2_screen.py`):**

```bash
python3 run_c2_screen.py
```

Edit the `TARGETS` list at the top of `run_c2_screen.py` to specify which binaries to screen.

**Programmatic usage from an existing project:**

```python
from metis.c2_rmt import C2RMTAnalysis
import archinfo, angr

# From a path (C2 loads the binary internally):
result = C2RMTAnalysis('/usr/libexec/targetd').run()
result.print_report()

# From an existing angr project (avoids double-loading the binary):
proj = angr.Project(
    '/usr/libexec/targetd',
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')}
)
result = C2RMTAnalysis.from_project(proj).run()
```

### C2 Result Object

| Attribute | Type | Description |
|-----------|------|-------------|
| `result.functions_ranked` | list of (addr, score) | Top functions sorted by combined score, descending |
| `result.anomalous` | bool | True if any |z| > 2.0 |
| `result.z_radius` | float | Z-score for spectral radius |
| `result.z_energy` | float | Z-score for graph energy |
| `result.z_entropy` | float | Z-score for eigenvalue entropy |

```python
# Print top 20 functions:
for addr, score in result.functions_ranked[:20]:
    print(f'  0x{addr:x}  score={score:.3f}')

# Check anomaly:
if result.anomalous:
    print(f'ANOMALOUS — z_radius={result.z_radius:.2f}, '
          f'z_energy={result.z_energy:.2f}, '
          f'z_entropy={result.z_entropy:.2f}')
```

### C2 Scoring Formula

The combined function score is:

```
S = 0.4 * ev + 0.35 * log(1 + M) + 0.25 * log(1 + B)
```

Where:
- `ev` = eigenvector centrality (0–1)
- `M` = McCabe cyclomatic complexity = E − N + 2
- `B` = back-edge count (contributes to loop depth)

### Anomaly Thresholds

| Condition | Verdict |
|-----------|---------|
| All |z| ≤ 2.0 | NORMAL |
| Any |z| > 2.0 | ANOMALOUS |
| N < 100 nodes | Low-confidence (flagged in report) |

Null distribution: 50 configuration-model replicates matching the observed in/out degree sequence. The configuration model (Bollobás 1980, directed variant) is correct for call graphs — Marchenko-Pastur and Wigner semicircle law assume i.i.d. entries and are wrong for power-law degree distributions.

### FastC2 — Size-Unlimited Engine (L1 fix, 2026-04-18)

`metis/fast_c2.py` replaces angr CFGFast with lief+capstone for call graph construction on large binaries. The `analyse_binary()` factory function in `c2_rmt.py` selects the engine automatically:

| Binary size | Engine selected | Memory | Speed |
|-------------|----------------|--------|-------|
| ≤ 3.5 MB | Full (angr CFGFast) | ~2–4 GB | 30–120 s |
| > 3.5 MB | FastC2 (lief+capstone) | ~300 MB | 5–30 s |

**FastC2 capabilities:**

| Metric | FastC2 | Full C2 |
|--------|--------|---------|
| Binary-level z-scores | ⚠️ See below | ✅ Full RMT |
| Function ranking (combined score) | ✅ Works | ✅ Works |
| Cyclomatic complexity | ✅ (approximated: 1 + n_cond_branches) | ✅ (exact E−N+2) |
| Back-edge count | ✅ (backward branch heuristic) | ✅ (DFS-exact) |
| ObjC dispatch edges | ❌ BLR not resolved | ❌ Not resolved |
| Call graph edge resolution | ✅ BL direct calls only | ✅ BL + CFGFast heuristics |

**Binary-level z-score reliability:**

FastC2 produces meaningful z-scores ONLY when the call graph has sufficient BL (direct call) edges. Two classes of binaries give z=0.0 (flagged `reliable=False`):

1. **ObjC/Swift-heavy daemons** (storagekitd, CoreData-based services): All cross-function calls use `blraa`/`blr` (indirect pointer-auth dispatch). The BL-only call graph has 0 edges → null model is degenerate → z=0.
2. **Binaries with indirect-only call profiles**: If all real function calls go through vtable dispatch or ObjC msgSend with no direct `bl` edges between func_set members.

**For these binaries, FastC2 is still useful as a FUNCTION RANKER:** `functions_ranked` uses cyclomatic complexity (accurate from conditional-branch counting) and back-edge count, giving valid C3 target addresses even when z-scores are degenerate.

**When to trust the FastC2 z-score:**
- `result.binary_score.reliable == True` → edges detected, null model ran, z-scores are valid
- `result.binary_score.reliable == False` → z=0.0 sentinel; use `functions_ranked` only

**Usage:**

```python
from metis.c2_rmt import analyse_binary

r = analyse_binary('/usr/libexec/targetd')
print(f'engine: {r.engine}  reliable: {r.binary_score.reliable}')
if r.binary_score.reliable:
    print(f'z_radius={r.binary_score.z_radius:.2f}  anomalous={r.binary_score.flagged}')
# Always valid:
for f in r.functions_ranked[:10]:
    print(f'  {hex(f.addr)}  cyc={f.cyclomatic}  be={f.back_edges}')
```

---

## 5. Operations — C3 Template Matching

### What C3 Does

C3 scans the CFG of a binary looking for source-to-sink call chains that match known vulnerability patterns. Each template specifies:
- A set of **source** functions (attacker-controlled input entry points)
- A set of **sink** functions (dangerous operations)
- A set of **barrier** functions that, if present on the path, clear the match
- A confidence weight

A match fires when a path from a source to a sink exists in the call graph with no intervening barrier function.

### Six C3 Templates

| Template | Source | Sink | Barrier | Confidence |
|----------|--------|------|---------|------------|
| `MACH_OOB` | mach_msg receive buffer field | malloc, calloc size argument | bounds check / compare | 0.82 |
| `XPC_TYPE` | xpc_dictionary_get_value | typed XPC accessor (without xpc_get_type) | xpc_get_type, type assert | 0.65 |
| `INT_OVF` | XPC / mach value | arithmetic → allocator | bounds check, saturation | 0.79 |
| `PORT_UAF` | mach_port_deallocate | mach port operation on same name | port name epoch check | 0.71 |
| `IOKIT_OOB` | IOConnectCallMethod out-of-band data | memory copy / alloc | bounds check | 0.88 |
| `ICMP_IHL_SKIP` | recvmsg / recvfrom / pr_pack / icmp_input | printf / memcmp / memcpy | ip_hl / ntohs / ntohl | 0.60 |

### Running C3

**From the command line:**

```bash
# Full binary scan:
python3 run_c3_screen.py

# Limited to top-N C2 results:
python3 run_c3_screen.py --top 20
```

`run_c3_screen.py` reads `c2_top_addrs.json` automatically.

**Programmatic usage:**

```python
from metis.c3_templates import C3TemplateAnalysis
import archinfo, angr

proj = angr.Project(
    '/usr/libexec/targetd',
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')}
)

c3 = C3TemplateAnalysis(proj)

# Whole binary:
results = c3.run()

# Targeted on C2 top function addresses (list of ints):
top_addrs = [0x10001234, 0x10002abc, 0x10003def]
results = c3.analyse_functions(top_addrs)

# Inspect results:
for r in results:
    print(f'  {r.template_name}  conf={r.confidence:.2f}  '
          f'source={r.source_fn}  sink={r.sink_fn}  '
          f'barrier_present={r.barrier_present}')
```

### Adding a New C3 Template

Open `metis/c3_templates.py` and append a new entry to the `TEMPLATE_BANK` list:

```python
TEMPLATE_BANK.append(VulnTemplate(
    name        = 'MY_TEMPLATE',
    sources     = ['xpc_dictionary_get_int64', 'xpc_dictionary_get_uint64'],
    sinks       = ['memcpy', 'bcopy'],
    barriers    = ['my_bounds_check', 'assert'],
    confidence  = 0.75,
    vuln_class  = 'OOB_WRITE',
))
```

Fields:
- `sources` — list of function names that introduce attacker data
- `sinks` — list of function names that are dangerous if reached with tainted data
- `barriers` — list of function names that constitute a mitigating check; a path with any barrier is NOT flagged
- `confidence` — float 0–1 representing expected precision
- `vuln_class` — string label for the output JSON

> **Warning:** Do not add stdlib functions (memset, bzero, strncpy) as sources. C3 applies a stdlib caller filter; if the path passes only through CRT routines it will be suppressed.

---

## 6. Operations — C6 Taint Analysis

### What C6 Does

C6 is a symbolic taint analysis engine built on angr's `ExplorationTechnique` mechanism. It hooks 18 system functions with `SimProcedure` stubs that mark their return values or output buffers as symbolic bitvectors with labelled taint names. As angr explores paths, claripy's AST tracks those bitvectors through arithmetic operations. When a path reaches a dangerous operation with a tainted operand — and the constraint system is satisfiable — C6 emits an alert with the taint label, the constraint path, and a solved PoC input.

### Hook Table (18 hooks)

| Category | Hooks |
|----------|-------|
| Allocation | malloc, calloc, realloc, valloc, mmap |
| Network / IPC receive | recv, recvfrom, read, mach_msg_recv |
| XPC | xpc_dictionary_get_value, xpc_array_get_value, xpc_copy |
| IOKit | IOKit_copyScalar_64, IOKit_copyScalar_32, OSObject_getRef, io_connect_method |
| Dealloc tracking | free, mach_port_deallocate |

### Running C6

C6 is used programmatically — there is no standalone runner script. Build a minimal driver for each target function:

```python
from metis.c6_taint import C6TaintTechnique
from metis.exploration_technique import HardnessExplorationTechnique
import archinfo, angr

proj = angr.Project(
    '/usr/libexec/targetd',
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')}
)

# Entry state at the flagged function address:
state = proj.factory.call_state(0x10001234)

simgr = proj.factory.simgr(state)

# Attach C6 taint technique:
simgr.use_technique(C6TaintTechnique())

# Optionally compose with C1 backbone prioritisation:
simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))

simgr.run()

# Collect findings:
findings = simgr.one_deadended.globals.get('c6_findings', [])
for f in findings:
    print(f'  vuln_class={f["vuln_class"]}  taint={f["taint_label"]}')
    print(f'  constraint={f["constraint"]}')
    print(f'  poc_input={f["poc_input"]}')
```

### Adding a New C6 Hook

Open `metis/c6_taint.py` and add a new `SimProcedure` class, then register it in `_HOOK_TABLE`:

```python
class Hook_my_source(angr.SimProcedure):
    def run(self, arg0, arg1):
        # Mark the return value as a tainted symbolic bitvector:
        tainted = self.state.solver.BVS('my_source_ret', 64)
        # Store taint label for downstream alert generation:
        self.state.globals.setdefault('taint_labels', {})[tainted.args[0]] = 'MY_SOURCE'
        return tainted

# Register in the hook table at the bottom of the file:
_HOOK_TABLE['my_source_function'] = Hook_my_source
```

The `run()` method receives angr SimValue arguments corresponding to the function's calling convention parameters. Return a labelled BVS to propagate taint. For buffer-tainting hooks (like recv), iterate over `state.memory.store()` for each byte index with individual BVS values.

> **Warning:** C6 is designed for targeted use on functions already flagged by C3. Running C6 on a full binary without a targeted entry point will cause state explosion. Always scope C6 to a specific function address from `c3_hits.json`.

---

## 7. Operations — C7 Dynamic Validation *(v2)*

### What C7 Does

C7 takes a C6 finding (a symbolic PoC and a flagged function address) and validates it
on the live system. It extracts a concrete payload from the C6 angr state, delivers it
to the target process, and captures on-device evidence: a crash report, LLDB backtrace,
or DTrace sink-hit confirmation. The output is ASB-ready evidence suitable for pasting
directly into a vendor submission.

### Prerequisites

| Mode | Requirement |
|------|------------|
| SUBPROCESS | No special privileges; target must accept stdin/file input |
| LLDB | debuggable target (SIP disabled, `get-task-allow`, or use macOS VM) |
| DTRACE | SIP disabled or `com.apple.private.dtrace.allow-attach` entitlement |

For the macOS VM (SIP disabled, 192.168.64.2): all modes available. Use DTRACE for
production systems; LLDB for the VM.

### Running C7 Programmatically

```python
from metis.c7_dynamic import (
    C7Analysis, C7PoC, C7DeliveryMode, extract_poc_from_c6
)

# 1. Extract PoC from a C6 finding (angr SimState):
poc = extract_poc_from_c6(c6_finding, proj=proj)
# poc.payload: bytes
# poc.delivery: C7DeliveryMode (inferred from template: STDIN, FILE, MACH_MSG, etc.)

# 2. Validate:
c7 = C7Analysis(binary='/usr/sbin/smbd')

# DTrace mode (non-destructive, preferred for production):
evidence = c7.validate(poc, mode=C7DeliveryMode.DTRACE, timeout_s=60)

# LLDB mode (crash capture, use on VM):
evidence = c7.validate(poc, mode=C7DeliveryMode.LLDB, timeout_s=120)

# SUBPROCESS mode (exit code + crash report scan):
evidence = c7.validate(poc, mode=C7DeliveryMode.SUBPROCESS, timeout_s=30)

# 3. Write evidence files:
evidence.write('/tmp/c7_evidence')
# Writes: /tmp/c7_evidence.txt  (human-readable ASB block)
#         /tmp/c7_evidence.json (machine-readable companion)

# 4. ASB-ready text:
print(evidence.asb_text)
```

### Manual Mach Message Delivery

For Mach IPC targets that cannot be driven via stdin, C7 generates a ready-to-run
ctypes sender script:

```python
poc = C7PoC(payload=c6_payload, delivery=C7DeliveryMode.MACH_MSG,
            label='mach_msg_rcv_buf', target_service='com.apple.smbd')
c7.validate(poc, mode=C7DeliveryMode.SUBPROCESS)
# → writes /tmp/c7_mach_sender_XXXXXX.py
# Run: python3 /tmp/c7_mach_sender_XXXXXX.py
```

The generated script uses `bootstrap_look_up` to resolve the Mach port name, then
sends the PoC bytes as a Mach message body via `mach_msg`.

### C7 Result Codes

| Code | Meaning |
|------|---------|
| `CONFIRMED` | Crash report found; binary faulted on PoC input |
| `SINK_REACHED` | DTrace `C7_SINK_HIT` marker seen; sink confirmed reachable |
| `TIMEOUT` | Process did not crash or confirm within timeout |
| `NO_IMPACT` | Clean exit; PoC did not trigger the expected path |
| `ERROR` | Subprocess / LLDB / DTrace failed to launch |
| `MANUAL` | Evidence saved; manual delivery required |

### Interpreting C7 Output for ASB Submissions

A `CONFIRMED` or `SINK_REACHED` result with a function address matching the C3/C6
target is sufficient for an Apple ASB submission under **Userland → Daemons and
Frameworks**. Include:
1. `c7_evidence.txt` — paste verbatim into the submission description
2. `c3_hits.json` — attach as supporting material
3. The generated Mach sender script (if applicable)

Do not submit a `TIMEOUT` or `NO_IMPACT` result without further investigation — the
PoC may need delivery mode adjustment or the target may require specific preconditions
(e.g., an active client connection, a specific share mounted).

---

## 8. Operations — C1 Backbone Prioritisation

### What C1 Does

C1 is an `angr.ExplorationTechnique` that ranks active simulation states by their backbone fraction — the proportion of symbolic variable bits that are forced to a single value by the current path constraints. States with high backbone fraction are near the satisfiability phase transition and will be slow for the Z3 solver. C1 defers those states to a `hardness_deferred` stash and explores easier states first.

### C1 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `threshold` | float | 0.8 | Backbone fraction cutoff (fixed mode) or adaptive percentile target |
| `deferred_stash` | str | `'hardness_deferred'` | Name of the stash for deferred states |
| `probe_timeout_s` | float | 0.05 | Z3 timeout per state probe (50 ms) |
| `score_interval` | int | 1 | Score every N exploration steps |
| `min_constraints` | int | 3 | Skip scoring states with fewer constraints |
| `max_score_per_step` | int | 16 | Cap number of states scored per step |
| `adaptive_threshold` | bool | True | Defer top 20% hardest rather than fixed cutoff |
| `log_file` | str or None | None | CSV log path for per-state backbone scores |

### Using C1 Standalone

```python
from metis.exploration_technique import HardnessExplorationTechnique
import archinfo, angr

proj = angr.Project(
    '/path/to/binary',
    auto_load_libs=False,
    main_opts={'arch': archinfo.arch_from_id('aarch64')}
)

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

simgr.use_technique(HardnessExplorationTechnique(
    threshold=0.8,
    adaptive_threshold=True,
    probe_timeout_s=0.05,
    log_file='/tmp/hardness_log.csv',
))

simgr.run(n=1000)

# Inspect deferred states:
print(f'Active: {len(simgr.active)}, Deferred: {len(simgr.hardness_deferred)}')
```

### Composing C1 with C6

When composing, add both techniques to the same simulation manager. Order matters: add C6 first so its hooks are registered before C1 begins ranking states.

```python
simgr.use_technique(C6TaintTechnique())
simgr.use_technique(HardnessExplorationTechnique(threshold=0.8))
simgr.run()
```

### Measured Performance

| Metric | Value |
|--------|-------|
| Backbone probing time (avg) | 32 ms per state |
| State reduction | 60% fewer states explored before finding solution path |
| Test suite | 5/5 tests passing |
| Spearman ρ (backbone vs CDCL hardness) | +0.43, p = 0.012 |

---

## 9. Operations — Parallel Batch Screening *(v2)*

### What batch_screen.py Does

`batch_screen.py` runs C2 (`C2RMTAnalysis`) on every binary in a directory using
`multiprocessing.Pool`. Each binary is analysed in an independent subprocess — no
shared state between workers. Results are streamed live to stdout and written to a
timestamped JSON file on completion.

### Usage

```bash
# Screen all binaries in a directory (auto-detects workers = min(cpu_count, 8)):
python3 batch_screen.py /usr/libexec/

# Specify worker count:
python3 batch_screen.py /usr/libexec/ --workers 4

# Filter by extension (PE binaries only):
python3 batch_screen.py /path/to/pe_binaries/ --extensions .exe .dll

# Custom output directory:
python3 batch_screen.py /usr/libexec/ --output ~/triageforge/results/
```

### Performance

| Platform | Workers | Binaries | Wall time |
|----------|---------|----------|-----------|
| Dell i7-4th gen, 32 GB, Debian x86_64 | 8 | 6 Linux ELF | 43.6 min (limited by `git`) |
| Apple M-series (estimated) | 8 | 300 macOS daemons | ~15 min |
| GCP e2-standard-4 (4 vCPU) | 4 | 300 macOS daemons | ~45 min |

Sequential equivalent of the 6-binary Linux run: ~161 minutes. Achieved wall time:
43.6 minutes. Speedup: **3.7×** (limited by the largest binary; balanced loads approach 8×).

### Worker memory cap

Each angr worker uses 2–4 GB RAM during `CFGFast`. With 8 workers, peak RAM usage
is 16–32 GB. Cap workers at `min(cpu_count, floor(available_ram_GB / 4))` on
memory-constrained hosts:

```bash
# On a 16 GB host: max 4 workers
python3 batch_screen.py /usr/libexec/ --workers 4
```

### Output JSON schema

```json
{
  "timestamp": "20260417_195000",
  "binary_dir": "/usr/libexec",
  "n_binaries": 48,
  "n_workers": 8,
  "total_elapsed_s": 187.3,
  "results": [
    {
      "binary": "/usr/libexec/smbd",
      "name": "smbd",
      "status": "ok",
      "verdict": "ANOMALOUS",
      "n_functions": 11264,
      "z_radius": -3.56,
      "z_energy": -3.01,
      "z_entropy": -0.30,
      "top_functions": [
        {"addr": "0x100051e74", "name": "sub_100051e74",
         "combined": 2.04, "cyclomatic": 66, "back_edges": 9}
      ],
      "elapsed_s": 127.4
    }
  ]
}
```

Results are sorted by `|z_entropy|` descending — highest anomaly first.

### Triage workflow after batch run

```bash
# Read batch JSON and extract top-5 anomalous binaries:
python3 -c "
import json, sys
data = json.load(open('batch_20260417_195000.json'))
anomalous = [r for r in data['results'] if r['verdict'] == 'ANOMALOUS']
for r in anomalous[:5]:
    print(r['name'], r['z_entropy'], r['top_functions'][0]['addr'])
"

# Run C3 on the top anomalous binary using its saved top addresses:
# (Extract addresses from batch JSON, then run_c3_screen.py)
```

---

## 9a. Operations — Dell Batch Campaign & Per-Finding Orchestration *(v2)*

This section documents the real-world operational scripts that have evolved beyond the
generic `batch_screen.py` — specifically `dell_batch_screen.py` (the production Dell
runner) and the per-finding orchestration pattern used to capture PoC evidence for ASB
submissions.

### dell_batch_screen.py — Production Dell Runner

`dell_batch_screen.py` is a Dell-specific superset of `batch_screen.py` with
persistence, labelling, and live logging designed for overnight multi-binary campaigns
on a remote machine.

**Key differences from batch_screen.py:**

| Feature | `batch_screen.py` | `dell_batch_screen.py` |
|---------|-------------------|------------------------|
| Resume on restart | No | Yes — `--resume` skips done binaries |
| Output label | None | `--label sbin` / `--label libexec` |
| Output directory | cwd | `--outdir ~/darwin_research/findings/` |
| Done tracking | JSON only | `<label>_done.txt` (one path per line) |
| Live log | stdout | `dell_batch_<label>.log` |
| Anomaly summary | Batch JSON | `new_anomaly_c2.json` (continuously appended) |
| Memory guard | `--workers` flag | Same — cap at `floor(RAM_GB / 4)` |

**Typical invocation (on Dell):**

```bash
# Run from ~/darwin_research/toolchain/
python3 dell_batch_screen.py \
    --target ~/darwin_research/binaries/sbin \
    --label sbin \
    --resume \
    --outdir ~/darwin_research/findings/
```

**Output files produced (in `--outdir`):**

| File | Contents |
|------|----------|
| `dell_batch_<label>.log` | Live per-binary status: `[N/M] name z=(z_r,z_e,z_ent) *** ANOMALOUS` |
| `dell_batch_<label>_done.txt` | One binary path per line — used by `--resume` to skip |
| `new_batch_c2.json` | Dict keyed by binary name: `{flagged, z_radius, z_energy, z_entropy, top_funcs[]}` |
| `new_anomaly_c2.json` | Subset of above: ANOMALOUS-only entries, appended per run |

**Monitoring a running campaign:**

```bash
# Check progress
ssh dell "tail -5 ~/darwin_research/findings/dell_batch_sbin.log"

# Count done vs total
ssh dell "wc -l ~/darwin_research/findings/dell_batch_sbin_done.txt"

# Show all ANOMALOUS flags so far
ssh dell "grep ANOMALOUS ~/darwin_research/findings/dell_batch_sbin.log"

# Check worker PIDs and CPU load
ssh dell "ps aux | grep dell_batch | grep -v grep"
```

**Memory starvation — new angr job hangs in D-state:**

When batch workers are running, launching an additional angr process (C2 or C3) often
results in the new process entering Linux D-state (uninterruptible I/O wait) as the
kernel tries to allocate pages against swap pressure. Symptoms: process shows `D` in
`ps` output; its log file remains empty indefinitely.

Fix options (in order of preference):
1. Wait — the new process will start when a batch worker exits and frees RAM.
2. Kill one batch worker: `kill <pid>` — the `--resume` flag means the campaign
   continues correctly from where it left off on the next run.
3. Reduce worker count: send SIGTERM to all workers, restart with `--workers N-2`.

Do not kill the new job — killing it loses the analysis. Kill a batch worker instead.

---

### Per-Finding Orchestration Pattern

Each finding that reaches the dynamic evidence stage (C7) gets its own directory and a
pair of orchestration scripts. The canonical pattern is:

```
<finding>_audit/
├── FINDINGS.md              ← full research document
├── run_poc_evidence.py      ← orchestrator: deploys + fires PoC, captures terminal
└── vm_responder.py          ← VM-side payload injector (for network findings)
```

**`run_poc_evidence.py` responsibilities:**

1. Checks system context (`id`, `sw_vers`, `uname`, `ls -la <binary>`)
2. Snapshots existing crash reports in `~/Library/Logs/DiagnosticReports/`
3. Deploys `vm_responder.py` to the VM via SCP
4. Launches the target process (ping, daemon probe, etc.) as a background subprocess
5. Fires the VM-side injector via SSH + `sudo python3`
6. Waits for injector output (with `communicate(timeout=N)`)
7. Waits for target process to exit
8. Diffs crash reports: `crash_after - crash_before`
9. Writes verdict (`NO CRASH CONFIRMED` / `CRASH DETECTED`) to `poc_evidence.txt`

**`vm_responder.py` responsibilities:**

- Receives `<ping_pid> <mac_ip> <n_pkts>` as CLI arguments (no sniffing needed)
- Detects its own interface IP via routing: `_s.connect((mac_ip, 80)); vm_ip = _s.getsockname()[0]`
- Builds and sends crafted network packets via raw socket **without** `IP_HDRINCL`
  (kernel supplies the outer IP header; `IP_HDRINCL=1` causes EINVAL after the first
  packet even when the source address is local — see §14 and Appendix Issue 9)
- Runs `time.sleep(1.0)` between packets to interleave with the target process

**Running the orchestrator (no local root required):**

```bash
# From the finding directory on the local Mac:
python3 run_poc_evidence.py
# → poc_evidence.txt  (paste into FINDINGS.md items 9+10)
```

Local root is not required because all raw socket work is delegated to the VM.
The VM needs passwordless sudo (confirmed via `ssh dell "sudo -n echo ok"`).

**SSH + sudo non-interactive pattern:**

```python
ssh_cmd = [
    "ssh", "-i", VM_KEY, "-o", "StrictHostKeyChecking=no",
    f"{VM_USER}@{VM_IP}",
    f"sudo python3 {VM_SCRIPT} {arg1} {arg2} {arg3}",
]
vm_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
vm_stdout, vm_stderr = vm_proc.communicate(timeout=N_PKTS * 2 + 5)
```

This works because the VM is configured with `NOPASSWD` sudo for the `test` user.
If the VM requires a password, the SSH process will hang until `communicate()` times
out. Fix: `echo 'test ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/test-nopasswd`.

---

## 10. Interpreting Output

### C2 Anomaly Verdicts

A C2 ANOMALOUS verdict means the call graph structure deviates significantly from what would be expected from a random graph with the same degree sequence. This is a triage signal, not a confirmation of vulnerability.

Anomaly interpretation:

| Pattern | Likely meaning |
|---------|----------------|
| z_energy strongly negative | Massively structured internal complexity — many high-M functions |
| z_radius strongly positive | Unusually strong cyclic structure — persistent loops |
| z_entropy strongly positive | Noise-dominated spectrum — may be Swift/ObjC vtable noise (false positive) |
| z_entropy strongly negative | Rigid hierarchy — monolithic processing without abstraction |

Reference values from the audit corpus:

| Binary | z_radius | z_energy | z_entropy | Verdict |
|--------|----------|----------|-----------|---------|
| smbd | −3.56 | −3.01 | −0.30 | ANOMALOUS |
| opendirectoryd | −2.50 | −1.88 | −1.10 | ANOMALOUS |
| mDNSResponder | −1.85 | −22.33 | −142.37 | ANOMALOUS |
| amfid | −0.10 | −0.08 | −0.05 | NORMAL |

> **Warning:** z-score results are flagged as low-confidence when the call graph has fewer than 100 nodes. For small binaries, use the function-level metrics (cyclomatic M, back-edge count, eigenvector centrality) directly rather than the binary-level anomaly verdict.

### C3 Confidence Scores

| Confidence | Interpretation |
|------------|---------------|
| ≥ 0.85 | High confidence — source-to-sink path very likely unmitigated |
| 0.70–0.84 | Medium confidence — worth manual review |
| < 0.70 | Low confidence — barrier may exist; verify call chain manually |

A C3 match with `barrier_present=True` is not a vulnerability finding — it means a barrier function was found on the path. Record it and move on.

### C6 Alerts

Each C6 alert contains:
- `vuln_class` — one of: `OOB_WRITE`, `OOB_READ`, `UAF`, `INT_OVF`, `TYPE_CONFUSION`
- `taint_label` — which hook introduced the taint (e.g., `recv_buf_3`, `xpc_dict_val`)
- `constraint` — the SMT constraint path that led to the vulnerable state
- `poc_input` — a concrete byte sequence that satisfies the constraint (Z3-solved)

A C6 alert with a valid `poc_input` is the strongest finding the toolchain produces. It means symbolic execution reached a dangerous operation with a concretely satisfiable attacker input. This should be manually verified with a live PoC before filing.

---

## 11. Output File Reference

| File | Format | Contents |
|------|--------|---------|
| `c2_results.txt` | Plain text | Human-readable C2 report: anomaly verdict, z-scores, top-20 functions with scores |
| `c2_top_addrs.json` | JSON | `{binary_label: [{addr, score, cyclomatic, back_edges, name}]}` |
| `c3_results.txt` | Plain text | Human-readable C3 report: template hits with confidence and function names |
| `c3_hits.json` | JSON | `{binary_label: [{addr, template, confidence, source_fn, sink_fn}]}` |
| `c6_alerts.json` | JSON | `[{addr, vuln_class, taint_label, constraint, poc_input}]` |
| `c7_evidence.txt` | Plain text | ASB-ready evidence block: platform, payload hex, result, crash/DTrace output *(v2)* |
| `c7_evidence.json` | JSON | Machine-readable companion to `c7_evidence.txt` *(v2)* |
| `batch_YYYYMMDD_HHMMSS.json` | JSON | Batch C2 run: all binaries sorted by `\|z_entropy\|` *(v2)* |
| `hardness_log.csv` | CSV | Per-state backbone scores (only if `log_file` set in C1 parameters) |

### c2_top_addrs.json Schema

```json
{
  "targetd": [
    {
      "addr": 4295012928,
      "score": 2.341,
      "cyclomatic": 155,
      "back_edges": 12,
      "name": "sub_100012340"
    }
  ]
}
```

### c3_hits.json Schema

```json
{
  "targetd": [
    {
      "addr": 4295012928,
      "template": "MACH_OOB",
      "confidence": 0.82,
      "source_fn": "mach_msg",
      "sink_fn": "malloc"
    }
  ]
}
```

### c6_alerts.json Schema

```json
[
  {
    "addr": 4295012928,
    "vuln_class": "OOB_WRITE",
    "taint_label": "recv_buf_3",
    "constraint": "BVS(recv_buf_3)[0:15] > malloc_size_BVS",
    "poc_input": "ff 03 00 00 00 00 00 00"
  }
]
```

---

## 12. API Reference

### C1 — HardnessExplorationTechnique

```
metis.exploration_technique.HardnessExplorationTechnique

Constructor:
    HardnessExplorationTechnique(
        threshold=0.8,
        deferred_stash='hardness_deferred',
        probe_timeout_s=0.05,
        score_interval=1,
        min_constraints=3,
        max_score_per_step=16,
        adaptive_threshold=True,
        log_file=None,
    )

Methods:
    setup(simgr)          → called by angr on attachment
    step(simgr, **kwargs) → scores and defers states each exploration step
```

### C2 — C2RMTAnalysis

```
metis.c2_rmt.C2RMTAnalysis

Constructor:
    C2RMTAnalysis(binary_path: str)

Class method:
    C2RMTAnalysis.from_project(proj: angr.Project) → C2RMTAnalysis

Methods:
    run() → C2Result

C2Result attributes:
    .functions_ranked   list[(int, float)]  — (addr, score) sorted descending
    .anomalous          bool
    .z_radius           float
    .z_energy           float
    .z_entropy          float
    .print_report()     → prints human-readable report to stdout
```

### C3 — C3TemplateAnalysis

```
metis.c3_templates.C3TemplateAnalysis

Constructor:
    C3TemplateAnalysis(proj: angr.Project)

Methods:
    run() → list[C3Match]
    analyse_functions(addrs: list[int]) → list[C3Match]

C3Match attributes:
    .template_name      str
    .confidence         float
    .source_fn          str
    .sink_fn            str
    .barrier_present    bool
    .addr               int
```

### C6 — C6TaintTechnique

```
metis.c6_taint.C6TaintTechnique

Constructor:
    C6TaintTechnique()

Usage:
    simgr.use_technique(C6TaintTechnique())
    simgr.run()
    findings = simgr.one_deadended.globals.get('c6_findings', [])

Finding dict keys:
    'addr'          int     — instruction address of alert
    'vuln_class'    str     — OOB_WRITE | OOB_READ | UAF | INT_OVF | TYPE_CONFUSION
    'taint_label'   str     — hook name that introduced the taint
    'constraint'    str     — claripy AST string
    'poc_input'     str     — hex bytes (Z3-solved concrete input)
```

---

## 13. Maintenance

### Update Schedule

| Frequency | Task |
|-----------|------|
| Weekly | `pip install --upgrade angr` — angr releases frequently; check changelog for CLE/pyvex regressions |
| Before each engagement | Run test suite: `python3 -m pytest metis/test_pipeline.py -v` |
| After any angr upgrade | Run `python3 metis/validate_c3.py` and `python3 metis/validate_c6.py` |
| Before major changes | Backup: `zip -r metis_backup_$(date +%Y%m%d).zip metis/` |

> **Warning:** angr upgrades frequently change internal APIs in pyvex, cle, and claripy. After any `pip upgrade angr`, always run the full validation suite before using the toolchain on a live engagement. A silent regression in the hook resolution layer will produce false negatives without any error output.

### Test Suite

```bash
# Full unit tests:
python3 -m pytest metis/test_pipeline.py -v

# C3 validation (requires a test binary):
python3 metis/validate_c3.py

# C6 validation:
python3 metis/validate_c6.py
```

Expected: 5/5 tests passing in `test_pipeline.py`.

### Adding a New Binary Target

To add a binary to the standard C2 screen, edit the `TARGETS` list in `run_c2_screen.py`:

```python
TARGETS = [
    '/usr/libexec/targetd',
    '/usr/sbin/smbd',
    '/usr/libexec/your_new_target',
]
```

For arm64e binaries with PAC or chained fixup relocations, check whether CLE loads the binary cleanly before adding it to the batch run:

```python
import archinfo, angr
proj = angr.Project('/your/binary', auto_load_libs=False,
                    main_opts={'arch': archinfo.arch_from_id('aarch64')})
print(f'Functions found: {len(list(proj.kb.functions.values()))}')
```

If the function count is 0, the binary is affected by the arm64e PAC CLE bug (see §13). Use the manual address list workaround.

---

## 14. Troubleshooting

### Error Messages and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `SimEngineError: CLE could not find any executable sections` | Binary is encrypted, packed, or uses a segment layout CLE does not recognise | Use otool / Ghidra for manual analysis; skip the binary in batch runs |
| `KeyError: 'Win32'` in SYSCALL_CC | Windows ARM64 binary loaded without the SYSCALL_CC monkey-patch | Apply the Windows ARM64 patch before any `Project()` construction (see §13) |
| `angr.errors.AngrMemoryError: Not enough memory` | Binary exceeds approximately 3.3 MB — CFGFast OOMs on typical hardware (16 GB RAM) | Use sparse eigenvalue mode or skip; consider subsetting the CFG to a region of interest |
| `archinfo error: arch must be an archinfo.Arch instance` | `arch` passed as a bare string (e.g., `'aarch64'`) to `main_opts` | Use `archinfo.arch_from_id('aarch64')` — always an Arch object, never a string |
| `claripy.errors.BackendError: Cannot convert` | Constraint system too complex for Z3 to handle within timeout | Reduce `max_score_per_step` in C1; reduce the scope of the entry state |
| `AttributeError: 'NoneType' object has no attribute 'variables'` | Symbolic variable not set; a C6 hook returned None instead of a BVS | Check the hook's `run()` method — ensure it always returns a BVS, never None |
| C3 returns empty results | CFGFast missed the function (common for ObjC dispatch / Swift vtable targets) | Try `angr.analyses.CFGEmulated` at lower analysis level, or pass the function address list manually via `analyse_functions()` |
| z-scores all near 0 (full C2) | Call graph has fewer than 100 nodes | Results are flagged low-confidence; use function-level metrics (M, back-edges, ev) only |
| FastC2 z-scores are 0.0 and `reliable=False` | Binary uses ObjC/Swift indirect dispatch (`blraa`/`blr`) — no `bl` edges detected; null model is degenerate | Expected behavior for ObjC/Swift daemons. Use `functions_ranked` for C3 targeting. Binary-level z-scores are not available without L3 ObjC dispatch modelling. |
| FastC2 takes > 60 s on a large binary | Call graph has edges (reliable=True path taken) — null model is computing 50 × O(k) sparse eigensolutions for k top eigenvalues | Normal for n > 10,000 nodes. If n > 20,000, the binary likely has unusual LC_FUNCTION_STARTS (many stub entries). Consider skipping with `force_fast=False` to use full angr if binary is < RAM limit. |
| `ImportError: No module named 'z3'` | z3-solver not installed in the active venv | `pip install z3-solver` |
| All states immediately deferred by C1 | All paths are hard (backbone fraction > threshold) | Lower `threshold` to 0.6, or set `adaptive_threshold=True` to use percentile mode |
| `C7 TIMEOUT` — DTrace mode | DTrace probe did not fire within timeout | (1) Confirm binary actually runs when fed the PoC input; (2) increase `timeout_s`; (3) check SIP status (`csrutil status`); (4) switch to SUBPROCESS mode and check crash reports |
| `C7 NO_IMPACT` — SUBPROCESS mode | Process exited cleanly | (1) PoC delivery mode may be wrong (STDIN vs FILE vs MACH_MSG); (2) precondition not met (no mounted share, no active connection); (3) C6 constraint may be over-constrained — try reducing symbolic variable width |
| `C7 ERROR: permission denied` running DTrace | SIP enabled, `dtrace` entitlement absent | Use VM at 192.168.64.2 (SIP disabled) or apply `com.apple.private.dtrace.allow-attach` entitlement to target |
| `batch_screen.py` worker OOM killed | Each angr process uses 2–4 GB; too many workers | Reduce `--workers` to `floor(available_ram_GB / 4)` |
| `AttributeError: 'dyld_chained_ptr_arm64e_bind24' object has no attribute 'ordinal'` | CLE bug: arm64e binaries using bind24 chained fixup relocations (macOS 26 / Tahoe, all Apple Silicon system binaries) are not parseable by current CLE | Skip via `angr.options.IGNORE_MISSING_CALLS`; or extract function list via `nm`/`otool` and pass directly to `analyse_functions()`. Do not attempt to load the binary — CLE crashes before CFGFast begins. Affected: all arm64e binaries with `LC_DYLD_CHAINED_FIXUPS` on macOS 26. |
| macOS raw socket `sendto()` → `EINVAL` after first packet | `IP_HDRINCL=1` with a source address that does not exactly match a live local interface, **or** macOS's internal rate-limiter for raw IP injection | Remove `IP_HDRINCL` entirely. Without it, the kernel adds the IP header automatically using the interface address determined by routing — correct for VM-side injection where VM's address is the legitimate source. `SOCK_RAW + IPPROTO_ICMP` without `IP_HDRINCL` is the only reliable approach on macOS. |
| `socket.gethostbyname(socket.gethostname())` returns `127.0.0.1` | macOS resolves its own hostname to loopback when no mDNS/DNS record exists, or when the hostname is listed in `/etc/hosts` as loopback | Use the routing trick instead: `s = socket.socket(DGRAM); s.connect((remote, 80)); ip = s.getsockname()[0]; s.close()`. This returns the interface IP actually used to reach the target — always correct. |

### Diagnostic Commands

```bash
# Check angr version:
python3 -c "import angr; print(angr.__version__)"

# Check all imports:
python3 -c "import angr, archinfo, claripy, numpy, scipy, z3; print('OK')"

# Count functions in a binary:
python3 -c "
import archinfo, angr
p = angr.Project('/usr/libexec/targetd', auto_load_libs=False,
                 main_opts={'arch': archinfo.arch_from_id('aarch64')})
print(len(list(p.kb.functions.values())), 'functions')
"

# Quick C2 run and print:
python3 -c "
from metis.c2_rmt import C2RMTAnalysis
r = C2RMTAnalysis('/usr/libexec/targetd').run()
r.print_report()
"
```

---

## 15. Appendix — Known Issues & Workarounds

### Issue 1: angr CFG Size Limit (~3.3 MB Mach-O)

angr's `CFGFast` analysis will exhaust available memory on binaries larger than approximately 3.3 MB when running on a 16 GB RAM machine. This is a practical ceiling, not a hard limit — it varies with binary complexity and page count.

**Workaround:** For large targets, subset the analysis to a region of interest by providing a list of function addresses to `C3TemplateAnalysis.analyse_functions()` rather than running `run()` on the full binary.

### Issue 2: arm64e PAC / Chained Fixup Relocations (airportd, biometrickitd)

CLE has a known bug handling binaries that use arm64e pointer authentication codes (PAC) with chained fixup relocations. Affected binaries include `airportd` and `biometrickitd`. The symptom is an empty function list after `CFGFast`.

**Workaround:** Extract function addresses via `nm` or `otool -tv` and pass them directly to `analyse_functions()`:

```bash
nm -n /System/Library/PrivateFrameworks/BiometricKit.framework/biometrickitd \
    | grep ' T ' | awk '{print $1}' > biometric_addrs.txt
```

```python
addrs = [int(x, 16) for x in open('biometric_addrs.txt').read().splitlines()]
results = c3.analyse_functions(addrs)
```

### Issue 3: Python 3.12 Compatibility

angr has known compatibility issues with Python 3.12 that cause import failures. Use Python 3.11 or Python 3.13. Do not attempt to diagnose 3.12 failures — they are upstream issues.

### Issue 4: Windows ARM64 SYSCALL_CC Patch

When analysing Windows ARM64 PE binaries, angr's calling convention registry is missing the Win32 entry for AARCH64. This must be patched before any `Project()` construction:

```python
from angr.calling_conventions import SYSCALL_CC
SYSCALL_CC['AARCH64']['Win32'] = SYSCALL_CC['AARCH64'].get('Linux')
```

Additionally, angr's KB function lookup is unreliable for Windows PE binaries. Use `pefile` + `capstone` for IAT resolution:

```python
import pefile, capstone

pe = pefile.PE('target.exe')
iat = {
    imp.address: imp.name.decode()
    for entry in pe.DIRECTORY_ENTRY_IMPORT
    for imp in entry.imports
    if imp.name
}
```

### Issue 5: VEX IR Constant-Folding (ARM64 Compiler Optimisation)

ARM64 compilers commonly fold pointer arithmetic into load immediates. This means `Add64` nodes in VEX IR — which the original C3 design used for pattern detection — are absent even when the source code clearly adds an attacker-controlled offset to a base pointer. The VEX `Add64` scan produces false negatives.

**Workaround:** Use the `otool` sliding-window offset scan, which examines raw instruction sequences for `LDRB`/`LDRH` register-offset pairs without relying on VEX IR reconstruction. This is the default path in the production C3 implementation.

### Issue 6: ObjC Dispatch / Swift Vtables

`CFGFast` does not resolve Objective-C `objc_msgSend` dispatch or Swift vtable calls. Any vulnerability path that passes through an ObjC method boundary will appear as a dead end in the call graph. C3 will produce false negatives for ObjC targets.

**Known affected binaries:** Most Cocoa framework daemons, any binary with ObjC class methods in the hot path.

**Workaround:** Use Frida or DTrace to collect a dynamic call trace and augment the static CFG with the observed edges. See `metis/frida_func_fuzz.py` for the Frida integration scaffolding.

### Issue 7: Cross-Block VEX Temporaries

VEX IR temporaries (`t0`, `t1`, `t2`, ...) are SSA-scoped within a single IRSB (basic block). They do not carry meaning across block boundaries. Do not attempt to track `tN` temporaries across blocks when writing custom VEX analyses — use angr's `state.registers` and `state.memory` interfaces instead.

### Issue 8: angr KB Function Lookup — Windows PE

`proj.kb.functions` is unreliable across sessions for Windows PE binaries. Function addresses may differ between analysis runs due to ASLR simulation. Use `pefile` + `capstone` for authoritative IAT resolution on Windows targets (see Issue 4 above).

### Issue 9: macOS Raw Socket EINVAL on `sendto()` with IP_HDRINCL

When using `SOCK_RAW + IPPROTO_ICMP` with `IP_HDRINCL=1` on macOS, `sendto()` raises
`EINVAL (errno 22)` starting from the **second** packet — even when the supplied source
IP address matches a live local interface. Root cause: macOS's raw IP stack validates
the source address more strictly than Linux after the first send, and the internal
rate-limiter may also block rapid re-injection.

**Symptom:**
```
pkt #1: sent OK
pkt #2: [Errno 22] Invalid argument
pkt #3: [Errno 22] Invalid argument
...
```

**Fix:** Remove `IP_HDRINCL` entirely. Without it the kernel adds the outer IP header
automatically using the interface selected by routing:

```python
# WRONG — EINVAL after pkt #1:
s = socket.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.sendto(raw_ip_plus_icmp, (dst, 0))   # fails on pkt #2

# RIGHT — kernel adds IP header, src = local interface IP, all packets succeed:
s = socket.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
# no IP_HDRINCL
s.sendto(icmp_only_payload, (dst, 0))  # kernel fills src from routing table
```

For VM-to-Mac injection this is correct behaviour: the VM's real interface IP
(`192.168.64.2`) becomes the packet source automatically — no spoofing needed, and
macOS ping's `pr_pack()` filters by inner ICMP ident only, not outer source IP.

### Issue 10: `gethostbyname(gethostname())` Returns `127.0.0.1` on macOS

On macOS, `socket.gethostbyname(socket.gethostname())` often resolves to `127.0.0.1`
because the machine's own hostname is listed in `/etc/hosts` as loopback, or because
mDNS resolution is unavailable at the time of the call.

**Symptom:** PoC scripts compute `src_ip = "127.0.0.1"` instead of the Ethernet/Wi-Fi
interface address, causing raw packet injection to target the loopback interface.

**Fix:** Use the routing-based detection pattern:

```python
import socket

def get_local_ip_toward(remote_ip: str) -> str:
    """Return the local interface IP used to reach remote_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((remote_ip, 80))   # no actual connection — just sets routing
    ip = s.getsockname()[0]
    s.close()
    return ip

# Example:
vm_ip = get_local_ip_toward("192.168.64.1")   # returns 192.168.64.2
```

This works on both macOS and Linux and always returns the correct interface address.

### Issue 11: dyld Shared Cache (DSC) — Split Sub-Cache Format (macOS 14+)

On macOS 14 and later, the dyld shared cache is split across multiple sub-files.
The main file (`dyld_shared_cache_arm64e`) is a 573 KB stub containing only the
DSC header and image table pointer — all segment data lives in `.01`, `.02.dylddata`,
`.03.dyldreadonly`, `.04.dyldlinkedit` and so on.

**Symptom:** Binaries extracted with a single-file mmap produce **hollow Mach-Os**
(`all-zero` first segment) because `vm_to_file()` returns `None` for all TEXT
addresses (they map into `.01`, not the main file). angr errors:

```
No LC_FUNCTION_STARTS and no text-section symbols in '...IMCore'
'NoneType' object cannot be interpreted as an integer
```

**Root Cause:**
- Main file: 573 KB, mapping `vm=0x180000000, sz=0x88000`. One image entry only.
- `.01`: 1.7 GB, mapping `vm=0x180088000, sz=0x654ac000` — all TEXT from the first
  half of frameworks lives here. IMCore TEXT at `0x1BBC85000` → `.01` offset
  `0x3BBFD000`.
- `.04.dyldlinkedit`: 601 MB, covers `vm=0x1FEC7C000..0x222338000` — shared LINKEDIT.
  `LC_FUNCTION_STARTS.dataoff` is a file offset directly into `.04`.
- Data segments (`__DATA_CONST`, `__AUTH_CONST`, etc.) map into `.02.dylddata`.

**Image Table:** The main file's image table is empty in macOS 15+. Use the `.map`
file (`dyld_shared_cache_arm64e.map`) — it is a human-readable text file listing
all image paths with their `__TEXT` VM start addresses.

**Fix (dump_pf5.py):**
1. Parse the `.map` file for each target's `__TEXT` VM address.
2. Open **all** sub-caches; build a combined VM-range → `(sub-cache file, file offset)`
   resolver by reading each sub-cache's DSC header mapping table.
3. For each `LC_SEGMENT_64`, read data from the sub-cache whose mapping covers
   the segment's `vm_addr` using `segment.fileoff` directly (it encodes the offset
   within the correct sub-cache).
4. For `LC_FUNCTION_STARTS`, read from the LINKEDIT sub-cache (`*.dyldlinkedit`)
   at `lc.dataoff` — this is a direct file offset within that sub-cache.
5. **Two-phase layout required:** compute `final_lcs_size = max(len(lcs_buf), original_sizeofcmds)`
   BEFORE assigning segment `fileoff` values. If load commands grow (e.g. binaries
   with many sections), computing fileoffs before knowing `final_lcs_size` misplaces
   segment data (off-by-several-KB), producing a valid-magic but unreadable binary.

**Script:** `dump_pf5.py` (VM at `/private/tmp/dump_pf5.py`)  
**Output:** `/tmp/pf_dumped/` — 8 priority frameworks, ~0.07–4.8 MB each, non-hollow.

**Verification:**
```python
# Quick hollowness check — seek past header block to find first segment bytes:
with open(path, "rb") as f:
    f.read(32)      # mach_header
    soc = struct.unpack("<I", f.read(4))[0]  # offset 16+4 = wait, use proper read
    f.seek(32 + soc)
    sample = f.read(8)   # should be CF FA ED FE (Mach-O magic from TEXT)
```
Note: do NOT use `data = f.read(8192); sample = data[32+soc:]` — if `soc > 8192`
(common for large frameworks with many sections) the sample is empty, giving a
false-positive hollow result.

**LINKEDIT not mapped in output:** We drop `LC_DYLD_EXPORTS_TRIE`, `LC_CODE_SIGNATURE`,
and `LC_DYLD_CHAINED_FIXUPS`. Only `LC_FUNCTION_STARTS` data is preserved in a mini
`__LINKEDIT`. lief/angr emit "export trie out of bounds" warnings — these are harmless.

---

### Issue 12: C2 Batch Re-Run after Binary Replacement

The `run_c2_pf_frameworks.py` batch caches nothing — it processes each binary
sequentially. If a binary is **replaced** mid-run (hollow → fixed), only the next
scheduled full run will pick it up. For targeted re-analysis of replaced binaries:

```bash
# On Dell — quick re-run for specific files (nohup, background):
nohup /path/to/.venv_angr/bin/python3 -u ~/c2_priority8.py \
    > ~/darwin_research/priority8_c2.log 2>&1 &
```

Output: `~/darwin_research/findings/priority8_c2.json`

---

### Active Campaign Log (2026-04-23)

| When | Event |
|------|-------|
| 21:31 | `run_c2_pf_frameworks.py` started on Dell — 343 binaries, 3 workers |
| 21:31–21:46 | Priority-8 frameworks (IMCore, AuthKit, Sharing, etc.) all failed — hollow binaries |
| 21:37 | `mediasharingd` [17/343]: z=(0.603,-1.597,-7.763) **ANOMALOUS** |
| 21:48 | `CloudSharingUISKExtension` [34/343]: z=(3.39,1.961,-3.784) **ANOMALOUS** |
| 21:51 | C3 on mediasharingd top-20 complete: **0 matches** (entropy anomaly, no template hits) |
| 22:04 | `DesktopServicesHelper` [41/343]: z=(0.096,-1.111,-6.535) **ANOMALOUS** |
| 22:07 | `catutil` [46/343]: z=(1.808,-2.024,-7.802) **ANOMALOUS** |
| 22:07 | `kpasswdd` [63/343]: z=(-2.213,-1.821,-0.419) **ANOMALOUS** |
| 22:10 | DSC extraction root cause found: all TEXT in `.01` sub-cache, LINKEDIT in `.04` |
| 22:17 | `dump_pf5.py` deployed — 8 priority frameworks re-extracted: all non-hollow, LC_FS present |
| 22:22 | `c2_priority8.py` started on Dell (PID 92218) — re-running C2 on repaired binaries |
| ongoing | C2 batch at ~63/343 and progressing; priority-8 C2 results expected in ~30 min |

**C3 pipeline state:** mediasharingd — 0 matches. Next: run C3 on CloudSharingUISKExtension,
DesktopServicesHelper, catutil when priority-8 C2 completes.

---

---

## 16. FINDINGS_GUIDE.html — Architecture & Maintenance Guide

`FINDINGS_GUIDE.html` is the primary research dashboard for the darwin security
research programme. It is a **single static HTML file** — no build system, no
framework, no server required. It is opened directly in a browser via `file://` or
served via any static HTTP server.

**Location:** `~/Documents/Work/darwin_security_research/FINDINGS_GUIDE.html`

---

### Architecture Overview

The file has three logical layers:

```
FINDINGS_GUIDE.html
├── <style>              ← All CSS inline (no external stylesheet)
├── <nav class="sidebar"> ← Left navigation: grouped links to finding anchors
├── <main>               ← Content sections: Overview, Attack Surface Map,
│   ├── #overview            individual findings, tables, timeline
│   ├── #attack-surface-map
│   └── #<finding-id> ...
└── <script> × 2        ← (1) sidebar scroll tracker  (2) map badge tooltips
```

There are no external dependencies. No `fetch()` calls, no CDN links, no build step.

---

### CSS Architecture

**CSS variables** (`:root`) define the colour palette — edit these to retheme:

```css
:root {
  --blue: #0066cc;    --teal: #0077aa;    --green: #1a7f37;
  --red: #cf222e;     --amber: #7d4e00;   --mid: #57606a;
  --bg: #f6f8fa;      --border: #d0d7de;
}
```

**Badge classes** — two distinct systems that look similar but mean different things:

| Class | Used for | Examples |
|-------|----------|---------|
| `.badge .badge-critical/high/medium/low/info/closed` | Severity of the finding | `Critical`, `Medium`, `Low` |
| `.status-pill` (inline style) | Filing/workflow state | `Reviewing`, `Closed`, `Parked — Hardware Required` |
| `.map-badge` | Attack surface map icon | `AP`, `SM`, `HC` (abbreviations) |

Do not confuse severity badges with status pills — they are semantically different
elements styled to look similar.

---

### JavaScript — Sidebar Scroll Tracker

**Script block 1** (lines ~1509–1542): Highlights the active sidebar link based on
scroll position.

```javascript
const links = document.querySelectorAll('.sidebar a');
// IntersectionObserver watches every .finding and [id] element.
// When an element enters the viewport, its matching sidebar link gets class 'active'.
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      const match = document.querySelector(`.sidebar a[href="#${e.target.id}"]`);
      if (match) {
        links.forEach(l => l.classList.remove('active'));
        match.classList.add('active');
      }
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });

document.querySelectorAll('.finding, [id]').forEach(el => obs.observe(el));
```

The `rootMargin` is tuned so that only the section occupying the upper ~30% of the
viewport triggers the active state — prevents rapid flickering on short sections.

**Version stamp:** also in script 1 — reads `document.lastModified` and formats it
as `v2.x · Updated DD MMM YYYY`. The `v2.2` string is a fallback hardcoded for when
`lastModified` returns an empty or unparseable string (common when opened via
`file://` on some browsers):

```javascript
const el = document.getElementById('page-version-stamp');
const raw = document.lastModified; // "MM/DD/YYYY HH:MM:SS"
// ... parses and formats; falls back to hardcoded 'v2.2' if parse fails
```

To update the version string when the fallback is used: edit the hardcoded `v2.x`
string in the script block directly.

---

### JavaScript — Attack Surface Map Badges

**Script block 2** (lines ~1544–1563): Manages hover tooltips and click navigation
for the coloured icon badges in the attack surface map.

Each badge is an element like:

```html
<span class="map-badge badge-reviewing"
      data-title="smbd (SMB-01A)"
      data-desc="FSCTL_SRV_COPYCHUNK: no MaxChunkCount enforcement. CVSS 6.5."
      data-target="smb01a">
  SM
</span>
```

- `data-title` / `data-desc` → populate the floating `div#map-tooltip` on hover
- `data-target` → the `id` of the finding section to scroll to on click
- `mousemove` positions the tooltip near the cursor, clamping to the right edge:
  `if (x + 295 > window.innerWidth) x = e.clientX - 295;`
- Click handler: `document.getElementById(data-target).scrollIntoView({behavior:'smooth', block:'start'})`

**Adding a new badge to the map:**

1. Choose the correct layer row in the `<table class="attack-surface-map">`.
2. Add a `<span class="map-badge badge-<status>" data-title="..." data-desc="..." data-target="<finding-id>">AB</span>` where `AB` is a 2–3 letter abbreviation.
3. Add the corresponding `<div class="finding" id="<finding-id>">` section in `<main>`.
4. Add the sidebar link: `<a href="#<finding-id>">Finding Name</a>` in the correct `<div class="sidebar-group">`.

Status colours for `map-badge`:

| Class | Meaning | Hex |
|-------|---------|-----|
| `badge-reproduced` | Filed, confirmed by Apple | `#1a7f37` (green) |
| `badge-reviewing` | Filed, under Apple review | `#9a6700` (amber) |
| `badge-high` | High severity / critical | `#cf222e` (red) |
| `badge-planned` | Fix scheduled | `#0066cc` (blue) |
| `badge-received` | Filed, acknowledgement received | `#0969da` (blue) |
| `badge-closed` | Closed (won't fix / not actionable) | `#8e8e93` (grey) |

---

### Finding Section Structure

Each finding follows this HTML skeleton:

```html
<div class="finding" id="<finding-id>">
  <div class="finding-header">
    <span class="badge badge-<severity>">Medium</span>
    <span class="finding-title">Binary: Description</span>
    <span class="status-pill" style="background:#fff8c5;color:#7d4e00">Reviewing</span>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">OE</span><span class="meta-value">OE1234567890</span></div>
    <div class="meta-item"><span class="meta-label">Filed</span><span class="meta-value">17 Apr 2026</span></div>
    <div class="meta-item"><span class="meta-label">CVSS</span><span class="meta-value">6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)</span></div>
    <div class="meta-item"><span class="meta-label">File</span><span class="meta-value"><code>/path/to/binary</code></span></div>
  </div>
  <p class="finding-desc">Technical description of the vulnerability.</p>
  <div class="fix-block">Remediation notes / Apple response status.</div>
</div>
```

**Status pill colours (inline style):**

| State | Background | Colour |
|-------|-----------|--------|
| Reviewing | `#fff8c5` | `#7d4e00` |
| Fix Planned | `#ddf4ff` | `#0969da` |
| Closed | `#f0f0f0` | `#57606a` |
| Parked | `#fdf4c7` | `#7a4f00` |
| Received | `#e8f3ff` | `#0066cc` |

---

### Update Checklist

When adding or updating a finding:

- [ ] Add / update `<div class="finding" id="...">` section in `<main>`
- [ ] Add / update sidebar link in the correct `<div class="sidebar-group">`
- [ ] Add / update map badge in the attack surface map table
- [ ] Update the summary table in `#overview` (status column)
- [ ] Update the bounty projection table if filing status changed
- [ ] Update the version stamp (`v2.x`) in both the hardcoded fallback string and
      the human-readable stamp at the top of the page
- [ ] Update `MEMORY.md` → Apple ASB portfolio with new OE number / status

**To update the version fallback string:**
Search for `v2.` in the script block and increment the minor version. Also update the
`<span id="page-version-stamp">` element at the top of `<main>` if it contains a
hardcoded string (it may be overwritten by the JS on load).

---

### Responsive Layout Note

The sidebar hides on screens narrower than 900px (`@media (max-width: 900px)`). The
attack surface map table is horizontally scrollable below 700px. The dashboard is
designed for desktop browser use; mobile is functional but not the target layout.

---

*End of document. For questions or corrections, contact Stuart Thomas.*
