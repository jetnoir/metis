# C7 — Dynamic Validation Pass
## TriageForge v2 — Design Specification

**Author:** Stuart Thomas  
**Date:** 2026-04-18  
**Status:** Draft — for review before implementation  
**Depends on:** C6 taint analysis output (`c6_taint.py`), macOS research VM (192.168.64.2, SIP disabled)

---

## The Problem C7 Solves

Apple's ASB team requires on-device execution evidence before treating a report as
actionable. Nick's exact feedback on an early submission:
> *"Actionable reports need evidence of security impact from on-device execution."*

C6 produces a concrete PoC input (byte sequence or Mach message) derived from
symbolic taint analysis. C7 takes that input and:

1. Delivers it to the target process via the appropriate IPC mechanism
2. Monitors for observable security impact (crash / OOB access / info disclosure)
3. Captures evidence in ASB-submission-ready format

C7 closes the gap between *"the taint analysis says this path is reachable"* and
*"here is a crash report and register state proving it"*.

---

## Architecture

```
C6 output                C7 inputs                C7 output
─────────────────────    ─────────────────────    ─────────────────────────────
c6_poc.json              target binary path       c7_evidence/
  - binary               delivery mechanism         crash_report.ips  (if crash)
  - function addr        expected impact            registers.txt
  - taint path           monitor mode               backtrace.txt
  - concrete input  ───▶ vm_host / vm_key      ───▶ poc_transcript.txt
  - delivery type        timeout                    verdict.json
  - expected impact      asan_build (opt.)          (pass to ASB report gen)
```

### Delivery mechanisms (C7 must support all four)

| Type | Description | Example targets |
|------|-------------|-----------------|
| `xpc_message` | Craft an XPC message with controlled field values | amfid, biometrickitd, securityd |
| `mach_msg` | Send raw Mach message to named bootstrap port | IOKit UserClients, WindowServer |
| `network` | TCP/UDP packet with controlled payload | symptomsd :56824, smbd :445 |
| `stdin` | Pipe controlled bytes to binary stdin | ping, fsck, CLI tools |

---

## Implementation Plan

### Stage 1 — C7 core framework (2 weeks)

**File:** `macos_vuln_toolchain/metis/c7_validate.py`

```python
@dataclass
class C7Config:
    binary_path: str          # path on VM: e.g. /usr/libexec/biometrickitd
    poc_input: bytes          # concrete PoC bytes from C6
    delivery: str             # 'xpc_message' | 'mach_msg' | 'network' | 'stdin'
    delivery_params: dict     # delivery-specific params (port name, service name, etc.)
    expected_impact: str      # 'crash' | 'oob_read' | 'info_disclose' | 'auth_bypass'
    monitor_mode: str         # 'crash_only' | 'dtrace' | 'lldb'
    timeout_s: int = 30
    vm_host: str = "192.168.64.2"
    vm_key: str  = "~/.ssh/id_ed25519_vm"

@dataclass
class C7Result:
    verdict: str              # 'CRASH' | 'HANG' | 'INFO_DISCLOSE' | 'NO_IMPACT'
    crash_type: str | None    # 'SIGSEGV' | 'SIGABRT' | 'EXC_BAD_ACCESS' | None
    faulting_address: int | None
    registers: dict | None    # {x0: ..., x1: ..., pc: ..., lr: ...}
    backtrace: list[str]
    crash_report_path: str | None  # path to .ips file in DiagnosticReports
    evidence_dir: str         # local path where all evidence files were saved
    elapsed_s: float
    asb_summary: str          # auto-drafted 3-sentence impact summary
```

**Core flow:**

```python
def run(config: C7Config) -> C7Result:
    # 1. Pre-flight: confirm VM reachable, target binary exists
    _preflight(config)

    # 2. Install DTrace monitor on VM (crash + signal probe)
    dtrace_pid = _start_dtrace_monitor(config)

    # 3. Deliver PoC via appropriate mechanism
    deliver_fn = {
        'xpc_message': _deliver_xpc,
        'mach_msg':    _deliver_mach,
        'network':     _deliver_network,
        'stdin':       _deliver_stdin,
    }[config.delivery]
    deliver_fn(config)

    # 4. Wait for impact or timeout
    result = _wait_for_impact(config, dtrace_pid)

    # 5. Collect evidence from VM
    _collect_evidence(config, result)

    # 6. Draft ASB summary
    result.asb_summary = _draft_summary(config, result)

    return result
```

---

### Stage 2 — XPC delivery module (1 week, highest priority)

Most of our Tier 1 candidates (biometrickitd, findmydeviced, securityd) are
XPC-based. The XPC delivery module must:

1. Connect to the named XPC service on the VM
2. Construct an `xpc_object_t` dictionary with the C6-specified field types and values
3. Send the message and wait for reply (or timeout)

**Approach:** Compile a small Objective-C delivery harness on the VM at C7 runtime.
This avoids the complexity of constructing XPC binary wire format in Python.

```objc
// c7_xpc_sender.m — compiled per-run on VM
// Usage: ./c7_xpc_sender <service_name> <c6_poc.json>
// Reads field specs from JSON, builds xpc_dictionary, sends to service
int main(int argc, char *argv[]) {
    xpc_connection_t conn = xpc_connection_create(argv[1], NULL);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t reply) {
        // Log reply type + data for info-disclosure check
    });
    xpc_connection_resume(conn);

    // Build xpc_dictionary from c6_poc.json field specs
    xpc_object_t msg = build_xpc_message(argv[2]);
    xpc_connection_send_message(conn, msg);
    sleep(5);  // wait for side effects
    return 0;
}
```

The C7 Python code SSHes to the VM, writes this .m file, compiles it with
`clang -framework Foundation -framework XPC`, runs it, and captures output.

---

### Stage 3 — Crash detection and evidence capture (1 week)

**DTrace script (runs on VM, monitors for crash during PoC delivery):**

```d
/* c7_monitor.d — runs as root on VM */
proc:::signal-send
/args[2] == SIGSEGV || args[2] == SIGBUS || args[2] == SIGABRT/
{
    printf("SIGNAL pid=%d sig=%d comm=%s\n", args[0]->p_pid, args[2],
           args[0]->p_comm);
}

/* Monitor EXC_BAD_ACCESS via mach exception */
mach_trap:::mach_msg_trap
/arg0 & 0x80000000/
{
    printf("MACH_MSG_SEND_TIMEOUT pid=%d\n", pid);
}
```

**Crash report collection:**

```python
def _collect_crash_report(config: C7Config, target_name: str) -> str | None:
    """Poll ~/Library/Logs/DiagnosticReports/ on VM for new .ips files."""
    cmd = f"ls -t /Library/Logs/DiagnosticReports/{target_name}*.ips 2>/dev/null | head -1"
    newest = vm_ssh(cmd).strip()
    if not newest:
        return None
    # Rsync the .ips file to local evidence dir
    subprocess.run(["scp", "-i", config.vm_key,
                    f"test@{config.vm_host}:{newest}",
                    f"{config.evidence_dir}/crash_report.ips"])
    return f"{config.evidence_dir}/crash_report.ips"
```

---

### Stage 4 — LLDB register capture (optional, for OOB/UAF findings)

For crash types where we want register state at the point of fault:

```python
def _lldb_capture(config: C7Config, pid: int) -> dict:
    """Attach LLDB on VM, deliver PoC, capture registers at fault."""
    lldb_script = textwrap.dedent(f"""
        process attach --pid {pid}
        breakpoint set --name {config.delivery_params.get('target_func', 'malloc_error_break')}
        continue
        register read
        bt 20
        quit
    """)
    # Write script to VM, run lldb, parse output
    ...
```

This is only needed when `monitor_mode='lldb'` — crash_only mode is sufficient for
most ASB submissions.

---

### Stage 5 — ASB evidence formatting (small, high value)

The output of `run()` feeds directly into a report template:

```
c7_evidence/
├── verdict.json           ← machine-readable summary
├── crash_report.ips       ← Apple crash report (if crash)
├── registers.txt          ← register state at fault
├── backtrace.txt          ← symbolicated backtrace
├── poc_transcript.txt     ← full delivery + response log
└── poc_input.hex          ← annotated hex dump of PoC bytes
```

`verdict.json` format:

```json
{
  "verdict":          "CRASH",
  "crash_type":       "EXC_BAD_ACCESS (SIGSEGV)",
  "faulting_address": "0x0000000000000018",
  "crash_function":   "_XPC_DISPATCH_HANDLER+0x24",
  "binary":           "/usr/libexec/biometrickitd",
  "binary_version":   "macOS 26.4.1 (25E5200d)",
  "poc_delivery":     "xpc_message → com.apple.biometrickit",
  "elapsed_s":        4.2,
  "asb_summary":      "An unauthenticated XPC client can cause biometrickitd to crash (EXC_BAD_ACCESS at 0x18) by sending a message with a nil data field where a non-nil NSData is assumed. The faulting instruction is at _XPC_DISPATCH_HANDLER+0x24 (PC=0x100012abc). Impact: biometric authentication denial of service without user interaction from any process in the user session."
}
```

The `asb_summary` field is templated from the verdict fields — no LLM needed for this,
it's deterministic from the data.

---

## Integration with Existing Pipeline

C7 slots after C6 in the chain:

```
C2 (screen)  →  C3 (templates)  →  C6 (taint)  →  C7 (validate)  →  ASB report
fast_c2.py       c3_templates.py    c6_taint.py     c7_validate.py     (template)

Runtime:  90s        ~5 min           ~30 min           ~2 min           ~1 min
```

C7 is also callable standalone (with a hand-crafted `c6_poc.json`) for cases where
C6 wasn't used — e.g., the symptomsd TCP binding finding where we already have the
PoC manually constructed.

---

## Priority targets for C7 (from active pipeline)

| Target | Delivery | Expected impact | C6 status |
|--------|----------|-----------------|-----------|
| biometrickitd | `xpc_message` | crash / OOB read | C3 running → C6 next |
| findmydeviced | `xpc_message` | crash / auth bypass | C3 running → C6 next |
| symptomsd :56824 | `network` | info disclose / crash | Manual PoC exists |
| appleh16camerad | `xpc_message` | IOSurface OOB | Parked — MacBook needed |
| smbd (SMB-01A) | `network` | resource exhaustion | Manual PoC exists |

---

## What C7 is NOT

- **Not a fuzzer** — C7 takes a single concrete input from C6. Fuzzing is AFL++/libFuzzer's job.
- **Not a symbolic executor** — C7 runs on a real device with real state.
- **Not a general test harness** — C7 is tightly coupled to the ASB evidence format.
- **Not a replacement for manual PoC development** — when C6 fails to produce a PoC,
  C7 can still be driven manually with a hand-crafted `c6_poc.json`.

---

## Implementation order

```
Week 1:  C7 core framework + crash detection (DTrace monitor + IPS collection)
Week 2:  XPC delivery module (c7_xpc_sender.m compiler + SSH orchestration)
Week 3:  Evidence formatting + verdict.json + ASB summary template
Week 4:  Integration with C6 output + standalone driver script
         First real run: symptomsd (manual PoC → C7 evidence capture)
```

Total: ~4 weeks solo. Could be accelerated to 2 weeks by starting with `network`
and `stdin` delivery (simpler than XPC) while XPC is being designed.

---

## Open questions

1. **XPC sender compilation on VM:** The VM has SIP disabled — `clang` should be
   available. Need to verify Xcode CLI tools are installed (`xcode-select --version`).

2. **Entitlement-gated services:** biometrickitd requires specific entitlements to
   connect. C7's XPC sender needs to run with those entitlements, or we need an
   entitled helper binary pre-installed on the VM. Simpler approach: check if the
   service accepts unentitled clients first (com.apple.biometrickit has an open
   listening endpoint — verify with `notifyutil -g`).

3. **C7 for auth_bypass findings:** The `expected_impact='auth_bypass'` case is
   harder — no crash to detect. Needs a monitor that checks whether a privileged
   operation completed without the expected entitlement check. DTrace
   `syscall::*entitlement*:entry` and `proc:::exec*` probes are the hook points.

4. **Symbolication on VM:** `.ips` crash reports from a development build VM may not
   symbolicate well without Apple's symbol server. For private frameworks this is
   acceptable — the faulting address + binary + version is enough for ASB.

---

*C7 is the difference between a research tool and a commercial product.*  
*"Evidence of security impact from on-device execution" — that's the bar. C7 clears it automatically.*
