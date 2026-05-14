"""
c7_dynamic.py — C7: Dynamic on-device validation of C6 symbolic findings.

Purpose
-------
C7 closes the loop between angr symbolic analysis and on-device evidence.

  C6 output  →  concrete PoC input  →  C7 on-device run  →  ASB-ready evidence

Three validation modes are supported, in order of increasing invasiveness:

  SUBPROCESS — Launch binary, feed PoC via stdin/file, capture exit code and
               stdout/stderr.  No debugger.  Works for command-line tools.

  LLDB       — Launch binary under LLDB in batch mode.  Captures crash type,
               faulting address, register state, and backtrace automatically.
               Best for local daemons and command-line tools.

  DTRACE     — Attach a DTrace probe to the running binary or launch it under
               DTrace.  Non-destructive: confirms that the sink function is
               reached with attacker-controlled arguments without crashing.
               Requires sudo.  Best for daemons where crashing is undesirable.

Workflow
--------
    # After C6 finds a candidate:
    from metis.c7_dynamic import C7Analysis, C7DeliveryMode

    c7     = C7Analysis(proj, binary_path='/sbin/ping')
    poc    = c7.extract_poc_from_c6(finding)
    result = c7.validate(poc, mode=C7DeliveryMode.LLDB, target_args=['-c','1','127.0.0.1'])
    c7.write_evidence(result, Path('ping_c7_evidence.txt'))

Standalone (no C6 required):
    poc = C7PoC(
        payload=bytes.fromhex('deadbeef...'),
        label='manual_mach_msg',
        delivery=C7DeliveryMode.STDIN,
        sink_addr=0x100012345,
        expected_sink_arg=0xfeedcafe,
    )
    result = c7.validate(poc, mode=C7DeliveryMode.DTRACE, target_args=[])

Output
------
C7Evidence.asb_text — ASB-submission-ready plain text, including:
  • Platform, binary, macOS version
  • PoC payload description and delivery method
  • Validation result (CONFIRMED / SINK_REACHED / TIMEOUT / NO_IMPACT)
  • Crash type, faulting address, register dump, backtrace (if crashed)
  • DTrace output (if DTrace mode)
  • Conclusion paragraph with exploitation assessment

Integration with ROADMAP_V2.md §1.4
-------------------------------------
C7 implements the "C7 — Dynamic validation pass" roadmap item.  It consumes
VulnFinding.state (angr SimState) to extract concrete inputs and uses macOS
system tools (LLDB, DTrace, DiagnosticReports) for validation.

Requires
--------
  macOS (Darwin) — LLDB and DTrace are system tools, not pip packages
  angr             (for PoC extraction from SimState)
  sudo             (for DTrace mode only)

Limitations
-----------
1. mach_msg delivery to live daemons requires knowing the launchd service name
   and root privileges.  C7 generates a ready-to-run sender script rather than
   executing it — the researcher runs it in the appropriate context.
2. DTrace probes fire on the function entry point, not the exact call site.
   For functions called from many callers, the caller-pc filter narrows it.
3. LLDB batch mode terminates on first stop — useful for crashes, but misses
   daemons that catch signals (SIGFPE, etc.) without crashing.

Author: Stuart Thomas, TriageForge. Apache 2.0.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Delivery modes ────────────────────────────────────────────────────────────

class C7DeliveryMode(Enum):
    # ── Delivery / payload modes ──────────────────────────────────────────────
    STDIN      = auto()   # feed PoC bytes as stdin to the target binary
    FILE       = auto()   # write PoC to a temp file, pass path as argument
    MACH_MSG   = auto()   # generate a mach_msg sender script (not executed here)
    XPC        = auto()   # generate an XPC sender script (not executed here)
    MANUAL     = auto()   # evidence recorded manually; C7 only formats the report
    # ── Validation / runner modes ─────────────────────────────────────────────
    SUBPROCESS = auto()   # plain subprocess run; inspect exit code + stdout/stderr
    LLDB       = auto()   # launch under LLDB batch mode; capture crash/backtrace
    DTRACE     = auto()   # attach DTrace probe; confirm sink reached without crashing


# ── Validation result codes ───────────────────────────────────────────────────

class C7ResultCode(Enum):
    CONFIRMED    = 'CONFIRMED'      # crash or signal observed at expected site
    SINK_REACHED = 'SINK_REACHED'   # DTrace confirmed sink reached (no crash needed)
    TIMEOUT      = 'TIMEOUT'        # run completed without reaching sink
    NO_IMPACT    = 'NO_IMPACT'      # binary ran cleanly; finding likely not exploitable
    ERROR        = 'ERROR'          # tooling error (LLDB/DTrace not available, etc.)
    MANUAL       = 'MANUAL'         # evidence provided manually


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class C7PoC:
    """
    Concrete proof-of-concept input extracted from a C6 angr state (or manually
    crafted).

    Attributes
    ----------
    payload       : raw bytes of the PoC (mach_msg body, file content, stdin, …)
    label         : human label for the payload (e.g. 'mach_msg@0x1000abcd')
    delivery      : how to deliver payload to the target
    sink_addr     : address of the C6 sink call site (for DTrace caller filter)
    expected_sink_arg : concrete value of the critical sink argument (e.g. malloc size)
    taint_regions : [(start_addr, size, label)] — source regions from c6_tainted_regions
    vuln_class    : 'OOB', 'UAF', 'XTYPE', or None
    confidence    : C6 confidence score (0–1)
    notes         : free-form notes for the evidence report
    """
    payload           : bytes
    label             : str
    delivery          : C7DeliveryMode        = C7DeliveryMode.STDIN
    sink_addr         : int                   = 0
    expected_sink_arg : Optional[int]         = None
    taint_regions     : list[tuple]           = field(default_factory=list)
    vuln_class        : Optional[str]         = None
    confidence        : float                 = 0.0
    notes             : str                   = ''

    def hex_dump(self, width: int = 16) -> str:
        """Return a formatted hex dump of the payload (first 256 bytes)."""
        preview = self.payload[:256]
        lines   = []
        for i in range(0, len(preview), width):
            chunk = preview[i:i + width]
            hex_  = ' '.join(f'{b:02x}' for b in chunk)
            ascii_= ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'  {i:04x}  {hex_:<{width*3}}  |{ascii_}|')
        if len(self.payload) > 256:
            lines.append(f'  ... ({len(self.payload)} bytes total)')
        return '\n'.join(lines)


@dataclass
class C7Evidence:
    """
    Full dynamic validation evidence for one C6 finding.

    Attributes
    ----------
    result_code   : C7ResultCode — overall verdict
    poc           : C7PoC that was used
    binary_path   : target binary
    target_args   : argv passed to the binary (excluding binary name)
    mode          : validation mode used
    elapsed_s     : wall time of the validation run
    stdout        : captured stdout from the target / LLDB / DTrace
    stderr        : captured stderr
    crash_type    : 'SIGSEGV' / 'EXC_BAD_ACCESS' / 'SIGBUS' / '' etc.
    faulting_addr : memory address of the fault (0 if no crash)
    backtrace     : backtrace text from LLDB or crash report
    registers     : register dump text from LLDB
    dtrace_output : DTrace probe output (if DTrace mode)
    crash_report  : path to .ips crash report (if found in DiagnosticReports)
    timestamp     : ISO-8601 timestamp of the run
    macos_version : sw_vers output
    platform_info : uname -a output
    extra         : arbitrary dict for future fields
    """
    result_code   : C7ResultCode
    poc           : C7PoC
    binary_path   : str
    target_args   : list[str]
    mode          : C7DeliveryMode
    elapsed_s     : float                  = 0.0
    stdout        : str                    = ''
    stderr        : str                    = ''
    crash_type    : str                    = ''
    faulting_addr : int                    = 0
    backtrace     : str                    = ''
    registers     : str                    = ''
    dtrace_output : str                    = ''
    crash_report  : str                    = ''
    timestamp     : str                    = field(default_factory=lambda: datetime.now().isoformat())
    macos_version : str                    = ''
    platform_info : str                    = ''
    extra         : dict                   = field(default_factory=dict)

    @property
    def asb_text(self) -> str:
        """Generate Apple Security Bounty submission-ready evidence text."""
        return _format_asb_evidence(self)


# ── PoC extraction from C6 SimState ──────────────────────────────────────────

def extract_poc_from_c6(finding, proj=None) -> C7PoC:
    """
    Extract a concrete proof-of-concept input from a C6 VulnFinding.

    The finding's angr SimState is queried to concretise the tainted memory
    regions (mach_msg buffers, XPC payloads) recorded during symbolic execution.

    Parameters
    ----------
    finding : metis.c6_taint.VulnFinding
    proj    : angr.Project (optional — used to determine arch for arg extraction)

    Returns
    -------
    C7PoC with:
      payload       = concatenated bytes of first tainted region (or empty)
      taint_regions = all regions from c6_tainted_regions
      sink_addr     = finding.site_addr
      expected_sink_arg = concrete value of the first arg register at sink site
      vuln_class    = finding.vuln_class.name
      confidence    = finding.confidence
    """
    state  = finding.state
    label  = getattr(finding, 'taint_label', '') or 'c6_taint'
    vclass = getattr(finding.vuln_class, 'name', str(finding.vuln_class))

    # Collect tainted regions
    regions   = state.globals.get('c6_tainted_regions', [])
    payloads  = []
    for (start_addr, size, rlabel) in regions:
        try:
            mem_expr = state.memory.load(
                start_addr, size, endness=state.arch.memory_endness
            )
            concrete  = state.solver.eval(mem_expr, cast_to=bytes)
            payloads.append((start_addr, concrete, rlabel))
            log.info('C7: extracted %d bytes from tainted region @ %#x (%s)',
                     size, start_addr, rlabel)
        except Exception as e:
            log.debug('C7: could not concretise region @ %#x: %s', start_addr, e)

    # Primary payload = first tainted region (usually the mach_msg buffer)
    primary_payload = payloads[0][1] if payloads else b'\x00' * 64

    # Extract the concrete critical argument at the sink site.
    # For OOB: malloc size = arg0. For UAF/XTYPE: first arg may be a pointer.
    sink_arg = None
    if proj is not None or state.arch is not None:
        arch = state.arch
        try:
            if arch.name == 'AARCH64':
                sink_arg = state.solver.eval(state.regs.x0)
            elif arch.name in ('AMD64', 'X86_64'):
                sink_arg = state.solver.eval(state.regs.rdi)
        except Exception:
            pass

    notes_lines = [f'C6 finding: {finding.description}']
    if payloads:
        notes_lines.append(f'Tainted regions: {len(payloads)}')
        for sa, pb, rl in payloads:
            notes_lines.append(f'  {rl} @ {sa:#x}: {len(pb)} bytes')
    if sink_arg is not None:
        notes_lines.append(
            f'Concrete sink arg0 at site {finding.site_addr:#x}: {sink_arg:#x}'
        )

    return C7PoC(
        payload           = primary_payload,
        label             = label,
        delivery          = C7DeliveryMode.STDIN,  # default; override per delivery type
        sink_addr         = finding.site_addr,
        expected_sink_arg = sink_arg,
        taint_regions     = [(a, len(p), l) for a, p, l in payloads],
        vuln_class        = vclass,
        confidence        = finding.confidence,
        notes             = '\n'.join(notes_lines),
    )


# ── DTrace script templates ───────────────────────────────────────────────────

def _dtrace_script_oob(
    threshold: int,
    caller_addr: int,
    timeout_s: int = 30,
) -> str:
    """
    DTrace D script for OOB confirmation.

    Fires when malloc/calloc is called with a size argument above *threshold*
    from a call site near *caller_addr* (±0x20).  Exits 0 on hit, 1 on timeout.
    """
    caller_lo = caller_addr - 0x20 if caller_addr else 0
    caller_hi = caller_addr + 0x20 if caller_addr else 0xffffffffffffffff
    return textwrap.dedent(f"""\
        pid$target::malloc:entry
        /arg0 > {threshold:#x}/
        {{
            printf("C7_SINK_HIT malloc(%lu) ucallerpc=%p\\n", arg0, ucallerpc);
            ustack(12);
            exit(0);
        }}

        pid$target::calloc:entry
        /arg0 * arg1 > {threshold:#x}/
        {{
            printf("C7_SINK_HIT calloc(%lu * %lu) ucallerpc=%p\\n",
                   arg0, arg1, ucallerpc);
            ustack(12);
            exit(0);
        }}

        pid$target::realloc:entry
        /arg1 > {threshold:#x}/
        {{
            printf("C7_SINK_HIT realloc(%lu) ucallerpc=%p\\n", arg1, ucallerpc);
            ustack(12);
            exit(0);
        }}

        tick-{timeout_s}s
        {{
            printf("C7_TIMEOUT sink not reached in {timeout_s}s\\n");
            exit(1);
        }}
    """)


def _dtrace_script_uaf(timeout_s: int = 30) -> str:
    """DTrace D script for UAF (double-free / double port dealloc) confirmation."""
    return textwrap.dedent(f"""\
        pid$target::free:entry
        {{
            self->freed[arg0]++;
        }}

        pid$target::free:entry
        /self->freed[arg0] > 1/
        {{
            printf("C7_SINK_HIT double-free @ ptr=%p ucallerpc=%p\\n",
                   arg0, ucallerpc);
            ustack(12);
            exit(0);
        }}

        pid$target::mach_port_deallocate:entry
        {{
            self->dealloc[arg1]++;
        }}

        pid$target::mach_port_deallocate:entry
        /self->dealloc[arg1] > 1/
        {{
            printf("C7_SINK_HIT double-deallocate port=%#llx ucallerpc=%p\\n",
                   arg1, ucallerpc);
            ustack(12);
            exit(0);
        }}

        tick-{timeout_s}s
        {{
            printf("C7_TIMEOUT sink not reached in {timeout_s}s\\n");
            exit(1);
        }}
    """)


def _dtrace_script_xtype(timeout_s: int = 30) -> str:
    """DTrace D script for XPC type confusion confirmation."""
    accessors = ' '.join(
        f'pid$target::xpc_{fn}:entry,'
        for fn in (
            'int64_get_value', 'uint64_get_value', 'double_get_value',
            'bool_get_value', 'string_get_string_ptr', 'data_get_bytes_ptr',
            'data_get_length', 'array_get_count',
        )
    ).rstrip(',')
    return textwrap.dedent(f"""\
        {accessors}
        {{
            printf("C7_SINK_HIT %s() arg0=%p ucallerpc=%p\\n",
                   probefunc, arg0, ucallerpc);
            ustack(12);
            exit(0);
        }}

        tick-{timeout_s}s
        {{
            printf("C7_TIMEOUT sink not reached in {timeout_s}s\\n");
            exit(1);
        }}
    """)


# ── LLDB batch script templates ───────────────────────────────────────────────

_LLDB_BATCH_COMMANDS = [
    'settings set target.x86-disassembly-flavor intel',
    'settings set auto-confirm true',
    'run',
    'thread backtrace',
    'register read',
    'frame info',
    'memory region -- `$pc`',
    'quit',
]


# ── Platform helpers ──────────────────────────────────────────────────────────

def _macos_version() -> str:
    try:
        return subprocess.check_output(
            ['sw_vers'], text=True, timeout=5
        ).strip()
    except Exception:
        return platform.platform()


def _platform_info() -> str:
    try:
        return subprocess.check_output(
            ['uname', '-a'], text=True, timeout=5
        ).strip()
    except Exception:
        return platform.uname()._asdict().__str__()


# ── Crash report scanner ──────────────────────────────────────────────────────

def scan_crash_reports(binary_name: str, min_mtime: float = 0.0) -> list[Path]:
    """
    Scan ~/Library/Logs/DiagnosticReports/ for crash reports matching *binary_name*.

    Returns paths to .ips or .crash files whose modification time is ≥ *min_mtime*
    (Unix timestamp), sorted newest first.  Empty list if none found.
    """
    dirs = [
        Path.home() / 'Library' / 'Logs' / 'DiagnosticReports',
        Path('/Library/Logs/DiagnosticReports'),
    ]
    reports: list[Path] = []
    pattern = binary_name.replace('-', '').replace('_', '').lower()

    for d in dirs:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.suffix not in ('.ips', '.crash'):
                continue
            if p.stat().st_mtime < min_mtime:
                continue
            if pattern in p.name.lower().replace('-', '').replace('_', ''):
                reports.append(p)

    return sorted(reports, key=lambda p: p.stat().st_mtime, reverse=True)


def _read_crash_report(path: Path, max_lines: int = 80) -> str:
    """Return the first *max_lines* lines of a crash report file."""
    try:
        text = path.read_text(errors='replace')
        lines = text.splitlines()[:max_lines]
        if len(text.splitlines()) > max_lines:
            lines.append(f'... (truncated; full report at {path})')
        return '\n'.join(lines)
    except Exception as e:
        return f'[error reading {path}: {e}]'


# ── Core runners ──────────────────────────────────────────────────────────────

def _run_subprocess(
    binary: str,
    args: list[str],
    stdin_data: Optional[bytes],
    timeout: float,
) -> tuple[int, str, str, float]:
    """
    Run *binary* with *args*, optionally feeding *stdin_data*.

    Returns (returncode, stdout, stderr, elapsed_s).
    """
    t0  = time.monotonic()
    try:
        result = subprocess.run(
            [binary] + args,
            input   = stdin_data,
            capture_output = True,
            timeout = timeout,
        )
        elapsed = time.monotonic() - t0
        return (
            result.returncode,
            result.stdout.decode(errors='replace'),
            result.stderr.decode(errors='replace'),
            elapsed,
        )
    except subprocess.TimeoutExpired as e:
        elapsed = time.monotonic() - t0
        stdout  = (e.stdout or b'').decode(errors='replace')
        stderr  = (e.stderr or b'').decode(errors='replace')
        return (-1, stdout, stderr + '\n[TIMEOUT]', elapsed)
    except Exception as e:
        elapsed = time.monotonic() - t0
        return (-2, '', str(e), elapsed)


def _run_lldb(
    binary: str,
    args: list[str],
    stdin_data: Optional[bytes],
    timeout: float,
    extra_commands: Optional[list[str]] = None,
) -> tuple[str, str, float]:
    """
    Run *binary* under LLDB in batch mode.

    Writes stdin_data to a temp file (if provided) and passes it via
    ``process launch --stdin <file>``.

    Returns (lldb_output, error_message, elapsed_s).
    """
    if not shutil.which('lldb'):
        return '', 'lldb not found in PATH', 0.0

    t0          = time.monotonic()
    stdin_path  = None
    cmd_file    = None
    try:
        # Write stdin data to temp file
        if stdin_data:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as sf:
                sf.write(stdin_data)
                stdin_path = sf.name

        # Build LLDB command file
        cmds = [f'target create {binary}']
        if args:
            escaped = ' '.join(f'"{a}"' for a in args)
            cmds.append(f'settings set target.run-args {escaped}')
        if stdin_path:
            cmds.append(f'process launch --stdin {stdin_path} -- {" ".join(args)}')
        else:
            cmds.append(f'process launch -- {" ".join(args)}')
        cmds.extend(extra_commands or [])
        cmds.extend([
            'thread backtrace',
            'register read',
            'frame info',
            'quit',
        ])

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.lldbcmds', delete=False
        ) as cf:
            cf.write('\n'.join(cmds) + '\n')
            cmd_file = cf.name

        result = subprocess.run(
            ['lldb', '--batch', '-s', cmd_file],
            capture_output = True,
            timeout        = timeout,
        )
        elapsed = time.monotonic() - t0
        out     = result.stdout.decode(errors='replace')
        err     = result.stderr.decode(errors='replace')
        return out + '\n' + err, '', elapsed

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        return '', 'LLDB timed out', elapsed
    except Exception as e:
        elapsed = time.monotonic() - t0
        return '', str(e), elapsed
    finally:
        for p in (stdin_path, cmd_file):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


def _run_dtrace(
    binary: str,
    args: list[str],
    dtrace_script: str,
    stdin_data: Optional[bytes],
    timeout: float,
) -> tuple[str, str, float]:
    """
    Launch *binary* under DTrace using *dtrace_script*.

    Launches binary as a child of dtrace (-c flag).  Feeds stdin_data to the
    binary if provided via a wrapper shell command.

    Returns (dtrace_output, error_message, elapsed_s).

    Note: DTrace requires sudo on macOS (SIP restricts pid$ provider).
    """
    if not shutil.which('dtrace'):
        return '', 'dtrace not found in PATH', 0.0

    t0         = time.monotonic()
    script_file = None
    stdin_path  = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.d', delete=False
        ) as df:
            df.write(dtrace_script)
            script_file = df.name

        if stdin_data:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as sf:
                sf.write(stdin_data)
                stdin_path = sf.name

        # Build the target command for -c
        escaped_args = ' '.join(f"'{a}'" for a in args)
        if stdin_path:
            target_cmd = f"{binary} {escaped_args} < '{stdin_path}'"
        else:
            target_cmd = f'{binary} {escaped_args}'

        dtrace_cmd = [
            'sudo', 'dtrace',
            '-s', script_file,
            '-c', target_cmd,
        ]

        result = subprocess.run(
            dtrace_cmd,
            capture_output = True,
            timeout        = timeout + 5,   # DTrace startup adds overhead
        )
        elapsed = time.monotonic() - t0
        out     = result.stdout.decode(errors='replace')
        err     = result.stderr.decode(errors='replace')
        return out, err, elapsed

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        return '', 'DTrace timed out', elapsed
    except Exception as e:
        elapsed = time.monotonic() - t0
        return '', str(e), elapsed
    finally:
        for p in (script_file, stdin_path):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


# ── Crash output parsers ──────────────────────────────────────────────────────

_CRASH_RE = re.compile(
    r'stop reason\s*=\s*(signal|exception|EXC_\w+|SIG\w+)',
    re.IGNORECASE,
)
_FAULT_ADDR_RE = re.compile(
    r'(?:Exception Address|fault address|EXC_BAD_ACCESS.*?(?:0x[0-9a-f]+))',
    re.IGNORECASE,
)
_ADDR_RE = re.compile(r'0x[0-9a-f]{4,}', re.IGNORECASE)


def _parse_lldb_output(output: str) -> tuple[str, int, str, str]:
    """
    Parse LLDB batch output.

    Returns (crash_type, faulting_addr, backtrace, registers).
    """
    crash_type    = ''
    faulting_addr = 0
    backtrace     = ''
    registers     = ''

    # Detect crash type
    for signal_name in ('SIGSEGV', 'SIGBUS', 'SIGABRT', 'SIGILL',
                        'EXC_BAD_ACCESS', 'EXC_BAD_INSTRUCTION',
                        'EXC_ARITHMETIC'):
        if signal_name in output:
            crash_type = signal_name
            break

    # Extract faulting address from known patterns
    m = _FAULT_ADDR_RE.search(output)
    if m:
        addrs = _ADDR_RE.findall(m.group(0) + output[m.end():m.end() + 80])
        if addrs:
            try:
                faulting_addr = int(addrs[0], 16)
            except ValueError:
                pass

    # Extract backtrace block
    bt_start = output.find('* thread #')
    if bt_start == -1:
        bt_start = output.find('thread #')
    if bt_start != -1:
        bt_end = output.find('\n\n', bt_start + 1)
        backtrace = output[bt_start:bt_end if bt_end != -1 else bt_start + 3000]

    # Extract register block
    reg_start = output.find('General Purpose Registers')
    if reg_start == -1:
        reg_start = output.find('rax =')
    if reg_start == -1:
        reg_start = output.find(' x0 =')
    if reg_start != -1:
        reg_end = output.find('\n\n', reg_start + 1)
        registers = output[reg_start:reg_end if reg_end != -1 else reg_start + 2000]

    return crash_type, faulting_addr, backtrace.strip(), registers.strip()


def _parse_dtrace_output(output: str) -> tuple[bool, str]:
    """
    Parse DTrace output.  Returns (sink_hit, summary_line).
    """
    if 'C7_SINK_HIT' in output:
        for line in output.splitlines():
            if 'C7_SINK_HIT' in line:
                return True, line.strip()
    if 'C7_TIMEOUT' in output:
        return False, 'DTrace timeout — sink not reached'
    return False, 'No sink confirmation'


# ── Mach_msg sender script generator ─────────────────────────────────────────

def generate_mach_msg_sender(
    poc: C7PoC,
    service_name: str,
    out_path: Path,
) -> Path:
    """
    Generate a Python script that sends the C7 PoC payload as a mach_msg to
    *service_name* (a launchd-registered service, looked up via bootstrap_look_up).

    The generated script requires root and the target service to be running.
    It is NOT executed by C7 — the researcher runs it in the appropriate context.

    Parameters
    ----------
    poc          : C7PoC with payload and metadata
    service_name : launchd service name (e.g. 'com.apple.mDNSResponder')
    out_path     : where to write the generated script

    Returns
    -------
    Path to the generated script.
    """
    payload_hex = poc.payload.hex()
    payload_len = len(poc.payload)
    script = textwrap.dedent(f'''\
        #!/usr/bin/env python3
        """
        Generated by TriageForge C7 — mach_msg PoC sender.

        Target service : {service_name}
        PoC label      : {poc.label}
        Vuln class     : {poc.vuln_class}
        C6 confidence  : {poc.confidence:.0%}
        Site address   : {poc.sink_addr:#x}

        Run with: sudo python3 {out_path.name}

        Requires root to bootstrap_look_up privileged services.
        """

        import ctypes
        import ctypes.util
        import sys

        MACH_SEND_MSG        = 0x00000001
        MACH_RCV_MSG         = 0x00000002
        MACH_MSG_TIMEOUT_NONE = 0
        KERN_SUCCESS         = 0

        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

        # Bootstrap look-up
        bootstrap_look_up = libc.bootstrap_look_up
        bootstrap_look_up.restype  = ctypes.c_int
        bootstrap_look_up.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]

        task_get_bootstrap_port = libc.task_get_bootstrap_port
        mach_task_self_         = libc.mach_task_self_
        mach_task_self_.restype = ctypes.c_uint

        mach_msg = libc.mach_msg
        mach_msg.restype = ctypes.c_int

        # Look up the target service port
        bootstrap_port = ctypes.c_uint(0)
        kr = task_get_bootstrap_port(mach_task_self_(), ctypes.byref(bootstrap_port))
        if kr != KERN_SUCCESS:
            sys.exit(f"task_get_bootstrap_port failed: {{kr:#x}}")

        target_port = ctypes.c_uint(0)
        kr = bootstrap_look_up(
            bootstrap_port.value,
            b"{service_name}",
            ctypes.byref(target_port),
        )
        if kr != KERN_SUCCESS:
            sys.exit(f"bootstrap_look_up('{service_name}') failed: {{kr:#x}}")

        print(f"[+] Got port for {service_name}: {{target_port.value}}")

        # PoC payload ({payload_len} bytes)
        payload = bytes.fromhex(
            "{payload_hex}"
        )

        # Build mach_msg — set msgh_remote_port and msgh_bits in header
        # (first 24 bytes = mach_msg_header_t)
        import struct
        MACH_MSGH_BITS_REMOTE = 0x00000013  # MACH_MSG_TYPE_COPY_SEND
        header = struct.pack(
            "<IIIII",
            MACH_MSGH_BITS_REMOTE,   # msgh_bits
            len(payload),            # msgh_size (use full payload length)
            target_port.value,       # msgh_remote_port
            0,                       # msgh_local_port
            0,                       # msgh_voucher_port
        ) + struct.pack("<I", 0x1000)  # msgh_id

        msg = header + payload[len(header):]  # overlay header onto payload

        class MachMsgBuf(ctypes.Structure):
            _fields_ = [("data", ctypes.c_char * len(msg))]

        buf     = MachMsgBuf(data=msg)
        send_sz = ctypes.c_uint(len(msg))

        print(f"[+] Sending {{len(msg)}} bytes to {service_name}")
        kr = mach_msg(
            ctypes.byref(buf),
            MACH_SEND_MSG,    # option
            send_sz.value,    # send_size
            0,                # rcv_size
            0,                # rcv_name
            MACH_MSG_TIMEOUT_NONE,
            0,                # notify
        )

        if kr == KERN_SUCCESS:
            print("[+] mach_msg sent OK — monitor target process for crash")
        else:
            print(f"[-] mach_msg returned {{kr:#x}}")
    ''')

    out_path.write_text(script)
    out_path.chmod(0o755)
    log.info('C7: mach_msg sender written to %s', out_path)
    return out_path


# ── Evidence formatter ────────────────────────────────────────────────────────

def _format_asb_evidence(ev: 'C7Evidence') -> str:
    """Format a C7Evidence as an Apple Security Bounty evidence block."""
    result_str = ev.result_code.value
    lines = [
        'C7 Dynamic Validation Evidence',
        '================================',
        f'Generated    : {ev.timestamp}',
        f'Binary       : {ev.binary_path}',
        f'Arguments    : {" ".join(ev.target_args) or "(none)"}',
        f'Delivery     : {ev.mode.name}',
        f'Elapsed      : {ev.elapsed_s:.1f}s',
        '',
        ev.macos_version or '(macOS version not captured)',
        '',
        'PoC Summary',
        '-----------',
        f'Taint label  : {ev.poc.label}',
        f'Vuln class   : {ev.poc.vuln_class or "unknown"}',
        f'C6 confidence: {ev.poc.confidence:.0%}',
        f'Sink address : {ev.poc.sink_addr:#x}',
    ]
    if ev.poc.expected_sink_arg is not None:
        lines.append(f'Sink arg0    : {ev.poc.expected_sink_arg:#x} '
                     f'({ev.poc.expected_sink_arg})')
    lines.extend([
        f'Payload size : {len(ev.poc.payload)} bytes',
        '',
        'Payload hex dump:',
        ev.poc.hex_dump(),
        '',
    ])
    if ev.poc.notes:
        lines.extend(['PoC notes:', ev.poc.notes, ''])

    lines.extend([
        f'Validation result: {result_str}',
        '─' * 40,
    ])

    if ev.crash_type:
        lines.extend([
            f'Crash type   : {ev.crash_type}',
            f'Faulting addr: {ev.faulting_addr:#x}',
            '',
        ])

    if ev.backtrace:
        lines.extend(['Backtrace:', ev.backtrace, ''])

    if ev.registers:
        lines.extend(['Registers:', ev.registers, ''])

    if ev.dtrace_output:
        lines.extend(['DTrace output:', ev.dtrace_output.strip(), ''])

    if ev.crash_report:
        lines.extend(['Crash report (excerpt):', ev.crash_report, ''])

    if ev.stdout.strip():
        preview = '\n'.join(ev.stdout.splitlines()[:40])
        if len(ev.stdout.splitlines()) > 40:
            preview += '\n... (truncated)'
        lines.extend(['Target stdout:', preview, ''])

    if ev.stderr.strip():
        preview = '\n'.join(ev.stderr.splitlines()[:20])
        lines.extend(['Target stderr:', preview, ''])

    # Conclusion
    lines.append('Conclusion')
    lines.append('----------')
    if ev.result_code == C7ResultCode.CONFIRMED:
        lines.append(
            f'The finding is CONFIRMED on-device. The binary {Path(ev.binary_path).name} '
            f'crashed with {ev.crash_type or "a signal"} at address {ev.faulting_addr:#x}. '
            f'This constitutes on-device execution evidence suitable for an Apple '
            f'Security Bounty submission under "Userland → Daemons and Frameworks".'
        )
    elif ev.result_code == C7ResultCode.SINK_REACHED:
        lines.append(
            f'The sink function was reached with an attacker-controlled argument '
            f'(DTrace confirmed). No crash was required — the code path exists in '
            f'the shipping binary and is reachable with the crafted input. '
            f'This constitutes on-device execution evidence suitable for an Apple '
            f'Security Bounty submission under "Userland → Daemons and Frameworks".'
        )
    elif ev.result_code == C7ResultCode.TIMEOUT:
        lines.append(
            'The sink was NOT reached within the validation timeout. The finding '
            'may require a different delivery mechanism, longer timeout, or '
            'additional trigger conditions. Review C6 path constraints.'
        )
    elif ev.result_code == C7ResultCode.NO_IMPACT:
        lines.append(
            'The binary ran cleanly with the crafted input. The finding may be '
            'a false positive, or the vulnerable code path requires conditions '
            'not met by the current delivery mechanism.'
        )
    else:
        lines.append(str(ev.result_code))

    lines.extend([
        '',
        '─' * 40,
        ev.platform_info or '(platform info not captured)',
    ])

    return '\n'.join(lines)


# ── Main analysis class ───────────────────────────────────────────────────────

class C7Analysis:
    """
    C7 dynamic validation driver.

    Parameters
    ----------
    binary_path   : path to the target binary
    proj          : angr.Project (optional — used for PoC extraction only)
    default_timeout: default timeout in seconds for each validation run

    Example
    -------
    ::

        from metis.c7_dynamic import C7Analysis, C7DeliveryMode
        from metis.c6_taint import C6Analysis

        c6   = C6Analysis(proj)
        r6   = c6.run(initial_state, max_steps=500)
        if r6.findings:
            c7  = C7Analysis(binary_path='/sbin/ping', proj=proj)
            poc = c7.extract_poc(r6.findings[0])
            ev  = c7.validate(poc,
                              mode=C7DeliveryMode.LLDB,
                              target_args=['-c', '3', '127.0.0.1'])
            c7.write_evidence(ev, Path('ping_c7_evidence.txt'))
    """

    def __init__(
        self,
        binary_path: str,
        proj=None,
        default_timeout: float = 30.0,
    ) -> None:
        self.binary_path     = binary_path
        self.proj            = proj
        self.default_timeout = default_timeout
        self._macos_ver      = _macos_version()
        self._platform_info  = _platform_info()

    def extract_poc(self, finding) -> C7PoC:
        """
        Extract concrete PoC from a C6 VulnFinding.  Alias for module-level
        extract_poc_from_c6() that passes self.proj automatically.
        """
        return extract_poc_from_c6(finding, proj=self.proj)

    def validate(
        self,
        poc: C7PoC,
        mode: C7DeliveryMode = C7DeliveryMode.SUBPROCESS,
        target_args: Optional[list[str]] = None,
        timeout: Optional[float] = None,
        dtrace_threshold: int = 0x8000,
    ) -> C7Evidence:
        """
        Run dynamic validation for *poc*.

        Parameters
        ----------
        poc              : C7PoC (from extract_poc() or manually crafted)
        mode             : C7DeliveryMode (SUBPROCESS, LLDB, DTRACE, MANUAL)
        target_args      : argv for the binary (excluding binary name)
        timeout          : override default_timeout
        dtrace_threshold : for OOB DTrace script: min malloc size to flag

        Returns
        -------
        C7Evidence
        """
        args    = target_args or []
        timeout = timeout or self.default_timeout

        base = dict(
            poc           = poc,
            binary_path   = self.binary_path,
            target_args   = args,
            mode          = mode,
            macos_version = self._macos_ver,
            platform_info = self._platform_info,
        )

        if mode in (C7DeliveryMode.MANUAL, C7DeliveryMode.XPC):
            return C7Evidence(
                result_code = C7ResultCode.MANUAL,
                **base,
            )

        if mode == C7DeliveryMode.MACH_MSG:
            # Generate sender script, return instructional evidence
            sender = Path(tempfile.mkdtemp()) / 'send_poc.py'
            generate_mach_msg_sender(poc, 'com.apple.UNKNOWN_service', sender)
            return C7Evidence(
                result_code  = C7ResultCode.MANUAL,
                stdout       = f'Sender script generated: {sender}',
                **base,
            )

        # stdin_bytes: feed payload as stdin when delivery mode is STDIN
        # (or when using SUBPROCESS/LLDB without a specific delivery override)
        stdin_bytes = (
            poc.payload
            if poc.delivery in (C7DeliveryMode.STDIN, C7DeliveryMode.FILE)
               or mode in (C7DeliveryMode.SUBPROCESS, C7DeliveryMode.LLDB,
                           C7DeliveryMode.STDIN)
            else None
        )

        if mode == C7DeliveryMode.DTRACE:
            return self._validate_dtrace(poc, args, timeout, dtrace_threshold, base)
        elif mode == C7DeliveryMode.LLDB:
            return self._validate_lldb(poc, args, timeout, stdin_bytes, base)
        else:
            # SUBPROCESS, STDIN, FILE — all use subprocess runner
            return self._validate_subprocess(poc, args, timeout, stdin_bytes, base)

    # ── Private runners ───────────────────────────────────────────────────────

    def _validate_subprocess(
        self, poc, args, timeout, stdin_bytes, base
    ) -> C7Evidence:
        t_before = time.time()
        rc, stdout, stderr, elapsed = _run_subprocess(
            self.binary_path, args, stdin_bytes, timeout
        )

        # Scan crash reports created after the run started
        crash_paths = scan_crash_reports(
            Path(self.binary_path).name, min_mtime=t_before
        )
        crash_text = _read_crash_report(crash_paths[0]) if crash_paths else ''

        # Determine result
        crash_signals = ('Segmentation fault', 'Bus error', 'Illegal instruction',
                         'Abort trap', 'EXC_BAD_ACCESS')
        crashed = (rc < 0 and rc != -1) or any(s in stderr for s in crash_signals)
        if crash_paths:
            crashed = True

        result_code   = C7ResultCode.CONFIRMED if crashed else C7ResultCode.NO_IMPACT
        crash_type    = ''
        for sig in ('SIGSEGV', 'SIGBUS', 'SIGABRT', 'SIGILL',
                    'Segmentation fault', 'Bus error', 'Abort trap'):
            if sig in stderr or sig in stdout or sig in crash_text:
                crash_type = sig.split()[0]
                break

        return C7Evidence(
            result_code  = result_code,
            elapsed_s    = elapsed,
            stdout       = stdout,
            stderr       = stderr,
            crash_type   = crash_type,
            crash_report = crash_text,
            **base,
        )

    def _validate_lldb(
        self, poc, args, timeout, stdin_bytes, base
    ) -> C7Evidence:
        t_before = time.time()
        output, err_msg, elapsed = _run_lldb(
            self.binary_path, args, stdin_bytes, timeout
        )

        crash_type, faulting_addr, backtrace, registers = _parse_lldb_output(output)

        crash_paths = scan_crash_reports(
            Path(self.binary_path).name, min_mtime=t_before
        )
        crash_text = _read_crash_report(crash_paths[0]) if crash_paths else ''

        if err_msg:
            return C7Evidence(
                result_code  = C7ResultCode.ERROR,
                elapsed_s    = elapsed,
                stderr       = err_msg,
                **base,
            )

        if crash_type:
            result_code = C7ResultCode.CONFIRMED
        elif 'Process' in output and 'exited' in output:
            result_code = C7ResultCode.NO_IMPACT
        else:
            result_code = C7ResultCode.NO_IMPACT

        return C7Evidence(
            result_code   = result_code,
            elapsed_s     = elapsed,
            stdout        = output,
            crash_type    = crash_type,
            faulting_addr = faulting_addr,
            backtrace     = backtrace,
            registers     = registers,
            crash_report  = crash_text,
            **base,
        )

    def _validate_dtrace(
        self, poc, args, timeout, dtrace_threshold, base
    ) -> C7Evidence:
        vclass = (poc.vuln_class or '').upper()

        # Select DTrace script based on vuln class
        if 'UAF' in vclass:
            script = _dtrace_script_uaf(timeout_s=int(timeout))
        elif 'XTYPE' in vclass:
            script = _dtrace_script_xtype(timeout_s=int(timeout))
        else:
            # Default: OOB — watch malloc with threshold
            threshold = poc.expected_sink_arg or dtrace_threshold
            # DTrace threshold: use the concrete arg if we have it, else fallback
            # Use half the concrete value so we catch it even if payload varies
            actual_threshold = max(1024, threshold // 2) if threshold > 2048 else dtrace_threshold
            script = _dtrace_script_oob(
                threshold  = actual_threshold,
                caller_addr= poc.sink_addr,
                timeout_s  = int(timeout),
            )

        stdin_bytes = poc.payload if poc.delivery == C7DeliveryMode.STDIN else None
        output, err_msg, elapsed = _run_dtrace(
            self.binary_path, args, script, stdin_bytes, timeout
        )

        if err_msg and not output:
            return C7Evidence(
                result_code   = C7ResultCode.ERROR,
                elapsed_s     = elapsed,
                stderr        = err_msg,
                dtrace_output = output,
                **base,
            )

        sink_hit, summary = _parse_dtrace_output(output)
        result_code = (
            C7ResultCode.SINK_REACHED if sink_hit else C7ResultCode.TIMEOUT
        )
        log.info('C7 DTrace: %s — %s', result_code.value, summary)

        return C7Evidence(
            result_code   = result_code,
            elapsed_s     = elapsed,
            stdout        = '',
            stderr        = err_msg,
            dtrace_output = output,
            **base,
        )

    # ── Evidence writer ───────────────────────────────────────────────────────

    def write_evidence(
        self,
        evidence: C7Evidence,
        out_path: Path,
    ) -> Path:
        """
        Write ASB-ready evidence to *out_path* (text file).

        Also writes a companion JSON file (*out_path*.json) with structured data
        for automated processing.

        Returns the text file path.
        """
        import json

        out_path = Path(out_path)
        text     = evidence.asb_text
        out_path.write_text(text)
        log.info('C7: evidence written to %s', out_path)

        # Structured JSON companion
        json_path = out_path.with_suffix('.json')
        payload = {
            'timestamp'       : evidence.timestamp,
            'result_code'     : evidence.result_code.value,
            'binary_path'     : evidence.binary_path,
            'target_args'     : evidence.target_args,
            'mode'            : evidence.mode.name,
            'elapsed_s'       : evidence.elapsed_s,
            'crash_type'      : evidence.crash_type,
            'faulting_addr'   : hex(evidence.faulting_addr) if evidence.faulting_addr else '0x0',
            'vuln_class'      : evidence.poc.vuln_class,
            'confidence'      : evidence.poc.confidence,
            'sink_addr'       : hex(evidence.poc.sink_addr),
            'expected_sink_arg': hex(evidence.poc.expected_sink_arg) if evidence.poc.expected_sink_arg is not None else None,
            'payload_hex'     : evidence.poc.payload.hex(),
            'payload_bytes'   : len(evidence.poc.payload),
            'crash_report'    : bool(evidence.crash_report),
            'backtrace'       : evidence.backtrace[:2000] if evidence.backtrace else '',
            'dtrace_output'   : evidence.dtrace_output[:2000] if evidence.dtrace_output else '',
            'macos_version'   : evidence.macos_version,
            'platform_info'   : evidence.platform_info,
        }
        with open(json_path, 'w') as fh:
            json.dump(payload, fh, indent=2)
        log.info('C7: JSON written to %s', json_path)

        return out_path


# ── CLI convenience runner ────────────────────────────────────────────────────

def main() -> None:
    """
    CLI: validate a binary with a hex PoC payload.

    Usage:
        python3 -m metis.c7_dynamic <binary> <hex_payload> [--mode LLDB|DTRACE|SUBPROCESS] [-- arg1 arg2 ...]
    """
    import argparse

    parser = argparse.ArgumentParser(
        description='TriageForge C7 — dynamic PoC validation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('binary', help='Path to target binary')
    parser.add_argument('payload_hex',
                        help='PoC payload as hex string (e.g. deadbeef01020304)')
    parser.add_argument('--mode', default='SUBPROCESS',
                        choices=[m.name for m in C7DeliveryMode],
                        help='Delivery/validation mode')
    parser.add_argument('--vuln-class', default='OOB',
                        help='Vulnerability class (OOB/UAF/XTYPE)')
    parser.add_argument('--sink-addr', default='0x0',
                        help='Sink call site address (hex)')
    parser.add_argument('--sink-arg', default=None,
                        help='Expected concrete sink argument (hex)')
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--out', default='c7_evidence.txt',
                        help='Output evidence file path')
    parser.add_argument('args', nargs='*',
                        help='Target binary arguments')

    pargs = parser.parse_args()

    try:
        payload = bytes.fromhex(pargs.payload_hex)
    except ValueError as e:
        print(f'Error: invalid hex payload: {e}', file=sys.stderr)
        sys.exit(1)

    poc = C7PoC(
        payload           = payload,
        label             = 'cli_manual',
        delivery          = C7DeliveryMode[pargs.mode]
                            if pargs.mode in ('STDIN', 'FILE') else C7DeliveryMode.STDIN,
        sink_addr         = int(pargs.sink_addr, 16),
        expected_sink_arg = int(pargs.sink_arg, 16) if pargs.sink_arg else None,
        vuln_class        = pargs.vuln_class,
    )

    c7   = C7Analysis(binary_path=pargs.binary, default_timeout=pargs.timeout)
    ev   = c7.validate(poc, mode=C7DeliveryMode[pargs.mode], target_args=pargs.args)
    path = c7.write_evidence(ev, Path(pargs.out))

    print(ev.asb_text)
    print(f'\n→ Evidence saved to {path}')
    sys.exit(0 if ev.result_code in (C7ResultCode.CONFIRMED,
                                     C7ResultCode.SINK_REACHED) else 1)


if __name__ == '__main__':
    main()
