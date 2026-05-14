"""
c7_dynamic.py — C7: Dynamic on-device validation of C6 symbolic findings.

VERSION: 2.1.0-ZDI
AUTHOR: Stuart Thomas, TriageForge

COPYRIGHT NOTICE
----------------
Copyright (c) 2026 Stuart Thomas, TriageForge. All rights reserved.
This software and associated documentation files are protected under the 
Copyright, Designs and Patents Act 1988 (CDPA). Unauthorized copying, 
modification, distribution, or use of this software, via any medium, is 
strictly prohibited without express written permission from the author.

Purpose
-------
C7 closes the loop between angr symbolic analysis and on-device evidence.
  C6 output  →  concrete PoC input  →  C7 on-device run  →  ASB-ready evidence

Validation Modes:
  SUBPROCESS — Launch binary, feed PoC via stdin/file/network. 
  LLDB       — Attach to PID or launch in batch mode. Captures crash/registers.
  DTRACE     — Attach DTrace probe to running daemon. Non-destructive sink confirmation.

Upgrades for v2.1.0:
  - Added NETWORK delivery mode with threaded delayed-send for debugger race conditions.
  - Added PID attach mode for background daemons.
  - Added async CrashReporter polling to capture delayed .ips files.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

VERSION = "2.1.0-ZDI"


# ── Delivery modes ────────────────────────────────────────────────────────────

class C7DeliveryMode(Enum):
    STDIN      = auto()   # feed PoC bytes as stdin to the target binary
    FILE       = auto()   # write PoC to a temp file, pass path as argument
    MACH_MSG   = auto()   # generate a mach_msg sender script
    XPC        = auto()   # generate an XPC sender script
    NETWORK    = auto()   # blast PoC bytes over UDP/TCP
    MANUAL     = auto()   # evidence recorded manually


class C7ResultCode(Enum):
    CONFIRMED    = 'CONFIRMED'
    SINK_REACHED = 'SINK_REACHED'
    TIMEOUT      = 'TIMEOUT'
    NO_IMPACT    = 'NO_IMPACT'
    ERROR        = 'ERROR'
    MANUAL       = 'MANUAL'


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class C7PoC:
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
        return _format_asb_evidence(self)


# ── Platform helpers & Crash Scanner ──────────────────────────────────────────

def _macos_version() -> str:
    try:
        return subprocess.check_output(['sw_vers'], text=True, timeout=5).strip()
    except Exception:
        return platform.platform()

def _platform_info() -> str:
    try:
        return subprocess.check_output(['uname', '-a'], text=True, timeout=5).strip()
    except Exception:
        return platform.uname()._asdict().__str__()

def scan_crash_reports(binary_name: str, min_mtime: float = 0.0) -> list[Path]:
    dirs = [
        Path.home() / 'Library' / 'Logs' / 'DiagnosticReports',
        Path('/Library/Logs/DiagnosticReports'),
    ]
    reports: list[Path] = []
    pattern = binary_name.replace('-', '').replace('_', '').lower()

    for d in dirs:
        if not d.is_dir(): continue
        for p in d.iterdir():
            if p.suffix not in ('.ips', '.crash'): continue
            if p.stat().st_mtime < min_mtime: continue
            if pattern in p.name.lower().replace('-', '').replace('_', ''):
                reports.append(p)

    return sorted(reports, key=lambda p: p.stat().st_mtime, reverse=True)

def _read_crash_report(path: Path, max_lines: int = 80) -> str:
    try:
        text = path.read_text(errors='replace')
        lines = text.splitlines()[:max_lines]
        if len(text.splitlines()) > max_lines:
            lines.append(f'... (truncated; full report at {path})')
        return '\n'.join(lines)
    except Exception as e:
        return f'[error reading {path}: {e}]'


# ── Network Delivery Thread ───────────────────────────────────────────────────

def _fire_network_payload(poc: C7PoC, ip: str, port: int, delay: float = 1.5):
    """Fires UDP payload in background to allow debuggers time to attach."""
    time.sleep(delay)
    log.info(f"C7: Firing {len(poc.payload)} bytes to {ip}:{port} via UDP")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(poc.payload, (ip, port))
    except Exception as e:
        log.error(f"C7 Network Delivery Failed: {e}")


# ── Core runners ──────────────────────────────────────────────────────────────

def _run_subprocess(binary: str, args: list[str], stdin_data: Optional[bytes], timeout: float) -> tuple[int, str, str, float]:
    t0 = time.monotonic()
    try:
        result = subprocess.run([binary] + args, input=stdin_data, capture_output=True, timeout=timeout)
        return result.returncode, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'), time.monotonic() - t0
    except subprocess.TimeoutExpired as e:
        return -1, (e.stdout or b'').decode(errors='replace'), (e.stderr or b'').decode(errors='replace') + '\n[TIMEOUT]', time.monotonic() - t0
    except Exception as e:
        return -2, '', str(e), time.monotonic() - t0

def _run_lldb(binary: str, args: list[str], stdin_data: Optional[bytes], timeout: float, target_pid: Optional[int] = None) -> tuple[str, str, float]:
    if not shutil.which('lldb'): return '', 'lldb not found in PATH', 0.0

    t0 = time.monotonic()
    stdin_path = None
    cmd_file = None
    try:
        if stdin_data and not target_pid:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as sf:
                sf.write(stdin_data)
                stdin_path = sf.name

        cmds = [f'target create {binary}']
        
        if target_pid:
            cmds.append(f'process attach --pid {target_pid}')
            cmds.append('continue')
        else:
            if args: cmds.append(f'settings set target.run-args {" ".join(f"{a}" for a in args)}')
            if stdin_path: cmds.append(f'process launch --stdin {stdin_path} -- {" ".join(args)}')
            else: cmds.append(f'process launch -- {" ".join(args)}')
            
        cmds.extend(['thread backtrace', 'register read', 'frame info', 'quit'])

        with tempfile.NamedTemporaryFile(mode='w', suffix='.lldbcmds', delete=False) as cf:
            cf.write('\n'.join(cmds) + '\n')
            cmd_file = cf.name

        result = subprocess.run(['lldb', '--batch', '-s', cmd_file], capture_output=True, timeout=timeout)
        return result.stdout.decode(errors='replace') + '\n' + result.stderr.decode(errors='replace'), '', time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return '', 'LLDB timed out', time.monotonic() - t0
    except Exception as e:
        return '', str(e), time.monotonic() - t0
    finally:
        for p in filter(None, [stdin_path, cmd_file]):
            try: os.unlink(p)
            except OSError: pass

# ... [DTRACE SCRIPT TEMPLATES AND _run_dtrace REMAIN IDENTICAL TO YOUR V1. JUST OMITTED FOR BREVITY BUT ASSUME FULL RETENTION IN ACTUAL FILE] ...

def _parse_lldb_output(output: str) -> tuple[str, int, str, str]:
    crash_type, faulting_addr, backtrace, registers = '', 0, '', ''
    for sig in ('SIGSEGV', 'SIGBUS', 'SIGABRT', 'SIGILL', 'EXC_BAD_ACCESS', 'EXC_BAD_INSTRUCTION'):
        if sig in output: crash_type = sig; break

    m = re.search(r'(?:Exception Address|fault address|EXC_BAD_ACCESS.*?(?:0x[0-9a-f]+))', output, re.IGNORECASE)
    if m:
        addrs = re.findall(r'0x[0-9a-f]{4,}', m.group(0) + output[m.end():m.end() + 80])
        if addrs:
            try: faulting_addr = int(addrs[0], 16)
            except ValueError: pass

    bt_start = output.find('* thread #') if output.find('* thread #') != -1 else output.find('thread #')
    if bt_start != -1:
        bt_end = output.find('\n\n', bt_start + 1)
        backtrace = output[bt_start:bt_end if bt_end != -1 else bt_start + 3000]

    reg_start = output.find('General Purpose Registers') if output.find('General Purpose Registers') != -1 else output.find('rax =')
    if reg_start != -1:
        reg_end = output.find('\n\n', reg_start + 1)
        registers = output[reg_start:reg_end if reg_end != -1 else reg_start + 2000]

    return crash_type, faulting_addr, backtrace.strip(), registers.strip()

# ── Evidence formatter ────────────────────────────────────────────────────────
def _format_asb_evidence(ev: 'C7Evidence') -> str:
    result_str = ev.result_code.value
    lines = [
        'C7 Dynamic Validation Evidence',
        '================================',
        f'TriageForge Toolchain v{VERSION}',
        f'Generated    : {ev.timestamp}',
        f'Binary       : {ev.binary_path}',
        f'Delivery     : {ev.mode.name}',
        f'Validation result: {result_str}',
        '─' * 40,
    ]
    
    if ev.crash_type:
        lines.extend([f'Crash type   : {ev.crash_type}', f'Faulting addr: {ev.faulting_addr:#x}', ''])
    if ev.backtrace: lines.extend(['Backtrace:', ev.backtrace, ''])
    if ev.registers: lines.extend(['Registers:', ev.registers, ''])
    if ev.crash_report: lines.extend(['Crash report (excerpt):', ev.crash_report, ''])
    
    lines.extend(['', 'Conclusion', '----------'])
    if ev.result_code == C7ResultCode.CONFIRMED:
        lines.append(f'CONFIRMED on-device. The binary {Path(ev.binary_path).name} crashed with {ev.crash_type}. '
                     f'This constitutes on-device execution evidence suitable for ASB submission.')
    return '\n'.join(lines)


# ── Main analysis class ───────────────────────────────────────────────────────
class C7Analysis:
    def __init__(self, binary_path: str, default_timeout: float = 30.0) -> None:
        self.binary_path = binary_path
        self.default_timeout = default_timeout
        self._macos_ver = _macos_version()
        self._platform_info = _platform_info()

    def validate(self, poc: C7PoC, mode: C7DeliveryMode = C7DeliveryMode.SUBPROCESS, 
                 target_args: Optional[list[str]] = None, timeout: Optional[float] = None, 
                 target_pid: Optional[int] = None, net_ip: str = '127.0.0.1', net_port: int = 67) -> C7Evidence:
        args = target_args or []
        timeout = timeout or self.default_timeout
        base = dict(poc=poc, binary_path=self.binary_path, target_args=args, mode=mode, macos_version=self._macos_ver, platform_info=self._platform_info)

        # Network delivery background thread
        if mode == C7DeliveryMode.NETWORK:
            threading.Thread(target=_fire_network_payload, args=(poc, net_ip, net_port), daemon=True).start()

        stdin_bytes = poc.payload if poc.delivery == C7DeliveryMode.STDIN else None

        if mode == C7DeliveryMode.LLDB:
            return self._validate_lldb(poc, args, timeout, stdin_bytes, target_pid, base)
        else:
            return self._validate_subprocess(poc, args, timeout, stdin_bytes, base)

    def _validate_subprocess(self, poc, args, timeout, stdin_bytes, base) -> C7Evidence:
        t_before = time.time()
        rc, stdout, stderr, elapsed = _run_subprocess(self.binary_path, args, stdin_bytes, timeout)

        # Async Crash Polling
        crash_text, crash_type = '', ''
        for _ in range(10):
            crash_paths = scan_crash_reports(Path(self.binary_path).name, min_mtime=t_before)
            if crash_paths:
                crash_text = _read_crash_report(crash_paths[0])
                break
            time.sleep(1.0)

        crashed = (rc < 0 and rc != -1) or bool(crash_paths)
        if crashed and not crash_type:
            for sig in ('SIGSEGV', 'SIGBUS', 'SIGABRT', 'SIGILL', 'EXC_BAD_ACCESS'):
                if sig in stderr or sig in crash_text: crash_type = sig; break

        return C7Evidence(result_code=C7ResultCode.CONFIRMED if crashed else C7ResultCode.NO_IMPACT, elapsed_s=elapsed, stdout=stdout, stderr=stderr, crash_type=crash_type, crash_report=crash_text, **base)

    def _validate_lldb(self, poc, args, timeout, stdin_bytes, target_pid, base) -> C7Evidence:
        t_before = time.time()
        output, err_msg, elapsed = _run_lldb(self.binary_path, args, stdin_bytes, timeout, target_pid)
        crash_type, faulting_addr, backtrace, registers = _parse_lldb_output(output)

        # Async Crash Polling
        crash_text = ''
        for _ in range(10):
            crash_paths = scan_crash_reports(Path(self.binary_path).name, min_mtime=t_before)
            if crash_paths:
                crash_text = _read_crash_report(crash_paths[0])
                break
            time.sleep(1.0)

        result_code = C7ResultCode.CONFIRMED if crash_type else C7ResultCode.NO_IMPACT
        return C7Evidence(result_code=result_code, elapsed_s=elapsed, stdout=output, crash_type=crash_type, faulting_addr=faulting_addr, backtrace=backtrace, registers=registers, crash_report=crash_text, **base)

    def write_evidence(self, evidence: C7Evidence, out_path: Path) -> Path:
        out_path.write_text(evidence.asb_text)
        return out_path


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=f'TriageForge C7 v{VERSION} — dynamic PoC validation')
    parser.add_argument('binary', help='Path to target binary')
    parser.add_argument('payload_hex', help='PoC payload as hex string')
    parser.add_argument('--mode', default='NETWORK', choices=[m.name for m in C7DeliveryMode])
    parser.add_argument('--pid', type=int, help='Attach to running PID (Daemon mode)')
    parser.add_argument('--ip', default='127.0.0.1', help='Network target IP')
    parser.add_argument('--port', type=int, default=67, help='Network target Port')
    parser.add_argument('--out', default='c7_evidence.txt')
    pargs = parser.parse_args()

    poc = C7PoC(payload=bytes.fromhex(pargs.payload_hex), label='cli_manual')
    c7 = C7Analysis(binary_path=pargs.binary)
    ev = c7.validate(poc, mode=C7DeliveryMode[pargs.mode], target_pid=pargs.pid, net_ip=pargs.ip, net_port=pargs.port)
    path = c7.write_evidence(ev, Path(pargs.out))
    print(ev.asb_text)
    sys.exit(0 if ev.result_code == C7ResultCode.CONFIRMED else 1)

if __name__ == '__main__':
    main()
