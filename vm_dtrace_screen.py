#!/usr/bin/env python3
"""
vm_dtrace_screen.py — System-wide DTrace syscall profiler for macOS arm64 VM

Captures ALL syscalls system-wide for PROBE_SECS seconds, then aggregates
per-process. This catches daemons that wake up naturally during normal
operation (mDNSResponder answering queries, securityd handling auth, etc.)
rather than trying to probe each idle PID individually.

Attack-surface scoring:
  network syscalls (recv*, accept, recvmsg)   weight 4
  mach IPC (mach_msg*)                        weight 3
  exec/fork                                   weight 5
  file ops (open/read/write)                  weight 2
  syscall variety bonus                       weight 1

Outputs:
  vm_dtrace_results.json   — full ranked results
  vm_dtrace_report.txt     — human-readable ranked report

Usage (run as root on SIP-disabled VM):
  sudo python3 vm_dtrace_screen.py [--secs 30] [--outdir ~/darwin_research/findings]
"""
from __future__ import annotations
import sys, os, json, subprocess, re, argparse, tempfile
from pathlib import Path
from typing import Optional

parser = argparse.ArgumentParser()
parser.add_argument('--secs',   type=int, default=30,
                    help='Capture duration in seconds (default 30)')
parser.add_argument('--outdir', default=str(Path.home() / 'darwin_research/findings'))
args = parser.parse_args()

OUT = Path(args.outdir)
OUT.mkdir(parents=True, exist_ok=True)

# ── DTrace script — system-wide, no PID filter ────────────────────────────────
DTRACE_SCRIPT = r"""
#pragma D option quiet

syscall:::entry
{
    @sc[execname, probefunc] = count();
}

mach_trap:::entry
{
    @mt[execname, probefunc] = count();
}

tick-{secs}s
{
    printf("==SYSCALLS==\n");
    printa("%s\t%s\t%@d\n", @sc);
    printf("==MACH==\n");
    printa("%s\t%s\t%@d\n", @mt);
    exit(0);
}
"""

NETWORK_CALLS = {'recvfrom','recvmsg','recv','accept','accept_nocancel',
                 'recvfrom_nocancel','recvmsg_nocancel','read_nocancel'}
EXEC_CALLS    = {'execve','posix_spawn','fork','vfork'}
MACH_IPC      = {'mach_msg','mach_msg_overwrite','mach_msg2_internal','mach_msg_trap'}
FILE_CALLS    = {'open','read','write','open_nocancel','pread','pwrite','openat',
                 'openat_nocancel'}

# Daemons to skip (noise: launchd, kernel_task, dtrace itself, shells)
SKIP_PROCS = {'kernel_task','launchd','dtrace','python3','bash','sh','zsh',
              'mds','mds_stores','hidd','WindowServer','Dock','Finder',
              'loginwindow','distnoted','cfprefsd','notifyd','UserEventAgent'}

def score(sc: dict, mt: dict) -> float:
    s = 0.0
    for call, n in sc.items():
        if call in NETWORK_CALLS:  s += 4 * min(n, 50)
        elif call in EXEC_CALLS:   s += 5 * min(n, 10)
        elif call in FILE_CALLS:   s += 2 * min(n, 20)
        else:                      s += 0.3
    for call, n in mt.items():
        if call in MACH_IPC:       s += 3 * min(n, 50)
        else:                      s += 0.5
    s += len(sc) * 1.0
    return round(s, 2)

if os.geteuid() != 0:
    print('[!] DTrace requires root. Run with: sudo python3 vm_dtrace_screen.py')
    sys.exit(1)

script = DTRACE_SCRIPT.replace('{secs}', str(args.secs))
with tempfile.NamedTemporaryFile(suffix='.d', mode='w', delete=False) as f:
    f.write(script)
    script_path = f.name

print(f'[*] System-wide DTrace profiler — macOS arm64 VM')
print(f'    Capturing for {args.secs}s across all processes...')
print(f'    Output: {OUT}')

try:
    result = subprocess.run(
        ['dtrace', '-q', '-s', script_path],
        capture_output=True, text=True,
        timeout=args.secs + 30
    )
    output = result.stdout
    if result.stderr:
        # Print DTrace warnings/errors but continue
        for line in result.stderr.splitlines():
            if line.strip() and 'WARNING' not in line:
                print(f'  dtrace: {line}')
finally:
    os.unlink(script_path)

# ── Parse output ─────────────────────────────────────────────────────────────
# Each line: execname \t probefunc \t count
by_proc: dict[str, dict] = {}   # execname → {sc: {}, mt: {}}

section = None
for line in output.splitlines():
    line = line.strip()
    if line == '==SYSCALLS==':
        section = 'sc'
        continue
    elif line == '==MACH==':
        section = 'mt'
        continue
    if not line or not section:
        continue
    parts = line.split('\t')
    if len(parts) != 3:
        continue
    proc, call, count_str = parts
    try:
        count = int(count_str)
    except ValueError:
        continue
    if proc in SKIP_PROCS:
        continue
    if proc not in by_proc:
        by_proc[proc] = {'sc': {}, 'mt': {}}
    by_proc[proc][section][call] = by_proc[proc][section].get(call, 0) + count

print(f'[*] Captured activity from {len(by_proc)} distinct processes')

# ── Score and rank ────────────────────────────────────────────────────────────
results = []
for proc, data in by_proc.items():
    sc, mt = data['sc'], data['mt']
    s = score(sc, mt)
    results.append({
        'proc':    proc,
        'score':   s,
        'syscalls': sc,
        'mach':    mt,
        'network': [k for k in sc if k in NETWORK_CALLS],
        'exec':    [k for k in sc if k in EXEC_CALLS],
        'ipc':     [k for k in mt if k in MACH_IPC],
        'n_sc':    len(sc),
    })

results.sort(key=lambda r: r['score'], reverse=True)

# ── Output ────────────────────────────────────────────────────────────────────
json_out = OUT / 'vm_dtrace_results.json'
json_out.write_text(json.dumps(results, indent=2))

lines = [
    'DTrace System-Wide Profiler — macOS arm64 VM',
    f'Capture duration: {args.secs}s',
    f'Active processes captured: {len(results)}',
    '=' * 70, ''
]
for r in results:
    net_str  = f"  NETWORK: {', '.join(r['network'])}" if r['network'] else ''
    exec_str = f"  EXEC:    {', '.join(r['exec'])}"    if r['exec']    else ''
    ipc_str  = f"  IPC:     {', '.join(r['ipc'])}"     if r['ipc']     else ''
    lines.append(f"[score={r['score']:7.1f}]  {r['proc']}")
    if net_str:  lines.append(net_str)
    if exec_str: lines.append(exec_str)
    if ipc_str:  lines.append(ipc_str)
    top_sc = sorted(r['syscalls'].items(), key=lambda x: -x[1])[:8]
    lines.append(f"  top syscalls: {', '.join(f'{k}×{v}' for k,v in top_sc)}")
    lines.append('')

txt_out = OUT / 'vm_dtrace_report.txt'
txt_out.write_text('\n'.join(lines))

print(f'\n[+] Top 20 daemons by attack-surface score:')
print(f'  {"Score":>8}  {"Proc":<40s}  {"Flags"}')
for r in results[:20]:
    flags = ''
    if r['network']:  flags += '*** NET '
    if r['exec']:     flags += '*** EXEC '
    if r['ipc']:      flags += 'IPC '
    print(f'  {r["score"]:8.1f}  {r["proc"]:<40s}  {flags}')

print(f'\n[+] JSON → {json_out}')
print(f'[+] Text → {txt_out}')
