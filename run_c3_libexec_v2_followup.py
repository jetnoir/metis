#!/usr/bin/env python3
"""
run_c3_libexec_v2_followup.py — C3 template scan of top anomalous libexec binaries
from the overnight_libexec_v2.py Dell sweep.

Filters:
  - Postfix cluster (smtpd, smtp, lmtp, qmgr, showq, pickup, etc.) — third-party artifact
  - OpenSSH (ssh-keysign, ssh-pkcs11-helper, sftp-server, etc.) — third-party
  - OpenLDAP (slapconfig-keygen) — third-party
  - Already-closed targets from prior sessions

Targets: Apple-written daemons with high z_combined and plausible network/IPC
attack surface.

Run on Dell (has the arm64 thin slices):
  source ~/.venv_angr/bin/activate
  python3 toolchain/run_c3_libexec_v2_followup.py

Writes results to:
  findings/c3_libexec_v2_followup_hits.json
  findings/c3_libexec_v2_followup.log
"""
import sys, os, json, time, logging
from pathlib import Path

TOOLCHAIN = Path(__file__).parent
sys.path.insert(0, str(TOOLCHAIN))

import signal

import archinfo
import angr
from metis.fast_c2 import FastC2Analysis
from metis.c3_templates import C3TemplateAnalysis

OUTDIR    = TOOLCHAIN.parent / 'findings'
OUTDIR.mkdir(exist_ok=True)
HITS_FILE = OUTDIR / 'c3_libexec_v2_followup_hits.json'
LOG_FILE  = OUTDIR / 'c3_libexec_v2_followup.log'

logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(levelname)s %(message)s')

def log(msg):
    line = '[{}] {}'.format(time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    with open(LOG_FILE, 'a') as fh:
        fh.write(line + '\n')

# Base path to libexec binaries on Dell
BINDIR = Path('/path/to/darwin_research/binaries/libexec')

# Top anomalous Apple-written libexec binaries from libexec_v2 sweep.
# Format: (name, z_combined, n_funcs_hint)
# Excluded (third-party artifacts):
#   Postfix: smtpd(103), smtp(29), lmtp(47), qmgr/nqmgr/oqmgr, showq, pickup,
#            cleanup, discard, bounce, pipe, proxymap, scache, virtual, verify,
#            trivial-rewrite, spawn, local, master, tlsmgr, tlsproxy, postscreen,
#            qmqpd, qmqp-source/sink, anvil, dnsblog, error, flush, bounce
#   OpenSSH: ssh-keysign, ssh-pkcs11-helper, ssh-apple-pkcs11, ssh-sk-helper,
#            sftp-server, sshd (if present)
#   OpenLDAP: slapconfig-keygen
#   Already closed: bluetoothuserd, NANDTaskScheduler, ASPCarryLog,
#                   InternetSharing, appleh13camerad, appleh16camerad
#
# coreidvd z=+509M is a degenerate outlier (likely binary parsing artifact),
# not a meaningful finding — excluded.
TARGETS = [
    # Tier 1 — extreme z, Apple-written, network/IPC reachable
    ('promotedcontentd',            178.05,  'unknown'),
    ('locationd',                   146.75,  'unknown'),
    ('sharingd',                    136.31,  'unknown'),
    ('secd',                        130.87,  'unknown'),
    # Tier 2 — high z, interesting attack surface
    ('nfcd',                         51.33,  'unknown'),
    ('kcgend',                       43.15,  'unknown'),
    ('gamed',                        32.99,  'unknown'),
    ('nearbyd',                      30.56,  'unknown'),
    ('kernelmanager_helper',         26.60,  'unknown'),
    ('remindd',                      22.37,  'unknown'),
    ('bootpd',                       12.50,  'unknown'),  # DHCP, directly network-exposed
    ('opendirectoryd',               11.49,  'unknown'),
    ('gamesaved',                    11.01,  'unknown'),
    ('com.apple.cmio.videodriverkithostextension', 10.96, 'unknown'),
    ('feedbackd',                    10.42,  'unknown'),
    ('displaypolicyd',                9.67,  'unknown'),
    ('init_data_protection',          8.61,  'unknown'),
    ('seputil',                       8.25,  'unknown'),  # Secure Enclave utility
    ('dasd',                         13.02,  'unknown'),  # Device Activity Sensor
    ('automountd',                    6.30,  'unknown'),  # NFS automounter
    ('sandboxd',                      6.59,  'unknown'),
    ('mdmclient',                     6.84,  'unknown'),
    ('audiomxd',                      6.35,  'unknown'),
    ('srp-mdns-proxy',                5.08,  'unknown'),  # SRP+mDNS, network
    ('applekeystored',                5.79,  'unknown'),
    ('debugserver',                   7.00,  'unknown'),
    ('diagnosticd',                   5.07,  'unknown'),
    ('odproxyd',                      4.54,  'unknown'),
    ('diskimagesiod',                 3.98,  'unknown'),
    ('icloudwebd',                    3.84,  'unknown'),  # iCloud web daemon
]

ARCH        = archinfo.arch_from_id('aarch64')
TOP_N       = 50
FULL_SCAN_N = 400
MIN_CONF    = 0.4
# For large binaries, supplement C2 top-N with source-caller scan.
# find_source_callers() is fast (<5s) and adds XPC handlers / network receivers
# that rank low on cyclomatic complexity but are high attack-surface.
USE_SOURCE_CALLERS  = True
# Cap total source callers to avoid unbounded C3 runtime on very large daemons.
# locationd has 3,900+ callers; with ~15s/function that would be 16+ hours.
# 400 additional callers + 50 C2 = 450 functions → ~2 hours max per binary.
MAX_SOURCE_CALLERS  = 400
# Per-binary C3 wall-clock timeout (seconds).  Large binaries like sharingd or
# secd can take 20-40 minutes without a bound.  Set to 0 to disable.
C3_TIMEOUT          = 900   # 15 min per binary


def run_c2_top(binary_path):
    try:
        c2 = FastC2Analysis(binary_path)
        result = c2.run()
        if len(result.functions_ranked) <= FULL_SCAN_N:
            addrs = [f.addr for f in result.functions_ranked]
            log('  Small binary ({} funcs) — scanning all'.format(len(addrs)))
        else:
            addrs = [f.addr for f in result.functions_ranked[:TOP_N]]
        return addrs
    except Exception as e:
        log('  C2 error: {}'.format(e))
        return []


def run_c3(binary_path, func_addrs):
    proj = angr.Project(binary_path, auto_load_libs=False,
                        main_opts={'arch': ARCH})
    c3 = C3TemplateAnalysis(proj)
    log('  PLT map: {} stubs, boundaries: {} funcs'.format(
        len(c3._plt_map), len(c3._func_boundaries)))

    # Supplement C2 selection with source-caller scan for large binaries
    if USE_SOURCE_CALLERS and len(c3._func_boundaries) > FULL_SCAN_N:
        t_sc = time.time()
        source_addrs = c3.find_source_callers(max_total=MAX_SOURCE_CALLERS)
        n_before = len(func_addrs) if func_addrs else 0
        if func_addrs:
            combined = sorted(set(func_addrs) | source_addrs)
        else:
            combined = sorted(source_addrs)
        log('  Source-caller scan in {:.1f}s → +{} addrs ({} total)'.format(
            time.time() - t_sc,
            len(combined) - n_before,
            len(combined)))
        func_addrs = combined

    result = c3.analyse_functions(func_addrs=func_addrs if func_addrs else None)
    return [m for m in result.matches if not m.barrier_hit and m.confidence >= MIN_CONF]


if __name__ == '__main__':
    LOG_FILE.write_text('')
    log('C3 libexec_v2 followup — {} targets'.format(len(TARGETS)))

    # Resume: load prior results so successful runs are not repeated.
    # Entries with 'error' are always re-run; entries with n_hits >= 0 are kept.
    all_hits = {}
    if HITS_FILE.exists():
        try:
            prior = json.loads(HITS_FILE.read_text())
            kept = {n: v for n, v in prior.items() if 'error' not in v}
            all_hits.update(kept)
            log('Resumed: keeping {} completed entries, re-running {} errors'.format(
                len(kept), len(prior) - len(kept)))
        except Exception:
            pass

    for name, z_combined, _ in TARGETS:
        if name in all_hits:
            log('{} — already done (n_hits={}), skipping'.format(
                name, all_hits[name].get('n_hits', '?')))
            continue

        binary = BINDIR / name
        if not binary.exists():
            log('{} — NOT FOUND at {}'.format(name, binary))
            all_hits[name] = {'binary': str(binary), 'error': 'not found'}
            continue

        log('{} (z={:+.2f})'.format(name, z_combined))

        t0 = time.time()
        top_addrs = run_c2_top(str(binary))
        log('  C2 done in {:.1f}s → {} addrs'.format(time.time() - t0, len(top_addrs)))

        t1 = time.time()
        try:
            if C3_TIMEOUT > 0:
                def _c3_timeout_handler(signum, frame):
                    raise TimeoutError('C3 timeout after {}s'.format(C3_TIMEOUT))
                signal.signal(signal.SIGALRM, _c3_timeout_handler)
                signal.alarm(C3_TIMEOUT)
            active = run_c3(str(binary), top_addrs)
            if C3_TIMEOUT > 0:
                signal.alarm(0)  # cancel alarm
            elapsed = time.time() - t1
            log('  C3 done in {:.1f}s → {} hits'.format(elapsed, len(active)))
            for m in sorted(active, key=lambda x: -x.confidence)[:10]:
                log('    *** {} conf={:.3f} func={:#x}'.format(
                    m.template.name, m.confidence, m.func_addr))
            all_hits[name] = {
                'binary':     str(binary),
                'z_combined': z_combined,
                'n_hits':     len(active),
                'hits': [{'template':   m.template.name,
                          'confidence': round(m.confidence, 3),
                          'func_addr':  hex(m.func_addr),
                          'source':     m.source_node,
                          'sink':       m.sink_node}
                         for m in sorted(active, key=lambda x: -x.confidence)],
            }
        except TimeoutError as e:
            signal.alarm(0)
            elapsed = time.time() - t1
            log('  C3 TIMEOUT after {:.0f}s — skipping'.format(elapsed))
            all_hits[name] = {'binary': str(binary), 'z_combined': z_combined,
                              'error': 'timeout'}
        except Exception as e:
            if C3_TIMEOUT > 0:
                signal.alarm(0)
            log('  C3 error: {}'.format(e))
            all_hits[name] = {'binary': str(binary), 'z_combined': z_combined,
                              'error': str(e)[:300]}

        # Incremental save after each binary — survives process kill
        HITS_FILE.write_text(json.dumps(all_hits, indent=2))

    HITS_FILE.write_text(json.dumps(all_hits, indent=2))
    log('Done. Results → {}'.format(HITS_FILE))

    interesting = {n: v for n, v in all_hits.items() if v.get('n_hits', 0) > 0}
    log('Binaries with C3 hits: {}/{}'.format(len(interesting), len(all_hits)))
    for name, v in sorted(interesting.items(), key=lambda x: x[1].get('n_hits', 0), reverse=True):
        log('  *** {} — {} hits  z={}'.format(name, v['n_hits'], v.get('z_combined')))
        for h in v.get('hits', [])[:5]:
            log('      {} conf={}'.format(h['template'], h['confidence']))
