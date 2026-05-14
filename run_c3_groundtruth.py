#!/usr/bin/env python3
"""
run_c3_groundtruth.py — Calibration run against three known-finding binaries.

Tests whether C3 templates fire on functions we already know are interesting:
  mDNSResponder  — D2D trust gap + DNS packet size paths (MDNS_SIZE_ALLOC, XPC_SIZE_ALLOC)
  amfid          — XPC auth bypass in getStagedProfileWithReply (XPC_TYPE, XPC_SIZE_ALLOC)
  ping           — setuid ARGV → buffer write in pr_pack (ARGV_GLOBAL_WRITE)

A hit on the right function = template is working.
A miss on a known-vulnerable function = template gap or function not in C2 top-N.

Outputs:
  findings/c3_groundtruth_results.json
  findings/c3_groundtruth.log
"""
import sys, os, json, time, logging, warnings
from pathlib import Path

warnings.filterwarnings('ignore')
logging.disable(logging.ERROR)   # suppress angr/cle noise

TOOLCHAIN = Path(__file__).parent
sys.path.insert(0, str(TOOLCHAIN))

import archinfo
import angr
from metis.fast_c2 import FastC2Analysis
from metis.c3_templates import C3TemplateAnalysis, TEMPLATE_BANK

OUTDIR   = TOOLCHAIN.parent / 'findings'
OUTDIR.mkdir(exist_ok=True)
LOG_FILE  = OUTDIR / 'c3_groundtruth.log'
HITS_FILE = OUTDIR / 'c3_groundtruth_results.json'

ARCH     = archinfo.arch_from_id('aarch64')
MIN_CONF = 0.35          # lower threshold for calibration — we want to see near-misses too
TOP_N    = 100           # wider window for ground-truth test
FULL_N   = 500           # full scan for small binaries

def log(msg):
    line = '[{}] {}'.format(time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    with open(LOG_FILE, 'a') as fh:
        fh.write(line + '\n')


# ── Known-interesting function name substrings for each binary ────────────────
# These are what we EXPECT C3 to flag. If it doesn't, we have a gap.
EXPECTED = {
    'mDNSResponder': {
        'functions': ['xD2DParse', 'xD2DParseCompressed', 'xD2DServiceCallback',
                      'mDNS_Register', 'GetRRSet', 'rdlen', 'mDNSPlatformMem'],
        'templates': ['MDNS_SIZE_ALLOC', 'XPC_SIZE_ALLOC', 'INT_OVERFLOW_ALLOC', 'OOB_INDEX'],
        'finding':   'D2D-01 / OE1105676647831 — trust-gate bypass + DNS packet parsing',
        # Known VAs (from nm -arch arm64e) — force-included in C3 scan
        'known_vas': [
            0x10005068c,   # _xD2DParse
            0x1000500a8,   # _xD2DParseCompressedPacket
            0x100051f40,   # _xD2DServiceCallback
            0x10003a878,   # _GetLargeResourceRecord
        ],
    },
    'amfid': {
        'functions': ['getStagedProfile', 'profileData', 'verifyBool', 'XPC', 'xpc_'],
        'templates': ['XPC_TYPE', 'XPC_SIZE_ALLOC', 'CAST_NO_CHECK', 'MACH_OOB'],
        'finding':   'AMFID-02 / OE1105664355901 — getStagedProfileWithReply without entitlement check',
        'known_vas': [],   # stripped; amfid uses ObjC — VAs need runtime resolution
    },
    'ping': {
        'functions': ['pr_pack', 'recv', 'icmp', 'oicmp', 'oip'],
        'templates': ['ARGV_GLOBAL_WRITE', 'OOB_INDEX', 'INT_OVERFLOW_ALLOC'],
        'finding':   'PING-01 — oicmp fixed offset (oip+1) logic bug in pr_pack',
        'known_vas': [],   # stripped; pr_pack VA resolved via C2 cyclomatic ranking
    },
}

TARGETS = [
    ('mDNSResponder', '/usr/sbin/mDNSResponder'),
    ('amfid',         '/usr/libexec/amfid'),
    ('ping',          '/sbin/ping'),
]


def run_c2(binary_path):
    c2 = FastC2Analysis(binary_path)
    result = c2.run()
    if len(result.functions_ranked) <= FULL_N:
        addrs = [f.addr for f in result.functions_ranked]
        log('  Small binary ({} funcs) — scanning all'.format(len(addrs)))
    else:
        addrs = [f.addr for f in result.functions_ranked[:TOP_N]]
    return addrs, result.functions_ranked


def run_c3_full(binary_path, func_addrs):
    """Return ALL matches (not just active) for calibration."""
    proj = angr.Project(binary_path, auto_load_libs=False, main_opts={'arch': ARCH})
    c3 = C3TemplateAnalysis(proj)
    result = c3.analyse_functions(func_addrs=func_addrs)
    return result.matches, proj


def summarise_matches(matches, binary_name):
    """Sort matches by confidence, flag near-misses and barrier hits."""
    active   = [m for m in matches if not m.barrier_hit and m.confidence >= MIN_CONF]
    barriers = [m for m in matches if m.barrier_hit]
    weak     = [m for m in matches if not m.barrier_hit and m.confidence < MIN_CONF]

    expected_templates = EXPECTED[binary_name]['templates']
    expected_funcs     = EXPECTED[binary_name]['functions']

    hit_expected_tmpl = {m.template.name for m in active if m.template.name in expected_templates}
    missed_templates  = set(expected_templates) - {m.template.name for m in active}

    return {
        'active':             active,
        'barriers':           barriers,
        'weak':               weak,
        'hit_expected_tmpl':  hit_expected_tmpl,
        'missed_templates':   missed_templates,
    }


if __name__ == '__main__':
    LOG_FILE.write_text('')
    log('C3 ground-truth calibration — {} binaries'.format(len(TARGETS)))
    log('Templates in bank: {}'.format(len(TEMPLATE_BANK)))
    log('Min confidence threshold: {}'.format(MIN_CONF))
    log('Function window: top-{} (full scan ≤ {} funcs)'.format(TOP_N, FULL_N))
    log('')

    all_results = {}

    for name, binary in TARGETS:
        if not Path(binary).exists():
            log('{} — NOT FOUND'.format(name))
            continue

        log('═' * 60)
        log('{} — {}'.format(name, binary))
        log('Finding: {}'.format(EXPECTED[name]['finding']))
        log('Expected templates: {}'.format(EXPECTED[name]['templates']))
        log('Expected functions: {}'.format(EXPECTED[name]['functions']))
        log('')

        # ── C2 ──────────────────────────────────────────────────────────────
        t0 = time.time()
        try:
            addrs, ranked = run_c2(binary)
        except Exception as e:
            log('C2 FAILED: {}'.format(e))
            all_results[name] = {'error': 'C2 failed: ' + str(e)[:200]}
            continue
        c2_time = time.time() - t0

        # Inject known VAs (from nm symbol table) — ensures C3 analyses the
        # exact functions we know are interesting, even if C2 ranks them low.
        known_vas = EXPECTED[name].get('known_vas', [])
        injected  = [va for va in known_vas if va not in addrs]
        if injected:
            addrs = list(addrs) + injected
            log('C2: {} addrs in {:.1f}s (+{} injected known VAs)'.format(
                len(addrs), c2_time, len(injected)))
        else:
            log('C2: {} addrs in {:.1f}s (all known VAs already in top-N)'.format(
                len(addrs), c2_time))

        # Log top-20 by rank (for diagnostic)
        log('  Top-20 functions by C2 score:')
        for i, f in enumerate(ranked[:20]):
            marker = ' ◄ KNOWN' if any(k.lower() in 'sub_{:x}'.format(f.addr) or k.lower() in f.name.lower()
                                        for k in EXPECTED[name]['functions']) else ''
            log('    {:3d}. {:#012x}  M={:5d}  be={:3d}  score={:.4f}  {}{}'.format(
                i+1, f.addr, f.cyclomatic, f.back_edges, f.combined, f.name[:60], marker))

        # ── C3 ──────────────────────────────────────────────────────────────
        t1 = time.time()
        try:
            matches, proj = run_c3_full(binary, addrs)
        except Exception as e:
            log('C3 FAILED: {}'.format(e))
            all_results[name] = {'c2_addrs': len(addrs), 'error': 'C3 failed: ' + str(e)[:200]}
            continue
        c3_time = time.time() - t1
        log('C3: {} raw matches in {:.1f}s'.format(len(matches), c3_time))

        s = summarise_matches(matches, name)

        # Active hits
        log('')
        log('  ── ACTIVE hits (conf ≥ {}) ──'.format(MIN_CONF))
        if s['active']:
            for m in sorted(s['active'], key=lambda x: x.confidence, reverse=True):
                fva = hex(m.func_addr) if hasattr(m, 'func_addr') else '?'
                fname = ''
                try:
                    fn = proj.kb.functions.get(m.func_addr)
                    if fn:
                        fname = fn.name
                except Exception:
                    pass
                log('    *** {} conf={:.3f}  func={}  {}'.format(
                    m.template.name, m.confidence, fva, fname))
        else:
            log('    (none)')

        # Barrier hits — important: these mean the guard IS present
        log('')
        log('  ── BARRIER hits (guard detected — good news) ──')
        if s['barriers']:
            for m in sorted(s['barriers'], key=lambda x: x.confidence, reverse=True):
                fva = hex(m.func_addr) if hasattr(m, 'func_addr') else '?'
                log('    [guarded] {} conf={:.3f}  func={}'.format(
                    m.template.name, m.confidence, fva))
        else:
            log('    (none)')

        # Near-misses
        log('')
        log('  ── Near-misses (conf < {} but > 0) ──'.format(MIN_CONF))
        if s['weak']:
            for m in sorted(s['weak'], key=lambda x: x.confidence, reverse=True)[:10]:
                fva = hex(m.func_addr) if hasattr(m, 'func_addr') else '?'
                log('    [weak] {} conf={:.3f}  func={}'.format(
                    m.template.name, m.confidence, fva))
        else:
            log('    (none)')

        # Calibration verdict
        log('')
        log('  ── Calibration verdict ──')
        if s['hit_expected_tmpl']:
            log('  ✅ PASS — expected templates fired: {}'.format(s['hit_expected_tmpl']))
        else:
            log('  ⚠️  MISS — none of the expected templates fired')
        if s['missed_templates']:
            log('  Missing: {}'.format(s['missed_templates']))

        log('')

        all_results[name] = {
            'binary':            binary,
            'finding':           EXPECTED[name]['finding'],
            'c2_addrs_scanned':  len(addrs),
            'c2_time_s':         round(c2_time, 1),
            'c3_time_s':         round(c3_time, 1),
            'n_active':          len(s['active']),
            'n_barriers':        len(s['barriers']),
            'n_weak':            len(s['weak']),
            'hit_expected':      list(s['hit_expected_tmpl']),
            'missed_expected':   list(s['missed_templates']),
            'active_hits': [
                {'template': m.template.name,
                 'confidence': round(m.confidence, 3),
                 'func_va': hex(m.func_addr) if hasattr(m, 'func_addr') else '?'}
                for m in sorted(s['active'], key=lambda x: x.confidence, reverse=True)
            ],
        }

    HITS_FILE.write_text(json.dumps(all_results, indent=2))
    log('═' * 60)
    log('Ground-truth calibration complete.')
    log('Results → {}'.format(HITS_FILE))
    log('')
    log('Summary:')
    for name, v in all_results.items():
        if 'error' in v:
            log('  {} — ERROR: {}'.format(name, v['error']))
        elif v.get('hit_expected'):
            log('  {} — ✅ PASS  ({} active hits, expected templates: {})'.format(
                name, v['n_active'], v['hit_expected']))
        else:
            log('  {} — ⚠️  MISS  ({} active, {} barriers, {} weak)'.format(
                name, v.get('n_active', 0), v.get('n_barriers', 0), v.get('n_weak', 0)))
