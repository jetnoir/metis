#!/usr/bin/env python3
"""
run_c3_mac_followup.py — C3 template scan of top anomalous binaries on Mac.

Runs FastC2 to get top function addresses, then C3TemplateAnalysis on each.
Writes results to findings/c3_mac_followup_hits.json and findings/c3_mac_followup.log.
"""
import sys, os, json, time, logging
from pathlib import Path

TOOLCHAIN = Path(__file__).parent
sys.path.insert(0, str(TOOLCHAIN))

import archinfo
import angr
from metis.fast_c2 import FastC2Analysis
from metis.c3_templates import C3TemplateAnalysis

OUTDIR = TOOLCHAIN.parent / 'findings'
OUTDIR.mkdir(exist_ok=True)
HITS_FILE = OUTDIR / 'c3_mac_followup_hits.json'
LOG_FILE  = OUTDIR / 'c3_mac_followup.log'

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)

def log(msg):
    line = '[{}] {}'.format(time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    with open(LOG_FILE, 'a') as fh:
        fh.write(line + '\n')

TARGETS = [
    ('progressd',                         '/System/Library/Frameworks/ClassKit.framework/Versions/A/progressd',                                                                              338.11, 8060),
    ('shazamd',                           '/System/Library/Frameworks/ShazamKit.framework/shazamd',                                                                                          18.25, 1928),
    ('openAndSavePanelService',           '/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/com.apple.appkit.xpc.openAndSavePanelService.xpc/Contents/MacOS/com.apple.appkit.xpc.openAndSavePanelService', 15.78, 247),
    ('CoreMLModelSecurityService',        '/System/Library/Frameworks/CoreML.framework/Versions/A/XPCServices/CoreMLModelSecurityService.xpc/Contents/MacOS/CoreMLModelSecurityService',      15.07, 230),
    ('TrustedPeersHelper',                '/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/TrustedPeersHelper.xpc/Contents/MacOS/TrustedPeersHelper',                   13.36, 8486),
    ('CommCenter',                        '/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter',                                                                            13.01, 29384),
    ('coreauthd',                         '/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd',                                                                      12.27, 1511),
    ('ThumbnailsAgent',                   '/System/Library/Frameworks/QuickLookThumbnailing.framework/Support/com.apple.quicklook.ThumbnailsAgent',                                          11.90, 51),
    ('storekitagent',                     '/System/Library/Frameworks/StoreKit.framework/Support/storekitagent',                                                                              11.38, 23207),
    ('SKAskPermissionExtension',          '/System/Library/Frameworks/StoreKit.framework/Versions/A/PlugIns/SKAskPermissionExtension.appex/Contents/MacOS/SKAskPermissionExtension',         11.31, 86),
    ('QuickLookUIService',                '/System/Library/Frameworks/QuickLookUI.framework/Versions/A/XPCServices/QuickLookUIService.xpc/Contents/MacOS/QuickLookUIService',                10.97, 216),
    ('AMPSystemPlayerAgent',              '/System/Library/Frameworks/iTunesLibrary.framework/Versions/A/Support/AMPSystemPlayerAgent',                                                      10.00, 331),
    ('QuickLookSatellite',                '/System/Library/Frameworks/QuickLook.framework/Versions/A/XPCServices/QuickLookSatellite.xpc/Contents/MacOS/QuickLookSatellite',                  8.48, 78),
    ('automator.runner',                  '/System/Library/Frameworks/Automator.framework/Versions/A/XPCServices/com.apple.automator.runner.xpc/Contents/MacOS/com.apple.automator.runner',  7.80, 95),
    ('AMPAppSysPlayerService',            '/System/Library/Frameworks/iTunesLibrary.framework/Versions/A/XPCServices/AMPAppSysPlayerService.xpc/Contents/MacOS/AMPAppSysPlayerService',       7.52, 185),
]

ARCH = archinfo.arch_from_id('aarch64')
TOP_N       = 50    # top functions from C2 to feed into C3 (was 20)
FULL_SCAN_N = 300   # if binary has ≤ this many functions, scan all of them
MIN_CONF    = 0.4
# Supplement C2 top-N with source-caller scan for large binaries.
# find_source_callers() is fast (<5s) and adds XPC/IPC handlers that
# rank low on cyclomatic complexity but high on attack-surface relevance.
USE_SOURCE_CALLERS = True

def run_c2_top(binary_path, n_funcs_hint=0):
    """Return top-N function addresses by combined C2 score.
    For small binaries (≤ FULL_SCAN_N functions) returns all addresses."""
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
    """Run C3 template analysis. Returns list of active Match objects."""
    proj = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={'arch': ARCH},
    )
    c3 = C3TemplateAnalysis(proj)

    # Supplement C2 selection with source-caller scan for large binaries
    if USE_SOURCE_CALLERS and len(c3._func_boundaries) > FULL_SCAN_N:
        t_sc = time.time()
        source_addrs = c3.find_source_callers()
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

C3_TIMEOUT = 180   # seconds — skip binary if C3 takes longer than this

def run_c3_timed(binary_path, func_addrs, timeout_s=C3_TIMEOUT):
    """Run C3 in a subprocess with a hard timeout. Returns (active_list, timed_out)."""
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(run_c3, binary_path, func_addrs)
        try:
            result = fut.result(timeout=timeout_s)
            return result, False
        except concurrent.futures.TimeoutError:
            return [], True


if __name__ == '__main__':
    LOG_FILE.write_text('')
    log('C3 Mac follow-up starting — {} targets'.format(len(TARGETS)))

    # Load prior partial results so we can resume
    all_hits = {}
    if HITS_FILE.exists():
        try:
            all_hits = json.loads(HITS_FILE.read_text())
            log('Loaded {} prior results from {}'.format(len(all_hits), HITS_FILE))
        except Exception:
            pass

    for name, binary, z_combined, n_funcs in TARGETS:
        if name in all_hits and 'error' not in all_hits[name]:
            log('{} — already done, skipping'.format(name))
            continue

        if not Path(binary).exists():
            log('{} — NOT FOUND, skipping'.format(name))
            all_hits[name] = {'binary': binary, 'error': 'not found'}
            HITS_FILE.write_text(json.dumps(all_hits, indent=2))
            continue

        log('{} (z={:+.2f}, {} funcs)'.format(name, z_combined, n_funcs))

        # Step 1: C2 top addresses
        t0 = time.time()
        top_addrs = run_c2_top(binary, n_funcs)
        log('  C2 done in {:.1f}s → {} addrs'.format(time.time()-t0, len(top_addrs)))

        # Step 2: C3 scan with timeout
        t1 = time.time()
        try:
            active, timed_out = run_c3_timed(binary, top_addrs)
            elapsed = time.time() - t1
            if timed_out:
                log('  C3 TIMEOUT after {:.0f}s — skipping'.format(elapsed))
                all_hits[name] = {'binary': binary, 'z_combined': z_combined,
                                  'n_funcs': n_funcs, 'error': 'timeout'}
            else:
                log('  C3 done in {:.1f}s → {} hits'.format(elapsed, len(active)))
                for m in sorted(active, key=lambda x: -x.confidence)[:10]:
                    log('    *** {} conf={:.3f} func={}'.format(
                        m.template.name, m.confidence,
                        hex(m.func_addr) if hasattr(m, 'func_addr') else '?'))
                all_hits[name] = {
                    'binary':     binary,
                    'z_combined': z_combined,
                    'n_funcs':    n_funcs,
                    'n_hits':     len(active),
                    'hits': [{'template':   m.template.name,
                               'confidence': round(m.confidence, 3),
                               'func_va':   hex(m.func_addr) if hasattr(m, 'func_addr') else '?'}
                              for m in sorted(active, key=lambda x: -x.confidence)],
                }
        except Exception as e:
            log('  C3 error: {}'.format(e))
            all_hits[name] = {'binary': binary, 'z_combined': z_combined, 'error': str(e)[:300]}

        # Save incrementally after each binary
        HITS_FILE.write_text(json.dumps(all_hits, indent=2))

    log('Done. Results → {}'.format(HITS_FILE))

    interesting = {n: v for n, v in all_hits.items() if v.get('n_hits', 0) > 0}
    log('Binaries with C3 hits: {}/{}'.format(len(interesting), len(all_hits)))
    for name, v in sorted(interesting.items(), key=lambda x: x[1].get('n_hits', 0), reverse=True):
        log('  *** {} — {} hits  z={}'.format(name, v['n_hits'], v.get('z_combined')))
        for h in v.get('hits', []):
            log('      {} conf={}'.format(h['template'], h['confidence']))
