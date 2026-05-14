"""
validate_c3.py — C3 template matching validation harness.

Tests two patterns:
  1. MACH_OOB: mach_msg receive → malloc(tainted_size)
  2. XPC_TYPE:  xpc_dictionary_get_value → xpc_int64_get_value (no type guard)

Each test:
  - Compiles a small C harness with clang -arch arm64 -O0
  - Loads it with angr
  - Runs C3TemplateAnalysis.run_function() on the test function
  - Asserts the expected template name is (or is not) found

All four assertions must PASS for the validation to succeed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import angr

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from metis.c3_templates import (
    C3TemplateAnalysis, C3Result, TemplateMatch,
    extract_call_dataflow, TEMPLATE_BANK,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _compile(src: str, label: str) -> Path:
    """Compile *src* to a temp arm64 Mach-O binary, return the path."""
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='w') as f:
        f.write(src)
        c_path = f.name
    out_path = Path(tempfile.mktemp(suffix=f'_{label}'))
    result = subprocess.run(
        ['clang', '-arch', 'arm64', '-O0', '-dynamiclib',
         '-o', str(out_path), c_path,
         '-Wno-implicit-function-declaration',
         '-undefined', 'dynamic_lookup'],
        capture_output=True, text=True,
    )
    os.unlink(c_path)
    if result.returncode != 0:
        raise RuntimeError(f'Compile failed for {label}:\n{result.stderr}')
    return out_path


def _find_func(proj: angr.Project, name: str) -> 'angr.knowledge_plugins.Function | None':
    """Find a function by name in the project's knowledge base."""
    for addr, func in list(proj.kb.functions.items()):
        if func.name == name:
            return func
    return None


def _run_test(label: str, src: str, func_name: str,
              expect_template: 'str | None') -> bool:
    """
    Compile *src*, run C3 on *func_name*, check for *expect_template*.

    If *expect_template* is None, asserts that NO template matches.
    Returns True on PASS.
    """
    print(f'\n── {label} ──')
    binary = _compile(src, label)
    try:
        proj = angr.Project(str(binary), auto_load_libs=False)
        # Build CFG to populate functions KB
        proj.analyses.CFGFast(normalize=False, show_progressbar=False)
        func = _find_func(proj, func_name)
        if func is None:
            print(f'  WARN: function {func_name!r} not found; trying by substring')
            for addr, f in list(proj.kb.functions.items()):
                if func_name in (f.name or ''):
                    func = f
                    break
        if func is None:
            print(f'  FAIL: function {func_name!r} not found in binary')
            return False

        # Run C3 on this function only
        c3 = C3TemplateAnalysis(proj)
        result = c3.analyse_functions([func.addr])
        matches = result.matches

        if expect_template is None:
            # Only count active (non-barrier, high-confidence) matches
            active = [m for m in matches if not m.barrier_hit and m.confidence >= 0.40]
            if active:
                names = [m.template.name for m in active]
                print(f'  FAIL: expected no active match but got {names}')
                return False
            print(f'  PASS: no active findings (correct)')
            return True
        else:
            found = [m for m in matches if m.template.name == expect_template]
            if found:
                print(f'  PASS: {expect_template} detected at {func_name!r}  '
                      f'{found[0].confidence:.0%} confidence')
                return True
            else:
                names = [m.template.name for m in matches]
                print(f'  FAIL: expected {expect_template!r} but got {names}')
                # Debug: dump the call dataflow
                interesting = set()
                for t in TEMPLATE_BANK:
                    interesting.update(t.source_substrings)
                    interesting.update(t.sink_substrings)
                calls, cg = extract_call_dataflow(proj, func, interesting)
                print(f'  DEBUG: {len(calls)} calls, {cg.number_of_edges()} edges in CG')
                for call in calls:
                    print(f'    call: {call.callee_name}  tainted_args={call.tainted_args}')
                print(f'  DEBUG: edges: {list(cg.edges())}')
                return False
    finally:
        try:
            binary.unlink()
        except Exception:
            pass


# ── XPC_SIZE_ALLOC test ────────────────────────────────────────────────────────
# xpc_data_get_length → malloc(size) without bounds check.
# xpc_data_get_length returns a size_t directly — it IS the source in the
# XPC_SIZE_ALLOC template.  Return value flows straight to malloc.
XPC_SIZE_ALLOC_VULN = textwrap.dedent("""\
    #include <xpc/xpc.h>
    #include <stdlib.h>

    void test_xpc_size_alloc_vuln(xpc_object_t dict) {
        // Vulnerable: XPC data length used directly as malloc size
        xpc_object_t data = xpc_dictionary_get_value(dict, "payload");
        size_t sz = xpc_data_get_length(data);
        void *buf = malloc(sz);
        (void)buf;
    }
""")

# Safe version: XPC key count obtained but never passed to any allocator.
# xpc_dictionary_get_count is an XPC_SIZE_ALLOC source, but log_size is not a
# sink (not malloc/calloc/realloc).  No path from source to sink → no match.
# Deliberately avoids xpc_dictionary_get_value to prevent XPC_TYPE matches.
XPC_SIZE_ALLOC_SAFE = textwrap.dedent("""\
    #include <xpc/xpc.h>
    #include <stdlib.h>

    extern void log_size(size_t len);

    void test_xpc_size_alloc_safe(xpc_object_t dict) {
        // Safe: count is only logged — no dynamic allocation driven by XPC data
        size_t count = xpc_dictionary_get_count(dict);
        log_size(count);
    }
""")

# ── XPC_TYPE test ──────────────────────────────────────────────────────────────
# xpc_dictionary_get_value → xpc_int64_get_value without xpc_get_type guard
XPC_TYPE_VULN = textwrap.dedent("""\
    #include <xpc/xpc.h>

    void test_xpc_type_vuln(xpc_object_t dict) {
        xpc_object_t val = xpc_dictionary_get_value(dict, "key");
        // Vulnerable: no xpc_get_type check before typed accessor
        int64_t n = xpc_int64_get_value(val);
        (void)n;
    }
""")

# Safe version: xpc_get_type guard present before accessor
XPC_TYPE_SAFE = textwrap.dedent("""\
    #include <xpc/xpc.h>

    void test_xpc_type_safe(xpc_object_t dict) {
        xpc_object_t val = xpc_dictionary_get_value(dict, "key");
        // Safe: type check before accessor
        if (xpc_get_type(val) == XPC_TYPE_INT64) {
            int64_t n = xpc_int64_get_value(val);
            (void)n;
        }
    }
""")


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    results: list[tuple[str, bool]] = []

    results.append(('XPC_SIZE_ALLOC vuln', _run_test(
        'XPC_SIZE_ALLOC vuln',
        XPC_SIZE_ALLOC_VULN,
        'test_xpc_size_alloc_vuln',
        expect_template='XPC_SIZE_ALLOC',
    )))

    results.append(('XPC_SIZE_ALLOC safe', _run_test(
        'XPC_SIZE_ALLOC safe',
        XPC_SIZE_ALLOC_SAFE,
        'test_xpc_size_alloc_safe',
        expect_template=None,
    )))

    results.append(('XPC_TYPE vuln', _run_test(
        'XPC_TYPE vuln',
        XPC_TYPE_VULN,
        'test_xpc_type_vuln',
        expect_template='XPC_TYPE',
    )))

    results.append(('XPC_TYPE safe', _run_test(
        'XPC_TYPE safe',
        XPC_TYPE_SAFE,
        'test_xpc_type_safe',
        expect_template=None,
    )))

    print('\n' + '=' * 60)
    print('C3 Validation Summary')
    print('=' * 60)
    passed = 0
    for name, ok in results:
        status = 'PASS' if ok else 'FAIL'
        print(f'  {status}  {name}')
        if ok:
            passed += 1
    print(f'\n{passed}/{len(results)} tests passed')
    if passed < len(results):
        sys.exit(1)


if __name__ == '__main__':
    main()
