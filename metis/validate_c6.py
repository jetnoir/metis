"""
validate_c6.py — C6 component validation against synthetic test harnesses.

Builds three small C programs that each contain one of the three C6 target
vulnerability classes, then runs C6Analysis against them and verifies that:

  1. The correct VulnClass is detected on the vulnerable binary.
  2. No false positive is raised on the patched (safe) version.

Run from the metis directory:

    python validate_c6.py

Requirements:
    clang (Xcode command line tools)
    angr, lief (pip install angr lief)

Output:
    PASS / FAIL per test case, plus the full C6 finding report.

Note: these tests use concrete (non-mach_msg) entry points to avoid needing a
live Mach port. The mach_msg hook is validated separately by calling
taint_entry_state_buffer() to manually prime the taint.
"""

import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import angr

# Add parent directory to path so we can import metis as a package
sys.path.insert(0, str(Path(__file__).parent.parent))
from metis.c6_taint import C6Analysis, VulnClass

CLANG = 'clang'
ARCH  = '-arch', 'arm64'   # change to x86_64 if not on Apple Silicon

# ── Test harness C sources ────────────────────────────────────────────────────

# Test 1: OOB — tainted size reaches malloc
_OOB_VULN = textwrap.dedent("""\
    #include <stdlib.h>
    #include <string.h>

    // Simulates attacker-supplied message body with a size field.
    // In production this buffer would come from mach_msg receive.
    void handle_message(unsigned int attacker_size) {
        // VULNERABLE: no bounds check before malloc
        char *buf = malloc(attacker_size);
        if (buf) {
            memset(buf, 0, attacker_size);
            free(buf);
        }
    }

    int main(void) {
        handle_message(0xdeadbeef);
        return 0;
    }
""")

_OOB_SAFE = textwrap.dedent("""\
    #include <stdlib.h>
    #include <string.h>

    #define MAX_MSG_SIZE 4096

    void handle_message(unsigned int attacker_size) {
        // PATCHED: bounds check guards the allocation
        if (attacker_size == 0 || attacker_size > MAX_MSG_SIZE)
            return;
        char *buf = malloc(attacker_size);
        if (buf) {
            memset(buf, 0, attacker_size);
            free(buf);
        }
    }

    int main(void) {
        handle_message(0xdeadbeef);
        return 0;
    }
""")

# Test 2: UAF — double free
_UAF_VULN = textwrap.dedent("""\
    #include <stdlib.h>

    void process(int flag) {
        char *p = malloc(64);
        if (!p) return;
        if (flag) {
            free(p);   // first free
        }
        free(p);       // VULNERABLE: double free when flag != 0
    }

    int main(void) {
        process(1);
        return 0;
    }
""")

_UAF_SAFE = textwrap.dedent("""\
    #include <stdlib.h>

    void process(int flag) {
        char *p = malloc(64);
        if (!p) return;
        // PATCHED: conditional free — at most one free on any path
        if (flag) {
            free(p);
        }
        // When !flag: p is intentionally leaked (not the bug under test)
    }

    int main(void) {
        process(1);
        return 0;
    }
""")


def compile_c(src: str, outpath: Path) -> bool:
    """Compile *src* to *outpath* with clang. Returns True on success."""
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(src)
        tmp = Path(f.name)
    try:
        result = subprocess.run(
            [CLANG, *ARCH, '-O0', '-g', str(tmp), '-o', str(outpath)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f'[compile error]\n{result.stderr}')
            return False
        return True
    finally:
        tmp.unlink(missing_ok=True)


def run_c6_on_binary(
    binary_path: Path,
    taint_func_name: str,
    taint_arg_index: int,
    expected_class: VulnClass | None,
) -> bool:
    """
    Load *binary_path* under angr, manually taint one argument of
    *taint_func_name*, run C6Analysis, and check whether *expected_class*
    appears (or does not appear) in findings.

    Parameters
    ----------
    taint_func_name  : symbol whose first call we hook as the taint source
    taint_arg_index  : which argument register to taint (0-indexed)
    expected_class   : VulnClass to look for, or None to assert no findings
    """
    proj = angr.Project(str(binary_path), auto_load_libs=False,
                        main_opts={'base_addr': 0x400000})
    c6 = C6Analysis(proj)

    def _find_sym(name):
        """CLE find_symbol wrapper — handles IndexError from empty results in newer CLE."""
        try:
            result = proj.loader.find_symbol(name)
            return result
        except (IndexError, AttributeError):
            pass
        try:
            return next(
                (s for s in proj.loader.main_object.symbols if s.name == name),
                None
            )
        except Exception:
            return None

    # Find the entry point of the function under test
    sym = _find_sym(taint_func_name) or _find_sym(f'_{taint_func_name}')
    if sym is None:
        print(f'  [warn] symbol {taint_func_name!r} not found; using entry state')
        state = proj.factory.entry_state()
    else:
        state = proj.factory.call_state(sym.rebased_addr)

    # Manually taint the first argument (simulates mach_msg payload)
    # We taint via a symbolic argument register rather than memory for simplicity
    from metis.c6_taint import _fresh_taint, _ensure_c6_globals
    _ensure_c6_globals(state)

    taint_val = _fresh_taint('validate_arg', 32)
    arch = proj.arch
    # Set the chosen argument register to the tainted symbol
    if arch.name in ('AMD64', 'X86_64'):
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx']
    else:
        arg_regs = ['x0', 'x1', 'x2', 'x3']

    if taint_arg_index < len(arg_regs):
        setattr(state.regs, arg_regs[taint_arg_index], taint_val)

    result = c6.run(state, max_steps=200)
    result.print_report()

    found_classes = {f.vuln_class for f in result.findings}

    if expected_class is None:
        ok = len(result.findings) == 0
        label = 'no findings (clean path)'
    else:
        ok = expected_class in found_classes
        label = f'{expected_class.name} detected'

    status = 'PASS' if ok else 'FAIL'
    print(f'  → {status}: expected {label}')
    return ok


def main():
    tmpdir = Path(tempfile.mkdtemp(prefix='c6_validate_'))
    print(f'Working in {tmpdir}\n')

    tests = [
        ('OOB vuln',   _OOB_VULN,  'handle_message', 0, VulnClass.OOB),
        ('OOB safe',   _OOB_SAFE,  'handle_message', 0, None),
        ('UAF vuln',   _UAF_VULN,  'process',        0, VulnClass.UAF),
        ('UAF safe',   _UAF_SAFE,  'process',        0, None),
    ]

    results = {}
    for name, src, func, arg_idx, expected in tests:
        print(f'=== {name} ===')
        outpath = tmpdir / name.replace(' ', '_')
        if not compile_c(src, outpath):
            print(f'  SKIP: compilation failed')
            results[name] = False
            continue
        results[name] = run_c6_on_binary(outpath, func, arg_idx, expected)
        print()

    print('=' * 40)
    print('Summary')
    print('=' * 40)
    for name, ok in results.items():
        print(f'  {"PASS" if ok else "FAIL"}  {name}')

    all_pass = all(results.values())
    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
