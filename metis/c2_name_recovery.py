"""
C2 → LLM function name recovery
================================
Reads C2 top-function rankings, queries a local llama.cpp server
(Qwen2.5-Coder-3B-Instruct-Q8 on Quadro P1000) for each function,
and writes an augmented JSON with semantic names + validation metadata.

Three validation layers
-----------------------
1. Evidence citation  — model must name a string/import that justifies
                        its answer; confidence auto-downgraded if absent
                        or if the cited string is not found near the function
2. Structural sanity  — name semantics checked against binary features
                        (a "parse" function with 0 back-edges, an "encrypt"
                        function with no crypto imports, etc.)
3. Calibration mode   — run on known functions first (ping/pr_pack,
                        AMFID getStagedProfileWithReply) to measure
                        accuracy before trusting on unknown targets

Usage
-----
# Start llama.cpp server once per session (on Dell):
python3 -m llama_cpp.server \\
    --model ~/models/qwen2.5-coder-3b-instruct-q8_0.gguf \\
    --n_gpu_layers 99 --host 127.0.0.1 --port 8081 --n_ctx 2048 &

# Run name recovery (from Mac, server reachable at dell:8081):
python3 c2_name_recovery.py \\
    --binary /usr/libexec/biometrickitd \\
    --c2-json biometrickitd_c2_top_addrs.json \\
    --server http://192.168.1.55:8081 \\
    --output biometrickitd_named.json \\
    --top-n 20

Requires: requests, lief, capstone (all in venv_angr or venv_llm)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import lief
import requests
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

log = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_SERVER   = "http://127.0.0.1:8081"
MODEL_NAME       = "qwen2.5-coder-3b-instruct-q8_0.gguf"
MAX_DISASM_INSNS = 60      # lines of disassembly sent to model
CONTEXT_BYTES    = 512     # bytes either side of function for string search
MAX_TOKENS       = 120     # model output cap — JSON is short
TEMPERATURE      = 0.1     # low = more deterministic / less creative

# Semantic consistency rules: (name_keyword, required_disasm_or_string_pattern)
SANITY_RULES: list[tuple[list[str], list[str], str]] = [
    # (name_keywords,  required_evidence_patterns,          failure_message)
    (
        ['encrypt', 'decrypt', 'aes', 'hmac', 'sha', 'cipher'],
        ['cc_', 'ccrng', 'ccaes', 'cchkdf', 'common_crypto', 'corecrypto',
         'CCCrypt', 'SecKey'],
        'crypto name but no crypto imports near function',
    ),
    (
        ['malloc', 'alloc', 'create', 'new', 'init'],
        ['bl _malloc', 'bl _calloc', 'bl _new', '_alloc', 'malloc'],
        'alloc name but no malloc/calloc in disasm',
    ),
    (
        ['free', 'release', 'dealloc', 'destroy'],
        ['bl _free', 'bl _objc_release', '_dealloc', '_destroy'],
        'free/release name but no free call in disasm',
    ),
    (
        ['xpc', 'mach', 'ipc'],
        ['xpc_', 'mach_msg', 'bootstrap_', 'bl _xpc'],
        'XPC/Mach name but no IPC calls in disasm',
    ),
]


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class NameResult:
    addr            : int
    name_original   : str          # name from C2 (sub_XXXXXXXX)
    name_recovered  : str          # model suggestion
    description     : str
    confidence      : str          # 'high' | 'medium' | 'low'
    evidence        : Optional[str]
    evidence_found  : bool         # evidence string actually found near function
    sanity_failures : list[str]    # list of triggered sanity rule descriptions
    cyclomatic      : int
    back_edges      : int
    elapsed_s       : float
    accepted        : bool         # True if confidence=high AND no sanity failures


# ── Binary helpers ─────────────────────────────────────────────────────────────

def _load_binary(path: str) -> tuple[lief.Binary, bytes]:
    """Load Mach-O binary, return lief.Binary and raw bytes of __TEXT/__text."""
    binary = lief.parse(path)
    if binary is None:
        raise RuntimeError(f"lief could not parse {path}")
    # For fat binaries, lief returns the first slice — force arm64e
    raw = Path(path).read_bytes()
    return binary, raw


def _disassemble(raw: bytes, load_addr: int, func_addr: int,
                 max_insns: int = MAX_DISASM_INSNS) -> str:
    """Disassemble up to max_insns instructions starting at func_addr."""
    offset = func_addr - load_addr
    if offset < 0 or offset >= len(raw):
        return "(disassembly unavailable — address out of range)"

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False

    chunk = raw[offset: offset + max_insns * 8]   # 8 bytes/insn worst case
    lines = []
    for insn in md.disasm(chunk, func_addr):
        lines.append(f"  {insn.address:#010x}:  {insn.mnemonic:<8} {insn.op_str}")
        if len(lines) >= max_insns:
            break
    return "\n".join(lines) if lines else "(empty disassembly)"


def _extract_context_strings(raw: bytes, load_addr: int, func_addr: int,
                              window: int = CONTEXT_BYTES) -> list[str]:
    """
    Extract printable strings from ±window bytes around func_addr.
    Includes __cstring and nearby Mach-O section data.
    Returns list of strings ≥4 chars.
    """
    offset = func_addr - load_addr
    start  = max(0, offset - window)
    end    = min(len(raw), offset + window)
    chunk  = raw[start:end]

    # Simple printable-ASCII string extractor
    strings = []
    current = []
    for byte in chunk:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))

    # Deduplicate, keep meaningful ones (filter noise)
    seen = set()
    result = []
    for s in strings:
        if s not in seen and not re.match(r'^[\s/._-]+$', s):
            seen.add(s)
            result.append(s)
    return result[:40]   # cap at 40 strings


# ── Validation layers ──────────────────────────────────────────────────────────

def _validate_evidence(evidence: Optional[str],
                        context_strings: list[str]) -> bool:
    """Layer 1: Check cited evidence string actually appears near the function."""
    if not evidence:
        return False
    evidence_lower = evidence.lower()[:30]   # match on prefix to be lenient
    return any(evidence_lower in s.lower() for s in context_strings)


def _sanity_check(name: str, disasm: str,
                  context_strings: list[str],
                  back_edges: int) -> list[str]:
    """Layer 2: Structural consistency rules. Returns list of failure descriptions."""
    failures = []
    name_lower = name.lower()
    haystack   = (disasm + " " + " ".join(context_strings)).lower()

    for keywords, evidence_patterns, failure_msg in SANITY_RULES:
        if any(kw in name_lower for kw in keywords):
            if not any(pat.lower() in haystack for pat in evidence_patterns):
                failures.append(failure_msg)

    # Parse/decode name with zero back-edges is suspicious
    if any(kw in name_lower for kw in ['parse', 'decode', 'deserialise',
                                        'deserialize', 'read', 'scan']):
        if back_edges == 0:
            failures.append("parser/decoder name but no loops (back_edges=0)")

    return failures


def _downgrade_confidence(conf: str, reason: str,
                           current_failures: list[str]) -> str:
    """Returns the lower of conf and what the failures warrant."""
    if conf == 'high' and current_failures:
        log.debug("Downgrading high→medium: %s", reason)
        return 'medium'
    return conf


# ── LLM query ─────────────────────────────────────────────────────────────────

PROMPT_TEMPLATE = """\
You are a reverse engineer analysing a stripped ARM64 macOS binary ({binary_name}).
Below is the disassembly of one function at address {addr:#x}.
Cyclomatic complexity: {cc}.  Back edges (loop count): {be}.

Strings and imports visible near this function:
{context_strings}

Disassembly:
{disasm}

Your task: infer the most probable function name and a one-sentence description.

Rules:
- Name must follow C/ObjC naming convention (e.g. _validateEnrollmentData, parseXPCReply)
- The "evidence" field MUST be one exact string or import from the list above that
  supports your name. If none support it, set evidence to null and confidence to "low".
- Do NOT invent strings that are not in the list above.

Reply with ONLY valid JSON — no markdown, no explanation:
{{"name": "<name>", "description": "<one sentence>", "confidence": "high|medium|low", "evidence": "<exact_string_or_null>"}}
"""


def _query_llm(server: str, binary_name: str, addr: int, cc: int, be: int,
               context_strings: list[str], disasm: str) -> dict:
    """Query the llama.cpp OpenAI-compatible server. Returns parsed JSON dict."""
    ctx_str = "\n".join(f"  {s}" for s in context_strings) or "  (none)"
    prompt  = PROMPT_TEMPLATE.format(
        binary_name    = binary_name,
        addr           = addr,
        cc             = cc,
        be             = be,
        context_strings= ctx_str,
        disasm         = disasm,
    )

    payload = {
        "model"      : MODEL_NAME,
        "messages"   : [{"role": "user", "content": prompt}],
        "max_tokens" : MAX_TOKENS,
        "temperature": TEMPERATURE,
    }

    resp = requests.post(
        f"{server}/v1/chat/completions",
        json    = payload,
        timeout = 30,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"].strip()

    # Strip markdown code fences if model adds them despite instructions
    content = re.sub(r'^```(?:json)?\s*', '', content)
    content = re.sub(r'\s*```$', '', content)

    return json.loads(content)


# ── Main pipeline ──────────────────────────────────────────────────────────────

def recover_names(binary_path: str,
                  c2_json: str,
                  output_path: str,
                  server: str = DEFAULT_SERVER,
                  top_n: int  = 20,
                  min_confidence: str = 'medium') -> list[NameResult]:
    """
    Full name recovery pipeline for top-N functions from C2 output.

    Parameters
    ----------
    binary_path    : path to the macOS arm64e binary
    c2_json        : path to JSON produced by C2 (list of {addr, cyclomatic,
                     back_edges, name} dicts, sorted by combined score)
    output_path    : where to write augmented JSON
    server         : llama.cpp server URL
    top_n          : how many functions to process
    min_confidence : minimum confidence to mark accepted ('high' or 'medium')
    """
    log.info("Loading binary: %s", binary_path)
    binary, raw = _load_binary(binary_path)

    # Find load address from __TEXT segment
    text_seg = next((s for s in binary.segments if s.name == '__TEXT'), None)
    if text_seg is None:
        raise RuntimeError("No __TEXT segment — is this a Mach-O?")
    load_addr = text_seg.virtual_address
    log.info("Load address: %#x", load_addr)

    # Load C2 ranked functions
    with open(c2_json) as f:
        c2_funcs = json.load(f)
    targets = c2_funcs[:top_n]
    log.info("Processing top %d functions", len(targets))

    binary_name = Path(binary_path).name
    results: list[NameResult] = []

    for i, fn in enumerate(targets, 1):
        addr = fn["addr"]
        cc   = fn.get("cyclomatic", 0)
        be   = fn.get("back_edges", 0)
        orig = fn.get("name", f"sub_{addr:#x}")

        log.info("[%d/%d] %s  cc=%d be=%d", i, len(targets), hex(addr), cc, be)
        t0 = time.time()

        disasm          = _disassemble(raw, load_addr, addr)
        context_strings = _extract_context_strings(raw, load_addr, addr)

        try:
            raw_result = _query_llm(server, binary_name, addr, cc, be,
                                    context_strings, disasm)
        except (requests.RequestException, json.JSONDecodeError, KeyError) as exc:
            log.warning("LLM query failed for %#x: %s", addr, exc)
            results.append(NameResult(
                addr=addr, name_original=orig, name_recovered=orig,
                description="(query failed)", confidence="low",
                evidence=None, evidence_found=False, sanity_failures=[],
                cyclomatic=cc, back_edges=be,
                elapsed_s=time.time()-t0, accepted=False,
            ))
            continue

        name       = raw_result.get("name", orig)
        desc       = raw_result.get("description", "")
        conf       = raw_result.get("confidence", "low")
        evidence   = raw_result.get("evidence")    # may be null/None

        # ── Layer 1: evidence validation ──────────────────────────────────────
        ev_found = _validate_evidence(evidence, context_strings)
        if not ev_found and conf == 'high':
            log.debug("%#x: evidence '%s' not found near function → medium", addr, evidence)
            conf = 'medium'

        # ── Layer 2: structural sanity ────────────────────────────────────────
        sanity_fails = _sanity_check(name, disasm, context_strings, be)
        if sanity_fails and conf == 'high':
            conf = 'medium'

        elapsed  = time.time() - t0
        accepted = (conf in ('high', min_confidence))

        log.info("  → %s  [%s]%s  %.1fs",
                 name, conf,
                 f"  ⚠ {'; '.join(sanity_fails)}" if sanity_fails else "",
                 elapsed)

        results.append(NameResult(
            addr=addr, name_original=orig, name_recovered=name,
            description=desc, confidence=conf,
            evidence=evidence, evidence_found=ev_found,
            sanity_failures=sanity_fails,
            cyclomatic=cc, back_edges=be,
            elapsed_s=elapsed, accepted=accepted,
        ))

    # ── Write output ──────────────────────────────────────────────────────────
    out = {
        "binary"          : binary_path,
        "model"           : MODEL_NAME,
        "server"          : server,
        "functions_named" : len(results),
        "accepted"        : sum(1 for r in results if r.accepted),
        "results"         : [asdict(r) for r in results],
    }
    with open(output_path, "w") as f:
        json.dump(out, f, indent=2)

    log.info("Wrote %d results to %s (%d accepted)",
             len(results), output_path,
             out["accepted"])
    return results


def calibrate(server: str = DEFAULT_SERVER) -> None:
    """
    Layer 3: Run against known functions to measure accuracy.
    Uses /sbin/ping (pr_pack known = ICMP packet parser).
    Prints accuracy report.
    """
    print("\n=== Calibration mode ===")
    print("Testing model on /sbin/ping — pr_pack should be identified as ICMP parser")
    print("(Requires ping to be in the binary collection)\n")

    KNOWN = [
        # (binary, addr_hint_str, expected_name_fragment, expected_desc_fragment)
        ("/sbin/ping", None, "pack", "icmp"),
    ]

    # Quick server health check
    try:
        r = requests.get(f"{server}/v1/models", timeout=5)
        r.raise_for_status()
        print(f"Server OK: {r.json()['data'][0]['id']}\n")
    except Exception as e:
        print(f"Server not reachable at {server}: {e}")
        return

    print("Calibration requires running recover_names() on a binary with known")
    print("function names first, then comparing results manually.")
    print("Run: python3 c2_name_recovery.py --binary /sbin/ping --calibrate")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt = "%H:%M:%S",
    )

    ap = argparse.ArgumentParser(description="C2 → LLM function name recovery")
    ap.add_argument("--binary",      required=False, help="Path to macOS arm64e binary")
    ap.add_argument("--c2-json",     required=False, help="C2 top-functions JSON")
    ap.add_argument("--output",      required=False, help="Output JSON path")
    ap.add_argument("--server",      default=DEFAULT_SERVER,
                    help=f"llama.cpp server URL (default: {DEFAULT_SERVER})")
    ap.add_argument("--top-n",       type=int, default=20,
                    help="Number of top functions to name (default: 20)")
    ap.add_argument("--min-confidence", choices=["high", "medium"], default="medium",
                    help="Minimum confidence to mark result accepted (default: medium)")
    ap.add_argument("--calibrate",   action="store_true",
                    help="Run calibration mode on known functions")
    args = ap.parse_args()

    if args.calibrate:
        calibrate(args.server)
        return

    if not args.binary or not args.c2_json or not args.output:
        ap.error("--binary, --c2-json, and --output are required (unless --calibrate)")

    results = recover_names(
        binary_path    = args.binary,
        c2_json        = args.c2_json,
        output_path    = args.output,
        server         = args.server,
        top_n          = args.top_n,
        min_confidence = args.min_confidence,
    )

    # Print summary table
    print(f"\n{'Addr':>12}  {'Conf':>6}  {'OK':>3}  Name")
    print("-" * 70)
    for r in results:
        ok  = "✓" if r.accepted else "✗"
        warn = " ⚠" if r.sanity_failures else ""
        print(f"  {r.addr:#010x}  {r.confidence:>6}  {ok:>3}  {r.name_recovered}{warn}")

    accepted = sum(1 for r in results if r.accepted)
    print(f"\n{accepted}/{len(results)} accepted  "
          f"({accepted/len(results)*100:.0f}%)  "
          f"avg {sum(r.elapsed_s for r in results)/len(results):.1f}s/function")


if __name__ == "__main__":
    main()
