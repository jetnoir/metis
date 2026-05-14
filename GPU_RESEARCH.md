# Quadro P1000 — GPU Accelerated Analysis Research
## Can we use the Nvidia card, and how?

**Date:** 2026-04-18  
**GPU:** Nvidia Quadro P1000 (Pascal CC 6.1, 4 GB GDDR5, 512 CUDA cores)  
**Dell specs:** i7-4790 @ 3.6 GHz / 32 GB RAM / 1 TB HDD (rotational) / Debian Trixie  

---

## The honest picture first

The P1000 is a **2016 workstation display GPU**, not a compute card. It has:
- 512 CUDA cores (a GTX 1080 Ti has 3584)
- 4 GB VRAM (hard ceiling — models must fit here)
- CC 6.1 — supported by CUDA 12.4 (available in Debian apt)
- Currently: 0% GPU utilisation, 4028/4096 MB VRAM free

It is not going to run a 70B model. It is not going to beat a cloud A100. But it is
**sitting idle and it's free** — and for our specific use case, it's exactly enough.

---

## What actually helps: LLM function naming

### The problem it solves

Our C2 ranked output looks like this:

```
Rank 1: 0x100012abc  cc=377  be=21  name=sub_100012abc
Rank 2: 0x10003f920  cc=114  be=52  name=sub_10003f920
```

Every function in a stripped binary is `sub_XXXXXXXX`. C3 template scanning works on
CFG structure, but it's flying blind on semantics. If we could name those functions:

```
Rank 1: 0x100012abc  cc=377  be=21  name=_ISP_ProcessFrameBuffer   ← Tier 1 target
Rank 2: 0x10003f920  cc=114  be=52  name=_validateCalibrationData  ← probably boring
```

That's the difference between an unfocused 20-function C3 scan and a targeted 3-function
deep dive. **It reduces C3+C6 runtime by ~60–80%** on large binaries.

### The approach

Run the ARM64 disassembly of each top-ranked function through a local code LLM.
The model reads ~50 lines of disassembly + surrounding strings/imports and returns
a probable function name and one-line description.

This is a solved problem — it's called **function name recovery** (Hex-Rays and
Ghidra both have plugins for it). We're doing it offline, in bulk, overnight, for free.

---

## Model selection for 4 GB VRAM

| Model | VRAM at Q8 | VRAM at Q4_K_M | Code quality | Verdict |
|-------|-----------|----------------|--------------|---------|
| Qwen2.5-Coder-3B | **~3.3 GB** | ~1.9 GB | Excellent for function naming | ✅ **Best choice** |
| Phi-3.5-mini (3.8B) | ~3.6 GB | ~2.1 GB | Good general code | ✅ Fits |
| CodeGemma-2B | ~2.1 GB | ~1.2 GB | Reasonable | ✅ Fits easily |
| Qwen2.5-Coder-7B | ~7.6 GB | **~4.3 GB** | Best quality | ❌ 300 MB over |
| Llama-3.1-8B | ~8.5 GB | ~4.7 GB | Good general | ❌ Too large |

**Winner: Qwen2.5-Coder-3B-Instruct-Q8_0.gguf (~3.3 GB)**  
- Fits in 4 GB with 700 MB headroom for context
- Alibaba's code-specific model — trained on assembly and disassembly
- Available from HuggingFace: `Qwen/Qwen2.5-Coder-3B-Instruct-GGUF`

---

## HDD impact assessment

This is the critical concern given the 1 TB spinning disk.

### One-time costs (acceptable)
| Operation | HDD IO | Time estimate | Notes |
|-----------|--------|---------------|-------|
| CUDA toolkit install | ~87 MB download, ~200 MB install | <2 min | apt install, done once |
| llama-cpp-python compile | CPU-bound, not disk-bound | ~12–15 min | Compiler output ~200 MB |
| Model download | 3.3 GB write | ~22–33 s @ 100–150 MB/s | One-time, done overnight |

### Per-session costs (key insight: nearly zero after first load)

The P1000 has 4 GB VRAM. The model is 3.3 GB. Once loaded:
- **First cold load from HDD:** 3.3 GB read ÷ 150 MB/s = **~22 seconds**
- **After load (model in VRAM + RAM cache):** subsequent queries are **nanoseconds** — the HDD is not touched again
- **32 GB RAM available:** OS will cache the model file in page cache after first read. Second launch (even after no queries): ~1–2 seconds (reading from RAM cache, not HDD)

**The HDD is only the bottleneck once per boot.** After that, the 32 GB RAM absorbs the model file into page cache and it's effectively as fast as an SSD for our use case.

### IO conflict with batch sweep workers
The batch sweep workers write small JSON + log files (<<1 MB per binary). They don't
do sustained sequential IO. The model load is a one-time 3.3 GB read — schedule it
**before launching a new batch sweep**, not during. Once loaded, there's zero IO conflict.

### Disk space
- Current free: **804 GB** on the root partition
- CUDA toolkit: ~200 MB installed
- llama-cpp-python: ~200 MB compiled
- Model file: ~3.3 GB
- **Total new disk usage: ~3.7 GB** — less than 0.5% of free space. Irrelevant.

---

## The right architecture: persistent server, not per-query reloads

The naive approach (load model, query, unload, repeat) would be terrible:
- 22-second HDD load penalty per binary × 400 binaries = **2.4 hours just loading the model**

The correct approach is `llama-cpp-python` in **server mode**:

```bash
# Launch once, keep running (loads model into VRAM once from HDD):
~/.venv_angr/bin/python3 -m llama_cpp.server \
    --model ~/models/qwen2.5-coder-3b-instruct-q8_0.gguf \
    --n_gpu_layers 99 \         # load all layers to GPU
    --host 127.0.0.1 \
    --port 8081 \
    --n_ctx 2048                # context window (enough for ~50 asm lines)
```

Then the batch naming script calls `http://localhost:8081/v1/chat/completions`
for each function — the model stays in VRAM, no disk access, ~0.5–2 seconds per query.

**400 functions × 1 second each = 6–7 minutes total naming pass** — compatible with
running immediately after the C2 sweep, before C3 starts.

---

## What we build: `c2_name_recovery.py`

```python
"""
C2 → LLM function name recovery
Reads C2 top-functions JSON, queries local llama.cpp server for each,
writes an augmented JSON with semantic names.

Usage:
    # Start llama server first (once per session):
    python3 -m llama_cpp.server --model ~/models/qwen2.5-coder-3b-q8_0.gguf \
        --n_gpu_layers 99 --port 8081 &

    # Then run name recovery on any binary:
    python3 c2_name_recovery.py --binary /usr/libexec/findmydeviced \
        --c2-json findmydeviced_c2_top_addrs.json \
        --output findmydeviced_named.json
"""

PROMPT_TEMPLATE = """\
You are a reverse engineer analysing a stripped ARM64 macOS binary ({binary_name}).
The following is a disassembly of a single function at address {addr:#x}.
Cyclomatic complexity: {cc}. Back edges: {be}.
Imports/strings visible near this function: {context_strings}

Disassembly:
{disasm}

Reply with ONLY a JSON object:
{{"name": "<probable_function_name>", "description": "<one sentence>", "confidence": "high|medium|low"}}
"""
```

The `context_strings` field is extracted by scanning ±256 bytes around the function
for `__cstring` and `__objc_methnames` references — these are the most useful naming hints.

---

## What this unlocks for the active pipeline

| Binary | C2 top function | With naming |
|--------|----------------|-------------|
| findmydeviced | sub_100012abc cc=377 | `_FMD_ProcessPeerMessage` ← C3 knows exactly what to look for |
| biometrickitd | sub_10004f920 cc=114 | `_BKD_ValidateEnrollmentData` |
| feedbackd | sub_100089ab0 cc=89 | `_FBD_ParseReportPayload` |

Named functions → smarter C3 template queries → fewer false positives → faster path to ASB.

---

## What it does NOT help with

| Pipeline stage | GPU helps? | Why |
|----------------|-----------|-----|
| C2 RMT eigenvalues | ❌ No | Matrices ≤2000×2000, CPU numpy already <5ms |
| C2 null model sampling (50 samples) | ❌ No | Already parallelised on CPU, faster than GPU overhead |
| Z3 / SAT solving in C1 | ❌ No | No CUDA SAT solver worth using |
| angr symbolic execution | ❌ No | angr is pure Python/CPU, not GPU-parallelisable |
| AFL++ fuzzing | ❌ No | Fuzzer target is macOS, not Linux |
| **LLM function naming** | ✅ **Yes** | This is the one use case that fits perfectly |
| Batch embedding similarity | ✅ Maybe | Run-3B embeddings on function IR for cross-binary search — v2 idea |

---

## Installation plan (do AFTER current batch sweep completes)

**Estimated total setup time: ~45 minutes, no impact on running batch sweep**

```bash
# Step 1: CUDA toolkit (2 min — do NOT do this while batch workers are running)
sudo apt install -y nvidia-cuda-toolkit         # 87 MB download, installs nvcc

# Step 2: llama-cpp-python with CUDA (12–15 min compile — CPU-bound, disk-quiet)
# Install into a NEW venv to avoid polluting venv_angr
python3 -m venv ~/.venv_llm
source ~/.venv_llm/bin/activate
CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python==0.3.20  # latest stable

# Step 3: Download model (one-time, ~22s write at 150 MB/s)
mkdir -p ~/models
# Qwen2.5-Coder-3B-Instruct-Q8_0 from HuggingFace
~/.venv_llm/bin/python3 -c "
from huggingface_hub import hf_hub_download
hf_hub_download(
    repo_id='Qwen/Qwen2.5-Coder-3B-Instruct-GGUF',
    filename='qwen2.5-coder-3b-instruct-q8_0.gguf',
    local_dir='${HOME}/models'
)
"
# Or: wget -P ~/models https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/resolve/main/qwen2.5-coder-3b-instruct-q8_0.gguf

# Step 4: Test it works
source ~/.venv_llm/bin/activate
python3 -m llama_cpp.server \
    --model ~/models/qwen2.5-coder-3b-instruct-q8_0.gguf \
    --n_gpu_layers 99 --port 8081 --host 127.0.0.1 &
sleep 15   # wait for model load
curl -s http://localhost:8081/v1/models   # should return model name
# → {"data":[{"id":"qwen2.5-coder-3b-instruct-q8_0.gguf",...}]}

# Step 5: Quick naming test
curl -s http://localhost:8081/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5-coder-3b-instruct-q8_0.gguf",
       "messages":[{"role":"user","content":"A function with cc=377 that processes incoming network data and calls malloc 12 times. Give it a name. Reply with JSON only: {\"name\":\"<name>\"}"}],
       "max_tokens":50}' | python3 -m json.tool
```

---

## Recommended timing

```
NOW:        Current batch sweep still running (sbin 77.6%, libexec 38.4%)
            → Do NOT install CUDA yet (avoid HDD contention during batch writes)

After sweep: Step 1–4 above (~45 min total)
             Write c2_name_recovery.py (~2 hours)
             Test on findmydeviced (highest priority Tier 1 candidate)

Overnight:   Named function pass on all C3-pending candidates
             Results in by morning alongside C3 output
```

---

## One more thing: CUDA toolkit version warning

The P1000 is CC 6.1. The Debian apt `nvidia-cuda-toolkit` is CUDA 12.4.
CUDA 12.4 supports CC 3.5+, so CC 6.1 is fine. But llama.cpp may emit:

```
WARNING: Pascal architecture (CC 6.1) detected. Some optimisations disabled.
```

This is expected. Pascal has no Tensor Core units (those start at Volta CC 7.0).
llama.cpp will still use CUDA GEMM for matrix multiplication — meaningfully faster
than CPU for our 3B model, just not as fast as a modern Ampere/Hopper card.

Expected inference speed on P1000 vs CPU-only:
- CPU-only (i7-4790 8T): ~8–12 tokens/second for 3B Q8
- P1000 GPU: ~25–40 tokens/second for 3B Q8 (3–4× speedup)

For function naming queries (50 tokens output, 200 tokens input), that's
~2–3 seconds CPU vs ~1 second GPU per query. Meaningful for batch runs.

---

## Summary

| Question | Answer |
|----------|--------|
| Will it work? | ✅ Yes — Qwen2.5-Coder-3B-Q8 fits in 4 GB with 700 MB headroom |
| HDD impact | ✅ Negligible — one-time 22s load, then RAM-cached; no IO conflict with batch |
| Impact on angr workers | ✅ None — GPU is separate hardware, CPU usage is only during compile |
| Setup time | ✅ ~45 min, after current batch sweep completes |
| Research value | ✅ High — function naming reduces C3 false positives, accelerates every future analysis |
| Risk | ⚠️ Low — separate venv, CUDA toolkit is Debian-packaged, easy to remove |
