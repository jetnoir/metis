# Case Study: Windows 11 ping.exe — CVE-2022-23093 Analog Hunt
## C2 → Binary Analysis → Multi-LLM Validation

**Date:** 2026-04-17  
**Target:** `ping_w11_24h2_x64.exe` — Windows 11 24H2 (10.0.26100.1150), x86-64 PE  
**Source:** Microsoft symbol server via winbindex index (SHA256 verified)  
**CVE analog:** CVE-2022-23093 — FreeBSD `pr_pack()` IP options stack overflow  
**Outcome:** User-mode surface CLEAN — deliberate over-provisioning, no overflow possible  
**Validation:** Gemini 2.5 Pro, ChatGPT o3, Grok 3, DeepSeek R2 — unanimous  
**Scripts:** `windows-ping-audit/run_c2_ping_windows.py`

---

## 1. Background and Motivation

CVE-2022-23093 is a `pr_pack()` stack overflow in FreeBSD ping caused by `memcpy()` of
up to 60 bytes (attacker-controlled IP options) into a 20-byte fixed stack buffer. macOS
was confirmed immune (see `cve_2022_23093_darwin.md`). The question: does Windows `ping.exe`
have an analogous vulnerability in its ICMP reply buffer handling?

**Key architectural difference from BSD:** Windows ping is not a raw-socket ICMP
implementation. It delegates all ICMP I/O to `iphlpapi.dll` via `IcmpSendEcho2Ex()`,
which issues an `NtDeviceIoControlFile` call to `tcpip.sys`. The kernel parses the network
packet, validates the IP header, and returns a pre-structured `ICMP_ECHO_REPLY` to user
space. `ping.exe` never sees a raw ICMP packet — it only sees the kernel's output struct.

This shifts the overflow-equivalent surface from parse-time (as in BSD `pr_pack()`) to
**allocation-time** (does `ping.exe` allocate enough space for the kernel to fill?) and
**consumption-time** (does the response handler copy option data into a bounded buffer?).

---

## 2. Binary Acquisition

No Windows VM access required. Binaries downloaded directly from Microsoft's symbol
server using the winbindex index (https://winbindex.m417z.com):

```bash
# Get index
curl https://winbindex.m417z.com/data/by_filename_compressed/ping.exe.json.gz \
  | gunzip > ping_exe_index.json

# Parse to find most recent x64 and build MSDL URL
# Format: https://msdl.microsoft.com/download/symbols/{name}/{timestamp:08X}{virtualSize:x}/{name}

# Windows 11 24H2 (10.0.26100.1150, x64):
curl -H "User-Agent: Microsoft-Symbol-Server/10.0.10036.206" \
  https://msdl.microsoft.com/download/symbols/PING.EXE/D9C2AA09C000/PING.EXE \
  -o ping_w11_24h2_x64.exe

# Verify against index SHA256:
sha256sum ping_w11_24h2_x64.exe
# 96f2abac2542f4cd59628d14af1f1935febfa56c675c3430e108b5465ebc823e ✓
```

Same approach works for any Windows PE in the winbindex catalogue. The MSDL key is
`{TimeDateStamp:08X}{SizeOfImage:x}` from the PE optional header — construct it from
the JSON index's `timestamp` and `virtualSize` fields.

Also acquired: `iphlpapi.dll` (10.0.26100.1150, same build) for future analysis.

---

## 3. C2 Screen (`run_c2_ping_windows.py`)

```python
proj = angr.Project("ping_w11_24h2_x64.exe", auto_load_libs=False,
                    main_opts={'arch': archinfo.arch_from_id('x86_64')})
result = C2RMTAnalysis.from_project(proj).run()
```

**Results:**

| Metric | Value |
|---|---|
| Functions discovered | 138 |
| Call graph | 132 nodes, 153 edges |
| Binary spectral z-scores | Within normal range (all \|z\| < 2.0) |

**Top functions:**

| Rank | Address | Cyclomatic | Back-edges | Score |
|---|---|---|---|---|
| 1 | `0x140002890` | **155** | **25** | 2.5823 |
| 2 | `0x140001f60` | 38 | 15 | 1.9689 |
| 3 | `0x140001300` | 18 | 2 | 1.2863 (`_start`) |

The dominant function `sub_140002890` has cyclomatic=155 in a 44KB binary with 138
functions — an extreme outlier that immediately identifies the primary analysis target.

---

## 4. Function Identification (pefile + capstone + IAT resolution)

angr's KB-based callee resolution failed for import thunks in the PE (IAT entries are
runtime-resolved addresses, not static). Replaced with `pefile + capstone` for direct
disassembly with IAT lookup:

```python
pe = pefile.PE("ping_w11_24h2_x64.exe")
iat = {imp.address: imp.name.decode()
       for entry in pe.DIRECTORY_ENTRY_IMPORT
       for imp in entry.imports if imp.name}

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# Resolve CALL [rip + disp] → compute IAT slot VA → lookup name
```

**`sub_140002890`** — the entire ping main loop (cyclomatic=155):
- Calls: `WSAStartup`, `RtlIpv4StringToAddressW`, `IcmpCreateFile`, `Icmp6CreateFile`,
  `LocalAlloc` (×2), `IcmpSendEcho2Ex`, `Icmp6SendEcho2`, `GetLastError`,
  `GetIpForwardTable`, `GetNameInfoW`, `InetNtopW`, `fwprintf`, `Sleep`,
  `IcmpCloseHandle`, `LocalFree` (×2), `exit` (×4)
- **Conclusion:** This is `main()` + the ping loop + result printing, all in one function.
  High cyclomatic reflects: IPv4/IPv6 dispatch, option-flag handling (`-r`, `-s`, `-i`,
  `-T`), per-packet retry logic, error-path multiplexing.

**`sub_140001f60`** — response handler / output formatter (cyclomatic=38):
- Calls: `GetNameInfoW`, `InetNtopW`, `_security_check_cookie`
- **Stack frame:** `SUB RSP, 0x8C0` = **2240 bytes**
- First operation: `MOV RDI, [RCX + 0x20]` — reads `ICMP_ECHO_REPLY.Options.OptionsData`
- **Conclusion:** Formats and prints each ping reply (RTT, TTL, sequence). The
  `_security_check_cookie` confirms stack-allocated buffers large enough to trigger
  the compiler's stack-smashing protector. The immediate read of `OptionsData` means
  this function processes IP option data (record route / timestamp display when
  `-r`/`-s` is active).

---

## 5. Reply Buffer Allocation Analysis

The critical `LocalAlloc` for the IcmpSendEcho2Ex reply buffer, at `0x14000333b`:

```asm
; r15d = send data size (from -l option, default = 0x20 = 32 bytes)
0x140003320  mov  eax, 0x1ff8     ; = 8184 bytes  (small-data path)
0x140003325  mov  ecx, 0x10047    ; = 65607 bytes  (large-data path)
0x14000332a  cmp  r15d, 0x20      ; is send data > 32 bytes?
0x14000332e  cmova eax, ecx       ; if yes: use 65607, else 8184
0x140003331  xor  ecx, ecx        ; flags = 0 (LMEM_FIXED)
0x140003333  mov  esi, eax        ; save allocation size
0x140003335  mov  edx, eax        ; size arg for LocalAlloc
0x14000333b  call LocalAlloc      ; ← reply buffer
```

**Two-tier hardcoded allocation strategy:**

| Condition | Reply buffer size | Rationale |
|---|---|---|
| `-l` ≤ 32 bytes (default) | **8184** (0x1FF8) | 8192 − 8 = exactly 2 pages − heap header |
| `-l` > 32 bytes | **65607** (0x10047) | 65535 + 72 overhead ceiling |

---

## 6. Buffer Adequacy Analysis

### ICMP_ECHO_REPLY layout (x64, as used by ping.exe)

```
+0x00  Address        DWORD   4 bytes
+0x04  Status         DWORD   4 bytes
+0x08  RoundTripTime  DWORD   4 bytes
+0x0C  DataSize       WORD    2 bytes
+0x0E  Reserved       WORD    2 bytes
+0x10  Data           PVOID   8 bytes  (pointer into reply buffer)
+0x18  Options:
+0x18    Ttl          UCHAR   1 byte
+0x19    Tos          UCHAR   1 byte
+0x1A    Flags        UCHAR   1 byte
+0x1B    OptionsSize  UCHAR   1 byte
+0x20    OptionsData  PUCHAR  8 bytes  (pointer into reply buffer)
                              ← confirmed by [RCX+0x20] in sub_140001f60
Total: 40 bytes
```

### Required buffer size formula

```
sizeof(ICMP_ECHO_REPLY)   =  40 bytes
+ RequestDataSize          =  up to 65499 bytes (-l max)
+ 8                        =  ICMP error overhead (documented)
+ sizeof(IO_STATUS_BLOCK)  =  16 bytes (async variant requirement)
+ MaxIpOptionsSize         =  up to 40 bytes (IPv4 IHL limit: 4-bit field, max 60-byte header − 20 fixed = 40)
─────────────────────────────────────────────────────────────────
Worst case (-l 65499 -r 9): 40 + 65499 + 8 + 16 + 39 = 65602 bytes
```

### Verdict

| Case | Required | Allocated | Margin |
|---|---|---|---|
| Default (`-l 32 -r 9`) | ~135 bytes | 8184 bytes | +8049 bytes |
| Maximum (`-l 65499 -r 9`) | 65602 bytes | 65607 bytes | +5 bytes |

Both allocations are sufficient. The hardcoded constants are **deliberate conservative
ceilings**, not tight calculations — a known Microsoft technique to avoid heap
fragmentation and runtime size calculation complexity.

---

## 7. Stack Buffer Analysis — `sub_140001f60`

**Hypothesis:** Could `OptionsData` be copied into the 2240-byte stack frame without a
size check, and could `OptionsSize` be attacker-controlled?

**Analysis:**

1. `OptionsSize` is populated by `tcpip.sys` from the IP header's IHL field:
   `OptionsSize = (ip_hl << 2) - sizeof(struct ip) = at most 40 bytes`
2. IHL is a 4-bit field — physical maximum = 0xF = 60-byte header → 40 bytes of options
3. The kernel validates IHL before populating the struct; an attacker on the network
   cannot cause `OptionsSize > 40` to be returned to user space
4. 40 bytes into a 2240-byte stack frame = no overflow, regardless of whether
   `ping.exe` checks `OptionsSize` before copying

**Conclusion:** Even a completely unchecked `memcpy(stack_buf, OptionsData, OptionsSize)`
in `sub_140001f60` cannot overflow the 2240-byte frame. The protocol-level hard limit
neutralises the risk.

---

## 8. Multi-LLM Validation

Framed the binary findings as a structured question and put it to four LLMs:
**Gemini 2.5 Pro, ChatGPT o3, Grok 3, DeepSeek R2.** All four returned identical
conclusions on every point:

| Question | Consensus |
|---|---|
| Is 65607 sufficient for `-l 65499 -r 9`? | **Yes** — covers 65602-byte worst case with margin |
| Is 8184 sufficient for default + max options? | **Yes** — 135 bytes needed, 8184 allocated |
| Known CVEs on this path? | **None** — all prior Windows ICMP CVEs are in `tcpip.sys` |
| Stack overflow via OptionsData? | **Not possible** — kernel clamps to 40 bytes, frame is 2240 |

**Additional context from LLMs:**
- The 8184 = 8192 − 8 size is a classic Windows heap page-alignment trick (8KB block − heap header, no page spill)
- 65607 = 65535 + 72; the 72-byte overhead conservatively covers all struct/alignment/error scenarios
- "Ping of Death" class bugs in Windows have exclusively lived in `tcpip.sys`, not `ping.exe`

---

## 9. Findings Summary

| Finding | Result |
|---|---|
| CVE-2022-23093 analog (reply buffer overflow) | **NOT PRESENT** — over-allocated by design |
| Stack overflow via IP OptionsData | **NOT PRESENT** — bounded at 40 bytes by IPv4 IHL |
| Known CVEs on this surface | **None** |
| `iphlpapi.dll` IcmpParseReplies | **Not yet analysed** — acquired, pending C2 screen |

**Not filed:** No security impact. Allocation strategy is conservative and correct.

---

## 10. Methodological Lessons

### L1 — PE IAT resolution requires pefile, not angr KB

angr's `CFGFast` does not reliably resolve Windows IAT thunk names in a single-session
analysis. Use `pefile.PE()` to build an IAT map (`import.address → name`) and resolve
call targets by computing the RIP-relative IAT slot address from capstone disassembly.
This is fast, reliable, and requires no angr KB.

### L2 — Binary acquisition without VM access

Microsoft's symbol server (`msdl.microsoft.com`) hosts all Windows system binaries
indexed by winbindex. URL format:
```
https://msdl.microsoft.com/download/symbols/{name}/{TimeDateStamp:08X}{SizeOfImage:x}/{name}
User-Agent: Microsoft-Symbol-Server/10.0.10036.206
```
SHA256 verification against the winbindex JSON index confirms authenticity. No VM,
no installation media, no admin access required.

### L3 — Multi-LLM validation as a force multiplier

For questions about API contracts and undocumented struct layouts (here: exact
`IcmpSendEcho2Ex` buffer formula, `ICMP_ECHO_REPLY` field offsets, `IO_STATUS_BLOCK`
requirement), polling 4 LLMs simultaneously is faster than reading MSDN and produces
cross-validated answers. Unanimous agreement across Gemini/ChatGPT/Grok/DeepSeek
increases confidence significantly.

### L4 — Know when to stop at user-mode

Windows networking security lives in `tcpip.sys` (kernel), not in user-mode wrappers.
When the user-mode binary is a thin wrapper around a kernel API (as `ping.exe` is around
`NtDeviceIoControlFile → tcpip.sys`), the interesting attack surface is the kernel
driver, not the application. Pursuing `ping.exe` past the allocation analysis is
diminishing returns without a kernel debugger.

---

## 11. Next Steps (if continuing Windows research)

1. **Fix Windows VM access** (password reset via Utilman trick — see session notes)
2. **C2 screen on `iphlpapi.dll`** — `IcmpParseReplies()` is the user-mode boundary
   between raw kernel output and the `ICMP_ECHO_REPLY` struct; worth one pass
3. **`tcpip.sys` analysis** — the real surface for Windows ICMP bugs:
   - Requires kernel debugger (WinDbg + kernel debugging enabled in VM)
   - Target: ICMPv4/v6 receive path, fragmentation reassembly, option parsing
   - Prior art: CVE-2020-16898 (ICMPv6 RA), CVE-2021-24086 (IPv6 frag), CVE-2024-38063

---

## 12. Artefacts

| File | Contents |
|---|---|
| `windows-ping-audit/ping_w11_24h2_x64.exe` | Windows 11 24H2 ping.exe (SHA256 verified) |
| `windows-ping-audit/iphlpapi_w11_24h2_x64.dll` | Matching iphlpapi.dll (SHA256 verified) |
| `windows-ping-audit/run_c2_ping_windows.py` | C2 RMT screen script |
| `windows-ping-audit/win_ping_c2_results.txt` | C2 output (138 functions, top-20 ranked) |
| `windows-ping-audit/win_ping_c2_top_addrs.json` | Machine-readable ranked addresses |
