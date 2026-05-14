# Case Studies — metis Toolchain

Worked examples of the C2 → C3 → VEX IR → binary analysis pipeline applied to real targets.

| File | Target | Outcome |
|---|---|---|
| `cve_2022_23093_darwin.md` | macOS `/sbin/ping` (arm64e) | Primary finding: NOT vulnerable to CVE-2022-23093. Secondary logic bug (`oip+1` fixed offset) confirmed in binary at `0x10000300c`/`0x100003018` by otool scan. Not filed (no security impact). |
| `windows_ping_icmp_surface.md` | Windows 11 `ping.exe` (x64) | User-mode surface CLEAN. Two-tier hardcoded allocation (8184/65607 bytes) is deliberate over-provisioning. OptionsData stack overflow impossible (40-byte IPv4 IHL ceiling). Validated by 4 LLMs. Real surface is `tcpip.sys`. |

## Key reusable techniques documented

- **Darwin case study:** VEX IR constant-folding detection via otool sliding-window scan; C3 template limitations for buffer-as-argument patterns; loopback raw socket injection failure on macOS
- **Windows case study:** PE binary acquisition from Microsoft symbol server without VM access; pefile+capstone IAT resolution replacing angr KB for Windows imports; multi-LLM API contract validation
