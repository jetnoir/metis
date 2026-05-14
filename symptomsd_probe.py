#!/usr/bin/env python3
"""
symptomsd_probe.py — Probe symptomsd TCP listener for XPC message format,
auth bypass potential, and nstat proxy attack surface.

Run on macOS VM (SIP-disabled, as unprivileged user):
    python3 symptomsd_probe.py [--port 56824] [--host 127.0.0.1]

Protocol summary (from prior lldb analysis):
  TCP → SymptomEvaluator.framework (symtrans_main)
      → my_client_handle_new / __my_client_handle_new_block_invoke
      → XPC-over-Network.framework dispatcher (OS_xpc_dictionary / OS_xpc_error)
      → "payload" key = binary nstat data
      → NWStatsManager._drainReadBuffer → kernel nstat socket

nstat message header (from _drainReadBuffer disassembly):
  struct nstat_msg_hdr {
      uint64_t context;   // offset 0
      uint32_t type;      // offset 8
      uint16_t length;    // offset 12 (0xc) — checked: must be >= 0x10
      uint16_t flags;     // offset 14
  };  // total 16 bytes

Auth: com.apple.symptom_analytics.delegate_symptom entitlement
  checked at connection time, stored at [client+0x80].
"""
from __future__ import annotations
import socket, struct, time, sys, argparse, os

parser = argparse.ArgumentParser()
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=56824)
parser.add_argument('--timeout', type=float, default=3.0)
args = parser.parse_args()

HOST    = args.host
PORT    = args.port
TIMEOUT = args.timeout

print(f'[*] symptomsd TCP Probe')
print(f'    Target : {HOST}:{PORT}')
print(f'    Timeout: {TIMEOUT}s')
print()

results = []

def make_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((HOST, PORT))
    return s

def recv_all(s, timeout=None):
    s.settimeout(timeout or TIMEOUT)
    data = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    return data

def probe(label: str, payload: bytes | None, expect_close: bool = False):
    """Send payload (or nothing) and record response."""
    print(f'[{label}]')
    try:
        s = make_conn()
        print(f'  connected OK')
        if payload is not None:
            s.sendall(payload)
            print(f'  sent {len(payload)} bytes: {payload[:32].hex()}{"..." if len(payload) > 32 else ""}')
        resp = recv_all(s)
        try:
            s.close()
        except Exception:
            pass
        status = 'connection reset' if not resp and expect_close else f'{len(resp)} bytes received'
        print(f'  response: {status}')
        if resp:
            print(f'  hex[0:64]: {resp[:64].hex()}')
            print(f'  ascii[0:64]: {repr(resp[:64])}')
        results.append({'label': label, 'sent': len(payload or b''), 'recv': len(resp),
                        'resp_hex': resp[:128].hex(), 'connected': True})
    except ConnectionRefusedError:
        print(f'  REFUSED — nothing listening on {HOST}:{PORT}')
        results.append({'label': label, 'error': 'refused', 'connected': False})
    except Exception as e:
        print(f'  ERROR: {e}')
        results.append({'label': label, 'error': str(e), 'connected': False})
    print()
    time.sleep(0.5)


# ── Test 1: Connect, send nothing — does server speak first? ─────────────────
probe('T1_server_speaks_first', payload=None)

# ── Test 2: Send raw garbage ─────────────────────────────────────────────────
probe('T2_garbage', b'AAAA' * 16)

# ── Test 3: Send minimal nstat header (no XPC wrapper) ───────────────────────
# Header: context=0, type=ADD_ALL_SRCS(0x3E9), length=0x10, flags=0
nstat_hdr = struct.pack('<QIHH', 0x0000000000000001, 0x000003E9, 0x0010, 0x0000)
probe('T3_raw_nstat_ADD_ALL_SRCS', nstat_hdr)

# ── Test 4: Undersized nstat header (length < 0x10) — triggers skip? ─────────
nstat_short = struct.pack('<QIHH', 0xdeadbeef, 0x000003E9, 0x0008, 0x0000)
probe('T4_nstat_short_length', nstat_short)

# ── Test 5: XPC binary framing — public XPC-over-network magic ───────────────
# From public XPC wire format research:
# Bytes 0-3: magic = 0x29B00B92 (libxpc network magic observed in traffic captures)
# Bytes 4-7: flags
# Bytes 8-15: message ID
# Bytes 16-19: body size (LE)
# Then body (XPC serialised dictionary)
#
# Alternative: Apple uses a custom framing. Try both 0x29B00B92 and 0x58504300.
for magic_val, label in [(0x29B00B92, 'xpc_net'), (0x58504300, 'xpc_null')]:
    xpc_frame = struct.pack('<IIQII',
        magic_val,     # magic
        0x00000001,    # flags: body present
        0,             # message id
        0,             # body size = 0
        0,             # padding
    )
    probe(f'T5_xpc_magic_{label}', xpc_frame)

# ── Test 6: Null bytes / zeroed nstat header ─────────────────────────────────
probe('T6_null_bytes', b'\x00' * 64)

# ── Test 7: Large payload — triggers any length confusion? ───────────────────
# nstat header claiming length=0xFFFF (65535) but only 16 bytes sent
nstat_big = struct.pack('<QIHH', 0x1234567890abcdef, 0x000003E9, 0xFFFF, 0x0000)
probe('T7_nstat_oversize_claim', nstat_big)

# ── Test 8: Multiple nstat headers concatenated ───────────────────────────────
hdr1 = struct.pack('<QIHH', 0x0000000000000001, 0x000003E9, 0x0010, 0x0000)
hdr2 = struct.pack('<QIHH', 0x0000000000000002, 0x000003EC, 0x0010, 0x0000)
probe('T8_two_nstat_headers', hdr1 + hdr2)

# ── Test 9: Type 0x2716 SRC_DETAILS (kernel→user, minimum 0x98 bytes) ────────
# Send this type with exactly 0x97 bytes (one short of minimum)
nstat_details_short = struct.pack('<QIHH', 0xAA, 0x00002716, 0x97, 0x0000) + b'\x00' * (0x97 - 16)
probe('T9_nstat_SRC_DETAILS_undersized', nstat_details_short)

# ── Summary ───────────────────────────────────────────────────────────────────
print('=' * 60)
print(f'SUMMARY — {len(results)} probes')
connected = [r for r in results if r.get('connected')]
refused   = [r for r in results if r.get('error') == 'refused']
errors    = [r for r in results if r.get('error') and r.get('error') != 'refused']
got_data  = [r for r in connected if r.get('recv', 0) > 0]

print(f'  Connected:    {len(connected)}/{len(results)}')
print(f'  Got data:     {len(got_data)} probes')
print(f'  Refused:      {len(refused)}')
print(f'  Other errors: {len(errors)}')
print()
if got_data:
    print('  *** DATA RECEIVED — server responded to unauthenticated client ***')
    for r in got_data:
        print(f'    [{r["label"]}]: {r["recv"]} bytes  hex: {r["resp_hex"][:40]}')
else:
    print('  No data returned to unauthenticated probe (auth check likely gates all responses)')
