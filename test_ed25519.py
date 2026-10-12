# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Ed25519 against RFC 8032 section 7.1 test vectors (parsed from fonti/rfc8032.txt) and, if installed,
the optional `cryptography` package on generated and altered signatures. Exit 0 iff all pass."""
import os, re, sys, hashlib, random
import ed25519_rfc8032 as ed

def parse(path):
    t = open(path).read()
    sec = t[t.index("\n7.1.  Test Vectors for Ed25519\n"):t.index("\n7.2.  Test Vectors for Ed25519ctx\n")]
    res = []
    for blk in sec.split("-----TEST ")[1:]:
        lines = blk.split("\n")
        name = lines[0].strip()
        d, cur = {}, None
        for ln in lines[1:]:
            m = re.match(r"\s+(SECRET KEY|PUBLIC KEY|MESSAGE|SIGNATURE)\b", ln)
            if m:
                cur = m.group(1).split()[0]; d[cur] = ""; continue
            if cur and re.fullmatch(r"\s+[0-9a-f]+", ln):
                d[cur] += ln.strip()
        res.append((name, {k: bytes.fromhex(v) for k, v in d.items()}))
    return res

vecs = parse("fonti/rfc8032.txt")
fails = 0
for name, d in vecs:
    sk, pk, msg, sig = d["SECRET"], d["PUBLIC"], d["MESSAGE"], d["SIGNATURE"]
    ok = ed.public_key(sk) == pk and ed.sign(sk, msg) == sig and ed.verify(pk, msg, sig)
    bad = bytearray(sig); bad[5] ^= 1
    ok = ok and not ed.verify(pk, msg, bytes(bad))
    print("RFC8032 TEST %-9s len(msg)=%4d %s" % (name, len(msg), "OK" if ok else "FAIL"))
    fails += not ok
if len(vecs) != 5:
    print("expected 5 RFC vectors, parsed", len(vecs)); fails += 1
# S >= L must be rejected (RFC 8032 5.1.7): add L to S of TEST 1
name, d = vecs[0]
s = int.from_bytes(d["SIGNATURE"][32:], "little") + ed.L
mall = d["SIGNATURE"][:32] + s.to_bytes(32, "little")
r = ed.verify(d["PUBLIC"], d["MESSAGE"], mall)
print("S+L malleated signature rejected:", not r); fails += r
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("cryptography not installed: cross-check skipped (optional)")
else:
    rnd = random.Random(20261011)
    disagree = 0
    for i in range(300):
        sk = bytes(rnd.getrandbits(8) for _ in range(32))
        msg = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 200)))
        sig = ed.sign(sk, msg)
        pk = ed.public_key(sk)
        ref = Ed25519PrivateKey.from_private_bytes(sk)
        if ref.sign(msg) != sig: disagree += 1
        for variant in range(3):
            m2, s2 = msg, bytearray(sig)
            if variant == 1: s2[rnd.randrange(64)] ^= 1 << rnd.randrange(8)
            if variant == 2: m2 = msg + b"\x00"
            mine = ed.verify(pk, m2, bytes(s2))
            try:
                Ed25519PublicKey.from_public_bytes(pk).verify(bytes(s2), m2); theirs = True
            except InvalidSignature:
                theirs = False
            disagree += mine != theirs
    import cryptography
    print("cryptography %s cross-check: 300 keys x (sign + 3 verify): %d disagreements" % (cryptography.__version__, disagree))
    fails += disagree
print("FAILS", fails)
sys.exit(1 if fails else 0)
