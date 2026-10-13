# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""The 12 cases of "Taming the many EdDSAs" (novifinancial/ed25519-speccheck, cases.txt at 6551933, pinned in
fetch_sources.py) through ed25519_rfc8032.verify, on each case's own message (the raw bytes of its hex), as
TKCollective ran them on x402-foundation/tsc#4 (2026-10-13). cases.txt is read as data only.

For each case: verify()'s result, and the first of verify()'s own checks that refuses it (decoding, S < L,
small order, mixed order, the cofactorless equation), computed here from the point arithmetic of the module
so that the reason is not read back from verify(). The two equations of RFC 8032 5.1.7 step 3 are reported too.
With --json OUT the rows are written as JSON. Positive control first: RFC 8032 7.1 TEST 1 must verify, and a
copy with one bit of S flipped must not; otherwise the bench exits 1 before any case is run.

python3 speccheck.py [--json OUT]   -> exit 0 iff the positive control holds and the 12 cases were read
"""
import json
import os
import sys

import ed25519_rfc8032 as ed

HERE = os.path.dirname(os.path.abspath(__file__))
TEST1 = ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


def read_cases(path):
    with open(path, "rb") as f:
        lines = f.read().decode("ascii").split("\n")
    n = int(lines[0])
    rows = []
    for i in range(n):
        trip = lines[1 + 3 * i:4 + 3 * i]
        kv = dict(ln.split("=", 1) for ln in trip)
        if set(kv) != {"msg", "pbk", "sig"}:
            raise SystemExit("case %d: unexpected lines %r" % (i, trip))
        rows.append({k: bytes.fromhex(v) for k, v in kv.items()})
    if any(ln.strip() for ln in lines[1 + 3 * n:]):
        raise SystemExit("cases.txt: content after case %d" % (n - 1))
    return rows


def order_class(P):
    """'small' ([8]P neutral), 'prime' ([L]P neutral, not neutral), or 'mixed'; computed here."""
    neutral = ed._encode_point(ed._NEUTRAL)
    if ed._encode_point(ed._scalar_mul(8, P)) == neutral:
        return "small"
    if ed._encode_point(ed._scalar_mul(ed.L, P)) == neutral:
        return "prime"
    return "mixed"


def diagnose(pub, msg, sig):
    A, R = ed._decode_point(pub), ed._decode_point(sig[:32])
    S = int.from_bytes(sig[32:], "little")
    d = {"A": "undecodable" if A is None else order_class(A), "R": "undecodable" if R is None else order_class(R),
         "S_below_L": S < ed.L, "cofactorless": None, "cofactored": None}
    if A is not None and R is not None:
        k = int.from_bytes(ed._h512(sig[:32] + pub + msg), "little") % ed.L
        lhs, rhs = ed._scalar_mul(S, ed._B), ed._add(R, ed._scalar_mul(k, A))
        d["cofactorless"] = ed._encode_point(lhs) == ed._encode_point(rhs)
        d["cofactored"] = ed._encode_point(ed._scalar_mul(8, lhs)) == ed._encode_point(ed._scalar_mul(8, rhs))
    # the first of verify()'s checks, in verify()'s order, that refuses the case
    mixed_checked = hasattr(ed, "_prime_order")
    if d["A"] == "undecodable" or d["R"] == "undecodable":
        d["reason"] = "point does not decode (5.1.3): " + ",".join(x for x in "AR" if d[x] == "undecodable")
    elif not d["S_below_L"]:
        d["reason"] = "S >= L (5.1.7 step 1)"
    elif "small" in (d["A"], d["R"]):
        d["reason"] = "small-order " + ",".join(x for x in "AR" if d[x] == "small") + " (sentence 4)"
    elif mixed_checked and "mixed" in (d["A"], d["R"]):
        d["reason"] = "mixed-order " + ",".join(x for x in "AR" if d[x] == "mixed") + " (sentence 9)"
    elif not d["cofactorless"]:
        d["reason"] = "cofactorless equation fails (5.1.7 step 3)"
    else:
        d["reason"] = None
    return d


def main(argv):
    out = None
    if argv[1:2] == ["--json"] and len(argv) == 3:
        out = argv[2]
    elif len(argv) != 1:
        raise SystemExit(__doc__)
    pk, m, s = (bytes.fromhex(x) for x in TEST1)
    bad = bytearray(s)
    bad[40] ^= 1
    pos = ed.verify(pk, m, s) is True and ed.verify(pk, m, bytes(bad)) is False
    print("positive control (RFC 8032 7.1 TEST 1 verifies, S with one bit flipped does not):", "ok" if pos else "FAIL")
    if not pos:
        return 1
    rows = []
    for i, c in enumerate(read_cases(os.path.join(HERE, "fonti", "speccheck_cases.txt"))):
        got = ed.verify(c["pbk"], c["msg"], c["sig"])
        d = diagnose(c["pbk"], c["msg"], c["sig"])
        if got != (d["reason"] is None):
            print("case %d: verify() = %r but the diagnosis says %r" % (i, got, d["reason"]))
            return 1
        rows.append(dict(d, case=i, verify=got))
        print("%2d  %-8s  A=%-11s R=%-11s S<L=%-5s cofactorless=%-5s cofactored=%-5s  %s" % (
            i, "accepts" if got else "rejects", d["A"], d["R"], d["S_below_L"], d["cofactorless"], d["cofactored"],
            d["reason"] or "-"))
    if out:
        with open(out, "w") as f:
            json.dump(rows, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
