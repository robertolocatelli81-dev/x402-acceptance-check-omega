# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Mutant b64-padding-allowed: is it equivalent? Compares the real b64url_strict with the mutant on
200 000 random strings over the base64url alphabet plus '=', '+', '/' (lengths 0-12), and on every string
of length <= 3 over a reduced alphabet. Equivalent iff outcomes (bytes or rejection) never differ."""
import itertools, random, re
import acceptance_check as ac
src = open("acceptance_check.py").read()
old = r'_B64URL = re.compile(r"[A-Za-z0-9_-]*")'
assert src.count(old) == 1
ns = {}
exec(compile(src.replace(old, r'_B64URL = re.compile(r"[A-Za-z0-9_=-]*")'), "mut", "exec"), ns)
def outcome(f, s):
    try: return f(s)
    except ValueError: return "REJ"
alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/"
rnd = random.Random(7); diff = 0; with_eq_accepted = 0
for _ in range(200000):
    s = "".join(rnd.choice(alpha) for _ in range(rnd.randrange(0, 13)))
    a, b = outcome(ac.b64url_strict, s), outcome(ns["b64url_strict"], s)
    diff += a != b
small = "AQgw_-="
n = 0
for L in range(0, 6):
    for t in itertools.product(small, repeat=L):
        s = "".join(t); n += 1
        diff += outcome(ac.b64url_strict, s) != outcome(ns["b64url_strict"], s)
print("random 200000 + exhaustive %d: %d differences" % (n, diff))
# positive control: the comparison detects a real difference (mutant without the round-trip check)
ns2 = {}
exec(compile(src.replace(old, r'_B64URL = re.compile(r"[A-Za-z0-9_=-]*")').replace(
    'raise ValueError("non-canonical base64url (trailing bits)")', "pass"), "mut2", "exec"), ns2)
d2 = sum(outcome(ac.b64url_strict, s) != outcome(ns2["b64url_strict"], s) for s in ["QQ==", "QR", "QQ"])
print("control (padding + no round-trip): %d/3 strings differ (must be > 0)" % d2)
