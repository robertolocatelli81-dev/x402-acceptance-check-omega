# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Tests for the alignment with the README of examples/acceptance-record-cold at 90b5032 (2026-10-12),
sentences 1-4 of "Inputs the vectors do not yet pin", and with RFC 7515 7.2.1/7.2.2 for the JWS object.

1. The 8 points of small order, derived here from the curve equation (y = 1; y = -1, x = 0; y = 0,
   x^2 = -1; the four points of order 8 as odd multiples of one of them), and their 6 non-canonical encodings.
2. ed25519_rfc8032.verify refuses every small-order A and every small-order R (8 x 8 x 16 messages, S = 0).
3. The checker: each small-order key in the trust material, against forged signatures (R small-order, S = 0,
   searched so that R + [k]A is the neutral point, i.e. the cofactorless equation holds) on several signed
   payloads, gives key_unresolved, with policy_refusal equal to the completeness declaration (sentence 4).
4. R = neutral point signed by the honest key holder (S = k*a): signature_invalid (sentence 4).
5. New member names at every level of the input, random values: refused where our grammar is closed,
   ignored and listed in notes where a text says to ignore (README sentence 1, RFC 7515, RFC 7517).
6. The order sentence of the README: undecodable protected header before the key step, a payload that is
   not a JSON object after it.

Expected values are written from those texts, not read back from the checker.
python3 test_piccolo_ordine.py   -> exit 0 iff every check holds
"""
import hashlib
import random
import sys

import acceptance_check as ac
import ed25519_rfc8032 as ed
import test_generativi as tg

FAILS = []
COUNT = [0]


def check(name, cond, quiet=False):
    COUNT[0] += 1
    if not quiet or not cond:
        print("%-72s %s" % (name, "ok" if cond else "FAIL"))
    if not cond:
        FAILS.append(name)


p, L = ed.p, ed.L


def enc(y, sign):
    return (y | (sign << 255)).to_bytes(32, "little")


def pt(P):
    return ed._encode_point(P)


NEUTRAL = pt(ed._NEUTRAL)


def key_problem(pub):
    """ed.key_problem, or a marker when the module has none (so that older code fails check by check)."""
    f = getattr(ed, "key_problem", None)
    return f(pub) if f else "ed.key_problem missing"

# ---------------------------------------------------------------- 1. the 8 points, from the curve equation
sqrt_m1 = pow(2, (p - 1) // 4, p)                       # a square root of -1 mod p (p = 5 mod 8)
assert sqrt_m1 * sqrt_m1 % p == p - 1
by_equation = {enc(1, 0), enc(p - 1, 0), enc(0, 0), enc(0, 1)}    # orders 1, 2, 4, 4
T8 = enc(0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7, 1)   # an order-8 point
T8p = ed._decode_point(T8)
check("T8 decodes and has order 8", T8p is not None and pt(ed._scalar_mul(8, T8p)) == NEUTRAL
      and pt(ed._scalar_mul(4, T8p)) != NEUTRAL)
SMALL = [pt(ed._scalar_mul(k, T8p)) for k in range(8)]
check("[k]T8, k = 0..7: 8 distinct encodings", len(set(SMALL)) == 8)
check("they contain the 4 points of order 1, 2, 4 from the curve equation", by_equation <= set(SMALL))
check("each satisfies [8]P = neutral", all(pt(ed._scalar_mul(8, ed._decode_point(e))) == NEUTRAL for e in SMALL))
# x = 0 only at y = +-1; y >= p is non-canonical for y = 0, 1 (y + p < 2^255)
NONCANON = [enc(1, 1), enc(p - 1, 1), enc(p, 0), enc(p, 1), enc(p + 1, 0), enc(p + 1, 1)]
for e in SMALL:
    check("small-order %s...: key_problem = small-order point" % e.hex()[:12], key_problem(e) == "small-order point", True)
for e in NONCANON:
    check("non-canonical %s...: does not decode" % e.hex()[:12], key_problem(e) == "does not decode (RFC 8032 5.1.3)", True)
honest = [ed.public_key(hashlib.sha256(b"h%d" % i).digest()) for i in range(20)]
check("20 honest keys: key_problem None", all(key_problem(k) is None for k in honest))
a_mix, _ = ed._expand(hashlib.sha256(b"mix").digest())
mixed = pt(ed._add(ed._scalar_mul(a_mix, ed._B), T8p))
check("mixed-order key (aB + T8): not small order, usable (sentence 4 names small order only)", key_problem(mixed) is None)

# ---------------------------------------------------------------- 2. verify refuses small-order A and R
msgs = [b"", b"m"] + [hashlib.sha256(b"msg%d" % i).digest() for i in range(14)]
acc = 0
holds = 0
for A in SMALL:
    for R in SMALL:
        for m in msgs:
            k = int.from_bytes(hashlib.sha512(R + A + m).digest(), "little") % L
            if pt(ed._add(ed._decode_point(R), ed._scalar_mul(k, ed._decode_point(A)))) == NEUTRAL:
                holds += 1                       # the cofactorless equation holds with S = 0
            acc += ed.verify(A, m, R + bytes(32))
check("8 A x 8 R x 16 messages, S = 0: the equation holds %d times (>0, the forgery exists)" % holds, holds > 0)
check("... verify accepts 0 of 1024", acc == 0)
for A in SMALL + NONCANON:
    check("verify with A %s...: False on the RFC 8032 7.1 TEST 1 signature" % A.hex()[:12],
          ed.verify(A, b"", bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")) is False, True)


# ---------------------------------------------------------------- 2b. small-order R other than the neutral point
# Under a key of prime order only R = neutral can satisfy the cofactorless equation, so for the other 7 points the
# R refusal shows only under a mixed-order key A' = aB + T: with R = -[k]T and S = k*a mod L the equation
# [S]B = R + [k]A' holds (the holder of a signs; nobody is forged), and sentence 4 makes the signature invalid.
a_mr, _ = ed._expand(hashlib.sha256(b"mix-R").digest())
AB_mr = ed._scalar_mul(a_mr, ed._B)
R_seen = set()
n_r = 0
for T in SMALL:
    if T == NEUTRAL:
        continue
    Tp = ed._decode_point(T)
    Akey = pt(ed._add(AB_mr, Tp))
    hits = 0
    for i in range(300):
        env = tg.envelope(dict(tg.PAYLOAD, accepted_at="2026-10-05T09:00:00.%03dZ" % i))
        si = (env["protected"] + "." + env["payload"]).encode()
        for R in SMALL:
            if R == NEUTRAL:
                continue
            k = int.from_bytes(hashlib.sha512(R + Akey + si).digest(), "little") % L
            if pt(ed._add(ed._decode_point(R), ed._scalar_mul(k, Tp))) != NEUTRAL:
                continue
            S = k * a_mr % L
            sig = R + S.to_bytes(32, "little")
            eq = pt(ed._scalar_mul(S, ed._B)) == pt(ed._add(ed._decode_point(R), ed._scalar_mul(k, ed._decode_point(Akey))))
            env["signature"] = tg.b64u(sig)
            c = tg.base_case(acceptance=env)
            c["trust_material"]["keys"][1]["x"] = tg.b64u(Akey)
            r = ac.check(c)
            check("mixed key (aB + T %s...), R %s...: equation holds, verify False, signature_invalid"
                  % (T.hex()[:8], R.hex()[:8]), eq and ed.verify(Akey, si, sig) is False
                  and not tg.subset_agrees(tg.SIGINV, r), True)
            R_seen.add(R)
            n_r += 1
            hits += 1
            break
        if hits >= 3:
            break
check("small-order R other than the neutral point, under mixed-order keys: %d signatures, %d of the 7 points as R"
      % (n_r, len(R_seen)), len(R_seen) == 7)

# ---------------------------------------------------------------- 3. the checker under small-order keys
def forge(A, payload):
    """Envelope signed by nobody: R small-order, S = 0, chosen so that R + [k]A = neutral."""
    env = tg.envelope(payload)
    si = (env["protected"] + "." + env["payload"]).encode()
    Ap = ed._decode_point(A)
    for R in SMALL:
        k = int.from_bytes(hashlib.sha512(R + A + si).digest(), "little") % L
        if pt(ed._add(ed._decode_point(R), ed._scalar_mul(k, Ap))) == NEUTRAL:
            env["signature"] = tg.b64u(R + bytes(32))
            return env, True
    env["signature"] = tg.b64u(NEUTRAL + bytes(32))
    return env, False


PAYLOADS = [dict(tg.PAYLOAD, disposition=d, accepted_at=t) for d in ("accepted", "rejected", "disputed")
            for t in ("2026-10-04T18:05:00.000Z", "2026-10-05T09:00:00.123Z")]
forged_found = 0
for A in SMALL + NONCANON:
    for pl in PAYLOADS:
        env, found = forge(A, pl) if A in SMALL else (tg.envelope(pl), False)
        forged_found += found
        for complete in (False, True):
            c = tg.base_case(acceptance=env, trust_material_complete=complete)
            c["trust_material"]["keys"][1]["x"] = tg.b64u(A)
            r = ac.check(c)
            if A in SMALL:                        # README sentence 4
                want = {"result": "key_unresolved", "conditions": [], "key_step": "key_unresolved",
                        "disposition": None, "policy_refusal": complete}
            else:                                 # RFC 8032 5.1.7 step 1: the key does not decode
                want = {"result": "malformed", "conditions": ["signature_invalid"], "key_step": "signature_invalid",
                        "disposition": None, "policy_refusal": False}
            bad = tg.subset_agrees(want, r)
            check("key %s... complete=%s %s: %s" % (A.hex()[:12], complete, pl["disposition"], want["result"]), not bad, True)
check("forgeries found for %d of %d (key, payload) pairs over the 8 points" % (forged_found, 8 * len(PAYLOADS)),
      forged_found >= 8)
c = tg.base_case()
c["trust_material"]["keys"].append(tg.jwk("junk", SMALL[0]))
r = ac.check(c)
check("unused small-order key elsewhere in the trust material: verified, noted",
      r["result"] == "verified" and any(n.startswith("trust_material_key_unusable:junk") for n in r["notes"]))
c = tg.base_case()
c["trust_material"]["keys"][0]["x"] = tg.b64u(SMALL[0])          # the issuer's key is the neutral point
check("issuer key small-order, acceptance by the counterparty: verified", ac.check(c)["result"] == "verified")

# ---------------------------------------------------------------- 4. R = neutral, signed by the key holder
a, _ = ed._expand(tg.SK_CP)
rows = 0
for pl in PAYLOADS:
    env = tg.envelope(pl)
    si = (env["protected"] + "." + env["payload"]).encode()
    k = int.from_bytes(hashlib.sha512(NEUTRAL + tg.PK["cp-A"] + si).digest(), "little") % L
    sig = NEUTRAL + (k * a % L).to_bytes(32, "little")
    eq = pt(ed._scalar_mul(k * a % L, ed._B)) == pt(ed._scalar_mul(k, ed._decode_point(tg.PK["cp-A"])))
    env["signature"] = tg.b64u(sig)
    r = ac.check(tg.base_case(acceptance=env))
    rows += eq and not tg.subset_agrees(tg.SIGINV, r)
check("R = neutral, S = k*a by the holder (equation holds): signature_invalid on %d/%d" % (rows, len(PAYLOADS)),
      rows == len(PAYLOADS))
# every other small-order R and every non-canonical encoding, with S = k*a under the true key: signature_invalid
rows, total = 0, 0
for R in SMALL[1:] + NONCANON:
    for pl in PAYLOADS:
        env = tg.envelope(pl)
        si = (env["protected"] + "." + env["payload"]).encode()
        k = int.from_bytes(hashlib.sha512(R + tg.PK["cp-A"] + si).digest(), "little") % L
        env["signature"] = tg.b64u(R + (k * a % L).to_bytes(32, "little"))
        total += 1
        rows += not tg.subset_agrees(tg.SIGINV, ac.check(tg.base_case(acceptance=env)))
check("R = 7 other small-order points + 6 non-canonical, S = k*a: signature_invalid on %d/%d" % (rows, total),
      rows == total)

# ---------------------------------------------------------------- 5. new member names at every level
rnd = random.Random(20261012)
WEIRD = tg.WEIRD


def new_name(taken):
    while True:
        n = rnd.choice(["zz", "Kid", "ALG", "x5c", "typ", "note", "é", "acceptance_version ", "\u0000", "amount",
                        "Disposition", "keys2", "header2", "complete"]) + rnd.choice(["", str(rnd.randrange(99))])
        if n not in taken:
            return n


LEVELS = [
    ("case", lambda c, n, v: c.__setitem__(n, v), "input_error"),
    ("accepted_record", lambda c, n, v: c["accepted_record"].__setitem__(n, v), "input_error"),
    ("trust_material", lambda c, n, v: c["trust_material"].__setitem__(n, v), "input_error"),
    ("jwk", lambda c, n, v: c["trust_material"]["keys"][1].__setitem__(n, v), "verified"),
    ("jws_object", lambda c, n, v: c["acceptance"].__setitem__(n, v), "verified"),
    ("unprotected_header", lambda c, n, v: c["acceptance"].__setitem__("header", {n: v}), "verified"),
]
taken = {"case": ac.CASE_MEMBERS, "accepted_record": ac.RECORD_MEMBERS,
         "trust_material": {"keys"}, "jwk": ac.JWK_UNDERSTOOD, "jws_object": ac.ENVELOPE_MEMBERS | {"signatures"},
         "unprotected_header": {"alg", "kid", "crit"}}
level_fail = {}
for lvl, put, want in LEVELS:
    n_bad = 0
    for i in range(150):
        c = tg.base_case()
        n = new_name(taken[lvl])
        put(c, n, rnd.choice(WEIRD))
        r = ac.check(c)
        if r["result"] != want:
            n_bad += 1
        elif want == "verified" and not r["notes"]:
            n_bad += 1
    level_fail[lvl] = n_bad
    check("150 new names at level %-20s -> %s" % (lvl, want), n_bad == 0)
for lvl, raw_of in (("protected_header", "header"), ("payload", "payload")):
    n_bad = 0
    for i in range(150):
        n = new_name({"alg", "kid", "crit"} | ac.PAYLOAD_MEMBERS)
        v = rnd.choice(WEIRD)
        if lvl == "protected_header":
            env = tg.envelope(header={"alg": "EdDSA", "kid": "cp-A", n: v})
        else:
            env = tg.envelope(dict(tg.PAYLOAD, **{n: v}))
        r = ac.check(tg.base_case(acceptance=env))
        n_bad += not (r["result"] == "verified" and r["notes"])
    check("150 new names at level %-20s -> verified, noted" % lvl, n_bad == 0)

# ---------------------------------------------------------------- 6. order (README, after sentence 4)
c = tg.flip_sig(tg.base_case(acceptance=tg.envelope(raw_payload=b"[1]")))
check("payload not a JSON object + invalid signature: signature_invalid", not tg.subset_agrees(tg.SIGINV, ac.check(c)))
c = tg.base_case(acceptance=tg.envelope(raw_payload=b"[1]"))
check("payload not a JSON object, valid signature: malformed acceptance_member_invalid",
      not tg.subset_agrees(dict(tg.mal("acceptance_member_invalid"), key_step="signature_verified"), ac.check(c)))
c = tg.flip_sig(tg.base_case(acceptance=tg.envelope(raw_header=b"[1]")))
check("protected header not a JSON object + invalid signature: member_invalid, no key step",
      not tg.subset_agrees({"result": "malformed", "conditions": ["acceptance_member_invalid"], "key_step": None}, ac.check(c)))
c = tg.base_case(acceptance=tg.envelope(header={"alg": "EdDSA", "kid": "nope"}, raw_payload=b"x"))
check("unknown kid + payload not JSON: key_unresolved (key step first)", ac.check(c)["result"] == "key_unresolved")

print("CHECKS %d, FAILS %d %s" % (COUNT[0], len(FAILS), FAILS[:20]))
if __name__ == "__main__":
    sys.exit(1 if FAILS else 0)
