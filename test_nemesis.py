# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Tests added after the adversarial review of 2026-10-11: nesting depth, large numbers and the environment,
non-regular files, input readings without a test, JCS escapes. Exit 0 iff all pass."""
import copy
import json
import os
import subprocess
import sys
import tempfile

import acceptance_check as ac
import ed25519_rfc8032 as ed
import test_generativi as tg

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []


def check(name, cond):
    print("%-58s %s" % (name, "ok" if cond else "FAIL"))
    if not cond:
        FAILS.append(name)


def res(case):
    try:
        r = ac.check(case)
        return r["result"], r["conditions"]
    except BaseException as e:                     # a crash is a failure of the test, never a pass
        return "CRASH:" + type(e).__name__, []


def nested(n):
    return "[" * n + "]" * n


def hdr_case(extra_json):
    raw = ('{"alg":"EdDSA","kid":"cp-A","ext":%s}' % extra_json).encode()
    return tg.base_case(acceptance=tg.envelope(raw_header=raw))


def payload_case(extra_json):
    raw = (json.dumps(tg.PAYLOAD)[:-1] + ',"ext":%s}' % extra_json).encode()
    return tg.base_case(acceptance=tg.envelope(raw_payload=raw))


ENV = ("malformed", ["acceptance_envelope_invalid"])
VER = ("verified", [])

# 1. depth: the limit is MAX_DEPTH counted from the outer object; the header object is level 1
check("header, ignored member at depth MAX_DEPTH: verified", res(hdr_case(nested(ac.MAX_DEPTH - 1))) == VER)
check("header, ignored member at depth MAX_DEPTH+1: envelope", res(hdr_case(nested(ac.MAX_DEPTH))) == ENV)
for n in (5000, 200000):
    check("header (unauthenticated) nested %d: envelope, no crash" % n, res(hdr_case(nested(n))) == ENV)
    check("signed payload nested %d: envelope, no crash" % n, res(payload_case(nested(n))) == ENV)
check("brackets inside a string do not count", res(hdr_case(json.dumps("[" * 500 + '\\"{' * 100))) == VER)
check("escaped quote inside a string does not end it", res(hdr_case(json.dumps('"' + "[" * 100))) == VER)
_lim = sys.getrecursionlimit()
try:
    sys.setrecursionlimit(40)
    try:
        ac.strict_json(nested(ac.MAX_DEPTH))
        _r = "parsed"
    except ValueError:
        _r = "ValueError"
    except RecursionError:
        _r = "RecursionError"
finally:
    sys.setrecursionlimit(_lim)
check("low recursion limit: ValueError, never RecursionError", _r in ("parsed", "ValueError"))

# 2. numbers: opaque, never converted, so the verdict does not depend on PYTHONINTMAXSTRDIGITS
big = "1" + "0" * 5000
check("header, ignored member = 5001-digit integer: verified", res(hdr_case(big)) == VER)
check("payload, unknown member = 5001-digit integer", res(payload_case(big)) == ("malformed", ["acceptance_member_unknown"]))
check("payload, disposition = 1: member_invalid", res(tg.with_payload(disposition=1))[1] == ["acceptance_member_invalid"])
raw = json.dumps(tg.PAYLOAD).replace('"acceptance-record-v0"', "1").encode()
check("payload, acceptance_version = 1 (number): member_invalid",
      res(tg.base_case(acceptance=tg.envelope(raw_payload=raw))) == ("malformed", ["acceptance_member_invalid"]))
with tempfile.TemporaryDirectory() as td:
    path = os.path.join(td, "case.json")
    with open(path, "w") as f:
        json.dump(hdr_case(big), f)
    outs = []
    for env_value in (None, "0", "640"):
        env = dict(os.environ)
        env.pop("PYTHONINTMAXSTRDIGITS", None)
        if env_value is not None:
            env["PYTHONINTMAXSTRDIGITS"] = env_value
        p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "acceptance_check.py"), path],
                           capture_output=True, env=env, timeout=120)
        outs.append((p.returncode, json.loads(p.stdout.decode())["result"] if p.stdout else None))
    check("CLI verdict identical with PYTHONINTMAXSTRDIGITS unset/0/640", outs == [(0, "verified")] * 3)

    # 3. CLI: deep case file, FIFO, directory
    deep = os.path.join(td, "deep.json")
    with open(deep, "w") as f:
        f.write('{"x":' + nested(100000) + "}")
    p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "acceptance_check.py"), deep], capture_output=True, timeout=120)
    check("CLI deep case file: input_error exit 3", p.returncode == 3 and json.loads(p.stdout.decode())["result"] == "input_error")
    if hasattr(os, "mkfifo"):
        fifo = os.path.join(td, "fifo")
        os.mkfifo(fifo)
        try:
            p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "acceptance_check.py"), fifo], capture_output=True, timeout=20)
            ok = p.returncode == 3 and "not a regular file" in p.stdout.decode()
        except subprocess.TimeoutExpired:
            ok = False
        check("CLI FIFO: input_error, does not block", ok)

# 4. input readings the earlier suite did not pin
c = tg.base_case(); c["delegation"] = {"did:example:cp": ["cp-A", "cp-A"]}
check("delegation lists a kid twice: input_error", res(c)[0] == "input_error")
c = tg.base_case(); c["delegation"] = {"": ["cp-A"], "did:example:cp": ["cp-A"]}
check("delegation with an empty party: input_error", res(c)[0] == "input_error")
check("header kid empty string: envelope",
      res(tg.base_case(acceptance=tg.envelope(header={"alg": "EdDSA", "kid": ""}))) == ENV)
for k in ("issuer", "issuer_kid", "record_id"):
    c = tg.base_case(); c["accepted_record"][k] = ""
    check("accepted_record.%s empty: input_error" % k, res(c)[0] == "input_error")
c = tg.base_case(); del c["trust_material"]
check("acceptance without trust_material: input_error (our reading)", res(c)[0] == "input_error")
c = tg.base_case(); c["trust_material"] = {"keys": []}
check("trust_material with no keys: key_unresolved", res(c)[0] == "key_unresolved")
for bad_kid in (5, None, ["cp-A"]):
    c = tg.base_case(); c["trust_material"]["keys"].append(tg.jwk("x", tg.PK["other-A"]))
    c["trust_material"]["keys"][-1]["kid"] = bad_kid
    check("JWK kid %r: input_error" % (bad_kid,), res(c)[0] == "input_error")
for kv in ("cp-A", "", {}, None, 0):
    c = tg.base_case(); c["trust_material"] = {"keys": kv}
    check("trust_material.keys = %r: input_error" % (kv,), res(c)[0] == "input_error")
for ts, ok in (("1900-02-28T00:00:00.000Z", True), ("1900-02-29T00:00:00.000Z", False),
               ("2000-02-29T00:00:00.000Z", True), ("2024-02-29T00:00:00.000Z", True),
               ("2026-13-01T00:00:00.000Z", False), ("2026-00-01T00:00:00.000Z", False),
               ("2026-04-31T00:00:00.000Z", False), ("2026-12-31T23:59:59.999Z", True)):
    check("canonical_ts(%s) == %s" % (ts, ok), ac.canonical_ts(ts) is ok)
two = tg.with_payload(terms_sha256="x", outcome_sha256=7)
r = ac.check(two)
check("two ill-typed digests: acceptance_member_invalid once", r["conditions"] == ["acceptance_member_invalid"])
c = tg.base_case(); c["trust_material"]["keys"][1]["use"] = "sig"
r = ac.check(c)
check("ignored JWK member is listed in notes", r["result"] == "verified" and any("jwk_member_ignored:cp-A:use" in n for n in r["notes"]))
r = ac.check(tg.base_case(acceptance=tg.envelope(header={"alg": "EdDSA", "kid": "cp-A", "typ": "x"})))
check("ignored header parameter is listed in notes", r["result"] == "verified" and any("header_parameter_ignored:typ" in n for n in r["notes"]))

# 5. JCS escapes (RFC 8785 3.2.2.2), expected bytes written by hand
cases = [({"b": "1", "a": "2"}, b'{"a":"2","b":"1"}'),
         ({"k": "\b\t\n\f\r\"\\"}, b'{"k":"\\b\\t\\n\\f\\r\\"\\\\"}'),
         ({"k": "\x00\x1f\x7f"}, b'{"k":"\\u0000\\u001f\x7f"}'),
         ({"k": "é \U0001f600/"}, '{"k":"é \U0001f600/"}'.encode("utf-8"))]
for obj, want in cases:
    check("JCS %r" % (obj,), ac.jcs_string_object(obj) == want)
rec = dict(tg.RECORD, issuer="did:example:iss\b\x1fé")
want = (b'{"issuer":"did:example:iss\\b\\u001f\xc3\xa9","issuer_kid":"iss-A","outcome_at":"2026-10-04T18:00:00.000Z",'
        b'"outcome_sha256":"' + b"11" * 32 + b'","record_id":"r-1","terms_sha256":"' + b"22" * 32 + b'"}')
import hashlib
sha = hashlib.sha256(want).hexdigest()
c = tg.base_case(accepted_record=rec, acceptance=tg.envelope(dict(tg.PAYLOAD, accepted_record_sha256=sha)))
c["delegation"] = {"did:example:cp": ["cp-A"], rec["issuer"]: ["iss-A"]}
check("record with \\b, U+001F, e-acute: digest over hand-written JCS bytes verifies", res(c) == VER)

# 6. Ed25519: decoding and verification limits (RFC 8032 5.1.3 / 5.1.7)
p = ed.p
check("y = p (non-canonical) does not decode", not ed.point_valid(p.to_bytes(32, "little")))
check("y = p + 1 (non-canonical) does not decode", not ed.point_valid((p + 1).to_bytes(32, "little")))
check("x = 0 with x_0 = 1 does not decode", not ed.point_valid((1 | (1 << 255)).to_bytes(32, "little")))
check("y = 1, x_0 = 0 (neutral point) decodes", ed.point_valid((1).to_bytes(32, "little")))
check("y = 2 has no x: does not decode", not ed.point_valid((2).to_bytes(32, "little")))
sk = hashlib.sha256(b"nemesis").digest(); pk = ed.public_key(sk); msg = b"m"; sig = ed.sign(sk, msg)
check("honest signature verifies", ed.verify(pk, msg, sig))
check("public key that does not decode: False, no exception", ed.verify((p + 1).to_bytes(32, "little"), msg, sig) is False)
check("65-octet signature (zero appended) is invalid", not ed.verify(pk, msg, sig + b"\x00"))
check("R with y >= p is invalid", not ed.verify(pk, msg, (p + 1).to_bytes(32, "little") + sig[32:]))
neg = bytearray(pk); neg[31] ^= 0x80
check("signature does not verify under -A (sign bit of A flipped)", not ed.verify(bytes(neg), msg, sig))
check("signature with R negated is invalid", not ed.verify(pk, msg, bytes(bytearray(sig[:31]) + bytes([sig[31] ^ 0x80])) + sig[32:]))
# neutral public key: [S]B = R + [k]A' becomes [S]B = R; the negated R has the same y and must still fail
r0 = 123456789
R0 = ed._encode_point(ed._scalar_mul(r0, ed._B))
negR0 = bytes(bytearray(R0[:31]) + bytes([R0[31] ^ 0x80]))
neutral = (1).to_bytes(32, "little")
check("neutral key: (R, r) verifies (RFC 8032 does not reject small order)", ed.verify(neutral, b"any", R0 + r0.to_bytes(32, "little")))
check("neutral key: (-R, r) is invalid (x sign is compared)", not ed.verify(neutral, b"any", negR0 + r0.to_bytes(32, "little")))
# k must be reduced mod L before [k]A' (5.1.7 step 2): A' of mixed order makes an unreduced k differ
T = (0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7 | (1 << 255)).to_bytes(32, "little")
check("an order-8 point decodes", ed.point_valid(T))
Tp = ed._decode_point(T)
check("that point has order 8", ed._encode_point(ed._scalar_mul(8, Tp)) == ed._encode_point(ed._NEUTRAL)
      and ed._encode_point(ed._scalar_mul(4, Tp)) != ed._encode_point(ed._NEUTRAL))
a, prefix = ed._expand(sk)
Am = ed._encode_point(ed._add(ed._scalar_mul(a, ed._B), Tp))
found = None
for i in range(200):
    m = b"mix%d" % i
    r = int.from_bytes(hashlib.sha512(prefix + m).digest(), "little") % ed.L
    Rs = ed._encode_point(ed._scalar_mul(r, ed._B))
    k_full = int.from_bytes(hashlib.sha512(Rs + Am + m).digest(), "little")
    if (k_full % ed.L) % 8 == 0 and k_full % 8 != 0:
        found = (m, Rs + ((r + (k_full % ed.L) * a) % ed.L).to_bytes(32, "little"))
        break
check("mixed-order key, k mod L divisible by 8: verifies (k reduced mod L)", found is not None and ed.verify(Am, found[0], found[1]))

print("FAILS", len(FAILS), FAILS)
sys.exit(1 if FAILS else 0)
