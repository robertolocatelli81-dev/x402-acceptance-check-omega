# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Mutants of the lines changed on 2026-10-12 (small-order keys and R, README sentences 1-4), run against the
whole suite: each mutant is applied to a copy of this directory, and is killed iff at least one of
test_piccolo_ordine.py, test_generativi.py, test_nemesis.py, test_ed25519.py exits non-zero (or the 27
pinned vectors disagree). The unmutated copy must pass every one of them first (the bench must be able to pass).

python3 mutanti_v2.py   -> exit 0 iff the unmutated copy passes, every mutant is killed, and the two listed in
                           EQUIVALENT (equivalent since README sentence 9, 2026-10-13) survive
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ["test_piccolo_ordine.py", "test_generativi.py", "test_nemesis.py", "test_ed25519.py"]
ED, AC = "ed25519_rfc8032.py", "acceptance_check.py"

MUTANTS = [
    ("ed: A small order allowed", ED, "if _small_order(A) or _small_order(R):", "if _small_order(R):"),
    ("ed: R small order allowed", ED, "if _small_order(A) or _small_order(R):", "if _small_order(A):"),
    ("ed: no small-order check", ED, "if _small_order(A) or _small_order(R):", "if False:"),
    ("ed: order divides 4 only", ED, "_scalar_mul(8, P)", "_scalar_mul(4, P)"),
    ("ed: order divides 2 only", ED, "_scalar_mul(8, P)", "_scalar_mul(2, P)"),
    ("ed: neutral point only", ED, "return _encode_point(_scalar_mul(8, P)) == _encode_point(_NEUTRAL)",
     "return _encode_point(P) == _encode_point(_NEUTRAL)"),
    ("ed: key_problem ignores small order", ED, '        return "small-order point"', "        return None"),
    ("ed: x=0 sign bit accepted", ED, "if x == 0 and x_0 == 1:", "if False:"),
    ("ed: y >= p accepted", ED, "if y >= p:", "if False:"),
    ("ac: unusable key kept", AC, "keys[kid] = None", "keys[kid] = x"),
    ("ac: small-order key -> input_error", AC, 'notes.append("trust_material_key_unusable:%s: %s" % (kid, problem))',
     'raise InputError("unusable key")'),
    ("ac: undecodable key -> key_unresolved", AC, 'if problem in ("small-order point", "mixed-order point"):',
     "if problem is not None:"),
    ("ac: undecodable key -> input_error", AC, 'notes.append("trust_material_key_undecodable:%s: %s" % (kid, problem))',
     'raise InputError("undecodable key")'),
    ("ac: key step by membership", AC, "if keys.get(kid) is None:", "if kid not in keys:"),
    ("ac: no policy_refusal", AC, "policy_refusal=bool(complete), notes=notes)", "policy_refusal=False, notes=notes)"),
    ("ac: crit in unprotected header allowed", AC, 'if "crit" in uhdr:', "if not uhdr:"),
    ("ac: signatures member allowed", AC, 'if "signatures" in env:', 'if "signatures" in env and not env:'),
    ("ac: unprotected header ignored", AC, "jose.update(hdr)                                 # RFC 7515 7.2.1",
     "jose = dict(hdr)                                 # RFC 7515 7.2.1"),
    ("ac: version early unknown", AC, 'if pl.get("acceptance_version") != VERSION:                # README sentence 3',
     'if pl.get("acceptance_version") != VERSION:\n        return _report("unknown", ["acceptance_version_unsupported"])\n    if False:'),
    ("ac: unknown member refused", AC, 'notes.append("acceptance_member_ignored:%s" % k)', 'conds.append("acceptance_member_unknown")'),
    ("ac: envelope old name", AC, 'return _report("malformed", ["acceptance_member_invalid"], notes=notes, reasons=reasons)',
     'return _report("malformed", ["acceptance_envelope_invalid"], notes=notes, reasons=reasons)'),
    ("ac: alg from the protected header only", AC, 'if jose.get("alg") != "EdDSA":', 'if hdr.get("alg") != "EdDSA":'),
    ("ac: header not disjoint", AC, "            if both:\n", "            if False:\n"),
]
# Since sentence 9 (2026-10-13) these two survive by construction: a small-order point other than the neutral one
# has [L]P != neutral (L is odd, so [L]P = [L mod ord(P)]P with L mod ord(P) != 0), so verify's mixed-order check
# refuses it as R whether or not the small-order check does; the small-order check on R is needed for R = neutral
# only, which both mutants still refuse. Run and expected to survive.
EQUIVALENT = [
    ("ed: R refused only if neutral (equivalent since sentence 9)", ED, "if _small_order(A) or _small_order(R):",
     "if _small_order(A) or _encode_point(R) == _encode_point(_NEUTRAL):"),
    ("ed: R refused only if its order divides 4 (equivalent since sentence 9)", ED,
     "if _small_order(A) or _small_order(R):",
     "if _small_order(A) or _encode_point(_scalar_mul(4, R)) == _encode_point(_NEUTRAL):"),
]


def run_suite(d):
    failed = []
    for t in TESTS:
        p = subprocess.run([sys.executable, "-B", t], cwd=d, capture_output=True, timeout=900, env=dict(os.environ, HOME=d))
        if p.returncode != 0:
            failed.append(t)
    p = subprocess.run([sys.executable, "-B", "misura_vettori.py", os.path.join("fonti", "d750291_vectors.json")],
                       cwd=d, capture_output=True, timeout=300, env=dict(os.environ, HOME=d))
    if p.returncode != 0 or b"TOTAL 27/27" not in p.stdout:
        failed.append("vectors")
    return failed


def copy_tree(dst):
    for n in os.listdir(HERE):
        if n.endswith(".py") or n == "fonti":
            s = os.path.join(HERE, n)
            (shutil.copytree if os.path.isdir(s) else shutil.copy2)(s, os.path.join(dst, n))


def main():
    with tempfile.TemporaryDirectory() as td:
        base = os.path.join(td, "base")
        os.mkdir(base)
        copy_tree(base)
        f = run_suite(base)
        print("unmutated copy: %s" % ("passes" if not f else "FAILS %s (bench broken)" % f))
        if f:
            return 1
        survivors = []
        bad = []
        for i, (name, fn, old, new) in enumerate(MUTANTS + EQUIVALENT):
            d = os.path.join(td, "m%d" % i)
            os.mkdir(d)
            copy_tree(d)
            src = open(os.path.join(d, fn)).read()
            if src.count(old) != 1:
                print("%-45s anchor found %d times" % (name, src.count(old)))
                bad.append(name)
                continue
            open(os.path.join(d, fn), "w").write(src.replace(old, new))
            f = run_suite(d)
            print("%-45s %s %s" % (name, "killed by" if f else "SURVIVED", f), flush=True)
            if not f:
                survivors.append(name)
            if bool(f) == (i >= len(MUTANTS)):
                bad.append(name)
        print("MUTANTS %d (+%d equivalent), SURVIVORS %s, NOT AS EXPECTED %s" % (len(MUTANTS), len(EQUIVALENT),
                                                                                survivors, bad))
        return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
