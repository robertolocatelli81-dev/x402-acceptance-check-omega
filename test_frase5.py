# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Tests for sentence 5 of the README of examples/acceptance-record-cold at 0abf726 (2026-10-12): a timestamp
(`accepted_at` in the acceptance, `outcome_at` in the supplied record) is YYYY-MM-DDTHH:MM:SS.mmmZ exactly; any
other spelling is ill-typed (acceptance_member_invalid), and acceptance_precedes_outcome is compared only between
two values of that form. Where the check sits follows "Evaluation order": the key step first (key_unresolved and
signature_invalid stop there), then report-all with type-check suppression; no acceptance is no_record.

Every case is signed here with keys made here; the accepted_record_sha256 in each payload is computed over the
record as supplied (README A4), so no record-digest mismatch is mixed in unless a row asks for one. Expected values
are written from the text, not read back from the checker. Rows marked OUR are readings of ours (README).

python3 test_frase5.py   -> exit 0 iff every check holds
"""
import hashlib
import random
import sys

import acceptance_check as ac
import test_generativi as tg

CHECK = ac.check
MI = "acceptance_member_invalid"
FAILS = []
COUNT = [0]


def case(outcome_at, accepted_at="2026-10-04T18:05:00.000Z", rec_sha=None, **payload):
    rec = dict(tg.RECORD, outcome_at=outcome_at)
    sha = rec_sha or hashlib.sha256(ac.jcs_string_object(rec)).hexdigest()
    p = dict(tg.PAYLOAD, accepted_at=accepted_at, accepted_record_sha256=sha)
    p.update(payload)
    return tg.base_case(acceptance=tg.envelope(p), accepted_record=rec)


def drop(c, key):
    del c[key]
    return c


def only_issuer_key(c):
    c["trust_material"]["keys"] = c["trust_material"]["keys"][:1]
    return c


def _not_string():
    c = case("2026-10-04T18:00:00.000Z")
    c["accepted_record"]["outcome_at"] = 1
    return c


MAL_MI = {"result": "malformed", "conditions": [MI], "key_step": "signature_verified", "disposition": None}
NOFRAC = "2026-10-04T18:00:00Z"

TABLE = [
    # (id, build, expected subset, rule)
    ("no-fraction", lambda: case(NOFRAC), MAL_MI, "sentence 5"),
    ("no-fraction-same-instant-as-acceptance", lambda: case("2026-10-04T18:05:00Z"), MAL_MI,
     "sentence 5: ordering only between two canonical values ('.' < 'Z' bytewise would say 'precedes')"),
    ("no-fraction-after-acceptance", lambda: case("2026-10-04T19:00:00Z"), MAL_MI,
     "sentence 5: ordering only between two canonical values"),
    ("offset-same-instant", lambda: case("2026-10-05T03:00:00.000+09:00"), MAL_MI, "sentence 5: offset"),
    ("offset-zero", lambda: case("2026-10-04T18:00:00.000+00:00"), MAL_MI, "sentence 5: offset"),
    ("lowercase-t-z", lambda: case("2026-10-04t18:00:00.000z"), MAL_MI, "sentence 5: the form exactly"),
    ("six-fraction-digits", lambda: case("2026-10-04T18:00:00.000000Z"), MAL_MI, "sentence 5: three digits"),
    ("february-30", lambda: case("2026-02-30T18:00:00.000Z"), MAL_MI, "-03 5.3.2: a valid instant"),
    ("empty-string", lambda: case(""), MAL_MI, "sentence 5"),
    ("both-timestamps-ill-typed", lambda: case(NOFRAC, accepted_at="2026-10-04T18:05:00Z"), MAL_MI, "sentence 5"),
    ("no-fraction-signature-flipped", lambda: tg.flip_sig(case(NOFRAC)),
     {"result": "malformed", "conditions": ["signature_invalid"], "key_step": "signature_invalid",
      "disposition": None}, "Evaluation order 1: the key step stops evaluation"),
    ("no-fraction-key-unresolved", lambda: only_issuer_key(case(NOFRAC)),
     {"result": "key_unresolved", "conditions": [], "key_step": "key_unresolved", "policy_refusal": False},
     "Evaluation order 1"),
    ("no-fraction-no-acceptance", lambda: drop(case(NOFRAC), "acceptance"),
     {"result": "no_record", "conditions": [], "disposition": "not_responded"}, "Result tokens: no_record"),
    ("no-fraction-and-terms-mismatch", lambda: case(NOFRAC, terms_sha256="33" * 32),
     {"result": "malformed", "conditions": [MI, "acceptance_terms_digest_mismatch"]},
     "OUR: report-all; the terms digest does not depend on outcome_at"),
    ("no-fraction-and-record-digest-mismatch", lambda: case(NOFRAC, rec_sha="44" * 32),
     {"result": "malformed", "conditions": [MI, "acceptance_record_digest_mismatch"]},
     "OUR: report-all; A4, the digest of the record as supplied"),
    # controls: these hold before and after the change
    ("control-canonical-verified", lambda: case("2026-10-04T18:00:00.000Z"),
     {"result": "verified", "conditions": [], "disposition": "accepted"}, "control"),
    ("control-canonical-precedes", lambda: case("2026-10-04T18:10:00.000Z"),
     {"result": "malformed", "conditions": ["acceptance_precedes_outcome"]}, "control: README A7"),
    ("control-canonical-same-instant", lambda: case("2026-10-04T18:05:00.000Z"),
     {"result": "verified", "conditions": []}, "control: README A7, strict"),
    ("outcome-at-not-a-string", _not_string,
     {"result": "input_error"}, "OUR: every record member is a string (README, input_error)"),
]


def expect(cond, what):
    COUNT[0] += 1
    if not cond:
        FAILS.append(what)


def run_table():
    for tid, build, exp, rule in TABLE:
        try:
            got = CHECK(build())
        except Exception as e:  # a crash is a failure
            got = {"result": "CRASH:%s" % type(e).__name__}
        bad = tg.subset_agrees(exp, got)
        expect(not bad, "%s [%s]: %r" % (tid, rule, bad))
        print("%-42s %s  [%s]" % (tid, "ok  " if not bad else "FAIL %r" % bad, rule))


def mutate_ts(rnd, ts):
    """One change to a canonical timestamp. Only the last (identity) keeps the -03 5.3.2 form: the others drop
    or lengthen the fraction, add an offset, change case or separators, add whitespace, or give a month, day,
    hour or second that does not exist."""
    ops = [
        lambda s: s.replace(".000Z", "Z"), lambda s: s.replace("Z", "+00:00"), lambda s: s.replace("Z", "-00:00"),
        lambda s: s.replace("Z", "+09:00"), lambda s: s.lower(), lambda s: s.replace("T", " "),
        lambda s: s + "\n", lambda s: " " + s, lambda s: s.replace(".000", ".0"), lambda s: s.replace(".000", ".0000"),
        lambda s: s.replace("Z", "z"), lambda s: s.replace("T", "t"), lambda s: s[:-1],
        lambda s: s.replace(":00.", ":60."), lambda s: s.replace("-10-", "-13-"), lambda s: s.replace("-04T", "-32T"),
        lambda s: s.replace("2026", "02026"), lambda s: s.replace("18:", "24:"), lambda s: s.replace(".000", ",000"),
        lambda s: s.replace("0", "٠", 1), lambda s: s,
    ]
    return rnd.choice(ops)(ts)


def sweep(n=400, seed=20261012):
    """outcome_at mutated around and across the acceptance's instant. Invariants from sentence 5:
    non-canonical -> malformed with acceptance_member_invalid and never acceptance_precedes_outcome;
    canonical -> no acceptance_member_invalid, and precedes iff accepted_at < outcome_at."""
    rnd = random.Random(seed)
    bases = ["2026-10-04T18:00:00.000Z", "2026-10-04T18:05:00.000Z", "2026-10-04T18:10:00.000Z"]
    seen = {True: 0, False: 0}
    for i in range(n):
        o = mutate_ts(rnd, rnd.choice(bases))
        canon = o in bases     # only the identity change keeps the form (every other op breaks it)
        seen[bool(canon)] += 1
        r = CHECK(case(o))
        conds = r.get("conditions", [])
        if not canon:
            expect(r["result"] == "malformed" and MI in conds and "acceptance_precedes_outcome" not in conds,
                   "sweep %d: %r -> %r" % (i, o, r))
        else:
            want = "2026-10-04T18:05:00.000Z" < o
            expect(MI not in conds and ("acceptance_precedes_outcome" in conds) == want,
                   "sweep %d (canonical): %r -> %r" % (i, o, r))
    expect(seen[True] > 0 and seen[False] > 0, "sweep reached both classes: %r" % seen)
    print("SWEEP: %d outcome_at values (%d canonical, %d not)" % (n, seen[True], seen[False]))


def main():
    run_table()
    sweep()
    print("CHECKS %d, FAILED %d" % (COUNT[0], len(FAILS)))
    for f in FAILS[:20]:
        print("  FAIL", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
