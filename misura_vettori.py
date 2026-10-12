# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Runner: compares acceptance_check.check() with the pinned fields of each vector (PREREG.md).

python3 misura_vettori.py VECTORS.json [--variant sig|sha|disp ...] [--always-accept] [--json OUT]
A field is pinned iff its key is present in the vector's "expect". conditions compare as sets.
The checker receives only a deep copy of "case"; it never sees "expect", "what" or "id".
"""
import copy
import json
import sys

import acceptance_check as ac

PINNABLE = ("result", "conditions", "disposition", "key_step", "policy_refusal")


def always_accept(case, **_):
    return {"result": "verified", "conditions": [], "disposition": "accepted", "key_step": "signature_verified",
            "policy_refusal": False}


def field_agrees(name, expected, got):
    if name == "conditions":
        return isinstance(got, list) and len(got) == len(set(got)) and set(got) == set(expected)
    return type(got) is type(expected) and got == expected


def measure(vectors, checker):
    rows = []
    for v in vectors:
        exp = v["expect"]
        unknown = set(exp) - set(PINNABLE)
        if unknown:
            raise SystemExit("vector %s pins a field the runner does not know: %s" % (v["id"], sorted(unknown)))
        got = checker(copy.deepcopy(v["case"]))
        fields = {}
        for f in PINNABLE:
            if f in exp:
                fields[f] = {"pinned": True, "expected": exp[f], "got": got.get(f),
                             "agree": field_agrees(f, exp[f], got.get(f))}
            else:
                fields[f] = {"pinned": False, "got": got.get(f)}
        rows.append({"id": v["id"], "agree": all(x["agree"] for x in fields.values() if x["pinned"]),
                     "fields": fields, "reasons": got.get("reasons", []), "notes": got.get("notes", [])})
    return rows


def summary(rows):
    per_field = {}
    for r in rows:
        for f, x in r["fields"].items():
            if x["pinned"]:
                a, n = per_field.get(f, (0, 0))
                per_field[f] = (a + x["agree"], n + 1)
    return {"vectors_agree": sum(r["agree"] for r in rows), "vectors": len(rows),
            "per_field": {f: "%d/%d" % v for f, v in per_field.items()}}


def main(argv):
    args = argv[1:]
    out = None
    if "--json" in args:
        i = args.index("--json")
        out = args[i + 1]
        del args[i:i + 2]
    kw = {}
    while "--variant" in args:
        i = args.index("--variant")
        kw[{"sig": "sig_invalid_as_token", "sha": "sha256_any_string", "disp": "disposition_always"}[args[i + 1]]] = True
        del args[i:i + 2]
    checker = (lambda c: ac.check(c, **kw))
    if "--always-accept" in args:
        args.remove("--always-accept")
        checker = always_accept
    if len(args) != 1:
        raise SystemExit(__doc__)
    with open(args[0], "rb") as f:
        doc = ac.strict_json(f.read().decode("utf-8"))
    rows = measure(doc["vectors"], checker)
    for r in rows:
        bad = [f for f, x in r["fields"].items() if x["pinned"] and not x["agree"]]
        pinned = ",".join(f for f, x in r["fields"].items() if x["pinned"])
        line = "%-42s %s  pinned=[%s]" % (r["id"], "AGREE   " if r["agree"] else "DISAGREE", pinned)
        if bad:
            line += "  " + "; ".join("%s: expected %s got %s" % (f, json.dumps(r["fields"][f]["expected"]),
                                                                 json.dumps(r["fields"][f]["got"])) for f in bad)
        print(line)
    s = summary(rows)
    print("TOTAL %d/%d agree; per field: %s" % (s["vectors_agree"], s["vectors"], s["per_field"]))
    if out:
        with open(out, "w") as f:
            json.dump({"summary": s, "rows": rows, "variants": sorted(kw)}, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0 if s["vectors_agree"] == s["vectors"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
