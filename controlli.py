# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Positive controls (PREREG.md): the bench must be able to fail.

1. altered vectors: the runner must report disagreement;
2. source mutants of acceptance_check.py: each must be killed by the 27 vectors or by test_generativi
   (TABLE + fuzz); a surviving mutant is printed and makes the exit code 1;
3. a mutant of ed25519_rfc8032.verify that always accepts must be killed.
"""
import copy
import importlib.util
import json
import os
import sys
import types

import misura_vettori as mv
import test_generativi as tg

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "fonti", "d750291_vectors.json")


def load_module(name, src):
    mod = types.ModuleType(name)
    mod.__file__ = os.path.join(HERE, name + ".py")
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    return mod


MUTANTS = [
    ("precedes-not-strict", 'pl["accepted_at"] < rec["outcome_at"]', 'pl["accepted_at"] <= rec["outcome_at"]'),
    ("no-type-suppression-terms", 'if terms_ok and pl["terms_sha256"]', 'if pl.get("terms_sha256") != rec["terms_sha256"] or terms_ok and pl["terms_sha256"]'),
    ("sha-any-string", "ok = isinstance(v, str) if sha256_any_string else is_hex64(v)", "ok = isinstance(v, str)"),
    ("sig-invalid-own-token", "if sig_invalid_as_token:", "if True:"),
    ("authority-on-malformed", "    if conds:\n        return _report(\"malformed\"",
     "    if conds:\n        conds.append('acceptance_authority_unresolved') if kid not in deleg.get(cp, []) else None\n        return _report(\"malformed\""),
    ("signature-not-checked", "if not ed.verify(pub, signing_input, b64url_strict(env[\"signature\"])):", "if False:"),
    ("key-unresolved-continues", 'if keys.get(kid) is None:\n        return', 'if kid not in keys:\n        return'),
    ("key-unresolved-never", 'if keys.get(kid) is None:\n        return', 'if False:\n        return'),
    ("policy-refusal-always-false", "policy_refusal=bool(complete)", "policy_refusal=False"),
    ("policy-refusal-always-true", "policy_refusal=bool(complete)", "policy_refusal=True"),
    ("policy-refusal-on-siginvalid", 'return _report("malformed", ["signature_invalid"], key_step="signature_invalid", notes=notes)',
     'return _report("malformed", ["signature_invalid"], key_step="signature_invalid", policy_refusal=bool(complete), notes=notes)'),
    ("not-responded-signable", 'DISPOSITIONS_SIGNED = ("accepted", "rejected", "disputed")',
     'DISPOSITIONS_SIGNED = ("accepted", "rejected", "disputed", "not_responded")'),
    ("empty-cp-allowed", 'if cp is None or cp == "":', 'if cp is None:'),
    ("signer-issuer-no-bytes", "(issuer_pub is not None and issuer_pub == pub)", "False"),
    ("signer-issuer-no-party", "same_party = cp_ok and cp == rec[\"issuer\"]", "same_party = False"),
    ("signer-issuer-no-delegation", "delegated_to_issuer = kid in deleg.get(rec[\"issuer\"], [])", "delegated_to_issuer = False"),
    ("record-digest-unchecked", 'if record_ok and pl["accepted_record_sha256"] !=', 'if False and pl["accepted_record_sha256"] !='),
    ("record-digest-no-record_id", "hashlib.sha256(jcs_string_object(rec))",
     "hashlib.sha256(jcs_string_object({k: v for k, v in rec.items() if k != 'record_id'}))"),
    ("outcome-unchecked", 'if outcome_ok and pl["outcome_sha256"] != rec["outcome_sha256"]:', "if False:"),
    ("unknown-payload-refused", 'notes.append("acceptance_member_ignored:%s" % k)', 'conds.append("acceptance_member_invalid")'),
    ("version-any", 'if pl.get("acceptance_version") != VERSION:', "if False:"),
    ("version-string-any", 'if pl.get("acceptance_version") != VERSION:', 'if not isinstance(pl.get("acceptance_version"), str):'),
    ("envelope-old-name", 'return _report("malformed", ["acceptance_member_invalid"], notes=notes, reasons=reasons)',
     'return _report("malformed", ["acceptance_envelope_invalid"], notes=notes, reasons=reasons)'),
    ("payload-old-name", 'return _report("malformed", ["acceptance_member_invalid"], key_step=key_step, notes=notes,',
     'return _report("malformed", ["acceptance_envelope_invalid"], key_step=key_step, notes=notes,'),
    ("signatures-allowed", 'if "signatures" in env:', "if False:"),
    ("jws-member-refused", 'notes.append("jws_member_ignored:%s (RFC 7515 section 7.2.1)" % k)', 'reasons.append(k)'),
    ("header-member-refused", 'ENVELOPE_MEMBERS = {"protected", "header", "payload", "signature"}', 'ENVELOPE_MEMBERS = {"protected", "payload", "signature"}'),
    ("header-overlap-allowed", "            if both:\n", "            if False:\n"),
    ("header-crit-allowed", 'if "crit" in uhdr:', "if False:"),
    ("header-not-union", "jose.update(hdr)                                 # RFC 7515 7.2.1", "jose = dict(hdr)                                 # RFC 7515 7.2.1"),
    ("unusable-key-kept", "keys[kid] = None", "keys[kid] = x"),
    ("unusable-key-input-error", 'notes.append("trust_material_key_unusable:%s: %s" % (kid, problem))',
     'raise InputError("unusable key")'),
    ("x-length-unchecked", "if len(x) != 32:", "if False:"),
    ("unknown-case-member-ignored", "extra = set(case) - CASE_MEMBERS", "extra = set()"),
    ("unknown-record-member-ignored", "extra = set(rec) - RECORD_MEMBERS", "extra = set()"),
    ("crit-ignored", 'if "crit" in hdr:', "if False:"),
    ("duplicates-allowed", "raise _Dup(k)", "pass"),
    ("b64-lenient", 'raise ValueError("non-canonical base64url (trailing bits)")', "pass"),
    ("b64-padding-allowed", r'_B64URL = re.compile(r"[A-Za-z0-9_-]*")', r'_B64URL = re.compile(r"[A-Za-z0-9_=-]*")'),
    ("hex-search-not-fullmatch", "_HEX64.fullmatch(v)", "_HEX64.match(v)"),
    ("ts-search-not-fullmatch", "m = _TS.fullmatch(v)", "m = _TS.match(v)"),
    ("ts-unicode-digits", r'_TS = re.compile(r"([0-9]{4})', r'_TS = re.compile(r"(\d{4})'),
    ("ts-leap-second", "0 <= s <= 59", "0 <= s <= 60"),
    ("ts-any-day", "return 1 <= d <= mdays", "return 1 <= d <= 31"),
    ("complete-default-true", 'complete = case.get("trust_material_complete", False)', 'complete = case.get("trust_material_complete", True)'),
    ("disposition-on-malformed", "disposition=(disp if disposition_always and disp_ok else None)", "disposition=disp"),
    ("cp-null-is-invalid", 'if cp is None or cp == "":', 'if cp == "" or "confirming_party" not in pl:'),
]


def vectors_disagree(check):
    def safe(case):
        try:
            return check(case)
        except Exception as e:  # a crash is a disagreement, never a pass
            return {"result": "CRASH:%s" % type(e).__name__}
    doc = json.load(open(VEC))
    rows = mv.measure(doc["vectors"], safe)
    return [r["id"] for r in rows if not r["agree"]]


def main():
    fails = 0
    # 1. altered vectors
    doc = json.load(open(VEC))
    import acceptance_check as ac
    base = [v for v in doc["vectors"] if v["id"] == "acc-accepted-verified"][0]
    alt = []
    a = copy.deepcopy(base); tg.flip_sig(a["case"], 20, 3); alt.append(("signature byte flipped", a))
    a = copy.deepcopy(base); a["expect"]["result"] = "unknown"; alt.append(("expect.result changed", a))
    a = copy.deepcopy(base); a["expect"]["conditions"] = ["confirming_party_absent"]; alt.append(("extra expected condition", a))
    a = copy.deepcopy(base); a["expect"]["disposition"] = "rejected"; alt.append(("expect.disposition changed", a))
    for what, v in alt:
        r = mv.measure([v], ac.check)[0]
        print("altered vector (%s): %s" % (what, "DISAGREE (control ok)" if not r["agree"] else "AGREE (CONTROL FAILED)"))
        fails += r["agree"]

    # 2. source mutants
    src = open(os.path.join(HERE, "acceptance_check.py")).read()
    survivors = []
    for name, old, new in MUTANTS:
        if src.count(old) != 1:
            print("mutant %s: anchor found %d times (must be 1)" % (name, src.count(old)))
            fails += 1
            continue
        m = load_module("acceptance_check", src.replace(old, new))
        vec_kill = vectors_disagree(m.check)
        tab_kill = [t for t, _, _ in tg.run_table(m.check, verbose=False)]
        fz = tg.fuzz(400, check=m.check) if not vec_kill and not tab_kill else []
        killed = bool(vec_kill or tab_kill or fz)
        print("mutant %-30s %s  vectors=%d %s table=%d %s fuzz=%d" % (
            name, "killed" if killed else "SURVIVED", len(vec_kill), vec_kill[:3], len(tab_kill), tab_kill[:3], len(fz)))
        if not killed:
            survivors.append(name)

    # 3. Ed25519 always-accept
    import ed25519_rfc8032 as ed
    real = ed.verify
    ed.verify = lambda *a: True
    try:
        vk = vectors_disagree(ac.check)
    finally:
        ed.verify = real
    print("ed25519 verify->True: vectors disagreeing %s" % vk)
    fails += not vk
    # proven equivalent by equivalenza_b64.py (the round-trip check already refuses every '='):
    equivalent = {"b64-padding-allowed"}
    print("SURVIVORS", survivors, "of which proven equivalent:", sorted(equivalent & set(survivors)))
    return 1 if fails or set(survivors) - equivalent else 0


if __name__ == "__main__":
    sys.exit(main())
