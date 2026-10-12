# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Generative tests. Every case is built here with keys made here (no vector bytes are reused for signing),
and its expected class is written by hand in TABLE from the text cited in its "rule" column, not from the
checker's output. Classes marked "OUR" are readings this implementation fixes where the text is silent;
the "rule" column says which, and the README ("Readings of ours") summarises them. A seeded random fuzz then checks text-level invariants on 2 000 mutated payloads.

python3 test_generativi.py        -> exit 0 iff every TABLE row and every invariant holds
"""
import base64
import copy
import hashlib
import json
import random
import sys

import acceptance_check as ac
import ed25519_rfc8032 as ed

CHECK = ac.check   # replaced by the mutation harness


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


SK_ISS = hashlib.sha256(b"omega-test issuer").digest()
SK_CP = hashlib.sha256(b"omega-test counterparty").digest()
SK_OTHER = hashlib.sha256(b"omega-test other").digest()
PK = {k: ed.public_key(s) for k, s in (("iss-A", SK_ISS), ("cp-A", SK_CP), ("other-A", SK_OTHER))}

RECORD = {"issuer": "did:example:iss", "issuer_kid": "iss-A", "outcome_at": "2026-10-04T18:00:00.000Z",
          "outcome_sha256": "11" * 32, "record_id": "r-1", "terms_sha256": "22" * 32}
REC_SHA = hashlib.sha256(ac.jcs_string_object(RECORD)).hexdigest()
PAYLOAD = {"acceptance_version": "acceptance-record-v0", "accepted_at": "2026-10-04T18:05:00.000Z",
           "accepted_record_sha256": REC_SHA, "confirming_party": "did:example:cp", "disposition": "accepted",
           "outcome_sha256": "11" * 32, "terms_sha256": "22" * 32}


def jwk(kid, pub, **extra):
    d = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64u(pub)}
    d.update(extra)
    return d


def envelope(payload=None, header=None, sk=SK_CP, raw_payload=None, raw_header=None):
    h = raw_header if raw_header is not None else json.dumps(header or {"alg": "EdDSA", "kid": "cp-A"}).encode()
    p = raw_payload if raw_payload is not None else json.dumps(payload if payload is not None else PAYLOAD).encode()
    ph, pp = b64u(h), b64u(p)
    return {"protected": ph, "payload": pp, "signature": b64u(ed.sign(sk, (ph + "." + pp).encode()))}


def base_case(**kw):
    c = {"acceptance": envelope(), "accepted_record": dict(RECORD),
         "delegation": {"did:example:cp": ["cp-A"], "did:example:iss": ["iss-A"]},
         "trust_material": {"keys": [jwk("iss-A", PK["iss-A"]), jwk("cp-A", PK["cp-A"])]},
         "trust_material_complete": False}
    c.update(kw)
    return c


def with_payload(**changes):
    p = dict(PAYLOAD)
    for k, v in changes.items():
        if v is DROP:
            p.pop(k, None)
        else:
            p[k] = v
    return base_case(acceptance=envelope(p))


DROP = object()
MI = "acceptance_member_invalid"
VERIFIED = {"result": "verified", "conditions": [], "disposition": "accepted"}


def mal(*conds):
    return {"result": "malformed", "conditions": list(conds), "disposition": None}


INPUT = {"result": "input_error"}
ENV = mal("acceptance_member_invalid")   # README 90b5032 sentence 2 (was acceptance_envelope_invalid)
SIGINV = {"result": "malformed", "conditions": ["signature_invalid"], "key_step": "signature_invalid",
          "disposition": None, "policy_refusal": False}


def flip_sig(c, byte=10, bit=0):
    s = bytearray(base64.urlsafe_b64decode(c["acceptance"]["signature"] + "=="))
    s[byte] ^= 1 << bit
    c["acceptance"]["signature"] = b64u(bytes(s))
    return c


def sig_bytes(c, new):
    c["acceptance"]["signature"] = b64u(new)
    return c


def malleate_s(c):
    s = base64.urlsafe_b64decode(c["acceptance"]["signature"] + "==")
    S = int.from_bytes(s[32:], "little") + ed.L
    return sig_bytes(c, s[:32] + S.to_bytes(32, "little"))


def trailing_bits(c, member):
    """Change the last character so the decoded bytes are unchanged but the unused bits are non-zero."""
    sv = c["acceptance"][member]
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    unused = {2: 4, 3: 2}[len(sv) % 4]
    i = alpha.index(sv[-1])
    assert i & ((1 << unused) - 1) == 0
    c["acceptance"][member] = sv[:-1] + alpha[i | 1]
    assert base64.urlsafe_b64decode(c["acceptance"][member] + "==") == base64.urlsafe_b64decode(sv + "==")
    return c


def setk(c, path, value):
    o = c
    for k in path[:-1]:
        o = o[k]
    if value is DROP:
        del o[path[-1]]
    else:
        o[path[-1]] = value
    return c


def payload_with_dup():
    txt = json.dumps(PAYLOAD)[:-1] + ', "disposition": "rejected"}'
    return base_case(acceptance=envelope(raw_payload=txt.encode()))


def padded(c, member):
    s = c["acceptance"][member]
    if len(s) % 4:
        c["acceptance"][member] = s + "=" * (-len(s) % 4)
    else:
        c["acceptance"][member] = s + "===="   # still non-canonical: padding on an aligned string
    return c


# id, builder, expected subset, rule the expectation comes from ("OUR" = this implementation's reading)
TABLE = [
    ("base-verified", lambda: base_case(), VERIFIED, "README result table: verified"),
    ("rejected-verified", lambda: with_payload(disposition="rejected"),
     {"result": "verified", "disposition": "rejected"}, "README: disposition reported beside verified"),
    ("no-record", lambda: {"accepted_record": dict(RECORD)},
     {"result": "no_record", "conditions": [], "disposition": "not_responded"}, "README result table: no_record"),
    ("no-record-with-material", lambda: {k: v for k, v in base_case().items() if k != "acceptance"},
     {"result": "no_record", "disposition": "not_responded"}, "README: no acceptance record was supplied"),
    ("acceptance-null", lambda: base_case(acceptance=None), ENV, "OUR: null is a supplied, non-JWS value"),
    # --- unknown keys at every level
    ("unknown-case-member", lambda: base_case(extra=1), INPUT, "OUR: closed input grammar (text silent)"),
    ("unknown-record-member", lambda: setk(base_case(), ["accepted_record", "amount"], "5"), INPUT,
     "OUR: A4 + Changes (record_id) name the members; others refused"),
    ("unknown-trust-material-member", lambda: setk(base_case(), ["trust_material", "complete"], True), INPUT,
     "OUR: closed input grammar"),
    ("unknown-jwk-member", lambda: setk(base_case(), ["trust_material", "keys", 1, "use"], "sig"), VERIFIED,
     "RFC 7517 4: JWK members not understood MUST be ignored (reported in notes)"),
    ("unknown-header-param", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "cp-A", "typ": "x"})),
     VERIFIED, "RFC 7515 4: header params not understood MUST be ignored unless crit (reported in notes)"),
    ("crit-header", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "cp-A", "crit": ["zz"], "zz": 1})),
     ENV, "RFC 7515 4.1.11: crit param not understood -> JWS invalid"),
    ("empty-unprotected-header", lambda: setk(base_case(), ["acceptance", "header"], {}), VERIFIED,
     "RFC 7515 7.2.2: header is a member of the flattened syntax"),
    ("unknown-envelope-member", lambda: setk(base_case(), ["acceptance", "zz"], 1), VERIFIED,
     "RFC 7515 7.2.1: additional members not understood MUST be ignored (reported in notes)"),
    ("envelope-signatures-member", lambda: setk(base_case(), ["acceptance", "signatures"], []), ENV,
     "RFC 7515 7.2.2: signatures MUST NOT be present"),
    ("unprotected-header-not-object", lambda: setk(base_case(), ["acceptance", "header"], "x"), ENV,
     "RFC 7515 7.2.1: header is a JSON object"),
    ("unprotected-header-overlaps", lambda: setk(base_case(), ["acceptance", "header"], {"kid": "cp-A"}), ENV,
     "RFC 7515 7.2.1: names MUST be disjoint"),
    ("unprotected-header-crit", lambda: setk(base_case(), ["acceptance", "header"], {"crit": ["zz"]}), ENV,
     "RFC 7515 4.1.11: crit only in the protected header"),
    ("unprotected-header-typ", lambda: setk(base_case(), ["acceptance", "header"], {"typ": "x"}),
     dict(VERIFIED, notes=["header_parameter_ignored:typ (RFC 7515 section 4)"]),
     "RFC 7515 4: not understood, ignored (notes)"),
    ("kid-in-unprotected-header", lambda: setk(base_case(acceptance=envelope(header={"alg": "EdDSA"})),
                                               ["acceptance", "header"], {"kid": "cp-A"}), VERIFIED,
     "RFC 7515 7.2.1: the JOSE Header is the union"),
    ("alg-and-kid-in-unprotected-header", lambda: setk(base_case(acceptance=envelope(raw_header=b"{}")),
                                                       ["acceptance", "header"], {"alg": "EdDSA", "kid": "cp-A"}),
     VERIFIED, "RFC 7515 7.2.1: alg and kid from the union (OUR: protected {} accepted)"),
    ("alg-in-unprotected-header-only-none", lambda: setk(base_case(acceptance=envelope(header={"kid": "cp-A"})),
                                                         ["acceptance", "header"], {"alg": "none"}), ENV,
     "OUR: EdDSA only, from the union"),
    *[("envelope-%s-absent" % m, (lambda m=m: setk(base_case(), ["acceptance", m], DROP)), ENV, "OUR: README sentence 2 names all three")
      for m in ("protected", "payload", "signature")],
    ("unknown-payload-member", lambda: with_payload(note="hi"), VERIFIED, "README 90b5032 sentence 1: ignored"),
    ("unknown-payload-member-plus-mismatch", lambda: with_payload(note="hi", terms_sha256="33" * 32),
     mal("acceptance_terms_digest_mismatch"), "README sentence 1 + report-all"),
    # --- wrong types / non-canonical digests (README step 2: 64 lowercase hex, suppress the mismatch)
    *[("terms-%s" % n, (lambda v=v: with_payload(terms_sha256=v)), mal(MI), "README step 2 (5a4ea06)")
      for n, v in (("int", 123), ("null", None), ("list", []), ("upper", "AB" * 32), ("63", "a" * 63),
                   ("65", "a" * 65), ("nl", "22" * 32 + "\n"), ("0x", "0x" + "22" * 31), ("absent", DROP),
                   ("bool", True), ("obj", {}))],
    *[("outcome-%s" % n, (lambda v=v: with_payload(outcome_sha256=v)), mal(MI), "README step 2 (5a4ea06)")
      for n, v in (("upper", "1A" * 32), ("nl", "11" * 32 + "\n"), ("absent", DROP), ("num", 1.5))],
    *[("recsha-%s" % n, (lambda v=v: with_payload(accepted_record_sha256=v)), mal(MI), "README step 2 + A8")
      for n, v in (("upper", REC_SHA.upper()), ("absent", DROP), ("short", REC_SHA[:-1]), ("sp", " " + REC_SHA[1:]))],
    ("terms-illtyped-plus-outcome-mismatch", lambda: with_payload(terms_sha256="nope", outcome_sha256="33" * 32),
     mal(MI, "acceptance_outcome_digest_mismatch"), "README step 2: suppression is per dependent mismatch only"),
    # --- timestamps (README does not define the form; -03 5.3.2 retrieved_at form used)
    *[("accepted-at-%s" % n, (lambda v=v: with_payload(accepted_at=v)), mal(MI), "OUR via -03 5.3.2 form")
      for n, v in (("no-ms", "2026-10-04T18:05:00Z"), ("offset", "2026-10-04T18:05:00.000+00:00"),
                   ("feb30", "2026-02-30T18:05:00.000Z"), ("h24", "2026-10-04T24:00:00.000Z"),
                   ("leap", "2026-10-04T18:05:60.000Z"), ("int", 1759600000), ("null", None), ("absent", DROP),
                   ("fullwidth", "２026-10-04T18:05:00.000Z"), ("lower-z", "2026-10-04T18:05:00.000z"),
                   ("nl", "2026-10-04T18:05:00.000Z\n"))],
    ("accepted-at-early-and-illtyped-terms", lambda: with_payload(accepted_at="2026-10-04T17:00:00.000Z", terms_sha256=5),
     mal(MI, "acceptance_precedes_outcome"), "README report-all + step 2"),
    ("same-instant", lambda: with_payload(accepted_at=RECORD["outcome_at"]), VERIFIED, "README A7: strict"),
    ("one-ms-before", lambda: with_payload(accepted_at="2026-10-04T17:59:59.999Z"), mal("acceptance_precedes_outcome"),
     "table: earlier than"),
    # --- disposition / confirming party / version
    ("disp-not-responded", lambda: with_payload(disposition="not_responded"), mal(MI), "README A2"),
    ("disp-upper", lambda: with_payload(disposition="ACCEPTED"), mal(MI), "A3 ill-typed (not one of the three)"),
    ("disp-int", lambda: with_payload(disposition=1), mal(MI), "A3"),
    ("disp-absent", lambda: with_payload(disposition=DROP), mal(MI), "A3 absent"),
    ("cp-absent", lambda: with_payload(confirming_party=DROP), mal("confirming_party_absent"), "table"),
    ("cp-empty", lambda: with_payload(confirming_party=""), mal("confirming_party_absent"), "vector acc-confirming-party-empty"),
    ("cp-null", lambda: with_payload(confirming_party=None), mal("confirming_party_absent"), "OUR: null names no party"),
    ("cp-int", lambda: with_payload(confirming_party=5), mal(MI), "A3 ill-typed"),
    ("cp-is-issuer", lambda: with_payload(confirming_party="did:example:iss"), mal("acceptance_signer_is_issuer"), "A5 (ii)"),
    ("version-absent", lambda: with_payload(acceptance_version=DROP), mal(MI), "A1 + A3"),
    *[("version-%s" % n, (lambda v=v: with_payload(acceptance_version=v)), mal(MI), "README 90b5032 sentence 3")
      for n, v in (("v1", "acceptance-record-v1"), ("null", None), ("int", 0), ("upper", "ACCEPTANCE-RECORD-V0"),
                   ("nl", "acceptance-record-v0\n"), ("empty", ""), ("list", ["acceptance-record-v0"]))],
    ("version-other-plus-mismatch", lambda: with_payload(acceptance_version="v1", terms_sha256="33" * 32),
     mal(MI, "acceptance_terms_digest_mismatch"), "README sentence 3 + report-all (OUR: version joins report-all)"),
    # --- signer is issuer (A5) and authority (A6)
    ("signed-by-issuer-key", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "iss-A"}, sk=SK_ISS)),
     mal("acceptance_signer_is_issuer"), "A5 (i)"),
    ("issuer-key-new-kid", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "cp-X"}, sk=SK_ISS),
                                             delegation={"did:example:cp": ["cp-X"]},
                                             trust_material={"keys": [jwk("iss-A", PK["iss-A"]), jwk("cp-A", PK["cp-A"]),
                                                                      jwk("cp-X", PK["iss-A"])]}),
     mal("acceptance_signer_is_issuer"), "A5 (i): same key bytes under another kid"),
    ("delegated-to-issuer", lambda: base_case(delegation={"did:example:cp": ["cp-A"], "did:example:iss": ["cp-A"]}),
     mal("acceptance_signer_is_issuer"), "A5 (iii)"),
    ("authority-unresolved", lambda: base_case(delegation={"did:example:iss": ["iss-A"]}),
     {"result": "unknown", "conditions": ["acceptance_authority_unresolved"], "disposition": "accepted"}, "A6 + table"),
    ("authority-other-party", lambda: base_case(delegation={"did:example:someone": ["cp-A"]}),
     {"result": "unknown", "conditions": ["acceptance_authority_unresolved"]}, "A6"),
    ("malformed-no-authority", lambda: base_case(acceptance=envelope(dict(PAYLOAD, terms_sha256="33" * 32)), delegation={}),
     mal("acceptance_terms_digest_mismatch"), "README step 3"),
    ("report-all-four", lambda: with_payload(terms_sha256="33" * 32, outcome_sha256="44" * 32,
                                             accepted_at="2026-10-01T00:00:00.000Z", accepted_record_sha256="55" * 32),
     mal("acceptance_terms_digest_mismatch", "acceptance_outcome_digest_mismatch", "acceptance_precedes_outcome",
         "acceptance_record_digest_mismatch"), "README report-all"),
    ("record-other-id", lambda: setk(base_case(), ["accepted_record", "record_id"], "r-2"),
     mal("acceptance_record_digest_mismatch"), "A8"),
    ("record-without-record_id", lambda: setk(base_case(), ["accepted_record", "record_id"], DROP),
     mal("acceptance_record_digest_mismatch"), "A8: digest over the record held"),
    # --- key step (-03 5.4.2)
    ("kid-unknown", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "nope"})),
     {"result": "key_unresolved", "conditions": [], "key_step": "key_unresolved", "policy_refusal": False,
      "disposition": None}, "-03 5.4.2(a)"),
    ("kid-unknown-complete", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "nope"}),
                                               trust_material_complete=True),
     {"result": "key_unresolved", "policy_refusal": True}, "-03 5.4.2(b)"),
    ("kid-unknown-complete-omitted", lambda: {k: v for k, v in base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "nope"})).items()
                                              if k != "trust_material_complete"},
     {"result": "key_unresolved", "policy_refusal": False}, "-03 5.4.2: omitting is never a declaration"),
    ("kid-unknown-broken-payload", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": "nope"}, raw_payload=b"[1]")),
     {"result": "key_unresolved", "conditions": []}, "README step 1: stops evaluation"),
    ("complete-not-bool", lambda: base_case(trust_material_complete="true"), INPUT, "-03 5.4.2: explicit input; OUR type rule"),
    ("sig-bitflip-complete", lambda: flip_sig(base_case(trust_material_complete=True)), SIGINV,
     "-03 5.4.2: never turns (c) into a refusal"),
    *[("sig-flip-byte%d" % b, (lambda b=b: flip_sig(base_case(), b, b % 8)), SIGINV, "-03 5.4.2(c) + README step 1")
      for b in (0, 31, 32, 63)],
    ("sig-S-plus-L", lambda: malleate_s(base_case()), SIGINV, "RFC 8032 5.1.7 S < L"),
    ("sig-63-bytes", lambda: sig_bytes(base_case(), b"\x01" * 63), SIGINV, "OUR: the check ran and failed"),
    ("sig-other-key", lambda: base_case(acceptance=envelope(sk=SK_OTHER)), SIGINV, "-03 5.4.2(c)"),
    ("payload-swapped-after-signing", lambda: setk(base_case(), ["acceptance", "payload"],
                                                   envelope(dict(PAYLOAD, disposition="rejected"))["payload"]),
     SIGINV, "-03 5.4.2(c)"),
    ("sig-invalid-and-bad-payload", lambda: flip_sig(base_case(acceptance=envelope(dict(PAYLOAD, terms_sha256="x")))),
     SIGINV, "README step 1: signature_invalid is the only condition reported"),
    # --- duplicates, order, encodings
    ("payload-duplicate-member", payload_with_dup, ENV, "OUR: RFC 8259 4 SHOULD unique -> refuse"),
    ("header-duplicate-kid", lambda: base_case(acceptance=envelope(raw_header=b'{"alg":"EdDSA","kid":"cp-A","kid":"cp-A"}')),
     ENV, "RFC 7515 5.2 step 4: reject (or lexically last); closed -> reject"),
    ("payload-reordered", lambda: base_case(acceptance=envelope(raw_payload=json.dumps(dict(reversed(list(PAYLOAD.items())))).encode())),
     VERIFIED, "member order is not meaningful (RFC 8259 4)"),
    ("payload-whitespace", lambda: base_case(acceptance=envelope(raw_payload=json.dumps(PAYLOAD, indent=2).encode())),
     VERIFIED, "the signature covers the bytes; JSON whitespace is legal"),
    ("keys-reordered", lambda: setk(base_case(), ["trust_material", "keys"], [jwk("cp-A", PK["cp-A"]), jwk("iss-A", PK["iss-A"])]),
     VERIFIED, "order of trust material irrelevant"),
    ("payload-padded-b64", lambda: padded(base_case(), "payload"), ENV, "RFC 7515 2: base64url without padding"),
    ("signature-padded-b64", lambda: padded(base_case(), "signature"), ENV, "RFC 7515 2"),
    ("signature-nonzero-pad-bits", lambda: trailing_bits(base_case(), "signature"), ENV,
     "OUR: RFC 4648 3.5 canonical encoding (same bytes, different string)"),
    ("payload-nonzero-pad-bits", lambda: trailing_bits(base_case(), "payload"), ENV, "OUR: RFC 4648 3.5"),
    ("payload-std-alphabet", lambda: setk(base_case(), ["acceptance", "payload"],
                                          base_case()["acceptance"]["payload"].replace("-", "+").replace("_", "/") + "+"),
     ENV, "RFC 7515 2: base64url alphabet"),
    ("payload-not-utf8", lambda: base_case(acceptance=envelope(raw_payload=b'{"a":"\xff"}')), ENV, "OUR: RFC 8259 8.1 UTF-8"),
    ("payload-array", lambda: base_case(acceptance=envelope(raw_payload=b"[]")), ENV, "OUR: payload must be an object"),
    ("payload-nan", lambda: base_case(acceptance=envelope(raw_payload=json.dumps(dict(PAYLOAD, x=0)).replace("0}", "NaN}").encode())),
     ENV, "RFC 8259 6: NaN is not JSON"),
    ("payload-bom", lambda: base_case(acceptance=envelope(raw_payload=b"\xef\xbb\xbf" + json.dumps(PAYLOAD).encode())),
     ENV, "RFC 8259 8.1: MUST NOT add a BOM"),
    ("payload-lone-surrogate", lambda: base_case(acceptance=envelope(raw_payload=json.dumps(dict(PAYLOAD, confirming_party="\ud800")).encode())),
     ENV, "RFC 7493 2.1 (I-JSON)"),
    ("alg-es256", lambda: base_case(acceptance=envelope(header={"alg": "ES256", "kid": "cp-A"})), ENV, "OUR: EdDSA only"),
    ("alg-none", lambda: base_case(acceptance=envelope(header={"alg": "none", "kid": "cp-A"})), ENV, "OUR: EdDSA only"),
    ("kid-int", lambda: base_case(acceptance=envelope(header={"alg": "EdDSA", "kid": 1})), ENV, "OUR"),
    ("acceptance-compact-string", lambda: base_case(acceptance="a.b.c"), ENV, "OUR: flattened JSON only"),
    # --- input grammar (relying party)
    ("jwk-bad-point", lambda: setk(base_case(), ["trust_material", "keys", 1, "x"], b64u(b"\xff" * 32)),
     SIGINV, "RFC 8032 5.1.7 step 1: a public key that does not decode makes the signature invalid"),
    ("jwk-small-order-key", lambda: setk(base_case(), ["trust_material", "keys", 1, "x"], b64u(b"\x01" + b"\x00" * 31)),
     {"result": "key_unresolved", "key_step": "key_unresolved"}, "README 90b5032 sentence 4: the neutral point as key"),
    ("jwk-31-octets", lambda: setk(base_case(), ["trust_material", "keys", 1, "x"], b64u(b"\x01" * 31)), INPUT,
     "OUR: RFC 8037 2, x is 32 octets"),
    ("jwk-dup-kid", lambda: setk(base_case(), ["trust_material", "keys", 0, "kid"], "cp-A"), INPUT, "OUR: ambiguous resolution"),
    ("jwk-x25519", lambda: setk(base_case(), ["trust_material", "keys", 1, "crv"], "X25519"), INPUT, "OUR: Ed25519 only"),
    ("delegation-absent", lambda: {k: v for k, v in base_case().items() if k != "delegation"}, INPUT, "OUR"),
    ("delegation-not-list", lambda: base_case(delegation={"did:example:cp": "cp-A"}), INPUT, "A6 format {party: [kid,...]}"),
    ("record-hash-upper", lambda: setk(base_case(), ["accepted_record", "terms_sha256"], "22" * 31 + "2A"), INPUT, "OUR"),
    ("record-outcome-at-bad", lambda: setk(base_case(), ["accepted_record", "outcome_at"], "yesterday"), INPUT, "OUR"),
    ("case-not-object", lambda: [], INPUT, "OUR"),
]


def subset_agrees(exp, got):
    bad = []
    for k, v in exp.items():
        g = got.get(k)
        if k == "conditions":
            if sorted(set(g or [])) != sorted(set(v)) or len(g or []) != len(set(g or [])):
                bad.append((k, v, g))
        elif type(g) is not type(v) or g != v:
            bad.append((k, v, g))
    return bad


def run_table(check=None, verbose=True):
    check = check or CHECK
    fails = []
    for tid, build, exp, rule in TABLE:
        try:
            got = check(build())
        except Exception as e:  # a crash is a failure, never a pass
            got = {"result": "CRASH:%s" % type(e).__name__}
        bad = subset_agrees(exp, got)
        if bad:
            fails.append((tid, bad, rule))
        if verbose:
            print("%-40s %s  [%s]%s" % (tid, "ok  " if not bad else "FAIL", rule, "" if not bad else "  " + repr(bad)))
    return fails


TOKENS = {"verified", "unknown", "key_unresolved", "no_record", "malformed", "input_error"}
DIGEST_OF = {"terms_sha256": "acceptance_terms_digest_mismatch", "outcome_sha256": "acceptance_outcome_digest_mismatch",
             "accepted_record_sha256": "acceptance_record_digest_mismatch"}
WEIRD = [None, True, False, 0, -1, 1.5, "", " ", "x", "\n", [], {}, [1], {"a": 1}, "A" * 64, "a" * 64, "0" * 64,
         "2026-10-04T18:05:00.000Z", "accepted", "not_responded", "did:example:cp", "did:example:iss", "\u0000", "é" * 64]


def fuzz(n=2000, seed=20261011, check=None):
    """Random payload mutations (signed with the counterparty key). Invariants come from the README text."""
    check = check or CHECK
    rnd = random.Random(seed)
    viol = []
    for i in range(n):
        p = dict(PAYLOAD)
        for _ in range(rnd.randrange(1, 4)):
            op = rnd.randrange(4)
            if op == 0:
                p[rnd.choice(sorted(p) or ["x"])] = rnd.choice(WEIRD)
            elif op == 1 and p:
                p.pop(rnd.choice(sorted(p)))
            elif op == 2:
                p[rnd.choice(["zz", "Disposition", "terms_sha256 ", "kid", "accepted_record", "acceptance_version"])] = rnd.choice(WEIRD)
            else:
                k = rnd.choice(list(DIGEST_OF))
                p[k] = "".join(rnd.choice("0123456789abcdef") for _ in range(64))
        try:
            r = check(base_case(acceptance=envelope(p)))
        except Exception as e:
            viol.append((i, "crash %r" % e, p))
            continue
        conds = r.get("conditions", [])
        if r["result"] not in TOKENS:
            viol.append((i, "token", r["result"]))
        if r["result"] == "malformed" and not conds:
            viol.append((i, "malformed without condition", p))
        if r["result"] in ("malformed", "key_unresolved") and r.get("disposition") is not None:
            viol.append((i, "disposition on non-clean result (README 5a4ea06)", p))
        if p.get("acceptance_version") != "acceptance-record-v0" and not (
                r["result"] == "malformed" and "acceptance_member_invalid" in conds):
            viol.append((i, "version not acceptance-record-v0, not malformed acceptance_member_invalid (sentence 3)", p))
        if r["result"] == "malformed" and "acceptance_authority_unresolved" in conds:
            viol.append((i, "unknown stacked on malformed (README step 3)", p))
        if r["result"] == "verified":
            ok = (set(p) >= set(PAYLOAD) and p["disposition"] in ("accepted", "rejected", "disputed")
                  and all(p[k] == PAYLOAD[k] for k in ("terms_sha256", "outcome_sha256", "accepted_record_sha256",
                                                       "confirming_party", "acceptance_version"))
                  and ac.canonical_ts(p["accepted_at"]) and p["accepted_at"] >= RECORD["outcome_at"])
            if not ok:
                viol.append((i, "verified on a payload the text rejects", p))
        for k, cname in DIGEST_OF.items():
            illtyped = k not in p or not ac.is_hex64(p[k])
            if illtyped and cname in conds:
                viol.append((i, "mismatch reported on ill-typed %s (README step 2)" % k, p))
            if not illtyped:                         # report-all, the version included (README sentence 3)
                want = p[k] != (RECORD[k] if k != "accepted_record_sha256" else REC_SHA)
                if want != (cname in conds):
                    viol.append((i, "report-all: %s presence wrong" % cname, p))
    return viol


def main():
    fails = run_table()
    print("TABLE: %d/%d rows as expected" % (len(TABLE) - len(fails), len(TABLE)))
    viol = fuzz()
    print("FUZZ: 2000 mutated payloads, %d invariant violations" % len(viol))
    for v in viol[:10]:
        print("  ", v)
    return 1 if fails or viol else 0


if __name__ == "__main__":
    sys.exit(main())
