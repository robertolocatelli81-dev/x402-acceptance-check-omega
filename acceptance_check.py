# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Acceptance-record checker for the x402 tsc#4 acceptance conditions (third, independent implementation).

Written from the README of babyblueviper1/preaction-governance-conformance at 5a4ea06 and 646588c
(examples/acceptance-record-cold/README.md), the condition table posted in x402-foundation/tsc#4 on
2026-10-04, draft-krausz-verification-state-03 Sections 5.3.2, 5.4.1 and 5.4.2, and RFC 8032 Section 5.1.
Aligned on 2026-10-12 with the README at 90b5032 (section "Inputs the vectors do not yet pin", sentences 1-4,
and "Changes between versions") and with RFC 7515 Sections 4.1.11, 7.2.1 and 7.2.2; later the same day with the
README at 0abf726 (sentences 5-7; sentence 8 is left to the relying party and this checker keeps input_error there)
and the 46 vectors at 536681b; on 2026-10-13 with the README at 9d4cf2c (sentence 9, mixed-order keys and R) and the
50 vectors at 9d4cf2c. The code of the other
acceptance-record checkers (the reference one and actaseal's) was not opened, then or before; see the README
for what else of that repository we had read.

Closed by construction: every input member is either understood or refused with a reason. The only
members not refused are those a text says to ignore, and those are listed in "notes": members of the
signed acceptance other than the seven (README sentence 1), JOSE header parameters not listed in "crit"
(RFC 7515 Section 4), members of the JWS object other than those of RFC 7515 Section 7.2.2 (RFC 7515
Section 7.2.1), and JWK members (RFC 7517 Section 4). JSON nested deeper
than MAX_DEPTH levels is refused before it is parsed, and JSON numbers are kept as opaque values (no member
of this grammar is a number), so the verdict does not depend on the Python version, on the recursion limit
or on PYTHONINTMAXSTRDIGITS.

Python 3 standard library only. Usage: python3 acceptance_check.py CASE.json  (a JSON object = the "case").
Exit: 0 verified, 2 unknown / key_unresolved / no_record, 1 malformed, 3 input outside the grammar,
74 the receipt was not written whole to stdout (for example stdout closed, a full device, a file size limit,
a reader that went away; also with -u or PYTHONUNBUFFERED), whatever the verdict; one line "receipt not
written: <reason>" is then tried on stderr. A non-blocking stdout that is full is waited for, as a blocking write
would be, not reported. A usage error exits 3.
"""
import base64
import hashlib
import json
import os
import re
import stat
import sys

if __name__ == "__main__":   # run as a command, write no bytecode cache: CPython 3.9 and 3.11 write a .pyc with one
    sys.dont_write_bytecode = True   # raw write; cut by a file size limit, every later run died (EOFError, 13/10/2026)
    sys.pycache_prefix = os.devnull  # and read none: a cut .pyc is not opened (nothing lies under /dev/null; Linux)
import ed25519_rfc8032 as ed

VERSION = "acceptance-record-v0"                      # README A1
DISPOSITIONS_SIGNED = ("accepted", "rejected", "disputed")   # A2: not_responded is never signed
EXIT = {"verified": 0, "unknown": 2, "key_unresolved": 2, "no_record": 2, "malformed": 1,
        "signature_invalid": 1, "input_error": 3}
EXIT_RECEIPT_NOT_WRITTEN = 74                         # sysexits.h EX_IOERR

CASE_MEMBERS = {"acceptance", "accepted_record", "delegation", "trust_material", "trust_material_complete"}
RECORD_MEMBERS = {"issuer", "issuer_kid", "terms_sha256", "outcome_sha256", "outcome_at", "record_id"}
RECORD_REQUIRED = {"issuer", "issuer_kid", "terms_sha256", "outcome_sha256", "outcome_at"}
ENVELOPE_MEMBERS = {"protected", "header", "payload", "signature"}   # RFC 7515 7.2.2 (flattened)
PAYLOAD_MEMBERS = {"acceptance_version", "accepted_at", "accepted_record_sha256", "confirming_party",
                   "disposition", "outcome_sha256", "terms_sha256"}
HEADER_UNDERSTOOD = {"alg", "kid"}
MAX_DEPTH = 64                                         # our limit; the grammar itself needs 3 levels
JWK_UNDERSTOOD = {"kty", "crv", "kid", "x"}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z")


class InputError(Exception):
    """The relying party's own input is outside the grammar this checker implements."""


class _Dup(Exception):
    pass


# ---------------------------------------------------------------- strict primitives

def _no_dup_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Dup(k)
        out[k] = v
    return out


def _bad_constant(name):
    raise ValueError("non-finite number " + name)


class _Number(object):
    """A JSON number, kept as its text. No member of this grammar is a number, so it is never converted."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


def _check_depth(text):
    """Refuse JSON nested deeper than MAX_DEPTH, counting brackets outside strings, before json.loads."""
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON nested deeper than %d levels" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1


def strict_json(text):
    """RFC 8259 JSON, refusing duplicate names (RFC 7515 5.2 / RFC 7493 2.3), NaN/Infinity and lone surrogates."""
    _check_depth(text)
    try:
        obj = json.loads(text, object_pairs_hook=_no_dup_pairs, parse_constant=_bad_constant,
                         parse_int=_Number, parse_float=_Number)
    except _Dup as e:
        raise ValueError("duplicate member name %r" % (e.args[0],))
    except RecursionError:            # not reachable under MAX_DEPTH; kept so that no input can raise it
        raise ValueError("JSON nested too deeply")
    _check_strings(obj)
    return obj


def _check_strings(obj):
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, str):
            o.encode("utf-8")  # raises on a lone surrogate (RFC 7493 2.1)
        elif isinstance(o, dict):
            for k, v in o.items():
                k.encode("utf-8")
                stack.append(v)
        elif isinstance(o, list):
            stack.extend(o)


def b64url_strict(s):
    """RFC 7515 2 / RFC 4648 5 without padding; refuses padding, other alphabets and non-zero trailing bits."""
    if not isinstance(s, str) or not _B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise ValueError("non-canonical base64url (trailing bits)")
    return raw


def is_hex64(v):
    return isinstance(v, str) and _HEX64.fullmatch(v) is not None


def canonical_ts(v):
    """-03 5.3.2 retrieved_at form: UTC, Z, exactly three fractional digits, a valid instant, no leap second."""
    if not isinstance(v, str):
        return False
    m = _TS.fullmatch(v)
    if not m:
        return False
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 0 <= h <= 23 and 0 <= mi <= 59 and 0 <= s <= 59):
        return False
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= mdays


def _jcs_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs_string_object(obj):
    """RFC 8785 for an object whose values are all strings (the only shape the accepted record may take here).
    Members sorted by their UTF-16 code units (RFC 8785 3.2.3)."""
    keys = sorted(obj, key=lambda k: k.encode("utf-16-be"))
    body = ",".join(_jcs_string(k) + ":" + _jcs_string(obj[k]) for k in keys)
    return ("{" + body + "}").encode("utf-8")


# ---------------------------------------------------------------- input grammar (relying-party side)

def _validate_inputs(case, notes):
    if not isinstance(case, dict):
        raise InputError("case is not a JSON object")
    extra = set(case) - CASE_MEMBERS
    if extra:
        raise InputError("unknown case member(s): %s" % sorted(extra))
    rec = case.get("accepted_record")
    if not isinstance(rec, dict):
        raise InputError("accepted_record absent or not an object")
    extra = set(rec) - RECORD_MEMBERS
    if extra:
        raise InputError("unknown accepted_record member(s): %s" % sorted(extra))
    missing = RECORD_REQUIRED - set(rec)
    if missing:
        raise InputError("accepted_record lacks %s" % sorted(missing))
    for k, v in rec.items():
        if not isinstance(v, str):
            raise InputError("accepted_record.%s is not a string" % k)
    for k in ("terms_sha256", "outcome_sha256"):
        if not is_hex64(rec[k]):
            raise InputError("accepted_record.%s is not 64 lowercase hex" % k)
    for k in ("issuer", "issuer_kid") + (("record_id",) if "record_id" in rec else ()):
        if rec[k] == "":
            raise InputError("accepted_record.%s is empty" % k)

    if "trust_material_complete" in case and not isinstance(case["trust_material_complete"], bool):
        raise InputError("trust_material_complete is not a boolean")

    keys = None
    if "trust_material" in case:
        tm = case["trust_material"]
        if not isinstance(tm, dict) or set(tm) != {"keys"} or not isinstance(tm["keys"], list):
            raise InputError("trust_material must be exactly {\"keys\": [...]}")
        keys = {}
        for i, jwk in enumerate(tm["keys"]):
            if not isinstance(jwk, dict):
                raise InputError("trust_material.keys[%d] is not an object" % i)
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                raise InputError("trust_material.keys[%d] is not an OKP/Ed25519 JWK" % i)
            kid = jwk.get("kid")
            if not isinstance(kid, str) or kid == "":
                raise InputError("trust_material.keys[%d].kid absent, empty or not a string" % i)
            if kid in keys:
                raise InputError("duplicate kid %r in trust_material" % kid)
            try:
                x = b64url_strict(jwk.get("x"))
            except ValueError as e:
                raise InputError("trust_material.keys[%d].x: %s" % (i, e))
            if len(x) != 32:
                raise InputError("trust_material.keys[%d].x is not 32 octets (RFC 8037 2)" % i)
            for k in sorted(set(jwk) - JWK_UNDERSTOOD):
                notes.append("jwk_member_ignored:%s:%s (RFC 7517 section 4)" % (kid, k))
            problem = ed.key_problem(x)
            if problem in ("small-order point", "mixed-order point"):
                # README sentences 4 and 9: a small-order or mixed-order key is not a key of the confirming
                # party (key_unresolved).
                notes.append("trust_material_key_unusable:%s: %s" % (kid, problem))
                keys[kid] = None
            else:
                if problem is not None:
                    # RFC 8032 5.1.7 step 1: if the public key does not decode, the signature is invalid.
                    notes.append("trust_material_key_undecodable:%s: %s" % (kid, problem))
                keys[kid] = x

    deleg = None
    if "delegation" in case:
        deleg = case["delegation"]
        if not isinstance(deleg, dict):
            raise InputError("delegation is not an object")
        for party, kids in deleg.items():
            if party == "" or not isinstance(kids, list) or not all(isinstance(k, str) and k for k in kids):
                raise InputError("delegation[%r] must be a list of non-empty kid strings" % party)
            if len(set(kids)) != len(kids):
                raise InputError("delegation[%r] lists a kid twice" % party)

    if "acceptance" in case:
        if keys is None:
            raise InputError("acceptance supplied without trust_material")
        if deleg is None:
            raise InputError("acceptance supplied without delegation material")
    return rec, keys, deleg


# ---------------------------------------------------------------- the check

def _report(result, conditions=(), disposition=None, key_step=None, policy_refusal=False, notes=(), reasons=()):
    conds = sorted(set(conditions))
    return {"result": result, "conditions": conds, "disposition": disposition, "key_step": key_step,
            "policy_refusal": policy_refusal, "exit": EXIT[result], "notes": list(notes), "reasons": list(reasons)}


def check(case, *, sig_invalid_as_token=False, sha256_any_string=False, disposition_always=False):
    """Evaluate one case. The three keyword switches reproduce the alternative readings the README at 646588c
    left open (README, "Result"); the defaults are the readings stated in the README at 5a4ea06."""
    notes = []
    try:
        rec, keys, deleg = _validate_inputs(case, notes)
    except InputError as e:
        return _report("input_error", reasons=[str(e)])
    complete = case.get("trust_material_complete", False)   # -03 5.4.2: default is "not complete"

    if "acceptance" not in case:                              # README: no_record
        return _report("no_record", disposition="not_responded", notes=notes)

    env = case["acceptance"]
    # -- envelope: RFC 7515 7.2.2 flattened JSON serialization. README sentence 2: an encoding that is not
    # base64url without padding, or a protected header that is not a JSON object, is malformed
    # acceptance_member_invalid, found before the key step. The other envelope defects below (alg, kid,
    # crit, header, signatures, an absent member) carry the same condition: our reading, the README is silent.
    reasons = []
    hdr = None
    if not isinstance(env, dict):
        reasons.append("acceptance is not a JWS JSON object")
    else:
        for k in sorted(set(env) - ENVELOPE_MEMBERS - {"signatures"}):
            notes.append("jws_member_ignored:%s (RFC 7515 section 7.2.1)" % k)
        if "signatures" in env:
            reasons.append("signatures present: not the flattened syntax (RFC 7515 7.2.2)")
        for m in ("protected", "payload", "signature"):
            if m not in env:
                reasons.append("%s absent" % m)
            else:
                try:
                    raw = b64url_strict(env[m])
                except ValueError as e:
                    reasons.append("%s: %s" % (m, e))
                    continue
                if m == "protected":
                    try:
                        hdr = strict_json(raw.decode("utf-8"))
                        if not isinstance(hdr, dict):
                            raise ValueError("protected header is not a JSON object")
                    except (ValueError, UnicodeError) as e:
                        reasons.append("protected header: %s" % e)
                        hdr = None
        uhdr = env.get("header", {})
        if not isinstance(uhdr, dict):
            reasons.append("header is not a JSON object (RFC 7515 7.2.1)")
            uhdr = {}
        if hdr is not None:
            both = sorted(set(hdr) & set(uhdr))
            if both:
                reasons.append("header parameter(s) %s in both protected and header (RFC 7515 7.2.1: disjoint)" % both)
            if "crit" in uhdr:
                reasons.append("crit in the unprotected header (RFC 7515 4.1.11: protected header only)")
            jose = dict(uhdr)
            jose.update(hdr)                                 # RFC 7515 7.2.1: the JOSE Header is the union
            if jose.get("alg") != "EdDSA":
                reasons.append("alg is not EdDSA")
            if not isinstance(jose.get("kid"), str) or jose.get("kid") == "":
                reasons.append("kid absent, empty or not a string")
            if "crit" in hdr:
                reasons.append("crit present: this checker understands no header extension (RFC 7515 4.1.11)")
            for k in sorted(set(jose) - HEADER_UNDERSTOOD - {"crit"}):
                notes.append("header_parameter_ignored:%s (RFC 7515 section 4)" % k)
            hdr = jose
    if reasons:
        return _report("malformed", ["acceptance_member_invalid"], notes=notes, reasons=reasons)

    # -- key step, -03 5.4.2; README sentences 4 and 9: a small-order or mixed-order key resolves to nothing
    kid = hdr["kid"]
    if keys.get(kid) is None:
        return _report("key_unresolved", key_step="key_unresolved", policy_refusal=bool(complete), notes=notes)
    pub = keys[kid]
    signing_input = (env["protected"] + "." + env["payload"]).encode("ascii")
    if not ed.verify(pub, signing_input, b64url_strict(env["signature"])):
        if sig_invalid_as_token:
            return _report("signature_invalid", key_step="signature_invalid", notes=notes)
        return _report("malformed", ["signature_invalid"], key_step="signature_invalid", notes=notes)
    key_step = "signature_verified"

    # -- payload
    try:
        pl = strict_json(b64url_strict(env["payload"]).decode("utf-8"))
        if not isinstance(pl, dict):
            raise ValueError("payload is not a JSON object")
    except (ValueError, UnicodeError) as e:                   # README sentence 2, found after the key step
        return _report("malformed", ["acceptance_member_invalid"], key_step=key_step, notes=notes,
                       reasons=["payload: %s" % e])

    conds, reasons = [], []
    if pl.get("acceptance_version") != VERSION:                # README sentence 3 (report-all: our reading)
        conds.append("acceptance_member_invalid")
        reasons.append("acceptance_version absent, not a string, or not %r" % VERSION)
    for k in sorted(set(pl) - PAYLOAD_MEMBERS):                # README sentence 1
        notes.append("acceptance_member_ignored:%s" % k)

    def typed_sha(name):
        v = pl.get(name)
        ok = isinstance(v, str) if sha256_any_string else is_hex64(v)
        if not ok:
            conds.append("acceptance_member_invalid")
            reasons.append("%s absent or not 64 lowercase hex" % name)
        return ok

    terms_ok = typed_sha("terms_sha256")
    outcome_ok = typed_sha("outcome_sha256")
    record_ok = typed_sha("accepted_record_sha256")

    at_ok = canonical_ts(pl.get("accepted_at"))
    if not at_ok:
        conds.append("acceptance_member_invalid")
        reasons.append("accepted_at absent or not in canonical form")
    out_ok = canonical_ts(rec["outcome_at"])                  # README 0abf726 sentence 5: a string of another
    if not out_ok:                                            # form is ill-typed, found after the key step
        conds.append("acceptance_member_invalid")
        reasons.append("accepted_record.outcome_at not in canonical form")

    disp = pl.get("disposition")
    disp_ok = disp in DISPOSITIONS_SIGNED and isinstance(disp, str)
    if not disp_ok:
        conds.append("acceptance_member_invalid")
        reasons.append("disposition absent, not_responded, or not one of accepted/rejected/disputed")

    cp = pl.get("confirming_party")
    cp_ok = False
    if cp is None or cp == "":
        conds.append("confirming_party_absent")
    elif not isinstance(cp, str):
        conds.append("acceptance_member_invalid")
        reasons.append("confirming_party is not a string")
    else:
        cp_ok = True

    # acceptance_signer_is_issuer, README A5 (any one of three)
    issuer_pub = keys.get(rec["issuer_kid"])                 # None if absent or unusable
    same_key = kid == rec["issuer_kid"] or (issuer_pub is not None and issuer_pub == pub)
    same_party = cp_ok and cp == rec["issuer"]
    delegated_to_issuer = kid in deleg.get(rec["issuer"], [])
    if same_key or same_party or delegated_to_issuer:
        conds.append("acceptance_signer_is_issuer")

    if terms_ok and pl["terms_sha256"] != rec["terms_sha256"]:
        conds.append("acceptance_terms_digest_mismatch")
    if outcome_ok and pl["outcome_sha256"] != rec["outcome_sha256"]:
        conds.append("acceptance_outcome_digest_mismatch")
    if at_ok and out_ok and pl["accepted_at"] < rec["outcome_at"]:   # both canonical: bytewise = chronological
        conds.append("acceptance_precedes_outcome")
    if record_ok and pl["accepted_record_sha256"] != hashlib.sha256(jcs_string_object(rec)).hexdigest():
        conds.append("acceptance_record_digest_mismatch")

    if conds:
        return _report("malformed", conds, disposition=(disp if disposition_always and disp_ok else None),
                       key_step=key_step, notes=notes, reasons=reasons)

    if kid not in deleg.get(cp, []):                          # README A6
        return _report("unknown", ["acceptance_authority_unresolved"], disposition=disp, key_step=key_step,
                       notes=notes)
    return _report("verified", disposition=disp, key_step=key_step, notes=notes)


def _quiet(stream):
    """Point the descriptor BEHIND `stream` at the null device, so that the bytes the stream still buffers cannot fail
    again at the interpreter's own flush at exit (that second failure is what turned the exit code into 120). The
    descriptor is taken from the stream itself, never from a fixed number: with fd 1 closed at start, the number 1 may
    by now belong to a file this process opened for another purpose."""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):          # no descriptor behind it: nothing buffered in the OS sense
        return
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except OSError:
        pass


def _say(text):
    """Write text to stderr (line-buffered or unbuffered from Python 3.9 on, so a line ending in a newline is
    written at once); if stderr is closed or fails, give up without raising."""
    err = sys.stderr
    try:
        if err is None:
            return
        err.write(text)
    except (OSError, ValueError):
        _quiet(err)


def _wait_writable(buf):
    """stdout is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow,
    not gone). `select` is interruptible and retried by Python itself (PEP 475). The descriptor is asked for only
    here: a byte stream with no descriptor (an io.BytesIO under a TextIOWrapper, as pytest's capsys) never blocks."""
    import select
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:                      # no descriptor, or one select cannot wait on: report
        raise OSError("stdout is non-blocking and cannot be waited for: %s" % e)


def _text_layer_bytes(out, buf, text):
    """The bytes Python's own stdout text layer writes for `text` as the first thing written: its encoding and error
    handler, "\\n" as os.linesep where the platform translates it (not Linux; not measured here), and a byte order mark
    only where that layer puts one -- utf-16 / utf-32 only on a stdout seekable at offset 0 (a file), utf-8-sig on a
    pipe too, none on a seekable stdout past offset 0 (measured on 3.9, 3.11 and 3.13, 13/10/2026)."""
    import codecs
    if os.linesep != "\n":                                   # the text layer translates "\n" on such platforms
        text = text.replace("\n", os.linesep)
    encoding = out.encoding or "utf-8"
    enc = codecs.getincrementalencoder(encoding)(out.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")):
        enc.setstate(0)                                      # no byte order mark
    return enc.encode(text, final=True)


def _write_receipt(text):
    """Write the whole receipt to stdout and flush it; raise OSError if it did not all get there.

    The bytes go to sys.stdout.buffer in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw
    FileIO, whose write() can be short (a file size limit, a reader that went away) or return None (a non-blocking
    pipe that is full) without raising, and the text layer drops the rest in silence. A non-blocking stdout is
    waited for, not given up on. The bytes are the ones the text layer would write as the first thing written (its
    encoding and error handler, its newline translation where the platform has one, a byte order mark only where that
    layer writes one), so a receipt on a file or a pipe is byte for byte the same. In process two cases differ: after
    anything already written to a utf-8-sig pipe (the caller's text, an earlier receipt) the receipt carries a second
    one, and on a file whose offset something else moved after the text layer was made (stderr sharing that file) it
    carries none where that layer would write one."""
    out = sys.stdout
    if out is None:
        raise OSError("stdout is closed")
    try:
        out.flush()
        buf = getattr(out, "buffer", None)
        if buf is None:                                      # an in-process text stream (StringIO): no bytes below it
            out.write(text)
            out.flush()
            return
        data = memoryview(_text_layer_bytes(out, buf, text))
        while data:
            try:
                n = buf.write(data)
                waited = False
            except BlockingIOError as e:                     # buffered stdout on a full non-blocking pipe: part taken
                n = e.characters_written
                waited = True
            if n is None:                                    # raw stdout on a full non-blocking pipe: nothing taken
                n, waited = 0, True
            if n < 0 or n > len(data) or (n == 0 and not waited):
                raise OSError("short write: %d bytes not written" % len(data))
            data = data[n:]
            if data and waited:
                _wait_writable(buf)
        while True:
            try:
                buf.flush()
                return
            except BlockingIOError:
                _wait_writable(buf)
    except ValueError as e:                                  # I/O operation on closed file, or text it cannot encode
        raise OSError(str(e))


def main(argv):
    if len(argv) != 2:
        _say("usage: acceptance_check.py CASE.json\n")
        return 3
    try:
        fd = os.open(argv[1], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):        # checked on the descriptor, before any read: the
                raise ValueError("not a regular file")        # reason never names a descriptor number
        except BaseException:
            os.close(fd)
            raise
        with os.fdopen(fd, "rb") as f:
            case = strict_json(f.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeError) as e:
        rep = _report("input_error", reasons=["cannot read case: %s" % e])
    else:
        rep = check(case)
    try:
        _write_receipt(json.dumps(rep, indent=1, sort_keys=True) + "\n")
    except OSError as e:
        _quiet(sys.stdout)
        _say("receipt not written: %s\n" % e)
        return EXIT_RECEIPT_NOT_WRITTEN
    return rep["exit"]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
