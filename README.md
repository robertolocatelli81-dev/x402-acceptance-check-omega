# x402-acceptance-check-omega

A third implementation of the acceptance-record conditions discussed in
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4), checked against the vectors in
[babyblueviper1/preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance/tree/d750291/examples/acceptance-record-cold)
(`vectors.json` at `d750291`, 27 vectors, sha256 `4d01f3e72bdcbcca9e3e2a883ced0a87ae6c969f5cf6de4ef754dc63eb8ced0e`;
also the 25 vectors at `646588c` and `5a4ea06`, the same bytes, sha256
`c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0`; and, since 2026-10-12, the 46 vectors at
`536681b`, sha256 `464ee7933a17c3ab52db32b93ac21f555a026781f4a8a132b91977eb4fb02882`: 45/46, the one disagreement
being `acc-complete-not-boolean`, sentence 8 below, a choice of ours). The checker and its tests use the Python 3 standard library only; the
`cryptography` package is used, when installed, only by the optional cross-checks in `test_ed25519.py` and
`confronto_cryptography.py`.

## Written from

- the condition table posted in tsc#4 on 2026-10-04 and the replies of 2026-10-05;
- the README of `examples/acceptance-record-cold` at `5a4ea06` and at `646588c`;
- draft-krausz-verification-state-03, Sections 5.3.2, 5.4.1 and 5.4.2;
- RFC 8032, Section 5.1 (Ed25519) and the Section 7.1 test vectors;
- since 2026-10-12: the README of `examples/acceptance-record-cold` at `90b5032` (the section "Inputs the vectors
  do not yet pin", sentences 1-4, and "Changes between versions"), and RFC 7515, Sections 4.1.11, 7.2.1 and 7.2.2;
- since 2026-10-12, later the same day: that README at `0abf726` (sentences 5-8, the sentence-8 table and "Changes
  between versions") and the 46 vectors at `536681b`.

While this checker was written (2026-10-11), only the README and `vectors.json` of
`examples/acceptance-record-cold` were opened in that repository: not the reference checker
(`tools/acceptance_record_check.py`, `tools/_ed25519.py`), not `build_vectors.py` or `run_vectors.py`, and no
code of [actaseal/x402-acceptance-check-cold](https://github.com/actaseal/x402-acceptance-check-cold).
Before that, for other work in the same repository (we contributed vectors to `examples/x402-payment-fingerprint`),
we had read other files there, among them `tools/_rfc8785.py` (2026-10-06), the RFC 8785 module of that
repository, and `tools/evidence_set_check.py` (2026-10-06/07).

For the 2026-10-12 changes, only the README at `90b5032` (which includes its changelog) was read in that
repository; the reference checker's code (`tools/acceptance_record_check.py`, `tools/_ed25519.py`), changed in the
same commits, was not opened, and no code of actaseal was opened. Both checkers were, however, run as black boxes
before these changes: on 2026-10-12 we ran the reference (at `e2d896b`) and actaseal's (at `b06ca87`) on inputs of
ours and posted what they return on tsc#4; among them an extra `header: {}` member, which both return `verified`. The
reading of `header` below was chosen after seeing that.

`PREREG.md` (Italian) was written before the checker. This repository's history starts after both, so that
order, and the dates above, are our statement and not something the history shows.

**Not independent on three points.** The README at `5a4ea06` already states the three readings that came out
of actaseal's comparison (how `signature_invalid` surfaces, what a well-typed `*_sha256` is, when `disposition`
is reported), and this implementation was written after reading it.

## Result

`python3 fetch_sources.py && python3 misura_vettori.py fonti/d750291_vectors.json`:
27/27 vectors agree on every pinned field (result 27/27, conditions 27/27, disposition 7/7, key_step 6/6,
policy_refusal 1/1), on Python 3.9.25, 3.11.2 and 3.13.15. Condition lists compare as sets. On the 25 vectors at
`646588c`: 25/25. `vectors.json` at `90b5032` has the same bytes as at `d750291` (sha256 `4d01f3e7…ed0e`).

With the three points read the other way (`--variant sig --variant sha --variant disp`): 23/27, on
`acc-signature-invalid`, `acc-signature-invalid-declared-complete`, `acc-signature-invalid-one-byte-flipped` and
`acc-illtyped-digest-suppresses-mismatch` (22/25 at `646588c`). A checker that always answers
`verified`/`accepted` (`--always-accept`) gets 3/27 on the same runner (3/25 at `646588c`).

`python3 misura_vettori.py fonti/536681b_vectors.json` (46 vectors, sentences 5, 6 and 8 among them): 45/46 (result
45/46, conditions 46/46, disposition 8/8, key_step 11/12, policy_refusal 2/3) on Python 3.9.25, 3.11.2 and
3.13.15. The one disagreement is `acc-complete-not-boolean`: `trust_material_complete: "true"` is `input_error`
here, where the vector expects `key_unresolved` with `policy_refusal: null` (sentence 8 leaves that choice to the
relying party, and the README's table at `0abf726` records it for this checker). At `951d4fe`, before the
sentence-5 change below, it was 44/46: `acc-outcome-at-no-fraction` was `input_error` too.

The 27 vectors do not exercise the four sentences of 2026-10-12: this version and `fd88fbb` both give 27/27.
`test_piccolo_ordine.py` and the rows of `test_generativi.py` marked "sentence" do: both files fail on `fd88fbb`
(11 of the 14 "sentence" rows; the version rows `null`, `0` and a list were already malformed there).

## Run

```
python3 fetch_sources.py           # downloads four vector files, four READMEs, RFC 7515, RFC 8032 and the draft into fonti/, checks sha256
python3 misura_vettori.py fonti/d750291_vectors.json
python3 misura_vettori.py fonti/536681b_vectors.json   # 45/46: acc-complete-not-boolean is input_error here (sentence 8)
python3 acceptance_check.py CASE.json    # one case; exit 0 verified, 2 unknown/key_unresolved/no_record,
                                         # 1 malformed, 3 input outside the grammar,
                                         # 74 receipt not written whole to stdout (any verdict; a non-blocking
                                         #    stdout that is full is waited for, not reported, on POSIX;
                                         #    on Windows select waits only on sockets, so there a full
                                         #    non-blocking pipe would be 74 -- not measured)
python3 test_generativi.py && python3 test_nemesis.py && python3 test_ed25519.py && python3 test_piccolo_ordine.py
python3 test_frase5.py               # sentence 5: outcome_at of another form is malformed, after the key step
python3 test_ricevuta.py             # the receipt is written whole, or exit 74 (real processes, no mocks)
python3 controlli.py                 # positive controls: altered vectors, source mutants
python3 mutanti_v2.py                # mutants of the lines changed on 2026-10-12, against the whole suite
python3 mutanti_ricevuta.py          # mutants of the lines that write the receipt, against test_ricevuta.py
```

## Inputs the README now settles (2026-10-12)

The README at `90b5032` adopted four sentences under "Inputs the vectors do not yet pin"; this checker follows them:

1. a member of the signed acceptance other than the seven is ignored (listed in `notes` as
   `acceptance_member_ignored:<name>`);
2. `protected`, `payload` or `signature` not base64url without padding, or a protected header or payload that does
   not decode to a JSON object, is malformed `acceptance_member_invalid`; an undecodable encoding or protected
   header is found before the key step, a payload that is not a JSON object after it;
3. `acceptance_version` absent, not a string, or other than `acceptance-record-v0` is malformed
   `acceptance_member_invalid`;
4. a small-order key in the trust material (any of the 8 points whose order divides 8) gives `key_unresolved`,
   with `policy_refusal: true` if the trust material was declared complete; a signature whose `R` is a small-order
   point is `signature_invalid`.

The README at `0abf726` added sentences 5-8 the same day. Measured here on 2026-10-12 (Python 3.9, 3.11, 3.13):

5. a timestamp, `accepted_at` in the acceptance and `outcome_at` in the supplied record, is `YYYY-MM-DDTHH:MM:SS.mmmZ`
   exactly, and any other spelling is malformed `acceptance_member_invalid`, found after the key step; ordering
   (`acceptance_precedes_outcome`) is compared only between two values of that form. Followed since the commit after
   `951d4fe` for `outcome_at` (it was `input_error`: see Changes); `accepted_at` already was. `test_frase5.py` holds
   it: 420 checks, 402 of them failing at `951d4fe`;
6. a protected header whose `alg` is not `EdDSA` (even over a valid Ed25519 signature), or whose `kid` is absent or
   not a string, is `acceptance_member_invalid` found before the key step: what this checker already returned
   (measured on the three cases: `key_step` is `null`). A `kid` that is the empty string is not in sentence 6 and
   stays our reading below;
7. a payload that is valid JSON but not canonical verifies (measured: members in reverse order, indented), and
   `confirming_party` is compared byte-exact, so `" "` is a party name and the authority step decides it (measured:
   `unknown`, `acceptance_authority_unresolved`);
8. not followed: `trust_material_complete` other than the JSON value `true`, and a `kid` listed twice in the trust
   material, are `input_error` here, as before. Sentence 8 names this as the relying party's choice and the
   README's table at `0abf726` records it for this checker.

## Readings of ours

Up to `fd88fbb` three readings here were ours: an unknown payload member was malformed `acceptance_member_unknown`,
an unparseable envelope was malformed `acceptance_envelope_invalid`, an unsupported `acceptance_version` was
`unknown` (`acceptance_version_unsupported`). The README now decides all three (sentences 1-3 above), and those
three names are gone from the checker.

Where the texts are still silent, the choices are ours and no vector pins them:

- the other envelope defects (`alg` not `EdDSA`, `kid` absent, empty or not a string, `crit` present, one of
  `protected`/`payload`/`signature` absent, `acceptance` not a JSON object) are malformed `acceptance_member_invalid`,
  found before the key step, as in sentence 2;
- the JWS object follows RFC 7515 Section 7.2.2: an unprotected `header` (a JSON object) is accepted and its
  parameters join the JOSE Header (Section 7.2.1, union, names disjoint), `crit` there is refused (Section 4.1.11),
  `signatures` is refused (Section 7.2.2), and other members are ignored and listed in `notes` (Section 7.2.1);
- the protected header and the payload are read strictly: duplicate member names and a lone surrogate (RFC 7493), a
  byte order mark and `NaN`/`Infinity` (RFC 8259), and nesting deeper than 64 levels (our limit) make them not decode
  to a JSON object, so sentence 2 applies;
- an `x` that is not unpadded base64url or not 32 octets is `input_error`;
- a timestamp (`accepted_at`, `outcome_at`) is `YYYY-MM-DDTHH:MM:SS.mmmZ` as sentence 5 writes it, and this
  checker also asks for a valid instant, what -03 Section 5.3.2 asks of `retrieved_at` (month 01-12, a day that
  exists in that month and year, hour 00-23, minute 00-59, second 00-59, no second 60), and reads the `T` and `Z` of
  the form as upper-case (-03 itself does not state the case; RFC 3339 Section 5.6 allows `t` and `z`). Either one
  of another spelling makes the acceptance malformed `acceptance_member_invalid`, found after the signature is
  checked (`key_step` `signature_verified`). An `outcome_at` that is not a string at all is `input_error`, with every
  other non-string member of the supplied record (the grammar below).

Two choices follow a text rather than our reading: with `acceptance_version` wrong, the other malformed conditions are
still reported (the README's report-all, "Evaluation order" step 2); a trust-material `x` of 32 octets that does not
decode (RFC 8032 Section 5.1.3, the non-canonical encodings of the small-order points among them) gives
`signature_invalid`, because RFC 8032 Section 5.1.7 step 1 makes the signature invalid when the public key does not
decode.

Where we know that the reference checker at `90b5032` answers otherwise (run as a black box on 2026-10-12, not
read): a `kid` that is the empty string (`key_unresolved` there), `crit` in the protected header, a `header` member that
is not an object, overlaps the protected header, holds `crit`, or a `signatures` member (`verified` there), `alg` and
`kid` only in `header` (malformed there), and a payload with a duplicate member, a lone surrogate, a byte order mark,
`NaN` or deep nesting (`verified` there, the last duplicate taken).

Input of the relying party outside the grammar is `input_error`, exit 3, not one of the five result tokens. It is
checked before the acceptance is read, so no signature is checked. These are all the cases in the code:

- the case file cannot be read, is not a regular file, is not UTF-8, or is not strict JSON (a duplicate member name,
  a lone surrogate, a byte order mark, `NaN`/`Infinity`/`-Infinity`, nesting deeper than 64 levels), or the case is
  not a JSON object;
- a case member other than `acceptance`, `accepted_record`, `delegation`, `trust_material` and
  `trust_material_complete`;
- `accepted_record` absent or not an object; a member of it other than `issuer`, `issuer_kid`, `terms_sha256`,
  `outcome_sha256`, `outcome_at` and `record_id`; one of the first five absent; a member that is not a string;
  `terms_sha256` or `outcome_sha256` not 64 lowercase hex characters; `issuer`, `issuer_kid` or a present
  `record_id` empty;
- `trust_material_complete` present and not a boolean (`"true"` included);
- `trust_material` not exactly `{"keys": [...]}`; a key that is not an object, not `kty` `OKP` with `crv`
  `Ed25519`, or whose `kid` is absent, empty or not a string; two keys with the same `kid`; an `x` that is absent,
  not a string, not unpadded base64url (padding, another alphabet, non-zero trailing bits) or not 32 octets;
- `delegation` not an object; a party that is the empty string, or whose value is not a list of non-empty strings,
  or lists a `kid` twice;
- an `acceptance` without `trust_material` or without `delegation`.

JSON numbers are never converted, so the verdict does not depend on `PYTHONINTMAXSTRDIGITS`.

## Not covered

ES256 and the compact serialization; verification of the accepted record itself; RFC 8785 numbers (the record
holds strings only). Ed25519 here is not constant time and uses the cofactorless equation that RFC 8032 Section
5.1.7 allows. Keys and `R` of small order are refused (README sentence 4; RFC 8032 does not require it); keys of
mixed order (a large-order point plus a small-order one) are not refused, as neither text asks for it.

## Changes

**2026-10-12 (after `951d4fe`): the receipt on a non-blocking stdout, the reason on a directory.** Three
changes to how the receipt is written, none to a verdict: (1) a non-blocking stdout that is full (a pipe whose
`O_NONBLOCK` flag this process inherited, read late) is now waited for with `select` (on POSIX; on Windows `select` waits only on sockets, so there a full non-blocking
pipe would be reported as 74 -- not measured), as a blocking write would be,
and the receipt arrives whole with the verdict's exit code; at `951d4fe` the write stopped at the first `EAGAIN`,
65 536 of the 168 177 bytes of the large `verified` receipt had reached the pipe and the exit was 74, and with a
pipe never read the exit was 74 too, where the checker now waits (measured: still waiting after 1.5 s, like `cat`).
(2) The receipt goes to `sys.stdout.buffer` only when there is one: a program that calls `main()` with
`sys.stdout` set to a text stream without `.buffer` (a `StringIO`) gets the receipt through that stream (at
`951d4fe`: `AttributeError`, exit 1), and one whose `.buffer` has no descriptor (a `TextIOWrapper` over an
`io.BytesIO`, as pytest's `capsys`) gets it through that buffer, as at `951d4fe`: the descriptor is asked for only
when a non-blocking stdout must be waited for. (3) The `input_error` reason for a case path that is not a regular file is
`cannot read case: not a regular file`; at `951d4fe` the check came after the descriptor was wrapped, and the reason
named the descriptor number (`[Errno 21] Is a directory: 3`, or `2` with stderr closed), so the receipt depended on
which descriptor was free. On POSIX nothing else in the bytes changes; where the platform's text layer translates
`\n` the bytes now follow `os.linesep`, as `print` did (not measured: Linux only here). After a failed write the
descriptor pointed at the null device is the one behind the stream object, never the number 1 or 2 (with fd 1
closed at start, that number can belong to a file this process opened). `test_ricevuta.py` also checks a pipe
already full when the checker starts (the full pipe is then met at the flush) and that the checker sleeps while it
waits (CPU time under 0.6 s in 1.5 s); it fails 17 checks at `951d4fe` (the non-blocking cases with and without
`PYTHONUNBUFFERED`, the `StringIO` case on three inputs, the directory reason with and without stderr) and 390 at
`0496d58`, none now, on Python 3.9, 3.11 and 3.13; `mutanti_ricevuta.py` kills 25/25 on Python 3.11 (new: giving up
on `EAGAIN` at the write or at the flush, waiting by spinning instead of `select` in three places, no `StringIO`
fallback, the descriptor asked for before writing, the regular-file check after wrapping the descriptor). The 77 receipts of `fonti/` written
to a file are byte-identical to `0496d58`; of the six `input_error`/usage cases, only the directory differs, as
said.

**2026-10-12 (after `951d4fe`): sentence 5, `outcome_at`.** An `outcome_at` of another spelling than
`YYYY-MM-DDTHH:MM:SS.mmmZ` was `input_error` (exit 3, no signature checked), a reading of ours; the README at
`0abf726` (sentence 5) makes it malformed `acceptance_member_invalid`, found after the key step, and this checker
now follows it: with a valid signature the result is `malformed` with `acceptance_member_invalid` (exit 1,
`key_step` `signature_verified`), with an invalid signature `signature_invalid`, with an unresolved key
`key_unresolved`, with no acceptance in the case `no_record` (at `951d4fe`: `input_error` there too), and `acceptance_precedes_outcome` is compared only between two canonical values. `accepted_at`
was already so. A non-string `outcome_at` stays `input_error`. The 46 vectors at `536681b`: 44/46 at `951d4fe`,
45/46 now, the remaining disagreement being sentence 8 (above). `test_frase5.py` (19 table rows and a 400-value
sweep, 420 checks) fails 402 at `951d4fe` and passes now, on Python 3.9, 3.11 and 3.13; the row
`record-outcome-at-bad` of `test_generativi.py` now expects `acceptance_member_invalid` with
`acceptance_record_digest_mismatch` (the record changed, so its digest did, A4). The 27 vectors give 27/27 before
and after, and the receipts of the 77 cases of `fonti/` written to a file have the same bytes and exit codes
before and after. Sentences 6 and 7 were measured and already held; sentence 8 is not followed (above).
`fetch_sources.py` pins the README at `0abf726` and the vectors at `536681b`.

**2026-10-12 (after `0496d58`): exit 74 when the receipt is not written.** If the receipt cannot be written whole to
stdout (stdout closed, a full device, a file size limit, a reader that has gone away; a non-blocking pipe that is
full too, until the entry above), the exit code is now 74 (`EX_IOERR` of sysexits.h) whatever the verdict, also with `-u` or
`PYTHONUNBUFFERED` (stdout is then a raw file whose writes can be short without an error, so the receipt is written
in a loop that checks the count), and one line `receipt not written: <reason>` is tried on stderr; if stderr fails
too, the exit code is still 74, with no traceback. At `0496d58`, measured on Python 3.9, 3.11 and 3.13: with stdout
closed (`>&-`) the exit code was 1, the code of `malformed`, with an `AttributeError` traceback, also on a `verified`
case; with stdout on `/dev/full` or on a pipe whose reader had closed it was 120 (the interpreter's own flush at
exit) for the receipts of a few hundred bytes, and 1 with a traceback for a `verified` receipt of 168 177 bytes; a
usage error with stderr closed exited 1 instead of 3. Verdicts and receipts are unchanged: the receipts written to a
file for the 77 cases of `fonti/` (27 at `d750291`, 25 at `646588c`, 25 at `5a4ea06`) have the same bytes and exit
codes before and after on all three versions, and the 27 vectors give 27/27. `test_ricevuta.py` fails on `0496d58`
(383 failed checks with the `test_ricevuta.py` of that commit; the file has changed since, see the
entry above) and passes now; `mutanti_ricevuta.py` kills 17/17 mutants of the new lines. With
`PYTHONUNBUFFERED=1` and a file size limit of 4096 bytes (`ulimit -f 4`), the `verified` receipt of 168 177 bytes
was cut to 4096 bytes with exit 0 at `0496d58`; now it exits 74.

**2026-10-12 (after `fd88fbb`).** The defect reported on x402-foundation/tsc#4 was in this checker too. At
`fd88fbb`, with the neutral point as the confirming party's key in the trust material, the signature `R` = neutral
point, `S` = 0 verified for every message, so a forged acceptance came out `verified`; with the other small-order
keys a forgery with `S` = 0 exists for some messages (`R` searched among the 8 small-order points): measured on 48
key/payload pairs, 34 forged acceptances were `verified` at `fd88fbb`. A signature with `R` = neutral point made by
the holder of a real key (`S` = k·a mod L) was also `verified`. We found it on 2026-10-12 and reported it on tsc#4, where
it held for all three checkers. Sentences 1-3 were proposed there by us, so on them this checker follows a text
we wrote. Now: small-order keys give `key_unresolved` and small-order
`R` gives `signature_invalid` (sentence 4); unknown signed members are ignored (sentence 1); envelope and version
defects are `acceptance_member_invalid` (sentences 2 and 3); the JWS object follows RFC 7515 Section 7.2.2 (a
`header` member was malformed before); a 32-octet key that does not decode gives `signature_invalid` (RFC 8032
Section 5.1.7 step 1; it was `input_error`). The 27 vectors give 27/27 before and after.

## License

Licensed under either of the MIT License ([LICENSE-MIT](LICENSE-MIT)) or the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)), at your option. SPDX: `MIT OR Apache-2.0`.

The vectors (CC0-1.0, in a repository under the MIT License), RFC 8032 and the draft are not redistributed here:
`fetch_sources.py` downloads them and checks the pinned sha256 values.
