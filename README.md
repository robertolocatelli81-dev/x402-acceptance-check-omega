# x402-acceptance-check-omega

A third implementation of the acceptance-record conditions discussed in
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4), checked against the vectors in
[babyblueviper1/preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance/tree/d750291/examples/acceptance-record-cold)
(`vectors.json` at `d750291`, 27 vectors, sha256 `4d01f3e72bdcbcca9e3e2a883ced0a87ae6c969f5cf6de4ef754dc63eb8ced0e`;
also the 25 vectors at `646588c` and `5a4ea06`, the same bytes, sha256
`c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0`; and, since 2026-10-12, the 46 vectors at
`536681b`, sha256 `464ee7933a17c3ab52db32b93ac21f555a026781f4a8a132b91977eb4fb02882`: 45/46, the one disagreement
being `acc-complete-not-boolean`, sentence 8 below, a choice of ours; since 2026-10-13, the 50 vectors at `9d4cf2c`,
sha256 `c5d0a142cf22b1cfff366fb1b6689de0b0d88ba0ad5cf846db9027204f0c138a`: 49/50, the same one disagreement). The checker and its tests use the Python 3 standard library only; the
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
  between versions") and the 46 vectors at `536681b`;
- since 2026-10-13: that README at `9d4cf2c` (sentence 9 and its "Changes between versions" entry) and the 50 vectors
  at `9d4cf2c`; the 12 cases of `cases.txt` of
  [novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck/blob/65519336fda78a3d016e947df6d82848aca0c9da/cases.txt)
  at `6551933` ("Taming the many EdDSAs", Apache-2.0), read as data, sha256
  `db14ccd6953ffa79c81586da8f4ab41dd893f7efd07af97d027a27c179b3ab6b`.

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

`python3 misura_vettori.py fonti/9d4cf2c_vectors.json` (50 vectors, the three of sentence 9 among them): 49/50 (result
49/50, conditions 50/50, disposition 8/8, key_step 14/15, policy_refusal 2/3) on Python 3.9.25, 3.11.2 and 3.13.15;
the one disagreement is `acc-complete-not-boolean` (sentence 8, as above). At `6a137d0`, before sentence 9, it was
47/50: `acc-mixed-order-key-accepted-by-both-equations` was `verified` and `acc-mixed-order-key-equations-disagree`
was malformed `signature_invalid`.

The 27 vectors do not exercise the four sentences of 2026-10-12: this version and `fd88fbb` both give 27/27.
`test_piccolo_ordine.py` and the rows of `test_generativi.py` marked "sentence" do: both files fail on `fd88fbb`
(11 of the 14 "sentence" rows; the version rows `null`, `0` and a list were already malformed there).

## Run

```
python3 fetch_sources.py           # downloads five vector files, five READMEs, speccheck's cases.txt, RFC 7515, RFC 8032 and the draft into fonti/, checks sha256
python3 misura_vettori.py fonti/d750291_vectors.json
python3 misura_vettori.py fonti/536681b_vectors.json   # 45/46: acc-complete-not-boolean is input_error here (sentence 8)
python3 misura_vettori.py fonti/9d4cf2c_vectors.json   # 49/50: the same one disagreement
python3 speccheck.py                 # the 12 cases of ed25519-speccheck through ed25519_rfc8032.verify, with the reason
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
python3 mutanti_v3.py                # mutants of the lines changed on 2026-10-13 (sentence 9), against the whole suite
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

The README at `9d4cf2c` added sentence 9 on 2026-10-13; quoted from it:

> 9. A key in the trust material that is a mixed-order point (neither small-order nor in the prime-order subgroup: `[L]A` is not the identity, `L` the group order) is not a key of the confirming party: the result is `key_unresolved`, as in sentence 4. A signature whose `R` is a mixed-order point is `signature_invalid`. Whether a signature under such a key, or with such an `R`, verifies depends on whether the verifier uses the cofactorless (`[S]B = R + [k]A`) or the cofactored (`[8][S]B = [8]R + [8][k]A`) equation of RFC 8032 §5.1.7, so two conforming RFC 8032 verifiers can disagree on the same acceptance. Checking `[L]P` for the key and for `R` before verification removes that dependence. Vectors: `acc-mixed-order-key-accepted-by-both-equations` (a signature every RFC 8032 verifier accepts), `acc-mixed-order-key-equations-disagree`, `acc-mixed-order-r-real-key`. Reported by TKCollective's measurement table on x402-foundation/tsc#4 (2026-10-13, case 3: mixed-order `A` and `R` accepted by their guard and by the library).

This checker follows it since the commit after `6a137d0`: `ed25519_rfc8032.key_problem` returns `mixed-order point`
for a key that is not of small order and whose `[L]A` is not the neutral point (`L` the order of the base point, the
prime order of its subgroup), and the checker treats it as a small-order key (sentence 4): `key_unresolved`, with
`policy_refusal` equal to the completeness declaration, found at the key step, and listed in `notes` as
`trust_material_key_unusable:<kid>: mixed-order point`. `ed25519_rfc8032.verify` returns False when `A` or `R` is of
mixed order, before the equation. With the `A` check in place the `R` check cannot change what `verify` returns: if `A`
is in the subgroup of order `L` and the cofactorless equation holds, `R = [S]B - [k]A` is in that subgroup too; it is
kept because sentence 9 names `R`, and `mutanti_v3.py` lists that mutant as surviving.

## Ed25519 on the 12 cases of "Taming the many EdDSAs"

`python3 speccheck.py` runs the 12 cases of `cases.txt` (pinned above) through `ed25519_rfc8032.verify`, each on its
own message (the bytes of its hex, not a JWS signing input), as TKCollective ran them for tanilo-receipt-verify 0.2.1
([x402-foundation/tsc#4, 2026-10-13](https://github.com/x402-foundation/tsc/issues/4#issuecomment-6146209141)). The
reason is the first of `verify`'s own checks that refuses the case, computed by `speccheck.py` from the point
arithmetic, not read back from `verify`; the two columns of the equations of RFC 8032 Section 5.1.7 step 3 are
computed the same way. Positive control first: RFC 8032 Section 7.1 TEST 1 verifies and a copy with one bit of `S`
flipped does not. The last two columns are copied from TKCollective's comment (their measurement, cryptography 50.0.2
and OpenSSL 4.0.3; as they state, the 0.2.1 column is their guard followed, when it passed, by the library, not the
package's public `verify()`); we ran `cryptography` 50.0.1 with OpenSSL 4.0.2 on the same 12 cases and got the
same 12 results as their last column.

| Case | `A` | `R` | cofactorless / cofactored | `6a137d0` | now | reason now | tanilo-receipt-verify 0.2.1 | `cryptography` alone |
|---|---|---|---|---|---|---|---|---|
| 0 | small order | small order | holds / holds | rejects | rejects | small-order `A`, `R` (sentence 4) | rejected, `small_order_key` | accepts |
| 1 | small order | mixed order | holds / holds | rejects | rejects | small-order `A` (sentence 4) | rejected, `small_order_key` | accepts |
| 2 | mixed order | small order | holds / holds | rejects | rejects | small-order `R` (sentence 4) | rejected, `small_order_r` | accepts |
| 3 | mixed order | mixed order | holds / holds | **accepts** | rejects | mixed-order `A`, `R` (sentence 9) | **accepted** | accepts |
| 4 | mixed order | mixed order | fails / holds | rejects | rejects | mixed-order `A`, `R` (sentence 9); at `6a137d0` the cofactorless equation | rejected by the library | rejects |
| 5 | mixed order | prime order | fails / holds | rejects | rejects | mixed-order `A` (sentence 9); at `6a137d0` the cofactorless equation | rejected by the library | rejects |
| 6, 7 | prime order | prime order | holds / holds | rejects | rejects | `S` >= `L` (RFC 8032 5.1.7 step 1) | rejected, `signature_s_out_of_range` | rejects |
| 8, 9 | mixed order | `x` = 0 with the sign bit set | - | rejects | rejects | `R` does not decode (RFC 8032 5.1.3) | rejected, `small_order_r` | rejects |
| 10 | `x` = 0 with the sign bit set | mixed order | - | rejects | rejects | `A` does not decode (RFC 8032 5.1.3) | rejected, `small_order_key` | rejects |
| 11 | `x` = 0 with the sign bit set | mixed order | - | rejects | rejects | `A` does not decode (RFC 8032 5.1.3) | rejected, `small_order_key` | accepts |

Case 3 is the only case on which `6a137d0` and now differ: at `6a137d0` this verifier accepted it, as
tanilo-receipt-verify 0.2.1 does; now it is refused. On the other eleven the verdict is the same at `6a137d0`, now, and
in TKCollective's 0.2.1 column; the reasons differ on 8 to 11 (here the encoding is refused before any order is
computed) and on 4 and 5 (the library's equation there and at `6a137d0`, the order check now). `test_ed25519.py` asks
that none of the 12 verifies: it fails at `6a137d0` on case 3.

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
5.1.7 allows. Keys and `R` of small order (README sentence 4) and of mixed order (sentence 9) are refused; RFC 8032
requires neither. With both refused, `A` and `R` lie in the subgroup of order `L`, where the cofactorless and the
cofactored equation give the same result.

## Changes

**2026-10-13 (after `6a137d0`): sentence 9, mixed-order keys and `R`; what a cut bytecode cache does to an import.** (1) A trust-material
key of mixed order is now `key_unresolved` (sentence 9, as sentence 4; it was used as a key), and `verify` refuses a
mixed-order `A` or `R` (see "Inputs the README now settles"). The 50 vectors at `9d4cf2c`: 47/50 at `6a137d0`, 49/50
now, on Python 3.9, 3.11 and 3.13; the receipts written to a file for the 50 cases have the same bytes, stderr and
exit codes at `6a137d0` and now for 48 of them, on the three versions; the two that differ are
`acc-mixed-order-key-accepted-by-both-equations` (`verified`, exit 0, at `6a137d0`) and
`acc-mixed-order-key-equations-disagree` (malformed `signature_invalid`, exit 1), both now `key_unresolved`, exit 2.
`test_piccolo_ordine.py` (section 7 and the mixed-order rows of sections 1 and 2b) fails 29 of its 254 checks at `6a137d0`,
`test_ed25519.py` fails there on case 3 of ed25519-speccheck, `test_nemesis.py` on one check (a mixed-order key whose
signature satisfies the cofactorless equation: `verify` returned True), on the three versions; all pass now.
`mutanti_v3.py` kills 10/10 mutants of the new lines; one more, which drops the `R` check from `verify`, survives and
is equivalent (above). Two mutants of `mutanti_v2.py` became equivalent with this change and are listed as such there:
refusing as `R` only the neutral point, or only points whose order divides 4, among the small-order points; any other
small-order point `P` has `[L]P` different from the neutral point and is refused by the mixed-order check. The other
23 are killed. In `test_nemesis.py` the check that `k` is reduced mod `L` used a mixed-order key and now expects
False; with `A` of prime order, `[k]A = [k mod L]A`, so that reduction no longer shows in what `verify` returns.
(2) The bytecode cache, unchanged in the code: run as a command, the checker still sets `sys.dont_write_bytecode` and
points `sys.pycache_prefix` at `os.devnull`, so a `.pyc` of `ed25519_rfc8032` cut by CPython 3.9 or 3.11 (they write
it with one raw write; CPython fixed the writing side upstream in
[GH-126606](https://github.com/python/cpython/issues/126606), "don't write incomplete pyc files", backported to 3.12
as `df59b64589` and to 3.13 as `ad1b23bf29`) is not read when the checker runs as a command. Declared limit, measured
on Python 3.9, 3.11 and 3.13 with a `.pyc` cut to 1 024 bytes: a program that imports the checker reads that file
and exits 1 with `EOFError: marshal data too short`, with `-B` too (`-B` stops writing the cache, not reading it);
deleting `__pycache__`, or a `PYTHONPYCACHEPREFIX` that points elsewhere, is the remedy. `import acceptance_check`
under `ulimit -f 1` leaves two cut files of 1 024 bytes, the `.pyc` of `acceptance_check` and that of
`ed25519_rfc8032`, on Python 3.9 and 3.11 and none on 3.13 (measured). `test_ricevuta.py`
now also checks the import case, `-B`, and the two remedies; `mutanti_ricevuta.py` kills 38/38 on Python 3.11.
(3) `speccheck.py` and the table above are new; `fetch_sources.py` also pins the README and the vectors at `9d4cf2c`
and speccheck's `cases.txt`.

**2026-10-13 (after `acfad3d`): the byte order mark, the bytecode cache.** No verdict changes. (1) The receipt's bytes
are now those Python's own text layer writes there as the first thing written (encoding, error handler, and a byte
order mark only where that layer writes one). At `acfad3d` they came from `str.encode`: with `PYTHONIOENCODING` set
to `utf-16` or `utf-32` (or an alias) a pipe got a byte order mark (`ff fe 7b 00` where the text layer writes
`7b 00`), and so did a file whose offset was already past 0 when the checker started (opened for appending by a
program, as Python's `open(path, "ab")` does, or a shell group `{ printf x; checker; } > f`), for `utf-8-sig` too; on
a new file, and after a shell's `>>` (the offset is still 0 when Python starts, and the text layer too writes a byte
order mark in the middle of the file), the bytes were already the same. In process two cases still differ: after
anything already written to a `utf-8-sig` pipe (the caller's text, an earlier receipt) the receipt carries a second
byte order mark, and on a file whose offset something else moved after the text layer was made (stderr sharing that
file) it carries none where that layer writes one; the command has neither case. (2) Run as a command, the checker
sets `sys.dont_write_bytecode` and points `sys.pycache_prefix` at `os.devnull` before importing `ed25519_rfc8032`, so
it neither writes nor reads a bytecode cache. At `acfad3d`, from a copy without `__pycache__`, one run under
`ulimit -f 1` left a 1 024-byte `ed25519_rfc8032.cpython-39.pyc` (and `-311`), and every later run, with no limit,
exited 1 with `EOFError: marshal data too short` (Python 3.13 installed no cut file, but a cut file
put there makes it exit 1 as well); a file cut that way is now not opened. One written by a program that imports the
checker as a library is not covered, and such an import changes neither flag. `test_ricevuta.py` now compares the
receipt with the text layer's bytes (nine encodings, buffered and `-u`, pipe, new file, appended file, in process
four encoding spellings, and the `cp864` error handler on a reason with `%`) and runs the bytecode cases: it fails
22 checks at `acfad3d` on Python 3.9 and 3.11, 21 on 3.13, none now; `mutanti_ricevuta.py` kills 38/38 on Python
3.11 (13 new). The 47 vectors at `6eaf50c`: 46/47, as at `acfad3d` (the disagreement is
`acc-complete-not-boolean`), and their 47 receipts written to a file are byte-identical to `acfad3d`. Measured on
Linux, Python 3.9, 3.11 and 3.13, 13/10/2026.

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
