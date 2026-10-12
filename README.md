# x402-acceptance-check-omega

A third implementation of the acceptance-record conditions discussed in
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4), checked against the vectors in
[babyblueviper1/preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance/tree/d750291/examples/acceptance-record-cold)
(`vectors.json` at `d750291`, 27 vectors, sha256 `4d01f3e72bdcbcca9e3e2a883ced0a87ae6c969f5cf6de4ef754dc63eb8ced0e`;
also the 25 vectors at `646588c` and `5a4ea06`, the same bytes, sha256
`c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0`). The checker and its tests use the Python 3 standard library only; the
`cryptography` package is used, when installed, only by the optional cross-checks in `test_ed25519.py` and
`confronto_cryptography.py`.

## Written from

- the condition table posted in tsc#4 on 2026-10-04 and the replies of 2026-10-05;
- the README of `examples/acceptance-record-cold` at `5a4ea06` and at `646588c`;
- draft-krausz-verification-state-03, Sections 5.3.2, 5.4.1 and 5.4.2;
- RFC 8032, Section 5.1 (Ed25519) and the Section 7.1 test vectors.

While this checker was written (2026-10-11), only the README and `vectors.json` of
`examples/acceptance-record-cold` were opened in that repository: not the reference checker
(`tools/acceptance_record_check.py`, `tools/_ed25519.py`), not `build_vectors.py` or `run_vectors.py`, and no
code of [actaseal/x402-acceptance-check-cold](https://github.com/actaseal/x402-acceptance-check-cold).
Before that, for other work in the same repository (we contributed vectors to `examples/x402-payment-fingerprint`),
we had read other files there, among them `tools/_rfc8785.py` (2026-10-06), the RFC 8785 module of that
repository, and `tools/evidence_set_check.py` (2026-10-06/07).

`PREREG.md` (Italian) was written before the checker. This repository's history starts after both, so that
order, and the dates above, are our statement and not something the history shows.

**Not independent on three points.** The README at `5a4ea06` already states the three readings that came out
of actaseal's comparison (how `signature_invalid` surfaces, what a well-typed `*_sha256` is, when `disposition`
is reported), and this implementation was written after reading it.

## Result

`python3 fetch_sources.py && python3 misura_vettori.py fonti/d750291_vectors.json`:
27/27 vectors agree on every pinned field (result 27/27, conditions 27/27, disposition 7/7, key_step 6/6,
policy_refusal 1/1), on Python 3.9.25, 3.11.2 and 3.13.15. Condition lists compare as sets. On the 25 vectors at
`646588c`: 25/25.

With the three points read the other way (`--variant sig --variant sha --variant disp`): 23/27, on
`acc-signature-invalid`, `acc-signature-invalid-declared-complete`, `acc-signature-invalid-one-byte-flipped` and
`acc-illtyped-digest-suppresses-mismatch` (22/25 at `646588c`). A checker that always answers
`verified`/`accepted` (`--always-accept`) gets 3/27 on the same runner (3/25 at `646588c`).

## Run

```
python3 fetch_sources.py           # downloads the vectors, the two READMEs, RFC 8032 and the draft into fonti/, checks sha256
python3 misura_vettori.py fonti/d750291_vectors.json
python3 acceptance_check.py CASE.json    # one case; exit 0 verified, 2 unknown/key_unresolved/no_record,
                                         # 1 malformed, 3 input outside the grammar
python3 test_generativi.py && python3 test_nemesis.py && python3 test_ed25519.py && python3 controlli.py
```

## Readings of ours

Where the text is silent, the choices are ours and no vector pins them: an unknown payload member is
malformed `acceptance_member_unknown`; an envelope that cannot be parsed is malformed
`acceptance_envelope_invalid`; an unsupported `acceptance_version` is `unknown`
(`acceptance_version_unsupported`). These three condition names are proposals, not names from the tsc#4 table.
Input of the relying party outside the grammar (unknown members, no `trust_material` or no `delegation` next to
an acceptance, no `accepted_record`) is `input_error`, exit 3, not one of the five result tokens. JSON nested
deeper than 64 levels is refused; JSON numbers are never converted, so the verdict does not depend on
`PYTHONINTMAXSTRDIGITS`.

## Not covered

ES256 and the compact serialization; verification of the accepted record itself; RFC 8785 numbers (the record
holds strings only). Ed25519 here is not constant time, uses the cofactorless equation that RFC 8032 Section 5.1.7
allows, and does not reject keys of small order (RFC 8032 does not require it); keys come from the relying
party's trust material.

## License

Licensed under either of the MIT License ([LICENSE-MIT](LICENSE-MIT)) or the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)), at your option. SPDX: `MIT OR Apache-2.0`.

The vectors (CC0-1.0, in a repository under the MIT License), RFC 8032 and the draft are not redistributed here:
`fetch_sources.py` downloads them and checks the pinned sha256 values.
