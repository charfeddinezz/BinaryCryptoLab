# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-10-28

### Added

* **`binarycryptolab.script_templates`** - a total Bitcoin script parser and template
  classifier, plus redeem-script verification:
  * tokenizes pushes (direct, PUSHDATA1/2/4), small integers, and every opcode the
    templates use, with the byte offset of any truncation;
  * classifies P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, multisig (with threshold and
    full key list), HTLC (hash lock, algorithm, branches), CLTV/CSV timelocks (value
    and unit), OP_RETURN, and non-standard scripts;
  * `verify_script_claim` checks a caller-supplied script against a P2SH or P2WSH
    address by recomputing `HASH160` or `SHA256`, which turns the former "opaque
    script hash" warning into a byte-exact proof when the script is available.
* **`binarycryptolab.hd_keys`** - BIP-32 extended public keys:
  * parses `xpub`/`ypub`/`zpub`/`tpub`/`upub`/`vpub` (and the `Y`/`Z`/`U`/`V`
    multisig variants) with full structural validation;
  * derives non-hardened children and paths through **public** derivation only,
    refusing hardened indices with an explanation instead of an error code;
  * searches an index range for an address and reports the matching index;
  * refuses extended *private* keys without echoing them.
* **Exact prefix probability for every encoding** - `bech32_prefix_probability` and
  `cashaddr_prefix_probability` count constrained bits exactly, so the former
  "Base58Check only" refusal is gone. The Bech32 value coincides with `32^-k` (as it
  must, the alphabet is `2^5`); the CashAddr value differs by up to 8x because its
  8-bit version byte does not align with 5-bit groups.
* **`dissect-address --redeem-script`, `--xpub`, `--index-range`, `--stdin`** with
  matching text, JSON, and CSV output.
* Unregistered Base58 version bytes are now decoded and labelled `unknown` rather
  than refused, with the checksum still verified and an `unregistered_version` notice
  in the safety audit.
* 122 new tests (1318 total), including the published BIP-32 vectors and a
  125-of-125 agreement check between public and private derivation.

### Fixed

* BIP-32 child serialization used the parent chain code instead of the derived one.
  Caught by comparing against the published `m/0H/1` vector and an independent
  private-side derivation in the tests.

## [1.5.0] - 2026-10-28

### Added

* **`binarycryptolab.address_formats`** - one decoder for every accepted input:
  * Base58Check on Bitcoin, Bitcoin Cash (legacy), Litecoin, Dogecoin, Dash, and
    Zcash (two-byte prefixes), reporting **every** chain consistent with a version
    byte instead of inventing certainty;
  * Bech32 and Bech32m for any registered HRP (`bc`, `tb`, `bcrt`, `ltc`, `tltc`,
    `rltc`), in either case, with unknown HRPs decoded and labelled instead of
    rejected;
  * CashAddr (`bitcoincash:`, `bchtest:`, `bchreg:`) with a from-scratch checksum
    implementation, validated by re-encoding the published example back to itself;
  * BIP-21 payment URIs, with query parameters preserved and validated;
  * raw `scriptPubKey` input covering P2PKH, P2SH, P2WPKH, P2WSH, P2TR, witness
    versions 1-16, P2PK, OP_RETURN, and non-standard scripts (behind `script:`);
  * **WIF private keys are refused**, and the message never repeats the input.
* **`binarycryptolab.address_safety`** - an offline hazard audit graded
  `danger` / `review` / `no-known-hazard`: documented burn and genesis addresses,
  constant payloads, undefined witness versions (unencumbered, anyone can spend),
  malformed Taproot programs, NUMS output keys, off-curve Taproot keys, opaque
  script hashes, published public keys, OP_RETURN, non-standard scripts, test
  networks, ambiguous chains, and hostile BIP-21 amounts or `req-` parameters.
* **`binarycryptolab.utxo_audit`** - `audit-address-data` checks a UTXO export the
  caller supplies: script match, duplicate outpoints, value and supply bounds,
  spent entries, confirmed versus unconfirmed totals, and exact BTC formatting.
  The report always states `trusted: false` and that no network request was made.
* **Taproot derivation** - `derive_p2tr_address` applies the BIP-341 key-path tweak
  and is cross-checked against OpenSSL by deriving `(k + t) * G` for random keys,
  so a bug in the point arithmetic cannot pass unnoticed.
* **Per-type backward costs** - P2PKH/P2WPKH `2^288`, P2SH `2^160`, P2WSH `2^256`,
  Taproot `2^128` (no hash layer), P2PK `2^128`, undefined witness versions `2^0`,
  OP_RETURN unspendable.
* **Batch dissection** - several inputs, `--input-file`, CSV and JSON envelopes,
  per-item errors, and an aggregate summary by type, chain, and safety grade.
* **`dissect-address --public-key`** runs the controlled experiment inline,
  including Taproot key-path derivation.
* 164 new tests (1196 total), a new `docs/address_scenarios.md`, and an Arabic
  section in `docs/how_it_works_ar.md`.

### Changed

* `dissect-address` accepts zero or more positional inputs; a single address keeps
  the previous single-report output exactly.
* Bare hexadecimal that is not a recognised script is now rejected with guidance
  instead of being guessed at; `script:<hex>` forces script interpretation.

## [1.4.0] - 2026-10-28

### Added

* **`binarycryptolab.address_forensics`** - address dissection as a first-class
  input:
  * `dissect_address` decodes Base58Check, Bech32, and Bech32m, **recomputes** the
    checksum, and prints the exact locking script and its disassembly;
  * `PayloadProfile` reports bit length, leading zero bits, Hamming weight with an
    exact two-sided binomial p-value, distinct bytes, byte entropy, and nibble
    frequencies, and the seven-test randomness battery is reused on the payload
    with a Fisher combination and a Bonferroni verdict;
  * structural findings - `leading_zero_bits`, `hamming_weight`, `nibble_skew`,
    `constant_payload`, `palindromic_payload` - each with the probability of
    occurring by chance;
  * `AddressKnowledgeScale` reduces every fact to bits: the address fixes 160
    bits, leaves `2^96` candidate public keys, and fixes **zero** of the 256
    scalar bits. `recoverable` is always `False`;
  * `HardnessReport` prices the chain: `2^0` to the payload, `2^160` to a public
    key, `2^128` to the scalar, `2^288` in total, with the collision-versus-preimage
    distinction and Grover/Shor caveats stated explicitly;
  * `base58_prefix_probability` counts prefix outcomes **exactly**. The naive
    `58^-k` formula is shown alongside it and is smaller by a factor of about 2.5;
    the exact values were validated against a 200 000-address Monte Carlo;
  * `vanity_report` refuses to treat a post-hoc prefix as evidence: without a
    declared prefix the corrected probability is `1.0`;
  * `controlled_experiment` and `matches_public_key` relate an address to a public
    key you already hold by deriving all four common address forms.
* **`binarycryptolab dissect-address ADDRESS`** with `--network`, `--claimed-prefix`,
  `--report-format {text,json}`, `--output`, and `--overwrite`.
* `docs/address_forensics.md` and an Arabic section in `docs/how_it_works_ar.md`.
* 57 new tests (47 module tests plus 10 CLI tests), including the exact-versus-Monte
  Carlo prefix check.

### Notes

* Nothing here recovers a private key from an address, and the report says so on
  every page: `2^96` public keys remain consistent with a 20-byte hash, and `0` of
  `256` scalar bits are known.

## [1.3.0] - 2026-10-28

### Added

* **`binarycryptolab.curve_arithmetic`** - analysis-only secp256k1 arithmetic
  (Jacobian add/double/multiply, negation, subtraction, SEC 1 decoding) and a
  bounded baby-step/giant-step interval solver. Cross-checked against
  `cryptography`/OpenSSL for random scalars, against the published generator
  vector, and through the group laws; it is never used for key generation,
  signing, or secret protection.
* **`binarycryptolab.key_reconstruction`** - the segment/compare/assemble layer:
  * `segment_hex` / `segment_bits` split values into nibbles, bytes, 16-, 32-, and
    64-bit words with bit offsets;
  * `parse_template` accepts a 64-digit hexadecimal pattern with one contiguous
    `?` window and reports known bits, window width, and the bits below it;
  * `InformationLedger` / `build_ledger` reduce every fact about a scalar to one
    scale of bits: 4 bits per known hex digit, `log2 m` for a congruence,
    `256 - log2 w` for an interval, and **explicitly zero** for public
    coordinates, addresses, hashes, and the mirror point;
  * `solve_template` searches the unknown window only, assembles
    `k = K + x * 2^low`, and re-derives the public key through `cryptography`
    before reporting; refusals explain the missing bits instead of guessing;
  * `solve_offset` and `compare_keys` detect small scalar differences between
    public keys (the related-key case) together with nibble agreement, shared
    prefixes/suffixes, and pairwise Hamming distances.
* `assemble-private-key` and `compare-keys` CLI commands, plus
  `examples/key_assembly.py` and `docs/key_assembly.md`.

### Security

* The assembled scalar is excluded from `repr` and redacted in JSON unless
  `reveal=True`; the CLI prints it only with `--reveal` and warns that the value
  is a private key.
* Windows above 40 bits are refused with an explanatory error, so no call can turn
  into a general attack on the curve.
* Error messages never contain the scalar, its digits, or a partial key.

### Tests

* 131 new tests (993 total): 51 for the curve arithmetic, 67 for segmentation,
  the ledger, assembly and comparison, and 13 for the two new CLI commands.

## [1.2.0] - 2026-10-28

### Added

* **`binarycryptolab.special_functions`** — dependency-free numerics for the
  statistical layer: normal CDF/survival/two-sided p-values, regularized
  incomplete gamma (series and continued fraction) and its chi-square
  specialisation, exact binomial mass and two-sided tails, Fisher combination,
  and overflow-safe `log2_sum_exp`. Verified against published critical values
  (χ² at 1, 2, 3, 4, 10, and 30 degrees of freedom).
* **`binarycryptolab.randomness`** — a seven-test battery over key material:
  monobit, runs, longest run (exact dynamic program, no lookup tables), lag-1
  serial correlation, approximate entropy, nibble uniformity, and distinct-byte
  occupancy (exact Stirling-number distribution, normal approximation with exact
  moments above 256 bytes). `randomness_report` adds Fisher and Bonferroni
  combinations, the minimum p-value, a family-wise verdict, plug-in and
  Miller–Madow entropy, and explicit caveats.
* `PublicKeyDissection.randomness` runs the battery over `x ‖ y` and is included
  in the JSON report; the text report, GUI, and example print it.
* `Forecast` now exposes `structure_bits`, `combined_p_value`,
  `bonferroni_p_value`, `minimum_p_value`, `alpha`, and per-family
  `EvidenceContribution` records (`evidence`), plus `BayesFactor` records
  (`bayes_factors`) with priors, log2 Bayes factors, posteriors, and log2
  posteriors.
* `bits_from_bytes`, `distinct_bytes_moments`, `distinct_bytes_p_value`,
  `P_VALUE_FLOOR`, and the `RandomnessReport`/`StatisticalTest` models are part
  of the public API.

### Changed

* The structure score is now derived from a combined p-value instead of a
  hand-tuned scale: family p-values are floored at `2^-64`, combined with
  Fisher's method, and mapped as
  `score = min(100, max(0, -log₂ p - log₂ 100) / 128 × 100)`. The Bonferroni
  bound (`k · min p`) is reported next to it, and both are printed in the text
  report and the GUI.
* Generation hypotheses are now Bayesian. Priors are explicit (0.85 / 0.09 /
  0.05 / 0.01), the "structured coordinate" model uses an analytic reduced-space
  Bayes factor (`2^256 · 256⁻¹ Σ 2^-m`), and `hypothesis.score` is the posterior
  probability rather than a heuristic. Hypothesis labels follow the posterior.
* Evidence families were renamed and extended (`repetition`, `runs`, `serial`,
  `sequence`), and randomness tests now feed the same de-duplication as findings,
  so correlated measurements cannot multiply the evidence.
* Combined p-values are rounded to significant figures (not decimal places) and
  floored at `1e-300`, so tiny probabilities survive JSON serialisation.

### Fixed

* The battery no longer raises on degenerate input: a constant bit string yields
  a failing `serial_correlation` placeholder instead of a `0/0` error.
* `distinct_bytes_exact_p` documents and enforces its exact-DP size limit and
  points to `distinct_bytes_p_value` for longer inputs.

### Tests

* 126 new tests (862 total): 49 for the special functions, 51 for the battery,
  26 for the statistical forecast, plus CLI coverage for the new report sections.

## [1.1.0] - 2026-10-27

### Added

* **Public-key forensics** (`binarycryptolab.forensics`): `dissect_public_key`,
  `dissect_many`, and immutable models (`PublicKeyDissection`,
  `CoordinateProfile`, `Representation`, `BitProfile`, `StructureFinding`,
  `Forecast`, `SearchEstimate`, `AddressMatrixEntry`).
* Identity dissection: SEC 1 encoding detection (compressed, uncompressed, 64 raw
  bytes), prefix byte, y parity, x-only BIP-340 form, and both canonical
  encodings.
* Coordinate profiles: hex/decimal values, bit length, leading/trailing zeros,
  Hamming weight with exact two-sided binomial p-value, byte entropy, nibble
  histogram, base 2⁸/2¹⁶/2³²/2⁶⁴ limb decompositions, little-endian
  serialisation, distance to the field prime, ASCII bit grids, and printable-ASCII
  detection.
* Mirror-point analysis: `-P` (the other point sharing the same x), its compressed
  encoding, and its mainnet addresses, with an explanation of x-only ambiguity.
* Keyspace context: group order, distinct-key count, birthday collision bound, and
  field prime alongside the search-cost table.
* Curve verification: field-range checks, `y² ≡ x³ + 7 (mod p)`, point-at-infinity
  rejection, prefix/parity agreement, encoding agreement, length checks, and
  address round-trips.
* Sixteen representations per key (hex, binary, decimal, Base58, Base64, Base32,
  Base64url, spaced hex, `x mod n`, little-endian variants, diagnostic
  Base58Check) plus SHA-256, SHA-512, double SHA-256, RIPEMD-160, and HASH160
  digests of several encodings.
* Structural findings with probabilities: leading/trailing zeros, reduced
  magnitude, near-prime coordinates, Hamming-weight anomalies, palindromes,
  repeated blocks, known magic constants, nibble skew, printable runs, and
  coordinate relations (`x == y`, `y == -x`).
* Scored forecast: verdict, structure score (evidence-family de-duplication),
  four ranked generation hypotheses, and a discrete-logarithm cost table for
  exhaustive, Pollard-rho, and baby-step/giant-step search, with `recoverable`
  permanently `false`.
* **P2SH-P2WPKH (nested SegWit)** derivation, `p2sh_address_from_script_hash`,
  and `address_matrix` covering four address types across four networks.
* CLI command `dissect-public-key` with `--depth`, `--networks`, `--art`, batch
  mode (`--input-file`, up to 1000 keys), text/JSON/CSV reports, and overwrite
  protection.
* Streamlit tab **Key forensics** with metrics, findings, hypotheses, coordinate
  and address tables, expandable digest/representation/bit-grid sections, and
  JSON/CSV downloads.
* `PublicKeyDissection` is also exported from the package root.
* Documentation: `docs/public_key_forensics.md` (probability model, scoring,
  worked examples, limits) and `examples/public_key_forensics.py`.
* 143 new tests (722 total): forensics engine, probability helpers, CLI single and
  batch modes, nested SegWit, GUI service, and security invariants.

### Changed

* `AnalysisResult` gained a `forensics` field, serialized as
  `public_key_forensics`; JSON and CSV reports include it when present.
* CSV reports now flatten the forensics section into readable rows, and no longer
  duplicate `input` metadata under `report.*`.
* `AddressType` gained `P2SH_P2WPKH` with `nested-segwit`, `nested`,
  `p2sh_p2wpkh`, and `wrapped-segwit` aliases.

### Security

* The forecast never computes, guesses, or searches for a private key, and
  documents the infeasibility of doing so.
* Batch error messages name the offending line number, never the key bytes.
* Forensics output contains no private-key field anywhere; tests assert this for
  JSON reports, CSV reports, and CLI output.

## [1.0.0] - 2026-10-27

### Added

* Strict validation for binary, hexadecimal, and decimal input, with configurable
  size limits and an explicit odd-length hexadecimal policy.
* Binary analysis: width-preserving statistics, integer/hex/byte conversions,
  grouped display, byte frequency, and Shannon entropy.
* Hexadecimal analysis: nibble-accurate binary conversion, integer value, byte
  statistics, entropy, and an explicitly labelled UTF-8 preview.
* Bit operations: population count, width-bounded NOT, masks, shifts, bit-range
  extraction, reversal, padding, comparisons, and Hamming distance.
* Byte operations: conversions, XOR, Hamming distance, chunking, slicing,
  endianness conversion, and integer/bytes helpers.
* Hashing: SHA-256, SHA-512, double SHA-256, RIPEMD-160, and HASH160, with
  backend probing and published test vectors.
* secp256k1 support: scalar range validation, public-key derivation with
  `cryptography`, compressed/uncompressed encodings, and point validation.
* Base58 and Base58Check encoding/decoding with constant-time checksum checks.
* Bech32 and Bech32m encoding/decoding validated against the official BIP-173
  and BIP-350 vectors.
* Bitcoin address derivation: P2PKH and P2WPKH on mainnet, testnet, signet, and
  regtest, plus address decoding and validation.
* Deterministic JSON and CSV reports with atomic writes and overwrite
  protection.
* argparse CLI with `analyze-binary`, `analyze-hex`, `hash`, `public-key`,
  `bitcoin-address`, and `decode-address` commands, documented exit codes, and
  private-key disclosure warnings.
* Optional Streamlit interface with analysis, hashing, public-key, and address
  tabs, JSON/CSV downloads, and no network access.
* Documentation: architecture, usage, cryptography, Bitcoin addresses, and
  security notes; three runnable examples.
* 500+ tests covering unit, property-based, integration, CLI, and GUI behaviour.
* CI workflow running Ruff, mypy, and pytest on Python 3.11–3.13, plus an
  optional GUI job.

### Security

* Private scalars are never logged, echoed, or written to reports.
* `AnalysisResult` rejects non-redacted private-key input.
* No custom cryptographic primitives; all cryptography uses maintained
  libraries.
* Input limits and atomic report writes reduce denial-of-service and data-loss
  risk.
