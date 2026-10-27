# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
