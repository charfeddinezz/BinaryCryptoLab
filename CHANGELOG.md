# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
