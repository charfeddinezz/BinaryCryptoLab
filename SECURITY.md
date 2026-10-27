# Security policy

## Scope

BinaryCryptoLab is a local educational tool for binary/hex analysis, hashing,
secp256k1 public-key derivation, and Bitcoin address encoding. It never
generates keys, never signs transactions, never queries the blockchain, and
never transmits data.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

Security fixes are made on the default branch and released as a new patch
version.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

1. Open a private security advisory for this repository:
   <https://github.com/charfeddinezz/BinaryCryptoLab/security/advisories/new>
2. Include:
   * affected version or commit;
   * a minimal reproduction;
   * the impact you believe it has;
   * whether the issue involves private key material.
3. Do not include real private keys, seed phrases, or funded wallet data. Use a
   synthetic scalar such as `1` or a throwaway value.

You can expect an initial response within a reasonable time. Please allow time
for a fix and a release before public disclosure.

## Security properties

* No network access from the package.
* No custom cryptographic primitives; hashing uses `hashlib`/OpenSSL and
  elliptic-curve operations use `cryptography`/OpenSSL.
* Private scalars are validated against the secp256k1 range, never logged,
  never returned, and never written to reports.
* The analysis result model refuses to accept private-key input unless it is
  replaced by `<redacted>`.
* Base58Check checksum comparisons use `hmac.compare_digest`.
* Reports are written atomically and do not overwrite existing files by default.
* Input size limits prevent unbounded memory use.

## Known limitations

* Base58Check and Bech32 detect errors; they do not provide authenticity.
* The tool cannot detect that a supplied key is a real, funded key. It is your
  responsibility to use synthetic values.
* Text and file content hashed via the CLI is deliberately omitted from reports,
  but any report you export may still contain sensitive hexadecimal data you
  supplied.
* Address derivation does not establish ownership or balance.
* WIF, BIP-32, BIP-39, PSBT, and signing are out of scope.

## User responsibilities

* Use synthetic test keys only.
* Never paste a key that controls funds into a terminal or a web form.
* Treat any leaked private key as compromised and move funds immediately.
* Never reuse test values in a funded wallet.
* Keep `cryptography` (and Streamlit, if installed) up to date.
* Delete exported reports if they contain data you consider sensitive.

See [`docs/security.md`](docs/security.md) for the full threat model.
