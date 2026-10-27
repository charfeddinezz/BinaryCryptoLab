# Cryptography notes

This document explains what BinaryCryptoLab computes, which library performs
each operation, and what the results do and do not prove.

## Hashing, encryption, and encoding

These three operations are often confused. They are not interchangeable.

| Operation | Reversible? | Purpose | Example in this project |
| --- | --- | --- | --- |
| Hashing | No (one-way) | Fixed-size fingerprint / integrity check | SHA-256, RIPEMD-160, HASH160 |
| Encryption | Yes, with a key | Confidentiality | **Not implemented** |
| Encoding | Yes, no key | Represent bytes in a different alphabet | Base58Check, Bech32 |

BinaryCryptoLab performs hashing and encoding only. It does not encrypt,
decrypt, sign, or verify signatures. It cannot reverse a hash, and it makes no
attempt to do so.

## Hash functions

| Algorithm | Output | Implementation |
| --- | --- | --- |
| SHA-256 | 32 bytes | `hashlib.sha256` (OpenSSL) |
| SHA-512 | 64 bytes | `hashlib.sha512` (OpenSSL) |
| Double SHA-256 | 32 bytes | `SHA256(SHA256(data))` |
| RIPEMD-160 | 20 bytes | `hashlib.new("ripemd160")` when available |
| HASH160 | 20 bytes | `RIPEMD160(SHA256(data))` |

### Availability and failure behaviour

RIPEMD-160 is not part of the FIPS module and is not available in every Python
build. `binarycryptolab.hashing.ripemd160_available()` performs a real probe by
hashing a fixed value. When the algorithm is missing:

* `ripemd160()`, `hash160()`, and `hash_bytes(..., "ripemd160")` raise
  `UnsupportedHashError`;
* no alternative algorithm is silently substituted;
* `supported_algorithms()` omits the affected entries so the CLI and GUI can
  present only working options.

The CLI surfaces the error as a normal exit-code-1 failure.

### Published vectors used by the tests

| Input | Algorithm | Digest |
| --- | --- | --- |
| `b""` | SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `b"abc"` | SHA-256 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `b"abc"` | SHA-512 | `ddaf35a193617abacc417349ae204131…54ca49f` (abbreviated) |
| `b""` | Double SHA-256 | `5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456` |
| `b""` | RIPEMD-160 | `9c1185a5c5e9fc54612808977ee8f548b2258d31` |
| `b"abc"` | RIPEMD-160 | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |
| `b""` | HASH160 | `b472a266d0bd89c13706a4132ccfb16f7c3b9fcb` |

## Base58Check

Base58 uses the Bitcoin alphabet
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, which omits `0`,
`O`, `I`, and `l` because they are visually ambiguous.

Base58Check appends four checksum bytes:

```
checksum = SHA256(SHA256(version || payload))[0:4]
address  = Base58(version || payload || checksum)
```

Decoding validates the checksum with `hmac.compare_digest` (constant time with
respect to the checksum bytes), the payload length, and the version byte. A
single-character change is detected with overwhelming probability; the tests
exercise this property.

Base58Check provides **error detection**, not authentication. Anyone can create
a valid checksum. It does not prove that an address belongs to anyone.

## Bech32 and Bech32m

Two checksum variants exist:

| Variant | Constant | Used for |
| --- | --- | --- |
| Bech32 (BIP-173) | `1` | SegWit version 0 programs (P2WPKH, P2WSH) |
| Bech32m (BIP-350) | `0x2bc830a3` | SegWit versions 1–16 |

The implementation follows the reference algorithms: a BCH checksum over the
expanded human-readable part and 5-bit data groups, followed by six checksum
characters. Decoding rejects:

* mixed case;
* an invalid or misplaced separator;
* characters outside the Bech32 charset;
* a failed checksum;
* a checksum variant that does not match the witness version;
* witness versions above 16;
* witness programs outside 2–40 bytes;
* version-0 programs that are not 20 or 32 bytes;
* non-zero padding in the 5-to-8-bit conversion.

The test suite includes the official BIP-173 and BIP-350 vectors, including
every listed invalid case and the scriptPubKey produced by each valid address.

## secp256k1

### Domain parameters

| Parameter | Value |
| --- | --- |
| Field prime `p` | `2^256 − 2^32 − 977` = `fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f` |
| Curve | `y² = x³ + 7` (`a = 0`, `b = 7`) |
| Generator `Gx` | `79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| Generator `Gy` | `483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8` |
| Order `n` | `fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` |
| Cofactor `h` | 1 |

### Private scalars

A valid private scalar satisfies:

```
1 <= k < n
```

`ecc.validate_private_scalar` rejects `0`, negative values, `n`, values above
`n`, booleans, and non-integers. Messages never include the supplied scalar.
The `parse_private_scalar` helper accepts hexadecimal text by default (with an
optional `0x` prefix) and decimal text when `base=10`.

### Public-key derivation

```
public_key = k * G
```

This scalar multiplication is performed by
[`cryptography`](https://cryptography.io/) (`ec.derive_private_key` with
`SECP256K1`), which uses OpenSSL. **BinaryCryptoLab contains no elliptic-curve
arithmetic of its own.** A custom implementation would be both
security-sensitive and unnecessary.

### Public-key encodings

| Encoding | Length | Prefix | Structure |
| --- | --- | --- | --- |
| Compressed | 33 bytes | `02` or `03` | `x` coordinate only; prefix encodes `y` parity |
| Uncompressed | 65 bytes | `04` | `x || y` |
| Raw uncompressed | 64 bytes | none | accepted as input for convenience; `04` is added |

`parse_public_key_hex` validates the length and prefix, then delegates point
validation (including rejection of the point at infinity and points not on the
curve) to `cryptography`. The project does not implement its own point
validation.

A public key cannot be turned back into a private key. That is the security
assumption of elliptic-curve cryptography, and this project neither claims nor
implements any way around it.

### Known-answer tests

* Scalar `1` → the generator point `G`.
* Scalar `2` → `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`.
* The Bitcoin wiki example scalar produces the published public key
  `0450863a…e9c582ba6` and address `16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM`.

## What this project deliberately does not do

* No custom cryptographic primitives.
* No key generation (the OS CSPRNG is not needed here because the tool never
  generates keys).
* No signing or signature verification.
* No BIP-32/BIP-39 derivation, no WIF encoding, no keystore files.
* No recovery of private keys from public keys.
* No brute force, scanning, or data exfiltration.

## Further reading

* FIPS 180-4 — Secure Hash Standard.
* The RIPEMD-160 specification (Dobbertin, Bosselaers, Preneel).
* BIP-173 — Base32 address format for SegWit v0.
* BIP-350 — Bech32m format for SegWit v1+.
* SEC 2 — Recommended Elliptic Curve Domain Parameters.
* `cryptography` documentation — <https://cryptography.io/>
