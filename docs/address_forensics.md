# Address forensics

An address is the public half of a one-way commitment. This document explains
exactly what `binarycryptolab dissect-address` extracts from one, what the numbers
mean, and why the tool never claims to recover a key.

## 1. What an address actually is

A mainnet P2PKH address such as `1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb` is built in
three steps:

```text
public key Q (33 or 65 bytes)
    -> HASH160(Q) = RIPEMD160(SHA256(Q))          20 bytes
    -> 0x00 || HASH160(Q)                         21 bytes, version byte prepended
    -> Base58Check(version || payload)            checksum, then base58 digits
```

`Base58Check` appends the first four bytes of `SHA256(SHA256(version || payload))`
and then encodes the result in the 58-character alphabet. Decoding is
deterministic, which is why the payload can be recovered with certainty; inverting
`HASH160` is a different problem entirely.

SegWit addresses replace Base58Check with Bech32 (witness version 0) or Bech32m
(witness versions 1-16), and the payload is either a 20-byte key hash (P2WPKH), a
32-byte script hash (P2WSH), or a 2-40 byte witness program (Taproot uses 32).

## 2. The dissection

For the address above the tool reports, among other fields:

```text
type                   p2pkh
network                mainnet
version byte           0x00
payload                ab9a4edd7600fe91d0f46a97dc851ad45c1ce176
checksum (encoded)     c6b1840e
checksum (recomputed)  c6b1840e
checksum valid         yes
script (hex)           76a914ab9a4edd7600fe91d0f46a97dc851ad45c1ce17688ac
script (asm)           OP_DUP OP_HASH160 ab9a...e176 OP_EQUALVERIFY OP_CHECKSIG
```

The checksum is always recomputed rather than trusted, so a corrupted address is
rejected with a clear error instead of being analysed as if it were valid.

## 3. The payload profile and its exact p-values

A `HASH160` output should look like 20 uniform random bytes. The profile checks
that with tests whose null distributions are known exactly:

| Test | Statistic | Null distribution | Meaning |
| --- | --- | --- | --- |
| Leading zero bits | 0 for this address | `Binomial(160, 1/2)` | A digest starting with many zeros is rarer than it looks |
| Hamming weight | 82 | `Binomial(160, 1/2)`, two-sided | Number of set bits |
| Nibble frequencies | see report | `chi-square` with 15 df | Uneven nibbles suggest structure |
| Distinct bytes | 19 | exact enumeration | Collisions among 20 draws from 256 |
| Byte entropy | 4.222 bits/byte | descriptive | Upper bound is `log2(20) = 4.32` here |
| Palindromic payload | no | `2^-80` | A perfect mirror is essentially impossible by chance |

The randomness battery (monobit, runs, longest run, serial correlation,
approximate entropy, nibble uniformity, distinct bytes) adds p-values. Combining
them naively would multiply the error rate, so the report gives both a Fisher
combination and a Bonferroni-adjusted decision. The address above passes on both
counts with a Fisher p-value of `9.298e-01` and zero structural findings.

**These tests cannot find a private key.** They can only show that a payload is
unusual. A payload that fails them would still leave 2^160 preimages to search.

## 4. Prefix probability: the exact count, and why the textbook formula is wrong

The probability that a random mainnet P2PKH address starts with a given prefix is
a counting problem, not `58^-k`. The version byte is fixed at zero and the total
number of base58 digits is fixed by the payload, so short prefixes are far more
likely than the naive formula suggests.

The module enumerates every 20-byte payload that produces each prefix and divides
by `2^160`. Results for the address above:

| Prefix | Exact probability | Naive `58^-k` | Ratio |
| --- | --- | --- | --- |
| `1G` | `4.360e-02` | `1.724e-02` | 2.53 |
| `1Ge` | `7.517e-04` | `2.973e-04` | 2.53 |
| `1GeM` | `1.296e-05` | `5.125e-06` | 2.53 |
| `1GeMQ` | `2.235e-07` | `8.837e-08` | 2.53 |
| `1GeMQK` | `3.853e-09` | `1.524e-09` | 2.53 |

The exact figures were validated against a Monte Carlo sample of 200 000 derived
addresses: `1G` appeared 8 727 times against an expectation of 8 720, `1Ge` 147
times against 150, and `1GeM` 3 times against 3.

### The look-elsewhere effect

If you only notice the prefix *after* seeing the address, the p-value is not
`3.853e-09`; it is the probability that *some* six-character feature would have
struck you as interesting, which is close to one. This is the look-elsewhere
effect. The tool therefore returns a corrected probability of `1.0` and an
explicit verdict unless you supply `--claimed-prefix`. Only a prefix fixed before
the fact supports a claim, and even then a short prefix is cheap to mine
deliberately - which is exactly what vanity address generators do.

## 5. The backward chain, priced in bits

| Step | Cost | Feasible | Why |
| --- | --- | --- | --- |
| address -> payload | `2^0` | yes | Base58Check decoding is deterministic |
| payload -> public key | `2^160` | no | Preimage of HASH160; collisions do not help |
| public key -> scalar | `2^128` | no | Pollard rho on secp256k1 |
| total | `2^288` | no | The steps compose |

Two distinctions matter:

* **Collision versus preimage.** Finding *some* public key with the same hash
  costs about `2^80` (birthday bound on a 160-bit digest), and it would be useless:
  the address commits to the *specific* key that signed, not to any key that
  happens to hash to the same value. Only a preimage works, and that is `2^160`.
* **Bitcoin addresses are not hashed public keys on chain.** Once a key spends, its
  public key is public and the remaining barrier drops to the `2^128` discrete
  logarithm. That is still far beyond any classical attack, and it is why address
  reuse is discouraged.

This module is not used for signing or key generation; it never sees a scalar.

## 6. Quantum caveats

* **Grover** gives a quadratic speedup for unstructured search: `2^160` becomes
  `2^80` *evaluations*, requiring coherent superposition of the hash circuit for
  the whole search. A `2^80` gate-count estimate is not a `2^80` wall-clock
  estimate.
* **Shor** solves the discrete logarithm in polynomial time on a large
  fault-tolerant machine, which is why the public-key step is the one that would
  actually fall first.
* Neither changes the answer today: no such machine exists, and the report says so
  rather than pretending the barrier is stable forever.

## 7. Controlled experiments

`controlled_experiment(address, public_key)` is the honest counterpart to key
recovery. Given a public key you already hold, it derives the four common address
forms - P2PKH compressed, P2PKH uncompressed, P2WPKH, and P2SH-P2WPKH - and
reports which of them matches. It answers "is this my address?" and never "what is
this address's key?".

```python
from binarycryptolab.address_forensics import controlled_experiment, dissect_address

report = dissect_address("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb")
print(report.scale.public_key_candidates_log2)  # 96.0
print(report.scale.scalar_bits_known)  # 0.0
print(report.recoverable)  # False
```

## 8. What the tool refuses

* It does not search for a private key behind an address.
* It does not claim that an address holds funds, or that anyone owns it; that needs
  a blockchain, and this tool makes no network requests.
* It does not present a post-hoc prefix as evidence.
* It does not report a scalar unless a bounded, verified search actually produced
  one - which cannot happen from an address alone.
