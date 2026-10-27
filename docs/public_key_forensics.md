# Public-key forensics and structural forecasting

BinaryCryptoLab can take a **public** secp256k1 key and decompose it from every
angle that public mathematics allows. This document explains what is measured,
how the scores are computed, how to read them, and — most importantly — what the
forecast cannot tell you.

> A public key cannot be turned into a private key. This feature does not search,
> guess, or brute-force anything. It reads the *structure* of the key and reports
> how unusual that structure is.

## Running it

```bash
binarycryptolab dissect-public-key --public-key 0279BE667E...F81798
binarycryptolab dissect-public-key --public-key 02... --depth deep
binarycryptolab dissect-public-key --public-key 02... --networks mainnet,testnet
binarycryptolab dissect-public-key --input-file keys.txt --report-format json
binarycryptolab dissect-public-key --public-key 02... --art
```

Python:

```python
from binarycryptolab import dissect_public_key

dissection = dissect_public_key(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    depth="deep",
)
print(dissection.forecast.verdict)
print(dissection.forecast.structure_score)
print(len(dissection.addresses))
```

GUI: the **Key forensics** tab exposes the same options with tables and JSON/CSV
download buttons.

## What is collected

### Identity

| Field | Meaning |
| --- | --- |
| `curve` | Always `secp256k1`. |
| `input_encoding` | `compressed`, `uncompressed`, or `raw-uncompressed` (64 bytes). |
| `prefix_byte` | `0x02`, `0x03`, or `0x04`. |
| `y_parity` | `even` or `odd`, recovered from the compressed prefix. |
| `compressed_hex` / `uncompressed_hex` | Both canonical SEC 1 encodings. |
| `x_only_hex` | BIP-340-style x-only serialisation (no Taproot tweak applied). |

### Coordinates

For `x` and `y` independently:

* zero-padded 64-character hexadecimal and the full decimal value;
* bit length, leading zero bits, trailing zero bits;
* Hamming weight, ratio, and the two-sided binomial tail probability;
* Shannon entropy of the 32 coordinate bytes and the number of distinct bytes;
* a nibble histogram, ordered by frequency;
* limb decompositions in base 2⁸, 2¹⁶, 2³², and 2⁶⁴ (deep mode);
* little-endian serialisation (deep mode);
* parity, position relative to `p/2`, and the distance `p - coordinate`;
* an 8×32 ASCII bit grid (`--art`, or the GUI checkbox);
* printable ASCII runs hidden in the bytes.

### Curve verification

| Check | What it proves |
| --- | --- |
| `0 <= x < p`, `0 <= y < p` | The coordinates are field elements. |
| `y² ≡ x³ + 7 (mod p)` | The point really is on secp256k1. |
| Not the point at infinity | `(0, 0)` is rejected. |
| Prefix matches parity | The 33-byte form is self-consistent. |
| Compressed and uncompressed agree | Both encodings describe one point. |
| Lengths are 33 and 65 bytes | SEC 1 conformance. |
| Mainnet addresses round-trip | Each derived address decodes back to the same payload. |

Note that a point on the curve is not the same as a point in the prime-order
subgroup — for secp256k1 the cofactor is 1, so every valid curve point is in the
group. The library used for parsing (`cryptography`) enforces this.

### Representations

Compressed, uppercase, uncompressed, raw 64-byte, `x`, `y`, x-only, binary, and
decimal forms; Base58, Base64, Base32 (deep), Base64url (deep), spaced and
colon-free byte groups; `x mod n`; little-endian hex (deep); and a Base58Check
form of the raw bytes for diagnostic purposes. **None of these is an address** —
addresses are listed separately, and the tool never presents a private-key format
such as WIF.

### Digests

SHA-256 of the compressed, uncompressed, and x-only encodings; double SHA-256;
RIPEMD-160; HASH160 of the compressed and uncompressed encodings; and, in deep
mode, SHA-512 and the uncompressed double-SHA-256.

### Mirror point (−P)

Every valid x has exactly two points: `(x, y)` and `(x, p − y)`. They are additive
inverses, share the x-only encoding, and differ in the SEC 1 prefix
(`02` ↔ `03`). The report shows the twin point, its compressed encoding, and its
mainnet P2PKH/P2WPKH addresses, because their addresses are *different*: an
x-only export is ambiguous, and using the wrong twin sends funds to an address the
original key cannot spend.

For the generator point the mirror is
`03 79be667e…f81798` with mainnet addresses
`1GrLCmVQXoyJXaPJQdqssNqwxvha1eUo2E` (P2PKH) and
`bc1q4h0ycu78h88wzldxc7e79vhw5xsde0n8jk4wl5` (P2WPKH).

### Keyspace context

| Property | Value |
| --- | --- |
| Group order | `0xffff…364141` (256 bits) |
| Distinct public keys | about 2²⁵⁶ |
| Collision bound at 2⁶⁴ keys | about 2⁻¹²⁸ |
| Field prime | `0xffff…fffc2f` |

The numbers frame the search-cost table: even a birthday collision between two
keys needs about 2¹²⁸ keys.

### The address matrix

Four address types per network, with the locking script for each:

| Type | Key encoding | Locking script |
| --- | --- | --- |
| `p2pkh` | compressed | `76a914<hash160>88ac` |
| `p2pkh` | uncompressed | `76a914<hash160>88ac` (different hash) |
| `p2wpkh` | compressed | `0014<hash160>` |
| `p2sh-p2wpkh` | compressed | `a914<hash160(redeem)>87` |

Networks: mainnet, testnet, signet, regtest. Testnet, signet, and regtest share
Base58 version bytes, so their Base58 addresses are identical by design; only the
Bech32 human-readable part differs (`tb` vs `bcrt`).

## How the forecast is computed

### Finding probabilities

Each finding gets a probability that a **uniformly random 256-bit value** would
show the same pattern:

| Finding | Probability |
| --- | --- |
| `k` leading zero bits | `2^-k` |
| bit length ≤ `m` | `2^(m-256)` |
| `k` trailing zero bits | `2^-k` |
| `p - coordinate < 2^k` | `2^-k` |
| Hamming weight anomaly | two-sided binomial tail, `X ~ Bin(256, 1/2)` |
| palindromic coordinate | `≈ 16^-32 = 2^-128` |
| repeated block of `L` hex digits | `16^-(64-L)` |
| known magic constant (`deadbeef`, …) | `2^-32` |
| printable ASCII run | `≈ 3×10^-3` (informational) |
| nibble histogram skew | binomial tail, `X ~ Bin(64, 1/16)` |

The binomial tail is computed exactly with integer combinatorics:

```
p = Σ_{|i - n/2| >= |observed - n/2|} C(n, i) / 2^n
```

### Evidence families

Several findings can describe one underlying fact: a coordinate of small
magnitude also has many leading zeros, a low Hamming weight, and a skewed digit
histogram. To avoid multiplying the same evidence, findings are grouped into
families and only the strongest member of each family contributes:

| Family | Members |
| --- | --- |
| `magnitude` | leading/trailing zeros, small magnitude, near the field prime |
| `bit-balance` | Hamming weight |
| `pattern` | palindrome, repeated block, magic constant |
| `digit-skew` | nibble histogram |
| `ascii` | printable runs |
| `relation` | `x == y`, `y == -x` |
| `encoding` | unprefixed input |

The total surprisal `E = Σ_family max(-log₂ p)` is capped at 64 bits per finding
and 256 bits overall. The reported score is:

```
structure_score = min(100, 1.5625 × E)
```

so 64 bits of independent evidence saturates the scale.

| Score | Verdict |
| --- | --- |
| ≥ 60 | strongly structured: do not use this key for real funds |
| ≥ 25 | moderately structured: investigate before trusting this key |
| ≥ 8 | mildly structured: most likely a coincidence, but worth noting |
| < 8 | consistent with a uniformly random public key |

### Hypotheses

Four generation stories are scored in `[0, 1]`:

| Hypothesis | Score |
| --- | --- |
| CSPRNG | `1 - score/100` |
| low-entropy source | `min(1, score/70)` |
| puzzle / teaching key | `0.15 + 0.85·score/100` when the coordinate magnitude is reduced, else `0.05 + score/400` |
| transcription error / truncated copy | `0.2` if a repeat or palindrome was found, else `0.02` |

Scores map to `likely` (≥ 0.75), `plausible` (≥ 0.5), `possible` (≥ 0.25),
`unlikely` (≥ 0.1), and `very unlikely` otherwise. These weights are heuristics,
deliberately simple and documented so you can disagree with them.

### Search-cost table

For scalar sizes 32, 64, 128, 160, and 256 bits, the report shows:

* **exhaustive** search at 10⁹ tests/s;
* **Pollard rho** at 2^(bits/2) group operations, 10⁶ ops/s;
* **baby-step/giant-step** at 2^(bits/2) entries and 32 bytes per entry.

The table exists so that statements like "a 64-bit scalar is crackable" and "a
256-bit scalar is not" come with numbers attached. **No search is implemented.**
The `recoverable` field is always `false`.

## Reading a report

1. **Start with verification.** If any check fails, the input is not a valid
   secp256k1 public key and every other section is moot.
2. **Check the findings.** An empty list is the common, healthy case. A
   `critical` finding means the key's structure is astronomically unlikely to be
   random.
3. **Read the score, then the hypotheses.** The score answers "how unusual?";
   the hypotheses answer "what could explain it?".
4. **Compare the address matrix with reality.** If you expected
   `bc1q…` and the matrix says `1BgG…`, you have the wrong key or the wrong script
   type.
5. **Treat the key as unsafe if the score is high.** Migrate funds to a key from a
   CSPRNG; never "fix" a weak key by reusing it.

## Worked examples

### Generator point (scalar 1)

```
structure score : 0.0/100
findings        : none
verdict         : consistent with a uniformly random public key
```

Leading zeros: 1 bit for each coordinate, exactly what chance predicts.

### Point with x = 1

```
structure score : 100.0/100
findings        : x_small_magnitude (critical), x_leading_zero_bits (critical),
                  x_hamming_weight (critical), nibble_skew (critical)
verdict         : strongly structured: do not use this key for real funds
```

`x = 1` has probability `2^-255` under the uniform model. Such a point corresponds
to a tiny scalar, but confirming that would require solving the discrete
logarithm — which this tool does not do and cannot do.

### A key with an unusual Hamming weight

A coordinate with 96 one-bits (expected 128, σ ≈ 8) has a two-sided binomial
p-value of roughly 4×10⁻⁴, i.e. about 11 bits of evidence. On its own that gives a
score near 17: "mildly structured". Four independent findings of that size would
reach "moderately structured".

## Limitations

* Probability estimates assume uniform 256-bit values. A key can be generated by a
  weak process and still look random; a key can look structured and be safe.
* Structure cannot confirm or refute that the key corresponds to a small scalar.
  That is the discrete logarithm problem, and this project does not attack it.
* No blockchain data is consulted: ownership, balance, and history are unknown.
* The x-only form is not a Taproot output key; the BIP-341 tweak is not applied.
* The score is a heuristic aggregate. It is reproducible and documented, but it is
  not a cryptographic proof.

## Why no key recovery

Recovering a private scalar from a public key on secp256k1 requires solving the
elliptic-curve discrete logarithm problem. The best known general algorithms
(Pollard rho, BSGS) are exponential; for a 256-bit scalar the cost is about
2¹²⁸ group operations, which is far beyond any conceivable computation. Tools
that claim otherwise are either solving a toy curve, using a key the owner
already leaked, or lying. BinaryCryptoLab reports the cost, explains the limits,
and stops there.
