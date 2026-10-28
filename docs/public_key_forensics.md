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

The forecast is a small, fully specified statistical pipeline. Every step is
reproducible from the numbers printed in the report; nothing depends on a hidden
weight or a trained model.

1. each finding and each randomness test produces a p-value under the null
   hypothesis "this key material is uniformly random";
2. correlated measurements are collapsed into **evidence families**;
3. the family p-values are combined with **Fisher's method**, with a
   **Bonferroni** bound computed as a distribution-free cross-check;
4. the combined p-value becomes a score, and **Bayes' rule** turns the same
   evidence into posterior probabilities for four generation stories.

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

```text
p = Σ_{|i - n/2| >= |observed - n/2|} C(n, i) / 2^n
```

### The randomness battery

The 512 bits of `x ‖ y` are also run through seven independent tests
(`binarycryptolab.randomness`):

| Test | Statistic | Null distribution |
| --- | --- | --- |
| `monobit` | `\|ones - zeros\| / sqrt(n)` | standard normal |
| `runs` | number of symbol changes | normal approximation |
| `longest_run` | longest run of ones | **exact** dynamic program over all `2^n` strings |
| `serial_correlation` | lag-1 coefficient | standard normal |
| `approximate_entropy` | `phi(2) - phi(3)` in nats | chi-square, `2n(ln 2 - ApEn) ~ χ²(4)` |
| `nibble_uniformity` | chi-square on the 16 hex digits | `χ²(15)` |
| `distinct_bytes` | number of distinct byte values | **exact** occupancy distribution, or a normal approximation with exact moments above 256 bytes |

The report publishes each p-value, the Fisher combination, the Bonferroni bound
`min(1, 7·min p)`, the minimum p-value, the family-wise verdict, the plug-in bit
entropy, and the Miller-Madow bias-corrected entropy. Because the seven tests
share one input, their p-values are dependent: Fisher is optimistic and
Bonferroni is conservative, so both are printed and the caveat is stored in
`randomness.notes`.

### Evidence families

Several measurements can describe one underlying fact: a coordinate of small
magnitude also has many leading zeros, a low Hamming weight, a skewed digit
histogram, and fails the monobit and runs tests on the same bytes. To avoid
multiplying the same evidence, findings and tests are grouped into families and
only the strongest member of each family contributes:

| Family | Findings | Randomness tests |
| --- | --- | --- |
| `magnitude` | leading/trailing zeros, small magnitude, near the field prime | — |
| `bit-balance` | Hamming weight | `monobit` |
| `repetition` | palindrome, repeated block, magic constant | `distinct_bytes` |
| `digit-skew` | nibble histogram | `nibble_uniformity` |
| `runs` | — | `runs`, `longest_run` |
| `serial` | — | `serial_correlation` |
| `sequence` | — | `approximate_entropy` |
| `ascii` | printable runs | — |
| `relation` | `x == y`, `y == -x` | — |
| `encoding` | unprefixed input (p = 1, carries no evidence) | — |

Family p-values are floored at `2^-64`. The floor exists because the battery
relies on asymptotic approximations that are not calibrated far beyond that
tail, and because exact tails underflow for degenerate inputs. The uncapped test
p-values stay available in `dissection.randomness`.

### Combination and score

With `k` usable families (the `encoding` family, whose p-value is exactly 1, is
excluded):

```text
statistic   = -2 Σ ln p_i                    ~ χ²(2k) under the null
fisher_p    = sf(χ²(2k), statistic)
bonferroni  = min(1, k · min p_i)
```

The score uses the Fisher statistic and reports the Bonferroni bound next to it:

```text
structure_bits  = min(256, max(0, -log₂(fisher_p) - log₂(1/0.01)))
structure_score = min(100, structure_bits / 128 · 100)
```

`log₂(1/0.01) ≈ 6.64` bits is the noise floor: evidence below the 1% level is
not counted. The scale saturates at 128 bits of evidence above that floor, which
keeps the score informative for ordinary keys while still reaching 100 for
pathological ones (`x = 1` reaches 256 bits).

| Score | Verdict |
| --- | --- |
| ≥ 60 | strongly structured: do not use this key for real funds |
| ≥ 25 | moderately structured: investigate before trusting this key |
| ≥ 8 | mildly structured: most likely a coincidence, but worth noting |
| < 8 | consistent with a uniformly random public key |

### Bayes factors and posteriors

Four generation stories are compared with explicit priors and a log-space
posterior:

```text
log₂ P(Hᵢ | D) = log₂ P(Hᵢ) + log₂ BFᵢ - log₂ Σⱼ P(Hⱼ) BFⱼ
```

| Hypothesis | Prior | Bayes factor |
| --- | --- | --- |
| CSPRNG (reference model) | 0.85 | `BF = 1` by definition |
| weak or low-entropy generator | 0.09 | repetition + digit-skew evidence, minus 8 bits of model complexity |
| structured / truncated / hand-made coordinate | 0.05 | `max(magnitude BF, general BF)` |
| related-key or incrementing generator | 0.01 | `2^-4`, because one key cannot test it |

The **magnitude Bayes factor** is analytic. The alternative draws a coordinate
uniformly from `[0, 2^m)` for an unknown `m`, with a uniform prior over
`m ∈ [0, 255]`, while the null assigns `2^-256`:

```text
P(x | H₁) = 256⁻¹ Σ_{m=b}^{255} 2^-m,    BF = 2^256 · P(x | H₁)
```

so a full-width coordinate is penalised by the 8 bits of model choice and a
one-bit coordinate earns 248 bits. The result is reported as `log2_bayes_factor`,
`posterior`, and `log2_posterior`; the log form stays finite when a posterior
probability underflows to zero, so use it for comparisons.

Hypotheses are labelled `likely` (≥ 0.75), `plausible` (≥ 0.5), `possible`
(≥ 0.25), `unlikely` (≥ 0.1), or `very unlikely`. Priors are printed in the
report, so you can substitute your own and recompute the posterior by hand.

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

```text
structure score : 0.0/100
findings        : none
Fisher p        : 0.952   Bonferroni p: 1.0
randomness      : all 7 tests pass (family-wise)
verdict         : consistent with a uniformly random public key
P(CSPRNG)       : 0.998
```

Leading zeros: 1 bit for each coordinate, exactly what chance predicts.

### Point with x = 1

```text
structure score : 100.0/100
findings        : x_small_magnitude (critical), x_leading_zero_bits (critical),
                  x_hamming_weight (critical), nibble_skew (critical)
Fisher p        : 1.97e-118   Bonferroni p: 3.79e-19
randomness      : 6 of 7 tests fail
verdict         : strongly structured: do not use this key for real funds
P(structured)   : 1.0   (magnitude Bayes factor 2^248)
```

`x = 1` has probability `2^-255` under the uniform model. Such a point corresponds
to a tiny scalar, but confirming that would require solving the discrete
logarithm — which this tool does not do and cannot do.

### A key with an unusual Hamming weight

A coordinate with 96 one-bits (expected 128, σ ≈ 8) has an exact two-sided
binomial p-value of 7.6×10⁻⁵, i.e. 13.7 bits. Subtracting the 6.64-bit noise floor
leaves 7.0 bits, which is a score of about 5.5: still "consistent with a uniformly
random public key". This is deliberate — one mildly unusual measurement is not
evidence of a broken generator. It takes about 40 bits above the floor (a score of
25) before the verdict changes.

## Limitations

* Probability estimates assume uniform 256-bit values. A key can be generated by a
  weak process and still look random; a key can look structured and be safe.
* Structure cannot confirm or refute that the key corresponds to a small scalar.
  That is the discrete logarithm problem, and this project does not attack it.
* No blockchain data is consulted: ownership, balance, and history are unknown.
* The x-only form is not a Taproot output key; the BIP-341 tweak is not applied.
* The score is a statistical aggregate, not a cryptographic proof. Fisher's method
  assumes the evidence families are independent; they are approximately, not
  exactly, independent, which is why the conservative Bonferroni bound is printed
  alongside it.
* The randomness battery has limited power on 64 bytes of key material. It can
  detect gross anomalies (constant, padded, or tiny coordinates) but not a weak
  generator that is statistically well behaved.

## Why no key recovery

Recovering a private scalar from a public key on secp256k1 requires solving the
elliptic-curve discrete logarithm problem. The best known general algorithms
(Pollard rho, BSGS) are exponential; for a 256-bit scalar the cost is about
2¹²⁸ group operations, which is far beyond any conceivable computation. Tools
that claim otherwise are either solving a toy curve, using a key the owner
already leaked, or lying. BinaryCryptoLab reports the cost, explains the limits,
and stops there.
