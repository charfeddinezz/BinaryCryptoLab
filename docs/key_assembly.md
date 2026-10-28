# Key segmentation, one information scale, and bounded assembly

This document describes `binarycryptolab.key_reconstruction`: how a private scalar
is segmented into hexadecimal parts, how every kind of knowledge about it is
reduced to **one scale of bits**, and how the unknown part can be assembled when -
and only when - it is small enough to search.

> **What this cannot do.** A public key fixes `Q = k * G`. Recovering `k` from `Q`
> is the elliptic-curve discrete logarithm problem: about `2^128` group operations
> on secp256k1, with no known shortcut. No amount of segmentation, comparison, or
> clever aggregation changes that, because the coordinates are a hash-like image of
> the scalar, not its digits. This module therefore values every public datum at
> **zero bits** and assembles a scalar only from knowledge *you* supply.

## The one scale

Every fact about a scalar is expressed as "how many of the 256 bits it fixes".
Nothing is compared on a scale of intuition.

| Source | Bits | Why |
| --- | --- | --- |
| one known hexadecimal digit | 4 | a nibble has exactly 16 values, `log2 16 = 4` |
| scalar known modulo `m` | `log2 m` | a congruence partitions the space into `m` classes |
| scalar known to lie in an interval of width `w` | `256 - log2 w` | the remainder is `log2 w` bits |
| public key coordinates `(x, y)` | **0** | inverting them is the discrete logarithm |
| addresses, hashes, encodings | **0** | pure functions of the same point |
| mirror point `-P`, x-only form | **0** | the same coordinates again |

The ledger then reports:

```text
known_bits   = min(256, sum of the contributions)
unknown_bits = max(0, 256 - known_bits)
search_log2  = unknown_bits / 2          (baby-step/giant-step)
feasible     = unknown_bits <= budget    (default 32, hard cap 40)
```

The last two lines are the honest answer to "can this key be assembled?". A
template with 200 known bits and a 56-bit window reports `2^28` operations and
`feasible = false`; nothing is attempted.

## Templates

A template is exactly 64 hexadecimal digits in which `?` marks unknown digits.
One contiguous run is allowed; separators (` `, `_`, `:`, `-`), mixed case, and a
`0x` prefix are accepted.

```text
c0ffee0000000000000000000000000000000000000000000000000000??????
|--------------------- 58 known digits --------------------||-- 6 --|
                                                           24 unknown bits
```

`parse_template` returns a `KeyTemplate` with `known_value` (unknown digits set to
zero), `unknown_start` (bit offset from the most significant bit), `unknown_bits`,
`low_bits` (known bits below the window), and `known_digits`.

| Window | Steps in the table | Typical time |
| --- | --- | --- |
| 16 bits | 256 | milliseconds |
| 24 bits | 4 096 | about 0.15 s |
| 32 bits | 65 536 | about 1 s |
| 40 bits (cap) | 1 048 576 | tens of seconds, about 100 MB |

## Assembly

With the template's known value `K`, the window width `b`, and the number of known
bits below it `low`, the search solves

```text
Q - K*G = x * (2^low * G),      0 <= x < 2^b
```

by baby-step/giant-step over the window only, then assembles

```text
k = K + x * 2^low
```

and re-derives the public key through `cryptography` before reporting anything. A
candidate that does not reproduce the input key is discarded and the result is
marked unsolved - the tool never reports an unverified scalar.

The search cost is `2^(b/2)` table entries and about `2^(b/2)` group operations.
That is why the window is capped: the cap is what separates "recover the tail of a
puzzle" from "attack the curve", and the second is refused with an explanatory
error rather than attempted.

## Comparing a set of keys

`compare_keys` segments the `x` coordinates of a key set and reports:

* **nibble agreement** - for each of the 64 positions, how many keys share the most
  common digit (a repetition signal, not a scalar signal);
* **shared prefix and suffix** - leading/trailing nibbles identical in every key;
* **pairwise Hamming distance** - how far apart the coordinates are;
* **related keys** - small scalar *differences*, which are provable from public
  data: if `Q2 = Q1 + d*G` with small `d`, the solver finds `d`.

A difference is genuinely useful and genuinely limited: `d` links two keys, so
knowing one scalar gives the other, but `d` alone reveals neither. Unrelated keys
differ by a value spread over the whole group and are not recoverable.

`max_pairs` bounds the number of pairs examined; the report says when it truncated.

## Worked example

Scalar `c0ffee0000...0000abcdef` (synthetic), public key
`03ff6129f30fb6e99e22a879f4365ab2566116db82843da41b2be4b79d29d9d26d`:

```text
known   : 232 bits       (58 known hex digits)
unknown : 24 bits
verdict : searchable: 24 unknown bits, about 2^12 operations

solved   : True
verified : True
steps    : 4096
elapsed  : 0.156 s
```

Passing `--reveal` prints the assembled scalar; by default it stays redacted.

Refusing an oversized window:

```text
refused: the template leaves 128 unknown bits, above the budget of 16;
this tool does not attack the full keyspace
```

## What the comparison of public keys can and cannot show

| Question | Answer |
| --- | --- |
| Are these two keys the same point? | Yes, decidable: compare coordinates. |
| Is one the mirror of the other? | Yes, decidable: same `x`, opposite `y`. |
| Do they share hex digits by chance? | Yes, measurable: 1/16 per nibble position. |
| Do their scalars differ by a small amount? | Sometimes: bounded search over the difference. |
| What is either scalar? | Undecidable in practice: the discrete logarithm. |
| Do they come from the same weak generator? | Yes as *evidence*, never as proof. |

## Security notes

* The assembled scalar is a private key. `TemplateSolution.assembled_hex` and
  `unknown_value` are excluded from `repr`, and `as_dict()` redacts them unless
  `reveal=True` is passed explicitly; the CLI prints them only with `--reveal`.
* Error messages never contain the scalar, the template's digits, or a partial key.
* Only use these commands on keys you generated yourself. Comparing or
  reconstructing someone else's key is not legitimate even when the window is small.
* The Streamlit interface deliberately does **not** expose assembly or comparison:
  a browser session is a poor place for a private scalar.
* `curve_arithmetic.py` is analysis code, not cryptography: it is used for bounded
  searches only, is never used to generate or sign with a key, and is verified
  against `cryptography` in `tests/test_curve_arithmetic.py`.
