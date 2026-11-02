# The discrete-logarithm audit and the cross-logarithm paper

This page documents the `dlp-audit` command, the `binarycryptolab.dlp` module, and the
research paper in [`paper/`](../paper/). It is the reference for what the audit
measures, what it refuses to claim, and how to reproduce every number.

## The question

"اللوغاريتم المتقاطع" (the *cross-logarithm*) is the claim that secp256k1's discrete
logarithm can be obtained through a structure outside the group — by moving the problem
into a finite field, by exploiting an algebraic relation between keys, or by combining
partial information from many keys or addresses. The audit tests that claim on the
published parameters and reports what it finds.

The argument has two halves:

1. **A theorem.** Any algorithm that uses only the group operation needs `Ω(√n)`
   operations (Nechaev 1994; Shoup 1997). For secp256k1, `n ≈ 2^256`, so the bound is
   about `2^128`. No generic cross-logarithm can beat it.
2. **An enumeration.** Any algorithm that is *not* generic must exploit a checkable
   property: composite order, trace one, small embedding degree, a supersingular
   neighbour, a singular curve, a proper subfield, or an isomorphism. Ten such
   properties are measured from the curve parameters and none is exploitable.

The measurement is the third element: it confirms that a real implementation behaves
like a generic algorithm at the sizes where it can be run to completion, and that the
same harness *does* exploit structure when structure exists.

## `binarycryptolab dlp-audit`

```bash
binarycryptolab dlp-audit
binarycryptolab dlp-audit --address 1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa
binarycryptolab dlp-audit --report-format json --output audit.json
binarycryptolab dlp-audit --sizes 12,16,20 --trials 5 --skip-measurement
```

| Option | Meaning |
| --- | --- |
| `--sizes` | Comma-separated instance sizes in bits (default `12,16,20,24,28,32`); at least two are required for a slope |
| `--trials` | Independent instances per size (default `5`; the paper uses `15`) |
| `--skip-measurement` | Audit the parameters and skip the scaling study — faster, and the report then says the fit is not assessable instead of inventing one |
| `--address` | Include the backward chain for one mainnet address (decode only; no lookup) |
| `--report-format` | `text`, `json`, or `csv` |
| `--output` | Write to a file atomically, refusing to overwrite silently |

Exit code `0` means the audit ran. The verdict (`refuted` / `not refuted`) is in the
report, not in the exit code, because the audit is a measurement, not a gate.

## What the audit reports

* **Scaling fit** — median rho steps per size, the least-squares slope in
  `log2(steps)` per bit, its standard error, `R²`, the z-score against `0.5`, and the
  256-bit extrapolation. Fewer than three sizes gives no error estimate, and the
  report then says the agreement test is *not assessable* rather than printing a
  verdict from a zero-width interval.
* **Structural findings** — ten properties, each with the value that was measured, an
  `exploitable` flag, and a sentence saying what the value means.
* **Cost models** — `1.25√q` for the ECDLP, `L_p[1/3, 1.923]` for the finite-field
  DLP (the contrast that shows what a real sub-exponential attack looks like), and the
  address chain.
* **Claim rebuttals** — eight claims (`index_calculus`, `pohlig_hellman`,
  `glv_speedup`, `brute_force_scale`, `quantum`, `statistical_structure`,
  `side_channel`, `published_proof`), each with why it fails and what evidence in this
  project bears on it.
* **Falsifiers** — five observations that would overturn the conclusion, each with a
  mechanical acceptance test.

## What it will not do

* It never attacks secp256k1. The largest instance is 32 bits; the 256-bit numbers are
  extrapolations of a measured exponent and evaluations of published formulae, and the
  JSON labels them that way.
* It never contacts the network and never reads a balance.
* It does not claim that no algorithm exists. Hardness is model-relative; the paper's
  falsifiers state exactly what would end the conclusion.

## The paper

* [`paper/cross_logarithm_en.md`](../paper/cross_logarithm_en.md) — English.
* [`paper/cross_logarithm_ar.md`](../paper/cross_logarithm_ar.md) — العربية.
* [`paper/reproduce.py`](../paper/reproduce.py) — regenerates every number and figure
  in about eight seconds, with no plotting dependency and no network access.
* `paper/data/*.json` — the measured results, committed so a reader can quote them and
  a test can prove they are current.
* `paper/figures/*.svg` — the three figures, written by the same script.

```bash
python paper/reproduce.py
python -m pytest -q tests/test_dlp.py tests/test_cli_v19.py tests/test_reproduce.py
```

`tests/test_reproduce.py` fails if the committed snapshots no longer match what the
code produces, so the paper cannot drift away from the implementation.
