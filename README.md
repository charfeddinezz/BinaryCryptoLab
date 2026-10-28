# BinaryCryptoLab

**A local Python toolkit for binary and hexadecimal analysis, bit/byte
statistics, hashing, secp256k1 public-key derivation, deep public-key forensics,
and Bitcoin address encoding.**

BinaryCryptoLab is built for learning, teaching, auditing, and experimentation.
It validates its input strictly, delegates cryptography to maintained libraries,
and produces deterministic JSON/CSV reports. It never contacts the network,
never stores private keys, and never attempts to recover anyone's key.

> **Security first:** use synthetic test values only. Command-line arguments can
> be captured by shell history and process listings. A leaked private key must be
> treated as compromised. Address derivation does not prove ownership or balance.
> Read [`SECURITY.md`](SECURITY.md) and [`docs/security.md`](docs/security.md).

---

## Features

### Analysis

- Strict binary parsing with optional `0b` prefix, whitespace normalisation,
  leading-zero preservation, and configurable size limits.
- Strict hexadecimal parsing with optional `0x` prefix, mixed case, and an
  explicit odd-length policy (`--strict-hex` to reject).
- Binary and hexadecimal integer/byte conversions that preserve textual width.
- Bit statistics: ones, zeros, Hamming weight, ratios, and per-bit entropy.
- Byte statistics: frequency distribution, unique/min/max/average byte, and
  Shannon entropy.
- Grouped binary/hex display and a clearly labelled UTF-8 preview for hex data.

### Bit and byte operations

- Population count, width-bounded NOT, AND/OR/XOR, masks, shifts.
- Bit-range extraction, bit reversal, padding, comparisons, first/last
  differing bit, Hamming distance.
- Byte conversion, XOR, Hamming distance, chunking, concatenation, slicing,
  endianness conversion, integer ↔ bytes with explicit byte order.

### Cryptography and Bitcoin

- SHA-256, SHA-512, double SHA-256, RIPEMD-160 (when the backend provides it),
  and HASH160.
- secp256k1 scalar range validation, public-key derivation, and
  compressed/uncompressed SEC 1 encodings via [`cryptography`](https://cryptography.io/).
- Base58 and Base58Check with constant-time checksum verification.
- Bech32 and Bech32m (BIP-173/BIP-350) with the official test vectors.
- P2PKH, P2WPKH, and P2SH-P2WPKH (nested SegWit) address derivation on mainnet,
  testnet, signet, and regtest.
- Address decoding and validation: checksum, version/HRP, witness version, and
  witness program length.

### Public-key forensics and forecasting

- One command that dissects a public key from every public angle: identity,
  coordinates, bit/byte profiles, limb tables, ASCII bit grids, curve
  verification, digests, the full 16-entry address matrix, the mirrored point
  `−P` (same x, different addresses), and keyspace context.
- Structural findings with computed probabilities (leading/trailing zeros,
  reduced magnitude, Hamming-weight binomial tails, palindromes, repeated blocks,
  magic constants, digit skew, printable runs, coordinate relations).
- A seven-test randomness battery (monobit, runs, longest run, serial
  correlation, approximate entropy, nibble uniformity, distinct bytes) with
  exact tails, Fisher combination, and a Bonferroni bound.
- A scored forecast computed statistically: evidence families, Fisher/Bonferroni
  combined p-values, analytic Bayes factors with printed priors, posterior
  probabilities for four generation hypotheses, and the discrete-logarithm cost of
  exhaustive, Pollard-rho, and baby-step/giant-step search — with an explicit,
  permanent statement that no key recovery is implemented or possible.
- Batch mode: dissect up to 1000 keys from a file and export text, JSON, or CSV.

### Interfaces and reports

- Professional `argparse` CLI with six commands, helpful `--help`, documented
  exit codes, and private-key warnings.
- Deterministic JSON and CSV reports, atomic writes, overwrite protection.
- Optional Streamlit interface with JSON/CSV downloads and no network access.
- 860+ tests: unit, property-based (Hypothesis), integration, CLI, and GUI.

## Requirements

- **Python 3.11, 3.12, or 3.13** (the CI matrix covers all three).
- **`cryptography` 42 to 51** (installed automatically; the declared range is `>=42,<52`).
- Optional: **Streamlit 1.50+** for the graphical interface.
- No other runtime dependencies.

RIPEMD-160 must be provided by the OpenSSL build behind `hashlib`. Most Linux
distributions and the official python.org installers provide it. If it is
missing, the tool raises a clear error and never substitutes another hash.

## Installation

### Linux / macOS

```bash
git clone https://github.com/charfeddinezz/BinaryCryptoLab.git
cd BinaryCryptoLab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
git clone https://github.com/charfeddinezz/BinaryCryptoLab.git
cd BinaryCryptoLab
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If script execution is blocked for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Runtime-only and optional extras

```bash
python -m pip install .            # runtime only
python -m pip install -e ".[gui]"  # add Streamlit
python -m pip install -e ".[dev]"  # tests, Ruff, mypy, Hypothesis, coverage
```

## Quick start

```bash
binarycryptolab analyze-binary 101101
```

```text
BinaryCryptoLab 1.1.0 - binary analysis

Field            Value
---------------  ---------------------------------------------------------------------------------
Input            101101
Normalized       101101
Grouped          1011 01
Bit length       6
Decimal          45
Hexadecimal      2d
Bits             6 bits | 4 one | 2 zero | weight 4 | one ratio 0.6667
Bytes            2d
Byte length      1
Padding bits     2
Complete bytes   0
Incomplete bits  6
Byte stats       1 byte(s) | unique 1 | min 0x2d | max 0x2d | avg 45.00 | entropy 0.0000 bits/byte
Byte frequency   0x2d:1
Entropy          0.0000 bits/byte

Warnings:
  - Non-byte-aligned binary input was left-padded with 2 zero bit(s) for byte-level statistics; the
    textual bit statistics still describe the original width.
```

```bash
binarycryptolab analyze-hex 2D
```

```text
BinaryCryptoLab 1.1.0 - hexadecimal analysis

Field              Value
-----------------  ---------------------------------------------------------------------------------
Input              2D
Normalized         2d
Grouped            2d
Digits             2
Integer (decimal)  45
Binary             00101101
Binary length      8
Bits               8 bits | 4 one | 4 zero | weight 4 | one ratio 0.5000
Bytes              2d
Byte length        1
Byte stats         1 byte(s) | unique 1 | min 0x2d | max 0x2d | avg 45.00 | entropy 0.0000 bits/byte
Byte frequency     0x2d:1
Entropy            0.0000 bits/byte
UTF-8 preview      '-'
```

## Command-line usage

```text
binarycryptolab [--version] [-v|--verbose] [--debug] COMMAND ...
```

| Command | Purpose |
| --- | --- |
| `analyze-binary` | Parse and analyse a binary string. |
| `analyze-hex` | Parse and analyse a hexadecimal string. |
| `hash` | Hash bytes, text, or a file. |
| `public-key` | Derive a secp256k1 public key from a **test** private scalar. |
| `bitcoin-address` | Derive a P2PKH or P2WPKH address from a public key. |
| `decode-address` | Validate and decode a Bitcoin address. |
| `dissect-public-key` | Deep public-key dissection, address matrix, and structural forecast. |

Run `binarycryptolab COMMAND --help` for the full option list. The complete
reference, with outputs, is in [`docs/usage.md`](docs/usage.md).

### Hashing

```bash
binarycryptolab hash --algorithm sha256 --hex 2D
```

```text
BinaryCryptoLab 1.1.0 - hash

Field          Value
-------------  ----------------------------------------------------------------
Algorithm      sha256
Digest (hex)   3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112
Digest length  32 bytes
Input length   1 byte(s)

Input analysis:
Field        Value
-----------  -----
Input type   hex
Digits       2
Bit length   8
Byte length  1
```

Other sources and algorithms:

```bash
binarycryptolab hash --algorithm sha256 --text "abc"
binarycryptolab hash --algorithm double-sha256 --binary 101101
binarycryptolab hash --algorithm hash160 --hex 02
binarycryptolab hash --algorithm sha256 --file ./artifact.bin
```

Text and file contents are deliberately omitted from reports; only the digest,
input length, and (for files) the file name are recorded.

### Public keys (synthetic test scalars only)

```bash
binarycryptolab public-key --private-key 1 --format compressed
```

```text
BinaryCryptoLab 1.1.0 - secp256k1 public key

Field           Value
--------------  ------------------------------------------------------------------
Curve           secp256k1
X               79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Y               483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
Compressed      0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Display format  compressed

Curve order (n): 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A public key cannot be used to recover a private key.

Warnings:
  - The private scalar was validated but is intentionally absent from this output.
  - Use synthetic test values only; never reuse a test key in a funded wallet.
```

The command also writes this warning to stderr:

```text
SECURITY: a private key supplied as a command-line argument can be captured by shell
history, process listings, or terminal logging. Use synthetic test values only. Prefer
--prompt-private-key (hidden input) or the Python API.
```

Use `--private-key-base 10` for decimal scalars, `--format uncompressed|both` for
other encodings, or `--prompt-private-key` to enter the scalar with hidden input.
The scalar is never printed, logged, or written into a report; the report's input
fields contain `<redacted>`.

### Bitcoin addresses

```bash
PUB=0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
binarycryptolab bitcoin-address --public-key "$PUB" --type p2wpkh --network mainnet
```

```text
BinaryCryptoLab 1.1.0 - Bitcoin address

Field            Value
---------------  ------------------------------------------------------------------
Address          bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
Type             p2wpkh
Network          mainnet
HASH160          751e76e8199196d454941c45d1b3a323f1433bd6
Public key       0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Key encoding     compressed
Witness version  0
Witness program  751e76e8199196d454941c45d1b3a323f1433bd6
scriptPubKey     0014751e76e8199196d454941c45d1b3a323f1433bd6

No blockchain data was queried; ownership and balances are unknown.
```

```bash
binarycryptolab decode-address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

```text
BinaryCryptoLab 1.1.0 - address validation

Field              Value
-----------------  ----------------------------------------
Address            1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
Type               p2pkh
Network            mainnet
Network ambiguous  no
Payload            751e76e8199196d454941c45d1b3a323f1433bd6
Witness version    -

Checksum, version/HRP, witness version, and program length were validated.
```

Supported networks: `mainnet`, `testnet`, `signet`, `regtest`. Supported derived
types: `p2pkh`, `p2wpkh`, `p2sh-p2wpkh`. SegWit types require a compressed public
key; uncompressed keys are rejected with an explicit message instead of being
converted silently.


### Public-key dissection and forecast

```bash
binarycryptolab dissect-public-key --public-key 0279BE667E...F81798
```

```text
BinaryCryptoLab 1.1.0 - public key dissection

Field             Value
----------------  ------------------------------------------------------------------
Curve             secp256k1
Input encoding    compressed
Prefix byte       0x02
y parity          even
Compressed        0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Uncompressed      0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798...
x-only (BIP-340)  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Depth             standard

Coordinates
Coord  Hex                             Bits  Lead 0s  Trail 0s  Weight  Binomial p
-----  ------------------------------  ----  -------  --------  ------  ----------
x      79be667ef9dcb...f2815b16f81798  255   1        3         135     0.417
y      483ada7726a3c...47d08ffb10d4b8  255   1        3         123     0.574

Curve verification: all 10 checks passed

Structural findings (0)
  none: the key looks like a uniformly random 256-bit point

Randomness battery
Test                 Statistic  p-value    Result
-------------------  ---------  ---------  ------
monobit              0.1768     8.597e-01  pass
runs                 0.1865     8.520e-01  pass
...                              (7 tests)

Forecast
  Verdict         : consistent with a uniformly random public key
  Size class      : full 256-bit magnitude
  Structure score : 0.0/100
  Structure bits  : 0.0 (above the noise floor)
  Fisher p        : 9.517e-01
  Bonferroni p    : 1.000e+00
  Recoverable     : no
```

The full report adds per-family evidence, four Bayesian hypotheses with priors and
posteriors, a discrete-logarithm cost table, the
16-row address matrix (P2PKH compressed/uncompressed, P2WPKH, P2SH-P2WPKH across
four networks) with locking scripts, digests, every textual representation, and
bit/byte profiles.

```bash
# deep mode adds Base32/Base64url, limb tables, SHA-512, and bit grids
binarycryptolab dissect-public-key --public-key 02... --depth deep --art

# batch mode: one key per line, CSV export
binarycryptolab dissect-public-key --input-file keys.txt --report-format csv \
    --output keys.csv
```

The forecast is a **statistical reading**, not key recovery. `recoverable` is
always `no`; the formulas, evidence-family de-duplication, and limits are
documented in [`docs/public_key_forensics.md`](docs/public_key_forensics.md).

### Reports

```bash
binarycryptolab analyze-binary 101101 --format json --output reports/binary.json
binarycryptolab analyze-hex 2D --format csv --output reports/hex.csv
binarycryptolab public-key --private-key 1 --report-format json --output reports/key.json
```

- JSON contains the application name/version, UTC timestamp, input type,
  non-sensitive normalized input, analysis sections, hashes, public key and
  address data (when relevant), warnings, and security notes.
- CSV is a deterministic long-format table (`section,key,value`) with one row per
  byte value in the frequency section.
- Existing files are never replaced without `--overwrite`.
- Writes are atomic, and missing parent directories are created.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Expected error (invalid input, unknown algorithm, I/O, overwrite refusal) |
| `2` | Usage error (argparse) |
| `130` | Interrupted |

Errors go to stderr, never include private key material, and do not show
tracebacks unless `--debug` is passed.

## Python API

```python
from binarycryptolab import (
    analyze,
    analyze_binary,
    analyze_hex,
    dissect_public_key,
    hash160,
    sha256,
)
from binarycryptolab.bitcoin import address_from_public_key, decode_address
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.reports import write_json

result = analyze_binary("101101")
assert (result.integer_value, result.hexadecimal) == (45, "2d")
assert result.bit_stats.hamming_weight == 4

assert analyze_hex("2d").binary == "00101101"
assert sha256(b"abc").hex().startswith("ba7816bf")
assert len(hash160(b"\x02")) == 20

info = public_key_from_private(1)  # synthetic test scalar only
assert info.compressed_hex == ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

address = address_from_public_key(info.compressed_hex, address_type="p2wpkh")
assert address.address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
assert decode_address(address.address).payload_hex == address.hash160_hex

forensics = dissect_public_key(info.compressed_hex)
assert forensics.forecast.recoverable is False
assert len(forensics.addresses) == 16

write_json(analyze("binary", "101101"), "reports/binary.json")
```

Every public function is typed and documented. Ambiguity is always resolved with
an explicit parameter: `byteorder` for integer conversions, `width` for
width-dependent bit operations, `base` for private scalars, `network` for
addresses, and `encoding` for text decoding.

## Optional graphical interface

```bash
python -m pip install -e ".[gui]"
binarycryptolab-gui
```

Open <http://127.0.0.1:8501>. Tabs provide binary/hex analysis, hashing,
public-key derivation, and address derivation, with JSON/CSV download buttons.
The app makes no network requests, writes nothing unless you download a report,
and uses a password field for private scalars while keeping them out of results.

The CLI works identically without Streamlit.

## Examples

Four runnable scripts live in [`examples/`](examples):

```bash
python examples/binary_analysis.py
python examples/hex_analysis.py
python examples/public_key_analysis.py
python examples/public_key_forensics.py
```

Or with make:

```bash
make examples
```

## Testing and quality

```bash
python -m pytest -q
python -m ruff check src tests examples
python -m ruff format --check src tests examples
python -m mypy
```

Or everything at once:

```bash
make check
```

- **Tests:** unit tests for every module, Hypothesis property tests, CLI tests,
  report tests, and Streamlit `AppTest` tests (skipped automatically when the GUI
  extra is absent).
- **Vectors:** FIPS 180-4, RIPEMD-160, BIP-173, BIP-350, SEC 2, and the Bitcoin
  wiki address example.
- **Typing:** mypy strict mode passes for the package.
- **Linting:** Ruff with `E`, `F`, `W`, `I`, `N`, `UP`, `B`, `C4`, `SIM`, `RUF`,
  `DTZ`, and `T20` rules.

Coverage and GUI tests run in GitHub Actions; see
[`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Project structure

```text
BinaryCryptoLab/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── .editorconfig
├── Makefile
├── src/binarycryptolab/
│   ├── __init__.py  __main__.py  cli.py  config.py  exceptions.py  validation.py
│   ├── analysis.py  binary_utils.py  hex_utils.py  bit_operations.py
│   ├── byte_operations.py  statistics.py
│   ├── hashing.py  ecc.py  bitcoin.py  base58.py  bech32.py
│   ├── forensics.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── analysis_result.py
│   ├── reports/
│   │   ├── __init__.py  json_report.py  csv_report.py  _io.py
│   ├── gui/
│   │   ├── __init__.py  service.py  app.py  launcher.py
│   └── utils/
│       ├── __init__.py  formatting.py  logging_utils.py
├── tests/
│   ├── conftest.py  vectors.py  __init__.py
│   ├── test_validation.py  test_analysis.py
│   ├── test_binary_utils.py  test_hex_utils.py
│   ├── test_bit_operations.py  test_byte_operations.py  test_statistics.py
│   ├── test_hashing.py  test_ecc.py  test_base58.py  test_bech32.py
│   ├── test_bitcoin.py  test_forensics.py  test_reports.py  test_cli.py
│   ├── test_security.py
│   └── test_gui.py  test_gui_app.py
├── examples/
│   ├── binary_analysis.py  hex_analysis.py
│   ├── public_key_analysis.py  public_key_forensics.py
├── docs/
│   ├── architecture.md  usage.md  cryptography.md
│   ├── bitcoin_addresses.md  public_key_forensics.md  security.md
└── .github/workflows/tests.yml
```

## Dependencies

| Dependency | Role | Constraint |
| --- | --- | --- |
| `cryptography` | secp256k1 operations via OpenSSL | `>=42,<52` |
| `streamlit` (optional) | Graphical interface | `>=1.50,<2` |
| `pytest`, `pytest-cov`, `hypothesis` (dev) | Tests and property tests | see `pyproject.toml` |
| `ruff` (dev) | Linting and formatting | `>=0.6,<1` |
| `mypy` (dev) | Static typing | `>=1.10,<2` |

`hashlib`, `hmac`, `json`, `csv`, `argparse`, `dataclasses`, `pathlib`, and
`logging` come from the standard library.

## How it works

- [Architecture](docs/architecture.md) — layering, data flow, invariants, and
  extension points.
- [Cryptography](docs/cryptography.md) — hashing vs encryption vs encoding,
  secp256k1 parameters, encodings, and failure behaviour.
- [Bitcoin addresses](docs/bitcoin_addresses.md) — P2PKH/P2WPKH/P2SH-P2WPKH
  derivation, networks, scriptPubKeys, vectors, and limitations.
- [Public-key forensics](docs/public_key_forensics.md) — every measured angle, the
  probability model, the evidence-family score, and the hard limits.
- [Security](docs/security.md) — threat model, non-goals, and safe-use
  checklist.
- [Usage](docs/usage.md) — complete CLI reference and Python API examples.

## Known limitations

- Only P2PKH, P2WPKH, and P2SH-P2WPKH addresses are **derived**. Generic P2SH,
  P2WSH, and Taproot-style outputs can be decoded and validated but not created.
- No WIF encoding, BIP-32/39 derivation, signing, PSBT, or keystore support.
- No blockchain access: balances and history are out of scope.
- RIPEMD-160 depends on the OpenSSL build; unavailable backends cause a clear
  error.
- The tool cannot detect whether a supplied key controls funds. Use synthetic
  values.
- The structural forecast cannot confirm or refute that a key corresponds to a
  small scalar: that would require solving the discrete logarithm, which this
  project does not attempt. Probabilities assume uniformly random 256-bit values.
- Reports you export may contain the hexadecimal data you supplied. Treat them
  accordingly.

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
run `make check` before opening a pull request. Never include real private keys,
seed phrases, or funded wallet data in issues, tests, or examples.

## License

Released under the [MIT License](LICENSE).

BinaryCryptoLab is an educational and analytical tool. It is provided without
any warranty and does not guarantee the security of any wallet, key, or address.
