# Architecture

BinaryCryptoLab is a small, layered Python package. The goal of the layering is
that **validation happens once**, **cryptography is delegated to a maintained
library**, and **no private key can reach a report by accident**.

## Layers

```
                +---------------------------+
                |     CLI  /  Streamlit     |   presentation
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |    analysis.py            |   use-case orchestration
                |    reports/               |
                +-------------+-------------+
                              |
        +---------------------+----------------------+
        |                     |                      |
        v                     v                      v
+---------------+     +---------------+      +---------------+
| validation    |     | statistics    |      | models        |
| binary/hex    |     | bit/byte      |      | dataclasses   |
+-------+-------+     +-------+-------+      +---------------+
        |                     |
        v                     v
+---------------+     +---------------+      +---------------+
| binary_utils  |     | byte_ops      |      | formatting    |
| hex_utils     |     | bit_ops       |      | logging       |
+-------+-------+     +-------+-------+      +---------------+
        |                     |
        +----------+----------+
                   |
                   v
   +-------------------------------+
   | hashing | base58 | bech32     |   encodings and digests
   | ecc     | bitcoin            |   secp256k1 and addresses
   +-------------------------------+
```

Dependencies point downwards only. `bitcoin` may use `ecc`, `hashing`,
`base58`, and `bech32`; the encoding modules never import `bitcoin`.

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `config.py` | Non-sensitive constants: application name, version, input limits, exit codes. |
| `exceptions.py` | Documented exception hierarchy rooted at `BinaryCryptoLabError`. |
| `validation.py` | Strict normalisation of binary, hexadecimal, and decimal input; size limits. |
| `binary_utils.py` | Binary ↔ integer/hex/bytes conversion with explicit padding policy. |
| `hex_utils.py` | Hex ↔ integer/bytes/text conversion; text decoding only on request. |
| `bit_operations.py` | Bit counting, masks, shifts, masks, ranges, comparisons, Hamming distance. |
| `byte_operations.py` | Byte conversion, XOR, Hamming distance, chunking, slicing, endianness. |
| `statistics.py` | Bit statistics, byte histograms, Shannon entropy. |
| `analysis.py` | Engines that turn validated input into `BinaryAnalysis` / `HexAnalysis` / `AnalysisResult`. |
| `hashing.py` | SHA-256, SHA-512, double SHA-256, RIPEMD-160, HASH160, algorithm registry. |
| `ecc.py` | secp256k1 domain parameters, scalar validation, public-key derivation/parsing via `cryptography`. |
| `base58.py` | Base58 and Base58Check encode/decode with constant-time checksum comparison. |
| `bech32.py` | Bech32/Bech32m checksums and BIP-173/BIP-350 SegWit address encoding. |
| `bitcoin.py` | Network parameters, P2PKH/P2WPKH derivation, address decoding and validation. |
| `models/analysis_result.py` | Frozen dataclasses shared by the analysis engines, reports, CLI, and GUI. |
| `reports/` | Deterministic JSON and long-format CSV rendering plus atomic file writes. |
| `utils/` | Terminal-safe formatting helpers and stderr logging configuration. |
| `cli.py` | argparse CLI, exit codes, error boundary, private-key warnings. |
| `gui/` | Optional Streamlit UI (`app.py`), Streamlit-free service layer (`service.py`), launcher. |

## Data flow

1. **Presentation** collects input (CLI argument, GUI widget, or library call).
2. **`validation`** removes allowed whitespace, strips an optional prefix, checks
   the character set, rejects empty input, enforces a size limit, and applies
   the documented odd-length hexadecimal policy.
3. **Analysis engines** call conversion utilities and `statistics` to build an
   immutable `BinaryAnalysis` or `HexAnalysis`.
4. **`AnalysisResult`** wraps the analysis together with optional hash, public
   key, address, and warning sections. It has a `to_dict()` method that is
   guaranteed JSON-serialisable.
5. **Reports** render the result to JSON or CSV and write atomically.
6. **Presentation** prints a table, writes a file, or offers download buttons.

## Design decisions

### Immutable, typed result models

All result objects are `@dataclass(frozen=True, slots=True)`. Reports and the
GUI receive the same data, and a caller cannot mutate a result that has already
been serialised by another component.

### Private keys cannot enter the model

`AnalysisResult` accepts an input type of `"private_key"`, but its constructor
enforces that both `original_input` and `normalized_input` equal the literal
marker `<redacted>`. Supplying anything else raises `ValueError`. The CLI and
GUI therefore cannot store a scalar in a report even if a future change forgets
to redact it.

Private scalars are accepted only by `ecc.parse_private_scalar` and
`ecc.derive_public_key`, which never return them. Error messages describe the
valid range without echoing the value.

### Explicit ambiguity resolution

Where an operation could be ambiguous, the API requires the caller to be
explicit:

* `int_to_bytes` / `bytes_to_int` require `byteorder`.
* `bitwise_not` requires a width.
* `int_to_binary` requires a width when padding is wanted.
* Private scalars default to hexadecimal, but the base is a parameter and a CLI
  option.
* Binary input that is not byte-aligned is left-padded for byte statistics, and
  the number of padding bits is reported.

### Representation is preserved

* Binary analysis records the textual width, so leading zeros contribute to
  bit statistics.
* Hexadecimal → binary conversion is nibble-by-nibble, so `"2d"` becomes
  `"00101101"`, not `"101101"`.
* The original user input is stored verbatim in `original_input` for reports
  (except for private scalar input and hashed text/file content).

### One cryptographic dependency

Elliptic-curve arithmetic comes exclusively from [`cryptography`]
(OpenSSL). There is no hand-written point multiplication, no custom curve
arithmetic, and no fallback implementation. RIPEMD-160 availability is probed at
runtime; when it is missing, `UnsupportedHashError` is raised and no substitute
algorithm is used.

### Deterministic, atomic reports

* JSON uses `sort_keys=True` by default and rejects NaN/Infinity.
* CSV is a long-format table with a fixed row order.
* Both writers create missing parent directories (opt-out available), refuse to
  overwrite by default, and write through a temporary file followed by
  `os.replace`, so a crash cannot leave a truncated report.

### CLI and GUI share behaviour

The Streamlit interface calls the same analysis, hashing, ECC, and Bitcoin
functions as the CLI. `gui/service.py` contains only orchestration and is
Streamlit-free, which keeps it unit-testable without the optional dependency.

## Error handling

All expected failures derive from `BinaryCryptoLabError`:

```
BinaryCryptoLabError
├── ConfigurationError
├── InputValidationError
│   ├── InvalidBinaryError
│   ├── InvalidHexError
│   └── InvalidDecimalError
├── InvalidPrivateKeyError
├── InvalidPublicKeyError
├── UnsupportedHashError
├── AddressEncodingError
│   ├── Base58Error
│   │   └── InvalidBase58Error
│   └── Bech32Error
│       └── InvalidBech32Error
└── ReportGenerationError
```

The CLI catches this hierarchy at its boundary, prints `error: <message>` to
stderr, and returns exit code 1. Unexpected exceptions are reported without a
traceback unless `--debug` is used.

## Testing strategy

* Deterministic unit tests for every public function.
* Published vectors: FIPS 180-4, RIPEMD-160, BIP-173, BIP-350, SEC 2, and the
  Bitcoin wiki address example.
* Hypothesis property tests for round-trips (binary, hex, Base58, XOR,
  entropy bounds, scalar ranges).
* CLI tests run in-process and assert exit codes, stdout/stderr, and report
  files.
* Streamlit `AppTest` tests run the real UI script when the optional dependency
  is installed; otherwise they skip.

## Resource limits

`InputLimits` caps binary digits (100,000), hexadecimal digits (100,000), and
decimal digits (10,000) before any expensive conversion. File hashing via the
CLI is capped at 64 MiB. The limits are intentionally generous for an
educational tool and can be lowered per call or per command.
