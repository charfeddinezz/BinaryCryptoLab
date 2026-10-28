# Usage guide

This guide covers installation, every command, every option, the Python API, and
the optional graphical interface. All commands and outputs shown here were run
against version 1.1.0.

## Installation

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"        # development: tests, lint, typing
# or, for runtime only:
python -m pip install .
```

### Windows (PowerShell)

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If PowerShell blocks activation scripts, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Optional graphical interface

```bash
python -m pip install -e ".[gui]"
binarycryptolab-gui
```

## Command-line overview

```text
binarycryptolab [--version] [-v|--verbose] [--debug] COMMAND ...

COMMAND
  analyze-binary   analyse a binary string
  analyze-hex      analyse a hexadecimal string
  hash             hash bytes, text, or a file
  public-key        derive a secp256k1 public key from a TEST private scalar
  bitcoin-address   derive a Bitcoin address from a public key
  decode-address    decode and validate a Bitcoin address
  dissect-public-key  dissect a public key and forecast its structure
```

Global options must appear **before** the command:

| Option | Meaning |
| --- | --- |
| `--version` | Print the version and exit. |
| `-v`, `--verbose` | Enable `INFO` log messages on stderr. |
| `--debug` | Show tracebacks for unexpected errors (development only). |

Every command accepts `--help`, for example
`binarycryptolab analyze-binary --help`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Expected runtime error: invalid input, unknown algorithm, I/O failure, refusing to overwrite. |
| `2` | Usage error: unknown command, missing or conflicting arguments (argparse). |
| `130` | Interrupted with Ctrl-C. |

Expected errors print `error: ...` to stderr and never include a traceback or a
private scalar.

## analyze-binary

```text
binarycryptolab analyze-binary INPUT [--max-length N]
                               [--format {text,json,csv}]
                               [--output PATH] [--overwrite]
```

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

Notes:

* An optional `0b` prefix and ASCII whitespace are accepted.
* Leading zeros count as bits in the textual statistics.
* Byte statistics use left padding; `Padding bits` reports how many zeros were
  added.
* `--max-length` defaults to 100,000 bits.

## analyze-hex

```text
binarycryptolab analyze-hex INPUT [--max-length N] [--strict-hex]
                           [--format {text,json,csv}]
                           [--output PATH] [--overwrite]
```

```bash
binarycryptolab analyze-hex 2d
```

```text
BinaryCryptoLab 1.1.0 - hexadecimal analysis

Field              Value
-----------------  ---------------------------------------------------------------------------------
Input              2d
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

Notes:

* Upper- and lowercase digits, an optional `0x` prefix, and whitespace are
  accepted.
* Odd-length input is padded with one leading zero nibble and flagged in the
  warnings. Use `--strict-hex` to reject it instead.
* Hexadecimal input is **not** assumed to be UTF-8. The `UTF-8 preview` row is
  informational and shows `(not UTF-8 text)` when decoding fails. Use the Python
  API (`hex_utils.hex_to_text`) with an explicit encoding to decode text.

## hash

```text
binarycryptolab hash [--algorithm NAME]
                     (--hex HEX | --binary BIN | --text TEXT | --file PATH)
                     [--format {text,json,csv}] [--output PATH] [--overwrite]
```

Algorithms: `sha256` (default), `sha512`, `double-sha256`, `ripemd160`,
`hash160`. Aliases `sha-256`, `sha256d`, `hash256`, and `ripemd-160` are
accepted.

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

Other examples:

```bash
binarycryptolab hash --algorithm sha256 --text "abc"
binarycryptolab hash --algorithm double-sha256 --binary 101101
binarycryptolab hash --algorithm hash160 --hex 02
binarycryptolab hash --algorithm sha256 --file ./artifact.bin
```

* `--hex` hashes the decoded bytes, not the characters.
* `--binary` left-pads the bit string to a byte boundary.
* `--text` hashes UTF-8 bytes. The text itself is omitted from reports.
* `--file` hashes file contents up to 64 MiB; only the file name and size appear
  in reports.
* If RIPEMD-160 is unavailable in the Python build, the command exits with code
  1 and explains the limitation. No other algorithm is substituted.

## public-key

```text
binarycryptolab public-key (--private-key SCALAR | --prompt-private-key)
                           [--private-key-base {10,16}]
                           [--format {compressed,uncompressed,both}]
                           [--report-format {text,json,csv}]
                           [--output PATH] [--overwrite]
```

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

The CLI always prints a security warning to stderr when a scalar is supplied:

```text
SECURITY: a private key supplied as a command-line argument can be captured by shell
history, process listings, or terminal logging. Use synthetic test values only. Prefer
--prompt-private-key (hidden input) or the Python API.
```

Notes:

* Scalars are hexadecimal by default; use `--private-key-base 10` for decimal.
* Valid range: `1 <= k < n`. Out-of-range values exit with code 1 and the error
  never contains the scalar.
* `--prompt-private-key` reads the scalar with hidden input (safer than an
  argument, though still visible to a compromised machine).
* Use `--report-format json|csv` with `--output` to save a report. Reports
  contain `<redacted>` for the input fields and never contain the scalar.

## bitcoin-address

```text
binarycryptolab bitcoin-address --public-key HEX
                                [--type {p2pkh,p2wpkh,p2sh-p2wpkh}]
                                [--network {mainnet,testnet,regtest,signet}]
                                [--report-format {text,json,csv}]
                                [--output PATH] [--overwrite]
```

```bash
export PUB=0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
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

Warnings:
  - Address derivation is a local computation; no blockchain data was queried.
  - An address does not prove ownership and does not contain funds by itself.
```

Notes:

* P2WPKH and P2SH-P2WPKH require a compressed public key. Supplying the
  uncompressed form exits with code 1 and a specific message.
* P2PKH accepts both encodings and records which one was used.
* No blockchain query is performed. The output never claims that an address has
  funds.

## decode-address

```text
binarycryptolab decode-address ADDRESS [--network NETWORK]
                                       [--report-format {text,json,csv}]
                                       [--output PATH] [--overwrite]
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

* Base58Check addresses are checked for checksum, length, and version byte.
* Bech32 addresses are checked for checksum variant, HRP, witness version, and
  program length.
* Testnet, signet, and regtest share a Base58 version byte; without
  `--network`, the result is marked ambiguous.
* P2SH, P2WSH, and witness-v1+ outputs are recognised for validation but are not
  derived by this tool.


## dissect-public-key

```text
binarycryptolab dissect-public-key (--public-key HEX | --input-file PATH)
                                  [--depth {standard,deep}]
                                  [--networks LIST] [--art]
                                  [--report-format {text,json,csv}]
                                  [--output PATH] [--overwrite]
```

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

Forecast
  Verdict         : consistent with a uniformly random public key
  Size class      : full 256-bit magnitude
  Structure score : 0.0/100
  Structure bits  : 0.0 (above the noise floor)
  Fisher p        : 9.517e-01
  Bonferroni p    : 1.000e+00
  Recoverable     : no
```

The report continues with the hypotheses, the discrete-logarithm cost table, the
16-row address matrix, digests, representations, and bit profiles. Run
`--depth deep` for extra encodings, limb tables, SHA-512 digests, and bit grids
(`--art` prints the grids in text mode).

Options:

| Option | Meaning |
| --- | --- |
| `--public-key HEX` | A single SEC 1 public key (compressed, uncompressed, or 64 raw bytes). |
| `--input-file PATH` | Batch mode: one key per line; blank lines and `#` comments are skipped; at most 1000 keys. |
| `--depth` | `standard` (default) or `deep`. |
| `--networks` | Comma-separated subset of `mainnet,testnet,signet,regtest`. |
| `--art` | Include ASCII bit grids in the text report. |
| `--report-format` | `text` (default), `json`, or `csv`. |
| `--output` / `--overwrite` | Write to a file; existing files are protected. |

Batch mode with `--report-format csv` emits `key_index,section,key,value` rows so
a spreadsheet can hold hundreds of keys; `--report-format json` emits a JSON array
with an `index` field per key.

### Reading the forecast

The score is a statistical reading of the key's structure, not key recovery. See
[`public_key_forensics.md`](public_key_forensics.md) for the exact formulas, the
evidence families, the Fisher/Bonferroni combination, the Bayes factors, and the
hypothesis priors. `recoverable` is always `false`: BinaryCryptoLab does not
attack the discrete logarithm.

The `Randomness battery` section runs seven tests over `x ‖ y` and reports each
p-value, the Fisher combination, a Bonferroni bound, and the family-wise verdict.
The `Evidence families` table shows which measurements survived de-duplication,
and the hypotheses table prints each prior, log2 Bayes factor, and posterior.

You can run the battery and the special functions directly:

```python
from binarycryptolab.randomness import bits_from_bytes, randomness_report
from binarycryptolab.special_functions import chi_square_sf, fisher_combine

key_bytes = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
report = randomness_report(bits_from_bytes(key_bytes), data=key_bytes)
print(report.familywise_pass, f"{report.fisher_p_value:.3f}")  # True 0.978

print(chi_square_sf(1, 3.841458820694124))  # 0.05
print(fisher_combine([0.5, 0.5])[1])  # 0.5966...
```

### Python API

```python
from binarycryptolab import dissect_public_key

dissection = dissect_public_key(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    depth="deep",
)
print(dissection.forecast.structure_score)  # 0.0
print(dissection.x.leading_zero_bits)  # 1
print(dissection.addresses[0].address)  # 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
print(dissection.as_dict()["forecast"]["recoverable"])  # False
```

## Reports

All report-capable commands share these options:

| Option | Meaning |
| --- | --- |
| `--format` (analysis/hash) or `--report-format` (key/address) | `text`, `json`, or `csv`. |
| `--output PATH` | Write to `PATH` instead of stdout. Missing directories are created. |
| `--overwrite` | Permit replacing an existing file. Without it the command exits with code 1. |

```bash
binarycryptolab analyze-binary 101101 --format json --output reports/binary.json
binarycryptolab analyze-hex 2D --format csv --output reports/hex.csv
binarycryptolab public-key --private-key 1 --report-format json --output reports/key.json
```

JSON reports contain the application name and version, a UTC timestamp, the
input type, non-sensitive input, analysis sections, hashes, public key and
address data when present, the `public_key_forensics` section for dissections,
warnings, and security notes. CSV reports use a
long-format table:

```csv
section,key,value
application,name,BinaryCryptoLab
application,version,1.1.0
application,generated_at_utc,2026-10-27T20:25:48Z
input,type,hex
input,original,2d
input,normalized,2d
hexadecimal,value,2d
hexadecimal,digits,2
...
byte_frequency,0x2d,1
```

Files are written atomically (temporary file plus `os.replace`), so an
interrupted write cannot leave a truncated report.

## Python API

```python
from binarycryptolab import analyze_binary, analyze_hex, hash160, sha256

result = analyze_binary("101101")
print(result.integer_value)  # 45
print(result.hexadecimal)  # 2d
print(result.bit_stats.hamming_weight)  # 4

hex_result = analyze_hex("2d")
print(hex_result.binary)  # 00101101

print(sha256(b"abc").hex())
print(hash160(b"\x02").hex())
```

Bit and byte operations are explicit about widths and byte order:

```python
from binarycryptolab.bit_operations import bitwise_not, extract_bit_range
from binarycryptolab.byte_operations import int_to_bytes, bytes_to_int

print(bin(bitwise_not(0b1010, width=4)))  # 0b101
print(bin(extract_bit_range(0b101101, 1, 5)))  # 0b110

data = int_to_bytes(258, length=2, byteorder="big")
print(data.hex())  # 0102
print(bytes_to_int(data, byteorder="big"))  # 258
```

Public keys and addresses:

```python
from binarycryptolab.bitcoin import address_from_public_key, decode_address
from binarycryptolab.ecc import public_key_from_private

info = public_key_from_private(1)  # synthetic test scalar
print(info.compressed_hex)

address = address_from_public_key(info.compressed_hex, address_type="p2wpkh")
print(address.address)  # bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

print(decode_address(address.address).payload_hex)
```

Reports:

```python
from binarycryptolab import analyze
from binarycryptolab.reports import write_json, write_csv

write_json(analyze("binary", "101101"), "reports/binary.json")
write_csv(analyze("binary", "101101"), "reports/binary.csv")
```

Hashing text with a defined encoding and converting hexadecimal text explicitly:

```python
from binarycryptolab.hex_utils import hex_to_text, text_to_hex

print(hex_to_text("48656c6c6f"))  # Hello
print(text_to_hex("Hello"))  # 48656c6c6f
```

## Graphical interface

```bash
python -m pip install -e ".[gui]"
binarycryptolab-gui
```

Then open <http://127.0.0.1:8501>. The launcher binds to localhost by default.
Extra arguments are forwarded to Streamlit, for example:

```bash
binarycryptolab-gui --server.port=8600
```

The interface provides analysis, hashing, public-key derivation, **key
forensics**, and address derivation tabs, with JSON and CSV download buttons. The
forensics tab exposes depth, network selection, bit grids, findings, hypotheses,
the mirror point, and the keyspace table. It performs no network requests, and it
never stores a private scalar in a downloadable result.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `error: hexadecimal input has an odd number of digits` | Odd-length input is padded with a leading zero by default; pass `--strict-hex` if you want it rejected. This message appears only with `--strict-hex`. |
| `error: RIPEMD-160 is not available` | Your Python/OpenSSL build lacks RIPEMD-160. Install a build that provides it; the tool will not substitute another hash. |
| `error: refusing to overwrite existing file` | Pass `--overwrite` or choose another path. |
| `unexpected error: ...` | Re-run with `--debug` before the command for a traceback and report the issue. |
| GUI shows "requires Streamlit" | Install the optional extra: `python -m pip install -e ".[gui]"`. |
| `error: public key #N is invalid` | Batch dissection names the failing line; fix or remove that line. |
| `error: input file contains more than 1000 keys` | Split the file into batches of at most 1000 keys. |
