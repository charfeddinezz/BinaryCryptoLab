"""Command-line interface.

The CLI is built with :mod:`argparse` from the standard library so that the
core tool has no runtime dependency beyond ``cryptography``.  It follows these
rules:

* Expected failures produce a concise ``error:`` message on stderr and exit
  code ``1``; usage errors exit with ``2``; success exits with ``0``.
* Stack traces are hidden unless ``--debug`` is passed.
* Private scalars are never echoed, logged, or written to reports.  A warning
  about shell history and process inspection is printed whenever a private key
  is supplied, and a hidden-prompt alternative is offered.
* Reports are written atomically and never overwrite files unless
  ``--overwrite`` is given.

Run ``binarycryptolab --help`` or ``binarycryptolab <command> --help`` for
details.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import io
import json
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Final

from ._version import __version__
from .address_compare import AddressComparison, compare_addresses
from .address_forensics import (
    AddressDissection,
    ControlledExperiment,
    controlled_experiment,
    dissect_address,
)
from .analysis import analyze, attach_hashes
from .binary_utils import binary_to_bytes
from .bitcoin import Network, address_from_public_key, decode_address
from .config import APP_NAME, EXIT_ERROR, EXIT_SUCCESS, EXIT_USAGE, MAX_FILE_HASH_BYTES
from .ecc import (
    CURVE_ORDER,
    parse_private_scalar,
    public_key_from_private,
    public_key_info_from_hex,
)
from .exceptions import (
    BinaryCryptoLabError,
    InputValidationError,
    InvalidPrivateKeyError,
    ReportGenerationError,
)
from .forensics import (
    ALL_NETWORKS,
    DEPTH_LEVELS,
    PublicKeyDissection,
    dissect_many,
    dissect_public_key,
)
from .hashing import HashAlgorithm, hash_bytes
from .hex_utils import hex_to_bytes
from .key_reconstruction import (
    HEX_DIGITS,
    MAX_UNKNOWN_BITS,
    ComparisonReport,
    TemplateSolution,
    compare_keys,
    parse_template,
    solve_template,
)
from .mining import MiningEstimate, estimate_prefix_mining
from .models.analysis_result import REDACTED, AnalysisResult
from .reports import render_csv, render_json, write_csv, write_json
from .reports._io import atomic_write_text, resolve_target
from .script_recovery import CandidateKey, ScriptRecovery, recover_script
from .utils.formatting import (
    abbreviate,
    format_bit_row,
    format_byte_row,
    format_frequency,
    format_table,
    join_warning_lines,
    safe_display,
)
from .utils.logging_utils import configure_logging, get_logger
from .utxo_audit import UtxoAudit, audit_address_data
from .validation import normalize_hex

__all__ = ["build_parser", "main"]

_LOGGER = get_logger("cli")

_EPILOG: Final = """\
examples:
  binarycryptolab analyze-binary 101101
  binarycryptolab analyze-hex 2D
  binarycryptolab analyze-hex 2d --format json --output report.json
  binarycryptolab hash --algorithm sha256 --hex 2D
  binarycryptolab public-key --private-key 1 --format compressed
  binarycryptolab bitcoin-address --public-key 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 --type p2wpkh
  binarycryptolab decode-address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --network mainnet
  binarycryptolab dissect-public-key --public-key 0279BE667E...F81798 --depth deep
  binarycryptolab dissect-public-key --input-file keys.txt --format csv --output keys.csv

security:
  Use synthetic test values only.  Command-line arguments can be recorded in
  shell history and are visible to other local processes.  Prefer
  --prompt-private-key (hidden input) or the Python API for sensitive values.
  This tool never contacts the network and never stores private keys.
"""

#: Maximum number of public keys accepted in one batch dissection.
MAX_BATCH_KEYS: Final = 1000

_FORENSICS_WARNINGS: Final = (
    "The forecast is a statistical reading of a public key, not key recovery.",
    "No blockchain data was queried; ownership, balance, and history are unknown.",
    "Addresses for testnet, signet, and regtest are for testing only.",
)

_PRIVATE_KEY_WARNING: Final = (
    "SECURITY: a private key supplied as a command-line argument can be captured by "
    "shell history, process listings, or terminal logging. Use synthetic test values "
    "only. Prefer --prompt-private-key (hidden input) or the Python API."
)


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description=(
            "Local toolkit for binary/hex analysis, secp256k1 public-key derivation, "
            "hashing, and Bitcoin address encoding."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable informational log messages on stderr",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show tracebacks for unexpected errors (development only)",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    binary = subparsers.add_parser(
        "analyze-binary",
        help="analyse a binary string",
        description="Analyse a binary string (optional 0b prefix and whitespace).",
    )
    binary.add_argument("input", help="binary string, e.g. 101101")
    binary.add_argument(
        "--max-length",
        type=_positive_int,
        default=None,
        help="maximum number of bits accepted (default: 100000)",
    )
    _add_report_options(binary, flag="--format")
    binary.set_defaults(handler=_cmd_analyze_binary)

    hexadecimal = subparsers.add_parser(
        "analyze-hex",
        help="analyse a hexadecimal string",
        description="Analyse a hexadecimal string (optional 0x prefix, mixed case).",
    )
    hexadecimal.add_argument("input", help="hexadecimal string, e.g. 2D")
    hexadecimal.add_argument(
        "--max-length",
        type=_positive_int,
        default=None,
        help="maximum number of hexadecimal digits accepted (default: 100000)",
    )
    hexadecimal.add_argument(
        "--strict-hex",
        action="store_true",
        help="reject odd-length hexadecimal input instead of left-padding it",
    )
    _add_report_options(hexadecimal, flag="--format")
    hexadecimal.set_defaults(handler=_cmd_analyze_hex)

    hashing = subparsers.add_parser(
        "hash",
        help="hash bytes or text",
        description=(
            "Hash bytes supplied as hexadecimal, binary, text, or a file. "
            "Text and file contents are not stored in reports."
        ),
    )
    hashing.add_argument(
        "--algorithm",
        default=HashAlgorithm.SHA256.value,
        help="hash algorithm: sha256, sha512, double-sha256, ripemd160, hash160",
    )
    source = hashing.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", help="hash the bytes encoded by this hexadecimal string")
    source.add_argument("--binary", help="hash the bytes encoded by this binary string")
    source.add_argument("--text", help="hash this UTF-8 text")
    source.add_argument("--file", help=f"hash a file (max {MAX_FILE_HASH_BYTES} bytes)")
    _add_report_options(hashing, flag="--format")
    hashing.set_defaults(handler=_cmd_hash)

    public_key = subparsers.add_parser(
        "public-key",
        help="derive a secp256k1 public key from a TEST private scalar",
        description=(
            "Derive a secp256k1 public key using the cryptography library. "
            "The private scalar is validated but never printed, logged, or stored."
        ),
    )
    key_source = public_key.add_mutually_exclusive_group(required=True)
    key_source.add_argument(
        "--private-key",
        help="private scalar in hexadecimal (or decimal with --private-key-base 10)",
    )
    key_source.add_argument(
        "--prompt-private-key",
        action="store_true",
        help="read the private scalar from a hidden interactive prompt (safer)",
    )
    public_key.add_argument(
        "--private-key-base",
        type=int,
        choices=(10, 16),
        default=16,
        help="numeric base for --private-key (default: 16)",
    )
    public_key.add_argument(
        "--format",
        choices=("compressed", "uncompressed", "both"),
        default="compressed",
        help="public key encoding to display (default: compressed)",
    )
    _add_report_options(public_key, flag="--report-format")
    public_key.set_defaults(handler=_cmd_public_key)

    address = subparsers.add_parser(
        "bitcoin-address",
        help="derive a Bitcoin address from a public key",
        description=(
            "Derive a P2PKH, P2WPKH, or P2SH-P2WPKH address from a secp256k1 "
            "public key. No blockchain data is queried."
        ),
    )
    address.add_argument("--public-key", required=True, help="SEC 1 public key in hexadecimal")
    address.add_argument(
        "--type",
        choices=("p2pkh", "p2wpkh", "p2sh-p2wpkh"),
        default="p2pkh",
        help="address type (default: p2pkh)",
    )
    address.add_argument(
        "--network",
        choices=("mainnet", "testnet", "regtest", "signet"),
        default="mainnet",
        help="Bitcoin network (default: mainnet)",
    )
    _add_report_options(address, flag="--report-format")
    address.set_defaults(handler=_cmd_bitcoin_address)

    decoder = subparsers.add_parser(
        "decode-address",
        help="decode and validate a Bitcoin address",
        description="Validate checksum, version/HRP, witness version, and program length.",
    )
    decoder.add_argument("address", help="address to decode")
    decoder.add_argument(
        "--network",
        choices=("mainnet", "testnet", "regtest", "signet"),
        default=None,
        help="expected network (default: infer)",
    )
    _add_report_options(decoder, flag="--report-format")
    decoder.set_defaults(handler=_cmd_decode_address)

    dissect = subparsers.add_parser(
        "dissect-public-key",
        help="dissect a public key from every public angle and forecast its structure",
        description=(
            "Decompose a secp256k1 public key: coordinates, encodings, bit and byte "
            "profiles, curve checks, digests, the full address matrix, structural "
            "findings, and a scored forecast. No private key is computed, searched "
            "for, or stored."
        ),
    )
    source = dissect.add_mutually_exclusive_group(required=True)
    source.add_argument("--public-key", help="SEC 1 public key in hexadecimal")
    source.add_argument(
        "--input-file",
        metavar="PATH",
        help=f"file with one public key per line (blank lines and # comments ignored, "
        f"max {MAX_BATCH_KEYS} keys)",
    )
    dissect.add_argument(
        "--depth",
        choices=DEPTH_LEVELS,
        default="standard",
        help="standard report, or deep for extra encodings, limbs, and bit grids",
    )
    dissect.add_argument(
        "--networks",
        default=None,
        metavar="LIST",
        help="comma-separated networks for the address matrix "
        "(default: mainnet,testnet,signet,regtest)",
    )
    dissect.add_argument(
        "--art",
        action="store_true",
        help="include ASCII bit grids for x and y in the text report",
    )
    _add_report_options(dissect, flag="--report-format")
    dissect.set_defaults(handler=_cmd_dissect_public_key)

    assembler = subparsers.add_parser(
        "assemble-private-key",
        help="assemble a scalar from known hex digits plus a bounded search",
        description=(
            "Reduce everything known about a scalar to one scale of bits, then search "
            "the unknown hex window (at most 40 bits) and assemble the full 64-digit "
            "scalar. Every candidate is verified by re-deriving the public key. This "
            "does not and cannot derive a key from a public key alone."
        ),
    )
    assembler.add_argument("--public-key", required=True, help="SEC 1 public key in hexadecimal")
    assembler.add_argument(
        "--template",
        required=True,
        help=(
            f"{HEX_DIGITS} hex digits where '?' marks unknown digits, exactly one "
            "contiguous run, for example 0000...0000????????"
        ),
    )
    assembler.add_argument(
        "--max-unknown-bits",
        type=int,
        default=32,
        metavar="BITS",
        help=f"refuse templates wider than BITS unknown bits (default 32, max {MAX_UNKNOWN_BITS})",
    )
    assembler.add_argument(
        "--reveal",
        action="store_true",
        help="print the assembled scalar (it is a private key; it is redacted by default)",
    )
    _add_report_options(assembler, flag="--report-format")
    assembler.set_defaults(handler=_cmd_assemble_private_key)

    comparer = subparsers.add_parser(
        "compare-keys",
        help="segment a set of public keys and compare them position by position",
        description=(
            "Compare public coordinates nibble by nibble, report shared prefixes and "
            "suffixes, and detect small scalar offsets between keys. Nothing here "
            "solves a discrete logarithm over the full group."
        ),
    )
    comparator_source = comparer.add_mutually_exclusive_group(required=True)
    comparator_source.add_argument(
        "--public-key",
        action="append",
        metavar="KEY",
        help="public key in hexadecimal (repeat the option for each key)",
    )
    comparator_source.add_argument(
        "--input-file",
        metavar="PATH",
        help=f"file with one public key per line (max {MAX_BATCH_KEYS} keys)",
    )
    comparer.add_argument(
        "--max-delta-bits",
        type=int,
        default=16,
        metavar="BITS",
        help=f"scalar-difference window for the related-key check (default 16, max {MAX_UNKNOWN_BITS})",
    )
    comparer.add_argument(
        "--max-pairs",
        type=int,
        default=200,
        metavar="N",
        help="maximum number of key pairs to examine (default 200)",
    )
    _add_report_options(comparer, flag="--report-format")
    comparer.set_defaults(handler=_cmd_compare_keys)

    dissect_address_command = subparsers.add_parser(
        "dissect-address",
        help="dissect an address into every public fact and every backward cost",
        description=(
            "Decode and re-verify an address (checksum, version or HRP, locking "
            "script), profile its payload with exact statistical tests, state what it "
            "does and does not reveal on the single scale of bits, and price every "
            "step of the backward chain. No key is recovered."
        ),
    )
    dissect_address_command.add_argument(
        "address",
        nargs="*",
        help=(
            "one or more inputs: a Base58Check, Bech32, Bech32m, or CashAddr address, "
            "a BIP-21 payment URI, or a raw scriptPubKey in hexadecimal"
        ),
    )
    dissect_address_command.add_argument(
        "--input-file",
        default=None,
        metavar="PATH",
        help="read inputs one per line; blank lines and # comments are skipped",
    )
    dissect_address_command.add_argument(
        "--network",
        choices=("mainnet", "testnet", "regtest", "signet"),
        default=None,
        help="expected network (default: infer)",
    )
    dissect_address_command.add_argument(
        "--claimed-prefix",
        default=None,
        metavar="PREFIX",
        help="a vanity prefix declared in advance; only then is the p-value valid",
    )
    dissect_address_command.add_argument(
        "--redeem-script",
        default=None,
        metavar="HEX",
        help=(
            "a candidate redeem or witness script; verified against the address "
            "payload and classified (multisig, HTLC, timelock, ...)"
        ),
    )
    dissect_address_command.add_argument(
        "--xpub",
        default=None,
        metavar="KEY",
        help="an extended public key to search for this address (public derivation only)",
    )
    dissect_address_command.add_argument(
        "--index-range",
        default="0:20",
        metavar="START:COUNT",
        help="child indices examined with --xpub (default 0:20, count at most 10000)",
    )
    dissect_address_command.add_argument(
        "--stdin",
        action="store_true",
        help="read inputs from standard input, one per line",
    )
    dissect_address_command.add_argument(
        "--public-key",
        default=None,
        metavar="HEX",
        help=(
            "run the controlled experiment against this public key you own "
            "(derives P2PKH, P2WPKH, P2SH-P2WPKH, and Taproot)"
        ),
    )
    _add_report_options(dissect_address_command, flag="--report-format")
    dissect_address_command.set_defaults(handler=_cmd_dissect_address)

    audit_data_command = subparsers.add_parser(
        "audit-address-data",
        help="audit a UTXO export you supply, offline",
        description=(
            "Check a JSON export you produced yourself (node, wallet, or explorer) "
            "against an address: does every output pay to its script, do the totals "
            "add up, are there duplicates, and what is left after spent entries. No "
            "network request is made; the data is never trusted, only audited."
        ),
    )
    recover_command = subparsers.add_parser(
        "recover-script",
        help="recover the redeem script behind an address from candidate public keys",
        description=(
            "Enumerate every standard script the supplied public keys can produce "
            "(P2PK, every m-of-n multisig subset, CLTV timelocks, HTLC) and check which "
            "one hashes to the address. A match recovers the spending conditions "
            "exactly; a miss is reported with the catalogue's limits."
        ),
    )
    recover_command.add_argument("address", help="the address to analyse")
    recover_command.add_argument(
        "--candidate-key",
        action="append",
        default=[],
        metavar="HEX",
        help="a public key you plausibly control (repeatable, up to 15)",
    )
    recover_command.add_argument(
        "--hash-lock",
        action="append",
        default=[],
        metavar="HASH160",
        help="a 20-byte HASH160 digest to try in HTLC templates (repeatable)",
    )
    recover_command.add_argument(
        "--timelock",
        action="append",
        type=int,
        default=[],
        metavar="N",
        help="a CLTV height or time to try in timelock templates (repeatable)",
    )
    recover_command.add_argument(
        "--max-candidates",
        type=int,
        default=20_000,
        metavar="N",
        help="budget on enumerated scripts (default 20000)",
    )
    _add_report_options(recover_command, flag="--report-format")
    recover_command.set_defaults(handler=_cmd_recover_script)

    compare_command = subparsers.add_parser(
        "compare-addresses",
        help="relate a set of addresses: reuse, nesting, shared bits",
        description=(
            "Find structural relations between addresses: the same payload in two "
            "encodings, one address wrapping another's script, or long shared bit "
            "sequences with an exact probability."
        ),
    )
    compare_command.add_argument("address", nargs="+", help="two or more addresses")
    _add_report_options(compare_command, flag="--report-format")
    compare_command.set_defaults(handler=_cmd_compare_addresses)

    mining_command = subparsers.add_parser(
        "estimate-mining",
        help="price a vanity prefix in attempts and in measured wall-clock time",
        description=(
            "Convert a prefix into constrained bits with the exact counting model, "
            "then measure this machine's derivation rate and report the expected time, "
            "from 1e3 to 1e12 attempts per second."
        ),
    )
    mining_command.add_argument("address", help="an address fixing the encoding and version")
    mining_command.add_argument(
        "--prefix",
        default=None,
        metavar="PREFIX",
        help="the prefix to price (default: the address's own six characters)",
    )
    mining_command.add_argument(
        "--iterations",
        type=int,
        default=256,
        metavar="N",
        help="benchmark derivations, 1..5000 (default 256)",
    )
    _add_report_options(mining_command, flag="--report-format")
    mining_command.set_defaults(handler=_cmd_estimate_mining)

    audit_data_command.add_argument("address", help="the address the export describes")
    audit_data_command.add_argument(
        "--input-file",
        required=True,
        metavar="PATH",
        help="JSON file with a 'utxos' list (see docs/address_forensics.md)",
    )
    audit_data_command.add_argument(
        "--source",
        default=None,
        metavar="TEXT",
        help="provenance to record instead of the file's own 'source' field",
    )
    _add_report_options(audit_data_command, flag="--report-format")
    audit_data_command.set_defaults(handler=_cmd_audit_address_data)

    return parser


def _add_report_options(parser: argparse.ArgumentParser, *, flag: str) -> None:
    parser.add_argument(
        flag,
        dest="report_format",
        choices=("text", "json", "csv"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help="write the report to PATH instead of stdout",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow replacing an existing output file",
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _emit(
    result: AnalysisResult,
    *,
    report_format: str,
    output: str | None,
    overwrite: bool,
    renderer: Callable[[AnalysisResult], str],
) -> int:
    if report_format == "json":
        text = render_json(result)
    elif report_format == "csv":
        text = render_csv(result)
    else:
        text = renderer(result)
        if not text.endswith("\n"):
            text += "\n"
    if output:
        if report_format == "json":
            target = write_json(result, output, overwrite=overwrite)
        elif report_format == "csv":
            target = write_csv(result, output, overwrite=overwrite)
        else:
            target = resolve_target(output, overwrite=overwrite, create_parents=True)
            atomic_write_text(target, text, overwrite=overwrite)
        print(f"Report written to {target}")
    else:
        sys.stdout.write(text)
    return EXIT_SUCCESS


def _append_warnings(lines: list[str], warnings: tuple[str, ...]) -> None:
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.append(join_warning_lines(warnings))


def _header(title: str) -> str:
    return f"{APP_NAME} {__version__} - {title}"


def _render_binary_text(result: AnalysisResult) -> str:
    section = result.binary
    if section is None:  # pragma: no cover - defensive
        raise ReportGenerationError("binary analysis section is missing")
    rows = [
        ("Input", safe_display(section.original)),
        ("Normalized", safe_display(section.normalized, 160)),
        ("Grouped", section.grouped_display),
        ("Bit length", str(section.bit_length)),
        ("Decimal", safe_display(str(section.integer_value), 160)),
        ("Hexadecimal", section.hexadecimal),
        ("Bits", format_bit_row(section.bit_stats)),
        ("Bytes", safe_display(section.bytes_hex) or "(none)"),
        ("Byte length", str(section.byte_stats.byte_length)),
        ("Padding bits", str(section.padding_bits)),
        ("Complete bytes", str(section.complete_bytes)),
        ("Incomplete bits", str(section.incomplete_bits)),
        ("Byte stats", format_byte_row(section.byte_stats)),
        ("Byte frequency", format_frequency(section.byte_stats.byte_frequency)),
        ("Entropy", f"{section.byte_stats.entropy:.4f} bits/byte"),
    ]
    lines = [_header("binary analysis"), "", format_table(("Field", "Value"), rows)]
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _render_hex_text(result: AnalysisResult) -> str:
    section = result.hexadecimal
    if section is None:  # pragma: no cover - defensive
        raise ReportGenerationError("hexadecimal analysis section is missing")
    rows = [
        ("Input", safe_display(section.original)),
        ("Normalized", safe_display(section.normalized, 160)),
        ("Grouped", section.grouped_display),
        ("Digits", str(section.hex_length)),
        ("Integer (decimal)", safe_display(str(section.integer_value), 160)),
        ("Binary", safe_display(section.binary, 160)),
        ("Binary length", str(section.binary_length)),
        ("Bits", format_bit_row(section.bit_stats)),
        ("Bytes", safe_display(section.bytes_hex) or "(none)"),
        ("Byte length", str(section.byte_stats.byte_length)),
        ("Byte stats", format_byte_row(section.byte_stats)),
        ("Byte frequency", format_frequency(section.byte_stats.byte_frequency)),
        ("Entropy", f"{section.byte_stats.entropy:.4f} bits/byte"),
        (
            "UTF-8 preview",
            safe_display(repr(section.text_utf8)) if section.text_utf8 else "(not UTF-8 text)",
        ),
    ]
    lines = [_header("hexadecimal analysis"), "", format_table(("Field", "Value"), rows)]
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _render_hash_text(result: AnalysisResult) -> str:
    lines = [_header("hash"), ""]
    rows = []
    if result.input_type in {"text", "file"}:
        rows.append(("Input", result.original_input))
    for digest in result.hashes:
        rows.extend(
            [
                ("Algorithm", digest.algorithm.value),
                ("Digest (hex)", digest.hexdigest),
                ("Digest length", f"{digest.digest_length} bytes"),
                ("Input length", f"{digest.input_length} byte(s)"),
            ]
        )
    lines.append(format_table(("Field", "Value"), rows))
    if result.binary is not None:
        section = result.binary
        lines.extend(
            [
                "",
                "Input analysis:",
                format_table(
                    ("Field", "Value"),
                    [
                        ("Input type", "binary"),
                        ("Bit length", str(section.bit_length)),
                        ("Bits", format_bit_row(section.bit_stats)),
                        ("Byte length", str(section.byte_stats.byte_length)),
                    ],
                ),
            ]
        )
    elif result.hexadecimal is not None:
        hex_section = result.hexadecimal
        lines.extend(
            [
                "",
                "Input analysis:",
                format_table(
                    ("Field", "Value"),
                    [
                        ("Input type", "hex"),
                        ("Digits", str(hex_section.hex_length)),
                        ("Bit length", str(hex_section.binary_length)),
                        ("Byte length", str(hex_section.byte_stats.byte_length)),
                    ],
                ),
            ]
        )
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _render_public_key_text(result: AnalysisResult) -> str:
    info = result.public_key or {}
    display_format = str(result.extra.get("display_format", "compressed"))
    rows: list[tuple[str, str]] = [
        ("Curve", str(info.get("curve", "secp256k1"))),
        ("X", str(info.get("x", ""))),
        ("Y", str(info.get("y", ""))),
    ]
    if display_format in {"compressed", "both"}:
        rows.append(("Compressed", str(info.get("compressed_hex", ""))))
    if display_format in {"uncompressed", "both"}:
        rows.append(("Uncompressed", str(info.get("uncompressed_hex", ""))))
    rows.append(("Display format", display_format))
    lines = [_header("secp256k1 public key"), ""]
    lines.append(format_table(("Field", "Value"), rows))
    lines.append("")
    lines.append(f"Curve order (n): 0x{CURVE_ORDER:064x}")
    lines.append("A public key cannot be used to recover a private key.")
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _render_address_text(result: AnalysisResult) -> str:
    info = result.address or {}
    rows = [
        ("Address", str(info.get("address", ""))),
        ("Type", str(info.get("type", ""))),
        ("Network", str(info.get("network", ""))),
        ("HASH160", str(info.get("hash160", ""))),
        ("Public key", str(info.get("public_key_hex", ""))),
        ("Key encoding", str(info.get("public_key_encoding", ""))),
        (
            "Witness version",
            str(info.get("witness_version")) if info.get("witness_version") is not None else "-",
        ),
        ("Witness program", str(info.get("witness_program_hex") or "-")),
        ("scriptPubKey", str(info.get("script_pubkey_hex", ""))),
    ]
    lines = [_header("Bitcoin address"), "", format_table(("Field", "Value"), rows)]
    lines.append("")
    lines.append("No blockchain data was queried; ownership and balances are unknown.")
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _render_decoded_address_text(result: AnalysisResult) -> str:
    info = result.address or {}
    rows = [
        ("Address", str(info.get("address", ""))),
        ("Type", str(info.get("type", ""))),
        ("Network", str(info.get("network", ""))),
        ("Network ambiguous", "yes" if info.get("network_ambiguous") else "no"),
        ("Payload", str(info.get("payload_hex", ""))),
        (
            "Witness version",
            str(info.get("witness_version")) if info.get("witness_version") is not None else "-",
        ),
    ]
    lines = [_header("address validation"), "", format_table(("Field", "Value"), rows)]
    lines.append("")
    lines.append("Checksum, version/HRP, witness version, and program length were validated.")
    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _cmd_analyze_binary(args: argparse.Namespace) -> int:
    result = analyze("binary", args.input, max_length=args.max_length)
    _LOGGER.info("binary analysis completed")
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_binary_text,
    )


def _cmd_analyze_hex(args: argparse.Namespace) -> int:
    result = analyze(
        "hex",
        args.input,
        allow_odd_hex=not args.strict_hex,
        max_length=args.max_length,
    )
    _LOGGER.info("hexadecimal analysis completed")
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_hex_text,
    )


def _read_hash_input(args: argparse.Namespace) -> tuple[bytes, AnalysisResult]:
    if args.hex is not None:
        data = hex_to_bytes(args.hex, allow_odd=True)
        return data, analyze("hex", args.hex)
    if args.binary is not None:
        data = binary_to_bytes(args.binary)
        return data, analyze("binary", args.binary)
    if args.text is not None:
        data = args.text.encode("utf-8")
        message = (
            "Text input is hashed as UTF-8. Its content is intentionally omitted from "
            "reports and logs to avoid capturing secrets."
        )
        result = AnalysisResult(
            input_type="text",
            original_input=f"<text input omitted, {len(data)} bytes>",
            normalized_input="<omitted>",
            warnings=(message,),
            extra={"input_length_bytes": len(data)},
        )
        return data, result
    path = Path(args.file)
    if not path.exists():
        raise InputValidationError(f"file not found: {path}")
    if not path.is_file():
        raise InputValidationError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_HASH_BYTES:
        raise InputValidationError(
            f"file is too large to hash ({size} bytes); the limit is {MAX_FILE_HASH_BYTES} bytes"
        )
    data = path.read_bytes()
    result = AnalysisResult(
        input_type="file",
        original_input=f"<file: {path.name}, {len(data)} bytes>",
        normalized_input="<omitted>",
        warnings=(
            "File contents are hashed but not included in reports to avoid capturing secrets.",
        ),
        extra={"file_name": path.name, "input_length_bytes": len(data)},
    )
    return data, result


def _cmd_hash(args: argparse.Namespace) -> int:
    algorithm = HashAlgorithm.parse(args.algorithm)
    data, base_result = _read_hash_input(args)
    digest = hash_bytes(data, algorithm)
    result = attach_hashes(base_result, (digest,))
    _LOGGER.info("hash computation completed with %s", algorithm.value)
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_hash_text,
    )


def _cmd_public_key(args: argparse.Namespace) -> int:
    print(_PRIVATE_KEY_WARNING, file=sys.stderr)
    if args.prompt_private_key:
        scalar_text = getpass.getpass("Private scalar (input hidden): ")
    else:
        scalar_text = args.private_key
    scalar = parse_private_scalar(scalar_text, base=args.private_key_base)
    info = public_key_from_private(scalar)
    warnings = (
        "The private scalar was validated but is intentionally absent from this output.",
        "Use synthetic test values only; never reuse a test key in a funded wallet.",
    )
    result = AnalysisResult(
        input_type="private_key",
        original_input=REDACTED,
        normalized_input=REDACTED,
        public_key=info.as_dict(),
        warnings=warnings,
        extra={"display_format": args.format},
    )
    _LOGGER.info("public key derivation completed")
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_public_key_text,
    )


def _cmd_bitcoin_address(args: argparse.Namespace) -> int:
    public_info = public_key_info_from_hex(args.public_key)
    address_info = address_from_public_key(
        args.public_key, address_type=args.type, network=args.network
    )
    normalized = normalize_hex(args.public_key, allow_odd=False)
    warnings = [
        "Address derivation is a local computation; no blockchain data was queried.",
        "An address does not prove ownership and does not contain funds by itself.",
    ]
    if args.network in {"testnet", "regtest", "signet"}:
        warnings.append(f"{args.network} addresses are for testing only.")
    result = AnalysisResult(
        input_type="public_key",
        original_input=args.public_key,
        normalized_input=normalized,
        public_key=public_info.as_dict(),
        address=address_info.as_dict(),
        warnings=tuple(warnings),
    )
    _LOGGER.info("address derivation completed")
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_address_text,
    )


def _cmd_decode_address(args: argparse.Namespace) -> int:
    decoded = decode_address(args.address, args.network)
    warnings: list[str] = []
    if decoded.network_ambiguous:
        warnings.append(
            "This Base58 version byte is shared by testnet, signet, and regtest; "
            "the network shown is an inference."
        )
    if decoded.address_type in {"p2sh", "p2wsh"} or decoded.address_type.startswith("witness_v"):
        warnings.append(
            f"{decoded.address_type} addresses are decoded for validation only; "
            "this tool derives p2pkh and p2wpkh addresses."
        )
    result = AnalysisResult(
        input_type="address",
        original_input=args.address,
        normalized_input=args.address,
        address=decoded.as_dict(),
        warnings=tuple(warnings),
    )
    return _emit(
        result,
        report_format=args.report_format,
        output=args.output,
        overwrite=args.overwrite,
        renderer=_render_decoded_address_text,
    )


# ---------------------------------------------------------------------------
# Public-key forensics
# ---------------------------------------------------------------------------


def _parse_networks(text: str | None) -> tuple[Network, ...]:
    """Parse a comma-separated network list, preserving order and dropping duplicates."""
    if text is None:
        return tuple(ALL_NETWORKS)
    names = [part.strip() for part in text.split(",") if part.strip()]
    if not names:
        raise InputValidationError("--networks needs at least one network name")
    selected: list[Network] = []
    for name in names:
        network = Network.parse(name)
        if network not in selected:
            selected.append(network)
    return tuple(selected)


def _section(payload: dict[str, object], key: str) -> dict[str, object]:
    """Return a nested mapping, or an empty mapping when absent or mistyped."""
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _entries(payload: dict[str, object], key: str) -> list[dict[str, object]]:
    """Return a nested list of mappings, or an empty list when absent."""
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _as_float(value: object, default: float = 0.0) -> float:
    """Coerce a JSON value to ``float`` for display, falling back to a default."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_text_list(value: object) -> list[str]:
    """Coerce a JSON value to a list of strings, dropping anything else."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _probability_label(value: object) -> str:
    """Format a probability for the text report."""
    if not isinstance(value, (int, float)):
        return "-"
    number = float(value)
    if number >= 0.01:
        return f"{number:.3f}"
    return f"{number:.2e}"


def _render_forensics_text(result: AnalysisResult) -> str:
    """Render a deep public-key dissection as aligned text sections."""
    data = result.forensics or {}
    public_key = _section(data, "public_key")
    coordinates = _section(data, "coordinates")
    forecast = _section(data, "forecast")
    lines: list[str] = [_header("public key dissection"), ""]

    identity = [
        ("Curve", str(data.get("curve", ""))),
        ("Input encoding", str(_section(data, "input").get("encoding", ""))),
        ("Prefix byte", str(public_key.get("prefix_byte", ""))),
        ("y parity", str(public_key.get("y_parity", ""))),
        ("Compressed", str(public_key.get("compressed_hex", ""))),
        ("Uncompressed", str(public_key.get("uncompressed_hex", ""))),
        ("x-only (BIP-340)", str(public_key.get("x_only_hex", ""))),
        ("Depth", str(data.get("depth", ""))),
    ]
    lines.append(format_table(("Field", "Value"), identity))

    lines.append("")
    lines.append("Coordinates")
    coordinate_rows = []
    for name in ("x", "y"):
        profile = _section(coordinates, name)
        coordinate_rows.append(
            (
                name,
                abbreviate(str(profile.get("hexadecimal", "")), 30),
                str(profile.get("bit_length", "")),
                str(profile.get("leading_zero_bits", "")),
                str(profile.get("trailing_zero_bits", "")),
                str(profile.get("hamming_weight", "")),
                _probability_label(profile.get("hamming_p_value")),
                f"{_as_float(profile.get('byte_entropy')):.3f}",
                "even" if profile.get("is_even") else "odd",
            )
        )
    lines.append(
        format_table(
            (
                "Coord",
                "Hex",
                "Bits",
                "Lead 0s",
                "Trail 0s",
                "Weight",
                "Binomial p",
                "Entropy",
                "Parity",
            ),
            coordinate_rows,
        )
    )

    verification = _section(data, "verification")
    lines.append("")
    failed = [name for name, passed in verification.items() if not passed]
    if failed:
        lines.append("Curve verification: FAILED")
        for name in failed:
            lines.append(f"  - {name}")
    else:
        lines.append(f"Curve verification: all {len(verification)} checks passed")

    findings = _entries(data, "findings")
    lines.append("")
    lines.append(f"Structural findings ({len(findings)})")
    if findings:
        lines.append(
            format_table(
                ("Severity", "Code", "Evidence", "p"),
                [
                    (
                        str(finding.get("severity", "")),
                        str(finding.get("code", "")),
                        abbreviate(str(finding.get("evidence", "")), 58),
                        _probability_label(finding.get("probability")),
                    )
                    for finding in findings
                ],
            )
        )
        for finding in findings:
            lines.append(f"  - {finding.get('title', '')}: {finding.get('interpretation', '')}")
    else:
        lines.append("  none: the key looks like a uniformly random 256-bit point")

    randomness = _section(data, "randomness")
    lines.append("")
    lines.append("Randomness battery")
    tests = _entries(randomness, "tests")
    if tests:
        lines.append(
            format_table(
                ("Test", "Statistic", "p-value", "Result"),
                [
                    (
                        str(test.get("name", "")),
                        f"{_as_float(test.get('statistic')):.4f}",
                        f"{_as_float(test.get('p_value')):.3e}",
                        "pass" if test.get("passed") else "FAIL",
                    )
                    for test in tests
                ],
            )
        )
        lines.append(
            f"  Fisher p={_as_float(randomness.get('fisher_p_value')):.3e}; "
            f"Bonferroni p={_as_float(randomness.get('bonferroni_p_value')):.3e}; "
            f"family-wise {'pass' if randomness.get('familywise_pass') else 'FAIL'}"
        )
    else:
        lines.append("  none: the key material was too short for the battery")

    evidence = _entries(forecast, "evidence")
    if evidence:
        lines.append("")
        lines.append("  Evidence families (independent, strongest per family)")
        lines.append(
            format_table(
                ("Family", "p-value", "Bits", "Sources"),
                [
                    (
                        str(item.get("family", "")),
                        f"{_as_float(item.get('p_value')):.3e}",
                        f"{_as_float(item.get('surprisal_bits')):.1f}",
                        abbreviate(", ".join(_as_text_list(item.get("sources"))), 46),
                    )
                    for item in evidence
                ],
            )
        )

    lines.append("")
    lines.append("Forecast")
    lines.append(f"  Verdict         : {forecast.get('verdict', '')}")
    lines.append(f"  Size class      : {forecast.get('size_class', '')}")
    score = _as_float(forecast.get("structure_score"))
    surprisal = _as_float(forecast.get("total_surprisal_bits"))
    lines.append(f"  Structure score : {score:.1f}/100")
    lines.append(
        f"  Structure bits  : {_as_float(forecast.get('structure_bits')):.1f} (above the noise floor)"
    )
    lines.append(f"  Surprisal       : {surprisal:.1f} bits (raw, before combination)")
    lines.append(f"  Fisher p        : {_as_float(forecast.get('combined_p_value')):.3e}")
    lines.append(f"  Bonferroni p    : {_as_float(forecast.get('bonferroni_p_value')):.3e}")
    lines.append(f"  Recoverable     : {'yes' if forecast.get('recoverable') else 'no'}")
    lines.append("")
    lines.append("  Hypotheses (prior -> posterior via Bayes' rule)")
    hypotheses = _entries(forecast, "hypotheses")
    factors = _entries(forecast, "bayes_factors")
    if hypotheses:
        rows: list[tuple[str, str, str, str, str]] = []
        for index, item in enumerate(hypotheses):
            factor = factors[index] if index < len(factors) else {}
            rows.append(
                (
                    str(item.get("likelihood", "")),
                    f"{_as_float(factor.get('prior')):.2f}",
                    f"{_as_float(item.get('score')):.4f}",
                    f"{_as_float(factor.get('log2_bayes_factor')):+.1f}",
                    str(item.get("hypothesis", "")),
                )
            )
        lines.append(
            format_table(("Likelihood", "Prior", "Posterior", "log2 BF", "Hypothesis"), rows)
        )
    estimates = _entries(forecast, "search_estimates")
    if estimates:
        lines.append("")
        lines.append("  Discrete-logarithm cost (not implemented; for scale only)")
        lines.append(
            format_table(
                ("Strategy", "Scalar bits", "Operations", "Memory", "Time", "Today"),
                [
                    (
                        str(item.get("strategy", "")),
                        str(item.get("scalar_bits", "")),
                        str(item.get("operations", "")),
                        abbreviate(str(item.get("memory", "")), 40),
                        str(item.get("estimated_time", "")),
                        str(item.get("feasible_today", "")),
                    )
                    for item in estimates
                ],
            )
        )

    addresses = _entries(data, "address_matrix")
    if addresses:
        lines.append("")
        lines.append(f"Address matrix ({len(addresses)})")
        lines.append(
            format_table(
                ("Network", "Type", "Key", "Address", "scriptPubKey"),
                [
                    (
                        str(entry.get("network", "")),
                        str(entry.get("address_type", "")),
                        str(entry.get("key_encoding", "")),
                        str(entry.get("address", "")),
                        abbreviate(str(entry.get("script_pubkey_hex", "")), 44),
                    )
                    for entry in addresses
                ],
            )
        )

    mirror = _section(data, "mirror_point")
    if mirror:
        lines.append("")
        lines.append("Mirror point (-P, shares the same x)")
        mirror_rows = [
            ("x", str(mirror.get("x_hex", ""))),
            ("y = p - y", str(mirror.get("y_hex", ""))),
            ("Compressed", str(mirror.get("compressed_hex", ""))),
            ("y parity", str(mirror.get("y_parity", ""))),
        ]
        lines.append(format_table(("Field", "Value"), mirror_rows))
        mirror_addresses = _entries(mirror, "addresses")
        if mirror_addresses:
            lines.append("")
            lines.append(
                format_table(
                    ("Mirror", "Address", "scriptPubKey"),
                    [
                        (
                            str(entry.get("address_type", "")),
                            str(entry.get("address", "")),
                            abbreviate(str(entry.get("script_pubkey_hex", "")), 44),
                        )
                        for entry in mirror_addresses
                    ],
                )
            )
        if mirror.get("note"):
            lines.append(f"  {mirror['note']}")

    keyspace = _section(data, "keyspace")
    if keyspace:
        lines.append("")
        lines.append("Keyspace")
        lines.append(
            format_table(
                ("Property", "Value"),
                [(str(key), abbreviate(str(value), 78)) for key, value in keyspace.items()],
            )
        )

    digests = _section(data, "digests")
    if digests:
        lines.append("")
        lines.append("Digests")
        lines.append(
            format_table(
                ("Algorithm", "Digest"),
                [(name, abbreviate(str(value), 72)) for name, value in digests.items()],
            )
        )

    representations = _entries(data, "representations")
    if representations:
        lines.append("")
        lines.append("Representations")
        lines.append(
            format_table(
                ("Label", "Value"),
                [
                    (str(item.get("label", "")), abbreviate(str(item.get("value", "")), 72))
                    for item in representations
                ],
            )
        )

    profiles = _entries(data, "bit_profiles")
    if profiles:
        lines.append("")
        lines.append("Bit profiles")
        lines.append(
            format_table(
                ("View", "Bits", "Ones", "One ratio", "Entropy", "Longest 1 run", "Longest 0 run"),
                [
                    (
                        str(item.get("label", "")),
                        str(item.get("length_bits", "")),
                        str(item.get("ones", "")),
                        f"{_as_float(item.get('one_ratio')):.4f}",
                        f"{_as_float(item.get('entropy')):.4f}",
                        str(item.get("one_run_longest", "")),
                        str(item.get("zero_run_longest", "")),
                    )
                    for item in profiles
                ],
            )
        )

    if result.extra.get("art"):
        lines.append("")
        lines.append("Bit grid (x, most significant bit first)")
        lines.extend(
            f"  {row}" for row in _as_text_list(_section(coordinates, "x").get("bit_grid"))
        )
        lines.append("Bit grid (y, most significant bit first)")
        lines.extend(
            f"  {row}" for row in _as_text_list(_section(coordinates, "y").get("bit_grid"))
        )

    recommendations = forecast.get("recommendations")
    if isinstance(recommendations, list) and recommendations:
        lines.append("")
        lines.append("Recommendations")
        lines.extend(f"  - {item}" for item in recommendations)
    limitations = forecast.get("limitations")
    if isinstance(limitations, list) and limitations:
        lines.append("")
        lines.append("Limitations")
        lines.extend(f"  - {item}" for item in limitations)

    _append_warnings(lines, result.warnings)
    return "\n".join(lines) + "\n"


def _dissection_result(
    public_key: str,
    *,
    networks: tuple[Network, ...],
    depth: str,
    art: bool,
) -> AnalysisResult:
    """Dissect one key and wrap it in a report-ready result."""
    dissection = dissect_public_key(public_key, networks=networks, depth=depth)
    payload = dissection.as_dict()
    return AnalysisResult(
        input_type="public_key",
        original_input=public_key.strip(),
        normalized_input=dissection.input_hex,
        public_key=payload["public_key"],
        forensics=payload,
        warnings=_FORENSICS_WARNINGS,
        extra={"depth": depth, "networks": [network.value for network in networks], "art": art},
    )


def _read_public_keys(path_text: str) -> tuple[str, ...]:
    """Read one public key per line, ignoring blanks and ``#`` comments."""
    path = Path(path_text).expanduser()
    if not path.exists():
        raise InputValidationError(f"input file does not exist: {path}")
    if path.is_dir():
        raise InputValidationError(f"input path is a directory: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(f"input file is not valid UTF-8 text: {path}") from exc
    except OSError as exc:
        raise InputValidationError(
            f"could not read input file {path}: {exc.strerror or exc}"
        ) from exc
    keys: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys.append(stripped)
        if len(keys) > MAX_BATCH_KEYS:
            raise InputValidationError(
                f"input file contains more than {MAX_BATCH_KEYS} keys; split it into smaller batches"
            )
    if not keys:
        raise InputValidationError(f"input file contains no public keys: {path}")
    return tuple(keys)


def _render_batch_text(keys: tuple[str, ...], dissections: tuple[PublicKeyDissection, ...]) -> str:
    """Render a one-line-per-key batch summary."""
    rows: list[tuple[str, str, str, str, str]] = []
    for index, dissection in enumerate(dissections, start=1):
        payload = dissection.as_dict()
        forecast = _section(payload, "forecast")
        mainnet = [
            entry
            for entry in _entries(payload, "address_matrix")
            if entry.get("network") == Network.MAINNET.value
        ]
        p2pkh = next((entry for entry in mainnet if entry.get("address_type") == "p2pkh"), {})
        p2wpkh = next((entry for entry in mainnet if entry.get("address_type") == "p2wpkh"), {})
        rows.append(
            (
                str(index),
                str(p2pkh.get("address", "")),
                str(p2wpkh.get("address", "")),
                f"{_as_float(forecast.get('structure_score')):.1f}",
                str(forecast.get("verdict", "")).split(":")[0],
            )
        )
    lines = [
        _header("public key dissection (batch)"),
        "",
        format_table(
            ("#", "Mainnet P2PKH", "Mainnet P2WPKH", "Score", "Verdict"),
            rows,
        ),
        "",
        f"{len(keys)} key(s) analysed. This tool never computes private keys.",
    ]
    return "\n".join(lines) + "\n"


def _render_batch_csv(dissections: tuple[PublicKeyDissection, ...]) -> str:
    """Render a batch dissection as long-format CSV with a key index column."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(("key_index", "section", "key", "value"))
    for index, dissection in enumerate(dissections, start=1):
        payload = dissection.as_dict()
        rendered = AnalysisResult(
            input_type="public_key",
            original_input=str(_section(payload, "input").get("hex", "")),
            normalized_input=str(_section(payload, "input").get("hex", "")),
            forensics=payload,
        )
        reader = csv.reader(io.StringIO(render_csv(rendered)))
        next(reader, None)  # header
        writer.writerows((str(index), row[0], row[1], row[2]) for row in reader)
    return buffer.getvalue()


def _emit_batch(payload: str, *, output: str | None, overwrite: bool) -> int:
    """Write batch output to a file or stdout."""
    if output:
        target = resolve_target(output, overwrite=overwrite, create_parents=True)
        atomic_write_text(target, payload, overwrite=overwrite)
        print(f"Report written to {target}")
    else:
        sys.stdout.write(payload)
    return EXIT_SUCCESS


def _cmd_dissect_public_key(args: argparse.Namespace) -> int:
    networks = _parse_networks(args.networks)
    if args.public_key is not None:
        result = _dissection_result(
            args.public_key, networks=networks, depth=args.depth, art=args.art
        )
        _LOGGER.info("public key dissection completed")
        return _emit(
            result,
            report_format=args.report_format,
            output=args.output,
            overwrite=args.overwrite,
            renderer=_render_forensics_text,
        )

    keys = _read_public_keys(args.input_file)
    dissections = dissect_many(keys, networks=networks, depth=args.depth)
    _LOGGER.info("batch public key dissection completed for %d key(s)", len(dissections))
    if args.report_format == "json":
        payload = json.dumps(
            [
                {"index": index, **dissection.as_dict()}
                for index, dissection in enumerate(dissections, start=1)
            ],
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        return _emit_batch(payload + "\n", output=args.output, overwrite=args.overwrite)
    if args.report_format == "csv":
        return _emit_batch(
            _render_batch_csv(dissections), output=args.output, overwrite=args.overwrite
        )
    text = _render_batch_text(keys, dissections)
    if args.art:
        for dissection in dissections:
            text += "\n" + _render_forensics_text(
                AnalysisResult(
                    input_type="public_key",
                    original_input=dissection.input_hex,
                    normalized_input=dissection.input_hex,
                    forensics=dissection.as_dict(),
                    warnings=_FORENSICS_WARNINGS,
                    extra={"art": True},
                )
            )
    return _emit_batch(text, output=args.output, overwrite=args.overwrite)


#: Warnings printed by the reconstruction commands.
_RECONSTRUCTION_WARNINGS: Final[tuple[str, ...]] = (
    "A public key alone cannot yield its scalar: that is the discrete logarithm "
    "problem, about 2^128 operations on secp256k1. This command only searches the "
    "window you declare unknown.",
    "The assembled scalar is a private key. It is redacted unless you pass --reveal; "
    "treat any output, shell history, and terminal scrollback as sensitive.",
    "Only use this on keys you generated yourself. Comparing or reconstructing "
    "someone else's key is not legitimate even when the window is small.",
)


def _render_ledger_text(solution: TemplateSolution, *, reveal: bool) -> str:
    """Render a template solution and its information ledger as text."""
    ledger = solution.ledger
    lines = [
        "private key assembly",
        "====================",
        "",
        "Template",
        f"  pattern        : {solution.template.render()}",
        f"  known digits   : {solution.template.known_digits} of {HEX_DIGITS}",
        f"  known bits     : {solution.template.known_bits}",
        f"  unknown window : {solution.template.unknown_bits} bits "
        f"(starting {solution.template.unknown_start} bits from the top, "
        f"{solution.template.low_bits} known bits below)",
        "",
        "Information ledger (one scale: bits of the 256-bit scalar)",
        format_table(
            ("Source", "Bits", "Note"),
            [
                (entry.label, f"{entry.bits:.0f}", abbreviate(entry.note, 58))
                for entry in ledger.entries
            ],
        ),
        f"  known   : {ledger.known_bits:.0f} bits",
        f"  unknown : {ledger.unknown_bits:.0f} bits",
        f"  verdict : {ledger.verdict}",
        "",
        "Search",
        f"  status         : {'solved and verified' if solution.solved else 'not solved'}",
        f"  steps          : {solution.steps}",
        f"  elapsed        : {solution.elapsed_seconds:.3f} s",
        f"  message        : {solution.message}",
    ]
    if solution.solved and solution.assembled_hex is not None:
        if reveal:
            lines.append(f"  assembled hex  : {solution.assembled_hex}")
        else:
            lines.append("  assembled hex  : redacted (pass --reveal to print the private key)")
    lines.append("")
    lines.append("Warnings:")
    lines.extend(f"  - {warning}" for warning in _RECONSTRUCTION_WARNINGS)
    return "\n".join(lines) + "\n"


def _cmd_assemble_private_key(args: argparse.Namespace) -> int:
    template = parse_template(args.template)
    solution = solve_template(args.public_key, template, max_unknown_bits=args.max_unknown_bits)
    _LOGGER.info("template search %s", "succeeded" if solution.solved else "found nothing")
    if args.report_format == "json":
        payload = json.dumps(
            solution.as_dict(reveal=args.reveal), indent=2, sort_keys=True, ensure_ascii=False
        )
        return _emit_batch(payload + "\n", output=args.output, overwrite=args.overwrite)
    return _emit_batch(
        _render_ledger_text(solution, reveal=args.reveal),
        output=args.output,
        overwrite=args.overwrite,
    )


def _render_comparison_text(report: ComparisonReport) -> str:
    """Render a key-set comparison as text."""
    lines = [
        "public key comparison",
        "=====================",
        "",
        f"  keys compared  : {report.count}",
        f"  pairs examined : {report.pairs_examined}" + (" (capped)" if report.truncated else ""),
        f"  shared x prefix: {report.shared_prefix_nibbles} hex digits",
        f"  shared x suffix: {report.shared_suffix_nibbles} hex digits",
        "",
        "Nibble agreement (how many keys share the most common digit at each position)",
        format_table(
            ("Position", "Keys agreeing", "Fraction"),
            [
                (
                    f"{index + 1:02d}",
                    str(count),
                    f"{count / report.count:.2f}",
                )
                for index, count in enumerate(report.nibble_agreement)
                if count > 1
            ]
            or [("-", "1", f"{1 / report.count:.2f}")],
        ),
        "",
        "Pairwise Hamming distance of the x coordinates",
        format_table(
            ("Pair", "Distance (bits of 256)"),
            [
                (f"{left}-{right}", f"{distance}")
                for left, right, distance in report.pairwise_hamming[:40]
            ],
        )
        if report.pairwise_hamming
        else "  none",
        "",
        "Related keys (small scalar offsets proved from public data)",
    ]
    if report.relationships:
        lines.append(
            format_table(
                ("Left", "Right", "Delta", "Verified"),
                [
                    (
                        str(item.left),
                        str(item.right),
                        str(item.delta),
                        "yes" if item.verified else "no",
                    )
                    for item in report.relationships
                ],
            )
        )
        lines.append(
            "  A delta means Q_right = Q_left + delta * G: if you know one scalar, you "
            "know the other. It does not reveal either scalar on its own."
        )
    else:
        lines.append("  none inside the requested window")
    lines.append("")
    lines.append("Notes:")
    lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines) + "\n"


def _cmd_compare_keys(args: argparse.Namespace) -> int:
    keys = tuple(args.public_key) if args.public_key else tuple(_read_public_keys(args.input_file))
    report = compare_keys(keys, max_delta_bits=args.max_delta_bits, max_pairs=args.max_pairs)
    _LOGGER.info("compared %d public keys", report.count)
    if args.report_format == "json":
        payload = json.dumps(report.as_dict(), indent=2, sort_keys=True, ensure_ascii=False)
        return _emit_batch(payload + "\n", output=args.output, overwrite=args.overwrite)
    return _emit_batch(
        _render_comparison_text(report), output=args.output, overwrite=args.overwrite
    )


def _render_address_dissection_text(
    dissection: AddressDissection,
    *,
    experiment: ControlledExperiment | None = None,
) -> str:
    """Render an address dissection as text."""
    profile = dissection.payload_profile
    safety = dissection.safety
    lines = [
        "address dissection",
        "===================",
        "",
        format_table(
            ("Field", "Value"),
            [
                ("address", dissection.address),
                ("input kind", dissection.input_kind),
                ("encoding", dissection.encoding),
                ("type", dissection.address_type),
                ("chain", dissection.chain),
                ("chain candidates", ", ".join(dissection.chain_candidates)),
                ("network", dissection.network),
                ("network ambiguous", "yes" if dissection.network_ambiguous else "no"),
                (
                    "version byte",
                    "-" if dissection.version_byte is None else f"0x{dissection.version_byte:02x}",
                ),
                ("HRP", dissection.human_readable_part or "-"),
                ("payload", dissection.payload_hex or "-"),
                ("payload bytes", str(dissection.payload_length_bytes)),
                ("checksum (encoded)", dissection.checksum_hex or "-"),
                ("checksum (recomputed)", dissection.recomputed_checksum_hex or "-"),
                ("checksum valid", "yes" if dissection.checksum_valid else "NO"),
                (
                    "witness version",
                    "-" if dissection.witness_version is None else str(dissection.witness_version),
                ),
                ("leading zero bytes", str(dissection.leading_zero_bytes)),
                ("leading '1' chars", str(dissection.base58_leading_ones)),
            ],
        ),
    ]
    if dissection.uri_params:
        lines.extend(["", "Payment URI parameters"])
        lines.append(
            format_table(
                ("Name", "Value"),
                [(name, abbreviate(value, 44)) for name, value in dissection.uri_params],
            )
        )

    lines.extend(
        [
            "",
            "Locking script",
            f"  hex : {dissection.script_pubkey_hex or '-'}",
            f"  asm : {dissection.script_asm}",
            "",
        ]
    )

    if profile is None:
        lines.extend(
            ["Payload profile", "  no payload: the output commits to a script, not a hash"]
        )
    else:
        lines.extend(
            [
                "Payload profile",
                format_table(
                    ("Field", "Value"),
                    [
                        ("label", profile.label),
                        ("bit length", str(profile.bit_length)),
                        ("leading zero bits", str(profile.leading_zero_bits)),
                        ("hamming weight", str(profile.hamming_weight)),
                        ("hamming p-value", f"{profile.hamming_p_value:.4f}"),
                        ("distinct bytes", str(profile.distinct_bytes)),
                        ("byte entropy", f"{profile.byte_entropy:.3f} bits/byte"),
                    ],
                ),
            ]
        )

    lines.append("")
    if dissection.randomness is None:
        lines.extend(["Randomness battery", "  not applicable: there is no payload to test"])
    else:
        battery = dissection.randomness
        lines.append("Randomness battery (payload bits)")
        lines.append(
            format_table(
                ("Test", "Statistic", "p-value", "Result"),
                [
                    (
                        test.name,
                        f"{test.statistic:.4f}",
                        f"{test.p_value:.3e}",
                        "pass" if test.passed else "FAIL",
                    )
                    for test in battery.tests
                ],
            )
        )
        lines.append(
            f"  Fisher p={battery.fisher_p_value:.3e}; "
            f"Bonferroni p={battery.bonferroni_p_value:.3e}; "
            f"family-wise {'pass' if battery.familywise_pass else 'FAIL'}"
        )

    lines.extend(["", f"Structural findings ({len(dissection.findings)})"])
    if dissection.findings:
        lines.append(
            format_table(
                ("Severity", "Code", "Evidence", "p"),
                [
                    (
                        finding.severity,
                        finding.code,
                        abbreviate(finding.evidence, 46),
                        f"{finding.probability:.3e}",
                    )
                    for finding in dissection.findings
                ],
            )
        )
    else:
        lines.append("  none: the payload looks like a uniform digest")

    if dissection.taproot is not None:
        taproot = dissection.taproot
        lines.extend(
            [
                "",
                "Taproot output key",
                format_table(
                    ("Field", "Value"),
                    [
                        ("output key", taproot.output_key_hex),
                        ("on curve", "yes" if taproot.valid_x_coordinate else "NO"),
                        ("even y", "yes" if taproot.even_y else "no"),
                        ("NUMS point", "yes" if taproot.is_nums_key else "no"),
                    ],
                ),
                f"  note: {taproot.note}",
            ]
        )

    scale = dissection.scale
    total = (
        "unbounded"
        if dissection.hardness.total_cost_log2 is None
        else f"2^{dissection.hardness.total_cost_log2:.0f}"
    )
    lines.extend(
        [
            "",
            "What the output tells you (one scale)",
            format_table(
                ("Question", "Answer"),
                [
                    ("bits that specify the output", f"{scale.address_bits}"),
                    ("candidates still possible", f"2^{scale.public_key_candidates_log2:.0f}"),
                    (
                        "bits of the private scalar known",
                        f"{scale.scalar_bits_known:.0f} of {scale.scalar_bits_total}",
                    ),
                    ("bits of the private scalar unknown", f"{scale.scalar_bits_unknown:.0f}"),
                    ("can this tool recover the key", "no"),
                ],
            ),
            f"  note: {scale.note}",
            "",
            "Backward chain (cost in base-2 operations)",
            format_table(
                ("Step", "Feasible", "Cost", "Method"),
                [
                    (
                        step.step,
                        "yes" if step.feasible else "no",
                        f"2^{step.cost_log2:.0f}",
                        abbreviate(step.method, 44),
                    )
                    for step in dissection.hardness.steps
                ],
            ),
            f"  total  : {total}",
            f"  verdict: {dissection.hardness.verdict}",
            "",
            f"Prefix analysis ({dissection.vanity.encoding})",
            f"  observed prefix : {dissection.vanity.prefix}",
            f"  exact probability: {dissection.vanity.probability:.3e}",
            f"  constrained bits : {dissection.vanity.constrained_bits}",
            f"  naive alphabet^-k: {dissection.vanity.naive_probability:.3e}",
            f"  verdict          : {dissection.vanity.verdict}",
            f"  note             : {dissection.vanity.note}",
            "",
            f"Safety audit (grade: {safety.grade})",
            format_table(
                ("Severity", "Code", "What it means"),
                [
                    (check.severity, check.code, abbreviate(check.title, 58))
                    for check in safety.checks
                ],
            ),
            f"  unspendable      : {'yes' if safety.unspendable else 'no'}",
            f"  anyone can spend : {'yes' if safety.anyone_can_spend else 'no'}",
            f"  verdict          : {safety.verdict}",
        ]
    )
    if safety.known_address is not None:
        entry = safety.known_address
        lines.extend(
            [
                "",
                f"Documented address: {entry.label}",
                f"  kind     : {entry.kind}",
                f"  reference: {entry.reference}",
                f"  meaning  : {entry.meaning}",
            ]
        )

    if dissection.script_claim is not None:
        claim = dissection.script_claim
        template = claim.template
        lines.extend(
            [
                "",
                "Redeem-script claim (supplied by the caller)",
                format_table(
                    ("Field", "Value"),
                    [
                        ("template", template.kind),
                        ("hash algorithm", claim.hash_algorithm or "-"),
                        (
                            "required hash",
                            abbreviate(claim.required_hash, 64) if claim.required_hash else "-",
                        ),
                        ("computed hash", abbreviate(claim.computed_hash, 64) or "-"),
                        ("verified", "YES" if claim.matches else "no"),
                    ],
                ),
            ]
        )
        if template.kind == "multisig":
            lines.append(f"  multisig        : {template.threshold}-of-{template.total_keys}")
            lines.append(f"  keys            : {len(template.public_keys)} published")
        if template.hash_lock:
            lines.append(f"  hash lock       : {template.hash_lock} ({template.hash_algorithm})")
        if template.timelock_value is not None:
            lines.append(
                f"  timelock        : {template.timelock_value} ({template.timelock_kind})"
            )
        lines.append(f"  spend paths     : {template.spend_paths}")
        lines.append(f"  disassembly     : {abbreviate(template.disassembly, 96)}")
        lines.extend(f"  note            : {note}" for note in template.notes)
        lines.append(f"  verdict         : {claim.verdict}")

    if dissection.key_match is not None:
        match = dissection.key_match
        lines.extend(
            [
                "",
                "Extended public key search (public derivation only)",
                format_table(
                    ("Field", "Value"),
                    [
                        ("key version", match.key_label),
                        ("network", match.network),
                        ("derives", match.script_type),
                        ("range searched", f"{match.range_start}..{match.range_end - 1}"),
                        ("indices checked", str(match.checked)),
                        (
                            "match",
                            "none"
                            if not match.matched
                            else f"index {match.matched_index} ({match.matched_path})",
                        ),
                    ],
                ),
            ]
        )
        lines.append(
            format_table(
                ("Index", "Derived address"),
                [(str(index), addr) for index, addr in match.sample],
            )
        )
        lines.append(f"  verdict: {match.verdict}")

    if experiment is not None:
        lines.extend(
            [
                "",
                "Controlled experiment (caller-supplied public key)",
                format_table(
                    ("Derivation", "Address", "Match"),
                    [
                        (label, value, "YES" if label in experiment.matching_labels else "-")
                        for label, value in experiment.derived_addresses
                    ],
                ),
                f"  verdict: {experiment.verdict}",
            ]
        )

    plan = dissection.plan
    lines.extend(
        [
            "",
            f"Investigation plan ({len(plan.leads)} leads)",
            format_table(
                ("Effort", "Lead", "Question", "Needs"),
                [
                    (
                        lead.effort,
                        lead.code,
                        abbreviate(lead.question, 52),
                        abbreviate(lead.needs, 40),
                    )
                    for lead in plan.leads
                ],
            ),
            f"  summary: {plan.summary}",
        ]
    )
    for lead in plan.leads:
        if lead.command:
            lines.append(f"  {lead.code:22s} -> {lead.command}")
    lines.append("")
    lines.append("Closed questions")
    lines.extend(f"  - {item}" for item in plan.closed)

    lines.extend(["", "Caveats"])
    lines.extend(f"  - {caveat}" for caveat in dissection.hardness.caveats)
    lines.append("")
    lines.append("Notes")
    lines.extend(f"  - {note}" for note in dissection.notes)
    lines.append("")
    lines.append("Limitations")
    lines.extend(f"  - {item}" for item in dissection.limitations)
    lines.append("")
    lines.append("Warnings:")
    lines.append("  - An address is not a public key; no key material is derived or claimed.")
    lines.append("  - Ownership, balance, and history require chain data. This tool reads none.")
    return "\n".join(lines) + "\n"


def _parse_index_range(text: str) -> tuple[int, int]:
    """Parse ``START:COUNT`` into a tuple.

    Raises:
        InputValidationError: The text is malformed.
    """
    start_text, separator, count_text = text.partition(":")
    if not separator:
        raise InputValidationError("--index-range must look like START:COUNT, e.g. 0:20")
    try:
        start = int(start_text)
        count = int(count_text)
    except ValueError as exc:
        raise InputValidationError("--index-range needs two integers") from exc
    if start < 0 or count < 1:
        raise InputValidationError("--index-range needs start >= 0 and count >= 1")
    if count > 10_000:
        raise InputValidationError("--index-range count is capped at 10000")
    return start, count


def _collect_address_inputs(args: argparse.Namespace) -> list[str]:
    """Return every address, URI, or script the caller asked about.

    Raises:
        InputValidationError: No input was given.
    """
    items: list[str] = list(args.address or [])
    if getattr(args, "stdin", False):
        for line in sys.stdin.read().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                items.append(stripped)
    if args.input_file is not None:
        path = Path(args.input_file)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReportGenerationError(f"cannot read {path}: {exc}") from exc
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            items.append(stripped)
    if not items:
        raise InputValidationError(
            "provide at least one address, or pass --input-file with one per line"
        )
    return items


_ADDRESS_CSV_COLUMNS: Final = (
    "input",
    "address",
    "type",
    "chain",
    "network",
    "encoding",
    "payload_hex",
    "script_pubkey_hex",
    "address_bits",
    "candidates_log2",
    "scalar_bits_known",
    "total_cost_log2",
    "safety_grade",
    "script_claim",
    "xpub_match",
    "unspendable",
    "anyone_can_spend",
    "checksum_valid",
    "findings",
    "error",
)


def _dissection_csv_row(
    source: str, dissection: AddressDissection | None, error: str
) -> dict[str, str]:
    """Return one CSV row for a dissection or an error."""
    if dissection is None:
        row = dict.fromkeys(_ADDRESS_CSV_COLUMNS, "")
        row["input"] = source
        row["error"] = error
        return row
    total = dissection.hardness.total_cost_log2
    return {
        "input": source,
        "address": dissection.address,
        "type": dissection.address_type,
        "chain": dissection.chain,
        "network": dissection.network,
        "encoding": dissection.encoding,
        "payload_hex": dissection.payload_hex,
        "script_pubkey_hex": dissection.script_pubkey_hex,
        "address_bits": str(dissection.scale.address_bits),
        "candidates_log2": f"{dissection.scale.public_key_candidates_log2:g}",
        "scalar_bits_known": f"{dissection.scale.scalar_bits_known:g}",
        "total_cost_log2": "" if total is None else f"{total:g}",
        "safety_grade": dissection.safety.grade,
        "script_claim": (
            ""
            if dissection.script_claim is None
            else ("match" if dissection.script_claim.matches else "no-match")
        ),
        "xpub_match": (
            ""
            if dissection.key_match is None or dissection.key_match.matched_index is None
            else str(dissection.key_match.matched_index)
        ),
        "unspendable": "yes" if dissection.safety.unspendable else "no",
        "anyone_can_spend": "yes" if dissection.safety.anyone_can_spend else "no",
        "checksum_valid": "yes" if dissection.checksum_valid else "no",
        "findings": str(len(dissection.findings)),
        "error": "",
    }


def _render_csv_rows(columns: tuple[str, ...], rows: list[dict[str, str]]) -> str:
    """Render rows as CSV text."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _summarise_dissections(
    dissections: list[AddressDissection], errors: list[tuple[str, str]]
) -> dict[str, object]:
    """Return aggregate counts for a batch run."""
    by_type: dict[str, int] = {}
    by_chain: dict[str, int] = {}
    by_grade: dict[str, int] = {}
    for dissection in dissections:
        by_type[dissection.address_type] = by_type.get(dissection.address_type, 0) + 1
        by_chain[dissection.chain] = by_chain.get(dissection.chain, 0) + 1
        by_grade[dissection.safety.grade] = by_grade.get(dissection.safety.grade, 0) + 1
    return {
        "items": len(dissections) + len(errors),
        "parsed": len(dissections),
        "failed": len(errors),
        "by_type": dict(sorted(by_type.items())),
        "by_chain": dict(sorted(by_chain.items())),
        "by_grade": dict(sorted(by_grade.items())),
        "unspendable": sum(1 for item in dissections if item.safety.unspendable),
        "anyone_can_spend": sum(1 for item in dissections if item.safety.anyone_can_spend),
        "checksum_failures": sum(1 for item in dissections if not item.checksum_valid),
    }


def _cmd_dissect_address(args: argparse.Namespace) -> int:
    if args.index_range is not None:
        _parse_index_range(args.index_range)
    items = _collect_address_inputs(args)
    dissections: list[AddressDissection] = []
    errors: list[tuple[str, str]] = []
    experiment: ControlledExperiment | None = None
    for item in items:
        try:
            dissection = dissect_address(
                item,
                claimed_prefix=args.claimed_prefix,
                network=args.network,
                redeem_script=args.redeem_script,
                xpub=args.xpub,
                xpub_range=(
                    _parse_index_range(args.index_range) if args.xpub is not None else (0, 20)
                ),
            )
        except BinaryCryptoLabError as exc:
            errors.append((item, str(exc)))
            continue
        if args.public_key is not None and experiment is None:
            experiment = controlled_experiment(
                dissection.address, args.public_key, network=args.network or "mainnet"
            )
        dissections.append(dissection)

    if not dissections and errors:
        for item, message in errors:
            print(f"error: {abbreviate(item, 24)}: {message}", file=sys.stderr)
        return EXIT_ERROR

    fmt = args.report_format
    if fmt == "json":
        if len(items) == 1 and len(dissections) == 1:
            document: object = dissections[0].as_dict()
            if experiment is not None:
                document = {
                    **dissections[0].as_dict(),
                    "controlled_experiment": experiment.as_dict(),
                }
        else:
            document = {
                "items": [item.as_dict() for item in dissections],
                "errors": [{"input": source, "error": message} for source, message in errors],
                "summary": _summarise_dissections(dissections, errors),
            }
            if experiment is not None:
                document["controlled_experiment"] = experiment.as_dict()
        text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        code = EXIT_ERROR if errors else EXIT_SUCCESS
        return _emit_batch(text, output=args.output, overwrite=args.overwrite) or code
    if fmt == "csv":
        rows = [_dissection_csv_row(item.address, item, "") for item in dissections]
        rows.extend(_dissection_csv_row(source, None, message) for source, message in errors)
        text = _render_csv_rows(_ADDRESS_CSV_COLUMNS, rows)
        code = EXIT_ERROR if errors else EXIT_SUCCESS
        return _emit_batch(text, output=args.output, overwrite=args.overwrite) or code

    if len(dissections) == 1 and not errors:
        text = _render_address_dissection_text(dissections[0], experiment=experiment)
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)

    summary = _summarise_dissections(dissections, errors)
    lines = [
        "address batch",
        "=============",
        "",
        f"items     : {summary['items']}",
        f"parsed    : {summary['parsed']}",
        f"failed    : {summary['failed']}",
        f"by type   : {summary['by_type']}",
        f"by chain  : {summary['by_chain']}",
        f"by grade  : {summary['by_grade']}",
        f"unspendable      : {summary['unspendable']}",
        f"anyone can spend : {summary['anyone_can_spend']}",
        "",
        "Per item",
    ]
    for dissection in dissections:
        total = dissection.hardness.total_cost_log2
        cost = "unbounded" if total is None else f"2^{total:.0f}"
        lines.append(
            f"  {abbreviate(dissection.address, 34):34s} {dissection.address_type:11s} "
            f"{dissection.chain:12s} {dissection.network:8s} "
            f"cost={cost:<10s} grade={dissection.safety.grade}"
        )
        if dissection.safety.unspendable or dissection.safety.anyone_can_spend:
            lines.append(f"      hazard: {dissection.safety.verdict}")
    if errors:
        lines.extend(["", "Errors"])
        lines.extend(f"  {abbreviate(source, 34):34s} {message}" for source, message in errors)
    lines.extend(
        [
            "",
            "Warnings:",
            "  - A valid checksum proves encoding, not ownership or balance.",
            "  - No key material is derived, stored, or claimed for any input.",
        ]
    )
    text = "\n".join(lines) + "\n"
    code = EXIT_ERROR if errors else EXIT_SUCCESS
    return _emit_batch(text, output=args.output, overwrite=args.overwrite) or code


def _render_utxo_audit_text(audit: UtxoAudit) -> str:
    """Render a user-supplied data audit as text."""
    lines = [
        "address data audit (offline)",
        "============================",
        "",
        format_table(
            ("Field", "Value"),
            [
                ("address", audit.address),
                ("source", audit.source),
                ("outputs listed", str(len(audit.utxos))),
                ("total reported", f"{audit.total_btc} BTC"),
                ("confirmed", f"{_sats_to_btc(audit.confirmed_sats)} BTC"),
                ("unconfirmed", f"{_sats_to_btc(audit.unconfirmed_sats)} BTC"),
                ("marked spent", f"{_sats_to_btc(audit.spent_sats)} BTC"),
                ("balance after spent", f"{audit.balance_btc} BTC"),
                ("trusted", "no: the data is yours, not verified"),
            ],
        ),
        "",
        "Outputs",
    ]
    if audit.utxos:
        lines.append(
            format_table(
                ("Outpoint", "Value (BTC)", "Height", "Script"),
                [
                    (
                        abbreviate(utxo.outpoint, 40),
                        _sats_to_btc(utxo.value_sats),
                        "-" if utxo.height is None else str(utxo.height),
                        "match"
                        if utxo.script_matches
                        else ("mismatch" if utxo.script_matches is False else "not given"),
                    )
                    for utxo in audit.utxos
                ],
            )
        )
    else:
        lines.append("  none listed")
    lines.extend(["", "Problems"])
    if audit.problems:
        lines.extend(f"  - {problem}" for problem in audit.problems)
    else:
        lines.append("  none: the file is internally consistent")
    if audit.duplicates:
        lines.extend(["", "Duplicated outpoints"])
        lines.extend(f"  - {outpoint}" for outpoint in audit.duplicates)
    lines.extend(["", f"Verdict: {audit.verdict}", "", "Notes"])
    lines.extend(f"  - {note}" for note in audit.notes)
    lines.extend(
        [
            "",
            "Warnings:",
            "  - No network request was made; this is arithmetic over a file you supplied.",
            "  - A balance in a file is not a balance on chain.",
        ]
    )
    return "\n".join(lines) + "\n"


def _sats_to_btc(value: int) -> str:
    """Format satoshis as an exact BTC decimal string."""
    sign = "-" if value < 0 else ""
    magnitude = abs(value)
    return f"{sign}{magnitude // 100_000_000}.{magnitude % 100_000_000:08d}"


def _cmd_audit_address_data(args: argparse.Namespace) -> int:
    audit = audit_address_data(args.address, args.input_file, source=args.source)
    _LOGGER.info("address data audit completed")
    if args.report_format == "json":
        text = json.dumps(audit.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    if args.report_format == "csv":
        rows = [
            {
                "outpoint": utxo.outpoint,
                "value_sats": str(utxo.value_sats),
                "height": "" if utxo.height is None else str(utxo.height),
                "spent_by": utxo.spent_by or "",
                "script_matches": (
                    "" if utxo.script_matches is None else ("yes" if utxo.script_matches else "no")
                ),
                "problems": "; ".join(utxo.problems),
            }
            for utxo in audit.utxos
        ]
        text = _render_csv_rows(
            ("outpoint", "value_sats", "height", "spent_by", "script_matches", "problems"), rows
        )
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    return _emit_batch(_render_utxo_audit_text(audit), output=args.output, overwrite=args.overwrite)


def _render_recovery_text(report: ScriptRecovery) -> str:
    """Render a script-recovery report as text."""
    lines = [
        "script recovery",
        "===============",
        "",
        format_table(
            ("Field", "Value"),
            [
                ("address", report.address),
                ("type", report.address_type),
                ("candidate keys", str(len(report.candidate_keys))),
                ("candidates tested", str(report.attempts)),
                ("budget exhausted", "yes" if report.truncated else "no"),
                ("recovered", "YES" if report.recovered else "no"),
            ],
        ),
        "",
        "Candidate keys",
        format_table(
            ("#", "Key", "Label", "HASH160"),
            [
                (str(index + 1), abbreviate(key.public_key_hex, 22), key.label, key.hash160)
                for index, key in enumerate(report.candidate_keys)
            ],
        ),
        "",
    ]
    if report.matches:
        lines.append("Recovered scripts")
        lines.append(
            format_table(
                ("Template", "Summary", "Script", "Keys"),
                [
                    (
                        match.template,
                        match.summary,
                        abbreviate(match.script_hex, 40),
                        ", ".join(match.keys_used),
                    )
                    for match in report.matches
                ],
            )
        )
        for match in report.matches:
            lines.append("")
            lines.append(f"  full script : {match.script_hex}")
    elif report.key_matches:
        lines.append("Key-level match")
        lines.extend(
            f"  - {key.label}: {key.public_key_hex} hashes to the payload"
            for key in report.key_matches
        )
    else:
        lines.append("No match: none of the enumerated scripts or keys reproduces the address")
    lines.extend(["", f"Verdict: {report.verdict}", "", "Notes"])
    lines.extend(f"  - {note}" for note in report.notes)
    lines.extend(
        [
            "",
            "Warnings:",
            "  - Only supplied public keys were hashed; no private key was generated or guessed.",
            "  - A miss excludes the catalogue, not every possible script.",
        ]
    )
    return "\n".join(lines) + "\n"


def _cmd_recover_script(args: argparse.Namespace) -> int:
    keys = [
        CandidateKey(value, label=f"candidate #{index + 1}")
        for index, value in enumerate(args.candidate_key)
    ]
    report = recover_script(
        args.address,
        keys,
        timelock_values=tuple(args.timelock),
        hash_locks=tuple(args.hash_lock),
        max_candidates=args.max_candidates,
    )
    _LOGGER.info("script recovery completed")
    if args.report_format == "json":
        text = json.dumps(report.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    if args.report_format == "csv":
        rows = [
            {
                "template": match.template,
                "summary": match.summary,
                "script_hex": match.script_hex,
                "matched": "yes" if match.matched else "no",
                "keys_used": "; ".join(match.keys_used),
            }
            for match in report.matches
        ] or [{"template": "", "summary": "", "script_hex": "", "matched": "none", "keys_used": ""}]
        text = _render_csv_rows(("template", "summary", "script_hex", "matched", "keys_used"), rows)
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    return _emit_batch(_render_recovery_text(report), output=args.output, overwrite=args.overwrite)


def _render_comparison_text_two(result: AddressComparison) -> str:
    """Render an address comparison as text."""
    lines = [
        "address comparison",
        "==================",
        "",
        format_table(
            ("#", "Address", "Type", "Payload"),
            [
                (str(index + 1), abbreviate(addr, 40), kind, payload)
                for index, (addr, kind, payload) in enumerate(
                    zip(result.addresses, result.types, result.payloads, strict=True)
                )
            ],
        ),
        "",
        f"Pairs examined: {result.pair_count}",
        "",
        f"Relations ({len(result.relations)})",
    ]
    if result.relations:
        lines.append(
            format_table(
                ("Kind", "Left", "Right", "Evidence", "p"),
                [
                    (
                        relation.kind,
                        abbreviate(relation.left, 18),
                        abbreviate(relation.right, 18),
                        abbreviate(relation.evidence, 44),
                        "-" if relation.probability is None else f"{relation.probability:.3e}",
                    )
                    for relation in result.relations
                ],
            )
        )
        lines.append("")
        for relation in result.relations:
            lines.append(f"  {relation.kind}: {relation.explanation}")
    else:
        lines.append("  none: the payloads are unrelated at this resolution")
    lines.extend(["", f"Verdict: {result.verdict}", "", "Notes"])
    lines.extend(f"  - {note}" for note in result.notes)
    lines.extend(
        [
            "",
            "Warnings:",
            "  - A shared payload is reuse, not a shared owner.",
            "  - Two addresses from different keys are expected to show no relation.",
        ]
    )
    return "\n".join(lines) + "\n"


def _cmd_compare_addresses(args: argparse.Namespace) -> int:
    result = compare_addresses(args.address)
    _LOGGER.info("address comparison completed")
    if args.report_format == "json":
        text = json.dumps(result.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    if args.report_format == "csv":
        rows = [
            {
                "kind": relation.kind,
                "left": relation.left,
                "right": relation.right,
                "evidence": relation.evidence,
                "probability": "" if relation.probability is None else f"{relation.probability:g}",
            }
            for relation in result.relations
        ]
        text = _render_csv_rows(("kind", "left", "right", "evidence", "probability"), rows)
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    return _emit_batch(
        _render_comparison_text_two(result), output=args.output, overwrite=args.overwrite
    )


def _render_mining_text(estimate: MiningEstimate) -> str:
    """Render a mining estimate as text."""
    measured = estimate.measured
    lines = [
        "prefix mining estimate",
        "======================",
        "",
        format_table(
            ("Field", "Value"),
            [
                ("prefix", estimate.prefix),
                ("encoding", estimate.encoding),
                ("constrained bits", str(estimate.constrained_bits)),
                ("exact probability", f"{estimate.probability:.3e}"),
                ("expected attempts", f"{estimate.expected_attempts:.3e}"),
                ("difficulty (x 2^32)", f"{estimate.difficulty:.3e}"),
            ],
        ),
        "",
        "Measured on this machine",
        format_table(
            ("Field", "Value"),
            [
                ("derivation type", measured.address_type),
                ("iterations", str(measured.iterations)),
                ("elapsed", f"{measured.elapsed_seconds:.4f} s"),
                ("rate", f"{measured.per_second:,.0f} per second"),
                ("time per attempt", f"{measured.seconds_per_attempt * 1e6:.1f} microseconds"),
                ("expected wall clock", f"{estimate.expected_seconds_measured:,.0f} s"),
            ],
        ),
        "",
        "Expected time by attack rate",
        format_table(
            ("Attempts per second", "Seconds", "Human"),
            [
                (f"{rate:.0e}", f"{seconds:.3e}", human)
                for rate, seconds, human in estimate.rate_table
            ],
        ),
        "",
        f"Verdict: {estimate.verdict}",
        "",
        "Notes",
    ]
    lines.extend(f"  - {note}" for note in estimate.notes)
    lines.extend(
        [
            "",
            "Warnings:",
            "  - This is an estimate, not a mining service: no prefix was searched for.",
            "  - A cheap prefix proves nothing about the address's origin.",
        ]
    )
    return "\n".join(lines) + "\n"


def _cmd_estimate_mining(args: argparse.Namespace) -> int:
    from .mining import benchmark_derivation

    rate = benchmark_derivation(iterations=args.iterations)
    estimate = estimate_prefix_mining(args.address, prefix=args.prefix, rate=rate)
    _LOGGER.info("prefix mining estimated")
    if args.report_format == "json":
        text = json.dumps(estimate.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    if args.report_format == "csv":
        rows = [
            {
                "attempts_per_second": f"{rate_value:.0e}",
                "seconds": f"{seconds:.3e}",
                "human": human,
            }
            for rate_value, seconds, human in estimate.rate_table
        ]
        text = _render_csv_rows(("attempts_per_second", "seconds", "human"), rows)
        return _emit_batch(text, output=args.output, overwrite=args.overwrite)
    return _emit_batch(_render_mining_text(estimate), output=args.output, overwrite=args.overwrite)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list excluding the program name.  ``None`` uses
            :data:`sys.argv`.

    Returns:
        Process exit code: ``0`` on success, ``1`` for expected errors, ``2``
        for missing commands.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose, debug=args.debug)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        return int(handler(args))
    except InvalidPrivateKeyError as exc:
        # Deliberately concise: the exception never contains the scalar.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BinaryCryptoLabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover - depends on the shell pipeline
        return EXIT_ERROR
    except Exception as exc:
        print(f"unexpected error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        else:
            print("run with --debug for a traceback", file=sys.stderr)
        return EXIT_ERROR
