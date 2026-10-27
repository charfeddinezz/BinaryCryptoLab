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
from .models.analysis_result import REDACTED, AnalysisResult
from .reports import render_csv, render_json, write_csv, write_json
from .reports._io import atomic_write_text, resolve_target
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

    lines.append("")
    lines.append("Forecast")
    lines.append(f"  Verdict         : {forecast.get('verdict', '')}")
    lines.append(f"  Size class      : {forecast.get('size_class', '')}")
    score = _as_float(forecast.get("structure_score"))
    surprisal = _as_float(forecast.get("total_surprisal_bits"))
    lines.append(f"  Structure score : {score:.1f}/100")
    lines.append(f"  Surprisal       : {surprisal:.1f} bits")
    lines.append(f"  Recoverable     : {'yes' if forecast.get('recoverable') else 'no'}")
    lines.append("")
    lines.append("  Hypotheses")
    hypotheses = _entries(forecast, "hypotheses")
    if hypotheses:
        lines.append(
            format_table(
                ("Likelihood", "Score", "Hypothesis"),
                [
                    (
                        str(item.get("likelihood", "")),
                        f"{_as_float(item.get('score')):.2f}",
                        str(item.get("hypothesis", "")),
                    )
                    for item in hypotheses
                ],
            )
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
