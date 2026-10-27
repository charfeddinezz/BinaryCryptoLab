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
import getpass
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Final

from ._version import __version__
from .analysis import analyze, attach_hashes
from .binary_utils import binary_to_bytes
from .bitcoin import address_from_public_key, decode_address
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
from .hashing import HashAlgorithm, hash_bytes
from .hex_utils import hex_to_bytes
from .models.analysis_result import REDACTED, AnalysisResult
from .reports import render_csv, render_json, write_csv, write_json
from .reports._io import atomic_write_text, resolve_target
from .utils.formatting import (
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

security:
  Use synthetic test values only.  Command-line arguments can be recorded in
  shell history and are visible to other local processes.  Prefer
  --prompt-private-key (hidden input) or the Python API for sensitive values.
  This tool never contacts the network and never stores private keys.
"""

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
            "Derive a P2PKH or P2WPKH address from a secp256k1 public key. "
            "No blockchain data is queried."
        ),
    )
    address.add_argument("--public-key", required=True, help="SEC 1 public key in hexadecimal")
    address.add_argument(
        "--type",
        choices=("p2pkh", "p2wpkh"),
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
