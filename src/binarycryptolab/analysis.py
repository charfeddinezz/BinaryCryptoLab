"""Analysis engines for binary and hexadecimal input.

The engines turn validated input into immutable result models.  They never
interpret input as text unless the bytes happen to be valid UTF-8, in which
case a clearly-labelled preview is attached to hexadecimal results.

Representation rules
--------------------
* Binary input keeps its **textual width**.  ``"0011"`` has four zero bits and
  four characters, even though its integer value is ``3``.
* Hexadecimal input is converted nibble by nibble, so ``"2d"`` maps to
  ``"00101101"`` and every hexadecimal digit contributes four bits.
* Byte statistics for binary input use left padding to the next byte boundary;
  the number of added zero bits is reported so it can be accounted for.
"""

from __future__ import annotations

from dataclasses import replace

from .binary_utils import binary_to_bytes_padded, binary_to_hex, group_bits
from .config import DEFAULT_INPUT_LIMITS, InputLimits
from .hashing import HashDigest
from .hex_utils import hex_to_binary
from .models.analysis_result import AnalysisResult, BinaryAnalysis, HexAnalysis
from .statistics import bit_statistics, byte_statistics
from .validation import normalize_binary, normalize_hex

__all__ = [
    "analyze",
    "analyze_binary",
    "analyze_hex",
    "attach_hashes",
    "attach_warning",
]

_PADDING_NOTE = (
    "Non-byte-aligned binary input was left-padded with {count} zero bit(s) "
    "for byte-level statistics; the textual bit statistics still describe the "
    "original width."
)


def analyze_binary(
    value: str,
    *,
    max_length: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> BinaryAnalysis:
    """Analyse a binary string.

    Args:
        value: Binary text (optional ``0b`` prefix and ASCII whitespace are
            accepted).
        max_length: Optional override of the maximum number of bits.
        limits: Limit bundle used when *max_length* is ``None``.

    Returns:
        A :class:`BinaryAnalysis` describing the input.  Report writers accept
        :class:`AnalysisResult`, so use :func:`analyze` when you need JSON or
        CSV output.

    Raises:
        InvalidBinaryError: The input is not valid binary text.

    Example:
        >>> result = analyze_binary("101101")
        >>> result.integer_value, result.hexadecimal
        (45, '2d')
        >>> result.bit_stats.hamming_weight
        4
    """
    digits = normalize_binary(value, max_length=max_length, limits=limits)
    data, padding = binary_to_bytes_padded(digits)
    bit_stats = bit_statistics(digits)
    byte_stats = byte_statistics(data, padding_bits=padding)
    return BinaryAnalysis(
        original=value,
        normalized=digits,
        bit_length=len(digits),
        integer_value=int(digits, 2),
        hexadecimal=binary_to_hex(digits),
        bit_stats=bit_stats,
        bytes_hex=data.hex(),
        byte_stats=byte_stats,
        complete_bytes=len(digits) // 8,
        incomplete_bits=len(digits) % 8,
        padding_bits=padding,
        grouped_display=group_bits(digits, group_size=4),
    )


def analyze_hex(
    value: str,
    *,
    allow_odd: bool = True,
    max_length: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> HexAnalysis:
    """Analyse hexadecimal text.

    Args:
        value: Hexadecimal text (optional ``0x`` prefix, ASCII whitespace, and
            mixed case are accepted).
        allow_odd: Whether odd-length input is accepted.  When ``True`` a
            single zero nibble is prepended and the result is flagged with
            ``odd_length_input=True``.
        max_length: Optional override of the maximum number of hexadecimal
            digits.
        limits: Limit bundle used when *max_length* is ``None``.

    Returns:
        A :class:`HexAnalysis` describing the input.  Report writers accept
        :class:`AnalysisResult`, so use :func:`analyze` when you need JSON or
        CSV output.

    Raises:
        InvalidHexError: The input is not valid hexadecimal.

    Example:
        >>> result = analyze_hex("2D")
        >>> result.integer_value, result.binary
        (45, '00101101')
        >>> result.byte_stats.byte_length
        1
    """
    stripped = value.replace(" ", "").replace("\t", "")
    digits = normalize_hex(value, allow_odd=allow_odd, max_length=max_length, limits=limits)
    odd_length = len(stripped[2:] if stripped[:2].lower() == "0x" else stripped) % 2 == 1
    binary = hex_to_binary(digits)
    bit_stats = bit_statistics(binary)
    data = bytes.fromhex(digits)
    byte_stats = byte_statistics(data)
    try:
        text_preview: str | None = data.decode("utf-8")
    except UnicodeDecodeError:
        text_preview = None
    return HexAnalysis(
        original=value,
        normalized=digits,
        hex_length=len(digits),
        integer_value=int(digits, 16),
        binary=binary,
        binary_length=len(binary),
        bit_stats=bit_stats,
        bytes_hex=data.hex(),
        byte_stats=byte_stats,
        text_utf8=text_preview,
        odd_length_input=odd_length,
        grouped_display=" ".join(digits[index : index + 2] for index in range(0, len(digits), 2)),
    )


def analyze(
    input_type: str,
    value: str,
    *,
    allow_odd_hex: bool = True,
    max_length: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> AnalysisResult:
    """Analyse binary or hexadecimal input and return a report-ready result.

    Args:
        input_type: ``"binary"`` or ``"hex"`` (``"hexadecimal"`` is accepted as
            an alias).
        value: Input text.
        allow_odd_hex: Whether odd-length hexadecimal input is accepted.
        max_length: Optional override of the input length limit.
        limits: Limit bundle used when *max_length* is ``None``.

    Returns:
        An :class:`AnalysisResult` containing one analysis section and any
        warnings produced during analysis.

    Raises:
        InvalidBinaryError: Binary input is malformed.
        InvalidHexError: Hexadecimal input is malformed.
        ValueError: The input type is unknown.
    """
    normalized_type = input_type.strip().lower()
    warnings: list[str] = []
    if normalized_type in {"binary", "bin"}:
        binary = analyze_binary(value, max_length=max_length, limits=limits)
        if binary.padding_bits:
            warnings.append(_PADDING_NOTE.format(count=binary.padding_bits))
        if len(binary.normalized) > 1 and binary.normalized.startswith("0"):
            warnings.append(
                "Leading zero bits are preserved in the textual statistics but do not "
                "affect the decimal or hexadecimal integer value."
            )
        return AnalysisResult(
            input_type="binary",
            original_input=value,
            normalized_input=binary.normalized,
            binary=binary,
            warnings=tuple(warnings),
            extra={"length_limits": {"max_binary_length": limits.max_binary_length}},
        )
    if normalized_type in {"hex", "hexadecimal"}:
        hexadecimal = analyze_hex(
            value,
            allow_odd=allow_odd_hex,
            max_length=max_length,
            limits=limits,
        )
        if hexadecimal.odd_length_input:
            warnings.append(
                "Hexadecimal input had an odd number of digits; a single leading zero "
                "nibble was prepended."
            )
        return AnalysisResult(
            input_type="hex",
            original_input=value,
            normalized_input=hexadecimal.normalized,
            hexadecimal=hexadecimal,
            warnings=tuple(warnings),
            extra={"length_limits": {"max_hex_length": limits.max_hex_length}},
        )
    raise ValueError("input_type must be 'binary' or 'hex'")


def attach_hashes(result: AnalysisResult, digests: tuple[HashDigest, ...]) -> AnalysisResult:
    """Return a copy of *result* with hash results attached."""
    return replace(result, hashes=digests)


def attach_warning(result: AnalysisResult, message: str) -> AnalysisResult:
    """Return a copy of *result* with an additional warning."""
    return replace(result, warnings=(*result.warnings, message))
