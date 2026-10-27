"""Bit-level primitives.

Two indexing conventions are used and are documented on every affected
function:

* **Integer bit indices** count from the least-significant bit (LSB), starting
  at index ``0``.  This is the convention of :func:`extract_bit_range`,
  :func:`first_differing_bit`, and :func:`last_differing_bit` when they are
  given integers.
* **String bit indices** count from the most-significant bit (the leftmost
  character of a binary string), starting at index ``0``.  This is the
  convention of :func:`first_differing_bit` and :func:`last_differing_bit`
  when they are given binary strings.

Width-dependent operations require an explicit width.  In particular,
:func:`bitwise_not` refuses to run without one, because an unbounded bitwise
NOT is undefined for Python's arbitrary-precision integers.

Operations that combine binary strings of different lengths left-pad the
shorter string with zeros.  The padding is reported in the returned
:class:`BitComparison` and in the relevant docstrings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .exceptions import InputValidationError
from .validation import normalize_binary

__all__ = [
    "BitComparison",
    "bitwise_and",
    "bitwise_not",
    "bitwise_or",
    "bitwise_xor",
    "compare_binary_strings",
    "count_set_bits",
    "count_zero_bits",
    "extract_bit_range",
    "first_differing_bit",
    "hamming_distance",
    "hamming_distance_binary",
    "hamming_weight",
    "last_differing_bit",
    "mask_bits",
    "pad_binary",
    "reverse_bits",
    "shift_left",
    "shift_right",
]

_MAX_SHIFT: Final = 1 << 24


def _require_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(f"{label} must be an integer, not {type(value).__name__}")
    return value


def _require_non_negative(value: object, *, label: str) -> int:
    number = _require_int(value, label=label)
    if number < 0:
        raise InputValidationError(f"{label} must be non-negative")
    return number


def _require_width(width: object) -> int:
    number = _require_int(width, label="width")
    if number <= 0:
        raise InputValidationError("width must be a positive integer")
    return number


def _require_fits(value: int, width: int, *, label: str = "value") -> None:
    if value >= 1 << width:
        raise InputValidationError(f"{label} does not fit in {width} bits")


def count_set_bits(value: int) -> int:
    """Count the set (one) bits of a non-negative integer.

    Args:
        value: Non-negative integer.

    Returns:
        Population count, also known as Hamming weight.

    Raises:
        InputValidationError: The value is not a non-negative integer.
    """
    number = _require_non_negative(value, label="value")
    return number.bit_count()


def hamming_weight(value: int | bytes | bytearray | memoryview | str) -> int:
    """Return the Hamming weight (number of one bits) of *value*.

    Binary strings are normalized first, so an optional ``0b`` prefix and
    ASCII whitespace are accepted.  Leading zeros in a string do not change
    the Hamming weight.

    Args:
        value: Non-negative integer, bytes-like object, or binary string.

    Returns:
        Number of set bits.

    Raises:
        InputValidationError: The integer is negative or the type is unsupported.
        InvalidBinaryError: A string is not valid binary text.
    """
    if isinstance(value, str):
        return normalize_binary(value).count("1")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return sum(byte.bit_count() for byte in bytes(value))
    if isinstance(value, int) and not isinstance(value, bool):
        return count_set_bits(value)
    raise InputValidationError(f"unsupported type for Hamming weight: {type(value).__name__}")


def count_zero_bits(value: int, width: int) -> int:
    """Count zero bits of *value* inside a fixed *width*.

    Args:
        value: Non-negative integer that must fit in *width* bits.
        width: Number of bits to consider.

    Returns:
        ``width - popcount(value)``.

    Raises:
        InputValidationError: The value is negative, the width is invalid, or
            the value does not fit in the width.
    """
    number = _require_non_negative(value, label="value")
    bits = _require_width(width)
    _require_fits(number, bits)
    return bits - number.bit_count()


def bitwise_and(left: int, right: int) -> int:
    """Return ``left & right`` for two non-negative integers."""
    return _require_non_negative(left, label="left") & _require_non_negative(right, label="right")


def bitwise_or(left: int, right: int) -> int:
    """Return ``left | right`` for two non-negative integers."""
    return _require_non_negative(left, label="left") | _require_non_negative(right, label="right")


def bitwise_xor(left: int, right: int) -> int:
    """Return ``left ^ right`` for two non-negative integers."""
    return _require_non_negative(left, label="left") ^ _require_non_negative(right, label="right")


def bitwise_not(value: int, width: int) -> int:
    """Return the bitwise NOT of *value* limited to *width* bits.

    An explicit width is mandatory: unbounded bitwise NOT has no meaningful
    interpretation for arbitrary-precision integers.

    Args:
        value: Non-negative integer that must fit in *width* bits.
        width: Number of bits in the result.

    Returns:
        The one's complement of *value* within *width* bits.

    Raises:
        InputValidationError: The width is not positive, the value is negative,
            or the value does not fit in the width.
    """
    number = _require_non_negative(value, label="value")
    bits = _require_width(width)
    _require_fits(number, bits)
    return (~number) & ((1 << bits) - 1)


def shift_left(value: int, shift: int, *, width: int | None = None) -> int:
    """Shift *value* left by *shift* bits.

    When *width* is supplied, the result is masked to that width (bits shifted
    out are discarded).  Without *width* the result grows without bound.

    Raises:
        InputValidationError: Inputs are negative, the shift is too large, or
            the value does not fit in the requested width.
    """
    number = _require_non_negative(value, label="value")
    amount = _require_non_negative(shift, label="shift")
    if amount > _MAX_SHIFT:
        raise InputValidationError(f"shift must not exceed {_MAX_SHIFT}")
    result = number << amount
    if width is None:
        return result
    bits = _require_width(width)
    _require_fits(number, bits)
    return result & ((1 << bits) - 1)


def shift_right(value: int, shift: int) -> int:
    """Shift *value* right by *shift* bits (logical shift)."""
    number = _require_non_negative(value, label="value")
    amount = _require_non_negative(shift, label="shift")
    if amount > _MAX_SHIFT:
        raise InputValidationError(f"shift must not exceed {_MAX_SHIFT}")
    return number >> amount


def mask_bits(value: int, width: int) -> int:
    """Keep only the low *width* bits of *value*."""
    number = _require_non_negative(value, label="value")
    bits = _require_width(width)
    return number & ((1 << bits) - 1)


def extract_bit_range(value: int, start: int, stop: int, *, width: int | None = None) -> int:
    """Extract bits ``[start, stop)`` using LSB-based indices.

    Args:
        value: Non-negative integer.
        start: First bit position (inclusive), counted from the LSB.
        stop: Last bit position (exclusive), counted from the LSB.
        width: Optional total width used to validate that both indices fit.

    Returns:
        The extracted bits as an integer, right-aligned.  For example,
        ``extract_bit_range(0b101101, 1, 5) == 0b0110``.

    Raises:
        InputValidationError: Indices are negative or reversed, or *width* is
            supplied and *stop* exceeds it.
    """
    number = _require_non_negative(value, label="value")
    first = _require_non_negative(start, label="start")
    last = _require_non_negative(stop, label="stop")
    if first >= last:
        raise InputValidationError("start must be smaller than stop")
    if width is not None:
        bits = _require_width(width)
        _require_fits(number, bits)
        if last > bits:
            raise InputValidationError("stop must not exceed the specified width")
    return (number >> first) & ((1 << (last - first)) - 1)


def reverse_bits(value: int, width: int) -> int:
    """Reverse the bit order of *value* inside *width* bits.

    Args:
        value: Non-negative integer that fits in *width* bits.
        width: Number of bits to reverse.

    Returns:
        The bit-reversed integer.  For example, ``reverse_bits(0b1100, 4) == 0b0011``.
    """
    number = _require_non_negative(value, label="value")
    bits = _require_width(width)
    _require_fits(number, bits)
    result = 0
    for index in range(bits):
        result = (result << 1) | ((number >> index) & 1)
    return result


def pad_binary(value: str, width: int, *, side: str = "left") -> str:
    """Pad a binary string to *width* characters without changing its value.

    Left padding (the default) preserves the numeric interpretation and is
    used by byte conversion.  Right padding shifts the value and is only
    appropriate when the caller explicitly wants it.

    Args:
        value: Binary text.
        width: Target length in characters; must be at least the current length.
        side: ``"left"`` or ``"right"``.

    Returns:
        The padded binary string.

    Raises:
        InputValidationError: The width is too small or the side is unknown.
        InvalidBinaryError: The input is not valid binary text.
    """
    text = normalize_binary(value)
    target = _require_width(width)
    if target < len(text):
        raise InputValidationError(
            f"cannot pad a {len(text)}-bit string to the smaller width {target}"
        )
    if side not in {"left", "right"}:
        raise InputValidationError("side must be 'left' or 'right'")
    if side == "left":
        return text.zfill(target)
    return text.ljust(target, "0")


@dataclass(frozen=True, slots=True)
class BitComparison:
    """Result of comparing two binary strings.

    Attributes:
        left: Left-padded left operand.
        right: Left-padded right operand.
        equal: Whether the padded strings are identical.
        width: Width of the padded operands.
        hamming_distance: Number of differing bits.
        differing_indices: Positions (from the MSB) where the bits differ.
        first_difference: Smallest differing index from the MSB, or ``None``.
        last_difference: Largest differing index from the MSB, or ``None``.
        padding_applied: Whether either operand was left-padded.
    """

    left: str
    right: str
    equal: bool
    width: int
    hamming_distance: int
    differing_indices: tuple[int, ...]
    first_difference: int | None
    last_difference: int | None
    padding_applied: bool


def _normalized_pair(left: str, right: str) -> tuple[str, str, bool]:
    first = normalize_binary(left)
    second = normalize_binary(right)
    width = max(len(first), len(second))
    padded = len(first) != len(second)
    return first.zfill(width), second.zfill(width), padded


def compare_binary_strings(left: str, right: str) -> BitComparison:
    """Compare two binary strings, left-padding the shorter one with zeros.

    Padding is always on the left so that the numeric values are preserved;
    the ``padding_applied`` field reports whether this happened.  String bit
    indices are counted from the MSB (leftmost character) of the padded
    operands.

    Raises:
        InvalidBinaryError: Either operand is invalid binary text.
    """
    first, second, padded = _normalized_pair(left, right)
    differing = tuple(
        index for index, (a, b) in enumerate(zip(first, second, strict=True)) if a != b
    )
    return BitComparison(
        left=first,
        right=second,
        equal=not differing,
        width=len(first),
        hamming_distance=len(differing),
        differing_indices=differing,
        first_difference=differing[0] if differing else None,
        last_difference=differing[-1] if differing else None,
        padding_applied=padded,
    )


def hamming_distance(left: int | str, right: int | str) -> int:
    """Return the Hamming distance between two integers or binary strings.

    Both operands must use the same representation.  Integers are compared
    after zero-extension to the wider operand; binary strings are left-padded
    with zeros.  Use :func:`hamming_distance_binary` for an explicit
    string-only result object.

    Raises:
        InputValidationError: Operand types are mixed or negative.
        InvalidBinaryError: A string operand is not valid binary text.
    """
    if isinstance(left, str) and isinstance(right, str):
        return compare_binary_strings(left, right).hamming_distance
    if (
        isinstance(left, int)
        and not isinstance(left, bool)
        and isinstance(right, int)
        and not isinstance(right, bool)
    ):
        if left < 0 or right < 0:
            raise InputValidationError("Hamming distance requires non-negative integers")
        return (left ^ right).bit_count()
    raise InputValidationError("both operands must have the same representation")


def hamming_distance_binary(left: str, right: str) -> int:
    """Return the Hamming distance between two binary strings (zero-padded left)."""
    return compare_binary_strings(left, right).hamming_distance


def first_differing_bit(left: int | str, right: int | str) -> int | None:
    """Return the first differing bit, or ``None`` when both values are equal.

    * Integers: index from the LSB (0 is the least-significant bit).
    * Binary strings: index from the MSB of the left-padded operands
      (0 is the leftmost character).

    Raises:
        InputValidationError: Mixed representations or negative integers.
        InvalidBinaryError: A string operand is not valid binary text.
    """
    if isinstance(left, str) and isinstance(right, str):
        return compare_binary_strings(left, right).first_difference
    if (
        isinstance(left, int)
        and not isinstance(left, bool)
        and isinstance(right, int)
        and not isinstance(right, bool)
    ):
        if left < 0 or right < 0:
            raise InputValidationError("bit comparison requires non-negative integers")
        difference = left ^ right
        if difference == 0:
            return None
        return (difference & -difference).bit_length() - 1
    raise InputValidationError("both operands must have the same representation")


def last_differing_bit(left: int | str, right: int | str) -> int | None:
    """Return the last differing bit, or ``None`` when both values are equal.

    * Integers: index from the LSB, i.e. the highest set bit of the XOR.
    * Binary strings: index from the MSB of the left-padded operands.

    Raises:
        InputValidationError: Mixed representations or negative integers.
        InvalidBinaryError: A string operand is not valid binary text.
    """
    if isinstance(left, str) and isinstance(right, str):
        return compare_binary_strings(left, right).last_difference
    if (
        isinstance(left, int)
        and not isinstance(left, bool)
        and isinstance(right, int)
        and not isinstance(right, bool)
    ):
        if left < 0 or right < 0:
            raise InputValidationError("bit comparison requires non-negative integers")
        difference = left ^ right
        return difference.bit_length() - 1 if difference else None
    raise InputValidationError("both operands must have the same representation")
