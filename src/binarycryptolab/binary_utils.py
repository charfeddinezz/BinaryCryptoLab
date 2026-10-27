"""Binary string conversion helpers.

Representation policy
---------------------
A binary string carries two independent pieces of information: its numeric
value and its textual width (number of characters).  This module keeps them
separate:

* :class:`BinaryString` stores the *original* text, the *digits* with leading
  zeros preserved, and the derived integer value.
* :func:`binary_to_bytes` documents exactly how non-byte-aligned strings are
  padded (left padding, i.e. zeros are prepended).  :func:`binary_to_bytes_padded`
  also returns the number of padding bits so callers can remove them later.

No function silently drops leading zeros.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from .exceptions import InputValidationError
from .validation import normalize_binary, normalize_hex

__all__ = [
    "BinaryString",
    "binary_to_bytes",
    "binary_to_bytes_padded",
    "binary_to_hex",
    "binary_to_int",
    "bits_to_bytes",
    "bytes_to_binary",
    "group_bits",
    "hex_to_binary",
    "int_to_binary",
    "int_to_hex",
]

PaddingSide = Literal["left", "right"]

_HEX_DIGITS: Final = "0123456789abcdef"


@dataclass(frozen=True, slots=True)
class BinaryString:
    """A validated binary string that preserves its original representation.

    Attributes:
        original: Exactly what the user supplied.
        digits: Binary digits with whitespace and the optional prefix removed.
            Leading zeros are kept.
        value: Integer value of ``digits``.
        length: Number of bit characters in ``digits``.
    """

    original: str
    digits: str
    value: int
    length: int

    @classmethod
    def parse(cls, text: str, *, max_length: int | None = None) -> BinaryString:
        """Validate *text* and build a :class:`BinaryString`."""
        digits = normalize_binary(text, max_length=max_length)
        return cls(original=text, digits=digits, value=int(digits, 2), length=len(digits))

    @property
    def is_byte_aligned(self) -> bool:
        """Whether the digit count is a multiple of eight."""
        return self.length % 8 == 0

    @property
    def padding_bits(self) -> int:
        """Number of zero bits that left-padding to a whole byte would add."""
        return (-self.length) % 8

    @property
    def byte_length(self) -> int:
        """Number of bytes after left padding to a byte boundary."""
        return (self.length + 7) // 8


def binary_to_int(value: str, *, max_length: int | None = None) -> int:
    """Convert a binary string to a non-negative integer.

    Leading zeros do not affect the result.  ``"0"`` is valid and yields ``0``.

    Raises:
        InvalidBinaryError: The input is not valid binary text.
    """
    return int(normalize_binary(value, max_length=max_length), 2)


def int_to_binary(value: int, *, width: int | None = None) -> str:
    """Convert a non-negative integer to a binary string.

    Args:
        value: Non-negative integer.
        width: Optional minimum width; the result is zero-padded on the left to
            at least this many characters.

    Raises:
        InputValidationError: The integer is negative or the width is invalid.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("value must be an integer")
    if value < 0:
        raise InputValidationError("only non-negative integers have a binary representation")
    digits = format(value, "b")
    if width is None:
        return digits
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise InputValidationError("width must be a positive integer")
    if width < len(digits):
        raise InputValidationError(f"value needs {len(digits)} bits, which exceeds width {width}")
    return digits.zfill(width)


def int_to_hex(value: int, *, width: int | None = None, prefix: bool = False) -> str:
    """Convert a non-negative integer to lowercase hexadecimal.

    Args:
        value: Non-negative integer.
        width: Optional minimum number of hexadecimal digits (left-padded with
            zeros).  The result always has an even number of digits when no
            width is given and the value needs an odd number of nibbles.
        prefix: Whether to prepend ``0x``.

    Raises:
        InputValidationError: The integer is negative or the width is invalid.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("value must be an integer")
    if value < 0:
        raise InputValidationError("only non-negative integers have a hexadecimal representation")
    digits = format(value, "x")
    if len(digits) % 2:
        digits = "0" + digits
    if width is not None:
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise InputValidationError("width must be a positive integer")
        if width < len(digits):
            raise InputValidationError(f"width {width} is smaller than {len(digits)} digits")
        digits = digits.zfill(width if width % 2 == 0 else width + 1)
    return ("0x" + digits) if prefix else digits


def binary_to_hex(value: str, *, max_length: int | None = None) -> str:
    """Convert a binary string to even-length lowercase hexadecimal.

    The binary string is left-padded to a multiple of four bits so that the
    numeric value is preserved (``"101101"`` becomes ``"2d"``).

    Raises:
        InvalidBinaryError: The input is not valid binary text.
    """
    digits = normalize_binary(value, max_length=max_length)
    padding = (-len(digits)) % 4
    return format(int(digits, 2), "x").zfill((len(digits) + padding) // 4)


def hex_to_binary(value: str, *, allow_odd: bool = True, max_length: int | None = None) -> str:
    """Convert hexadecimal text to binary, preserving the encoded width.

    The returned string has exactly ``4 * len(normalized_hex)`` characters, so
    each nibble maps to four bits and leading zero bits are preserved.

    Args:
        value: Hexadecimal text.
        allow_odd: Whether odd-length hexadecimal input is padded with one zero
            nibble (see :func:`binarycryptolab.validation.normalize_hex`).
        max_length: Optional limit on the number of hexadecimal digits.

    Raises:
        InvalidHexError: The input is not valid hexadecimal.
    """
    digits = normalize_hex(value, allow_odd=allow_odd, max_length=max_length)
    return "".join(format(int(char, 16), "04b") for char in digits)


def bits_to_bytes(bits: list[int] | tuple[int, ...]) -> bytes:
    """Pack a sequence of bit values (MSB first) into bytes, padding on the right.

    This helper is intentionally narrow: it is used by tests and examples to
    demonstrate why left padding (used by :func:`binary_to_bytes`) preserves
    the numeric value while right padding does not.

    Raises:
        InputValidationError: A bit value is not 0 or 1.
    """
    if not bits:
        raise InputValidationError("at least one bit is required")
    for bit in bits:
        if bit not in (0, 1):
            raise InputValidationError("bit values must be 0 or 1")
    padded = list(bits) + [0] * ((-len(bits)) % 8)
    result = bytearray()
    for start in range(0, len(padded), 8):
        byte = 0
        for bit in padded[start : start + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def binary_to_bytes_padded(
    value: str, *, side: PaddingSide = "left", max_length: int | None = None
) -> tuple[bytes, int]:
    """Convert binary text to bytes and report the padding that was applied.

    Args:
        value: Binary text.
        side: ``"left"`` (default, preserves numeric value) or ``"right"``
            (appends zero bits, which changes the numeric value and is only
            useful for bitstream-style data).
        max_length: Optional limit on the number of binary digits.

    Returns:
        ``(data, padding_bits)`` where ``padding_bits`` is in ``0..7``.

    Raises:
        InvalidBinaryError: The input is not valid binary text.
        InputValidationError: The padding side is unknown.
    """
    digits = normalize_binary(value, max_length=max_length)
    padding = (-len(digits)) % 8
    if side == "left":
        packed = digits.zfill(len(digits) + padding)
    elif side == "right":
        packed = digits.ljust(len(digits) + padding, "0")
    else:
        raise InputValidationError("side must be 'left' or 'right'")
    return int(packed, 2).to_bytes((len(packed) // 8), "big"), padding


def binary_to_bytes(
    value: str, *, side: PaddingSide = "left", max_length: int | None = None
) -> bytes:
    """Convert binary text to bytes.

    Non-byte-aligned input is padded to the next byte boundary.  The default
    left padding preserves the numeric value; ``side="right"`` shifts the
    value and is documented as such.  Use :func:`binary_to_bytes_padded` when
    the caller needs to know how many padding bits were added.

    Raises:
        InvalidBinaryError: The input is not valid binary text.
        InputValidationError: The padding side is unknown.
    """
    return binary_to_bytes_padded(value, side=side, max_length=max_length)[0]


def bytes_to_binary(data: bytes | bytearray | memoryview, *, width: int | None = None) -> str:
    """Convert bytes-like data to a binary string, MSB first.

    Args:
        data: Bytes to convert.  An empty value yields ``""`` unless *width*
            is given.
        width: Optional exact width in bits.  When supplied, the output is
            zero-padded on the left to that width and the data must fit.

    Raises:
        InputValidationError: The type or width is unsupported, or the data
            does not fit in *width*.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError("data must be a bytes-like object")
    digits = "".join(format(byte, "08b") for byte in bytes(data))
    if width is None:
        return digits
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise InputValidationError("width must be a positive integer")
    if len(digits) > width:
        raise InputValidationError(f"{len(digits)} bits do not fit in width {width}")
    return digits.zfill(width)


def group_bits(
    value: str, *, group_size: int = 4, separator: str = " ", pad_left: bool = False
) -> str:
    """Group a binary string into blocks for display.

    Grouping starts at the leftmost character and never changes the digits, so
    the displayed string always represents exactly the same bit sequence and
    width as the input.  Set ``pad_left=True`` to zero-pad the first group to a
    full block (useful for aligned tables, at the cost of adding leading zeros
    that were not in the input).

    Args:
        value: Binary text.
        group_size: Number of bits per group.
        separator: Text placed between groups.
        pad_left: Whether the first group is zero-padded to full width.

    Returns:
        Grouped text.

    Raises:
        InvalidBinaryError: The input is not valid binary text.
        InputValidationError: The group size is invalid.
    """
    if isinstance(group_size, bool) or not isinstance(group_size, int) or group_size <= 0:
        raise InputValidationError("group_size must be a positive integer")
    digits = normalize_binary(value)
    if pad_left:
        padding = (-len(digits)) % group_size
        digits = digits.zfill(len(digits) + padding)
    return separator.join(
        digits[index : index + group_size] for index in range(0, len(digits), group_size)
    )
