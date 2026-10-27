"""Hexadecimal conversion helpers.

Hexadecimal text is ambiguous unless the caller states what it represents.
This module keeps three views separate and never guesses:

* **Numeric value** - :func:`hex_to_int`, :func:`int_to_hex`.
* **Encoded byte sequence** - :func:`hex_to_bytes`, :func:`bytes_to_hex`.
* **Text** - :func:`hex_to_text` and :func:`text_to_hex` are the only
  functions that interpret bytes as text, and they require an explicit
  encoding (UTF-8 by default, with strict error handling).

Hexadecimal input is never assumed to be UTF-8.
"""

from __future__ import annotations

from typing import Final

from .exceptions import InputValidationError, InvalidHexError
from .validation import normalize_hex, strip_whitespace

__all__ = [
    "bytes_to_hex",
    "hex_digit_count",
    "hex_to_binary",
    "hex_to_bytes",
    "hex_to_int",
    "hex_to_text",
    "int_to_hex",
    "is_hex_string",
    "text_to_hex",
]

_HEX_DIGITS: Final = frozenset("0123456789abcdefABCDEF")


def hex_to_bytes(value: str, *, allow_odd: bool = True, max_length: int | None = None) -> bytes:
    """Decode hexadecimal text to bytes.

    Odd-length input is accepted by default and padded with one leading zero
    nibble; pass ``allow_odd=False`` to reject it instead.

    Raises:
        InvalidHexError: The input is not valid hexadecimal or has an odd
            number of digits while ``allow_odd`` is ``False``.
    """
    digits = normalize_hex(value, allow_odd=allow_odd, max_length=max_length)
    return bytes.fromhex(digits)


def bytes_to_hex(data: bytes | bytearray | memoryview, *, uppercase: bool = False) -> str:
    """Encode bytes as hexadecimal text.

    Raises:
        InputValidationError: *data* is not a bytes-like object.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError("data must be a bytes-like object")
    text = bytes(data).hex()
    return text.upper() if uppercase else text


def hex_to_int(value: str, *, max_length: int | None = None) -> int:
    """Interpret hexadecimal text as a non-negative integer.

    Leading zero nibbles do not affect the result.

    Raises:
        InvalidHexError: The input is not valid hexadecimal.
    """
    digits = normalize_hex(value, allow_odd=True, max_length=max_length)
    return int(digits, 16)


def int_to_hex(value: int, *, bytes_length: int | None = None, prefix: bool = False) -> str:
    """Encode a non-negative integer as even-length lowercase hexadecimal.

    Args:
        value: Non-negative integer.
        bytes_length: Optional fixed size in bytes.  The value must fit and the
            output has exactly ``2 * bytes_length`` digits.
        prefix: Whether to prepend ``0x``.

    Raises:
        InputValidationError: The integer is negative or does not fit.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("value must be an integer")
    if value < 0:
        raise InputValidationError("only non-negative integers have a hexadecimal representation")
    if bytes_length is None:
        digits = format(value, "x")
        if len(digits) % 2:
            digits = "0" + digits
    else:
        if isinstance(bytes_length, bool) or not isinstance(bytes_length, int) or bytes_length <= 0:
            raise InputValidationError("bytes_length must be a positive integer")
        try:
            digits = value.to_bytes(bytes_length, "big").hex()
        except OverflowError as exc:
            raise InputValidationError(f"value does not fit in {bytes_length} byte(s)") from exc
    return "0x" + digits if prefix else digits


def hex_digit_count(value: str, *, allow_prefix: bool = True) -> int:
    """Return the number of hexadecimal digits the user supplied.

    The count reflects the input exactly: it excludes whitespace and an
    accepted ``0x`` prefix, includes leading zeros, and does not include the
    padding nibble that odd-length normalization may add.

    Raises:
        InvalidHexError: The input is empty or not valid hexadecimal.
    """
    normalize_hex(value, allow_prefix=allow_prefix, allow_odd=True)
    text = strip_whitespace(value)
    if allow_prefix and text[:2].lower() == "0x":
        text = text[2:]
    return len(text)


def is_hex_string(value: str, *, allow_prefix: bool = True) -> bool:
    """Return whether *value* is non-empty hexadecimal text.

    This helper never raises for malformed strings.
    """
    if not isinstance(value, str):
        return False
    try:
        normalize_hex(value, allow_prefix=allow_prefix, allow_odd=True)
    except Exception:
        return False
    return True


def hex_to_binary(value: str, *, allow_odd: bool = True, max_length: int | None = None) -> str:
    """Convert hexadecimal text to a width-preserving binary string.

    Each hexadecimal digit becomes exactly four binary digits.

    Raises:
        InvalidHexError: The input is not valid hexadecimal.
    """
    digits = normalize_hex(value, allow_odd=allow_odd, max_length=max_length)
    return "".join(format(int(char, 16), "04b") for char in digits)


def hex_to_text(
    value: str, *, encoding: str = "utf-8", errors: str = "strict", max_length: int | None = None
) -> str:
    """Decode hexadecimal text as text using an explicit encoding.

    This is the *only* function in the package that treats hexadecimal input as
    text.  Decoding failures are reported as :class:`InvalidHexError` rather
    than being silently replaced.

    Raises:
        InvalidHexError: The input is not valid hexadecimal or cannot be
            decoded with the requested encoding.
        InputValidationError: The encoding name is not a known codec.
    """
    data = hex_to_bytes(value, max_length=max_length)
    try:
        return data.decode(encoding, errors=errors)
    except LookupError as exc:
        raise InputValidationError(f"unknown text encoding: {encoding!r}") from exc
    except UnicodeDecodeError as exc:
        raise InvalidHexError(f"hexadecimal input is not valid {encoding} text") from exc


def text_to_hex(text: str, *, encoding: str = "utf-8", errors: str = "strict") -> str:
    """Encode text as lowercase hexadecimal using an explicit encoding.

    Raises:
        InputValidationError: The value is not text, the encoding is unknown,
            or the text cannot be encoded.
    """
    if not isinstance(text, str):
        raise InputValidationError("text must be a string")
    try:
        return text.encode(encoding, errors).hex()
    except LookupError as exc:
        raise InputValidationError(f"unknown text encoding: {encoding!r}") from exc
    except UnicodeEncodeError as exc:
        raise InputValidationError(
            f"text cannot be encoded as {encoding} with errors={errors!r}"
        ) from exc
