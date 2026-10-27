"""Strict input normalization and validation.

The functions in this module are deliberately conservative: malformed input is
rejected instead of being reinterpreted.  Every rejection raises a documented
exception from :mod:`binarycryptolab.exceptions`.

Normalization rules
-------------------
* ASCII whitespace (spaces, tabs, newlines, carriage returns, vertical tabs,
  and form feeds) is removed from anywhere in the string.  This makes grouped
  input such as ``"1011 0101"`` or ``"de ad be ef"`` convenient to type.
* An optional base prefix (``0b`` / ``0B``, ``0x`` / ``0X``) is removed when
  prefixes are allowed.  Prefixes are only recognised at the start of the
  input, after whitespace removal.
* Binary digits are limited to ``0`` and ``1``.  Hexadecimal digits are
  accepted in either case and normalized to lowercase.
* Empty input is always rejected explicitly.
* Hexadecimal input with an odd number of digits is rejected unless
  ``allow_odd=True``; in that case a single zero nibble is prepended on the
  left (``"abc"`` becomes ``"0abc"``).  This policy is explicit and is
  reported by the analysis layer as a warning.
* Input size is checked before scanning for invalid characters.
"""

from __future__ import annotations

from .config import DEFAULT_INPUT_LIMITS, InputLimits
from .exceptions import (
    InputValidationError,
    InvalidBinaryError,
    InvalidDecimalError,
    InvalidHexError,
)

__all__ = [
    "normalize_binary",
    "normalize_hex",
    "parse_decimal",
    "strip_whitespace",
]

_WHITESPACE = " \t\r\n\v\f"
_WHITESPACE_TABLE = str.maketrans("", "", _WHITESPACE)
_BINARY_ALPHABET = frozenset("01")
_HEX_ALPHABET = frozenset("0123456789abcdef")
_DECIMAL_ALPHABET = frozenset("0123456789")


def strip_whitespace(value: str) -> str:
    """Remove all ASCII whitespace characters from *value*.

    Args:
        value: Text to normalize.

    Returns:
        The text with every ASCII whitespace character removed.  The original
        string is never modified in place.
    """
    return value.translate(_WHITESPACE_TABLE)


def _require_text(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise InputValidationError(f"{label} must be a string, got {type(value).__name__}")
    return value


def _check_length(length: int, limit: int, *, label: str) -> None:
    if length > limit:
        raise InputValidationError(
            f"{label} is too long: {length} characters exceeds the limit of {limit}"
        )


def normalize_binary(
    value: str,
    *,
    allow_prefix: bool = True,
    max_length: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> str:
    """Validate a binary string and return its canonical form.

    Args:
        value: Binary text, optionally containing ASCII whitespace and an
            optional ``0b`` prefix.
        allow_prefix: Whether a leading ``0b``/``0B`` prefix is accepted.
            When ``False``, such a prefix is reported as invalid input.
        max_length: Optional per-call override of
            :attr:`InputLimits.max_binary_length`.
        limits: Limit bundle used when *max_length* is ``None``.

    Returns:
        The binary digits only, with no prefix and no whitespace.

    Raises:
        InputValidationError: The value is not text, is too long, or has an
            invalid length limit.
        InvalidBinaryError: The input is empty, has an unexpected prefix, or
            contains characters other than ``0`` and ``1``.
    """
    text = strip_whitespace(_require_text(value, label="binary input"))
    limit = limits.max_binary_length if max_length is None else max_length
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InputValidationError("binary length limit must be an integer")
    if limit <= 0:
        raise InputValidationError("binary length limit must be positive")

    _check_length(len(text), limit + 2, label="binary input")
    if text[:2].lower() == "0b":
        if not allow_prefix:
            raise InvalidBinaryError("binary input must not include a '0b' prefix")
        text = text[2:]

    if not text:
        raise InvalidBinaryError(
            "binary input is empty after removing whitespace and the optional prefix"
        )
    _check_length(len(text), limit, label="binary input")

    invalid = sorted({char for char in text if char not in _BINARY_ALPHABET})
    if invalid:
        rendered = ", ".join(repr(char) for char in invalid)
        raise InvalidBinaryError(
            f"binary input contains invalid character(s): {rendered}; only '0' and '1' are allowed"
        )
    return text


def normalize_hex(
    value: str,
    *,
    allow_prefix: bool = True,
    allow_odd: bool = False,
    max_length: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> str:
    """Validate a hexadecimal string and return its canonical form.

    Args:
        value: Hexadecimal text, optionally containing ASCII whitespace and an
            optional ``0x`` prefix.  Upper- and lowercase digits are accepted.
        allow_prefix: Whether a leading ``0x``/``0X`` prefix is accepted.
        allow_odd: When ``True``, an odd number of digits is accepted and a
            single ``0`` nibble is prepended.  When ``False`` (the default),
            odd-length input is rejected.
        max_length: Optional per-call override of
            :attr:`InputLimits.max_hex_length`.
        limits: Limit bundle used when *max_length* is ``None``.

    Returns:
        Lowercase hexadecimal digits, even-length by construction, with no
        prefix and no whitespace.

    Raises:
        InputValidationError: The value is not text or is too long.
        InvalidHexError: The input is empty, has an unexpected prefix, has an
            odd number of digits while ``allow_odd`` is ``False``, or contains
            characters outside ``0-9a-fA-F``.
    """
    text = strip_whitespace(_require_text(value, label="hexadecimal input"))
    limit = limits.max_hex_length if max_length is None else max_length
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InputValidationError("hexadecimal length limit must be an integer")
    if limit <= 0:
        raise InputValidationError("hexadecimal length limit must be positive")

    _check_length(len(text), limit + 2, label="hexadecimal input")
    if text[:2].lower() == "0x":
        if not allow_prefix:
            raise InvalidHexError("hexadecimal input must not include a '0x' prefix")
        text = text[2:]

    if not text:
        raise InvalidHexError(
            "hexadecimal input is empty after removing whitespace and the optional prefix"
        )
    _check_length(len(text), limit, label="hexadecimal input")

    lowered = text.lower()
    invalid = sorted({char for char in lowered if char not in _HEX_ALPHABET})
    if invalid:
        rendered = ", ".join(repr(char) for char in invalid)
        raise InvalidHexError(
            f"hexadecimal input contains invalid character(s): {rendered}; "
            "only 0-9 and a-f (either case) are allowed"
        )

    if len(lowered) % 2:
        if not allow_odd:
            raise InvalidHexError(
                "hexadecimal input has an odd number of digits "
                f"({len(lowered)}); pad it with a leading zero or pass allow_odd=True"
            )
        lowered = "0" + lowered
    return lowered


def parse_decimal(
    value: str | int,
    *,
    min_value: int | None = 0,
    max_value: int | None = None,
    max_digits: int | None = None,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> int:
    """Parse a non-negative decimal integer with strict validation.

    Args:
        value: Decimal text or a non-boolean integer.  Text may contain ASCII
            whitespace and underscores as visual separators, and may start
            with ``+``.
        min_value: Inclusive lower bound, or ``None`` for no lower bound.
        max_value: Inclusive upper bound, or ``None`` for no upper bound.
        max_digits: Optional override of
            :attr:`InputLimits.max_decimal_digits`.
        limits: Limit bundle used when *max_digits* is ``None``.

    Returns:
        The parsed integer.

    Raises:
        InvalidDecimalError: The text is empty, contains non-digit characters,
            or is outside the requested range.
        InputValidationError: The value has an unsupported type or is too long.
    """
    if isinstance(value, bool):
        raise InputValidationError("decimal input must be an integer, not a boolean")
    if isinstance(value, int):
        number = value
        digits = len(str(abs(number)))
    else:
        text = strip_whitespace(_require_text(value, label="decimal input"))
        limit = limits.max_decimal_digits if max_digits is None else max_digits
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise InputValidationError("decimal digit limit must be a positive integer")
        if text.startswith("+"):
            text = text[1:]
        text = text.replace("_", "")
        if not text:
            raise InvalidDecimalError("decimal input is empty")
        if text.startswith("-"):
            raise InvalidDecimalError("decimal input must not be negative")
        _check_length(len(text), limit, label="decimal input")
        if any(char not in _DECIMAL_ALPHABET for char in text):
            raise InvalidDecimalError("decimal input contains characters other than digits 0-9")
        digits = len(text)
        number = int(text)

    if max_digits is not None and digits > max_digits:
        raise InvalidDecimalError(
            f"decimal input has {digits} digits, exceeding the limit of {max_digits}"
        )
    if min_value is not None and number < min_value:
        raise InvalidDecimalError(f"decimal input must be at least {min_value}")
    if max_value is not None and number > max_value:
        raise InvalidDecimalError(f"decimal input must be at most {max_value}")
    return number
