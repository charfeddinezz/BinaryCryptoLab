"""Base58 and Base58Check encoding (Bitcoin alphabet).

Base58 is a binary-to-text encoding, not encryption.  Base58Check appends the
first four bytes of ``SHA256(SHA256(payload))`` as a checksum, which detects
transcription errors.  Decoding verifies the checksum in constant time.

This module is dependency-free and follows the Bitcoin reference alphabet
``123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz``, which omits
``0``, ``O``, ``I``, and ``l`` to avoid visually ambiguous characters.
"""

from __future__ import annotations

import hmac
from typing import Final

from .exceptions import Base58Error, InputValidationError, InvalidBase58Error
from .hashing import double_sha256

__all__ = [
    "B58_ALPHABET",
    "b58decode",
    "b58encode",
    "base58check_decode",
    "base58check_encode",
    "base58check_verify",
]

B58_ALPHABET: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX: Final = {char: index for index, char in enumerate(B58_ALPHABET)}
_CHECKSUM_LENGTH: Final = 4


def _require_bytes(data: object, *, label: str = "payload") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError(f"{label} must be a bytes-like object")
    return bytes(data)


def b58encode(data: bytes | bytearray | memoryview) -> str:
    """Encode bytes with Base58 (no checksum).

    Leading zero bytes are encoded as leading ``1`` characters, so decoding
    restores them exactly.

    Raises:
        InputValidationError: The input is not bytes-like.
    """
    payload = _require_bytes(data)
    if not payload:
        return ""
    leading_zeros = len(payload) - len(payload.lstrip(b"\x00"))
    number = int.from_bytes(payload, "big")
    encoded = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(B58_ALPHABET[remainder])
    return "1" * leading_zeros + "".join(reversed(encoded))


def b58decode(text: str) -> bytes:
    """Decode a Base58 string (no checksum).

    Raises:
        Base58Error: The input is not text, contains characters outside the
            Bitcoin Base58 alphabet, or is empty.
    """
    if not isinstance(text, str):
        raise Base58Error("Base58 input must be a string")
    if not text:
        raise Base58Error("Base58 input must not be empty")
    number = 0
    for char in text:
        try:
            digit = _B58_INDEX[char]
        except KeyError as exc:
            raise Base58Error(f"invalid Base58 character {char!r}") from exc
        number = number * 58 + digit
    leading_ones = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading_ones + body


def base58check_encode(payload: bytes | bytearray | memoryview) -> str:
    """Encode *payload* as Base58Check.

    The checksum is the first four bytes of ``SHA256(SHA256(payload))``.

    Raises:
        InputValidationError: The payload is not bytes-like or is empty.
    """
    data = _require_bytes(data=payload)
    if not data:
        raise InputValidationError("Base58Check payload must not be empty")
    return b58encode(data + double_sha256(data)[:_CHECKSUM_LENGTH])


def base58check_decode(text: str, *, verify: bool = True) -> bytes:
    """Decode Base58Check text and return the payload without the checksum.

    Args:
        text: Base58Check string.
        verify: When ``True`` (the default) the checksum is validated.

    Returns:
        The decoded payload.

    Raises:
        InvalidBase58Error: The checksum does not match or the input is too
            short to contain a checksum.
        Base58Error: The input is not valid Base58 text.
    """
    raw = b58decode(text)
    if len(raw) < _CHECKSUM_LENGTH + 1:
        raise InvalidBase58Error("Base58Check input is too short to contain a checksum")
    payload, checksum = raw[:-_CHECKSUM_LENGTH], raw[-_CHECKSUM_LENGTH:]
    if verify:
        expected = double_sha256(payload)[:_CHECKSUM_LENGTH]
        if not hmac.compare_digest(checksum, expected):
            raise InvalidBase58Error("Base58Check checksum verification failed")
    return payload


def base58check_verify(text: str) -> bool:
    """Return whether *text* is valid Base58Check data.

    This predicate never raises for malformed strings.
    """
    try:
        base58check_decode(text)
    except (Base58Error, InputValidationError):
        return False
    return True
