"""Bech32 and Bech32m encoding (BIP-173 and BIP-350).

The implementation follows the reference algorithms published with BIP-173 and
BIP-350.  It is deliberately small and heavily tested against the published
test vectors:

* Bech32 (checksum constant ``1``) is used for SegWit version 0 programs.
* Bech32m (checksum constant ``0x2bc830a3``) is used for SegWit versions 1-16.

SegWit addresses (``bc1...``, ``tb1...``, ``bcrt1...``) are produced by
:func:`encode_segwit_address`, which validates the human-readable part, witness
version, and witness program length as required by BIP-173/BIP-350.

Bech32 is an encoding with error detection, not encryption or a signature.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from .exceptions import InputValidationError, InvalidBech32Error

__all__ = [
    "BECH32_HRP_LIMIT",
    "Bech32Spec",
    "bech32_create_checksum",
    "bech32_decode",
    "bech32_encode",
    "bech32_polymod",
    "bech32_verify_checksum",
    "convert_5_to_8",
    "convert_8_to_5",
    "decode_segwit_address",
    "encode_segwit_address",
]

CHARSET: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_REV: Final = {char: index for index, char in enumerate(CHARSET)}
_GENERATOR: Final = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
BECH32_HRP_LIMIT: Final = 83
MAX_ADDRESS_LENGTH: Final = 90
_SEGWIT_VERSION_MAX: Final = 16
_WITNESS_PROGRAM_MIN: Final = 2
_WITNESS_PROGRAM_MAX: Final = 40
_WITNESS_V0_PROGRAM_LENGTH: Final = 20


class Bech32Spec(StrEnum):
    """Checksum variant."""

    BECH32 = "bech32"
    BECH32M = "bech32m"

    @property
    def constant(self) -> int:
        """The checksum constant for this variant."""
        return 1 if self is Bech32Spec.BECH32 else 0x2BC830A3


def _require_text(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise InputValidationError(f"{label} must be a string")
    return value


def bech32_polymod(values: list[int] | tuple[int, ...]) -> int:
    """Return the BCH checksum polymod of a sequence of 5-bit values."""
    checksum = 1
    for value in values:
        if not isinstance(value, int) or not 0 <= value <= 31:
            raise InvalidBech32Error("polymod input values must be 5-bit integers")
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(_GENERATOR):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the human-readable part for checksum computation.

    Raises:
        InvalidBech32Error: The HRP contains characters outside ``33..126``.
    """
    if not isinstance(hrp, str) or not hrp:
        raise InvalidBech32Error("Bech32 human-readable part must be a non-empty string")
    for code in (ord(char) for char in hrp):
        if not 33 <= code <= 126:
            raise InvalidBech32Error("Bech32 human-readable part has an invalid character")
    values = [ord(char) >> 5 for char in hrp]
    values.append(0)
    values.extend(ord(char) & 31 for char in hrp)
    return values


def bech32_verify_checksum(hrp: str, data: list[int] | tuple[int, ...]) -> Bech32Spec | None:
    """Return the checksum variant that matches, or ``None`` if none does."""
    checksum = bech32_polymod(bech32_hrp_expand(hrp) + list(data))
    for spec in (Bech32Spec.BECH32, Bech32Spec.BECH32M):
        if checksum == spec.constant:
            return spec
    return None


def bech32_create_checksum(
    hrp: str, data: list[int] | tuple[int, ...], spec: Bech32Spec
) -> list[int]:
    """Create the six-value checksum for *hrp* and *data*."""
    values = bech32_hrp_expand(hrp) + list(data)
    polymod = bech32_polymod([*values, 0, 0, 0, 0, 0, 0]) ^ spec.constant
    return [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]


def bech32_encode(hrp: str, data: list[int] | tuple[int, ...], spec: Bech32Spec) -> str:
    """Encode an HRP and 5-bit data values as a Bech32 or Bech32m string.

    Args:
        hrp: Human-readable part, ``1..83`` characters.
        data: 5-bit values (each ``0..31``).
        spec: Checksum variant.

    Raises:
        InvalidBech32Error: The HRP or data values are invalid.
    """
    text = _require_text(hrp, label="human-readable part")
    if not 1 <= len(text) <= BECH32_HRP_LIMIT:
        raise InvalidBech32Error(f"human-readable part must be 1..{BECH32_HRP_LIMIT} characters")
    if text.lower() != text:
        raise InvalidBech32Error("human-readable part must be lowercase")
    for value in data:
        if not isinstance(value, int) or not 0 <= value <= 31:
            raise InvalidBech32Error("bech32 data values must be integers in 0..31")
    checksum = bech32_create_checksum(text, data, spec)
    encoded = "".join(CHARSET[value] for value in [*data, *checksum])
    result = f"{text}1{encoded}"
    if len(result) > MAX_ADDRESS_LENGTH:
        raise InvalidBech32Error(f"encoded Bech32 string exceeds {MAX_ADDRESS_LENGTH} characters")
    return result


def bech32_decode(text: str) -> tuple[str, list[int], Bech32Spec]:
    """Decode a Bech32 or Bech32m string.

    Args:
        text: Encoded string.  Mixed-case strings are rejected (BIP-173).

    Returns:
        ``(hrp, data_without_checksum, spec)``.

    Raises:
        InvalidBech32Error: The string is malformed, has a mixed case, an
            invalid separator, an invalid character, or an invalid checksum.
    """
    value = _require_text(text, label="bech32 string")
    if not 8 <= len(value) <= MAX_ADDRESS_LENGTH:
        raise InvalidBech32Error(
            f"bech32 string length must be between 8 and {MAX_ADDRESS_LENGTH} characters"
        )
    if value.lower() != value and value.upper() != value:
        raise InvalidBech32Error("bech32 strings must not mix upper- and lowercase")
    value = value.lower()
    separator = value.rfind("1")
    if separator < 1 or separator + 7 > len(value):
        raise InvalidBech32Error("bech32 string has an invalid separator position")
    hrp = value[:separator]
    if len(hrp) > BECH32_HRP_LIMIT:
        raise InvalidBech32Error("bech32 human-readable part is too long")
    data: list[int] = []
    for char in value[separator + 1 :]:
        try:
            data.append(CHARSET_REV[char])
        except KeyError as exc:
            raise InvalidBech32Error(f"invalid bech32 character {char!r}") from exc
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        raise InvalidBech32Error("bech32 checksum verification failed")
    return hrp, data[:-6], spec


def convert_8_to_5(data: bytes | bytearray, *, pad: bool = True) -> list[int]:
    """Regroup 8-bit data into 5-bit values (BIP-173 reference algorithm).

    Args:
        data: Bytes to convert.
        pad: Whether a final partial group is zero-padded.  When ``False`` a
            non-zero remainder is rejected.

    Raises:
        InvalidBech32Error: A value is out of range or the remainder is invalid
            while ``pad`` is ``False``.
    """
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = 31
    max_accumulator = (1 << 12) - 1
    for byte in bytes(data):
        if not 0 <= byte <= 255:
            raise InvalidBech32Error("8-bit input values must be in 0..255")
        accumulator = ((accumulator << 8) | byte) & max_accumulator
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (5 - bits)) & max_value)
    elif bits >= 5 or ((accumulator << (5 - bits)) & max_value):
        raise InvalidBech32Error("invalid padding in 8-to-5 conversion")
    return result


def convert_5_to_8(data: list[int] | tuple[int, ...], *, pad: bool = True) -> bytes:
    """Regroup 5-bit values into bytes (BIP-173 reference algorithm).

    Args:
        data: 5-bit values to convert.
        pad: Whether a final partial byte is zero-padded.  When ``False`` a
            non-zero remainder is rejected, which is what SegWit address
            decoding requires.

    Raises:
        InvalidBech32Error: A value is out of range or the remainder is invalid
            while ``pad`` is ``False``.
    """
    accumulator = 0
    bits = 0
    result = bytearray()
    max_value = 255
    max_accumulator = (1 << 12) - 1
    for value in data:
        if not isinstance(value, int) or not 0 <= value <= 31:
            raise InvalidBech32Error("5-bit input values must be in 0..31")
        accumulator = ((accumulator << 5) | value) & max_accumulator
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (8 - bits)) & max_value)
    elif bits >= 5 or ((accumulator << (8 - bits)) & max_value):
        raise InvalidBech32Error("invalid padding in 5-to-8 conversion")
    return bytes(result)


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a SegWit address per BIP-173/BIP-350.

    Args:
        hrp: Human-readable part (``bc``, ``tb``, ``bcrt``).
        witver: Witness version ``0..16``.
        witprog: Witness program bytes.

    Returns:
        The encoded address.

    Raises:
        InvalidBech32Error: The version, program length, or HRP is invalid.
    """
    if isinstance(witver, bool) or not isinstance(witver, int):
        raise InvalidBech32Error("witness version must be an integer")
    if not 0 <= witver <= _SEGWIT_VERSION_MAX:
        raise InvalidBech32Error("witness version must be between 0 and 16")
    if not isinstance(witprog, (bytes, bytearray)):
        raise InvalidBech32Error("witness program must be bytes")
    program = bytes(witprog)
    if not _WITNESS_PROGRAM_MIN <= len(program) <= _WITNESS_PROGRAM_MAX:
        raise InvalidBech32Error("witness program must be 2..40 bytes")
    if witver == 0 and len(program) not in (_WITNESS_V0_PROGRAM_LENGTH, 32):
        raise InvalidBech32Error("witness version 0 programs must be 20 or 32 bytes")
    spec = Bech32Spec.BECH32 if witver == 0 else Bech32Spec.BECH32M
    return bech32_encode(hrp, [witver, *convert_8_to_5(program)], spec)


def decode_segwit_address(expected_hrp: str, address: str) -> tuple[int, bytes]:
    """Decode and validate a SegWit address.

    Args:
        expected_hrp: Required human-readable part, e.g. ``"bc"``.
        address: Address to decode.

    Returns:
        ``(witness_version, witness_program)``.

    Raises:
        InvalidBech32Error: The HRP does not match, the checksum variant is
            wrong for the witness version, the version is invalid, or the
            program length is invalid.
    """
    hrp, data, spec = bech32_decode(address)
    if hrp != expected_hrp:
        raise InvalidBech32Error(
            f"address human-readable part {hrp!r} does not match the expected {expected_hrp!r}"
        )
    if not data:
        raise InvalidBech32Error("address is missing a witness version")
    witver = data[0]
    if witver > _SEGWIT_VERSION_MAX:
        raise InvalidBech32Error("witness version must be between 0 and 16")
    program = convert_5_to_8(data[1:], pad=False)
    if not _WITNESS_PROGRAM_MIN <= len(program) <= _WITNESS_PROGRAM_MAX:
        raise InvalidBech32Error("witness program must be 2..40 bytes")
    if witver == 0 and len(program) not in (_WITNESS_V0_PROGRAM_LENGTH, 32):
        raise InvalidBech32Error("witness version 0 programs must be 20 or 32 bytes")
    expected_spec = Bech32Spec.BECH32 if witver == 0 else Bech32Spec.BECH32M
    if spec is not expected_spec:
        raise InvalidBech32Error(
            f"witness version {witver} requires {expected_spec.value} encoding"
        )
    return witver, program
