"""Byte sequence operations.

All functions require explicit byte order where an integer/byte conversion
could be ambiguous.  Lengths and ranges are validated before any data is
produced, and conversions never silently truncate.

Non-byte-aligned binary input is handled by
:mod:`binarycryptolab.binary_utils`: it is left-padded to a byte boundary so the
numeric value is preserved.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from .binary_utils import binary_to_bytes, bytes_to_binary
from .exceptions import InputValidationError
from .hex_utils import bytes_to_hex, hex_to_bytes

__all__ = [
    "BYTE_ORDERS",
    "ByteComparison",
    "byte_frequency",
    "bytes_from_binary",
    "bytes_from_hex",
    "bytes_hamming_distance",
    "bytes_to_binary_string",
    "bytes_to_hex_string",
    "bytes_to_int",
    "bytes_to_int_iter",
    "chunk_bytes",
    "compare_bytes",
    "concat_bytes",
    "int_to_bytes",
    "reverse_bytes",
    "slice_bytes",
    "swap_endianness",
    "xor_bytes",
]

ByteOrder = Literal["big", "little"]
BYTE_ORDERS: Final[tuple[str, ...]] = ("big", "little")


def _require_bytes(data: object, *, label: str = "data") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError(f"{label} must be a bytes-like object")
    return bytes(data)


def _require_byteorder(byteorder: object) -> ByteOrder:
    if byteorder not in BYTE_ORDERS:
        raise InputValidationError("byteorder must be 'big' or 'little'")
    return byteorder  # type: ignore[return-value]


def _require_length(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(f"{label} must be an integer")
    if value < 0:
        raise InputValidationError(f"{label} must be non-negative")
    return value


def bytes_from_binary(value: str, *, side: Literal["left", "right"] = "left") -> bytes:
    """Convert binary text to bytes (left-padded by default)."""
    return binary_to_bytes(value, side=side)


def bytes_from_hex(value: str, *, allow_odd: bool = True) -> bytes:
    """Convert hexadecimal text to bytes (odd input padded with one zero nibble)."""
    return hex_to_bytes(value, allow_odd=allow_odd)


def bytes_to_binary_string(
    data: bytes | bytearray | memoryview, *, width: int | None = None
) -> str:
    """Convert bytes to a binary string, MSB first."""
    return bytes_to_binary(data, width=width)


def bytes_to_hex_string(data: bytes | bytearray | memoryview, *, uppercase: bool = False) -> str:
    """Convert bytes to lowercase (or uppercase) hexadecimal text."""
    return bytes_to_hex(data, uppercase=uppercase)


def byte_frequency(data: bytes | bytearray | memoryview) -> dict[int, int]:
    """Count occurrences of each byte value.

    Returns:
        A mapping of byte value to count.  Keys are sorted ascending so that
        reports are deterministic.  An empty input yields an empty mapping.
    """
    counter = Counter(_require_bytes(data))
    return {value: counter[value] for value in sorted(counter)}


def compare_bytes(
    left: bytes | bytearray | memoryview, right: bytes | bytearray | memoryview
) -> ByteComparison:
    """Compare two byte sequences.

    Equal-length sequences are compared position by position.  When lengths
    differ, the shorter sequence is compared against a zero-padded prefix of
    the longer one and ``padding_applied`` is ``True``.

    Raises:
        InputValidationError: Either operand is not bytes-like.
    """
    first = _require_bytes(left, label="left")
    second = _require_bytes(right, label="right")
    width = max(len(first), len(second))
    padded_first = first.ljust(width, b"\x00")
    padded_second = second.ljust(width, b"\x00")
    differing = tuple(
        index
        for index, (a, b) in enumerate(zip(padded_first, padded_second, strict=True))
        if a != b
    )
    bit_distance = sum(
        (padded_first[index] ^ padded_second[index]).bit_count() for index in range(width)
    )
    return ByteComparison(
        equal=first == second,
        length_left=len(first),
        length_right=len(second),
        differing_indices=differing,
        bytes_hamming_distance=len(differing),
        bits_hamming_distance=bit_distance,
        padding_applied=len(first) != len(second),
    )


@dataclass(frozen=True, slots=True)
class ByteComparison:
    """Result of comparing two byte sequences.

    Attributes:
        equal: Whether the original sequences are byte-for-byte identical.
        length_left: Length of the left operand in bytes.
        length_right: Length of the right operand in bytes.
        differing_indices: Byte positions that differ (zero-padded comparison).
        bytes_hamming_distance: Number of differing byte positions.
        bits_hamming_distance: Number of differing bits across the compared range.
        padding_applied: Whether zero padding was needed because lengths differ.
    """

    equal: bool
    length_left: int
    length_right: int
    differing_indices: tuple[int, ...]
    bytes_hamming_distance: int
    bits_hamming_distance: int
    padding_applied: bool


def xor_bytes(left: bytes | bytearray | memoryview, right: bytes | bytearray | memoryview) -> bytes:
    """XOR two byte sequences of identical length.

    Unequal lengths are rejected: silently truncating or zero-extending would
    hide data-length errors.

    Raises:
        InputValidationError: The operands are not bytes-like or differ in length.
    """
    first = _require_bytes(left, label="left")
    second = _require_bytes(right, label="right")
    if len(first) != len(second):
        raise InputValidationError(
            f"XOR requires equal lengths, got {len(first)} and {len(second)} bytes"
        )
    return bytes(a ^ b for a, b in zip(first, second, strict=True))


def bytes_hamming_distance(
    left: bytes | bytearray | memoryview, right: bytes | bytearray | memoryview
) -> int:
    """Return the number of differing bits between two byte sequences.

    Lengths must match; padding is never inferred.

    Raises:
        InputValidationError: Lengths differ or operands are not bytes-like.
    """
    first = _require_bytes(left, label="left")
    second = _require_bytes(right, label="right")
    if len(first) != len(second):
        raise InputValidationError(
            f"Hamming distance requires equal lengths, got {len(first)} and {len(second)} bytes"
        )
    return sum((a ^ b).bit_count() for a, b in zip(first, second, strict=True))


def chunk_bytes(
    data: bytes | bytearray | memoryview, size: int, *, allow_remainder: bool = True
) -> list[bytes]:
    """Split bytes into fixed-size chunks, in order.

    Args:
        data: Bytes to split.
        size: Chunk size in bytes; must be positive.
        allow_remainder: When ``True`` a final short chunk is returned.  When
            ``False``, input whose length is not a multiple of *size* raises.

    Returns:
        A list of chunks.  Empty input yields an empty list.

    Raises:
        InputValidationError: The chunk size is invalid or a remainder exists
            while ``allow_remainder`` is ``False``.
    """
    payload = _require_bytes(data)
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise InputValidationError("size must be a positive integer")
    if not allow_remainder and len(payload) % size:
        raise InputValidationError(
            f"{len(payload)} bytes is not a multiple of the chunk size {size}"
        )
    return [payload[index : index + size] for index in range(0, len(payload), size)]


def concat_bytes(*parts: bytes | bytearray | memoryview) -> bytes:
    """Concatenate byte sequences.

    Raises:
        InputValidationError: Any part is not bytes-like.
    """
    return b"".join(_require_bytes(part, label=f"part {index}") for index, part in enumerate(parts))


def slice_bytes(data: bytes | bytearray | memoryview, start: int, stop: int | None = None) -> bytes:
    """Return ``data[start:stop]`` with validated, non-negative indices.

    Raises:
        InputValidationError: Indices are negative, inverted, or beyond the data.
    """
    payload = _require_bytes(data)
    first = _require_length(start, label="start")
    last = len(payload) if stop is None else _require_length(stop, label="stop")
    if first > last:
        raise InputValidationError("start must not be greater than stop")
    if last > len(payload):
        raise InputValidationError(f"stop {last} exceeds the data length {len(payload)}")
    return payload[first:last]


def reverse_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Return the bytes in reverse order."""
    return _require_bytes(data)[::-1]


def swap_endianness(data: bytes | bytearray | memoryview) -> bytes:
    """Reverse byte order, converting between big- and little-endian layouts.

    Raises:
        InputValidationError: The operand is not bytes-like.
    """
    return _require_bytes(data)[::-1]


def bytes_to_int(
    data: bytes | bytearray | memoryview, *, byteorder: ByteOrder = "big", signed: bool = False
) -> int:
    """Convert bytes to an integer with an explicit byte order.

    Args:
        data: Bytes to convert.
        byteorder: ``"big"`` (default) or ``"little"``; required to be explicit.
        signed: Whether two's complement interpretation is used.

    Raises:
        InputValidationError: The operand or byte order is invalid.
    """
    payload = _require_bytes(data)
    if not payload and not signed:
        return 0
    return int.from_bytes(payload, byteorder=_require_byteorder(byteorder), signed=signed)


def int_to_bytes(
    value: int,
    *,
    length: int | None = None,
    byteorder: ByteOrder = "big",
    signed: bool = False,
) -> bytes:
    """Convert an integer to bytes with an explicit byte order.

    Args:
        value: Integer to convert.
        length: Optional fixed output length.  When omitted the minimal length
            is used (zero bytes encode ``0`` unless a length is given).
        byteorder: ``"big"`` (default) or ``"little"``.
        signed: Whether two's complement encoding is used.

    Raises:
        InputValidationError: The value does not fit, the length is invalid, or
            the byte order is invalid.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("value must be an integer")
    order = _require_byteorder(byteorder)
    if length is not None:
        _require_length(length, label="length")
        if length == 0:
            raise InputValidationError("length must be positive when provided")
    try:
        if length is None:
            needed = max(1, (value.bit_length() + (8 if signed else 7)) // 8)
            if value < 0 and not signed:
                raise InputValidationError("negative values require signed=True")
            return value.to_bytes(needed, order, signed=signed)
        return value.to_bytes(length, order, signed=signed)
    except OverflowError as exc:
        raise InputValidationError("value does not fit in the requested length") from exc


def bytes_to_int_iter(data: Sequence[int] | Iterable[int]) -> tuple[int, ...]:
    """Validate an iterable of byte values and return it as a tuple.

    Raises:
        InputValidationError: A value is outside ``0..255``.
    """
    values = tuple(data)
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
            raise InputValidationError("byte values must be integers in 0..255")
    return values
