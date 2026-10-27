"""Bit-level and byte-level statistics.

Definitions
-----------
* **Bit statistics** operate on the *textual width* of a binary string, so a
  leading zero counts as a zero bit.  This is different from the integer value
  of the string, which ignores leading zeros.
* **Byte statistics** operate on the byte sequence obtained by left-padding
  the binary string to a byte boundary (or on the bytes decoded from
  hexadecimal text).  ``padding_bits`` records how many zero bits were added;
  those bits are included in the byte histogram because they are part of the
  padded byte sequence.
* **Shannon entropy** is computed over the empirical byte distribution, in
  bits per byte.  It is only reported as meaningful when at least one byte is
  present.  A distribution concentrated on a single byte value has entropy
  ``0.0``; a uniform distribution over 256 values is close to ``8.0``.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .exceptions import InputValidationError

__all__ = [
    "BitStatistics",
    "ByteStatistics",
    "bit_statistics",
    "byte_statistics",
    "entropy_bits",
    "shannon_entropy",
]

_MAX_ENTROPY_BITS_PER_SYMBOL: Final = 8.0


@dataclass(frozen=True, slots=True)
class BitStatistics:
    """Statistics for a fixed-width binary string.

    Attributes:
        length: Number of bits (textual width, including leading zeros).
        ones: Number of ``1`` characters.
        zeros: Number of ``0`` characters.
        hamming_weight: Alias of :attr:`ones`, kept for readability.
        one_ratio: ``ones / length``; ``0.0`` for an empty string.
        zero_ratio: ``zeros / length``; ``0.0`` for an empty string.
        width_entropy: Shannon entropy in bits per bit symbol (0 or 1).
    """

    length: int
    ones: int
    zeros: int
    hamming_weight: int
    one_ratio: float
    zero_ratio: float
    width_entropy: float


@dataclass(frozen=True, slots=True)
class ByteStatistics:
    """Statistics for a byte sequence.

    Attributes:
        byte_length: Number of bytes analysed.
        padding_bits: Zero bits added on the left to reach a byte boundary.
        unique_bytes: Number of distinct byte values.
        min_byte: Smallest byte value, or ``None`` for empty input.
        max_byte: Largest byte value, or ``None`` for empty input.
        average_byte: Arithmetic mean of byte values, or ``None`` for empty input.
        byte_frequency: Sorted ``(value, count)`` pairs.
        most_common: Sorted ``(value, count)`` pairs ordered by descending count
            then ascending value.
        entropy: Shannon entropy in bits per byte (``0.0`` for empty input).
        entropy_meaningful: Whether the entropy value is informative.
        total_entropy_bits: ``entropy * byte_length``.
    """

    byte_length: int
    padding_bits: int
    unique_bytes: int
    min_byte: int | None
    max_byte: int | None
    average_byte: float | None
    byte_frequency: tuple[tuple[int, int], ...]
    most_common: tuple[tuple[int, int], ...]
    entropy: float
    entropy_meaningful: bool
    total_entropy_bits: float

    def frequency_of(self, value: int) -> int:
        """Return the count of byte *value* (``0`` when absent)."""
        for byte_value, count in self.byte_frequency:
            if byte_value == value:
                return count
        return 0


def shannon_entropy(counts: Sequence[int] | Mapping[Any, int]) -> float:
    """Compute empirical Shannon entropy in bits per symbol.

    Args:
        counts: Occurrence counts (not probabilities), as a mapping of symbol to
            count or a sequence of counts.  Zero counts are ignored.

    Returns:
        Entropy in bits per symbol; ``0.0`` when the total count is zero or all
        observations have the same value.

    Raises:
        InputValidationError: A count is negative or not an integer.
    """
    values = list(counts.values()) if isinstance(counts, Mapping) else list(counts)
    for count in values:
        if isinstance(count, bool) or not isinstance(count, int):
            raise InputValidationError("counts must be integers")
        if count < 0:
            raise InputValidationError("counts must be non-negative")
    total = sum(values)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in values:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def entropy_bits(counts: Sequence[int] | Mapping[Any, int]) -> float:
    """Return total empirical entropy in bits (``entropy_per_symbol * total``)."""
    values = list(counts.values()) if isinstance(counts, Mapping) else list(counts)
    return shannon_entropy(values) * sum(values)


def bit_statistics(bits: str) -> BitStatistics:
    """Compute statistics over the textual width of a binary string.

    Args:
        bits: Binary digits (no prefix, no whitespace); callers normally pass
            the output of :func:`binarycryptolab.validation.normalize_binary`.

    Returns:
        A :class:`BitStatistics` instance.

    Raises:
        InputValidationError: The string contains characters other than ``0``
            and ``1``.  Use ``normalize_binary`` first to support prefixes.
    """
    if not isinstance(bits, str):
        raise InputValidationError("bits must be a string")
    invalid = {char for char in bits if char not in "01"}
    if invalid:
        raise InputValidationError("bits must contain only '0' and '1'")
    length = len(bits)
    ones = bits.count("1")
    zeros = length - ones
    counts = {"0": zeros, "1": ones}
    return BitStatistics(
        length=length,
        ones=ones,
        zeros=zeros,
        hamming_weight=ones,
        one_ratio=(ones / length) if length else 0.0,
        zero_ratio=(zeros / length) if length else 0.0,
        width_entropy=shannon_entropy(counts),
    )


def byte_statistics(data: bytes, *, padding_bits: int = 0) -> ByteStatistics:
    """Compute statistics for a byte sequence.

    Args:
        data: Bytes to analyse.
        padding_bits: Informational count of zero bits added to the original
            binary string so it aligned to a byte boundary.  It does not change
            the computation and must be in ``0..7``.

    Returns:
        A :class:`ByteStatistics` instance.

    Raises:
        InputValidationError: *data* is not bytes or *padding_bits* is invalid.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError("data must be a bytes-like object")
    if (
        isinstance(padding_bits, bool)
        or not isinstance(padding_bits, int)
        or not 0 <= padding_bits <= 7
    ):
        raise InputValidationError("padding_bits must be an integer in 0..7")

    payload = bytes(data)
    counter = Counter(payload)
    frequency = tuple((value, counter[value]) for value in sorted(counter))
    most_common = tuple(sorted(counter.items(), key=lambda item: (-item[1], item[0])))
    entropy = shannon_entropy(counter)
    if entropy > _MAX_ENTROPY_BITS_PER_SYMBOL + 1e-9:
        # Defensive invariant: empirical byte entropy cannot exceed 8 bits.
        raise InputValidationError("computed byte entropy exceeds the theoretical maximum")

    return ByteStatistics(
        byte_length=len(payload),
        padding_bits=padding_bits,
        unique_bytes=len(counter),
        min_byte=min(payload) if payload else None,
        max_byte=max(payload) if payload else None,
        average_byte=(sum(payload) / len(payload)) if payload else None,
        byte_frequency=frequency,
        most_common=most_common,
        entropy=entropy,
        entropy_meaningful=bool(payload),
        total_entropy_bits=entropy * len(payload),
    )
