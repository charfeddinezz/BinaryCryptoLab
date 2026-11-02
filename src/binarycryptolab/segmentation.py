"""Segmentation, folding, reversal, and lag-autocorrelation of a byte string.

This module answers one question that a plain bit/byte report cannot: *does the
data look structured when it is cut into machine words?*

A public key, a HASH160 digest, and an arbitrary blob of bytes are all "just bits"
at the top level.  Cutting them into 8-, 16-, 32-, and 64-bit words and then
folding those words with XOR exposes a specific class of mistake --- a value that
repeats with a period, or a buffer whose second half mirrors its first --- that a
frequency table smooths away.

What a result means, and what it does not
-----------------------------------------
* A **zero fold** at some width means the segments XOR to zero.  With three or more
  segments that is a 1-in-``2**width`` coincidence, so it is worth a look; with two
  segments it only says the halves are equal, which is worth a bigger look.
* A **non-zero fold is the normal outcome** and is not evidence of anything.  Most
  of the value of this module is in stating that plainly instead of implying that a
  number came out.
* A **short tail** (the last segment of a 64-bit cut of a 160-bit digest) is padded
  by position, not by value.  The module reports those segments as incomplete
  rather than silently mixing widths.

Nothing here reverses a hash, guesses a key, or contacts a network.  It is integer
arithmetic over bytes the caller already supplied.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from .exceptions import InputValidationError
from .special_functions import chi_square_sf

__all__ = [
    "AUTOCORRELATION_LAGS",
    "DEFAULT_WIDTHS",
    "LagAutocorrelation",
    "ReversalAnalysis",
    "Segment",
    "SegmentationReport",
    "WidthAnalysis",
    "bit_autocorrelation",
    "segmentation_report",
]

#: Word widths, in bits, that :func:`segmentation_report` cuts the data into.
DEFAULT_WIDTHS: Final = (8, 16, 32, 64)

#: Bit lags reported by :func:`bit_autocorrelation`.
AUTOCORRELATION_LAGS: Final = (1, 2, 3, 4, 8, 16)


@dataclass(frozen=True, slots=True)
class Segment:
    """One fixed-width slice of the input.

    Attributes:
        index: Zero-based position in the slice sequence.
        hex: The slice's bytes in hexadecimal.
        value: The slice interpreted as a big-endian unsigned integer.
        bits: Width of the slice in bits, as cut.  A short tail reports its real
            length here, never the nominal width.
        complete: Whether the slice filled the nominal width.
    """

    index: int
    hex: str
    value: int
    bits: int
    complete: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "index": self.index,
            "hex": self.hex,
            "value": str(self.value),
            "bits": self.bits,
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class WidthAnalysis:
    """All segments at one word width, plus the relations between them.

    Attributes:
        width: Nominal width in bits.
        segment_count: How many slices the data produced.
        segments: The slices themselves.
        fold_xor: XOR of every segment value.
        fold_xor_hex: The same value in hexadecimal, zero padded to the width.
        adjacent_xor: ``(i, j, value)`` for each neighbouring pair ``i ^ j``.
        adjacent_difference: ``(i, j, value)`` for each neighbouring pair ``i - j``.
        complete: Whether every segment filled the width.
        note: One sentence on how to read the fold for this width and count.
    """

    width: int
    segment_count: int
    segments: tuple[Segment, ...]
    fold_xor: int
    fold_xor_hex: str
    adjacent_xor: tuple[tuple[int, int, int], ...]
    adjacent_difference: tuple[tuple[int, int, int], ...]
    complete: bool
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "width_bits": self.width,
            "segment_count": self.segment_count,
            "segments": [segment.as_dict() for segment in self.segments],
            "fold_xor": str(self.fold_xor),
            "fold_xor_hex": self.fold_xor_hex,
            "adjacent_xor": [
                {"left": left, "right": right, "value": str(value)}
                for left, right, value in self.adjacent_xor
            ],
            "adjacent_difference": [
                {"left": left, "right": right, "value": str(value)}
                for left, right, value in self.adjacent_difference
            ],
            "complete": self.complete,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class ReversalAnalysis:
    """The input compared with its own byte reversal.

    Attributes:
        original_hex: The input, in order.
        reversed_hex: The input, byte-reversed.
        xor_hex: ``original XOR reversed``, zero padded to the input length.
        is_palindrome: Whether the two are identical.
    """

    original_hex: str
    reversed_hex: str
    xor_hex: str
    is_palindrome: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "original_hex": self.original_hex,
            "reversed_hex": self.reversed_hex,
            "xor_hex": self.xor_hex,
            "is_palindrome": self.is_palindrome,
        }


@dataclass(frozen=True, slots=True)
class LagAutocorrelation:
    """Agreement between the bit string and itself shifted by ``lag``.

    Attributes:
        lag: Shift in bits.
        matches: Positions where the bit equals its shifted self.
        comparisons: Positions compared (``total - lag``).
        ratio: ``matches / comparisons``; 0.5 under a fair coin.
        deviation: ``ratio - 0.5``, the amount that matters.
    """

    lag: int
    matches: int
    comparisons: int
    ratio: float
    deviation: float

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "lag": self.lag,
            "matches": self.matches,
            "comparisons": self.comparisons,
            "ratio": self.ratio,
            "deviation": self.deviation,
        }


@dataclass(frozen=True, slots=True)
class SegmentationReport:
    """Complete segmentation view of one byte string.

    Attributes:
        data_hex: The input.
        byte_length: Length of the input in bytes.
        bit_length: Length of the input in bits.
        widths: One :class:`WidthAnalysis` per requested width.
        reversal: The byte-reversal comparison.
        autocorrelation: One entry per lag in :data:`AUTOCORRELATION_LAGS`.
        ones: Number of set bits.
        zeros: Number of clear bits.
        transitions: How many adjacent bit pairs differ.
        runs: Number of maximal constant-bit runs.
        longest_run: Length of the longest run.
        balance_chi_square: 1-degree-of-freedom chi-square for a fair-coin split.
        balance_p_value: Survival function of that statistic.  Small values mean
            the split is lopsided; with 160-256 bits only a gross imbalance shows.
        verdict: One-paragraph reading of the whole report.
        notes: Honesty notes about the limits of the measurements.
    """

    data_hex: str
    byte_length: int
    bit_length: int
    widths: tuple[WidthAnalysis, ...]
    reversal: ReversalAnalysis
    autocorrelation: tuple[LagAutocorrelation, ...]
    ones: int
    zeros: int
    transitions: int
    runs: int
    longest_run: int
    balance_chi_square: float
    balance_p_value: float
    verdict: str
    notes: tuple[str, ...]

    @property
    def zero_folds(self) -> tuple[int, ...]:
        """Widths whose segments fold to zero, and whose cut was complete."""
        return tuple(
            analysis.width
            for analysis in self.widths
            if analysis.complete and analysis.fold_xor == 0 and analysis.segment_count > 1
        )

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "data_hex": self.data_hex,
            "byte_length": self.byte_length,
            "bit_length": self.bit_length,
            "widths": [analysis.as_dict() for analysis in self.widths],
            "reversal": self.reversal.as_dict(),
            "autocorrelation": [item.as_dict() for item in self.autocorrelation],
            "ones": self.ones,
            "zeros": self.zeros,
            "transitions": self.transitions,
            "runs": self.runs,
            "longest_run": self.longest_run,
            "balance_chi_square": self.balance_chi_square,
            "balance_p_value": self.balance_p_value,
            "zero_folds": list(self.zero_folds),
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def _bits(data: bytes) -> str:
    """Return the input as a most-significant-bit-first bit string."""
    return "".join(f"{byte:08b}" for byte in data)


def bit_autocorrelation(
    bits: str, lags: Iterable[int] = AUTOCORRELATION_LAGS
) -> tuple[LagAutocorrelation, ...]:
    """Compare a bit string with shifted copies of itself.

    Args:
        bits: A string of ``0`` and ``1`` characters.
        lags: Shifts to test, in bits.  Lags at or beyond the length are skipped.

    Returns:
        One :class:`LagAutocorrelation` per usable lag, in the order requested.
    """
    if not bits:
        raise InputValidationError("autocorrelation needs at least one bit")
    total = len(bits)
    results: list[LagAutocorrelation] = []
    for lag in lags:
        if lag <= 0 or lag >= total:
            continue
        comparisons = total - lag
        matches = sum(1 for index in range(comparisons) if bits[index] == bits[index + lag])
        ratio = matches / comparisons
        results.append(
            LagAutocorrelation(
                lag=lag,
                matches=matches,
                comparisons=comparisons,
                ratio=ratio,
                deviation=ratio - 0.5,
            )
        )
    return tuple(results)


def _runs(bits: str) -> tuple[int, int]:
    """Return ``(run_count, longest_run)`` for a bit string."""
    if not bits:
        return 0, 0
    run_count = 1
    longest = 1
    current = 1
    for index in range(1, len(bits)):
        if bits[index] == bits[index - 1]:
            current += 1
            longest = max(longest, current)
        else:
            run_count += 1
            current = 1
    return run_count, longest


def _fold_note(width: int, count: int, complete: bool, fold: int) -> str:
    """Explain how to read one width's fold."""
    if not complete:
        return (
            f"the last {width}-bit segment is short, so this fold mixes widths; "
            "read it as descriptive, not as a test"
        )
    if count <= 1:
        return "a single segment is its own fold, so this width carries no information"
    if fold == 0:
        return (
            f"the {count} segments fold to zero, which is a 1-in-2^{width} coincidence "
            "for unrelated data and is worth inspecting"
        )
    return "the segments do not fold to zero, which is the expected outcome for unrelated data"


def segmentation_report(
    data: bytes | bytearray | memoryview,
    *,
    widths: Iterable[int] = DEFAULT_WIDTHS,
    lags: Iterable[int] = AUTOCORRELATION_LAGS,
) -> SegmentationReport:
    """Cut *data* into words at each width and describe the result.

    Args:
        data: The bytes to analyse.  Must not be empty.
        widths: Word widths in bits.  Each must be a positive multiple of 8.
        lags: Bit lags for the autocorrelation section.

    Returns:
        A :class:`SegmentationReport`.

    Raises:
        InputValidationError: The input is empty, or a width is not a positive
            multiple of eight.

    Example:
        >>> report = segmentation_report(bytes.fromhex("0102030405060708"))
        >>> report.widths[1].width
        16
        >>> report.reversal.is_palindrome
        False
    """
    payload = bytes(data)
    if not payload:
        raise InputValidationError("segmentation needs at least one byte")

    cleaned_widths: list[int] = []
    for width in widths:
        if width <= 0 or width % 8 != 0:
            raise InputValidationError(
                f"a segment width must be a positive multiple of 8 bits, got {width}"
            )
        cleaned_widths.append(width)
    if not cleaned_widths:
        raise InputValidationError("at least one segment width is required")

    analyses: list[WidthAnalysis] = []
    for width in cleaned_widths:
        size = width // 8
        segments: list[Segment] = []
        for index, start in enumerate(range(0, len(payload), size)):
            chunk = payload[start : start + size]
            segments.append(
                Segment(
                    index=index,
                    hex=chunk.hex(),
                    value=int.from_bytes(chunk, "big"),
                    bits=len(chunk) * 8,
                    complete=len(chunk) == size,
                )
            )
        fold = 0
        for segment in segments:
            fold ^= segment.value
        complete = all(segment.complete for segment in segments)
        adjacent_xor = tuple(
            (left.index, right.index, left.value ^ right.value)
            for left, right in itertools.pairwise(segments)
        )
        adjacent_difference = tuple(
            (left.index, right.index, left.value - right.value)
            for left, right in itertools.pairwise(segments)
        )
        analyses.append(
            WidthAnalysis(
                width=width,
                segment_count=len(segments),
                segments=tuple(segments),
                fold_xor=fold,
                fold_xor_hex=f"{fold:0{size * 2}x}",
                adjacent_xor=adjacent_xor,
                adjacent_difference=adjacent_difference,
                complete=complete,
                note=_fold_note(width, len(segments), complete, fold),
            )
        )

    reversed_payload = payload[::-1]
    xor_payload = bytes(left ^ right for left, right in zip(payload, reversed_payload, strict=True))
    reversal = ReversalAnalysis(
        original_hex=payload.hex(),
        reversed_hex=reversed_payload.hex(),
        xor_hex=xor_payload.hex(),
        is_palindrome=payload == reversed_payload,
    )

    bits = _bits(payload)
    ones = bits.count("1")
    zeros = len(bits) - ones
    transitions = sum(1 for index in range(1, len(bits)) if bits[index] != bits[index - 1])
    run_count, longest = _runs(bits)
    expected = len(bits) / 2
    chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    p_value = chi_square_sf(1.0, chi_square)

    zero_folds = [
        analysis.width
        for analysis in analyses
        if analysis.complete and analysis.fold_xor == 0 and analysis.segment_count > 1
    ]
    balance_phrase = "consistent" if p_value >= 0.01 else "lop-sided"
    if zero_folds:
        verdict = (
            "the data folds to zero at "
            + ", ".join(f"{width}-bit" for width in zero_folds)
            + " width; for unrelated data that is a coincidence worth inspecting, and it "
            "is the strongest structural signal this report can raise. The bit balance is "
            f"{balance_phrase} with a fair coin (p={p_value:.4g})."
        )
    else:
        verdict = (
            f"no width folds to zero, and the bit balance is {balance_phrase} with a fair "
            "coin; this is the expected result for a digest or a key"
        )

    notes = (
        "A non-zero fold is the normal outcome; its absence of information is the point "
        "of printing it rather than only printing the exception.",
        "Adjacent XOR and adjacent differences are descriptive arithmetic, not tests: "
        "they have no null distribution and no p-value.",
        "With 160-256 bits the balance chi-square can only detect a gross imbalance; "
        "a large p-value is not proof of randomness.",
        "Autocorrelation at these lags is not independent of the bit-balance test; both "
        "read the same bits, so agreement between them is not extra evidence.",
    )

    return SegmentationReport(
        data_hex=payload.hex(),
        byte_length=len(payload),
        bit_length=len(bits),
        widths=tuple(analyses),
        reversal=reversal,
        autocorrelation=bit_autocorrelation(bits, lags),
        ones=ones,
        zeros=zeros,
        transitions=transitions,
        runs=run_count,
        longest_run=longest,
        balance_chi_square=chi_square,
        balance_p_value=p_value,
        verdict=verdict,
        notes=notes,
    )
