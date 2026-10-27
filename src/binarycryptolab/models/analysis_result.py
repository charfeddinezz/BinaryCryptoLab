"""Structured analysis result models.

These dataclasses are the contract between the analysis engines, the report
writers, the CLI, and the graphical interface.  They are immutable, fully
typed, and expose ``to_dict`` methods that produce JSON-serializable data.

Nothing in this module stores or exposes private key material.  Public key and
address sections contain only public data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from .._version import __version__
from ..config import APP_NAME
from ..hashing import HashDigest
from ..statistics import BitStatistics, ByteStatistics

__all__ = [
    "REDACTED",
    "AnalysisResult",
    "BinaryAnalysis",
    "HexAnalysis",
    "InputType",
    "utc_timestamp",
]

InputType = str

#: Marker used wherever a sensitive value must not be recorded.
REDACTED: Final = "<redacted>"

#: Input types accepted by :class:`AnalysisResult`.  ``"private_key"`` results
#: are only used to describe *derived public data* and must redact their input.
_VALID_INPUT_TYPES: Final[frozenset[str]] = frozenset(
    {"binary", "hex", "text", "file", "public_key", "private_key", "address"}
)


def utc_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class BinaryAnalysis:
    """Result of analysing a binary string.

    The bit statistics describe the **original textual width**, so leading
    zeros are counted.  Byte statistics describe the left-padded byte sequence;
    :attr:`padding_bits` states how many zero bits were prepended.

    Attributes:
        original: Original user input, unmodified.
        normalized: Binary digits with whitespace/prefix removed.
        bit_length: Number of bit characters (after normalization).
        integer_value: Mathematical value of the digits.
        hexadecimal: Even-length lowercase hexadecimal representation.
        bit_stats: Bit-level statistics.
        bytes_hex: Byte sequence as lowercase hexadecimal.
        byte_stats: Byte-level statistics.
        complete_bytes: ``bit_length // 8``.
        incomplete_bits: ``bit_length % 8``; the leading partial group.
        padding_bits: Zero bits prepended to reach a byte boundary.
        grouped_display: Binary text grouped in nibbles for display.
    """

    original: str
    normalized: str
    bit_length: int
    integer_value: int
    hexadecimal: str
    bit_stats: BitStatistics
    bytes_hex: str
    byte_stats: ByteStatistics
    complete_bytes: int
    incomplete_bits: int
    padding_bits: int
    grouped_display: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation (no sensitive fields)."""
        stats = self.byte_stats
        bits = self.bit_stats
        return {
            "input_type": "binary",
            "original_input": self.original,
            "normalized_input": self.normalized,
            "binary": {
                "value": self.normalized,
                "length_bits": self.bit_length,
                "grouped_display": self.grouped_display,
            },
            "integer": {
                "decimal": str(self.integer_value),
                "hexadecimal": self.hexadecimal,
                "bit_length": self.integer_value.bit_length(),
            },
            "bits": {
                "ones": bits.ones,
                "zeros": bits.zeros,
                "hamming_weight": bits.hamming_weight,
                "one_ratio": bits.one_ratio,
                "zero_ratio": bits.zero_ratio,
                "width_entropy": bits.width_entropy,
            },
            "bytes": {
                "hexadecimal": self.bytes_hex,
                "byte_length": stats.byte_length,
                "complete_bytes": self.complete_bytes,
                "incomplete_bits": self.incomplete_bits,
                "padding_bits": self.padding_bits,
                "unique_bytes": stats.unique_bytes,
                "min_byte": stats.min_byte,
                "max_byte": stats.max_byte,
                "average_byte": stats.average_byte,
                "entropy": stats.entropy,
                "entropy_meaningful": stats.entropy_meaningful,
                "total_entropy_bits": stats.total_entropy_bits,
                "frequency": {str(value): count for value, count in stats.byte_frequency},
            },
        }


@dataclass(frozen=True, slots=True)
class HexAnalysis:
    """Result of analysing a hexadecimal string.

    Attributes:
        original: Original user input, unmodified.
        normalized: Lowercase hexadecimal digits, even length.
        hex_length: Number of hexadecimal digits.
        integer_value: Mathematical value of the digits.
        binary: Binary representation; four bits per hexadecimal digit.
        binary_length: ``4 * hex_length``.
        bit_stats: Bit-level statistics over :attr:`binary`.
        bytes_hex: Byte sequence as lowercase hexadecimal (equals
            :attr:`normalized`).
        byte_stats: Byte-level statistics.
        text_utf8: Best-effort UTF-8 decoding, or ``None`` when the bytes are
            not valid UTF-8.  Provided for convenience only; hexadecimal input
            is never assumed to be text.
        odd_length_input: Whether the user supplied an odd number of digits.
        grouped_display: Hexadecimal text grouped in bytes for display.
    """

    original: str
    normalized: str
    hex_length: int
    integer_value: int
    binary: str
    binary_length: int
    bit_stats: BitStatistics
    bytes_hex: str
    byte_stats: ByteStatistics
    text_utf8: str | None
    odd_length_input: bool
    grouped_display: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation (no sensitive fields)."""
        stats = self.byte_stats
        bits = self.bit_stats
        return {
            "input_type": "hex",
            "original_input": self.original,
            "normalized_input": self.normalized,
            "hexadecimal": {
                "value": self.normalized,
                "digits": self.hex_length,
                "odd_length_input_padded": self.odd_length_input,
                "grouped_display": self.grouped_display,
            },
            "integer": {
                "decimal": str(self.integer_value),
                "hexadecimal": self.normalized,
                "bit_length": self.integer_value.bit_length(),
            },
            "binary": {
                "value": self.binary,
                "length_bits": self.binary_length,
            },
            "bits": {
                "ones": bits.ones,
                "zeros": bits.zeros,
                "hamming_weight": bits.hamming_weight,
                "one_ratio": bits.one_ratio,
                "zero_ratio": bits.zero_ratio,
                "width_entropy": bits.width_entropy,
            },
            "bytes": {
                "hexadecimal": self.bytes_hex,
                "byte_length": stats.byte_length,
                "unique_bytes": stats.unique_bytes,
                "min_byte": stats.min_byte,
                "max_byte": stats.max_byte,
                "average_byte": stats.average_byte,
                "entropy": stats.entropy,
                "entropy_meaningful": stats.entropy_meaningful,
                "total_entropy_bits": stats.total_entropy_bits,
                "frequency": {str(value): count for value, count in stats.byte_frequency},
            },
            "text_preview": {
                "utf8": self.text_utf8,
                "note": (
                    "Hexadecimal input is not assumed to be text. "
                    "The preview is informational only."
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """A complete, report-ready analysis result.

    Attributes:
        input_type: ``"binary"`` or ``"hex"``.
        original_input: Original, non-sensitive user input.
        normalized_input: Normalized representation of the input.
        binary: Binary analysis section, when the input was binary.
        hexadecimal: Hexadecimal analysis section, when the input was hex.
        hashes: Optional hash results requested by the user.
        public_key: Optional public key information (never private).
        address: Optional Bitcoin address information.
        warnings: Human-readable validation and safety notes.
        app_name: Application name recorded in reports.
        app_version: Application version recorded in reports.
        generated_at: UTC ISO-8601 timestamp of report creation.
        extra: Additional non-sensitive metadata.
    """

    input_type: InputType
    original_input: str
    normalized_input: str
    binary: BinaryAnalysis | None = None
    hexadecimal: HexAnalysis | None = None
    hashes: tuple[HashDigest, ...] = ()
    public_key: dict[str, Any] | None = None
    address: dict[str, Any] | None = None
    warnings: tuple[str, ...] = ()
    app_name: str = APP_NAME
    app_version: str = __version__
    generated_at: str = field(default_factory=utc_timestamp)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.input_type not in _VALID_INPUT_TYPES:
            raise ValueError(f"input_type must be one of {sorted(_VALID_INPUT_TYPES)}")
        if self.input_type == "private_key" and (
            self.original_input != REDACTED or self.normalized_input != REDACTED
        ):
            raise ValueError(
                "private key input must be redacted before it reaches an analysis result"
            )

    @property
    def byte_stats(self) -> ByteStatistics | None:
        """Byte statistics of whichever section is present."""
        if self.binary is not None:
            return self.binary.byte_stats
        if self.hexadecimal is not None:
            return self.hexadecimal.byte_stats
        return None

    def to_dict(self) -> dict[str, Any]:
        """Return the full report as a JSON-serializable dictionary."""
        payload: dict[str, Any] = {
            "application": {
                "name": self.app_name,
                "version": self.app_version,
                "generated_at_utc": self.generated_at,
            },
            "input": {
                "type": self.input_type,
                "original": self.original_input,
                "normalized": self.normalized_input,
            },
            "analysis": {},
            "hashes": [digest.as_dict() for digest in self.hashes],
            "public_key": self.public_key,
            "bitcoin_address": self.address,
            "warnings": list(self.warnings),
            "security_notes": [
                "This report contains no private keys.",
                "A public key and an address are not interchangeable.",
                "Address derivation does not prove ownership or balance.",
            ],
            "extra": self.extra,
        }
        if self.binary is not None:
            payload["analysis"] = self.binary.to_dict()
        elif self.hexadecimal is not None:
            payload["analysis"] = self.hexadecimal.to_dict()
        return payload
