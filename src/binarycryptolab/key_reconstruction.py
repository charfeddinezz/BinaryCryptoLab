"""Bounded reconstruction of a scalar from known hexadecimal segments.

What this module does
---------------------
It treats a private scalar as 64 hexadecimal digits, lets you mark the digits you
already know, reduces every piece of knowledge to a single scale (bits of the
256-bit keyspace), and - only when the unknown part is small enough - searches
that part and assembles the full scalar.  Every candidate is verified by
re-deriving the public key through :mod:`cryptography` before it is reported.

What this module cannot do
--------------------------
It cannot turn a public key into a private key.  A public key fixes ``k * G``, and
recovering ``k`` from it is the elliptic-curve discrete logarithm problem: about
``2**128`` group operations on secp256k1, with no known shortcut.  The ledger in
this module therefore values every public datum - the coordinates, the encodings,
the addresses, the hashes - at **zero bits**, and only counts knowledge you
actually supply (known hex digits, residues, intervals).  The search is refused
unless the remaining space is small enough to enumerate.

Honest framing of "assemble the private key hex by hex": the assembly works when
all but a small window of the hex is known - a puzzle with a partly published
scalar, a key with a known prefix and a truncated tail, or a key generated with a
known offset from another key.  In every other case the ledger reports how many
bits would still need to be known, which is the real answer.

Security
--------
* Scalars are never echoed in errors, logs, or ``repr`` output.
* :meth:`TemplateSolution.as_dict` redacts the assembled scalar unless the caller
  passes ``reveal=True``.
* The interval search is capped at :data:`MAX_UNKNOWN_BITS` bits, so no call can
  turn into a general attack on the curve.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Final

from .curve_arithmetic import (
    MAX_TABLE_ENTRIES,
    Point,
    decode_public_key,
    discrete_log_interval,
    multiply,
    sub,
)
from .ecc import CURVE_ORDER, GENERATOR, derive_public_key, public_key_bytes
from .exceptions import InputValidationError

__all__ = [
    "HEX_DIGITS",
    "MAX_UNKNOWN_BITS",
    "ComparisonReport",
    "HexSegment",
    "InformationLedger",
    "KeyRelationship",
    "KeyTemplate",
    "LedgerEntry",
    "TemplateSolution",
    "assemble_hex",
    "compare_keys",
    "decode_public_key",
    "parse_template",
    "segment_bits",
    "segment_hex",
    "solve_offset",
    "solve_template",
]

#: Width of a secp256k1 scalar in hexadecimal digits.
HEX_DIGITS: Final = 64

#: Bits of the scalar that may remain unknown.  ``2**40`` needs about
#: ``2**20`` baby steps (roughly 100 MB and several seconds), which is the largest
#: search this project is willing to run; anything above it is refused instead of
#: pretending to be a general attack.
MAX_UNKNOWN_BITS: Final = 40

#: Default search budget, small enough to finish instantly.
DEFAULT_UNKNOWN_BITS: Final = 32

_HEX_CHARACTERS: Final = frozenset("0123456789abcdefABCDEF")
_UNKNOWN_CHARACTER: Final = "?"
_SCALAR_BITS: Final = 256


# ---------------------------------------------------------------------------
# Segmentation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HexSegment:
    """One slice of a hexadecimal value.

    Attributes:
        label: Human-readable name, for example ``"nibble 12"`` or ``"byte 3"``.
        digits: The hexadecimal digits in the segment.
        start_bit: Offset from the most significant bit.
        width_bits: Width of the segment in bits.
        value: Integer value of the segment.
    """

    label: str
    digits: str
    start_bit: int
    width_bits: int
    value: int

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "label": self.label,
            "digits": self.digits,
            "start_bit": self.start_bit,
            "width_bits": self.width_bits,
            "value": self.value,
        }


def segment_hex(text: str, *, unit: int = 1) -> tuple[HexSegment, ...]:
    """Split a hexadecimal string into fixed-width segments.

    Args:
        text: Hexadecimal digits, optionally prefixed with ``0x``.
        unit: Segment width in hexadecimal digits.  ``1`` gives nibbles, ``2``
            bytes, ``4`` 16-bit words, ``8`` 32-bit words, and ``16`` 64-bit words.

    Returns:
        Segments ordered from the most significant digit.

    Raises:
        InputValidationError: The text is not an even hexadecimal string, or the
            unit is not one of 1, 2, 4, 8, or 16.

    Example:
        >>> [segment.digits for segment in segment_hex("0f0f", unit=2)]
        ['0f', '0f']
    """
    cleaned = text.strip()
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        raise InputValidationError("the hexadecimal value is empty")
    if any(character not in _HEX_CHARACTERS for character in cleaned):
        raise InputValidationError("the value must be hexadecimal")
    if unit not in (1, 2, 4, 8, 16):
        raise InputValidationError("the unit must be 1, 2, 4, 8, or 16 hex digits")
    if len(cleaned) % unit:
        raise InputValidationError(f"the length must be a multiple of {unit} hex digits")
    segments: list[HexSegment] = []
    for index in range(0, len(cleaned), unit):
        digits = cleaned[index : index + unit]
        start = index * 4
        segments.append(
            HexSegment(
                label=f"{unit * 4}-bit segment {index // unit}",
                digits=digits.lower(),
                start_bit=start,
                width_bits=unit * 4,
                value=int(digits, 16),
            )
        )
    return tuple(segments)


def segment_bits(value: int, *, width: int = _SCALAR_BITS, unit: int = 1) -> tuple[HexSegment, ...]:
    """Return the hex segments of an integer of a fixed bit width.

    Raises:
        InputValidationError: The value does not fit, or the width is not a
            multiple of ``4 * unit``.
    """
    if not isinstance(value, int) or value < 0:
        raise InputValidationError("the value must be a non-negative integer")
    if width <= 0 or width % (4 * unit):
        raise InputValidationError("the width must be a positive multiple of 4 * unit")
    if value >= 1 << width:
        raise InputValidationError("the value does not fit in the requested width")
    return segment_hex(f"{value:0{width // 4}x}", unit=unit)


# ---------------------------------------------------------------------------
# Templates: which hex digits are known
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyTemplate:
    """A 64-digit hexadecimal pattern with one contiguous unknown window.

    Attributes:
        pattern: The normalized pattern, lower case, with ``?`` for unknown digits.
        known_value: The numeric value with the unknown digits set to zero.
        unknown_start: Offset of the first unknown bit from the most significant bit.
        unknown_bits: Number of unknown bits (a multiple of four).
        low_bits: Number of known bits below the unknown window.
        known_digits: Number of known hexadecimal digits.
    """

    pattern: str
    known_value: int
    unknown_start: int
    unknown_bits: int
    low_bits: int
    known_digits: int

    @property
    def known_bits(self) -> int:
        """Number of scalar bits the template already fixes."""
        return _SCALAR_BITS - self.unknown_bits

    @property
    def search_operations_log2(self) -> float:
        """Exponent of the baby-step/giant-step cost for the unknown window."""
        return self.unknown_bits / 2.0

    def render(self) -> str:
        """Return the pattern with separators every four digits for readability."""
        return " ".join(self.pattern[index : index + 4] for index in range(0, HEX_DIGITS, 4))

    def assemble(self, unknown_value: int) -> int:
        """Return the scalar obtained by placing *unknown_value* in the window.

        Raises:
            InputValidationError: The value does not fit in the unknown window.
        """
        if not isinstance(unknown_value, int):
            raise InputValidationError("the unknown part must be an integer")
        if not 0 <= unknown_value < (1 << self.unknown_bits):
            raise InputValidationError("the value does not fit in the unknown window")
        return self.known_value + (unknown_value << self.low_bits)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation (never includes a scalar)."""
        return {
            "pattern": self.pattern,
            "known_digits": self.known_digits,
            "known_bits": self.known_bits,
            "unknown_bits": self.unknown_bits,
            "unknown_start": self.unknown_start,
            "low_bits": self.low_bits,
        }


def parse_template(pattern: str) -> KeyTemplate:
    """Parse a 64-digit hexadecimal pattern with ``?`` for unknown digits.

    Args:
        pattern: Exactly 64 hexadecimal digits, where ``?`` marks unknown digits.
            Whitespace, ``0x``, ``_``, ``:``, and ``-`` separators are ignored.

    Returns:
        The parsed template.

    Raises:
        InputValidationError: The pattern is not 64 digits, contains other
            characters, or does not have exactly one contiguous unknown run.

    Example:
        >>> template = parse_template("00" + "?" * 8 + "0" * 54)
        >>> template.unknown_bits
        32
    """
    cleaned = (
        pattern.strip()
        .lower()
        .replace("0x", "")
        .replace(" ", "")
        .replace("_", "")
        .replace(":", "")
        .replace("-", "")
    )
    if len(cleaned) != HEX_DIGITS:
        raise InputValidationError(f"the pattern must contain exactly {HEX_DIGITS} hex digits")
    unknown_positions = [
        index for index, character in enumerate(cleaned) if character == _UNKNOWN_CHARACTER
    ]
    for character in cleaned:
        if character != _UNKNOWN_CHARACTER and character not in _HEX_CHARACTERS:
            raise InputValidationError("the pattern may contain only hex digits and '?'")
    if not unknown_positions:
        raise InputValidationError("the pattern has no unknown digits; nothing to solve")
    first, last = unknown_positions[0], unknown_positions[-1]
    if last - first + 1 != len(unknown_positions):
        raise InputValidationError("the unknown digits must form one contiguous run")
    if first == 0 and last == HEX_DIGITS - 1:
        raise InputValidationError("at least one hex digit must be known")
    unknown_bits = len(unknown_positions) * 4
    known_value = int(cleaned.replace(_UNKNOWN_CHARACTER, "0"), 16)
    return KeyTemplate(
        pattern=cleaned,
        known_value=known_value,
        unknown_start=first * 4,
        unknown_bits=unknown_bits,
        low_bits=(HEX_DIGITS - last - 1) * 4,
        known_digits=HEX_DIGITS - len(unknown_positions),
    )


def assemble_hex(template: KeyTemplate, unknown_value: int) -> str:
    """Return the assembled 64-digit hexadecimal scalar.

    Raises:
        InputValidationError: The value does not fit the unknown window.
    """
    return f"{template.assemble(unknown_value):0{HEX_DIGITS}x}"


# ---------------------------------------------------------------------------
# One scale for all information
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One source of information about a scalar, valued in bits.

    Attributes:
        label: What is known.
        bits: How many bits of the 256-bit scalar it fixes.
        note: Why it is worth that many bits.
    """

    label: str
    bits: float
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {"label": self.label, "bits": self.bits, "note": self.note}


@dataclass(frozen=True, slots=True)
class InformationLedger:
    """Every kind of knowledge about a scalar, reduced to one scale of bits.

    The scale is "how many of the 256 bits of the scalar are known".  Public data
    contributes nothing, because inverting it is the discrete logarithm problem;
    hexadecimal digits and algebraic constraints contribute their real
    information content.

    Attributes:
        entries: The contributions, in report order.
        space_bits: Size of the scalar space under consideration (256).
        solvable_bits: Largest unknown window this tool will search.
    """

    entries: tuple[LedgerEntry, ...]
    space_bits: int = _SCALAR_BITS
    solvable_bits: int = DEFAULT_UNKNOWN_BITS

    @property
    def known_bits(self) -> float:
        """Total information known about the scalar, in bits."""
        return min(float(self.space_bits), math.fsum(entry.bits for entry in self.entries))

    @property
    def unknown_bits(self) -> float:
        """Information still missing, in bits."""
        return max(0.0, self.space_bits - self.known_bits)

    @property
    def feasible(self) -> bool:
        """Whether the remaining space is small enough to search."""
        return self.unknown_bits <= self.solvable_bits

    @property
    def search_operations_log2(self) -> float:
        """Exponent of the cost of the remaining search (about ``2**(bits/2)``)."""
        return self.unknown_bits / 2.0

    @property
    def verdict(self) -> str:
        """Plain-language reading of the ledger."""
        if self.unknown_bits <= 0.0:
            return "the scalar is fully determined by the known information"
        if self.feasible:
            return (
                f"searchable: {self.unknown_bits:.0f} unknown bits, about "
                f"2^{self.search_operations_log2:.0f} operations"
            )
        return (
            f"not searchable: {self.unknown_bits:.0f} unknown bits would need about "
            f"2^{self.search_operations_log2:.0f} operations"
        )

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "entries": [entry.as_dict() for entry in self.entries],
            "space_bits": self.space_bits,
            "known_bits": round(self.known_bits, 3),
            "unknown_bits": round(self.unknown_bits, 3),
            "solvable_bits": self.solvable_bits,
            "feasible": self.feasible,
            "search_operations_log2": round(self.search_operations_log2, 3),
            "verdict": self.verdict,
        }


#: Public data carries no usable information about the scalar.  These entries are
#: part of the ledger so the zero is explicit rather than implied.
_PUBLIC_ENTRIES: Final[tuple[LedgerEntry, ...]] = (
    LedgerEntry(
        label="public key coordinates x and y",
        bits=0.0,
        note=(
            "Inverting (x, y) = k * G is the elliptic-curve discrete logarithm: about "
            "2^128 operations on secp256k1. No feasible information."
        ),
    ),
    LedgerEntry(
        label="addresses, hashes, and encodings",
        bits=0.0,
        note="Derived from the same point through public functions; they add no new constraint.",
    ),
    LedgerEntry(
        label="mirror point -P and x-only form",
        bits=0.0,
        note="Both are functions of the same coordinates, so they repeat the same zero.",
    ),
)


def build_ledger(
    template: KeyTemplate | None = None,
    *,
    extra: tuple[LedgerEntry, ...] = (),
    solvable_bits: int = DEFAULT_UNKNOWN_BITS,
) -> InformationLedger:
    """Build the single-scale ledger for a template plus other known facts.

    Args:
        template: Known/unknown hexadecimal digits, or ``None`` when nothing is
            known about the scalar.
        extra: Additional constraints, for example a known residue modulo a small
            number (worth ``log2(modulus)`` bits) or a known interval (worth
            ``log2(width)`` bits).
        solvable_bits: Search budget used to decide whether the remainder is
            practical.

    Returns:
        The ledger.

    Raises:
        InputValidationError: ``solvable_bits`` is outside ``1..MAX_UNKNOWN_BITS``.
    """
    if not 1 <= solvable_bits <= MAX_UNKNOWN_BITS:
        raise InputValidationError(f"solvable_bits must be between 1 and {MAX_UNKNOWN_BITS}")
    entries: list[LedgerEntry] = []
    if template is not None:
        entries.append(
            LedgerEntry(
                label=f"{template.known_digits} known hexadecimal digits",
                bits=float(4 * template.known_digits),
                note="Each known hex digit removes exactly four bits of uncertainty.",
            )
        )
    entries.extend(extra)
    entries.extend(_PUBLIC_ENTRIES)
    return InformationLedger(entries=tuple(entries), solvable_bits=solvable_bits)


def residue_entry(value: int, modulus: int) -> LedgerEntry:
    """Return the ledger entry for knowing a scalar modulo *modulus*.

    Raises:
        InputValidationError: The modulus is not greater than one, or the residue
            is out of range.
    """
    if not isinstance(modulus, int) or modulus < 2:
        raise InputValidationError("the modulus must be an integer of at least 2")
    if not 0 <= value < modulus:
        raise InputValidationError("the residue must satisfy 0 <= value < modulus")
    return LedgerEntry(
        label=f"scalar known modulo {modulus}",
        bits=math.log2(modulus),
        note="A congruence modulo m removes log2(m) bits on the single scale.",
    )


def interval_entry(low: int, high: int) -> LedgerEntry:
    """Return the ledger entry for knowing that the scalar lies in ``[low, high)``.

    Raises:
        InputValidationError: The interval is empty.
    """
    if not 0 <= low < high:
        raise InputValidationError("the interval must satisfy 0 <= low < high")
    return LedgerEntry(
        label=f"scalar in [{low}, {high})",
        bits=_SCALAR_BITS - math.log2(high - low),
        note="An interval of width w leaves log2(w) bits; the ledger counts what it removes.",
    )


# ---------------------------------------------------------------------------
# Solving a template
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TemplateSolution:
    """The outcome of a bounded template search.

    Attributes:
        public_key_hex: The compressed key that was explained.
        template: The pattern that was solved.
        assembled_hex: The complete 64-digit scalar, or ``None`` when unsolved.
            Excluded from ``repr`` so a stray log cannot leak it.
        unknown_value: The value found in the unknown window.
        verified: Whether the assembled scalar re-derives the input public key
            through ``cryptography``.
        steps: Number of group operations the search performed.
        elapsed_seconds: Wall-clock duration of the search.
        ledger: The single-scale information budget for this template.
        message: Plain-language outcome.
    """

    public_key_hex: str
    template: KeyTemplate
    assembled_hex: str | None = field(repr=False)
    unknown_value: int | None = field(repr=False)
    verified: bool
    steps: int
    elapsed_seconds: float
    ledger: InformationLedger
    message: str

    @property
    def solved(self) -> bool:
        """Whether a verified scalar was found."""
        return self.assembled_hex is not None and self.verified

    def as_dict(self, *, reveal: bool = False) -> dict[str, Any]:
        """Return a JSON-serializable representation.

        Args:
            reveal: Include the assembled scalar.  The default redacts it so that
                reports and logs cannot leak a private key by accident.
        """
        return {
            "public_key": self.public_key_hex,
            "template": self.template.as_dict(),
            "ledger": self.ledger.as_dict(),
            "solved": self.solved,
            "verified": self.verified,
            "steps": self.steps,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "assembled_scalar_hex": self.assembled_hex if reveal else None,
            "unknown_window_value": self.unknown_value if reveal else None,
            "redacted": not reveal,
            "message": self.message,
        }


def _verify_scalar(scalar: int, public_key_hex: str) -> bool:
    """Re-derive *scalar* through ``cryptography`` and compare the encodings."""
    try:
        derived = derive_public_key(scalar)
    except Exception:
        return False
    return public_key_bytes(derived, compressed=True).hex() == public_key_hex.lower()


def solve_template(
    public_key_hex: str,
    template: KeyTemplate | str,
    *,
    max_unknown_bits: int = DEFAULT_UNKNOWN_BITS,
) -> TemplateSolution:
    """Search the unknown window of a template and assemble the full scalar.

    The search is a baby-step/giant-step walk over the unknown window only:

    .. math:: Q - K \\cdot G = x \\cdot 2^{low} G, \\qquad 0 \\le x < 2^{b}

    where ``K`` is the template with the unknown digits set to zero, ``b`` is the
    width of the window in bits, and ``low`` is the number of known bits below it.
    A found ``x`` is assembled into the full scalar and verified by re-deriving
    the public key.

    Args:
        public_key_hex: Compressed, uncompressed, or raw secp256k1 public key.
        template: A :class:`KeyTemplate` or its 64-digit pattern.
        max_unknown_bits: Refuse windows wider than this.  Capped at
            :data:`MAX_UNKNOWN_BITS`.

    Returns:
        The solution.  When the search finds nothing, ``solved`` is ``False`` and
        ``message`` explains why.

    Raises:
        InputValidationError: The key or template is invalid, or the window is
            wider than the budget.

    Example:
        >>> pattern = "0" * 62 + "??"
        >>> solve_template(
        ...     "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ...     pattern,
        ...     max_unknown_bits=8,
        ... ).assembled_hex
        '0000000000000000000000000000000000000000000000000000000000000001'
    """
    parsed = template if isinstance(template, KeyTemplate) else parse_template(template)
    if not 1 <= max_unknown_bits <= MAX_UNKNOWN_BITS:
        raise InputValidationError(f"max_unknown_bits must be between 1 and {MAX_UNKNOWN_BITS}")
    if parsed.unknown_bits > max_unknown_bits:
        raise InputValidationError(
            f"the template leaves {parsed.unknown_bits} unknown bits, above the "
            f"budget of {max_unknown_bits}; this tool does not attack the full keyspace"
        )
    point = decode_public_key(public_key_hex)
    ledger = build_ledger(parsed, solvable_bits=max_unknown_bits)
    started = time.perf_counter()

    known_point = multiply(GENERATOR, parsed.known_value)
    target = sub(point, known_point)
    base = multiply(GENERATOR, 1 << parsed.low_bits)
    steps = math.isqrt((1 << parsed.unknown_bits) - 1) + 1
    found = discrete_log_interval(
        target,
        generator=base,
        low=0,
        high=1 << parsed.unknown_bits,
        max_entries=min(MAX_TABLE_ENTRIES, steps),
    )
    elapsed = time.perf_counter() - started

    if found is None:
        return TemplateSolution(
            public_key_hex=public_key_hex.lower(),
            template=parsed,
            assembled_hex=None,
            unknown_value=None,
            verified=False,
            steps=steps,
            elapsed_seconds=elapsed,
            ledger=ledger,
            message=(
                "no value in the unknown window explains this public key; the known "
                "digits, the window position, or the key itself is inconsistent"
            ),
        )

    scalar = parsed.assemble(found)
    if not 0 < scalar < CURVE_ORDER:
        return TemplateSolution(
            public_key_hex=public_key_hex.lower(),
            template=parsed,
            assembled_hex=None,
            unknown_value=found,
            verified=False,
            steps=steps,
            elapsed_seconds=elapsed,
            ledger=ledger,
            message="the assembled value is outside the valid scalar range 1 <= k < n",
        )

    verified = _verify_scalar(scalar, public_key_hex)
    if not verified:
        return TemplateSolution(
            public_key_hex=public_key_hex.lower(),
            template=parsed,
            assembled_hex=None,
            unknown_value=found,
            verified=False,
            steps=steps,
            elapsed_seconds=elapsed,
            ledger=ledger,
            message="the candidate failed verification against cryptography; nothing is reported",
        )

    return TemplateSolution(
        public_key_hex=public_key_hex.lower(),
        template=parsed,
        assembled_hex=f"{scalar:0{HEX_DIGITS}x}",
        unknown_value=found,
        verified=True,
        steps=steps,
        elapsed_seconds=elapsed,
        ledger=ledger,
        message=(
            f"assembled and verified: {parsed.known_digits} known digits plus a "
            f"{parsed.unknown_bits}-bit window"
        ),
    )


def solve_offset(
    reference_public_key_hex: str,
    target_public_key_hex: str,
    *,
    max_delta_bits: int = 16,
) -> int | None:
    """Return ``d`` such that ``Q_target = Q_reference + d * G``, if ``|d|`` is small.

    This is the related-key case: two keys generated with a small scalar
    difference (an incrementing counter, a re-used nonce, a hand-edited key).  The
    search is over the difference only, so it is bounded by ``2**(max_delta_bits/2)``
    operations and says nothing about unrelated keys.

    Args:
        reference_public_key_hex: The key whose scalar you already know.
        target_public_key_hex: The key whose scalar you want to express relative to it.
        max_delta_bits: Width of the difference window, capped at
            :data:`MAX_UNKNOWN_BITS`.

    Returns:
        The signed difference, or ``None`` when it is not in the window.

    Raises:
        InputValidationError: A key is invalid or the budget is out of range.
    """
    if not 1 <= max_delta_bits <= MAX_UNKNOWN_BITS:
        raise InputValidationError(f"max_delta_bits must be between 1 and {MAX_UNKNOWN_BITS}")
    reference = decode_public_key(reference_public_key_hex)
    target = decode_public_key(target_public_key_hex)
    delta = sub(target, reference)
    high = 1 << max_delta_bits
    steps = math.isqrt(high - 1) + 1
    positive = discrete_log_interval(
        delta, low=0, high=high, max_entries=min(MAX_TABLE_ENTRIES, steps)
    )
    if positive is not None:
        return positive
    negative = discrete_log_interval(
        sub(reference, target), low=1, high=high, max_entries=min(MAX_TABLE_ENTRIES, steps)
    )
    return -negative if negative is not None else None


# ---------------------------------------------------------------------------
# Comparing a set of keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyRelationship:
    """A small scalar difference found between two keys.

    Attributes:
        left: One-based index of the first key.
        right: One-based index of the second key.
        delta: Signed difference such that ``Q_right = Q_left + delta * G``.
        verified: Whether the relation was re-checked with ``cryptography``.
    """

    left: int
    right: int
    delta: int
    verified: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "left": self.left,
            "right": self.right,
            "delta": self.delta,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    """Segmentation and comparison of a set of public keys.

    Attributes:
        count: Number of keys compared.
        nibble_agreement: For each of the 64 x-nibble positions, how many keys
            share the most common digit there.
        shared_prefix_nibbles: Leading x-nibbles identical in every key.
        shared_suffix_nibbles: Trailing x-nibbles identical in every key.
        pairwise_hamming: ``(i, j, bits)`` Hamming distances between x coordinates.
        relationships: Small scalar offsets discovered between pairs.
        pairs_examined: How many pairs the offset search actually visited.
        truncated: Whether the pair budget stopped the offset search early.
        notes: Caveats about what a comparison of public keys can and cannot show.
    """

    count: int
    nibble_agreement: tuple[int, ...]
    shared_prefix_nibbles: int
    shared_suffix_nibbles: int
    pairwise_hamming: tuple[tuple[int, int, int], ...]
    relationships: tuple[KeyRelationship, ...]
    pairs_examined: int
    truncated: bool
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "count": self.count,
            "nibble_agreement": list(self.nibble_agreement),
            "shared_prefix_nibbles": self.shared_prefix_nibbles,
            "shared_suffix_nibbles": self.shared_suffix_nibbles,
            "pairwise_hamming": [list(item) for item in self.pairwise_hamming],
            "relationships": [item.as_dict() for item in self.relationships],
            "pairs_examined": self.pairs_examined,
            "truncated": self.truncated,
            "notes": list(self.notes),
        }


def compare_keys(
    public_keys: tuple[str, ...] | list[str],
    *,
    max_delta_bits: int = 16,
    max_pairs: int = 200,
) -> ComparisonReport:
    """Segment a set of public keys and compare them position by position.

    The comparison is over public coordinates only.  Shared nibbles are reported
    as repetitions, and each pair is checked for a small scalar difference, which
    is the only relationship that can be *proved* from public keys without solving
    a discrete logarithm.

    Args:
        public_keys: Two or more public keys in any SEC 1 encoding.
        max_delta_bits: Difference window used for the related-key check.
        max_pairs: Cap on the number of pairs examined.

    Returns:
        The comparison report.

    Raises:
        InputValidationError: Fewer than two keys are supplied, or one is invalid.
    """
    keys = tuple(public_keys)
    if len(keys) < 2:
        raise InputValidationError("at least two public keys are required for a comparison")
    if max_pairs < 1:
        raise InputValidationError("max_pairs must be positive")
    points: list[Point] = []
    for index, key in enumerate(keys, start=1):
        try:
            points.append(decode_public_key(key))
        except InputValidationError as exc:
            raise InputValidationError(f"public key #{index} is invalid: {exc}") from exc

    x_values = [point[0] for point in points if point is not None]
    width = 64
    x_hex = [f"{value:0{width}x}" for value in x_values]
    agreement: list[int] = []
    for position in range(width):
        counts: dict[str, int] = {}
        for text in x_hex:
            digit = text[position]
            counts[digit] = counts.get(digit, 0) + 1
        agreement.append(max(counts.values()))

    prefix = 0
    for position in range(width):
        if len({text[position] for text in x_hex}) != 1:
            break
        prefix += 1
    suffix = 0
    for position in range(width - 1, prefix - 1, -1):
        if len({text[position] for text in x_hex}) != 1:
            break
        suffix += 1

    hamming: list[tuple[int, int, int]] = []
    relationships: list[KeyRelationship] = []
    pairs = 0
    truncated = False
    high = 1 << max_delta_bits
    steps = math.isqrt(high - 1) + 1
    for left in range(len(points)):
        for right in range(left + 1, len(points)):
            if pairs >= max_pairs:
                truncated = True
                break
            pairs += 1
            left_point, right_point = points[left], points[right]
            if left_point is not None and right_point is not None:
                distance = (left_point[0] ^ right_point[0]).bit_count()
                hamming.append((left + 1, right + 1, distance))
            delta = sub(right_point, left_point)
            found = discrete_log_interval(
                delta, low=0, high=high, max_entries=min(MAX_TABLE_ENTRIES, steps)
            )
            if found is None:
                opposite = discrete_log_interval(
                    sub(left_point, right_point),
                    low=1,
                    high=high,
                    max_entries=min(MAX_TABLE_ENTRIES, steps),
                )
                found = -opposite if opposite is not None else None
            if found is not None:
                verified = (
                    multiply(GENERATOR, found) == delta
                    if found >= 0
                    else multiply(GENERATOR, -found) == sub(left_point, right_point)
                )
                relationships.append(
                    KeyRelationship(left=left + 1, right=right + 1, delta=found, verified=verified)
                )
        if truncated:
            break

    return ComparisonReport(
        count=len(keys),
        nibble_agreement=tuple(agreement),
        shared_prefix_nibbles=prefix,
        shared_suffix_nibbles=suffix,
        pairwise_hamming=tuple(hamming),
        relationships=tuple(relationships),
        pairs_examined=pairs,
        truncated=truncated,
        notes=(
            "Shared nibbles are repetitions in public coordinates. They are evidence "
            "about the generator, not about the scalar: the coordinates are its hash-"
            "like image, not its digits.",
            "A small scalar difference between two keys is provable from public data "
            "and is reported when found; unrelated keys have differences spread over "
            "the whole group and are not recoverable.",
            "This comparison never solves a discrete logarithm over the full group; "
            "the offset search is limited to the window you request.",
            "Comparing keys you do not own can reveal relationships about them; only "
            "do this with keys you generated.",
        ),
    )
