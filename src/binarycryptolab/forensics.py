"""Deep public-key dissection and structural forecasting.

What this module does
---------------------
Given a **public** secp256k1 key, :func:`dissect_public_key` describes it from
every angle that is mathematically available from public data alone:

* identity: curve, SEC 1 encoding, prefix byte, parity, x-only (BIP-340) form;
* coordinates: hexadecimal, decimal, bit length, leading/trailing zeros,
  Hamming weight, byte entropy, limb decompositions, little-endian form, and an
  ASCII bit grid;
* curve verification: ``y² ≡ x³ + 7 (mod p)``, range checks against the field
  prime, compressed/uncompressed agreement, and address round-trips;
* representations: hex/binary/decimal/Base58/Base64/Base32 forms of the key, its
  coordinates, and its coordinates in little-endian order;
* bit and byte profiles of every representation;
* digests: SHA-256, double SHA-256, RIPEMD-160, SHA-512, and HASH160 of the
  compressed and uncompressed encodings;
* the address matrix: P2PKH (both key encodings), P2WPKH, and P2SH-P2WPKH for
  mainnet, testnet, signet, and regtest, with locking scripts;
* structural findings: patterns that a uniformly random key would almost never
  show, each with a computed probability;
* a forecast: an explicit, scored assessment of how likely each generation
  story is (CSPRNG, low-entropy RNG, puzzle/teaching key, corrupt copy), the
  cost of an exhaustive search for various scalar sizes, and a clear statement
  that key recovery is neither implemented nor feasible.

What this module does **not** do
--------------------------------
It does not compute, guess, or search for a private key.  There is no brute
force, no baby-step/giant-step table, no Pollard rho, and no network access.  A
public key cannot be turned into a private key; the "forecast" here is a
statistical reading of the key's *structure* (:math:`-\\log_2 p` evidence
values, binomial tail probabilities, and pattern matching), not a solver.  Any
claim to the contrary would be false.

Every probability in this module is an order-of-magnitude estimate for a
uniformly random 256-bit value, not a proof about how a particular key was made.
"""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from typing import Any, Final, Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .base58 import b58encode
from .bitcoin import (
    AddressType,
    Network,
    decode_address,
    derive_p2pkh_address,
    derive_p2sh_p2wpkh_address,
    derive_p2wpkh_address,
)
from .ecc import (
    COMPRESSED_PUBLIC_KEY_LENGTH,
    CURVE_ORDER,
    FIELD_PRIME,
    UNCOMPRESSED_PUBLIC_KEY_LENGTH,
    parse_public_key_hex,
    public_key_bytes,
    public_key_info_from_hex,
)
from .exceptions import AddressEncodingError, BinaryCryptoLabError, InvalidPublicKeyError
from .hashing import double_sha256, hash160, ripemd160, sha256, sha512
from .statistics import bit_statistics, byte_statistics
from .validation import normalize_hex

__all__ = [
    "ALL_NETWORKS",
    "DEPTH_LEVELS",
    "AddressMatrixEntry",
    "BitProfile",
    "CoordinateProfile",
    "Forecast",
    "ForecastHypothesis",
    "MirrorPoint",
    "PublicKeyDissection",
    "Representation",
    "SearchEstimate",
    "StructureFinding",
    "dissect_many",
    "dissect_public_key",
]

Depth = Literal["standard", "deep"]

#: Depth levels accepted by :func:`dissect_public_key`.
DEPTH_LEVELS: Final[tuple[str, ...]] = ("standard", "deep")

#: Networks included in the address matrix, in report order.
ALL_NETWORKS: Final[tuple[Network, ...]] = (
    Network.MAINNET,
    Network.TESTNET,
    Network.SIGNET,
    Network.REGTEST,
)

_BITS: Final = 256
_HEX_WIDTH: Final = 64
_GRID_COLUMNS: Final = 32
_MIN_PROBABILITY: Final = 1e-300
_ZERO_PROBABILITY: Final = float(2**-256)

#: Built-in "magic" constants that occasionally appear in hand-made test keys.
_KNOWN_CONSTANTS: Final[tuple[str, ...]] = (
    "deadbeef",
    "cafebabe",
    "0badc0de",
    "abad1dea",
    "f00dbabe",
    "c0ffee",
    "8badf00d",
    "decafbad",
)

_ASCII_MINIMUM_RUN: Final = 5
_MAX_FINDING_SURPRISAL: Final = 64.0


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------


def _leading_zero_bits(value: int) -> int:
    """Return how many zero bits precede the most significant set bit."""
    return max(0, _BITS - value.bit_length())


def _trailing_zero_bits(value: int) -> int:
    """Return the number of trailing zero bits (256 for zero)."""
    if value == 0:
        return _BITS
    return (value & -value).bit_length() - 1


def _probability(exponent_bits: float) -> float:
    """Return ``2 ** -exponent_bits``, clamped away from zero."""
    value = math.pow(2.0, -exponent_bits)
    return max(_MIN_PROBABILITY, min(1.0, value))


def _surprisal(probability: float) -> float:
    """Return ``-log2(probability)``, capped to keep scores readable."""
    if probability <= 0:
        return _MAX_FINDING_SURPRISAL
    return min(_MAX_FINDING_SURPRISAL, -math.log2(probability))


def _binomial_two_sided_p(observed: int, trials: int = _BITS, bias: float = 0.5) -> float:
    """Two-sided binomial tail probability for a bit count.

    Args:
        observed: Number of ones observed.
        trials: Number of independent bits.
        bias: Probability of a one under the null hypothesis.

    Returns:
        ``P(|X - trials*bias| >= |observed - trials*bias|)`` for
        ``X ~ Binomial(trials, bias)``, computed exactly with integer
        combinatorics and converted to a float at the end.
    """
    if not 0 <= observed <= trials:
        raise ValueError("observed must be between 0 and trials")
    expected = trials * bias
    distance = abs(observed - expected)
    if distance == 0:
        return 1.0
    if bias == 0.5:
        integer_tail = sum(
            math.comb(trials, index)
            for index in range(trials + 1)
            if abs(index - expected) >= distance
        )
        return min(1.0, integer_tail / (1 << trials))
    # General case: accumulate the probability mass directly.
    accumulated = 0.0
    for index in range(trials + 1):
        if abs(index - expected) < distance:
            continue
        accumulated += math.comb(trials, index) * (bias**index) * ((1.0 - bias) ** (trials - index))
    return min(1.0, accumulated)


def _limbs(value: int, base_bits: int, width: int = _BITS) -> tuple[int, ...]:
    """Split *value* into base-``2**base_bits`` limbs, most significant first."""
    if base_bits <= 0 or width % base_bits != 0:
        raise ValueError("base_bits must divide the width")
    mask = (1 << base_bits) - 1
    count = width // base_bits
    return tuple((value >> (base_bits * (count - 1 - index))) & mask for index in range(count))


def _bit_grid(value: int, *, columns: int = _GRID_COLUMNS) -> tuple[str, ...]:
    """Render a 256-bit value as an ASCII grid of ``#`` and ``.``."""
    bits = f"{value:0{_BITS}b}"
    return tuple(bits[index : index + columns] for index in range(0, _BITS, columns))


def _human_duration(seconds: float) -> str:
    """Format a duration in seconds using human units."""
    if seconds < 0:
        raise ValueError("seconds must be non-negative")
    if seconds < 1e-6:
        return "less than a microsecond"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.0f} microseconds"
    units: tuple[tuple[float, str], ...] = (
        (365.25 * 24 * 3600, "years"),
        (24 * 3600, "days"),
        (3600, "hours"),
        (60, "minutes"),
        (1, "seconds"),
    )
    for factor, name in units:
        if seconds >= factor:
            amount = seconds / factor
            if amount >= 1e6:
                return f"{amount:.3e} {name}"
            return f"{amount:.2f} {name}"
    return f"{seconds * 1000:.1f} milliseconds"


def _format_count(value: float) -> str:
    """Format a large count compactly (``4.29e9``, ``1.16e77``)."""
    if value < 1000:
        return f"{value:.0f}"
    return f"{value:.3e}"


def _printable_runs(data: bytes, minimum: int = _ASCII_MINIMUM_RUN) -> tuple[str, ...]:
    """Return ASCII-printable runs of at least *minimum* characters."""
    runs: list[str] = []
    current: list[str] = []
    for byte_value in data:
        if 0x20 <= byte_value < 0x7F or byte_value == 0x09:
            current.append(chr(byte_value))
        else:
            if len(current) >= minimum:
                runs.append("".join(current))
            current = []
    if len(current) >= minimum:
        runs.append("".join(current))
    return tuple(runs)


def _repeated_period(text: str, period: int) -> bool:
    """Return whether *text* is a whole-number repetition of a *period*-char block."""
    if period <= 0 or len(text) % period != 0 or period >= len(text):
        return False
    block = text[:period]
    return all(text[index : index + period] == block for index in range(0, len(text), period))


def _is_palindrome(text: str) -> bool:
    """Return whether *text* reads the same forwards and backwards."""
    return len(text) > 1 and text == text[::-1]


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CoordinateProfile:
    """Everything measurable about one affine coordinate.

    Attributes:
        name: ``"x"`` or ``"y"``.
        hexadecimal: Zero-padded, 64-character lowercase hexadecimal.
        decimal: Decimal digits.
        bit_length: Position of the most significant set bit.
        byte_length: ``32`` for a full-width coordinate.
        leading_zero_bits: Zero bits before the most significant set bit.
        trailing_zero_bits: Zero bits after the least significant set bit.
        hamming_weight: Number of set bits.
        hamming_ratio: ``hamming_weight / 256``.
        hamming_p_value: Two-sided binomial tail probability of this weight.
        byte_entropy: Shannon entropy of the 32 coordinate bytes, bits/byte.
        unique_bytes: Number of distinct byte values in the coordinate.
        nibble_frequency: ``(digit, count)`` pairs, most frequent first.
        limb_bases: ``base -> limbs`` mappings (8, 16, 32, 64 bits).
        little_endian_hex: The coordinate serialised least significant byte first.
        is_even: Whether the coordinate is even.
        is_below_half_prime: Whether the coordinate is below ``p / 2``.
        distance_to_prime: ``p - value`` as decimal digits.
        bit_grid: ASCII rows of the 256-bit pattern.
        ascii_runs: Printable ASCII runs found in the coordinate bytes.
    """

    name: str
    hexadecimal: str
    decimal: str
    bit_length: int
    byte_length: int
    leading_zero_bits: int
    trailing_zero_bits: int
    hamming_weight: int
    hamming_ratio: float
    hamming_p_value: float
    byte_entropy: float
    unique_bytes: int
    nibble_frequency: tuple[tuple[str, int], ...]
    limb_bases: tuple[tuple[int, tuple[int, ...]], ...]
    little_endian_hex: str
    is_even: bool
    is_below_half_prime: bool
    distance_to_prime: str
    bit_grid: tuple[str, ...]
    ascii_runs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "name": self.name,
            "hexadecimal": self.hexadecimal,
            "decimal": self.decimal,
            "bit_length": self.bit_length,
            "byte_length": self.byte_length,
            "leading_zero_bits": self.leading_zero_bits,
            "trailing_zero_bits": self.trailing_zero_bits,
            "hamming_weight": self.hamming_weight,
            "hamming_ratio": self.hamming_ratio,
            "hamming_p_value": self.hamming_p_value,
            "byte_entropy": self.byte_entropy,
            "unique_bytes": self.unique_bytes,
            "nibble_frequency": dict(self.nibble_frequency),
            "limbs": {str(base): list(limbs) for base, limbs in self.limb_bases},
            "little_endian_hex": self.little_endian_hex,
            "is_even": self.is_even,
            "is_below_half_prime": self.is_below_half_prime,
            "distance_to_prime": self.distance_to_prime,
            "bit_grid": list(self.bit_grid),
            "ascii_runs": list(self.ascii_runs),
        }


@dataclass(frozen=True, slots=True)
class Representation:
    """One textual or binary view of the key.

    Attributes:
        label: Human-readable name, e.g. ``"compressed (hex)"``.
        encoding: Machine-readable encoding name, e.g. ``"hex"``.
        value: Rendered value.
        byte_length: Decoded length in bytes, when meaningful.
        note: What the representation is used for.
    """

    label: str
    encoding: str
    value: str
    byte_length: int | None
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "label": self.label,
            "encoding": self.encoding,
            "value": self.value,
            "byte_length": self.byte_length,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class BitProfile:
    """Bit statistics for one named byte string.

    Attributes:
        label: Which representation was measured.
        length_bits: Number of bits.
        ones: Number of one bits.
        zeros: Number of zero bits.
        one_ratio: Proportion of one bits.
        entropy: Shannon entropy of the bit distribution, bits per bit.
        one_run_longest: Longest run of consecutive one bits.
        zero_run_longest: Longest run of consecutive zero bits.
    """

    label: str
    length_bits: int
    ones: int
    zeros: int
    one_ratio: float
    entropy: float
    one_run_longest: int
    zero_run_longest: int

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "label": self.label,
            "length_bits": self.length_bits,
            "ones": self.ones,
            "zeros": self.zeros,
            "one_ratio": self.one_ratio,
            "entropy": self.entropy,
            "one_run_longest": self.one_run_longest,
            "zero_run_longest": self.zero_run_longest,
        }


@dataclass(frozen=True, slots=True)
class StructureFinding:
    """A pattern that is unusual for a uniformly random key.

    Attributes:
        code: Stable machine-readable identifier.
        title: Short human-readable description.
        evidence: The concrete measurement that triggered the finding.
        probability: Probability that a uniformly random key shows the finding.
        surprisal_bits: ``-log2(probability)``, capped at 64.
        severity: ``"critical"`` (``p <= 2^-40``), ``"warning"``
            (``p <= 2^-16``), or ``"info"``.
        interpretation: What the finding does and does not imply.
    """

    code: str
    title: str
    evidence: str
    probability: float
    surprisal_bits: float
    severity: str
    interpretation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "title": self.title,
            "evidence": self.evidence,
            "probability": self.probability,
            "probability_log2": -self.surprisal_bits,
            "surprisal_bits": self.surprisal_bits,
            "severity": self.severity,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True, slots=True)
class ForecastHypothesis:
    """One candidate explanation for the key's structure.

    Attributes:
        hypothesis: The generation story being considered.
        score: Confidence in ``[0, 1]``.
        likelihood: Verbal label derived from :attr:`score`.
        evidence: Why the score was assigned.
        testable: Whether the hypothesis could be confirmed or refuted locally.
    """

    hypothesis: str
    score: float
    likelihood: str
    evidence: str
    testable: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "hypothesis": self.hypothesis,
            "score": self.score,
            "likelihood": self.likelihood,
            "evidence": self.evidence,
            "testable": self.testable,
        }


@dataclass(frozen=True, slots=True)
class SearchEstimate:
    """Cost of one hypothetical key-search strategy.

    These numbers describe the *discrete logarithm problem*.  They are provided
    for security reasoning only; no such search is implemented.

    Attributes:
        strategy: ``"exhaustive"``, ``"pollard-rho"``, or ``"bsgs"``.
        scalar_bits: Size of the scalar space, in bits.
        operations_log2: Base-2 logarithm of the expected number of operations.
        operations: Human-readable operation count.
        memory: Human-readable memory requirement.
        estimated_time: Wall-clock estimate at the stated rate.
        feasible_today: ``"trivial"``, ``"possible"``, ``"infeasible"``, or
            ``"physically impossible"``.
        note: Context for the row.
    """

    strategy: str
    scalar_bits: int
    operations_log2: float
    operations: str
    memory: str
    estimated_time: str
    feasible_today: str
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "strategy": self.strategy,
            "scalar_bits": self.scalar_bits,
            "operations_log2": self.operations_log2,
            "operations": self.operations,
            "memory": self.memory,
            "estimated_time": self.estimated_time,
            "feasible_today": self.feasible_today,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class Forecast:
    """Scored structural assessment of a public key.

    Attributes:
        verdict: Headline verdict.
        size_class: Classification of the key's structural size.
        structure_score: ``0..100``; higher means "less like a random key".
        total_surprisal_bits: Sum of the strongest surprisal per evidence family,
            so correlated findings are not double-counted.
        hypotheses: Ranked generation stories.
        search_estimates: Discrete-logarithm cost table.
        recoverable: Always ``False``; the key cannot be inverted.
        summary: One-paragraph explanation.
        recommendations: Concrete next steps for the key's owner.
        limitations: What the forecast cannot determine.
    """

    verdict: str
    size_class: str
    structure_score: float
    total_surprisal_bits: float
    hypotheses: tuple[ForecastHypothesis, ...]
    search_estimates: tuple[SearchEstimate, ...]
    recoverable: bool
    summary: str
    recommendations: tuple[str, ...]
    limitations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "verdict": self.verdict,
            "size_class": self.size_class,
            "structure_score": self.structure_score,
            "total_surprisal_bits": self.total_surprisal_bits,
            "hypotheses": [item.as_dict() for item in self.hypotheses],
            "search_estimates": [item.as_dict() for item in self.search_estimates],
            "recoverable": self.recoverable,
            "summary": self.summary,
            "recommendations": list(self.recommendations),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class AddressMatrixEntry:
    """One address derived from the key, with its locking script.

    Attributes:
        network: Network name.
        address_type: ``"p2pkh"``, ``"p2wpkh"``, or ``"p2sh-p2wpkh"``.
        key_encoding: Public-key encoding used to build the address.
        address: Encoded address string.
        payload_hex: HASH160 or script hash used by the address.
        witness_version: Witness version when applicable.
        witness_program_hex: Witness program when applicable.
        script_pubkey_hex: Locking script that pays to the address.
        roundtrip_ok: Whether the address decodes back to the same payload.
        roundtrip_type: Address type reported by the decoder.
    """

    network: str
    address_type: str
    key_encoding: str
    address: str
    payload_hex: str
    witness_version: int | None
    witness_program_hex: str | None
    script_pubkey_hex: str
    roundtrip_ok: bool
    roundtrip_type: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "network": self.network,
            "address_type": self.address_type,
            "key_encoding": self.key_encoding,
            "address": self.address,
            "payload_hex": self.payload_hex,
            "witness_version": self.witness_version,
            "witness_program_hex": self.witness_program_hex,
            "script_pubkey_hex": self.script_pubkey_hex,
            "roundtrip_ok": self.roundtrip_ok,
            "roundtrip_type": self.roundtrip_type,
        }


@dataclass(frozen=True, slots=True)
class MirrorPoint:
    """The other curve point sharing this x coordinate.

    For every valid x there are exactly two points, ``(x, y)`` and ``(x, p - y)``.
    They are negatives of each other, so they share the same x-only serialisation
    and the same compressed prefix alphabet (``02``/``03`` flipped).  Wallets that
    expose only x therefore lose one bit of information: which of the two points
    is meant.  This section shows that twin explicitly.

    Attributes:
        x_hex: The shared x coordinate.
        y_hex: The mirrored y coordinate, ``p - y``.
        compressed_hex: SEC 1 compressed encoding of the mirrored point.
        y_parity: ``"even"`` or ``"odd"`` for the mirrored point.
        addresses: Mainnet P2PKH and P2WPKH entries for the mirrored point.
        note: Why the mirror matters.
    """

    x_hex: str
    y_hex: str
    compressed_hex: str
    y_parity: str
    addresses: tuple[AddressMatrixEntry, ...]
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "x_hex": self.x_hex,
            "y_hex": self.y_hex,
            "compressed_hex": self.compressed_hex,
            "y_parity": self.y_parity,
            "addresses": [entry.as_dict() for entry in self.addresses],
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class PublicKeyDissection:
    """Complete public-data dissection of a secp256k1 public key.

    Attributes:
        input_hex: Normalized input, lowercase hexadecimal.
        input_encoding: ``"compressed"``, ``"uncompressed"``, or
            ``"raw-uncompressed"`` (64 bytes without the ``0x04`` prefix).
        depth: ``"standard"`` or ``"deep"``.
        curve: Curve name.
        compressed_hex: Canonical compressed encoding.
        uncompressed_hex: Canonical uncompressed encoding.
        x_only_hex: 32-byte x-only encoding (BIP-340 style, no tweak applied).
        y_hex: 32-byte y coordinate.
        prefix_byte: SEC 1 prefix byte as ``0x02``-style text.
        y_parity: ``"even"`` or ``"odd"``.
        coordinates: Profiles for ``x`` and ``y``.
        verification: Named boolean checks that were performed.
        representations: All textual/binary views.
        bit_profiles: Bit statistics per representation.
        digests: ``(algorithm, hex digest)`` pairs.
        addresses: Address matrix.
        mirror: The other point that shares this x coordinate (``-P``).
        keyspace: Curve-size context (order, space, collision bound).
        findings: Structural findings, ordered by significance.
        forecast: Scored assessment.
        notes: Honesty notes about scope.
    """

    input_hex: str
    input_encoding: str
    depth: str
    curve: str
    compressed_hex: str
    uncompressed_hex: str
    x_only_hex: str
    y_hex: str
    prefix_byte: str
    y_parity: str
    coordinates: tuple[CoordinateProfile, ...]
    verification: tuple[tuple[str, bool], ...]
    representations: tuple[Representation, ...]
    bit_profiles: tuple[BitProfile, ...]
    digests: tuple[tuple[str, str], ...]
    addresses: tuple[AddressMatrixEntry, ...]
    mirror: MirrorPoint
    keyspace: tuple[tuple[str, str], ...]
    findings: tuple[StructureFinding, ...]
    forecast: Forecast
    notes: tuple[str, ...]

    @property
    def x(self) -> CoordinateProfile:
        """The ``x`` coordinate profile."""
        return self.coordinates[0]

    @property
    def y(self) -> CoordinateProfile:
        """The ``y`` coordinate profile."""
        return self.coordinates[1]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the whole dissection."""
        return {
            "input": {"hex": self.input_hex, "encoding": self.input_encoding},
            "depth": self.depth,
            "curve": self.curve,
            "public_key": {
                "compressed_hex": self.compressed_hex,
                "uncompressed_hex": self.uncompressed_hex,
                "x_only_hex": self.x_only_hex,
                "y_hex": self.y_hex,
                "prefix_byte": self.prefix_byte,
                "y_parity": self.y_parity,
                "compressed_length_bytes": COMPRESSED_PUBLIC_KEY_LENGTH,
                "uncompressed_length_bytes": UNCOMPRESSED_PUBLIC_KEY_LENGTH,
            },
            "coordinates": {profile.name: profile.as_dict() for profile in self.coordinates},
            "verification": dict(self.verification),
            "representations": [item.as_dict() for item in self.representations],
            "bit_profiles": [item.as_dict() for item in self.bit_profiles],
            "digests": dict(self.digests),
            "address_matrix": [entry.as_dict() for entry in self.addresses],
            "mirror_point": self.mirror.as_dict(),
            "keyspace": dict(self.keyspace),
            "findings": [finding.as_dict() for finding in self.findings],
            "forecast": self.forecast.as_dict(),
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


def _nibble_frequency(hexadecimal: str) -> tuple[tuple[str, int], ...]:
    """Return ``(digit, count)`` pairs ordered by descending count."""
    counts: dict[str, int] = {}
    for digit in hexadecimal:
        counts[digit] = counts.get(digit, 0) + 1
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _longest_run(bits: str, symbol: str) -> int:
    """Return the length of the longest run of *symbol* in *bits*."""
    best = 0
    current = 0
    for character in bits:
        if character == symbol:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _coordinate_profile(name: str, value: int, *, depth: str) -> CoordinateProfile:
    """Build a :class:`CoordinateProfile` for one coordinate."""
    hexadecimal = f"{value:0{_HEX_WIDTH}x}"
    raw = value.to_bytes(_HEX_WIDTH // 2, "big")
    stats = bit_statistics(f"{value:0{_BITS}b}")
    byte_stats = byte_statistics(raw)
    base_bits = (8, 16, 32, 64) if depth == "deep" else (32,)
    limbs = tuple((bits, _limbs(value, bits)) for bits in base_bits)
    return CoordinateProfile(
        name=name,
        hexadecimal=hexadecimal,
        decimal=str(value),
        bit_length=value.bit_length(),
        byte_length=len(raw),
        leading_zero_bits=_leading_zero_bits(value),
        trailing_zero_bits=_trailing_zero_bits(value),
        hamming_weight=stats.hamming_weight,
        hamming_ratio=stats.one_ratio,
        hamming_p_value=_binomial_two_sided_p(stats.hamming_weight),
        byte_entropy=byte_stats.entropy,
        unique_bytes=byte_stats.unique_bytes,
        nibble_frequency=_nibble_frequency(hexadecimal),
        limb_bases=limbs,
        little_endian_hex=raw[::-1].hex(),
        is_even=value % 2 == 0,
        is_below_half_prime=value < FIELD_PRIME // 2,
        distance_to_prime=str(FIELD_PRIME - value),
        bit_grid=_bit_grid(value),
        ascii_runs=_printable_runs(raw),
    )


def _bit_profile(label: str, data: bytes) -> BitProfile:
    """Compute bit statistics for a byte string."""
    bits = "".join(f"{byte_value:08b}" for byte_value in data)
    stats = bit_statistics(bits)
    return BitProfile(
        label=label,
        length_bits=stats.length,
        ones=stats.ones,
        zeros=stats.zeros,
        one_ratio=stats.one_ratio,
        entropy=stats.width_entropy,
        one_run_longest=_longest_run(bits, "1"),
        zero_run_longest=_longest_run(bits, "0"),
    )


def _representations(
    *, compressed: bytes, uncompressed: bytes, x: int, y: int, depth: str
) -> tuple[Representation, ...]:
    """Build every textual/binary view of the key."""
    x_bytes = x.to_bytes(_HEX_WIDTH // 2, "big")
    y_bytes = y.to_bytes(_HEX_WIDTH // 2, "big")
    raw = x_bytes + y_bytes
    items: list[Representation] = [
        Representation(
            "compressed (hex)",
            "hex",
            compressed.hex(),
            len(compressed),
            "SEC 1 compressed encoding; the form used by SegWit addresses.",
        ),
        Representation(
            "compressed (hex, uppercase)",
            "hex-uppercase",
            compressed.hex().upper(),
            len(compressed),
            "Same bytes; wallets often display uppercase.",
        ),
        Representation(
            "uncompressed (hex)",
            "hex",
            uncompressed.hex(),
            len(uncompressed),
            "SEC 1 uncompressed encoding (0x04 || x || y).",
        ),
        Representation(
            "raw coordinates (hex)",
            "hex",
            raw.hex(),
            len(raw),
            "64 bytes without the SEC 1 prefix; accepted by parse_public_key_hex.",
        ),
        Representation(
            "x coordinate (hex)",
            "hex",
            x_bytes.hex(),
            len(x_bytes),
            "Affine x; identical in both SEC 1 encodings.",
        ),
        Representation(
            "y coordinate (hex)",
            "hex",
            y_bytes.hex(),
            len(y_bytes),
            "Affine y; recoverable from x and the prefix parity.",
        ),
        Representation(
            "x-only (hex)",
            "hex",
            x_bytes.hex(),
            len(x_bytes),
            "BIP-340 style x-only form; no Taproot tweak is applied here.",
        ),
        Representation(
            "compressed (binary)",
            "binary",
            "".join(f"{byte_value:08b}" for byte_value in compressed),
            len(compressed),
            "Bit string in transmission order (big-endian bytes).",
        ),
        Representation(
            "x (binary)",
            "binary",
            f"{x:0{_BITS}b}",
            len(x_bytes),
            "256-bit bit string of the x coordinate.",
        ),
        Representation(
            "x (decimal)",
            "decimal",
            str(x),
            None,
            "Decimal digits, as printed by arbitrary-precision calculators.",
        ),
        Representation(
            "y (decimal)",
            "decimal",
            str(y),
            None,
            "Decimal digits of the y coordinate.",
        ),
        Representation(
            "compressed (decimal)",
            "decimal",
            str(int.from_bytes(compressed, "big")),
            len(compressed),
            "The compressed bytes interpreted as one big integer.",
        ),
        Representation(
            "compressed (base58)",
            "base58",
            b58encode(compressed),
            len(compressed),
            "Plain Base58 (no checksum, no version byte).",
        ),
        Representation(
            "compressed (base64)",
            "base64",
            base64.b64encode(compressed).decode("ascii"),
            len(compressed),
            "RFC 4648 Base64, used by many export formats.",
        ),
        Representation(
            "compressed (hex, spaced)",
            "hex-spaced",
            " ".join(f"{byte_value:02x}" for byte_value in compressed),
            len(compressed),
            "Byte-separated form for manual transcription checks.",
        ),
        Representation(
            "x (mod n)",
            "decimal",
            str(x % CURVE_ORDER),
            None,
            "x reduced modulo the group order; shown because tools sometimes mix them up.",
        ),
    ]
    if depth == "deep":
        items.extend(
            [
                Representation(
                    "compressed (base32)",
                    "base32",
                    base64.b32encode(compressed).decode("ascii"),
                    len(compressed),
                    "RFC 4648 Base32; the alphabet Bech32 borrows from.",
                ),
                Representation(
                    "compressed (base64url)",
                    "base64url",
                    base64.urlsafe_b64encode(compressed).decode("ascii"),
                    len(compressed),
                    "URL-safe Base64 variant.",
                ),
                Representation(
                    "x (little-endian hex)",
                    "hex",
                    x_bytes[::-1].hex(),
                    len(x_bytes),
                    "x serialised least significant byte first.",
                ),
                Representation(
                    "y (little-endian hex)",
                    "hex",
                    y_bytes[::-1].hex(),
                    len(y_bytes),
                    "y serialised least significant byte first.",
                ),
                Representation(
                    "x || y (reversed hex)",
                    "hex",
                    raw[::-1].hex(),
                    len(raw),
                    "Byte-reversed key material; a common endianness mistake.",
                ),
                Representation(
                    "compressed (base58check)",
                    "base58check",
                    b58encode(compressed + double_sha256(compressed)[:4]),
                    len(compressed) + 4,
                    "Base58 with a checksum, but no version byte; diagnostic only, not an address.",
                ),
            ]
        )
    return tuple(items)


def _digests(
    compressed: bytes, uncompressed: bytes, x_only: bytes, *, depth: str
) -> tuple[tuple[str, str], ...]:
    """Return digest name/digest pairs for the key encodings."""
    items: list[tuple[str, str]] = [
        ("sha256(compressed)", sha256(compressed).hex()),
        ("sha256(uncompressed)", sha256(uncompressed).hex()),
        ("sha256(x_only)", sha256(x_only).hex()),
        ("double_sha256(compressed)", double_sha256(compressed).hex()),
        ("ripemd160(compressed)", ripemd160(compressed).hex()),
        ("hash160(compressed)", hash160(compressed).hex()),
        ("hash160(uncompressed)", hash160(uncompressed).hex()),
    ]
    if depth == "deep":
        items.extend(
            [
                ("sha512(compressed)", sha512(compressed).hex()),
                ("double_sha256(uncompressed)", double_sha256(uncompressed).hex()),
                ("ripemd160(x_only)", ripemd160(x_only).hex()),
                ("hash160(x_only)", hash160(x_only).hex()),
            ]
        )
    return tuple(items)


def _verification(
    x: int,
    y: int,
    compressed: bytes,
    uncompressed: bytes,
    addresses: tuple[AddressMatrixEntry, ...],
) -> tuple[tuple[str, bool], ...]:
    """Return the named boolean checks performed on the key."""
    lhs = (y * y) % FIELD_PRIME
    rhs = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    prefix_matches_parity = compressed[0] == (0x02 if y % 2 == 0 else 0x03)
    prefix_decodes = uncompressed[0] == 0x04 and uncompressed[1:33] == x.to_bytes(32, "big")
    mainnet = [entry for entry in addresses if entry.network == Network.MAINNET.value]
    checks = [
        ("x is inside the field range [0, p)", 0 <= x < FIELD_PRIME),
        ("y is inside the field range [0, p)", 0 <= y < FIELD_PRIME),
        ("point satisfies y^2 = x^3 + 7 (mod p)", lhs == rhs),
        ("point is not the point at infinity", (x, y) != (0, 0)),
        ("SEC 1 prefix matches y parity", prefix_matches_parity),
        ("compressed and uncompressed encodings agree", prefix_decodes),
        ("compressed length is 33 bytes", len(compressed) == COMPRESSED_PUBLIC_KEY_LENGTH),
        (
            "uncompressed length is 65 bytes",
            len(uncompressed) == UNCOMPRESSED_PUBLIC_KEY_LENGTH,
        ),
        (
            "x and y are below the group order (not required, but informative)",
            x < CURVE_ORDER and y < CURVE_ORDER,
        ),
        (
            "every mainnet address decodes back to the same payload",
            all(entry.roundtrip_ok for entry in mainnet),
        ),
    ]
    return tuple(checks)


def _address_entries(
    compressed_hex: str, uncompressed_hex: str, networks: tuple[Network, ...]
) -> tuple[AddressMatrixEntry, ...]:
    """Build the address matrix with decoder round-trip checks."""
    entries: list[AddressMatrixEntry] = []
    builders = (
        ("p2pkh", "compressed", derive_p2pkh_address, compressed_hex),
        ("p2pkh", "uncompressed", derive_p2pkh_address, uncompressed_hex),
        ("p2wpkh", "compressed", derive_p2wpkh_address, compressed_hex),
        ("p2sh-p2wpkh", "compressed", derive_p2sh_p2wpkh_address, compressed_hex),
    )
    for network in networks:
        for address_type, encoding, builder, key_hex in builders:
            info = builder(key_hex, network)
            try:
                decoded = decode_address(info.address, network)
                roundtrip_ok = decoded.payload_hex == info.hash160_hex
                roundtrip_type = decoded.address_type
            except (AddressEncodingError, BinaryCryptoLabError):  # pragma: no cover - defensive
                roundtrip_ok = False
                roundtrip_type = "undecodable"
            entries.append(
                AddressMatrixEntry(
                    network=info.network,
                    address_type=address_type,
                    key_encoding=encoding,
                    address=info.address,
                    payload_hex=info.hash160_hex,
                    witness_version=info.witness_version,
                    witness_program_hex=info.witness_program_hex,
                    script_pubkey_hex=info.script_pubkey_hex,
                    roundtrip_ok=roundtrip_ok,
                    roundtrip_type=roundtrip_type,
                )
            )
    return tuple(entries)


def _mirror_point(x: int, y: int, networks: tuple[Network, ...]) -> MirrorPoint:
    """Build the mirrored point ``(x, p - y)`` and its mainnet addresses.

    The mirrored coordinates are validated and serialised by ``cryptography``; no
    point arithmetic is implemented here beyond the modular negation.
    """
    negated_y = (-y) % FIELD_PRIME
    numbers = ec.EllipticCurvePublicNumbers(x, negated_y, ec.SECP256K1())
    key = numbers.public_key()
    compressed = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    entries: list[AddressMatrixEntry] = []
    for builder, address_type in (
        (derive_p2pkh_address, "p2pkh"),
        (derive_p2wpkh_address, "p2wpkh"),
    ):
        info = builder(compressed.hex(), Network.MAINNET)
        decoded = decode_address(info.address, Network.MAINNET)
        entries.append(
            AddressMatrixEntry(
                network=info.network,
                address_type=address_type,
                key_encoding="compressed",
                address=info.address,
                payload_hex=info.hash160_hex,
                witness_version=info.witness_version,
                witness_program_hex=info.witness_program_hex,
                script_pubkey_hex=info.script_pubkey_hex,
                roundtrip_ok=decoded.payload_hex == info.hash160_hex,
                roundtrip_type=decoded.address_type,
            )
        )
    parity = "even" if negated_y % 2 == 0 else "odd"
    note = (
        "P and -P share the same x coordinate and the same x-only serialisation; "
        "only the SEC 1 prefix (and therefore one bit of y parity) distinguishes "
        "them. Their addresses are different, so an x-only export is ambiguous."
    )
    _ = networks  # networks are reserved for future mirror matrices; mainnet is shown
    return MirrorPoint(
        x_hex=f"{x:064x}",
        y_hex=f"{negated_y:064x}",
        compressed_hex=compressed.hex(),
        y_parity=parity,
        addresses=tuple(entries),
        note=note,
    )


def _keyspace() -> tuple[tuple[str, str], ...]:
    """Return curve-size context that frames the search-cost table."""
    order_bits = CURVE_ORDER.bit_length()
    collision_exponent = 64 + 64 - order_bits  # 2^64 keys, birthday bound
    return (
        ("curve_order_hex", f"{CURVE_ORDER:064x}"),
        ("curve_order_bits", str(order_bits)),
        ("distinct_public_keys", f"2^{order_bits} (approximately)"),
        (
            "collision_exponent_at_2^64_keys",
            f"2^{collision_exponent} (birthday bound: two random keys colliding)",
        ),
        ("field_prime_hex", f"{FIELD_PRIME:064x}"),
    )


def _finding(
    code: str,
    title: str,
    evidence: str,
    probability: float,
    interpretation: str,
) -> StructureFinding:
    """Assemble a :class:`StructureFinding` with derived severity and surprisal."""
    clamped = max(_MIN_PROBABILITY, min(1.0, probability))
    surprisal = _surprisal(clamped)
    if clamped <= 2.0**-40:
        severity = "critical"
    elif clamped <= 2.0**-16:
        severity = "warning"
    else:
        severity = "info"
    return StructureFinding(
        code=code,
        title=title,
        evidence=evidence,
        probability=clamped,
        surprisal_bits=surprisal,
        severity=severity,
        interpretation=interpretation,
    )


def _coordinate_findings(profile: CoordinateProfile) -> list[StructureFinding]:
    """Structural findings that depend on a single coordinate."""
    findings: list[StructureFinding] = []
    label = profile.name
    if profile.leading_zero_bits >= 8:
        findings.append(
            _finding(
                f"{label}_leading_zero_bits",
                f"{label} starts with many zero bits",
                f"{profile.leading_zero_bits} leading zero bits ({profile.hexadecimal[:16]}...)",
                2.0**-profile.leading_zero_bits,
                "Leading zeros mean the coordinate is numerically small. That can "
                "happen by chance, but it is also what truncated, zero-padded, or "
                "hand-written test keys look like.",
            )
        )
    for limit in (192, 160, 128, 96, 64):
        if profile.bit_length <= limit:
            findings.append(
                _finding(
                    f"{label}_small_magnitude",
                    f"{label} is smaller than 2^{limit}",
                    f"bit length {profile.bit_length} <= {limit}",
                    _probability(_BITS - limit),
                    "A coordinate this small is astronomically unlikely for a key "
                    "generated by a modern random number generator. It is typical of "
                    "puzzles, teaching examples, and weak generators.",
                )
            )
            break
    if profile.trailing_zero_bits >= 8:
        findings.append(
            _finding(
                f"{label}_trailing_zero_bits",
                f"{label} ends with many zero bits",
                f"{profile.trailing_zero_bits} trailing zero bits",
                2.0**-profile.trailing_zero_bits,
                "Trailing zeros indicate the coordinate is a multiple of a power of "
                "two, which random keys almost never are.",
            )
        )
    if profile.distance_to_prime.isdigit() and int(profile.distance_to_prime) < 2**40:
        distance = int(profile.distance_to_prime)
        findings.append(
            _finding(
                f"{label}_near_field_prime",
                f"{label} is close to the field prime",
                f"p - {label} = {distance} (< 2^{max(1, distance.bit_length())})",
                _probability(max(1, distance.bit_length())),
                "Coordinates just below p are as unusual as coordinates just above "
                "zero; both suggest deliberate construction.",
            )
        )
    if profile.hamming_p_value <= 1e-3:
        direction = "few" if profile.hamming_weight < _BITS // 2 else "many"
        findings.append(
            _finding(
                f"{label}_hamming_weight",
                f"{label} has unusually {direction} set bits",
                f"{profile.hamming_weight} of 256 bits set "
                f"(two-sided binomial p = {profile.hamming_p_value:.3e})",
                profile.hamming_p_value,
                "Bit-balance anomalies are what a biased generator, a repeated byte "
                "pattern, or a hand-typed value produce.",
            )
        )
    if _is_palindrome(profile.hexadecimal):
        findings.append(
            _finding(
                f"{label}_palindrome",
                f"{label} is a hexadecimal palindrome",
                profile.hexadecimal,
                _probability(_HEX_WIDTH / 2 * 4),
                "A palindromic coordinate is a deliberate construction, not a random draw.",
            )
        )
    for period in (2, 4, 8, 16):
        if _repeated_period(profile.hexadecimal, period):
            findings.append(
                _finding(
                    f"{label}_repeated_period_{period}",
                    f"{label} repeats a {period}-digit block",
                    profile.hexadecimal,
                    _probability((_HEX_WIDTH - period) * 4),
                    "Repeated blocks indicate a formatted, padded, or hand-made "
                    "value rather than fresh randomness.",
                )
            )
            break
    for word in _KNOWN_CONSTANTS:
        if word in profile.hexadecimal:
            findings.append(
                _finding(
                    f"{label}_known_constant_{word}",
                    f"{label} contains the constant {word}",
                    f"found {word!r} in the coordinate",
                    2.0**-32,
                    "Well-known magic constants are typical of test vectors and "
                    "deliberately constructed keys.",
                )
            )
    if profile.ascii_runs:
        findings.append(
            _finding(
                f"{label}_ascii_run",
                f"{label} contains printable ASCII",
                ", ".join(repr(run) for run in profile.ascii_runs),
                3e-3,
                "Long printable runs appear occasionally in random data, so this is "
                "informational unless combined with other findings.",
            )
        )
    return findings


def _key_findings(
    x: int, y: int, compressed: bytes, nibble_frequency: tuple[tuple[str, int], ...]
) -> list[StructureFinding]:
    """Structural findings that span both coordinates or the whole key."""
    findings: list[StructureFinding] = []
    if x == y:
        findings.append(
            _finding(
                "x_equals_y",
                "x and y are identical",
                "x == y",
                _ZERO_PROBABILITY,
                "A curve point with equal coordinates is a special case that a "
                "random scalar never produces; treat suspicious keys as unsafe.",
            )
        )
    if (x + y) % FIELD_PRIME == 0 and x != 0:
        findings.append(
            _finding(
                "y_is_negation_of_x",
                "y is the additive inverse of x",
                "x + y = p (mod p)",
                _ZERO_PROBABILITY,
                "This is a deliberately constructed relationship between the coordinates.",
            )
        )
    if compressed[0] == 0x04:
        findings.append(
            _finding(
                "unprefixed_input",
                "No SEC 1 prefix was supplied",
                "the input was 64 bytes, so 0x04 was implied",
                1.0,
                "Informational: some tools export raw coordinates. Both encodings "
                "describe the same point, but always state which one you have.",
            )
        )
    top_digit, top_count = nibble_frequency[0]
    nibble_p = _binomial_two_sided_p(top_count, trials=_HEX_WIDTH, bias=1 / 16)
    if top_count >= 12:
        findings.append(
            _finding(
                "nibble_skew",
                "Hexadecimal digits are heavily skewed",
                f"digit {top_digit!r} appears {top_count} of {_HEX_WIDTH} times "
                f"(p = {nibble_p:.3e})",
                nibble_p,
                "A skew like this is normal for padded values that contain many "
                "zeros, but it is not what a uniform 256-bit key looks like.",
            )
        )
    return findings


_FAMILY_SUFFIXES: Final[tuple[tuple[tuple[str, ...], str], ...]] = (
    (
        ("small_magnitude", "leading_zero_bits", "trailing_zero_bits", "near_field_prime"),
        "magnitude",
    ),
    (("hamming_weight",), "bit-balance"),
    (("palindrome", "repeated_period", "known_constant"), "pattern"),
    (("nibble_skew",), "digit-skew"),
    (("ascii_run",), "ascii"),
    (("x_equals_y", "y_is_negation_of_x"), "relation"),
    (("unprefixed_input",), "encoding"),
)


def _evidence_family(code: str) -> str:
    """Map a finding code to its evidence family.

    Several findings can describe the same underlying fact (a coordinate of
    small magnitude also has leading zero bits, a low Hamming weight, and a
    skewed digit histogram).  Counting each one separately would multiply the
    evidence, so the score uses the strongest finding per family only.
    """
    for suffixes, family in _FAMILY_SUFFIXES:
        if code.endswith(suffixes):
            return family
    return code


def _effective_surprisal(findings: tuple[StructureFinding, ...]) -> float:
    """Return the summed surprisal of the strongest finding in each family."""
    best: dict[str, float] = {}
    for finding in findings:
        family = _evidence_family(finding.code)
        best[family] = max(best.get(family, 0.0), finding.surprisal_bits)
    return sum(best.values())


def _hypothesis_label(score: float) -> str:
    """Translate a confidence score into a verbal likelihood."""
    if score >= 0.75:
        return "likely"
    if score >= 0.5:
        return "plausible"
    if score >= 0.25:
        return "possible"
    if score >= 0.1:
        return "unlikely"
    return "very unlikely"


def _search_estimates() -> tuple[SearchEstimate, ...]:
    """Return the discrete-logarithm cost table."""
    estimates: list[SearchEstimate] = []
    hash_rate = 1e9
    ec_rate = 1e6
    for bits in (32, 64, 128, 160, 256):
        operations = 2.0**bits
        seconds = operations / hash_rate
        estimates.append(
            SearchEstimate(
                strategy="exhaustive",
                scalar_bits=bits,
                operations_log2=float(bits),
                operations=_format_count(operations),
                memory="constant",
                estimated_time=_human_duration(seconds),
                feasible_today=(
                    "trivial"
                    if bits <= 40
                    else "possible"
                    if bits <= 64
                    else "infeasible"
                    if bits <= 128
                    else "physically impossible"
                ),
                note=f"one scalar test per operation at {hash_rate:.0e} tests/s",
            )
        )
    for bits in (64, 128, 256):
        exponent = bits / 2
        operations = 2.0**exponent
        seconds = operations / ec_rate
        estimates.append(
            SearchEstimate(
                strategy="pollard-rho",
                scalar_bits=bits,
                operations_log2=exponent,
                operations=_format_count(operations),
                memory="constant (a few hundred bytes)",
                estimated_time=_human_duration(seconds),
                feasible_today=(
                    "possible"
                    if bits <= 64
                    else "infeasible"
                    if bits <= 128
                    else "physically impossible"
                ),
                note=f"about 2^(bits/2) group operations at {ec_rate:.0e} ops/s",
            )
        )
    for bits in (128, 256):
        exponent = bits / 2
        entries = 2.0**exponent
        memory_gigabytes = entries * 32 / 1e9
        estimates.append(
            SearchEstimate(
                strategy="bsgs",
                scalar_bits=bits,
                operations_log2=exponent,
                operations=_format_count(entries),
                memory=f"{memory_gigabytes:.3e} GB",
                estimated_time=_human_duration(entries / ec_rate),
                feasible_today="infeasible" if bits <= 128 else "physically impossible",
                note="baby-step/giant-step trades time for memory; still exponential",
            )
        )
    return tuple(estimates)


def _forecast(findings: tuple[StructureFinding, ...], x: int, y: int) -> Forecast:
    """Score the findings and produce the forecast."""
    total = min(256.0, _effective_surprisal(findings))
    score = min(100.0, total * 1.5625)
    critical = [finding for finding in findings if finding.severity == "critical"]
    magnitude = [
        finding
        for finding in findings
        if finding.code.endswith(("small_magnitude", "leading_zero_bits"))
    ]
    if score >= 60:
        verdict = "strongly structured: do not use this key for real funds"
    elif score >= 25:
        verdict = "moderately structured: investigate before trusting this key"
    elif score >= 8:
        verdict = "mildly structured: most likely a coincidence, but worth noting"
    else:
        verdict = "consistent with a uniformly random public key"

    if magnitude and x.bit_length() < 224:
        size_class = "reduced-magnitude coordinate"
    elif magnitude:
        size_class = "partially structured coordinate"
    else:
        size_class = "full 256-bit magnitude"

    random_score = max(0.0, 1.0 - score / 100.0)
    weak_score = min(1.0, score / 70.0)
    puzzle_score = min(1.0, (0.15 + 0.85 * score / 100.0) if magnitude else 0.05 + score / 400.0)
    corrupt_score = (
        0.2
        if any(
            finding.code.endswith(("repeated_period_2", "repeated_period_4", "palindrome"))
            for finding in findings
        )
        else 0.02
    )

    hypotheses = (
        ForecastHypothesis(
            hypothesis="Generated by a cryptographically secure RNG",
            score=round(random_score, 3),
            likelihood=_hypothesis_label(random_score),
            evidence=(f"structure score {score:.1f}/100; {len(critical)} critical finding(s)"),
            testable="Compare this key with the export from the original wallet.",
        ),
        ForecastHypothesis(
            hypothesis="Generated from a low-entropy source (weak RNG, human choice)",
            score=round(weak_score, 3),
            likelihood=_hypothesis_label(weak_score),
            evidence=", ".join(finding.code for finding in findings) or "no structural findings",
            testable="Re-derive the key with a CSPRNG and compare the generation logs.",
        ),
        ForecastHypothesis(
            hypothesis="Puzzle, teaching, or vanity key with a deliberately small scalar",
            score=round(puzzle_score, 3),
            likelihood=_hypothesis_label(puzzle_score),
            evidence=(
                "coordinates of reduced magnitude"
                if magnitude
                else "no reduced-magnitude coordinates"
            ),
            testable="Public puzzles publish their target; this tool cannot confirm it offline.",
        ),
        ForecastHypothesis(
            hypothesis="Transcription error or truncated/re-encoded copy",
            score=round(corrupt_score, 3),
            likelihood=_hypothesis_label(corrupt_score),
            evidence="repeated blocks or palindromes in a coordinate"
            if corrupt_score > 0.1
            else "no repetition or palindrome detected",
            testable="Compare all 33 or 65 bytes with a second independent export.",
        ),
    )

    recommendations: list[str] = []
    if score >= 25:
        recommendations.extend(
            [
                "Treat this key as low-entropy. If it controls funds, create a new key "
                "with a CSPRNG and move the funds.",
                "Never reuse this value in a funded wallet or a production system.",
            ]
        )
    else:
        recommendations.append(
            "No structural weakness was detected, but absence of evidence is not "
            "proof of entropy: only the generator's source of randomness can "
            "establish that."
        )
    recommendations.extend(
        [
            "Verify the key byte-for-byte against a second export before accepting a deposit.",
            "Compare the mainnet P2PKH/P2WPKH addresses in the matrix with the address "
            "you expect; a mismatch means the key or the script type is wrong.",
            "This tool does not compute private keys. The discrete logarithm problem on "
            "secp256k1 remains infeasible; treat any claim otherwise as fraud.",
        ]
    )

    limitations = (
        "Probabilities assume uniformly random 256-bit values; they are not proof "
        "about how this specific key was generated.",
        "Structural analysis cannot confirm or refute that a key corresponds to a "
        "small scalar without solving the discrete logarithm.",
        "No blockchain data is consulted: ownership, balance, and history are unknown.",
    )

    summary = (
        f"Structure score {score:.1f}/100 from {len(findings)} finding(s) "
        f"({total:.1f} bits of independent surprisal, strongest per evidence family). "
        f"{verdict}. "
        "This is a statistical reading of the public key, not key recovery."
    )

    return Forecast(
        verdict=verdict,
        size_class=size_class,
        structure_score=round(score, 3),
        total_surprisal_bits=round(total, 3),
        hypotheses=hypotheses,
        search_estimates=_search_estimates(),
        recoverable=False,
        summary=summary,
        recommendations=tuple(recommendations),
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def dissect_public_key(
    public_key_hex: str,
    *,
    networks: tuple[str | Network, ...] | None = None,
    depth: str = "standard",
) -> PublicKeyDissection:
    """Dissect a public key from every publicly available angle.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal (compressed, uncompressed,
            or 64 raw bytes).
        networks: Networks to include in the address matrix.  ``None`` uses
            mainnet, testnet, signet, and regtest.
        depth: ``"standard"`` for the core report or ``"deep"`` for the extended
            encodings, limb tables, SHA-512 digests, and bit grids.

    Returns:
        A complete :class:`PublicKeyDissection`.

    Raises:
        InvalidPublicKeyError: The input is not a valid secp256k1 public key.
        ValueError: The depth is unknown.

    Example:
        >>> dissection = dissect_public_key(
        ...     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        ... )
        >>> dissection.forecast.recoverable
        False
        >>> dissection.addresses[0].address
        '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
    """
    if depth not in DEPTH_LEVELS:
        raise ValueError("depth must be 'standard' or 'deep'")
    selected_networks = (
        ALL_NETWORKS if networks is None else tuple(Network.parse(network) for network in networks)
    )
    if not selected_networks:
        raise ValueError("at least one network is required")

    public_key = parse_public_key_hex(public_key_hex)
    info = public_key_info_from_hex(public_key_hex)
    normalized = normalize_hex(public_key_hex, allow_odd=False)
    compressed = public_key_bytes(public_key, compressed=True)
    uncompressed = public_key_bytes(public_key, compressed=False)
    x = info.x
    y = info.y
    x_bytes = x.to_bytes(32, "big")
    input_encoding = info.input_encoding
    if len(bytes.fromhex(normalized)) == 64:
        input_encoding = "raw-uncompressed"

    x_profile = _coordinate_profile("x", x, depth=depth)
    y_profile = _coordinate_profile("y", y, depth=depth)
    findings = tuple(
        sorted(
            [
                *_coordinate_findings(x_profile),
                *_coordinate_findings(y_profile),
                *_key_findings(x, y, compressed, x_profile.nibble_frequency),
            ],
            key=lambda finding: (-finding.surprisal_bits, finding.code),
        )
    )
    addresses = _address_entries(compressed.hex(), uncompressed.hex(), selected_networks)

    bit_profiles = (
        _bit_profile("compressed", compressed),
        _bit_profile("uncompressed", uncompressed),
        _bit_profile("x", x_bytes),
        _bit_profile("y", y.to_bytes(32, "big")),
        _bit_profile("hash160(compressed)", hash160(compressed)),
        _bit_profile("sha256(compressed)", sha256(compressed)),
    )

    notes = (
        "Only public data is analysed. No private key exists anywhere in this report.",
        "The address matrix is a local computation; no blockchain data was queried.",
        "Addresses for testnet, signet, and regtest are for testing only.",
        "P2WPKH and P2SH-P2WPKH require the compressed encoding; the uncompressed "
        "P2PKH row is listed to show that both encodings are valid but different.",
        "The x-only form follows BIP-340 serialisation without the Taproot tweak, so "
        "it is not a Taproot output key.",
        "Structural findings are statistical; a clean report does not prove that the "
        "key was generated securely.",
    )

    return PublicKeyDissection(
        input_hex=normalized,
        input_encoding=input_encoding,
        depth=depth,
        curve="secp256k1",
        compressed_hex=compressed.hex(),
        uncompressed_hex=uncompressed.hex(),
        x_only_hex=x_bytes.hex(),
        y_hex=y.to_bytes(32, "big").hex(),
        prefix_byte=f"0x{compressed[0]:02x}",
        y_parity="even" if y % 2 == 0 else "odd",
        coordinates=(x_profile, y_profile),
        verification=_verification(x, y, compressed, uncompressed, addresses),
        representations=_representations(
            compressed=compressed,
            uncompressed=uncompressed,
            x=x,
            y=y,
            depth=depth,
        ),
        bit_profiles=bit_profiles,
        digests=_digests(compressed, uncompressed, x_bytes, depth=depth),
        addresses=addresses,
        mirror=_mirror_point(x, y, selected_networks),
        keyspace=_keyspace(),
        findings=findings,
        forecast=_forecast(findings, x, y),
        notes=notes,
    )


def dissect_many(
    public_keys: tuple[str, ...] | list[str],
    *,
    networks: tuple[str | Network, ...] | None = None,
    depth: str = "standard",
) -> tuple[PublicKeyDissection, ...]:
    """Dissect several public keys, preserving order.

    Args:
        public_keys: Public keys in hexadecimal.
        networks: Networks for the address matrix.
        depth: ``"standard"`` or ``"deep"``.

    Returns:
        One dissection per key.

    Raises:
        InvalidPublicKeyError: Any key is invalid.  The message identifies the
            one-based position, never the key bytes.
    """
    if isinstance(public_keys, str):
        raise ValueError("public_keys must be a sequence of strings, not a single string")
    results: list[PublicKeyDissection] = []
    for index, key in enumerate(public_keys, start=1):
        try:
            results.append(dissect_public_key(key, networks=networks, depth=depth))
        except InvalidPublicKeyError as exc:
            raise InvalidPublicKeyError(f"public key #{index} is invalid: {exc}") from exc
    return tuple(results)


def address_type_names() -> tuple[str, ...]:
    """Return the address types covered by the matrix, in report order."""
    return tuple(member.value for member in AddressType)
