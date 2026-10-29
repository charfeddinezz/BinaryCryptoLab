"""First-class dissection of Bitcoin addresses.

Why this module exists
----------------------
An address is not a public key. :func:`binarycryptolab.forensics.dissect_public_key`
correctly refuses one, but refusing is not the same as explaining. This module
takes an address as a first-class input and answers, with exact numbers:

* what the address *is*: encoding, version byte or HRP, payload, checksum,
  locking script, canonical form, and witness metadata;
* what the payload *looks like* statistically, using the same exact tests the
  public-key dissector uses (monobit, runs, longest run, serial correlation,
  approximate entropy, nibble uniformity, distinct bytes, with Fisher and
  Bonferroni combination);
* what the address tells you about the key, on the single scale of bits;
* what it would take to go backwards, with the cost of every step in the chain
  and the standard caveats (collision versus preimage resistance, Grover, Shor);
* whether a *pre-declared* vanity prefix was plausibly intentional, as opposed to
  the post-hoc fallacy of being impressed by whatever prefix happened to appear.

What it does not do
-------------------
It does not recover a public key or a private scalar from an address, and it
makes no claim about ownership, balance, or history. The backward steps are
listed with their cost precisely because they cannot be executed: the address to
public key step needs a preimage of ``RIPEMD160(SHA256(.))`` over 256-bit inputs
and the public key to scalar step needs an elliptic-curve discrete logarithm.

Relationship to the rest of the package
---------------------------------------
``address_forensics`` sits above ``bitcoin`` (decoding and derivation),
``randomness`` (the battery), and ``special_functions`` (exact tails). It is the
mirror image of ``key_reconstruction``: that module assembles a scalar when the
caller supplies enough knowledge, while this one explains an address and states
exactly why no such knowledge can be derived from it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

from .address_formats import DecodedInput, decode_address_input
from .address_safety import SafetyAudit, TaprootInfo, audit_decoded_input
from .bitcoin import (
    Network,
    derive_p2pkh_address,
    derive_p2sh_p2wpkh_address,
    derive_p2tr_address,
    derive_p2wpkh_address,
    hash160_public_key,
)
from .hd_keys import ExtendedKeyMatch, match_address, parse_extended_public_key
from .randomness import RandomnessReport, bits_from_bytes, randomness_report
from .script_templates import ScriptVerification, verify_script_claim
from .special_functions import binomial_two_sided_p
from .statistics import byte_statistics

__all__ = [
    "ADDRESS_ALPHABET",
    "AddressDissection",
    "AddressFinding",
    "AddressKnowledgeScale",
    "ControlledExperiment",
    "HardnessReport",
    "PayloadProfile",
    "RecoveryStep",
    "VanityReport",
    "base58_prefix_probability",
    "controlled_experiment",
    "dissect_address",
    "matches_public_key",
    "vanity_report",
]

#: Base58 alphabet, in value order.
ADDRESS_ALPHABET: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#: Length of a hash160 in bits; the preimage search space of the second step.
_HASH160_BITS: Final = 160
#: Size of the scalar space used by the single-scale reports.
_SCALAR_BITS: Final = 256
#: Expected Pollard-rho cost for a 256-bit curve, in group operations.
_DL_BITS: Final = 128
#: Checksum size, in bytes, appended by Base58Check.
_BASE58_CHECKSUM_BYTES: Final = 4


# ---------------------------------------------------------------------------
# Base58 prefix probabilities (exact counting, no simulations)
# ---------------------------------------------------------------------------


def _digit_value(character: str) -> int:
    """Return the Base58 digit value of a character.

    Raises:
        ValueError: The character is not in the Base58 alphabet.
    """
    index = ADDRESS_ALPHABET.find(character)
    if index < 0:
        raise ValueError(f"character {character!r} is not in the Base58 alphabet")
    return index


def _count_digits_starting_with(body: str, low: int, high: int) -> int:
    """Count integers in ``[low, high)`` whose Base58 digits start with *body*.

    For a fixed digit length ``L`` the values whose digits begin with *body* form a
    single interval, so the count is exact integer arithmetic rather than an
    estimate.
    """
    if not body:
        return high - low
    prefix_value = 0
    for character in body:
        prefix_value = prefix_value * 58 + _digit_value(character)
    length = len(body)
    total = 0
    for digits in range(max(1, length), 40):
        span = 58 ** (digits - length)
        lower = prefix_value * span
        upper = lower + span
        # Restrict to the integers that really have `digits` Base58 digits.
        lower = max(lower, 58 ** (digits - 1))
        upper = min(upper, 58**digits)
        lower = max(lower, low)
        upper = min(upper, high)
        if upper > lower:
            total += upper - lower
    return total


def base58_prefix_probability(
    prefix: str,
    *,
    version: int = 0,
    payload_length: int = 20,
) -> float:
    r"""Return the probability that a random Base58Check address starts with *prefix*.

    The model is the standard one: after the fixed version byte, the payload and
    checksum bytes are treated as uniform, so the 25-byte value is uniform on
    ``[version * 2^192, (version + 1) * 2^192)``. Under that model the probability
    is computed **exactly** by counting integers, not by the usual ``58^-k``
    approximation, which ignores the fixed version byte and the fixed digit count.

    Args:
        prefix: The address prefix, including the leading ``1`` of a mainnet P2PKH
            address when applicable.
        version: Base58 version byte (``0`` for P2PKH mainnet, ``5`` for P2SH).
        payload_length: Payload bytes before the checksum (20 for P2PKH/P2SH).

    Returns:
        A probability in ``[0, 1]``.

    Raises:
        ValueError: The prefix is empty, contains a non-Base58 character, or the
            version byte or payload length is out of range.

    Example:
        >>> 0.0 < base58_prefix_probability("1GeM") < 0.01
        True
    """
    if not isinstance(prefix, str) or not prefix:
        raise ValueError("the prefix must be a non-empty string")
    if not 0 <= version <= 255:
        raise ValueError("the version must be a byte")
    if payload_length < 1:
        raise ValueError("the payload length must be positive")
    for character in prefix:
        _digit_value(character)

    total_bytes = 1 + payload_length + _BASE58_CHECKSUM_BYTES
    body_bits = 8 * (total_bytes - 1)
    low = version << body_bits
    high = low + (1 << body_bits)
    span = high - low

    if version == 0:
        # A zero version byte produces exactly one leading '1'; the rest of the
        # string comes from the integer itself.
        if prefix[0] != "1":
            return 0.0
        count = _count_digits_starting_with(prefix[1:], low, high)
        return count / span
    count = _count_digits_starting_with(prefix, low, high)
    return count / span


@dataclass(frozen=True, slots=True)
class VanityReport:
    """Whether an address prefix looks deliberately chosen.

    Attributes:
        prefix: The prefix that was evaluated.
        probability: Exact probability that a random address starts with it.
        naive_probability: The usual ``58^-k`` approximation, for comparison.
        claimed_in_advance: Whether the caller declared the prefix before seeing
            the address. Only then is *probability* a valid p-value.
        corrected_probability: Bonferroni-corrected value over the number of
            prefix lengths examined; always ``1.0`` for a post-hoc observation
            because the search space is "any prefix at all".
        encoding: Which counting model produced the value: ``base58check``,
            ``bech32``, or ``cashaddr``.
        constrained_bits: How many payload bits the prefix fixes. The exact
            probability is ``2^-constrained_bits`` for the bit-aligned formats,
            so this number is the honest way to report a value that underflows.
        verdict: Plain-language conclusion.
        note: The look-elsewhere explanation.
    """

    prefix: str
    probability: float
    naive_probability: float
    claimed_in_advance: bool
    corrected_probability: float
    encoding: str
    constrained_bits: int
    verdict: str
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "prefix": self.prefix,
            "probability": self.probability,
            "naive_probability": self.naive_probability,
            "claimed_in_advance": self.claimed_in_advance,
            "corrected_probability": self.corrected_probability,
            "encoding": self.encoding,
            "constrained_bits": self.constrained_bits,
            "verdict": self.verdict,
            "note": self.note,
        }


_BECH32_ALPHABET: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CASHADDR_ALPHABET: Final = _BECH32_ALPHABET
_MAX_EXACT_BITS: Final = 1023


def _flatten_bits(segments: tuple[tuple[int, int], ...]) -> list[int | None]:
    """Flatten ``(value, width)`` segments into a bit list of fixed values."""
    bits: list[int | None] = []
    for value, width in segments:
        bits.extend((value >> (width - 1 - index)) & 1 for index in range(width))
    return bits


def _pad_to_groups(bits: list[int | None]) -> list[int | None]:
    """Pad a bit stream to a whole number of five-bit groups with zeros."""
    remainder = len(bits) % 5
    if remainder:
        bits.extend([0] * (5 - remainder))
    return bits


def _char_probability(bits: list[int | None], characters: str, alphabet: str) -> tuple[float, int]:
    """Return ``(probability, constrained_bits)`` for a character sequence.

    Each character fixes five bits of the stream. Bits that are already fixed by
    the version byte must agree, which is why the exact value can be far larger
    than ``alphabet^-k``.
    """
    unknown = 0
    position = 0
    for character in characters:
        index = alphabet.find(character)
        if index < 0:
            return 0.0, unknown
        for offset in range(5):
            if position >= len(bits):
                return 0.0, unknown
            expected = bits[position]
            if expected is None:
                unknown += 1
            elif expected != ((index >> (4 - offset)) & 1):
                return 0.0, unknown
            position += 1
    if unknown > _MAX_EXACT_BITS:
        return 0.0, unknown
    return 2.0**-unknown, unknown


def bech32_prefix_probability(address: str, prefix: str) -> tuple[float, int]:
    """Return the exact probability that a random SegWit address starts with *prefix*.

    The human-readable part is fixed, the witness version character is fixed, and
    every following character pins five bits of the witness program. Counting those
    bits exactly gives the true probability, which is much larger than the naive
    ``32^-k`` because the first data character is not free.

    Args:
        address: A valid Bech32 or Bech32m address, used for the HRP and version.
        prefix: The prefix to evaluate, in either case.

    Returns:
        ``(probability, constrained_bits)``.  A prefix that cannot occur returns
        ``(0.0, bits_examined)``.

    Raises:
        ValueError: The prefix is empty.
    """
    lowered_address = address.lower()
    lowered_prefix = prefix.strip().lower()
    if not lowered_prefix:
        raise ValueError("prefix must not be empty")
    separator = lowered_address.rfind("1")
    hrp = lowered_address[:separator]
    data = lowered_address[separator + 1 :]
    witness_version = _BECH32_ALPHABET.find(data[0])
    program_length = (len(data) - 1) * 5 // 8
    if witness_version < 0:
        raise ValueError("address does not carry a valid witness version")

    if len(lowered_prefix) <= len(hrp):
        if hrp.startswith(lowered_prefix):
            return 1.0, 0
        return 0.0, 0
    if not hrp.startswith(lowered_prefix[: len(hrp)]):
        return 0.0, 0
    rest = lowered_prefix[len(hrp) :]
    if not rest or rest[0] != "1":
        return 0.0, 0
    characters = rest[1:]
    if not characters:
        return 1.0, 0
    bits = _pad_to_groups(_flatten_bits(((witness_version, 5), (0, program_length * 8))))
    # The program bits are unknown: replace them after the version group.
    for index in range(5, min(len(bits), 5 + program_length * 8)):
        bits[index] = None
    return _char_probability(bits, characters, _BECH32_ALPHABET)


def cashaddr_prefix_probability(address: str, prefix: str) -> tuple[float, int]:
    """Return the exact probability that a random CashAddr starts with *prefix*.

    The eight-bit version byte is fixed, so the first one or two data characters
    are partly determined; the remaining characters pin five bits each.

    Args:
        address: A valid CashAddr address.
        prefix: The prefix to evaluate, including or excluding the ``prefix:`` part.

    Returns:
        ``(probability, constrained_bits)``.

    Raises:
        ValueError: The address has no prefix, or the prefix is empty.
    """
    lowered_address = address.strip().lower()
    lowered_prefix = prefix.strip().lower()
    if not lowered_prefix:
        raise ValueError("prefix must not be empty")
    if ":" not in lowered_address:
        raise ValueError("CashAddr addresses require an explicit prefix")
    declared, _, body = lowered_address.partition(":")

    if not lowered_prefix.startswith(declared[: len(lowered_prefix)]):
        return 0.0, 0
    if len(lowered_prefix) <= len(declared):
        return (1.0, 0) if declared.startswith(lowered_prefix) else (0.0, 0)
    remainder = lowered_prefix[len(declared) :]
    if not remainder.startswith(":"):
        return 0.0, 0
    if len(remainder) == 1:
        return 1.0, 0
    characters = remainder[1:]
    version = _CASHADDR_ALPHABET.find(body[0])
    if version < 0:
        raise ValueError("CashAddr body is malformed")
    payload_bytes = (len(body) - 8) * 5 // 8 - 1
    version_byte = int.from_bytes(
        __import__("binarycryptolab.address_formats", fromlist=["_cashaddr_bytes"])._cashaddr_bytes(
            [_CASHADDR_ALPHABET.find(character) for character in body[:-8]]
        )[:1],
        "big",
    )
    bits = _pad_to_groups(_flatten_bits(((version_byte, 8), (0, payload_bytes * 8))))
    for index in range(8, min(len(bits), 8 + payload_bytes * 8)):
        bits[index] = None
    return _char_probability(bits, characters, _CASHADDR_ALPHABET)


def vanity_report(
    address: str,
    *,
    claimed_prefix: str | None = None,
    version: int | None = None,
    payload_length: int = 20,
) -> VanityReport:
    """Evaluate the prefix of *address* for evidence of vanity generation.

    Every encoding the package accepts is measured with its own exact counting
    model, because they do not share one: Base58Check has fixed version and digit
    counts, while Bech32 and CashAddr fix their version inside the first data
    character and pin five bits per following character.

    A prefix noticed after the fact is not evidence: every address has one. Only a
    prefix **declared in advance** supports a significance claim, which is why
    ``claimed_prefix`` is required for a non-trivial verdict.

    Args:
        address: A valid address on any supported encoding.
        claimed_prefix: The prefix the caller expected before seeing the address.
        version: Version prefix to assume for Base58Check.  ``None`` uses the
            decoded value.
        payload_length: Payload size used by the Base58 counting model.

    Returns:
        The vanity analysis.

    Raises:
        ValueError: The prefix is empty or not representable in the address's
            alphabet.
    """
    decoded = decode_address_input(address)
    text = decoded.address or address.strip()

    if decoded.encoding == "base58check":
        if len(decoded.payload) != 20:
            raise ValueError("Base58 vanity analysis is defined for 20-byte payloads only")
        if version is None:
            version = decoded.version_byte if decoded.version_byte is not None else 0
        if decoded.version_byte is not None and version != decoded.version_byte:
            raise ValueError("the supplied version does not match the address")

        def measure(candidate: str) -> tuple[float, int]:
            probability = base58_prefix_probability(
                candidate, version=version, payload_length=payload_length
            )
            bits = 0 if probability <= 0.0 else max(0, math.ceil(-math.log2(probability)))
            return probability, bits

        encoding = "base58check"
        naive_base = 58.0
        free_offset = 1
        default_length = 6
    elif decoded.encoding in {"bech32", "bech32m"}:
        measure = lambda candidate: bech32_prefix_probability(text, candidate)  # noqa: E731
        encoding = decoded.encoding
        naive_base = 32.0
        free_offset = len(decoded.human_readable_part or "") + 2
        default_length = free_offset + 2
    elif decoded.encoding == "cashaddr":
        measure = lambda candidate: cashaddr_prefix_probability(text, candidate)  # noqa: E731
        encoding = "cashaddr"
        naive_base = 32.0
        free_offset = len(decoded.human_readable_part or "") + 2
        default_length = free_offset + 3
    else:
        raise ValueError(f"prefix analysis is not defined for {decoded.encoding!r} inputs")

    if claimed_prefix is None:
        prefix = text[:default_length]
        probability, bits = measure(prefix)
        naive = naive_base ** (-max(0, len(prefix) - free_offset))
        return VanityReport(
            prefix=prefix,
            probability=probability,
            naive_probability=naive,
            claimed_in_advance=False,
            corrected_probability=1.0,
            encoding=encoding,
            constrained_bits=bits,
            verdict="no significance claim: the prefix was chosen after seeing the address",
            note=(
                f"Every address has a prefix, and this one fixes {bits} bit(s) of the "
                "payload. That still cannot be a p-value, because the prefix was picked "
                "after seeing the address. Pass one you declared in advance to test it."
            ),
        )

    prefix = claimed_prefix.strip()
    if not prefix:
        raise ValueError("prefix must not be empty")
    lowered_prefix = prefix.lower() if encoding != "base58check" else prefix
    probability, bits = measure(lowered_prefix)
    naive = naive_base ** (-max(0, len(prefix) - free_offset))
    matches = (
        text.startswith(prefix)
        if encoding == "base58check"
        else text.lower().startswith(lowered_prefix)
    )
    corrected = min(1.0, probability)
    if not matches:
        verdict = "the address does not start with the declared prefix"
    elif corrected < 0.01:
        verdict = (
            f"unlikely by chance: p={corrected:.3e} ({bits} bits), so the prefix was "
            "plausibly chosen on purpose"
        )
    else:
        verdict = f"consistent with chance: p={corrected:.3f}"
    if encoding == "base58check":
        note = (
            "The exact count accounts for the fixed version byte and digit length; "
            "the naive 58^-k figure ignores both and is shown for comparison."
        )
    elif encoding == "cashaddr":
        note = (
            "The exact count accounts for the fixed 8-bit version byte, whose bits do "
            "not align with the 5-bit character groups; the naive 32^-k figure ignores "
            "that and is up to eight times smaller."
        )
    else:
        note = (
            "The exact count excludes the human-readable part, the separator, and the "
            "witness-version character, which is why it equals 32^-k here: the alphabet "
            "is exactly 2^5. Every character pins five bits of the program."
        )
    return VanityReport(
        prefix=prefix,
        probability=probability,
        naive_probability=naive,
        claimed_in_advance=True,
        corrected_probability=corrected,
        encoding=encoding,
        constrained_bits=bits,
        verdict=verdict,
        note=note,
    )


# ---------------------------------------------------------------------------
# Payload statistics
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PayloadProfile:
    """Statistical profile of an address payload (hash160 or witness program).

    Attributes:
        label: What the payload is, for example ``"hash160"``.
        hexadecimal: Lower-case hexadecimal.
        bit_length: Position of the highest set bit.
        leading_zero_bits: Zero bits before the first one.
        hamming_weight: Number of set bits.
        hamming_p_value: Exact two-sided binomial tail against ``Bin(n, 1/2)``.
        distinct_bytes: Number of distinct byte values.
        byte_entropy: Shannon entropy of the byte histogram, in bits.
        nibble_frequency: ``((digit, count), ...)`` ordered by descending count.
    """

    label: str
    hexadecimal: str
    bit_length: int
    leading_zero_bits: int
    hamming_weight: int
    hamming_p_value: float
    distinct_bytes: int
    byte_entropy: float
    nibble_frequency: tuple[tuple[str, int], ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "label": self.label,
            "hexadecimal": self.hexadecimal,
            "bit_length": self.bit_length,
            "leading_zero_bits": self.leading_zero_bits,
            "hamming_weight": self.hamming_weight,
            "hamming_p_value": self.hamming_p_value,
            "distinct_bytes": self.distinct_bytes,
            "byte_entropy": self.byte_entropy,
            "nibble_frequency": [[digit, count] for digit, count in self.nibble_frequency],
        }


def _payload_profile(payload: bytes, *, label: str) -> PayloadProfile:
    """Build a :class:`PayloadProfile` for *payload*."""
    integer = int.from_bytes(payload, "big")
    bit_length = integer.bit_length()
    ones = integer.bit_count()
    total_bits = len(payload) * 4 * 2
    histogram: dict[str, int] = {}
    for character in payload.hex():
        histogram[character] = histogram.get(character, 0) + 1
    ordered = tuple(sorted(histogram.items(), key=lambda item: (-item[1], item[0])))
    return PayloadProfile(
        label=label,
        hexadecimal=payload.hex(),
        bit_length=bit_length,
        leading_zero_bits=total_bits - bit_length,
        hamming_weight=ones,
        hamming_p_value=binomial_two_sided_p(ones, trials=total_bits),
        distinct_bytes=len(set(payload)),
        byte_entropy=byte_statistics(payload).entropy,
        nibble_frequency=ordered,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AddressFinding:
    """One structural observation about an address.

    Attributes:
        code: Stable machine-readable identifier.
        title: Short description.
        evidence: The measured value.
        probability: Probability of the pattern for a uniformly random payload.
        severity: ``info``, ``notice``, ``critical``.
        interpretation: What it would mean if real.
    """

    code: str
    title: str
    evidence: str
    probability: float
    severity: str
    interpretation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "title": self.title,
            "evidence": self.evidence,
            "probability": self.probability,
            "severity": self.severity,
            "interpretation": self.interpretation,
        }


def _payload_findings(profile: PayloadProfile) -> tuple[AddressFinding, ...]:
    """Return structural findings for a payload profile."""
    findings: list[AddressFinding] = []
    if profile.leading_zero_bits >= 8:
        findings.append(
            AddressFinding(
                code="leading_zero_bits",
                title="Payload starts with zero bits",
                evidence=f"{profile.leading_zero_bits} leading zero bits",
                probability=2.0**-profile.leading_zero_bits,
                severity="notice" if profile.leading_zero_bits < 24 else "critical",
                interpretation=(
                    "Leading zeros are what vanity generators produce, because a low "
                    "payload makes short or repeated address prefixes easier to mine."
                ),
            )
        )
    if profile.hamming_p_value < 0.01:
        findings.append(
            AddressFinding(
                code="hamming_weight",
                title="Unusual number of set bits",
                evidence=(
                    f"{profile.hamming_weight} of {len(profile.hexadecimal) * 4} bits set "
                    f"(p = {profile.hamming_p_value:.3e})"
                ),
                probability=profile.hamming_p_value,
                severity="notice",
                interpretation=(
                    "A biased generator, padding, or a hand-made value can produce a "
                    "skewed bit balance; a well-behaved hash never does."
                ),
            )
        )
    top_digit, top_count = profile.nibble_frequency[0]
    if top_count >= 12:
        findings.append(
            AddressFinding(
                code="nibble_skew",
                title="Hexadecimal digits are skewed",
                evidence=f"digit {top_digit!r} appears {top_count} times",
                probability=binomial_two_sided_p(
                    top_count, trials=len(profile.hexadecimal), bias=1 / 16
                ),
                severity="notice",
                interpretation="Typical of padded or mined payloads.",
            )
        )
    if profile.distinct_bytes == 1:
        findings.append(
            AddressFinding(
                code="constant_payload",
                title="Payload is a single repeated byte",
                evidence=f"{profile.distinct_bytes} distinct byte",
                probability=2.0**-152,
                severity="critical",
                interpretation=(
                    "A real hash160 is never constant; this would be a placeholder or a "
                    "test vector."
                ),
            )
        )
    text = profile.hexadecimal
    if len(text) > 4 and text == text[::-1]:
        findings.append(
            AddressFinding(
                code="palindromic_payload",
                title="Payload is a palindrome",
                evidence=text,
                probability=2.0 ** -(len(text) * 4 / 2),
                severity="critical",
                interpretation="A constructed value, not a hash output.",
            )
        )
    return tuple(findings)


# ---------------------------------------------------------------------------
# The single scale, and the cost of going backwards
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AddressKnowledgeScale:
    """What an address tells you, measured on one scale.

    Attributes:
        address_bits: Bits needed to specify the address payload itself.
        public_key_candidates_log2: How many public keys remain possible.
        scalar_bits_known: Bits of the private scalar that the address fixes.
        scalar_bits_total: Size of the scalar space.
        note: Why the third row is zero.
    """

    address_bits: int
    public_key_candidates_log2: float
    scalar_bits_known: float
    scalar_bits_total: int
    note: str

    @property
    def scalar_bits_unknown(self) -> float:
        """Bits of the scalar that remain unknown."""
        return float(self.scalar_bits_total) - self.scalar_bits_known

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address_bits": self.address_bits,
            "public_key_candidates_log2": self.public_key_candidates_log2,
            "scalar_bits_known": self.scalar_bits_known,
            "scalar_bits_unknown": self.scalar_bits_unknown,
            "scalar_bits_total": self.scalar_bits_total,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class RecoveryStep:
    """One step of the chain from address back to scalar.

    Attributes:
        step: What the step converts.
        feasible: Whether the step can be executed today.
        cost_log2: Base-2 logarithm of the operations needed.
        method: The algorithm and its status.
        note: Why the cost is what it is.
    """

    step: str
    feasible: bool
    cost_log2: float
    method: str
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "step": self.step,
            "feasible": self.feasible,
            "cost_log2": self.cost_log2,
            "method": self.method,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class HardnessReport:
    """The full backward chain, with costs and caveats.

    Attributes:
        steps: One :class:`RecoveryStep` per arrow, starting from the address.
        total_cost_log2: Cost of the whole chain in base-2 operations, or ``None``
            when the type admits no bound at all.
        verdict: Plain-language conclusion.
        caveats: Modelling notes that a careful reader needs.
    """

    steps: tuple[RecoveryStep, ...]
    total_cost_log2: float | None
    verdict: str
    caveats: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "steps": [step.as_dict() for step in self.steps],
            "total_cost_log2": self.total_cost_log2,
            "verdict": self.verdict,
            "caveats": list(self.caveats),
        }


_BASE_CAVEATS: Final = (
    "Costs are operation counts for the best publicly known classical algorithms, "
    "not wall-clock promises: hardware assumptions change the constant, never the "
    "exponent.",
    "Grover's algorithm lowers a 2^160 preimage search to about 2^80 quantum "
    "operations, which is still infeasible and requires a fault-tolerant machine "
    "that does not exist.",
    "Shor's algorithm would solve the discrete logarithm in polynomial time on a "
    "large fault-tolerant quantum computer. No such machine exists at the required "
    "scale, and published resource estimates remain contested. If one were built, "
    "secp256k1 would fail outright rather than degrade.",
    "RIPEMD-160 collision resistance is weaker than its preimage resistance; this "
    "asymmetry is why the hash step is quoted at 2^160 and not at the collision "
    "bound.",
)

_DECODE_STEP: Final = RecoveryStep(
    step="input -> version/payload/checksum",
    feasible=True,
    cost_log2=0.0,
    method="Base58Check, Bech32, Bech32m, or CashAddr decoding",
    note="Reversible by definition: the encoding is public and lossless.",
)


def _hash_step(bits: int, *, algorithm: str, kind: str) -> RecoveryStep:
    """Return the preimage step for a hash-committed output."""
    return RecoveryStep(
        step=f"payload -> {kind}",
        feasible=False,
        cost_log2=float(bits),
        method=f"preimage of {algorithm}",
        note=(
            "A preimage of the specific digest is required. Collision attacks are "
            "cheaper but useless here: a colliding value does not unlock this output."
        ),
    )


def _dl_step(*, exposed: bool = False) -> RecoveryStep:
    """Return the discrete-logarithm step."""
    return RecoveryStep(
        step="public key -> private scalar",
        feasible=False,
        cost_log2=float(_DL_BITS),
        method="Pollard rho on the secp256k1 group",
        note=(
            "About 2^128 group operations with constant memory. No index calculus "
            "or special algorithm is known for prime-order curves."
            if not exposed
            else "The key is already published, so no hash step stands in front of "
            "this cost; it starts immediately."
        ),
    )


def _hardness(address_type: str, payload_length: int) -> HardnessReport:
    """Return the backward-chain cost report for one output type.

    Args:
        address_type: Output type, e.g. ``p2pkh`` or ``p2tr``.
        payload_length: Payload size in bytes.

    Returns:
        The cost chain, its total, and the caveats that apply to this type.

    Raises:
        ValueError: The address type is not recognised.
    """
    caveats = _BASE_CAVEATS
    if address_type in {"p2pkh", "p2wpkh"}:
        steps = (
            _DECODE_STEP,
            _hash_step(
                _HASH160_BITS,
                algorithm="RIPEMD160(SHA256(.)) over 256-bit inputs",
                kind="public key",
            ),
            _dl_step(),
        )
        return HardnessReport(
            steps=steps,
            total_cost_log2=float(_DL_BITS + _HASH160_BITS),
            verdict=(
                "The chain cannot be run backwards. Both backward steps are infeasible, "
                "and they must both be solved: the cheaper one alone is already about "
                "2^128 operations."
            ),
            caveats=caveats,
        )
    if address_type in {"p2sh", "p2wsh"}:
        bits = _HASH160_BITS if address_type == "p2sh" else 256
        algorithm = "HASH160" if address_type == "p2sh" else "SHA256"
        steps = (
            _DECODE_STEP,
            _hash_step(bits, algorithm=f"{algorithm} over the redeem script", kind="script"),
            _dl_step(),
        )
        return HardnessReport(
            steps=steps,
            total_cost_log2=float(bits),
            verdict=(
                "The hash layer is infeasible to invert, but the practical barrier is "
                "smaller than it looks: redeem scripts come from a tiny family "
                "(multisig, HTLC, timelock), and guessing the family is far cheaper "
                "than 2^160. A script hash hides which script, not whether it is a "
                "common one."
            ),
            caveats=(
                *caveats,
                "Multisig and time-locked scripts are enumerable: an attacker "
                "guesses the template and hashes candidates, so script privacy is "
                "not 160-bit privacy.",
            ),
        )
    if address_type == "p2tr":
        steps = (
            _DECODE_STEP,
            RecoveryStep(
                step="payload -> public key",
                feasible=True,
                cost_log2=0.0,
                method="x-only key lift (BIP-340)",
                note=(
                    "The address is the output key itself, so the public key is "
                    "already known: one square root modulo the field prime."
                ),
            ),
            _dl_step(exposed=True),
        )
        return HardnessReport(
            steps=steps,
            total_cost_log2=float(_DL_BITS),
            verdict=(
                "There is no hash layer at all. A Taproot address publishes a 256-bit "
                "curve point, so the only barrier is the discrete logarithm, about "
                "2^128 classical operations."
            ),
            caveats=(
                *caveats,
                "Because the output key is public and untweaked by any hash, Taproot "
                "outputs are the first that a large fault-tolerant quantum computer "
                "would break, and key-path spends add no further protection.",
            ),
        )
    if address_type.startswith("witness_v"):
        try:
            version = int(address_type.removeprefix("witness_v"))
        except ValueError:
            version = -1
        return HardnessReport(
            steps=(
                _DECODE_STEP,
                RecoveryStep(
                    step="unknown witness version -> spending",
                    feasible=True,
                    cost_log2=0.0,
                    method="BIP-141 forward compatibility (unencumbered output)",
                    note=(
                        "Consensus defines no script for versions above the current "
                        "one, so the output is spendable by anyone who can pay the fee."
                    ),
                ),
            ),
            total_cost_log2=0.0,
            verdict=(
                f"Witness version {version} has no spending rules yet. No key is "
                "needed: the coins are claimable by any miner, so this is not "
                "'hard to break', it is already open."
            ),
            caveats=caveats,
        )
    if address_type == "p2pk":
        return HardnessReport(
            steps=(
                _DECODE_STEP,
                RecoveryStep(
                    step="script -> public key",
                    feasible=True,
                    cost_log2=0.0,
                    method="the key is written into the output",
                    note="Pay-to-public-key publishes the key on chain.",
                ),
                _dl_step(exposed=True),
            ),
            total_cost_log2=float(_DL_BITS),
            verdict=(
                "The public key is public, so only the discrete logarithm stands "
                "between an observer and the coins: about 2^128 classical operations."
            ),
            caveats=caveats,
        )
    if address_type == "op_return":
        return HardnessReport(
            steps=(_DECODE_STEP,),
            total_cost_log2=0.0,
            verdict=(
                "OP_RETURN outputs are provably unspendable by consensus. There is no "
                "chain to run backwards because there is no way forward."
            ),
            caveats=caveats,
        )
    if address_type == "unknown":
        return HardnessReport(
            steps=(
                _DECODE_STEP,
                _hash_step(
                    _HASH160_BITS,
                    algorithm="whatever hash the chain uses (unknown)",
                    kind="committed object",
                ),
                _dl_step(),
            ),
            total_cost_log2=float(_HASH160_BITS + _DL_BITS),
            verdict=(
                "The chain is not registered, so the rule behind the digest is unknown. "
                "If it is a hash of a key, the chain costs about 2^288; if it is a hash "
                "of a script, it costs about 2^160. Both are out of reach."
            ),
            caveats=_BASE_CAVEATS,
        )
    return HardnessReport(
        steps=(_DECODE_STEP,),
        total_cost_log2=None,
        verdict=(
            "The locking script does not match a recognised template, so no cost "
            "bound can be stated: spendability depends entirely on the custom script."
        ),
        caveats=caveats,
    )


def _scale(address_type: str, payload_length: int) -> AddressKnowledgeScale:
    """Return the single-scale knowledge report for one output type."""
    bits = payload_length * 8
    if address_type in {"p2pkh", "p2wpkh"}:
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=float(_SCALAR_BITS - bits),
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                f"The address fixes a {bits}-bit digest, which leaves about "
                f"2^{_SCALAR_BITS - bits} public keys consistent with it (2^256 "
                "points, 2^160 digests). It fixes zero bits of the private scalar."
            ),
        )
    if address_type == "unknown":
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=float(_SCALAR_BITS - bits),
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                "The version prefix is not registered, so the commitment rule is "
                "unknown. The payload is a 160-bit digest; whether it commits to a key, "
                "a script, or something else cannot be determined offline."
            ),
        )
    if address_type == "p2sh":
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=float(_SCALAR_BITS - bits),
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                "The address fixes a 160-bit script hash. Roughly 2^96 scripts share "
                "it, and it fixes zero bits of any private scalar; the script, not a "
                "key, is the missing object."
            ),
        )
    if address_type == "p2wsh":
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=0.0,
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                "The address fixes a 256-bit SHA256 script hash, so exactly one 32-byte "
                "preimage (modulo collisions) matches it. It fixes zero bits of any "
                "private scalar: the script is the missing object, and scripts are "
                "usually guessable."
            ),
        )
    if address_type == "p2tr":
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=0.0,
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                "The address *is* a public key: a 256-bit x-coordinate that determines "
                "the point up to its y parity. It fixes zero bits of the private "
                "scalar, but there is no hash barrier left, only the discrete logarithm."
            ),
        )
    if address_type == "p2pk":
        return AddressKnowledgeScale(
            address_bits=bits,
            public_key_candidates_log2=0.0,
            scalar_bits_known=0.0,
            scalar_bits_total=_SCALAR_BITS,
            note=(
                "The output publishes the public key itself, so it fixes all 264 bits "
                "of the point and zero bits of the private scalar."
            ),
        )
    return AddressKnowledgeScale(
        address_bits=bits,
        public_key_candidates_log2=0.0,
        scalar_bits_known=0.0,
        scalar_bits_total=_SCALAR_BITS,
        note=(
            "This output does not commit to a key at all, so the notion of candidate "
            "keys does not apply. No bits of any private scalar are fixed."
        ),
    )


# ---------------------------------------------------------------------------
# Dissection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AddressDissection:
    """Everything that can be established about an address without a network.

    Attributes:
        address: Canonical address string, or the script hex for script inputs.
        encoding: ``base58check``, ``bech32``, ``bech32m``, ``cashaddr``, or
            ``script``.
        address_type: ``p2pkh``, ``p2sh``, ``p2wpkh``, ``p2wsh``, ``p2tr``,
            ``witness_vN``, ``p2pk``, ``op_return``, or ``nonstandard``.
        chain: Best-known chain name.
        chain_candidates: Every chain consistent with the format.
        chain_ambiguous: Whether more than one chain is consistent.
        input_kind: ``address``, ``bip21_uri``, or ``script_pubkey``.
        uri_params: BIP-21 query parameters, as ordered pairs.
        network: Inferred network.
        network_ambiguous: Whether several networks share these parameters.
        version_byte: Base58 version byte, when applicable.
        human_readable_part: Bech32 HRP or CashAddr prefix, when applicable.
        payload_hex: Hash, witness program, or public key, in hexadecimal.
        payload_length_bytes: Payload size.
        checksum_hex: Checksum as encoded.
        recomputed_checksum_hex: Checksum recomputed from the payload.
        checksum_valid: Whether the two agree.
        script_pubkey_hex: The locking script this output pays to.
        script_asm: Human-readable locking script.
        witness_version: Witness version for SegWit outputs.
        leading_zero_bytes: Zero bytes before the payload (Base58 only).
        base58_leading_ones: Leading ``1`` characters, one per zero byte.
        payload_profile: Statistical profile of the payload, when there is one.
        randomness: Battery over the payload bits, when there is a payload.
        findings: Structural observations.
        scale: The single-scale knowledge report.
        hardness: The backward chain with costs.
        vanity: Prefix analysis.
        taproot: Taproot key inspection, for P2TR outputs.
        safety: The offline hazard audit.
        script_claim: Verification of a caller-supplied redeem or witness script.
        key_match: The result of searching a caller-supplied extended public key.
        notes: Context for the reader.
        limitations: What the report cannot decide.
    """

    address: str
    encoding: str
    address_type: str
    chain: str
    chain_candidates: tuple[str, ...]
    chain_ambiguous: bool
    input_kind: str
    uri_params: tuple[tuple[str, str], ...]
    network: str
    network_ambiguous: bool
    version_byte: int | None
    human_readable_part: str | None
    payload_hex: str
    payload_length_bytes: int
    checksum_hex: str
    recomputed_checksum_hex: str
    checksum_valid: bool
    script_pubkey_hex: str
    script_asm: str
    witness_version: int | None
    leading_zero_bytes: int
    base58_leading_ones: int
    payload_profile: PayloadProfile | None
    randomness: RandomnessReport | None
    findings: tuple[AddressFinding, ...]
    scale: AddressKnowledgeScale
    hardness: HardnessReport
    vanity: VanityReport
    taproot: TaprootInfo | None
    safety: SafetyAudit
    notes: tuple[str, ...]
    limitations: tuple[str, ...]
    script_claim: ScriptVerification | None = None
    key_match: ExtendedKeyMatch | None = None

    @property
    def recoverable(self) -> bool:
        """Always ``False``: an address cannot yield its key."""
        return False

    @property
    def plan(self) -> Any:
        """Return the investigation plan for this dissection.

        The import is local so that ``investigation`` can depend on this module
        without a cycle at import time.
        """
        from .investigation import build_plan

        return build_plan(self)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "encoding": self.encoding,
            "type": self.address_type,
            "chain": self.chain,
            "chain_candidates": list(self.chain_candidates),
            "chain_ambiguous": self.chain_ambiguous,
            "input_kind": self.input_kind,
            "uri_params": [{"name": name, "value": value} for name, value in self.uri_params],
            "network": self.network,
            "network_ambiguous": self.network_ambiguous,
            "version_byte": self.version_byte,
            "human_readable_part": self.human_readable_part,
            "payload_hex": self.payload_hex,
            "payload_length_bytes": self.payload_length_bytes,
            "checksum_hex": self.checksum_hex,
            "recomputed_checksum_hex": self.recomputed_checksum_hex,
            "checksum_valid": self.checksum_valid,
            "script_pubkey_hex": self.script_pubkey_hex,
            "script_asm": self.script_asm,
            "witness_version": self.witness_version,
            "leading_zero_bytes": self.leading_zero_bytes,
            "base58_leading_ones": self.base58_leading_ones,
            "payload_profile": (
                None if self.payload_profile is None else self.payload_profile.as_dict()
            ),
            "randomness": None if self.randomness is None else self.randomness.as_dict(),
            "findings": [finding.as_dict() for finding in self.findings],
            "scale": self.scale.as_dict(),
            "hardness": self.hardness.as_dict(),
            "vanity": self.vanity.as_dict(),
            "taproot": None if self.taproot is None else self.taproot.as_dict(),
            "safety": self.safety.as_dict(),
            "script_claim": None if self.script_claim is None else self.script_claim.as_dict(),
            "key_match": None if self.key_match is None else self.key_match.as_dict(),
            "recoverable": self.recoverable,
            "plan": self.plan.as_dict(),
            "notes": list(self.notes),
            "limitations": list(self.limitations),
        }


def _locking_script(
    address_type: str, payload: bytes, witness_version: int | None
) -> tuple[str, str]:
    """Return ``(script_pubkey_hex, asm)`` for the decoded output.

    Raises:
        ValueError: The output type is not recognised.
    """
    if address_type == "p2pkh":
        return (
            f"76a914{payload.hex()}88ac",
            f"OP_DUP OP_HASH160 {payload.hex()} OP_EQUALVERIFY OP_CHECKSIG",
        )
    if address_type == "p2sh":
        return (f"a914{payload.hex()}87", f"OP_HASH160 {payload.hex()} OP_EQUAL")
    if address_type == "p2wpkh":
        return (f"0014{payload.hex()}", f"OP_0 {payload.hex()}")
    if address_type == "p2wsh":
        return (f"0020{payload.hex()}", f"OP_0 {payload.hex()}")
    if address_type == "p2tr":
        return (f"5120{payload.hex()}", f"OP_1 {payload.hex()}")
    if address_type == "p2pk":
        return (f"{len(payload):02x}{payload.hex()}ac", f"{payload.hex()} OP_CHECKSIG")
    if address_type == "op_return":
        return ("6a", "OP_RETURN")
    if address_type == "unknown":
        return ("", "unknown: the version prefix is not registered")
    if address_type == "nonstandard":
        return ("", "unrecognised locking script")
    if address_type.startswith("witness_v"):
        version = (
            witness_version
            if witness_version is not None
            else int(address_type.removeprefix("witness_v"))
        )
        opcode = 0x00 if version == 0 else 0x50 + version
        return (
            f"{opcode:02x}{len(payload):02x}{payload.hex()}",
            f"OP_{version} {payload.hex()}",
        )
    raise ValueError(f"unsupported output type {address_type!r}")


def dissect_address(
    address: str,
    *,
    claimed_prefix: str | None = None,
    network: str | Network | None = None,
    redeem_script: str | None = None,
    xpub: str | None = None,
    xpub_range: tuple[int, int] = (0, 20),
) -> AddressDissection:
    """Dissect an address, BIP-21 URI, or locking script into public facts.

    Args:
        address: An address on any registered format, a payment URI, or a raw
            ``scriptPubKey`` in hexadecimal.
        claimed_prefix: A vanity prefix declared in advance, for the prefix test.
        network: Expected network.  When given, a mismatch is an error.
        redeem_script: A candidate redeem or witness script.  When given, the tool
            checks whether the address actually commits to it and classifies it.
        xpub: An extended public key.  When given, the tool derives addresses from
            public data only and searches ``xpub_range`` for a match.
        xpub_range: ``(start, count)`` for the extended-key search.

    Returns:
        The complete dissection.

    Raises:
        AddressEncodingError: The input is malformed or fails validation.
        InputValidationError: The input is empty or looks like private key
            material, in which case it is refused without being repeated.
        ValueError: The claimed prefix is invalid for this input.

    Example:
        >>> dissection = dissect_address("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb")
        >>> dissection.address_type
        'p2pkh'
        >>> dissection.recoverable
        False
        >>> dissection.checksum_valid
        True
    """
    decoded = decode_address_input(address, network=network)
    payload = decoded.payload
    kind = decoded.address_type
    script_hex, script_asm = _locking_script(kind, payload, decoded.witness_version)
    if decoded.input_kind == "script_pubkey":
        cleaned = decoded.original.strip().lower()
        script_hex = cleaned.removeprefix("0x")

    profile = None
    battery = None
    findings: tuple[AddressFinding, ...] = ()
    if payload:
        profile = _payload_profile(payload, label=_payload_label(kind, len(payload)))
        battery = randomness_report(bits_from_bytes(payload), data=payload, alpha=0.01)
        findings = _payload_findings(profile)

    try:
        if decoded.address is None:
            raise ValueError("script inputs have no address prefix")
        vanity = vanity_report(
            decoded.address,
            claimed_prefix=claimed_prefix,
            version=decoded.version_byte,
            payload_length=len(payload) or 20,
        )
    except ValueError:
        vanity = VanityReport(
            prefix=(decoded.address or decoded.original)[:6],
            probability=1.0,
            naive_probability=1.0,
            claimed_in_advance=False,
            corrected_probability=1.0,
            encoding=decoded.encoding,
            constrained_bits=0,
            verdict="vanity analysis applies to Base58Check addresses only",
            note="SegWit and CashAddr prefixes are constrained by their prefix rules, "
            "so they are not mined.",
        )

    safety = audit_decoded_input(decoded, declared_prefix=claimed_prefix)
    script_claim = (
        None
        if redeem_script is None
        else verify_script_claim(decoded.address or address, redeem_script)
    )
    key_match = (
        None
        if xpub is None
        else match_address(
            parse_extended_public_key(xpub),
            decoded.address or address,
            start=xpub_range[0],
            count=xpub_range[1],
        )
    )
    scale = _scale(kind, len(payload))
    hardness = _hardness(kind, len(payload))

    notes = [
        "Only public data is analysed. No key material is present in an address.",
        "The checksum was recomputed independently, not just compared.",
        "The scriptPubKey shown is the one this output pays to; no chain data is read.",
        "The randomness battery tests the payload as a bit string. A hash should look "
        "random, so failures indicate padding or construction, not weakness of the key.",
    ]
    if decoded.uri_params:
        notes.append(
            "The input was a BIP-21 payment URI; its query parameters are reported "
            "verbatim and validated, never resolved."
        )
    if decoded.input_kind == "script_pubkey":
        notes.append("The input was a raw locking script; the address shown was derived from it.")
    if decoded.notes:
        notes.extend(decoded.notes)
    if script_claim is not None:
        notes.append(
            "The redeem script was supplied by the caller and verified against the "
            "address payload; it is not fetched, guessed, or derived."
        )
    if key_match is not None:
        notes.append(
            "Extended-key matching uses public derivation only: no private key is "
            "used, accepted, or derived, and hardened indices are impossible."
        )
    if decoded.chain != "bitcoin":
        notes.append(
            f"The format is registered on {decoded.chain}; version prefixes are "
            "conventions, so cross-chain identity is advisory."
        )

    limitations = (
        "An address does not reveal its public key, and the report never claims one.",
        "Ownership, balance, and history require chain data; audit-address-data can "
        "read a file you supply yourself, but this command reads nothing.",
        "Structural statistics describe the payload, not the security of the generator "
        "that produced the key behind it.",
        "A clean report does not prove the output is safe to receive funds at.",
    )

    return AddressDissection(
        address=decoded.address or decoded.original,
        encoding=decoded.encoding,
        address_type=kind,
        chain=decoded.chain,
        chain_candidates=decoded.chain_candidates,
        chain_ambiguous=len(decoded.chain_candidates) > 1,
        input_kind=decoded.input_kind,
        uri_params=decoded.uri_params,
        network=decoded.network,
        network_ambiguous=decoded.network_ambiguous,
        version_byte=decoded.version_byte,
        human_readable_part=decoded.human_readable_part,
        payload_hex=payload.hex(),
        payload_length_bytes=len(payload),
        checksum_hex=decoded.checksum_hex,
        recomputed_checksum_hex=decoded.recomputed_checksum_hex,
        checksum_valid=decoded.checksum_valid,
        script_pubkey_hex=script_hex,
        script_asm=script_asm,
        witness_version=decoded.witness_version,
        leading_zero_bytes=decoded.leading_zero_bytes,
        base58_leading_ones=decoded.base58_leading_ones,
        payload_profile=profile,
        randomness=battery,
        findings=findings,
        scale=scale,
        hardness=hardness,
        vanity=vanity,
        taproot=safety.taproot,
        safety=safety,
        notes=tuple(notes),
        limitations=limitations,
        script_claim=script_claim,
        key_match=key_match,
    )


def _payload_label(kind: str, length: int) -> str:
    """Return a human label for the payload of *kind*."""
    if kind in {"p2pkh", "p2wpkh", "p2sh"}:
        return "hash160"
    if kind == "p2wsh":
        return "sha256 script hash"
    if kind == "p2tr":
        return "x-only output key"
    if kind == "p2pk":
        return "public key"
    return f"witness program ({length} bytes)"


# ---------------------------------------------------------------------------
# Controlled experiments with the caller's own keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ControlledExperiment:
    """A comparison between an address and a public key the caller supplies.

    This is the only way public-key data and an address can be related: the caller
    provides a public key they own, the tool derives its addresses, and the
    comparison is exact. Nothing is inferred from the address alone.

    Attributes:
        address: The target address.
        public_key_hex: The supplied public key (public data, safe to print).
        derived_addresses: ``((label, address), ...)`` for P2PKH (compressed and
            uncompressed), P2WPKH, P2SH-P2WPKH, and Taproot key path.
        matching_labels: Which derivations reproduce the target exactly.
        payload_matches: Whether the hash160 of the compressed key equals the payload.
        verdict: Plain-language conclusion.
    """

    address: str
    public_key_hex: str
    derived_addresses: tuple[tuple[str, str], ...]
    matching_labels: tuple[str, ...]
    payload_matches: bool
    verdict: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "public_key": self.public_key_hex,
            "derived_addresses": [[label, value] for label, value in self.derived_addresses],
            "matching_labels": list(self.matching_labels),
            "payload_matches": self.payload_matches,
            "verdict": self.verdict,
        }


def matches_public_key(
    address: str, public_key_hex: str, *, network: str | Network = "mainnet"
) -> bool:
    """Return whether *public_key_hex* derives *address* exactly.

    Args:
        address: The address to test.
        public_key_hex: A SEC 1 public key the caller owns.
        network: Network to derive on.

    Returns:
        ``True`` when any supported derivation reproduces the address byte for byte.

    Raises:
        AddressEncodingError: The address is invalid.
        InvalidPublicKeyError: The public key is invalid.
    """
    return bool(controlled_experiment(address, public_key_hex, network=network).matching_labels)


def controlled_experiment(
    address: str,
    public_key_hex: str,
    *,
    network: str | Network = "mainnet",
) -> ControlledExperiment:
    """Derive every address type from a supplied key and compare with *address*.

    Args:
        address: The target address.
        public_key_hex: A SEC 1 public key.
        network: Network for derivation.

    Returns:
        The comparison.

    Raises:
        AddressEncodingError: The address is invalid.
        InvalidPublicKeyError: The public key is invalid or not on the curve.
    """
    selected = Network.parse(network)
    decoded = decode_address_input(address, network=selected)
    target = decoded.address or ""
    derived = (
        ("p2pkh (compressed)", derive_p2pkh_address(public_key_hex, selected).address),
        ("p2pkh (uncompressed)", _uncompressed_p2pkh(public_key_hex, selected)),
        ("p2wpkh", derive_p2wpkh_address(public_key_hex, selected).address),
        ("p2sh-p2wpkh", derive_p2sh_p2wpkh_address(public_key_hex, selected).address),
        ("p2tr (BIP-341 key path)", derive_p2tr_address(public_key_hex, selected).address),
    )
    matching = tuple(label for label, value in derived if value == target)
    payload_matches = hash160_public_key(public_key_hex, compressed=True) == decoded.payload
    if matching:
        verdict = f"exact match: the supplied key derives {matching[0]}"
    elif decoded.address_type == "p2tr" and _taproot_script_path_note(decoded) and payload_matches:
        verdict = (
            "the key matches the payload but the address is a Taproot output, which is "
            "tweaked; a script-path commitment changes the output key"
        )
    elif decoded.address_type == "p2pkh" and payload_matches:
        verdict = "the compressed hash160 matches but the address was built from other bytes"
    else:
        verdict = (
            "no match: this public key does not produce the supplied address, which is "
            "expected unless the key really belongs to it"
        )
    return ControlledExperiment(
        address=target,
        public_key_hex=public_key_hex.strip(),
        derived_addresses=derived,
        matching_labels=matching,
        payload_matches=payload_matches,
        verdict=verdict,
    )


def _taproot_script_path_note(decoded: DecodedInput) -> bool:
    """Return whether a Taproot target could carry a script-path commitment."""
    return decoded.address_type == "p2tr" and len(decoded.payload) == 32


def _uncompressed_p2pkh(public_key_hex: str, network: Network) -> str:
    """Return the P2PKH address built from the uncompressed encoding."""
    from .bitcoin import p2pkh_address_from_hash160

    return p2pkh_address_from_hash160(hash160_public_key(public_key_hex, compressed=False), network)
