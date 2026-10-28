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

from dataclasses import dataclass
from typing import Any, Final

from .base58 import b58decode
from .bech32 import Bech32Spec, bech32_decode
from .bitcoin import (
    Network,
    decode_address,
    derive_p2pkh_address,
    derive_p2sh_p2wpkh_address,
    derive_p2wpkh_address,
    hash160_public_key,
)
from .hashing import double_sha256
from .randomness import RandomnessReport, bits_from_bytes, randomness_report
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
        verdict: Plain-language conclusion.
        note: The look-elsewhere explanation.
    """

    prefix: str
    probability: float
    naive_probability: float
    claimed_in_advance: bool
    corrected_probability: float
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
            "verdict": self.verdict,
            "note": self.note,
        }


def vanity_report(address: str, *, claimed_prefix: str | None = None) -> VanityReport:
    """Evaluate the prefix of *address* for evidence of vanity generation.

    A six-character prefix has probability around ``58^-6``, yet every address has
    one: being impressed by the prefix that happens to appear is the look-elsewhere
    fallacy. Only a prefix **declared in advance** supports a significance claim,
    which is why ``claimed_prefix`` is required for a non-trivial verdict.

    Args:
        address: A Base58Check address.
        claimed_prefix: The prefix the caller expected before seeing the address.

    Returns:
        The vanity analysis.

    Raises:
        AddressEncodingError: The address is not a valid Base58Check address.
        ValueError: The claimed prefix contains a non-Base58 character.
    """
    decoded = decode_address(address)
    if decoded.address_type not in {"p2pkh", "p2sh"}:
        raise ValueError("vanity analysis is defined for Base58Check addresses only")
    version = 0 if decoded.address_type == "p2pkh" else 5
    normalized = decoded.address.strip()
    if claimed_prefix is None:
        prefix = normalized[:6]
        probability = base58_prefix_probability(prefix, version=version)
        naive = 58.0 ** (-max(0, len(prefix) - 1))
        return VanityReport(
            prefix=prefix,
            probability=probability,
            naive_probability=naive,
            claimed_in_advance=False,
            corrected_probability=1.0,
            verdict="no significance claim: the prefix was chosen after seeing the address",
            note=(
                "Every address has a six-character prefix, so this value cannot be a "
                "p-value. Pass a prefix you declared in advance to test it properly."
            ),
        )
    prefix = claimed_prefix.strip()
    probability = base58_prefix_probability(prefix, version=version)
    naive = 58.0 ** (-max(0, len(prefix) - 1))
    matches = normalized.startswith(prefix)
    corrected = min(1.0, probability)
    if not matches:
        verdict = "the address does not start with the declared prefix"
    elif corrected < 0.01:
        verdict = (
            f"unlikely by chance: p={corrected:.3e}, so the prefix was plausibly chosen on purpose"
        )
    else:
        verdict = f"consistent with chance: p={corrected:.3f}"
    return VanityReport(
        prefix=prefix,
        probability=probability,
        naive_probability=naive,
        claimed_in_advance=True,
        corrected_probability=corrected,
        verdict=verdict,
        note=(
            "The exact count accounts for the fixed version byte and digit length; "
            "the naive 58^-k figure ignores both and is shown for comparison."
        ),
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
        total_cost_log2: Cost of the whole chain, in base-2 operations.
        verdict: Plain-language conclusion.
        caveats: Modelling notes that a careful reader needs.
    """

    steps: tuple[RecoveryStep, ...]
    total_cost_log2: float
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


def _hardness() -> HardnessReport:
    """Return the backward-chain cost report (constants only, no input needed)."""
    steps = (
        RecoveryStep(
            step="address -> version/payload/checksum",
            feasible=True,
            cost_log2=0.0,
            method="Base58Check or Bech32 decoding",
            note="Reversible by definition: the encoding is public and lossless.",
        ),
        RecoveryStep(
            step="payload -> public key",
            feasible=False,
            cost_log2=float(_HASH160_BITS),
            method="preimage of RIPEMD160(SHA256(.)) over 256-bit inputs",
            note=(
                "The best known generic preimage attack costs about 2^160. Collision "
                "attacks on RIPEMD-160 reach about 2^63, but a collision is useless "
                "here: the task is a preimage of a specific digest."
            ),
        ),
        RecoveryStep(
            step="public key -> private scalar",
            feasible=False,
            cost_log2=float(_DL_BITS),
            method="Pollard rho on the secp256k1 group",
            note=(
                "About 2^128 group operations with constant memory. No index calculus "
                "or special algorithm is known for prime-order curves."
            ),
        ),
    )
    return HardnessReport(
        steps=steps,
        total_cost_log2=float(_DL_BITS + _HASH160_BITS),
        verdict=(
            "The chain cannot be run backwards. Both backward steps are infeasible, and "
            "they must both be solved: the cheaper one alone is already about 2^128 "
            "operations."
        ),
        caveats=(
            "Costs are operation counts for the best publicly known classical "
            "algorithms, not wall-clock promises: hardware assumptions change the "
            "constant, never the exponent.",
            "Grover's algorithm lowers a 2^160 preimage search to about 2^80 quantum "
            "operations, which is still infeasible and requires a fault-tolerant "
            "machine that does not exist.",
            "Shor's algorithm would solve the discrete logarithm in polynomial time on "
            "a large fault-tolerant quantum computer. No such machine exists at the "
            "required scale, and published resource estimates remain contested. If one "
            "were built, secp256k1 would fail outright rather than degrade.",
            "RIPEMD-160 collision resistance is weaker than its preimage resistance; "
            "this asymmetry is why the second step is quoted at 2^160 and not at the "
            "collision bound.",
        ),
    )


# ---------------------------------------------------------------------------
# Dissection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AddressDissection:
    """Everything that can be established about an address without a network.

    Attributes:
        address: The canonical address string.
        encoding: ``base58check``, ``bech32``, or ``bech32m``.
        address_type: ``p2pkh``, ``p2sh``, ``p2wpkh``, ``p2wsh``, or ``witness_vN``.
        network: Inferred network.
        network_ambiguous: Whether several networks share these parameters.
        version_byte: Base58 version byte, when applicable.
        human_readable_part: Bech32 HRP, when applicable.
        payload_hex: Hash160 or witness program, in hexadecimal.
        payload_length_bytes: Payload size.
        checksum_hex: Checksum as encoded.
        recomputed_checksum_hex: Checksum recomputed from the payload.
        checksum_valid: Whether the two agree.
        script_pubkey_hex: The locking script this address pays to.
        script_asm: Human-readable locking script.
        witness_version: Witness version for SegWit addresses.
        leading_zero_bytes: Zero bytes before the payload (Base58 only).
        base58_leading_ones: Leading ``1`` characters, one per zero byte.
        payload_profile: Statistical profile of the payload.
        randomness: Battery over the payload bits.
        findings: Structural observations.
        scale: The single-scale knowledge report.
        hardness: The backward chain with costs.
        vanity: Prefix analysis.
        notes: Context for the reader.
        limitations: What the report cannot decide.
    """

    address: str
    encoding: str
    address_type: str
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
    payload_profile: PayloadProfile
    randomness: RandomnessReport
    findings: tuple[AddressFinding, ...]
    scale: AddressKnowledgeScale
    hardness: HardnessReport
    vanity: VanityReport
    notes: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def recoverable(self) -> bool:
        """Always ``False``: an address cannot yield its key."""
        return False

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "encoding": self.encoding,
            "type": self.address_type,
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
            "payload_profile": self.payload_profile.as_dict(),
            "randomness": self.randomness.as_dict(),
            "findings": [finding.as_dict() for finding in self.findings],
            "scale": self.scale.as_dict(),
            "hardness": self.hardness.as_dict(),
            "vanity": self.vanity.as_dict(),
            "recoverable": self.recoverable,
            "notes": list(self.notes),
            "limitations": list(self.limitations),
        }


def _locking_script(
    address_type: str, payload: bytes, witness_version: int | None
) -> tuple[str, str]:
    """Return ``(script_pubkey_hex, asm)`` for the decoded address."""
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
    version = 0 if witness_version is None else witness_version
    opcode = 0x00 if version == 0 else 0x50 + version
    return (
        f"{opcode:02x}{len(payload):02x}{payload.hex()}",
        f"OP_{version} {payload.hex()}",
    )


def dissect_address(address: str, *, claimed_prefix: str | None = None) -> AddressDissection:
    """Dissect an address into every public fact and every cost.

    Args:
        address: A Base58Check or SegWit address.
        claimed_prefix: A vanity prefix declared in advance, for the prefix test.

    Returns:
        The complete dissection.

    Raises:
        AddressEncodingError: The address is malformed or fails validation.
        ValueError: The claimed prefix is invalid for this address type.

    Example:
        >>> dissection = dissect_address("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb")
        >>> dissection.address_type
        'p2pkh'
        >>> dissection.recoverable
        False
        >>> dissection.checksum_valid
        True
    """
    decoded = decode_address(address)
    text = decoded.address.strip()
    lowered = text.lower()
    payload = bytes.fromhex(decoded.payload_hex)

    if lowered.startswith(("bc1", "tb1", "bcrt1")):
        _, _, spec = bech32_decode(lowered)
        encoding = "bech32" if spec is Bech32Spec.BECH32 else "bech32m"
        version_byte: int | None = None
        hrp = lowered.split("1", 1)[0]
        checksum_hex = ""
        recomputed = ""
        valid = True
        leading_zero_bytes = 0
        leading_ones = 0
    else:
        encoding = "base58check"
        raw = b58decode(text)
        version_byte = raw[0]
        hrp = None
        checksum_hex = raw[-_BASE58_CHECKSUM_BYTES:].hex()
        recomputed = double_sha256(raw[:-_BASE58_CHECKSUM_BYTES])[:_BASE58_CHECKSUM_BYTES].hex()
        valid = checksum_hex == recomputed
        leading_zero_bytes = len(raw) - len(raw.lstrip(b"\x00"))
        leading_ones = len(text) - len(text.lstrip("1"))

    script_hex, script_asm = _locking_script(decoded.address_type, payload, decoded.witness_version)
    profile = _payload_profile(
        payload, label="hash160" if len(payload) == 20 else "witness program"
    )
    battery = randomness_report(bits_from_bytes(payload), data=payload, alpha=0.01)
    findings = _payload_findings(profile)
    candidates_log2 = float(_SCALAR_BITS) - float(len(payload) * 8)
    scale = AddressKnowledgeScale(
        address_bits=len(payload) * 8,
        public_key_candidates_log2=candidates_log2,
        scalar_bits_known=0.0,
        scalar_bits_total=_SCALAR_BITS,
        note=(
            "The address fixes a 160-bit digest, which leaves about 2^96 public keys "
            "consistent with it (2^256 points, 2^160 digests). It fixes zero bits of "
            "the private scalar."
        ),
    )
    try:
        vanity = vanity_report(text, claimed_prefix=claimed_prefix)
    except ValueError:
        vanity = VanityReport(
            prefix=text[:6],
            probability=1.0,
            naive_probability=1.0,
            claimed_in_advance=False,
            corrected_probability=1.0,
            verdict="vanity analysis applies to Base58Check addresses only",
            note="SegWit prefixes are constrained by the HRP, so they are not mined.",
        )

    notes = (
        "Only public data is analysed. An address contains no key material.",
        "The checksum was recomputed independently, not just compared.",
        "The scriptPubKey shown is the one this address pays to; no chain data is read.",
        "The randomness battery tests the payload as a bit string. A hash should look "
        "random, so failures indicate padding or construction, not weakness of the key.",
    )
    limitations = (
        "An address does not reveal its public key, and the report never claims one.",
        "Ownership, balance, and history require a blockchain; this tool is offline.",
        "Structural statistics describe the payload, not the security of the generator "
        "that produced the key behind it.",
        "A clean report does not prove the address is safe to receive funds at.",
    )

    return AddressDissection(
        address=text,
        encoding=encoding,
        address_type=decoded.address_type,
        network=decoded.network,
        network_ambiguous=decoded.network_ambiguous,
        version_byte=version_byte,
        human_readable_part=hrp,
        payload_hex=decoded.payload_hex,
        payload_length_bytes=len(payload),
        checksum_hex=checksum_hex,
        recomputed_checksum_hex=recomputed,
        checksum_valid=valid,
        script_pubkey_hex=script_hex,
        script_asm=script_asm,
        witness_version=decoded.witness_version,
        leading_zero_bytes=leading_zero_bytes,
        base58_leading_ones=leading_ones,
        payload_profile=profile,
        randomness=battery,
        findings=findings,
        scale=scale,
        hardness=_hardness(),
        vanity=vanity,
        notes=notes,
        limitations=limitations,
    )


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
        derived_addresses: ``((label, address), ...)`` for every supported type.
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
    decoded = decode_address(address, selected)
    derived = (
        ("p2pkh (compressed)", derive_p2pkh_address(public_key_hex, selected).address),
        ("p2pkh (uncompressed)", _uncompressed_p2pkh(public_key_hex, selected)),
        ("p2wpkh", derive_p2wpkh_address(public_key_hex, selected).address),
        ("p2sh-p2wpkh", derive_p2sh_p2wpkh_address(public_key_hex, selected).address),
    )
    matching = tuple(label for label, value in derived if value == decoded.address)
    payload_matches = (
        hash160_public_key(public_key_hex, compressed=True).hex() == decoded.payload_hex
    )
    if matching:
        verdict = f"exact match: the supplied key derives {matching[0]}"
    elif decoded.address_type == "p2pkh" and payload_matches:
        verdict = "the compressed hash160 matches but the address was built from other bytes"
    else:
        verdict = (
            "no match: this public key does not produce the supplied address, which is "
            "expected unless the key really belongs to it"
        )
    return ControlledExperiment(
        address=decoded.address,
        public_key_hex=public_key_hex.strip(),
        derived_addresses=derived,
        matching_labels=matching,
        payload_matches=payload_matches,
        verdict=verdict,
    )


def _uncompressed_p2pkh(public_key_hex: str, network: Network) -> str:
    """Return the P2PKH address built from the uncompressed encoding."""
    from .bitcoin import p2pkh_address_from_hash160

    return p2pkh_address_from_hash160(hash160_public_key(public_key_hex, compressed=False), network)
