"""Randomness battery for fixed-size bit strings and byte sequences.

Every test returns a :class:`StatisticalTest` holding the statistic, an exact or
well-established p-value, and a plain-language explanation.  The tests are the
classical ones from NIST SP 800-22 and Knuth's *The Art of Computer Programming*,
adapted for the small samples a public key offers (256-512 bits):

===================  ======================================================
Test                 Null hypothesis
===================  ======================================================
``monobit``          ones and zeros are equally frequent
``runs``             the number of symbol changes matches a fair coin
``longest_run``      the longest run of ones is typical
``serial_correlation``adjacent bits are uncorrelated
``approximate_entropy``short patterns repeat as often as chance predicts
``nibble_uniformity``the sixteen nibble values are equally frequent
``distinct_bytes``   the number of distinct byte values matches sampling
===================  ======================================================

Two of these deserve a note:

* ``longest_run`` uses an **exact dynamic program** over all :math:`2^n` strings
  instead of the NIST lookup table, which is only calibrated for a 128-bit block.
* ``distinct_bytes`` uses the **exact occupancy distribution**, because a
  chi-square goodness-of-fit test on 256 bins with 64 observations violates the
  expected-count-of-five rule; the chi-square approximation would be meaningless.

Because several tests share the same 256-512 bits, their p-values are **not
independent**.  The report therefore shows three summaries: Fisher's combination
(which assumes independence and is therefore optimistic), a Bonferroni bound
(conservative), and the minimum p-value.  With seven tests, roughly one run in
fourteen produces a p-value below 0.01 by chance alone; a single borderline test
is not evidence of a weak key.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from typing import Any, Final

from .exceptions import InputValidationError
from .special_functions import (
    chi_square_sf,
    fisher_combine,
    normal_two_sided_p,
)

__all__ = [
    "DEFAULT_ALPHA",
    "MINIMUM_BITS",
    "P_VALUE_FLOOR",
    "RandomnessReport",
    "StatisticalTest",
    "approximate_entropy",
    "approximate_entropy_test",
    "bits_from_bytes",
    "distinct_byte_test",
    "distinct_bytes_exact_p",
    "distinct_bytes_moments",
    "distinct_bytes_p_value",
    "longest_run_length",
    "longest_run_p_value",
    "longest_run_test",
    "monobit_test",
    "nibble_uniformity_test",
    "randomness_report",
    "runs_test",
    "serial_correlation",
    "serial_correlation_test",
]

#: Family-wise significance level used to label a test as failed.
DEFAULT_ALPHA: Final = 0.01

#: Below this length the asymptotic tests are not meaningful.
MINIMUM_BITS: Final = 64

#: Floor applied before combining p-values.  Extremely structured inputs drive
#: exact tails to 0.0 by floating-point underflow (for example 512 identical
#: bits), which would make the logarithm undefined; clamping keeps the combined
#: statistic finite while remaining overwhelmingly significant.
P_VALUE_FLOOR: Final = 1e-300

_NIBBLE_BINS: Final = 16
_BYTE_BINS: Final = 256
_APPROX_ENTROPY_BLOCK: Final = 2


@dataclass(frozen=True, slots=True)
class StatisticalTest:
    """Outcome of one randomness test.

    Attributes:
        name: Stable machine-readable identifier.
        statistic: The test statistic (units depend on the test).
        p_value: Probability of a statistic at least this extreme under the null.
        passed: Whether ``p_value >= alpha``.
        detail: Human-readable summary of the statistic.
        explanation: What the test checks and how to read a failure.
    """

    name: str
    statistic: float
    p_value: float
    passed: bool
    detail: str
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "name": self.name,
            "statistic": self.statistic,
            "p_value": self.p_value,
            "passed": self.passed,
            "detail": self.detail,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def _clean_bits(bits: str) -> str:
    """Validate a bit string used by the battery.

    Raises:
        InputValidationError: The input is not a bit string or is too short.
    """
    if not isinstance(bits, str):
        raise InputValidationError("bit string must be text")
    stripped = "".join(bits.split())
    if not stripped:
        raise InputValidationError("bit string is empty")
    invalid = sorted({character for character in stripped if character not in "01"})
    if invalid:
        raise InputValidationError(f"bit string contains invalid character(s): {invalid}")
    if len(stripped) < MINIMUM_BITS:
        raise InputValidationError(
            f"at least {MINIMUM_BITS} bits are required for the randomness battery"
        )
    return stripped


def _clean_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Validate a byte sequence used by the battery."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError("data must be bytes")
    raw = bytes(data)
    if not raw:
        raise InputValidationError("data must not be empty")
    return raw


def bits_from_bytes(data: bytes | bytearray | memoryview) -> str:
    """Expand bytes into the big-endian bit string used by the battery.

    Args:
        data: Non-empty byte sequence.

    Returns:
        One ``"0"`` or ``"1"`` character per bit, most significant bit first.

    Raises:
        InputValidationError: The input is empty or is not a byte sequence.

    Example:
        >>> bits_from_bytes(b"\x00\xff")
        '0000000011111111'
    """
    return "".join(f"{byte:08b}" for byte in _clean_bytes(data))


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------


def monobit_test(bits: str) -> StatisticalTest:
    """NIST frequency (monobit) test.

    Args:
        bits: Bit string of at least :data:`MINIMUM_BITS` bits.

    Returns:
        The test outcome.  A small p-value means the ones/zeros balance is
        atypical for a fair coin.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    ones = cleaned.count("1")
    zeros = len(cleaned) - ones
    statistic = abs(ones - zeros) / math.sqrt(len(cleaned))
    p_value = math.erfc(statistic / math.sqrt(2.0))
    return StatisticalTest(
        name="monobit",
        statistic=statistic,
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=f"{ones} ones / {zeros} zeros, |S|/sqrt(n) = {statistic:.4f}",
        explanation=(
            "Checks whether ones and zeros appear equally often. A failure means "
            "the balance is unusual, which biased generators produce."
        ),
    )


def runs_test(bits: str) -> StatisticalTest:
    """Wald-Wolfowitz runs test (NIST variant).

    Counts how often the bit value changes.  Too few changes indicate clustering;
    too many indicate alternation.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    length = len(cleaned)
    ones = cleaned.count("1")
    proportion = ones / length
    changes = sum(1 for left, right in itertools.pairwise(cleaned) if left != right)
    runs = changes + 1
    if abs(proportion - 0.5) >= 2.0 / math.sqrt(length):
        # NIST: the runs test is not applicable when the monobit balance fails.
        return StatisticalTest(
            name="runs",
            statistic=float(runs),
            p_value=0.0,
            passed=False,
            detail=(
                f"{runs} runs; monobit proportion {proportion:.4f} is too far from 0.5 "
                "for the runs test to be applicable"
            ),
            explanation=(
                "Counts symbol changes. The test requires a balanced monobit result "
                "first, so it reports 0 here and the monobit failure should be read "
                "instead."
            ),
        )
    expected = 2.0 * length * proportion * (1.0 - proportion)
    variance = 2.0 * math.sqrt(2.0 * length) * proportion * (1.0 - proportion)
    statistic = abs(runs - expected) / variance if variance else 0.0
    p_value = math.erfc(statistic / math.sqrt(2.0))
    return StatisticalTest(
        name="runs",
        statistic=statistic,
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=f"{runs} runs (expected {expected:.2f}), z = {statistic:.4f}",
        explanation=(
            "Checks the oscillation rate between zeros and ones. Failures suggest "
            "clustering, alternation, or a short repeating period."
        ),
    )


def longest_run_length(bits: str) -> int:
    """Return the length of the longest run of ones.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    best = 0
    current = 0
    for character in cleaned:
        if character == "1":
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def longest_run_p_value(bits: str) -> float:
    """Return the exact tail probability of the observed longest run of ones.

    The distribution is computed by dynamic programming over all ``2**n`` bit
    strings, tracking the current run length, so the result does not rely on the
    NIST lookup tables (which assume a 128-bit block).

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    observed = longest_run_length(cleaned)
    if observed == 0:
        return 1.0
    return min(1.0, max(0.0, 1.0 - _probability_longest_run_at_most(len(cleaned), observed - 1)))


def _probability_longest_run_at_most(length: int, limit: int) -> float:
    """Return ``P(longest run of ones <= limit)`` for ``length`` fair bits."""
    if limit < 0:
        return 0.0
    if limit >= length:
        return 1.0
    # dp[r] = probability of being in state "current run of ones = r", with no
    # run having exceeded `limit` so far.
    dp = [0.0] * (limit + 2)
    dp[0] = 1.0
    for _ in range(length):
        nxt = [0.0] * (limit + 2)
        for run, probability in enumerate(dp):
            if probability == 0.0:
                continue
            nxt[0] += probability * 0.5  # next bit is 0
            if run < limit:
                nxt[run + 1] += probability * 0.5  # next bit is 1
        dp = nxt
    return min(1.0, sum(dp))


def longest_run_test(bits: str) -> StatisticalTest:
    """Exact longest-run-of-ones test.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    observed = longest_run_length(cleaned)
    p_value = longest_run_p_value(cleaned)
    return StatisticalTest(
        name="longest_run",
        statistic=float(observed),
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=f"longest run of ones = {observed} of {len(cleaned)} bits",
        explanation=(
            "A very long run of ones is rare in fair coin tosses; it appears in "
            "padded, truncated, or low-entropy material."
        ),
    )


def serial_correlation(bits: str) -> float:
    """Return the lag-1 serial correlation coefficient in ``[-1, 1]``.

    Raises:
        InputValidationError: The input is invalid or constant.
    """
    cleaned = _clean_bits(bits)
    values = [1.0 if character == "1" else 0.0 for character in cleaned]
    count = len(values)
    total = sum(values)
    numerator = count * sum(left * right for left, right in itertools.pairwise(values))
    denominator = count * sum(value * value for value in values) - total * total
    if denominator == 0.0:
        raise InputValidationError("serial correlation is undefined for a constant bit string")
    return (numerator - total * total) / denominator


def serial_correlation_test(bits: str) -> StatisticalTest:
    """Lag-1 serial correlation test with a normal approximation.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    coefficient = serial_correlation(cleaned)
    statistic = coefficient * math.sqrt(len(cleaned))
    p_value = normal_two_sided_p(statistic)
    return StatisticalTest(
        name="serial_correlation",
        statistic=coefficient,
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=f"rho = {coefficient:+.5f}, z = {statistic:+.4f}",
        explanation=(
            "Measures linear dependence between neighbouring bits. Strong "
            "correlation points at a counter, a shift register, or repeated bytes."
        ),
    )


def _phi(bits: str, block: int) -> float:
    """Return the NIST ``phi`` statistic for *block*-length patterns."""
    windows = [bits[index : index + block] for index in range(len(bits) - block + 1)]
    if not windows:
        return 0.0
    counts: dict[str, int] = {}
    for window in windows:
        counts[window] = counts.get(window, 0) + 1
    total = len(windows)
    return sum(math.log(count / total) for count in counts.values() for _ in range(count)) / total


def approximate_entropy(bits: str, block: int = _APPROX_ENTROPY_BLOCK) -> float:
    """Return the NIST approximate entropy ``ApEn(m)`` in nats.

    Raises:
        InputValidationError: The input or block size is invalid.
    """
    cleaned = _clean_bits(bits)
    if block < 1:
        raise InputValidationError("block size must be positive")
    if len(cleaned) < block + 1:
        raise InputValidationError("bit string is too short for this block size")
    return _phi(cleaned, block) - _phi(cleaned, block + 1)


def approximate_entropy_test(bits: str, block: int = _APPROX_ENTROPY_BLOCK) -> StatisticalTest:
    """NIST approximate entropy test.

    Raises:
        InputValidationError: The input is invalid.
    """
    cleaned = _clean_bits(bits)
    observed = approximate_entropy(cleaned, block)
    statistic = max(0.0, 2.0 * len(cleaned) * (math.log(2.0) - observed))
    degrees = 2**block
    p_value = chi_square_sf(float(degrees), statistic)
    return StatisticalTest(
        name="approximate_entropy",
        statistic=observed,
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=f"ApEn({block}) = {observed:.6f} nats, chi2 = {statistic:.4f} on {degrees} df",
        explanation=(
            "Compares how often short patterns repeat against the fair-coin "
            "prediction. Low values mean the material is too predictable."
        ),
    )


def nibble_uniformity_test(data: bytes | bytearray | memoryview) -> StatisticalTest:
    """Chi-square test that the sixteen nibble values are equally frequent.

    Also known as the poker test with a four-bit hand.

    Raises:
        InputValidationError: The data is invalid.
    """
    raw = _clean_bytes(data)
    digits = raw.hex()
    counts = [0] * _NIBBLE_BINS
    for character in digits:
        counts[int(character, 16)] += 1
    expected = len(digits) / _NIBBLE_BINS
    statistic = sum((count - expected) ** 2 / expected for count in counts)
    p_value = chi_square_sf(float(_NIBBLE_BINS - 1), statistic)
    return StatisticalTest(
        name="nibble_uniformity",
        statistic=statistic,
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=(f"chi2 = {statistic:.4f} on {_NIBBLE_BINS - 1} df over {len(digits)} nibbles"),
        explanation=(
            "Checks that all sixteen hexadecimal digits appear at the expected "
            "rate. A failure indicates padded, repeated, or hand-written bytes."
        ),
    )


def _stirling_second_kind(trials: int, bins: int) -> list[list[int]]:
    """Return ``S(n, k)`` for ``n <= trials`` and ``k <= bins`` as exact integers."""
    table = [[0] * (bins + 1) for _ in range(trials + 1)]
    table[0][0] = 1
    for n in range(1, trials + 1):
        for k in range(1, min(n, bins) + 1):
            table[n][k] = k * table[n - 1][k] + table[n - 1][k - 1]
    return table


def distinct_bytes_exact_p(data: bytes | bytearray | memoryview, bins: int = _BYTE_BINS) -> float:
    """Exact two-sided p-value for the number of distinct byte values.

    When ``n`` values are drawn uniformly from ``bins`` buckets, the probability of
    exactly ``k`` distinct values is

    .. math::  P(K = k) = \\binom{b}{k} k! S(n, k) / b^n

    where :math:`S(n, k)` is a Stirling number of the second kind.  The p-value is
    the total probability of all outcomes no more likely than the observed one,
    computed with exact integers before a single floating-point division.

    Raises:
        InputValidationError: The data is empty or ``bins`` is too small.
    """
    raw = _clean_bytes(data)
    if bins < 2:
        raise InputValidationError("bins must be at least 2")
    trials = len(raw)
    if trials > bins:
        raise InputValidationError(
            "the exact test requires at most one observation per bin; "
            "use distinct_bytes_p_value for longer inputs"
        )
    observed = len(set(raw))
    table = _stirling_second_kind(trials, bins)
    masses: list[tuple[int, int]] = []
    for k in range(1, min(trials, bins) + 1):
        numerator = math.comb(bins, k) * math.factorial(k) * table[trials][k]
        masses.append((k, numerator))
    denominator = bins**trials
    observed_mass = next(mass for k, mass in masses if k == observed)
    tail = sum(mass for _, mass in masses if mass <= observed_mass)
    return float(tail / denominator)


def distinct_bytes_moments(draws: int, bins: int = _BYTE_BINS) -> tuple[float, float]:
    """Return the exact mean and variance of the number of occupied bins.

    With ``draws`` values placed independently and uniformly into ``bins``
    buckets, the count of non-empty buckets :math:`K` has

    .. math:: E[K] = b\\left(1 - (1 - 1/b)^n\\right)

    and

    .. math:: \\operatorname{Var}(K) = b(b-1)\\left(1 - 2/b\\right)^n
              + b\\left(1 - 1/b\\right)^n - b^2\\left(1 - 1/b\\right)^{2n}.

    Raises:
        InputValidationError: ``draws`` or ``bins`` is out of range.
    """
    if draws < 1:
        raise InputValidationError("draws must be at least 1")
    if bins < 2:
        raise InputValidationError("bins must be at least 2")
    single = 1.0 - 1.0 / bins
    double = 1.0 - 2.0 / bins
    mean = bins * (1.0 - single**draws)
    variance = (
        bins * (bins - 1) * double**draws
        + bins * single**draws
        - bins * bins * single ** (2 * draws)
    )
    return mean, max(0.0, variance)


def distinct_bytes_p_value(
    data: bytes | bytearray | memoryview, bins: int = _BYTE_BINS
) -> tuple[float, str]:
    """Return the distinct-value p-value and the method used.

    The exact occupancy distribution is used when there are at most ``bins``
    observations, which keeps the dynamic program small.  Beyond that the exact
    table becomes expensive, so a normal approximation with the exact mean and
    variance from :func:`distinct_bytes_moments` and a continuity correction is
    used instead.

    Returns:
        ``(p_value, method)`` where ``method`` is ``"exact"`` or ``"normal"``.

    Raises:
        InputValidationError: The data is invalid.
    """
    raw = _clean_bytes(data)
    if len(raw) <= bins:
        return distinct_bytes_exact_p(raw, bins=bins), "exact"
    observed = len(set(raw))
    mean, variance = distinct_bytes_moments(len(raw), bins=bins)
    if variance <= 0.0:
        return 1.0, "normal"
    deviation = math.sqrt(variance)
    upper = float(normal_two_sided_p((observed - mean) / deviation))
    # Continuity correction on the same two-sided statistic.
    corrected = float(normal_two_sided_p((abs(observed - mean) - 0.5) / deviation))
    return min(1.0, max(upper, corrected)), "normal"


def distinct_byte_test(data: bytes | bytearray | memoryview) -> StatisticalTest:
    """Distinct-byte-value (occupancy) test.

    Raises:
        InputValidationError: The data is invalid.
    """
    raw = _clean_bytes(data)
    observed = len(set(raw))
    mean, _ = distinct_bytes_moments(len(raw))
    p_value, method = distinct_bytes_p_value(raw)
    return StatisticalTest(
        name="distinct_bytes",
        statistic=float(observed),
        p_value=p_value,
        passed=p_value >= DEFAULT_ALPHA,
        detail=(
            f"{observed} distinct byte values in {len(raw)} bytes "
            f"(expected {mean:.2f}), {method} p = {p_value:.3e}"
        ),
        explanation=(
            "Too few distinct values means repetition or padding; too many is "
            "almost impossible by chance. Up to one observation per bin the "
            "p-value is computed exactly from the occupancy distribution, because "
            "a chi-square approximation would break the expected-count rule; "
            "longer inputs use a normal approximation with exact moments."
        ),
    )


# ---------------------------------------------------------------------------
# Battery
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RandomnessReport:
    """The full randomness battery for one bit string and its byte view.

    Attributes:
        bits_used: Number of bits analysed.
        alpha: Per-test significance level.
        tests: Individual test outcomes.
        fisher_p_value: Fisher combination of the test p-values (optimistic,
            because the tests share the same input).
        bonferroni_p_value: Conservative bound ``min(1, k * min p)``.
        minimum_p_value: Smallest individual p-value.
        familywise_pass: Whether every test passes at ``alpha``.
        failed_tests: Names of the tests that failed.
        bit_entropy: Plug-in bit entropy in bits per symbol.
        bit_entropy_corrected: Miller-Madow bias-corrected estimate.
        notes: Caveats about sample size and multiple testing.
    """

    bits_used: int
    alpha: float
    tests: tuple[StatisticalTest, ...]
    fisher_p_value: float
    bonferroni_p_value: float
    minimum_p_value: float
    familywise_pass: bool
    failed_tests: tuple[str, ...]
    bit_entropy: float
    bit_entropy_corrected: float
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "bits_used": self.bits_used,
            "alpha": self.alpha,
            "tests": [test.as_dict() for test in self.tests],
            "fisher_p_value": self.fisher_p_value,
            "bonferroni_p_value": self.bonferroni_p_value,
            "minimum_p_value": self.minimum_p_value,
            "familywise_pass": self.familywise_pass,
            "failed_tests": list(self.failed_tests),
            "bit_entropy": self.bit_entropy,
            "bit_entropy_corrected": self.bit_entropy_corrected,
            "notes": list(self.notes),
        }


def _serial_correlation_or_degenerate(bits: str) -> StatisticalTest:
    """Return the serial-correlation test, or a failing placeholder.

    The coefficient is ``0/0`` for a constant bit string, so the battery must not
    raise: a constant string is the strongest possible evidence that the input is
    not random.
    """
    try:
        return serial_correlation_test(bits)
    except InputValidationError:
        return StatisticalTest(
            name="serial_correlation",
            statistic=0.0,
            p_value=P_VALUE_FLOOR,
            passed=False,
            detail="undefined: the bit string is constant, so the variance is zero",
            explanation=(
                "Measures dependence between adjacent bits. A constant string has "
                "no defined coefficient and is maximally non-random."
            ),
        )


def randomness_report(
    bits: str,
    *,
    data: bytes | None = None,
    alpha: float = DEFAULT_ALPHA,
) -> RandomnessReport:
    """Run the full battery and summarise the evidence.

    Args:
        bits: Bit string of at least :data:`MINIMUM_BITS` bits.
        data: Byte view used by the nibble and distinct-value tests.  ``None``
            decodes *bits* left-padded to a whole number of bytes.
        alpha: Per-test significance level in ``(0, 1)``.

    Returns:
        The aggregated report.

    Raises:
        InputValidationError: The input or alpha is invalid.
    """
    cleaned = _clean_bits(bits)
    if not 0.0 < alpha < 1.0:
        raise InputValidationError("alpha must be between 0 and 1")
    if data is None:
        padded = cleaned.zfill((len(cleaned) + 7) // 8 * 8)
        raw = bytes(int(padded[index : index + 8], 2) for index in range(0, len(padded), 8))
    else:
        raw = _clean_bytes(data)

    tests = (
        monobit_test(cleaned),
        runs_test(cleaned),
        longest_run_test(cleaned),
        _serial_correlation_or_degenerate(cleaned),
        approximate_entropy_test(cleaned),
        nibble_uniformity_test(raw),
        distinct_byte_test(raw),
    )
    adjusted = tuple(
        StatisticalTest(
            name=test.name,
            statistic=test.statistic,
            p_value=min(1.0, max(P_VALUE_FLOOR, test.p_value)),
            passed=test.p_value >= alpha,
            detail=test.detail,
            explanation=test.explanation,
        )
        for test in tests
    )

    p_values = [test.p_value for test in adjusted]
    _, combined, _ = fisher_combine(p_values)
    # The chi-square survival function underflows for degenerate inputs; keep the
    # reported value representable and finite.
    fisher_p = max(P_VALUE_FLOOR, combined)
    minimum = min(p_values)
    bonferroni = min(1.0, len(p_values) * minimum)
    ones = cleaned.count("1")
    proportion = ones / len(cleaned)
    if 0.0 < proportion < 1.0:
        plugin = -(
            proportion * math.log2(proportion) + (1.0 - proportion) * math.log2(1.0 - proportion)
        )
    else:  # pragma: no cover - guarded by the minimum length
        plugin = 0.0
    corrected = plugin + 1.0 / (2.0 * len(cleaned) * math.log(2.0))

    return RandomnessReport(
        bits_used=len(cleaned),
        alpha=alpha,
        tests=adjusted,
        fisher_p_value=fisher_p,
        bonferroni_p_value=bonferroni,
        minimum_p_value=minimum,
        familywise_pass=all(test.passed for test in adjusted),
        failed_tests=tuple(test.name for test in adjusted if not test.passed),
        bit_entropy=plugin,
        bit_entropy_corrected=min(1.0, corrected),
        notes=(
            f"{len(adjusted)} tests share the same {len(cleaned)} bits, so their "
            "p-values are dependent: Fisher's combination is optimistic and the "
            "Bonferroni bound is conservative.",
            "With this many tests, a p-value below 0.01 arises by chance in roughly "
            "one run in fourteen; a single borderline result is not evidence.",
            "Absence of a failed test does not prove randomness: these tests cannot "
            "detect a generator that is cryptographically weak but statistically "
            "well behaved.",
        ),
    )
