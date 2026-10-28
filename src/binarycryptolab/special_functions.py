"""Special mathematical functions used by the statistical analysis.

The functions here are the numeric backbone of the randomness battery and of the
forecast.  They are implemented with standard series and continued-fraction
expansions (Numerical Recipes, chapters 6 and 7) so that BinaryCryptoLab needs no
scientific-computing dependency, and every routine is unit tested against
published values.

Nothing here is cryptographic: these are classical probability functions.
"""

from __future__ import annotations

import math
from typing import Final

from .exceptions import InputValidationError

__all__ = [
    "binomial_pmf",
    "binomial_two_sided_p",
    "chi_square_sf",
    "fisher_combine",
    "log2_sum_exp",
    "normal_cdf",
    "normal_sf",
    "normal_two_sided_p",
    "regularized_gamma_p",
    "regularized_gamma_q",
]

_EPS: Final = 3.0e-16
_TINY: Final = 1.0e-300
_MAX_ITERATIONS: Final = 10_000
_FPMIN: Final = 1.0e-300


# ---------------------------------------------------------------------------
# Normal distribution
# ---------------------------------------------------------------------------


def normal_cdf(value: float) -> float:
    """Return the cumulative distribution function of the standard normal.

    Args:
        value: Standardised value.

    Returns:
        ``P(Z <= value)`` for ``Z ~ N(0, 1)``.

    Raises:
        InputValidationError: The value is not a finite number.
    """
    if not math.isfinite(value):
        raise InputValidationError("value must be a finite number")
    return 0.5 * math.erfc(-value / math.sqrt(2.0))


def normal_sf(value: float) -> float:
    """Return the survival function ``P(Z > value)`` of the standard normal."""
    if not math.isfinite(value):
        raise InputValidationError("value must be a finite number")
    return 0.5 * math.erfc(value / math.sqrt(2.0))


def normal_two_sided_p(statistic: float) -> float:
    """Return the two-sided p-value of a standard normal statistic.

    Args:
        statistic: ``z`` score.

    Returns:
        ``P(|Z| >= |statistic|)``.

    Raises:
        InputValidationError: The statistic is not finite.
    """
    return min(1.0, 2.0 * normal_sf(abs(statistic)))


# ---------------------------------------------------------------------------
# Incomplete gamma and chi-square
# ---------------------------------------------------------------------------


def _gamma_series(a: float, x: float) -> float:
    """Return ``P(a, x)`` (regularised lower incomplete gamma) by series."""
    if x <= 0.0:
        return 0.0
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(_MAX_ITERATIONS):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * _EPS:
            break
    factor = math.exp(-x + a * math.log(x) - math.lgamma(a))
    return total * factor


def _gamma_continued_fraction(a: float, x: float) -> float:
    """Return ``Q(a, x)`` (regularised upper incomplete gamma) by continued fraction."""
    b = x + 1.0 - a
    c = 1.0 / _FPMIN
    d = 1.0 / b if b != 0.0 else 1.0 / _FPMIN
    h = d
    for index in range(1, _MAX_ITERATIONS + 1):
        an = -index * (index - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = b + an / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    factor = math.exp(-x + a * math.log(x) - math.lgamma(a))
    return factor * h


def regularized_gamma_p(a: float, x: float) -> float:
    """Return the regularised lower incomplete gamma function ``P(a, x)``.

    Raises:
        InputValidationError: ``a`` or ``x`` is out of range.
    """
    if not (a > 0.0):
        raise InputValidationError("a must be positive")
    if x < 0.0:
        raise InputValidationError("x must be non-negative")
    if x == 0.0:
        return 0.0
    if x < a + 1.0:
        return _gamma_series(a, x)
    return 1.0 - _gamma_continued_fraction(a, x)


def regularized_gamma_q(a: float, x: float) -> float:
    """Return the regularised upper incomplete gamma function ``Q(a, x)``.

    Raises:
        InputValidationError: ``a`` or ``x`` is out of range.
    """
    if not (a > 0.0):
        raise InputValidationError("a must be positive")
    if x < 0.0:
        raise InputValidationError("x must be non-negative")
    if x == 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    return _gamma_continued_fraction(a, x)


def chi_square_sf(degrees_of_freedom: float, statistic: float) -> float:
    """Return the survival function of the chi-square distribution.

    Args:
        degrees_of_freedom: Positive degrees of freedom (may be fractional).
        statistic: Non-negative chi-square statistic.

    Returns:
        ``P(X >= statistic)`` for ``X ~ chi^2(degrees_of_freedom)``.

    Raises:
        InputValidationError: An argument is out of range.
    """
    if not (degrees_of_freedom > 0.0):
        raise InputValidationError("degrees_of_freedom must be positive")
    if statistic < 0.0:
        raise InputValidationError("statistic must be non-negative")
    return regularized_gamma_q(degrees_of_freedom / 2.0, statistic / 2.0)


# ---------------------------------------------------------------------------
# Binomial distribution
# ---------------------------------------------------------------------------


def binomial_pmf(observed: int, trials: int, bias: float = 0.5) -> float:
    """Return the probability mass of ``Bin(trials, bias)`` at ``observed``.

    Raises:
        InputValidationError: Arguments are out of range.
    """
    if not 0 <= observed <= trials:
        raise InputValidationError("observed must be between 0 and trials")
    if not 0.0 <= bias <= 1.0:
        raise InputValidationError("bias must be between 0 and 1")
    return math.comb(trials, observed) * (bias**observed) * ((1.0 - bias) ** (trials - observed))


def binomial_two_sided_p(observed: int, trials: int = 256, bias: float = 0.5) -> float:
    """Two-sided binomial tail probability for a count of successes.

    For ``bias = 0.5`` the result is computed exactly with integer combinatorics,
    so it stays accurate far below the double-precision range; the general case
    accumulates the probability mass directly.

    Args:
        observed: Number of successes observed.
        trials: Number of independent trials.
        bias: Probability of success under the null hypothesis.

    Returns:
        ``P(|X - trials*bias| >= |observed - trials*bias|)`` for
        ``X ~ Binomial(trials, bias)``.

    Raises:
        InputValidationError: Arguments are out of range.
    """
    if not 0 <= observed <= trials:
        raise InputValidationError("observed must be between 0 and trials")
    if not 0.0 < bias < 1.0:
        raise InputValidationError("bias must be strictly between 0 and 1")
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
    accumulated = 0.0
    for index in range(trials + 1):
        if abs(index - expected) < distance:
            continue
        accumulated += math.comb(trials, index) * (bias**index) * ((1.0 - bias) ** (trials - index))
    return min(1.0, accumulated)


# ---------------------------------------------------------------------------
# Combining evidence
# ---------------------------------------------------------------------------


def fisher_combine(p_values: tuple[float, ...] | list[float]) -> tuple[float, float, int]:
    """Combine independent p-values with Fisher's method.

    Under the null hypothesis, ``-2 * sum(ln p_i)`` follows a chi-square
    distribution with ``2k`` degrees of freedom.

    Args:
        p_values: p-values in ``(0, 1]``.

    Returns:
        ``(statistic, combined_p_value, degrees_of_freedom)``.  An empty input
        yields ``(0.0, 1.0, 0)``.

    Raises:
        InputValidationError: A p-value is outside ``(0, 1]`` or not finite.
    """
    cleaned: list[float] = []
    for value in p_values:
        number = float(value)
        if not math.isfinite(number) or not 0.0 < number <= 1.0:
            raise InputValidationError("p-values must be finite and in (0, 1]")
        cleaned.append(number)
    if not cleaned:
        return 0.0, 1.0, 0
    # Floor tiny p-values so that -2 ln p stays finite.
    statistic = -2.0 * sum(math.log(max(number, _TINY)) for number in cleaned)
    degrees = 2 * len(cleaned)
    return statistic, min(1.0, chi_square_sf(float(degrees), statistic)), degrees


def log2_sum_exp(values: tuple[float, ...] | list[float]) -> float:
    """Return ``log2(sum(2**v for v in values))`` without overflow.

    Args:
        values: Exponents in base-2 units.

    Returns:
        The base-2 logarithm of the summed weights.

    Raises:
        InputValidationError: The sequence is empty or contains a non-finite value.
    """
    if not values:
        raise InputValidationError("values must not be empty")
    if any(not math.isfinite(value) for value in values):
        raise InputValidationError("values must be finite")
    largest = max(values)
    total = sum(2.0 ** (value - largest) for value in values)
    return largest + math.log2(total)
