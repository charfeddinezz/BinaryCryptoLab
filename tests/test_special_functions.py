"""Tests for the dependency-free statistical special functions.

Every expected value is either an exact algebraic identity (symmetry, limit,
complement) or a published table value (chi-square and normal critical values),
so the tests do not simply restate the implementation.
"""

from __future__ import annotations

import math

import pytest

from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.special_functions import (
    binomial_pmf,
    binomial_two_sided_p,
    chi_square_sf,
    fisher_combine,
    log2_sum_exp,
    normal_cdf,
    normal_sf,
    normal_two_sided_p,
    regularized_gamma_p,
    regularized_gamma_q,
)

#: Published upper-tail critical values: (degrees of freedom, statistic) -> 0.05.
CHI_SQUARE_CRITICAL_VALUES = (
    (1, 3.841458820694124),
    (2, 5.991464547107979),
    (3, 7.814727903251179),
    (4, 9.487729036781154),
    (10, 18.307038053275146),
    (30, 43.772971825742186),
)


class TestNormalDistribution:
    """Normal CDF, survival function, and two-sided p-values."""

    def test_centre(self) -> None:
        assert normal_cdf(0.0) == pytest.approx(0.5)
        assert normal_sf(0.0) == pytest.approx(0.5)
        assert normal_two_sided_p(0.0) == pytest.approx(1.0)

    def test_published_critical_value(self) -> None:
        # 1.959964 is the two-sided 5% standard normal quantile.
        assert normal_two_sided_p(1.959964) == pytest.approx(0.05, abs=1e-6)
        assert normal_two_sided_p(2.575829) == pytest.approx(0.01, abs=1e-6)

    def test_symmetry_and_complement(self) -> None:
        for value in (-3.5, -1.0, -0.25, 0.0, 0.75, 2.0, 4.5):
            assert normal_cdf(value) + normal_sf(value) == pytest.approx(1.0, abs=1e-15)
            assert normal_two_sided_p(value) == pytest.approx(normal_two_sided_p(-value))

    def test_tail_monotonicity(self) -> None:
        values = [normal_sf(z) for z in (0.0, 0.5, 1.0, 2.0, 3.0)]
        assert values == sorted(values, reverse=True)
        assert all(0.0 < value <= 0.5 for value in values)

    def test_survival_stays_positive_in_the_far_tail(self) -> None:
        # A naive 1 - cdf would underflow to exactly zero here.
        assert normal_sf(37.0) > 0.0
        assert 0.0 < normal_two_sided_p(37.0) < 1e-298

    def test_extreme_values_are_finite(self) -> None:
        assert normal_cdf(-1e6) == pytest.approx(0.0)
        assert normal_sf(1e6) == pytest.approx(0.0)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_rejects_non_finite(self, value: float) -> None:
        with pytest.raises(InputValidationError):
            normal_cdf(value)
        with pytest.raises(InputValidationError):
            normal_sf(value)
        with pytest.raises(InputValidationError):
            normal_two_sided_p(value)


class TestGammaAndChiSquare:
    """Regularized incomplete gamma and its chi-square specialisation."""

    @pytest.mark.parametrize(("degrees", "statistic"), CHI_SQUARE_CRITICAL_VALUES)
    def test_chi_square_critical_values(self, degrees: int, statistic: float) -> None:
        assert chi_square_sf(float(degrees), statistic) == pytest.approx(0.05, abs=1e-9)

    def test_chi_square_limits(self) -> None:
        assert chi_square_sf(4.0, 0.0) == pytest.approx(1.0)
        assert chi_square_sf(4.0, 200.0) < 1e-40

    def test_gamma_complement(self) -> None:
        for a, x in ((0.5, 0.25), (1.0, 3.0), (2.5, 7.75), (18.0, 12.0), (40.0, 55.0)):
            assert regularized_gamma_p(a, x) + regularized_gamma_q(a, x) == pytest.approx(
                1.0, abs=1e-14
            )

    def test_gamma_exponential_case(self) -> None:
        # P(1, x) = 1 - exp(-x) is the exponential CDF.
        for x in (0.1, 1.0, 4.5):
            assert regularized_gamma_p(1.0, x) == pytest.approx(-math.expm1(-x), abs=1e-15)
            assert regularized_gamma_q(1.0, x) == pytest.approx(math.exp(-x), abs=1e-15)

    def test_gamma_half_integer_matches_erfc(self) -> None:
        # P(1/2, x) = erf(sqrt(x)), Q(1/2, x) = erfc(sqrt(x)).
        for x in (0.01, 0.5, 2.0, 9.0):
            assert regularized_gamma_q(0.5, x) == pytest.approx(math.erfc(math.sqrt(x)), abs=1e-14)

    def test_series_and_continued_fraction_agree(self) -> None:
        # a+1 ~ x is the crossover between the two expansions.
        for a, x in ((5.0, 6.0), (5.0, 4.9), (5.0, 5.1)):
            combined = regularized_gamma_p(a, x) + regularized_gamma_q(a, x)
            assert combined == pytest.approx(1.0, abs=1e-12)

    @pytest.mark.parametrize(("a", "x"), [(0.0, 1.0), (-1.0, 1.0), (1.0, -0.1)])
    def test_gamma_rejects_out_of_range(self, a: float, x: float) -> None:
        with pytest.raises(InputValidationError):
            regularized_gamma_p(a, x)
        with pytest.raises(InputValidationError):
            regularized_gamma_q(a, x)

    def test_chi_square_rejects_bad_input(self) -> None:
        with pytest.raises(InputValidationError):
            chi_square_sf(0.0, 1.0)
        with pytest.raises(InputValidationError):
            chi_square_sf(2.0, -1.0)


class TestBinomial:
    """Exact binomial mass and two-sided tails."""

    def test_mass_sums_to_one(self) -> None:
        for trials in (8, 64, 256):
            total = sum(binomial_pmf(k, trials) for k in range(trials + 1))
            assert total == pytest.approx(1.0, abs=1e-12)

    def test_mass_symmetry(self) -> None:
        assert binomial_pmf(3, 10) == pytest.approx(binomial_pmf(7, 10))
        assert binomial_pmf(0, 10, 0.25) == pytest.approx(0.75**10)

    def test_known_mass(self) -> None:
        assert binomial_pmf(5, 10, 0.5) == pytest.approx(252 / 1024)
        assert binomial_pmf(0, 4, 0.5) == pytest.approx(1 / 16)

    def test_two_sided_tail_at_the_mean_is_one(self) -> None:
        assert binomial_two_sided_p(128, trials=256) == pytest.approx(1.0)
        assert binomial_two_sided_p(4, trials=8) == pytest.approx(1.0)

    def test_two_sided_tail_is_exact_and_symmetric(self) -> None:
        # P(|X-128| >= 20) for X ~ Binomial(256, 1/2), summed exactly.
        expected = 2 * sum(math.comb(256, k) for k in range(0, 109)) / 2**256
        assert binomial_two_sided_p(108, trials=256) == pytest.approx(expected, rel=1e-12)
        assert binomial_two_sided_p(108, trials=256) == pytest.approx(
            binomial_two_sided_p(148, trials=256)
        )

    def test_fair_coin_has_no_bias(self) -> None:
        assert binomial_two_sided_p(128, trials=256) >= 0.99

    def test_extreme_counts_reach_the_floor(self) -> None:
        assert binomial_two_sided_p(0, trials=256) < 1e-70
        assert binomial_two_sided_p(256, trials=256) < 1e-70

    def test_general_bias(self) -> None:
        # Sanity: the two-sided p-value shrinks as the observed count moves away.
        near = binomial_two_sided_p(30, trials=100, bias=0.25)
        far = binomial_two_sided_p(50, trials=100, bias=0.25)
        assert 0.0 < far < near <= 1.0

    @pytest.mark.parametrize("observed", [-1, 257])
    def test_rejects_out_of_range(self, observed: int) -> None:
        with pytest.raises(InputValidationError):
            binomial_pmf(observed, 256)
        with pytest.raises(InputValidationError):
            binomial_two_sided_p(observed, trials=256)

    def test_rejects_bad_bias(self) -> None:
        with pytest.raises(InputValidationError):
            binomial_pmf(1, 4, 1.5)
        with pytest.raises(InputValidationError):
            binomial_two_sided_p(1, trials=4, bias=-0.1)


class TestFisherAndLogSumExp:
    """Combination of independent p-values and log-space arithmetic."""

    def test_uniform_p_values_do_not_produce_significance(self) -> None:
        statistic, combined, degrees = fisher_combine([0.5, 0.5])
        assert statistic == pytest.approx(4 * math.log(2.0))
        assert combined == pytest.approx(0.5966, abs=1e-4)
        assert degrees == 4

    def test_identical_small_p_values_combine(self) -> None:
        _, combined, degrees = fisher_combine([0.01] * 5)
        assert degrees == 10
        assert combined < 0.01

    def test_more_evidence_is_more_significant(self) -> None:
        _, one, _ = fisher_combine([0.01])
        _, three, _ = fisher_combine([0.01, 0.01, 0.01])
        assert three < one < 0.011

    def test_single_p_value_is_returned_unchanged(self) -> None:
        _, combined, degrees = fisher_combine([0.37])
        # Fisher with k = 1 maps p back onto itself exactly.
        assert combined == pytest.approx(0.37, abs=1e-12)
        assert degrees == 2

    def test_empty_input(self) -> None:
        assert fisher_combine([]) == (0.0, 1.0, 0)

    def test_tiny_p_values_stay_finite(self) -> None:
        _, combined, _ = fisher_combine([1e-300] * 3)
        assert 0.0 <= combined < 1e-100

    @pytest.mark.parametrize("value", [0.0, -0.5, 1.5, float("nan")])
    def test_rejects_invalid_p_values(self, value: float) -> None:
        with pytest.raises(InputValidationError):
            fisher_combine([0.5, value])

    def test_log2_sum_exp_matches_direct_sum(self) -> None:
        values = [-3.0, -3.0, -2.0]
        direct = sum(2.0**value for value in values)
        assert log2_sum_exp(values) == pytest.approx(math.log2(direct))

    def test_log2_sum_exp_handles_huge_weights(self) -> None:
        # 2**2000 would overflow a double; the shifted sum does not.
        assert log2_sum_exp([2000.0, 2000.0]) == pytest.approx(2001.0)

    def test_log2_sum_exp_single_value(self) -> None:
        assert log2_sum_exp([-7.5]) == pytest.approx(-7.5)

    def test_log2_sum_exp_rejects_bad_input(self) -> None:
        with pytest.raises(InputValidationError):
            log2_sum_exp([])
        with pytest.raises(InputValidationError):
            log2_sum_exp([float("inf")])
