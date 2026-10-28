"""Tests for the randomness battery.

The fixtures are deterministic bit strings and byte sequences with known
statistical behaviour: a repeated pattern, a balanced alternating string, and
byte data with a planted bias.  Values that depend on published theory (the
runs-test expectation, the distinct-values occupancy distribution) are checked
against independently computed references.
"""

from __future__ import annotations

import itertools
import math
import random

import pytest

from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.randomness import (
    MINIMUM_BITS,
    P_VALUE_FLOOR,
    approximate_entropy,
    approximate_entropy_test,
    bits_from_bytes,
    distinct_byte_test,
    distinct_bytes_exact_p,
    longest_run_length,
    longest_run_p_value,
    longest_run_test,
    monobit_test,
    nibble_uniformity_test,
    randomness_report,
    runs_test,
    serial_correlation,
    serial_correlation_test,
)


def _balanced_bits(length: int) -> str:
    """Return a bit string with an exact 50/50 balance and no long runs."""
    pattern = "0011"
    return (pattern * (length // 4 + 1))[:length]


def _rng_bits(length: int, seed: int = 20240501) -> str:
    """Return reproducible pseudo-random bits."""
    generator = random.Random(seed)
    return "".join(generator.choice("01") for _ in range(length))


class TestBitsFromBytes:
    """Byte-to-bit expansion."""

    def test_known_expansion(self) -> None:
        assert bits_from_bytes(b"\x00\xff") == "0000000011111111"
        assert bits_from_bytes(b"\x01") == "00000001"
        assert bits_from_bytes(b"\x80") == "10000000"

    def test_msb_first(self) -> None:
        assert bits_from_bytes(b"\xa5") == "10100101"

    def test_length(self) -> None:
        assert len(bits_from_bytes(bytes(range(32)))) == 256

    def test_accepts_memoryview(self) -> None:
        assert bits_from_bytes(memoryview(b"\xf0")) == "11110000"

    def test_rejects_empty(self) -> None:
        with pytest.raises(InputValidationError):
            bits_from_bytes(b"")

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(InputValidationError):
            bits_from_bytes("0011")  # type: ignore[arg-type]


class TestMonobit:
    """NIST frequency test."""

    def test_balanced_string_is_not_significant(self) -> None:
        result = monobit_test(_balanced_bits(256))
        assert result.name == "monobit"
        assert result.p_value == pytest.approx(1.0)
        assert result.passed

    def test_all_zeros_is_extremely_significant(self) -> None:
        result = monobit_test("0" * 256)
        assert result.p_value < 1e-50
        assert not result.passed
        assert "256 zeros" in result.detail

    def test_statistic_matches_definition(self) -> None:
        bits = "1" * 100 + "0" * 156
        result = monobit_test(bits)
        expected = abs(100 - 156) / math.sqrt(256)
        assert result.statistic == pytest.approx(expected)

    def test_too_short_is_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            monobit_test("01" * (MINIMUM_BITS // 4))

    def test_invalid_characters_are_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            monobit_test("01" * 30 + "xx")

    def test_whitespace_is_ignored(self) -> None:
        bits = _balanced_bits(128)
        spaced = " ".join(bits[index : index + 8] for index in range(0, len(bits), 8))
        assert monobit_test(spaced).statistic == pytest.approx(monobit_test(bits).statistic)


class TestRunsTest:
    """NIST runs test."""

    def test_alternating_pattern_fails(self) -> None:
        result = runs_test("01" * 128)
        assert result.name == "runs"
        assert result.p_value < 1e-6
        assert not result.passed

    def test_random_bits_pass(self) -> None:
        result = runs_test(_rng_bits(1024))
        assert result.p_value > 0.01

    def test_zero_variance_is_handled(self) -> None:
        result = runs_test("0" * 128)
        assert result.p_value == pytest.approx(0.0)
        assert not result.passed

    def test_runs_are_counted(self) -> None:
        result = runs_test("0" * 64 + "1" * 64)
        # Only two runs in 128 bits: far too few.
        assert "runs" in result.detail
        assert result.p_value < 1e-5


def _reference_longest_ones_tail(length: int, run: int) -> float:
    """Return the exact fraction of length-bit strings with an ones-run >= *run*.

    Enumerates all ``2**length`` strings implicitly with a transfer-matrix walk
    over states ``(current run of ones, seen a run of *run*)``; independent of the
    dynamic program under test.
    """
    states: dict[tuple[int, bool], int] = {(0, False): 1}
    for _ in range(length):
        updated: dict[tuple[int, bool], int] = {}
        for (current, seen), weight in states.items():
            # next bit is zero
            updated[(0, seen)] = updated.get((0, seen), 0) + weight
            # next bit is one
            nxt = current + 1
            key = (nxt, seen or nxt >= run)
            updated[key] = updated.get(key, 0) + weight
        states = updated
    hit = sum(weight for (_, seen), weight in states.items() if seen)
    return hit / 2**length


class TestLongestRun:
    """Exact dynamic-programming longest-run test."""

    def test_longest_run_length(self) -> None:
        assert longest_run_length("00001111" + "0" * 56) == 4
        assert longest_run_length("01" * 32) == 1
        assert longest_run_length("111111" + "0" * 58) == 6

    def test_known_string(self) -> None:
        assert longest_run_length("1011101110" + "0" * 54) == 3
        assert longest_run_length("0" * 64) == 0

    def test_exact_p_value_matches_enumeration(self) -> None:
        bits = "00001111" + "0" * 56
        observed = longest_run_length(bits)
        assert observed == 4
        reference = _reference_longest_ones_tail(len(bits), observed)
        assert longest_run_p_value(bits) == pytest.approx(reference, abs=1e-15)

    def test_p_value_is_monotone_in_the_run_length(self) -> None:
        short = longest_run_p_value("1" * 6 + "0" * 58)
        long = longest_run_p_value("1" * 12 + "0" * 52)
        assert 0.0 < long < short <= 1.0

    def test_no_ones_has_no_evidence(self) -> None:
        assert longest_run_p_value("0" * 64) == pytest.approx(1.0)

    def test_long_run_fails(self) -> None:
        result = longest_run_test("1" * 128)
        assert result.name == "longest_run"
        assert result.p_value < 1e-30
        assert not result.passed

    def test_random_bits_pass(self) -> None:
        assert longest_run_test(_rng_bits(2048)).passed


class TestSerialCorrelation:
    """Lag-1 serial correlation."""

    def test_alternating_bits_are_anti_correlated(self) -> None:
        assert serial_correlation("01" * 128) == pytest.approx(-1.0)

    def test_random_bits_are_near_zero(self) -> None:
        assert abs(serial_correlation(_rng_bits(2048))) < 0.1

    def test_constant_string_is_undefined(self) -> None:
        with pytest.raises(InputValidationError):
            serial_correlation("1" * 128)

    def test_test_wrapper(self) -> None:
        result = serial_correlation_test(_rng_bits(256))
        assert result.name == "serial_correlation"
        assert 0.0 <= result.p_value <= 1.0


class TestApproximateEntropy:
    """Approximate entropy with block size 2."""

    def test_random_bits_approach_ln_2(self) -> None:
        # For fair bits the NIST statistic phi(2) - phi(3) converges to ln 2 nats.
        value = approximate_entropy(_rng_bits(8192), block=2)
        assert value == pytest.approx(math.log(2.0), abs=0.05)

    def test_periodic_string_is_far_from_random(self) -> None:
        periodic = approximate_entropy("0011" * 512, block=2)
        random_value = approximate_entropy(_rng_bits(2048), block=2)
        assert periodic < random_value

    def test_wrapper_reports_a_p_value(self) -> None:
        result = approximate_entropy_test(_rng_bits(512), block=2)
        assert result.name == "approximate_entropy"
        assert 0.0 <= result.p_value <= 1.0


class TestNibbleUniformity:
    """Chi-square test on the hexadecimal digit histogram."""

    def test_zero_bytes_are_biased(self) -> None:
        result = nibble_uniformity_test(bytes(64))
        assert result.p_value < 1e-6
        assert not result.passed

    def test_balanced_nibbles_pass(self) -> None:
        data = bytes(range(256))
        result = nibble_uniformity_test(data)
        assert result.statistic == pytest.approx(0.0, abs=1e-9)
        assert result.passed

    def test_rejects_empty(self) -> None:
        with pytest.raises(InputValidationError):
            nibble_uniformity_test(b"")


class TestDistinctBytes:
    """Exact occupancy distribution of distinct byte values."""

    def test_all_identical_bytes(self) -> None:
        # One distinct value out of 256 bins in 32 draws is extremely unlikely.
        assert distinct_bytes_exact_p(bytes(32)) < 1e-60

    def test_all_distinct_bytes(self) -> None:
        data = bytes(range(64))
        assert distinct_bytes_exact_p(data) < 0.01

    def test_reference_matches_direct_enumeration(self) -> None:
        # Enumerate all 4**3 sequences over four bins and compute the same
        # "no more likely than observed" tail the helper reports.
        bins, draws = 4, 3
        sequences = list(itertools.product(range(bins), repeat=draws))
        counts: dict[int, int] = {}
        for sequence in sequences:
            distinct = len(set(sequence))
            counts[distinct] = counts.get(distinct, 0) + 1
        observed = 2
        tail = sum(count for distinct, count in counts.items() if count <= counts[observed])
        data = bytes([0, 1, 1])
        expected = tail / bins**draws
        assert distinct_bytes_exact_p(data, bins=bins) == pytest.approx(expected)

    def test_rejects_more_observations_than_bins(self) -> None:
        with pytest.raises(InputValidationError):
            distinct_bytes_exact_p(bytes(range(8)), bins=4)

    def test_rejects_too_few_bins(self) -> None:
        with pytest.raises(InputValidationError):
            distinct_bytes_exact_p(b"\x00\x01", bins=1)

    def test_wrapper_passes_for_balanced_data(self) -> None:
        data = bytes.randbytes(128) if hasattr(bytes, "randbytes") else bytes(range(128))
        result = distinct_byte_test(data)
        assert result.name == "distinct_bytes"
        assert 0.0 <= result.p_value <= 1.0


def _stirling(n: int, k: int) -> int:
    """Stirling number of the second kind ``S(n, k)``."""
    if k == 0:
        return 1 if n == 0 else 0
    table = [[0] * (k + 1) for _ in range(n + 1)]
    table[0][0] = 1
    for i in range(1, n + 1):
        for j in range(1, min(i, k) + 1):
            table[i][j] = j * table[i - 1][j] + table[i - 1][j - 1]
    return table[n][k]


class TestRandomnessReport:
    """Aggregation, multiple-testing correction, and serialization."""

    def test_all_seven_tests_run(self) -> None:
        report = randomness_report(_rng_bits(512))
        assert len(report.tests) == 7
        assert {test.name for test in report.tests} == {
            "monobit",
            "runs",
            "longest_run",
            "serial_correlation",
            "approximate_entropy",
            "nibble_uniformity",
            "distinct_bytes",
        }
        assert report.bits_used == 512

    def test_random_input_passes(self) -> None:
        report = randomness_report(_rng_bits(4096))
        assert report.familywise_pass
        assert report.failed_tests == ()
        assert report.minimum_p_value > 0.01

    def test_structured_input_fails(self) -> None:
        report = randomness_report("0" * 512)
        assert not report.familywise_pass
        assert "monobit" in report.failed_tests

    def test_extreme_input_keeps_p_values_finite(self) -> None:
        report = randomness_report("1" * 512)
        assert report.fisher_p_value > 0.0
        assert report.bonferroni_p_value > 0.0
        assert all(test.p_value >= P_VALUE_FLOOR for test in report.tests)

    def test_alpha_changes_the_verdict(self) -> None:
        bits = _rng_bits(512, seed=7)
        strict = randomness_report(bits, alpha=0.999)
        lenient = randomness_report(bits, alpha=0.001)
        assert len(strict.failed_tests) >= len(lenient.failed_tests)

    def test_entropy_bounds(self) -> None:
        report = randomness_report(_rng_bits(1024))
        assert 0.0 < report.bit_entropy <= 1.0
        assert report.bit_entropy <= report.bit_entropy_corrected
        assert report.bit_entropy_corrected <= 1.0

    def test_bonferroni_is_at_least_the_minimum(self) -> None:
        report = randomness_report("0" * 512)
        assert report.bonferroni_p_value >= report.minimum_p_value

    def test_data_argument_is_used(self) -> None:
        bits = bits_from_bytes(bytes(64))
        report = randomness_report(bits, data=bytes(64))
        assert report.tests[-1].name == "distinct_bytes"

    def test_notes_explain_the_caveats(self) -> None:
        report = randomness_report(_rng_bits(256))
        assert len(report.notes) == 3
        assert any("depend" in note for note in report.notes)

    def test_as_dict_round_trips(self) -> None:
        report = randomness_report(_rng_bits(256))
        payload = report.as_dict()
        assert payload["bits_used"] == 256
        assert len(payload["tests"]) == 7
        assert isinstance(payload["failed_tests"], list)
        assert isinstance(payload["notes"], list)
        assert set(payload) == {
            "bits_used",
            "alpha",
            "tests",
            "fisher_p_value",
            "bonferroni_p_value",
            "minimum_p_value",
            "familywise_pass",
            "failed_tests",
            "bit_entropy",
            "bit_entropy_corrected",
            "notes",
        }
        assert set(payload["tests"][0]) == {
            "name",
            "statistic",
            "p_value",
            "passed",
            "detail",
            "explanation",
        }

    def test_alpha_validation(self) -> None:
        for alpha in (0.0, 1.0, -0.5, 2.0):
            with pytest.raises(InputValidationError):
                randomness_report(_rng_bits(256), alpha=alpha)

    def test_short_input_is_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            randomness_report("0" * (MINIMUM_BITS - 1))
