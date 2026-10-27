"""Tests for bit and byte statistics."""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.statistics import (
    bit_statistics,
    byte_statistics,
    entropy_bits,
    shannon_entropy,
)


class TestBitStatistics:
    def test_example(self) -> None:
        stats = bit_statistics("101101")
        assert stats.length == 6
        assert stats.ones == 4
        assert stats.zeros == 2
        assert stats.hamming_weight == 4
        assert stats.one_ratio == pytest.approx(4 / 6)
        assert stats.zero_ratio == pytest.approx(2 / 6)
        assert stats.one_ratio + stats.zero_ratio == pytest.approx(1.0)

    def test_leading_zeros_count(self) -> None:
        stats = bit_statistics("000011")
        assert stats.length == 6
        assert stats.zeros == 4
        assert stats.ones == 2
        assert stats.hamming_weight == 2

    def test_all_zero_and_all_one(self) -> None:
        zeros = bit_statistics("00000000")
        assert zeros.one_ratio == 0.0
        assert zeros.zero_ratio == 1.0
        assert zeros.width_entropy == 0.0

        ones = bit_statistics("1111")
        assert ones.one_ratio == 1.0
        assert ones.width_entropy == 0.0

    def test_balanced_entropy(self) -> None:
        stats = bit_statistics("01")
        assert stats.width_entropy == pytest.approx(1.0)

    def test_empty_string(self) -> None:
        stats = bit_statistics("")
        assert stats.length == 0
        assert stats.ones == 0
        assert stats.one_ratio == 0.0
        assert stats.zero_ratio == 0.0

    def test_invalid_characters(self) -> None:
        with pytest.raises(InputValidationError):
            bit_statistics("102")

    def test_non_string(self) -> None:
        with pytest.raises(InputValidationError):
            bit_statistics(101)  # type: ignore[arg-type]

    @settings(max_examples=100, deadline=None)
    @given(st.text(alphabet="01", min_size=1, max_size=200))
    def test_invariants(self, bits: str) -> None:
        stats = bit_statistics(bits)
        assert stats.ones + stats.zeros == len(bits)
        assert stats.hamming_weight == bits.count("1")


class TestEntropy:
    def test_uniform_bytes(self) -> None:
        counts = dict.fromkeys(range(256), 1)
        assert shannon_entropy(counts) == pytest.approx(8.0)

    def test_single_symbol(self) -> None:
        assert shannon_entropy({7: 1000}) == 0.0

    def test_two_symbols(self) -> None:
        assert shannon_entropy({0: 1, 1: 1}) == pytest.approx(1.0)

    def test_empty_counts(self) -> None:
        assert shannon_entropy({}) == 0.0
        assert shannon_entropy([]) == 0.0

    def test_negative_counts_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            shannon_entropy({0: -1})

    def test_non_integer_counts_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            shannon_entropy({0: 1.5})  # type: ignore[dict-item]

    def test_entropy_bits(self) -> None:
        assert entropy_bits({0: 1, 1: 1}) == pytest.approx(2.0)


class TestByteStatistics:
    def test_simple(self) -> None:
        stats = byte_statistics(b"\x01\x02\x02\x03")
        assert stats.byte_length == 4
        assert stats.unique_bytes == 3
        assert stats.min_byte == 1
        assert stats.max_byte == 3
        assert stats.average_byte == pytest.approx(2.0)
        assert stats.byte_frequency == ((1, 1), (2, 2), (3, 1))
        assert stats.most_common[0] == (2, 2)
        assert stats.entropy_meaningful
        assert stats.entropy == pytest.approx(1.5)
        assert stats.frequency_of(2) == 2
        assert stats.frequency_of(99) == 0

    def test_empty(self) -> None:
        stats = byte_statistics(b"")
        assert stats.byte_length == 0
        assert stats.unique_bytes == 0
        assert stats.min_byte is None
        assert stats.max_byte is None
        assert stats.average_byte is None
        assert stats.entropy == 0.0
        assert not stats.entropy_meaningful
        assert stats.byte_frequency == ()

    def test_uniform_256(self) -> None:
        stats = byte_statistics(bytes(range(256)))
        assert stats.unique_bytes == 256
        assert stats.entropy == pytest.approx(8.0)
        assert stats.total_entropy_bits == pytest.approx(8.0 * 256)

    def test_padding_bits_are_reported(self) -> None:
        stats = byte_statistics(b"\x2d", padding_bits=2)
        assert stats.padding_bits == 2

    def test_invalid_padding(self) -> None:
        with pytest.raises(InputValidationError):
            byte_statistics(b"\x00", padding_bits=8)
        with pytest.raises(InputValidationError):
            byte_statistics(b"\x00", padding_bits=-1)

    def test_invalid_data(self) -> None:
        with pytest.raises(InputValidationError):
            byte_statistics("00")  # type: ignore[arg-type]

    @settings(max_examples=50, deadline=None)
    @given(st.binary(min_size=1, max_size=256))
    def test_entropy_bounds(self, data: bytes) -> None:
        stats = byte_statistics(data)
        assert 0.0 <= stats.entropy <= 8.0 + 1e-9
        assert stats.unique_bytes <= min(len(data), 256)
        assert stats.min_byte is not None and stats.max_byte is not None
        assert stats.min_byte <= stats.max_byte
        assert sum(count for _, count in stats.byte_frequency) == len(data)
        assert math.isclose(stats.total_entropy_bits, stats.entropy * len(data))
