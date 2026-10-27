"""Tests for bit-level operations, including width-dependent behaviour."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from binarycryptolab.bit_operations import (
    bitwise_and,
    bitwise_not,
    bitwise_or,
    bitwise_xor,
    compare_binary_strings,
    count_set_bits,
    count_zero_bits,
    extract_bit_range,
    first_differing_bit,
    hamming_distance,
    hamming_distance_binary,
    hamming_weight,
    last_differing_bit,
    mask_bits,
    pad_binary,
    reverse_bits,
    shift_left,
    shift_right,
)
from binarycryptolab.exceptions import InputValidationError, InvalidBinaryError


class TestCounting:
    def test_count_set_bits(self) -> None:
        assert count_set_bits(0) == 0
        assert count_set_bits(1) == 1
        assert count_set_bits(0b101101) == 4
        assert count_set_bits(2**64 - 1) == 64

    def test_negative_integer_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            count_set_bits(-1)

    def test_bool_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            count_set_bits(True)  # type: ignore[arg-type]

    def test_hamming_weight_representations(self) -> None:
        assert hamming_weight(0b101101) == 4
        assert hamming_weight("101101") == 4
        assert hamming_weight("0b101101") == 4
        assert hamming_weight("000101101") == 4
        assert hamming_weight(b"\xff\x00") == 8
        assert hamming_weight(b"") == 0

    def test_hamming_weight_invalid_type(self) -> None:
        with pytest.raises(InputValidationError):
            hamming_weight(1.5)  # type: ignore[arg-type]

    def test_count_zero_bits_requires_width(self) -> None:
        assert count_zero_bits(0b101101, 6) == 2
        assert count_zero_bits(0b101101, 8) == 4
        assert count_zero_bits(0, 8) == 8

    def test_count_zero_bits_rejects_overflow(self) -> None:
        with pytest.raises(InputValidationError):
            count_zero_bits(0b1111, 3)

    @settings(max_examples=100, deadline=None)
    @given(
        st.integers(min_value=0, max_value=2**128 - 1), st.integers(min_value=128, max_value=256)
    )
    def test_ones_plus_zeros_equals_width(self, value: int, width: int) -> None:
        assume(value < 2**width)
        assert count_set_bits(value) + count_zero_bits(value, width) == width


class TestBitwise:
    def test_binary_operators(self) -> None:
        assert bitwise_and(0b1100, 0b1010) == 0b1000
        assert bitwise_or(0b1100, 0b1010) == 0b1110
        assert bitwise_xor(0b1100, 0b1010) == 0b0110

    def test_negative_operands_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            bitwise_and(-1, 0)
        with pytest.raises(InputValidationError):
            bitwise_or(0, -1)
        with pytest.raises(InputValidationError):
            bitwise_xor(-1, -1)

    def test_not_requires_width(self) -> None:
        assert bitwise_not(0b1010, 4) == 0b0101
        assert bitwise_not(0, 8) == 0xFF
        assert bitwise_not(0xFF, 8) == 0

    def test_not_without_width_is_a_type_error(self) -> None:
        with pytest.raises(TypeError):
            bitwise_not(0b1010)  # type: ignore[call-arg]

    def test_not_rejects_width_overflow(self) -> None:
        with pytest.raises(InputValidationError):
            bitwise_not(0b10000, 4)

    def test_shifts(self) -> None:
        assert shift_left(0b101, 1) == 0b1010
        assert shift_left(0b101, 4) == 0b1010000
        assert shift_right(0b101, 1) == 0b10
        assert shift_right(0b101, 3) == 0

    def test_bounded_left_shift(self) -> None:
        assert shift_left(0b1011, 1, width=4) == 0b0110
        assert shift_left(0b1011, 1, width=8) == 0b00010110

    def test_shift_validation(self) -> None:
        with pytest.raises(InputValidationError):
            shift_left(-1, 1)
        with pytest.raises(InputValidationError):
            shift_right(1, -1)
        with pytest.raises(InputValidationError):
            shift_left(1, 10**9)

    def test_mask(self) -> None:
        assert mask_bits(0xFFFF, 8) == 0xFF
        assert mask_bits(0b1011, 2) == 0b11
        with pytest.raises(InputValidationError):
            mask_bits(1, 0)

    def test_extract_range(self) -> None:
        # LSB-based indexing.
        assert extract_bit_range(0b101101, 0, 4) == 0b1101
        assert extract_bit_range(0b101101, 1, 5) == 0b0110
        assert extract_bit_range(0b101101, 0, 6) == 0b101101
        assert extract_bit_range(0b101101, 1, 5, width=6) == 0b0110

    def test_extract_range_validation(self) -> None:
        with pytest.raises(InputValidationError):
            extract_bit_range(1, 2, 2)
        with pytest.raises(InputValidationError):
            extract_bit_range(1, 3, 2)
        with pytest.raises(InputValidationError):
            extract_bit_range(1, 0, 9, width=8)

    def test_reverse_bits(self) -> None:
        assert reverse_bits(0b1100, 4) == 0b0011
        assert reverse_bits(0b0001, 8) == 0b10000000
        assert reverse_bits(0, 5) == 0
        with pytest.raises(InputValidationError):
            reverse_bits(0b1111, 3)

    @settings(max_examples=100, deadline=None)
    @given(st.integers(min_value=0, max_value=2**32 - 1))
    def test_double_reverse_is_identity(self, value: int) -> None:
        assert reverse_bits(reverse_bits(value, 32), 32) == value


class TestComparison:
    def test_equal_strings(self) -> None:
        result = compare_binary_strings("1010", "1010")
        assert result.equal
        assert result.hamming_distance == 0
        assert result.first_difference is None
        assert result.last_difference is None
        assert not result.padding_applied

    def test_different_widths_are_left_padded(self) -> None:
        result = compare_binary_strings("1010", "001010")
        assert result.left == "001010"
        assert result.right == "001010"
        assert result.padding_applied
        assert result.equal

    def test_indices_are_msb_based_for_strings(self) -> None:
        result = compare_binary_strings("1000", "0001")
        assert result.differing_indices == (0, 3)
        assert result.first_difference == 0
        assert result.last_difference == 3
        assert result.hamming_distance == 2

    def test_hamming_distance(self) -> None:
        assert hamming_distance(0b1010, 0b0011) == 2
        assert hamming_distance("1010", "0011") == 2
        assert hamming_distance_binary("1", "000") == 1
        assert hamming_distance(0, 0) == 0

    def test_hamming_distance_mixed_types(self) -> None:
        with pytest.raises(InputValidationError, match="same representation"):
            hamming_distance(1, "1")  # type: ignore[arg-type]

    def test_hamming_distance_negative(self) -> None:
        with pytest.raises(InputValidationError):
            hamming_distance(-1, 1)

    def test_first_differing_integer_is_lsb_based(self) -> None:
        assert first_differing_bit(0b1000, 0b1001) == 0
        assert first_differing_bit(0b0001, 0b1001) == 3
        assert first_differing_bit(5, 5) is None

    def test_last_differing_integer_is_lsb_based(self) -> None:
        assert last_differing_bit(0b1000, 0b1001) == 0
        assert last_differing_bit(0b0001, 0b1001) == 3
        assert last_differing_bit(5, 5) is None

    def test_first_and_last_string(self) -> None:
        assert first_differing_bit("100", "101") == 2
        assert last_differing_bit("100", "101") == 2
        assert first_differing_bit("101", "101") is None

    def test_invalid_binary_in_comparison(self) -> None:
        with pytest.raises(InvalidBinaryError):
            compare_binary_strings("102", "101")


class TestPadding:
    def test_left_padding_preserves_value(self) -> None:
        assert pad_binary("1011", 8) == "00001011"
        assert pad_binary("1011", 4) == "1011"

    def test_right_padding(self) -> None:
        assert pad_binary("1011", 8, side="right") == "10110000"

    def test_errors(self) -> None:
        with pytest.raises(InputValidationError, match="smaller width"):
            pad_binary("1011", 3)
        with pytest.raises(InputValidationError):
            pad_binary("1011", 8, side="up")  # type: ignore[arg-type]
        with pytest.raises(InvalidBinaryError):
            pad_binary("10x1", 8)
