"""Tests for binary string conversion helpers."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.binary_utils import (
    BinaryString,
    binary_to_bytes,
    binary_to_bytes_padded,
    binary_to_hex,
    binary_to_int,
    bits_to_bytes,
    bytes_to_binary,
    group_bits,
    hex_to_binary,
    int_to_binary,
    int_to_hex,
)
from binarycryptolab.exceptions import InputValidationError, InvalidBinaryError


class TestBinaryString:
    def test_preserves_original_and_leading_zeros(self) -> None:
        value = BinaryString.parse(" 0b00101101 ")
        assert value.original == " 0b00101101 "
        assert value.digits == "00101101"
        assert value.length == 8
        assert value.value == 0x2D
        assert value.is_byte_aligned
        assert value.padding_bits == 0
        assert value.byte_length == 1

    def test_non_aligned(self) -> None:
        value = BinaryString.parse("101101")
        assert value.length == 6
        assert not value.is_byte_aligned
        assert value.padding_bits == 2
        assert value.byte_length == 1

    def test_invalid(self) -> None:
        with pytest.raises(InvalidBinaryError):
            BinaryString.parse("102")


class TestConversions:
    def test_binary_to_int(self) -> None:
        assert binary_to_int("101101") == 45
        assert binary_to_int("00101101") == 45
        assert binary_to_int("0") == 0
        assert binary_to_int("000") == 0

    def test_int_to_binary(self) -> None:
        assert int_to_binary(45) == "101101"
        assert int_to_binary(45, width=8) == "00101101"
        assert int_to_binary(0) == "0"
        assert int_to_binary(0, width=4) == "0000"

    @pytest.mark.parametrize("value", [-1, -100])
    def test_negative_int_rejected(self, value: int) -> None:
        with pytest.raises(InputValidationError):
            int_to_binary(value)

    def test_bool_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            int_to_binary(True)  # type: ignore[arg-type]

    def test_width_too_small(self) -> None:
        with pytest.raises(InputValidationError, match="exceeds width"):
            int_to_binary(255, width=4)

    def test_binary_to_hex(self) -> None:
        assert binary_to_hex("101101") == "2d"
        assert binary_to_hex("11111111") == "ff"
        assert binary_to_hex("0") == "0"
        # Nibble alignment is preserved by left padding.
        assert binary_to_hex("1") == "1"
        assert binary_to_hex("11111") == "1f"

    def test_hex_to_binary_preserves_width(self) -> None:
        assert hex_to_binary("2d") == "00101101"
        assert hex_to_binary("0f") == "00001111"
        assert hex_to_binary("1", allow_odd=True) == "00000001"

    def test_int_to_hex(self) -> None:
        assert int_to_hex(45) == "2d"
        assert int_to_hex(0) == "00"
        assert int_to_hex(45, prefix=True) == "0x2d"
        assert int_to_hex(1, width=4) == "0001"
        assert int_to_hex(1, width=3) == "0001"


class TestByteConversion:
    def test_aligned(self) -> None:
        assert binary_to_bytes("00101101") == b"\x2d"
        assert binary_to_bytes("11111111") == b"\xff"

    def test_left_padding_preserves_value(self) -> None:
        data, padding = binary_to_bytes_padded("101101")
        assert data == b"\x2d"
        assert padding == 2

    def test_right_padding_changes_value(self) -> None:
        data, padding = binary_to_bytes_padded("101101", side="right")
        assert data == b"\xb4"
        assert padding == 2

    def test_zero(self) -> None:
        assert binary_to_bytes("0") == b"\x00"
        assert binary_to_bytes("000000000") == b"\x00\x00"

    def test_invalid_side(self) -> None:
        with pytest.raises(InputValidationError):
            binary_to_bytes("1", side="middle")  # type: ignore[arg-type]

    def test_bytes_to_binary(self) -> None:
        assert bytes_to_binary(b"\x2d") == "00101101"
        assert bytes_to_binary(b"\x00\x01") == "0000000000000001"
        assert bytes_to_binary(b"") == ""
        assert bytes_to_binary(b"\x01", width=16) == "0000000000000001"

    def test_bytes_to_binary_width_errors(self) -> None:
        with pytest.raises(InputValidationError, match="do not fit"):
            bytes_to_binary(b"\xff\xff", width=8)
        with pytest.raises(InputValidationError):
            bytes_to_binary(b"\xff", width=0)

    def test_bytes_to_binary_type_error(self) -> None:
        with pytest.raises(InputValidationError):
            bytes_to_binary("ff")  # type: ignore[arg-type]

    def test_bits_to_bytes(self) -> None:
        assert bits_to_bytes([1, 0, 1]) == b"\xa0"
        assert bits_to_bytes([0] * 8) == b"\x00"
        assert bits_to_bytes([1] * 8) == b"\xff"
        with pytest.raises(InputValidationError):
            bits_to_bytes([])
        with pytest.raises(InputValidationError):
            bits_to_bytes([2])

    @settings(max_examples=100, deadline=None)
    @given(st.integers(min_value=0, max_value=2**128 - 1))
    def test_int_binary_round_trip(self, value: int) -> None:
        assert binary_to_int(int_to_binary(value)) == value

    @settings(max_examples=100, deadline=None)
    @given(st.binary(min_size=1, max_size=64))
    def test_bytes_binary_round_trip(self, data: bytes) -> None:
        assert binary_to_bytes(bytes_to_binary(data)) == data


class TestGrouping:
    def test_grouping_does_not_add_digits(self) -> None:
        assert group_bits("101101") == "1011 01"
        assert group_bits("101101", group_size=2) == "10 11 01"
        assert group_bits("101101", separator="-") == "1011-01"

    def test_optional_left_padding(self) -> None:
        assert group_bits("101101", pad_left=True) == "0010 1101"

    def test_invalid_group_size(self) -> None:
        with pytest.raises(InputValidationError):
            group_bits("1", group_size=0)
