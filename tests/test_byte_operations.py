"""Tests for byte sequence operations, including endianness."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.byte_operations import (
    byte_frequency,
    bytes_from_binary,
    bytes_from_hex,
    bytes_hamming_distance,
    bytes_to_binary_string,
    bytes_to_hex_string,
    bytes_to_int,
    bytes_to_int_iter,
    chunk_bytes,
    compare_bytes,
    concat_bytes,
    int_to_bytes,
    reverse_bytes,
    slice_bytes,
    swap_endianness,
    xor_bytes,
)
from binarycryptolab.exceptions import InputValidationError


class TestConversions:
    def test_from_binary_and_hex(self) -> None:
        assert bytes_from_binary("101101") == b"\x2d"
        assert bytes_from_hex("deadbeef") == b"\xde\xad\xbe\xef"
        assert bytes_from_hex("abc") == b"\x0a\xbc"

    def test_to_binary_and_hex(self) -> None:
        assert bytes_to_binary_string(b"\x01\x02") == "0000000100000010"
        assert bytes_to_hex_string(b"\xde\xad") == "dead"
        assert bytes_to_hex_string(b"\xde\xad", uppercase=True) == "DEAD"


class TestFrequency:
    def test_sorted_counts(self) -> None:
        assert byte_frequency(b"\x02\x01\x02\x02") == {1: 1, 2: 3}

    def test_empty(self) -> None:
        assert byte_frequency(b"") == {}

    def test_type_error(self) -> None:
        with pytest.raises(InputValidationError):
            byte_frequency("00")  # type: ignore[arg-type]


class TestXor:
    def test_xor(self) -> None:
        assert xor_bytes(b"\x00\xff", b"\xff\xff") == b"\xff\x00"
        assert xor_bytes(b"", b"") == b""

    def test_length_mismatch(self) -> None:
        with pytest.raises(InputValidationError, match="equal lengths"):
            xor_bytes(b"\x00", b"\x00\x00")

    @settings(max_examples=50, deadline=None)
    @given(st.binary(min_size=0, max_size=32), st.binary(min_size=0, max_size=32))
    def test_xor_is_involutive(self, left: bytes, right: bytes) -> None:
        if len(left) != len(right):
            with pytest.raises(InputValidationError):
                xor_bytes(left, right)
        else:
            assert xor_bytes(xor_bytes(left, right), right) == left


class TestHamming:
    def test_distance(self) -> None:
        assert bytes_hamming_distance(b"\x00", b"\xff") == 8
        assert bytes_hamming_distance(b"\x0f", b"\xf0") == 8
        assert bytes_hamming_distance(b"\x00", b"\x00") == 0

    def test_requires_equal_lengths(self) -> None:
        with pytest.raises(InputValidationError):
            bytes_hamming_distance(b"", b"\x00")


class TestChunking:
    def test_chunks(self) -> None:
        assert chunk_bytes(b"abcdef", 2) == [b"ab", b"cd", b"ef"]
        assert chunk_bytes(b"abcdef", 4) == [b"abcd", b"ef"]

    def test_remainder_rejected(self) -> None:
        with pytest.raises(InputValidationError, match="not a multiple"):
            chunk_bytes(b"abcdef", 4, allow_remainder=False)

    def test_empty(self) -> None:
        assert chunk_bytes(b"", 4) == []

    def test_invalid_size(self) -> None:
        with pytest.raises(InputValidationError):
            chunk_bytes(b"ab", 0)


class TestSequenceOperations:
    def test_concat(self) -> None:
        assert concat_bytes(b"a", b"b", b"c") == b"abc"
        assert concat_bytes() == b""

    def test_slice(self) -> None:
        assert slice_bytes(b"abcdef", 1, 3) == b"bc"
        assert slice_bytes(b"abcdef", 2) == b"cdef"
        assert slice_bytes(b"abcdef", 0, 0) == b""

    def test_slice_validation(self) -> None:
        with pytest.raises(InputValidationError):
            slice_bytes(b"abc", 2, 1)
        with pytest.raises(InputValidationError):
            slice_bytes(b"abc", 0, 4)
        with pytest.raises(InputValidationError):
            slice_bytes(b"abc", -1, 2)

    def test_reverse_and_endianness(self) -> None:
        assert reverse_bytes(b"\x01\x02\x03") == b"\x03\x02\x01"
        assert swap_endianness(b"\x01\x02\x03") == b"\x03\x02\x01"

    def test_compare_equal(self) -> None:
        result = compare_bytes(b"\x01\x02", b"\x01\x02")
        assert result.equal
        assert result.differing_indices == ()
        assert not result.padding_applied

    def test_compare_different(self) -> None:
        result = compare_bytes(b"\x01\x02", b"\x01\x03")
        assert not result.equal
        assert result.differing_indices == (1,)
        assert result.bits_hamming_distance == 1

    def test_compare_padded(self) -> None:
        result = compare_bytes(b"\x01", b"\x01\x00")
        assert result.padding_applied
        # The original sequences differ in length, so they are not byte-for-byte
        # equal even though the zero-padded comparison shows no differing byte.
        assert not result.equal
        assert result.differing_indices == ()
        assert result.length_left == 1
        assert result.length_right == 2
        assert result.bits_hamming_distance == 0


class TestIntegers:
    def test_bytes_to_int(self) -> None:
        assert bytes_to_int(b"\x01\x00") == 256
        assert bytes_to_int(b"\x01\x00", byteorder="little") == 1
        assert bytes_to_int(b"") == 0

    def test_int_to_bytes(self) -> None:
        assert int_to_bytes(256) == b"\x01\x00"
        assert int_to_bytes(256, byteorder="little") == b"\x00\x01"
        assert int_to_bytes(256, length=4) == b"\x00\x00\x01\x00"
        assert int_to_bytes(0) == b"\x00"

    def test_round_trip(self) -> None:
        for order in ("big", "little"):
            for value in (0, 1, 255, 256, 2**64):
                data = int_to_bytes(value, byteorder=order)  # type: ignore[arg-type]
                assert bytes_to_int(data, byteorder=order) == value  # type: ignore[arg-type]

    def test_overflow(self) -> None:
        with pytest.raises(InputValidationError, match="does not fit"):
            int_to_bytes(256, length=1)

    def test_negative_requires_signed(self) -> None:
        with pytest.raises(InputValidationError):
            int_to_bytes(-1)
        assert int_to_bytes(-1, length=1, signed=True) == b"\xff"
        assert bytes_to_int(b"\xff", signed=True) == -1

    def test_invalid_byteorder(self) -> None:
        with pytest.raises(InputValidationError, match="byteorder"):
            int_to_bytes(1, byteorder="middle")  # type: ignore[arg-type]
        with pytest.raises(InputValidationError, match="byteorder"):
            bytes_to_int(b"\x01", byteorder="middle")  # type: ignore[arg-type]

    def test_bool_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            int_to_bytes(True)  # type: ignore[arg-type]

    def test_bytes_to_int_iter(self) -> None:
        assert bytes_to_int_iter([0, 255]) == (0, 255)
        with pytest.raises(InputValidationError):
            bytes_to_int_iter([256])
