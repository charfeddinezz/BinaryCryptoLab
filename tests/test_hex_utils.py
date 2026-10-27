"""Tests for hexadecimal conversion helpers."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.exceptions import InputValidationError, InvalidHexError
from binarycryptolab.hex_utils import (
    bytes_to_hex,
    hex_digit_count,
    hex_to_binary,
    hex_to_bytes,
    hex_to_int,
    hex_to_text,
    int_to_hex,
    is_hex_string,
    text_to_hex,
)


class TestHexToBytes:
    def test_basic(self) -> None:
        assert hex_to_bytes("2d") == b"\x2d"
        assert hex_to_bytes("2D") == b"\x2d"
        assert hex_to_bytes("0x2d") == b"\x2d"
        assert hex_to_bytes("de ad be ef") == b"\xde\xad\xbe\xef"

    def test_leading_zeros_are_preserved(self) -> None:
        assert hex_to_bytes("0001") == b"\x00\x01"

    def test_odd_length_allowed_by_default(self) -> None:
        assert hex_to_bytes("abc") == b"\x0a\xbc"

    def test_odd_length_can_be_rejected(self) -> None:
        with pytest.raises(InvalidHexError):
            hex_to_bytes("abc", allow_odd=False)

    def test_empty(self) -> None:
        with pytest.raises(InvalidHexError):
            hex_to_bytes("")

    def test_invalid(self) -> None:
        with pytest.raises(InvalidHexError):
            hex_to_bytes("gg")


class TestBytesToHex:
    def test_lowercase(self) -> None:
        assert bytes_to_hex(b"\xde\xad") == "dead"
        assert bytes_to_hex(b"") == ""

    def test_uppercase(self) -> None:
        assert bytes_to_hex(b"\xde\xad", uppercase=True) == "DEAD"

    def test_type_error(self) -> None:
        with pytest.raises(InputValidationError):
            bytes_to_hex("dead")  # type: ignore[arg-type]


class TestHexIntegerConversions:
    def test_hex_to_int(self) -> None:
        assert hex_to_int("2d") == 45
        assert hex_to_int("0x2D") == 45
        assert hex_to_int("0002d") == 45
        assert hex_to_int("0") == 0

    def test_int_to_hex(self) -> None:
        assert int_to_hex(45) == "2d"
        assert int_to_hex(45, prefix=True) == "0x2d"
        assert int_to_hex(0) == "00"
        assert int_to_hex(1, bytes_length=4) == "00000001"

    def test_int_to_hex_negative(self) -> None:
        with pytest.raises(InputValidationError):
            int_to_hex(-1)

    def test_int_to_hex_overflow(self) -> None:
        with pytest.raises(InputValidationError, match="does not fit"):
            int_to_hex(256, bytes_length=1)

    def test_invalid_bytes_length(self) -> None:
        with pytest.raises(InputValidationError):
            int_to_hex(1, bytes_length=0)


class TestHexBinary:
    def test_width_is_four_bits_per_digit(self) -> None:
        assert hex_to_binary("2d") == "00101101"
        assert hex_to_binary("f") == "00001111"
        assert hex_to_binary("0f") == "00001111"


class TestText:
    def test_decode_utf8(self) -> None:
        assert hex_to_text("48656c6c6f") == "Hello"
        assert hex_to_text("e282ac") == "€"

    def test_decode_is_explicit_not_assumed(self) -> None:
        # 0xff is not valid UTF-8; decoding must fail rather than guess.
        with pytest.raises(InvalidHexError, match="utf-8"):
            hex_to_text("ff")

    def test_latin1_requires_explicit_encoding(self) -> None:
        assert hex_to_text("ff", encoding="latin-1") == "ÿ"

    def test_unknown_encoding(self) -> None:
        with pytest.raises(InputValidationError, match="unknown text encoding"):
            hex_to_text("41", encoding="not-a-codec")

    def test_encode_text(self) -> None:
        assert text_to_hex("Hello") == "48656c6c6f"
        assert text_to_hex("€") == "e282ac"

    def test_encode_non_string(self) -> None:
        with pytest.raises(InputValidationError):
            text_to_hex(b"Hello")  # type: ignore[arg-type]

    def test_encode_unknown_encoding(self) -> None:
        with pytest.raises(InputValidationError, match="unknown text encoding"):
            text_to_hex("a", encoding="not-a-codec")


class TestPredicates:
    @pytest.mark.parametrize("value", ["2d", "0x2d", "DEADBEEF", "abc"])
    def test_is_hex_string_true(self, value: str) -> None:
        assert is_hex_string(value)

    @pytest.mark.parametrize("value", ["", "0x", "zz", "12g", "hello"])
    def test_is_hex_string_false(self, value: str) -> None:
        assert not is_hex_string(value)

    def test_is_hex_string_non_string(self) -> None:
        assert not is_hex_string(123)  # type: ignore[arg-type]

    def test_hex_digit_count(self) -> None:
        assert hex_digit_count("0x2d") == 2
        assert hex_digit_count("abc") == 3
        assert hex_digit_count("0") == 1
        assert hex_digit_count("0002") == 4

    def test_empty_bytes_round_trip_is_rejected(self) -> None:
        # Empty hexadecimal text is rejected explicitly rather than decoded as b"".
        with pytest.raises(InvalidHexError):
            hex_to_bytes(bytes_to_hex(b""))

    @settings(max_examples=100, deadline=None)
    @given(st.binary(min_size=1, max_size=64))
    def test_hex_byte_round_trip(self, data: bytes) -> None:
        assert hex_to_bytes(bytes_to_hex(data)) == data
