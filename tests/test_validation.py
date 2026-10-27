"""Tests for strict input validation."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.config import InputLimits
from binarycryptolab.exceptions import (
    InputValidationError,
    InvalidBinaryError,
    InvalidDecimalError,
    InvalidHexError,
)
from binarycryptolab.validation import (
    normalize_binary,
    normalize_hex,
    parse_decimal,
    strip_whitespace,
)


class TestBinaryValidation:
    def test_simple_value(self) -> None:
        assert normalize_binary("101101") == "101101"

    def test_prefix_is_removed(self) -> None:
        assert normalize_binary("0b1011") == "1011"
        assert normalize_binary("0B1011") == "1011"

    def test_whitespace_is_removed(self) -> None:
        assert normalize_binary("  1011 0101\n") == "10110101"
        assert normalize_binary("10\t11\v01\f01") == "10110101"

    def test_leading_zeros_are_preserved(self) -> None:
        assert normalize_binary("000101") == "000101"
        assert normalize_binary("0000") == "0000"

    def test_zero_is_valid(self) -> None:
        assert normalize_binary("0") == "0"

    @pytest.mark.parametrize("value", ["", "   ", "0b", "0B  "])
    def test_empty_input_is_rejected(self, value: str) -> None:
        with pytest.raises(InvalidBinaryError, match="empty"):
            normalize_binary(value)

    @pytest.mark.parametrize("value", ["102", "abc", "0x2d", "12 3", "١٠١"])  # noqa: RUF001
    def test_invalid_characters_are_rejected(self, value: str) -> None:
        with pytest.raises(InvalidBinaryError):
            normalize_binary(value)

    def test_prefix_can_be_rejected(self) -> None:
        with pytest.raises(InvalidBinaryError, match="prefix"):
            normalize_binary("0b101", allow_prefix=False)

    def test_length_limit(self) -> None:
        with pytest.raises(InputValidationError, match="too long"):
            normalize_binary("1" * 11, max_length=10)
        assert normalize_binary("1" * 10, max_length=10) == "1" * 10

    def test_invalid_length_arguments(self) -> None:
        with pytest.raises(InputValidationError):
            normalize_binary("1", max_length=0)
        with pytest.raises(InputValidationError):
            normalize_binary("1", max_length=True)

    def test_non_string_rejected(self) -> None:
        with pytest.raises(InputValidationError, match="string"):
            normalize_binary(101)  # type: ignore[arg-type]

    def test_custom_limits(self) -> None:
        limits = InputLimits(max_binary_length=4, max_hex_length=4, max_decimal_digits=4)
        with pytest.raises(InputValidationError):
            normalize_binary("10101", limits=limits)

    @settings(max_examples=50, deadline=None)
    @given(st.text(alphabet="01", min_size=1, max_size=200))
    def test_valid_binary_round_trips(self, value: str) -> None:
        assert normalize_binary(value) == value

    @settings(max_examples=50, deadline=None)
    @given(st.text(min_size=1, max_size=20))
    def test_only_binary_digits_are_accepted(self, value: str) -> None:
        cleaned = strip_whitespace(value)
        digits = cleaned[2:] if cleaned[:2].lower() == "0b" else cleaned
        if digits and set(digits) <= {"0", "1"}:
            assert normalize_binary(value) == digits
        else:
            with pytest.raises(InvalidBinaryError):
                normalize_binary(value)


class TestHexValidation:
    def test_mixed_case_is_normalized(self) -> None:
        assert normalize_hex("DeAdBeEf") == "deadbeef"

    def test_prefix_is_removed(self) -> None:
        assert normalize_hex("0x2D") == "2d"
        assert normalize_hex("0X2d") == "2d"

    def test_whitespace_is_removed(self) -> None:
        assert normalize_hex(" de ad be ef ") == "deadbeef"

    def test_leading_zeros_are_preserved(self) -> None:
        assert normalize_hex("0002") == "0002"

    def test_odd_length_rejected_by_default(self) -> None:
        with pytest.raises(InvalidHexError, match="odd number"):
            normalize_hex("abc")

    def test_odd_length_is_left_padded_when_allowed(self) -> None:
        assert normalize_hex("abc", allow_odd=True) == "0abc"
        assert normalize_hex("0x1", allow_odd=True) == "01"

    @pytest.mark.parametrize("value", ["", "   ", "0x", "0X "])
    def test_empty_input_is_rejected(self, value: str) -> None:
        with pytest.raises(InvalidHexError, match="empty"):
            normalize_hex(value)

    @pytest.mark.parametrize("value", ["zz", "12g4", "0b101", "0xzz"])
    def test_invalid_characters_are_rejected(self, value: str) -> None:
        with pytest.raises(InvalidHexError):
            normalize_hex(value)

    def test_prefix_can_be_rejected(self) -> None:
        with pytest.raises(InvalidHexError, match="prefix"):
            normalize_hex("0x2d", allow_prefix=False)

    def test_length_limit(self) -> None:
        with pytest.raises(InputValidationError, match="too long"):
            normalize_hex("aa" * 6, max_length=10)
        assert normalize_hex("aa" * 5, max_length=10) == "aa" * 5

    def test_non_string_rejected(self) -> None:
        with pytest.raises(InputValidationError, match="string"):
            normalize_hex(b"2d")  # type: ignore[arg-type]

    @settings(max_examples=50, deadline=None)
    @given(st.text(alphabet="0123456789abcdef", min_size=2, max_size=40))
    def test_even_valid_hex_round_trips(self, value: str) -> None:
        if len(value) % 2 == 0:
            assert normalize_hex(value) == value
        else:
            with pytest.raises(InvalidHexError):
                normalize_hex(value)
            assert normalize_hex(value, allow_odd=True) == "0" + value


class TestDecimalValidation:
    def test_integer_input(self) -> None:
        assert parse_decimal(45) == 45

    def test_string_input(self) -> None:
        assert parse_decimal("45") == 45
        assert parse_decimal(" 4_500 ") == 4500
        assert parse_decimal("+7") == 7
        assert parse_decimal("0") == 0

    def test_range_checks(self) -> None:
        with pytest.raises(InvalidDecimalError, match="at least"):
            parse_decimal(-1)
        with pytest.raises(InvalidDecimalError, match="at most"):
            parse_decimal(10, max_value=9)
        assert parse_decimal(9, max_value=9) == 9

    @pytest.mark.parametrize("value", ["", " ", "abc", "1.5", "-3", "0x10"])
    def test_invalid_text_is_rejected(self, value: str) -> None:
        with pytest.raises(InvalidDecimalError):
            parse_decimal(value)

    def test_negative_integer_is_rejected(self) -> None:
        with pytest.raises(InvalidDecimalError, match="at least"):
            parse_decimal(-5)

    def test_bool_is_rejected(self) -> None:
        with pytest.raises(InputValidationError, match="boolean"):
            parse_decimal(True)  # type: ignore[arg-type]

    def test_digit_limit(self) -> None:
        with pytest.raises(InputValidationError, match="too long"):
            parse_decimal("12345", max_digits=4)
        assert parse_decimal("1234", max_digits=4) == 1234


def test_strip_whitespace() -> None:
    assert strip_whitespace(" a\tb\nc\rd\x0be\x0cf ") == "abcdef"
    assert strip_whitespace("") == ""
    assert strip_whitespace("no-whitespace") == "no-whitespace"
