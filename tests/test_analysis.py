"""Tests for the binary and hexadecimal analysis engines."""

from __future__ import annotations

import pytest

from binarycryptolab.analysis import (
    analyze,
    analyze_binary,
    analyze_hex,
    attach_hashes,
    attach_warning,
)
from binarycryptolab.exceptions import InvalidBinaryError, InvalidHexError
from binarycryptolab.hashing import hash_bytes
from binarycryptolab.models.analysis_result import AnalysisResult


class TestBinaryAnalysis:
    def test_required_example(self) -> None:
        result = analyze_binary("101101")
        assert result.normalized == "101101"
        assert result.bit_length == 6
        assert result.integer_value == 45
        assert result.hexadecimal == "2d"
        assert result.bit_stats.ones == 4
        assert result.bit_stats.zeros == 2
        assert result.bit_stats.hamming_weight == 4

    def test_leading_zeros_are_preserved(self) -> None:
        result = analyze_binary("000101101")
        assert result.bit_length == 9
        assert result.integer_value == 45
        assert result.bit_stats.zeros == 5
        assert result.byte_stats.byte_length == 2

    def test_byte_padding_is_reported(self) -> None:
        result = analyze_binary("101101")
        assert result.padding_bits == 2
        assert result.complete_bytes == 0
        assert result.incomplete_bits == 6
        assert result.bytes_hex == "2d"

    def test_grouped_display_keeps_all_digits(self) -> None:
        result = analyze_binary("101101")
        assert result.grouped_display.replace(" ", "") == "101101"

    def test_original_input_is_preserved(self) -> None:
        result = analyze_binary(" 0b1011 ")
        assert result.original == " 0b1011 "
        assert result.normalized == "1011"

    def test_invalid(self) -> None:
        with pytest.raises(InvalidBinaryError):
            analyze_binary("10x1")


class TestHexAnalysis:
    def test_example(self) -> None:
        result = analyze_hex("2D")
        assert result.normalized == "2d"
        assert result.hex_length == 2
        assert result.integer_value == 45
        assert result.binary == "00101101"
        assert result.binary_length == 8
        assert result.byte_stats.byte_length == 1
        assert result.bit_stats.hamming_weight == 4
        assert result.text_utf8 == "-"

    def test_odd_length_is_flagged(self) -> None:
        result = analyze_hex("abc")
        assert result.normalized == "0abc"
        assert result.odd_length_input
        assert result.binary == "0000101010111100"

    def test_odd_length_can_be_rejected(self) -> None:
        with pytest.raises(InvalidHexError):
            analyze_hex("abc", allow_odd=False)

    def test_non_utf8_has_no_preview(self) -> None:
        result = analyze_hex("ff")
        assert result.text_utf8 is None

    def test_invalid(self) -> None:
        with pytest.raises(InvalidHexError):
            analyze_hex("zz")


class TestAnalysisResult:
    def test_binary_result_to_dict(self) -> None:
        payload = analyze("binary", "101101").to_dict()
        assert payload["application"]["name"] == "BinaryCryptoLab"
        assert payload["input"]["type"] == "binary"
        assert payload["analysis"]["integer"]["decimal"] == "45"
        assert payload["analysis"]["binary"]["length_bits"] == 6
        assert payload["analysis"]["bytes"]["frequency"] == {"45": 1}

        def keys_of(value: object) -> set[str]:
            found: set[str] = set()
            if isinstance(value, dict):
                for key, item in value.items():
                    found.add(str(key))
                    found |= keys_of(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    found |= keys_of(item)
            return found

        assert not {key for key in keys_of(payload) if key.startswith("private")}

    def test_hex_result_to_dict(self) -> None:
        payload = analyze("hex", "2D").to_dict()
        assert payload["input"]["type"] == "hex"
        assert payload["analysis"]["hexadecimal"]["value"] == "2d"
        assert payload["analysis"]["binary"]["value"] == "00101101"

    def test_padding_warning(self) -> None:
        result = analyze("binary", "101101")
        assert any("left-padded" in warning for warning in result.warnings)

    def test_leading_zero_warning(self) -> None:
        result = analyze("binary", "0101")
        assert any("Leading zero" in warning for warning in result.warnings)

    def test_odd_hex_warning(self) -> None:
        result = analyze("hex", "abc")
        assert any("odd number of digits" in warning for warning in result.warnings)

    def test_attach_hashes_and_warning(self) -> None:
        result = analyze("binary", "1")
        digest = hash_bytes(b"\x01", "sha256")
        updated = attach_hashes(result, (digest,))
        assert updated.hashes == (digest,)
        warned = attach_warning(updated, "check this")
        assert warned.warnings[-1] == "check this"
        assert result.hashes == ()  # original is unchanged

    def test_invalid_input_type(self) -> None:
        with pytest.raises(ValueError, match="input_type"):
            analyze("octal", "755")

    def test_type_alias(self) -> None:
        assert analyze("hexadecimal", "2d").input_type == "hex"
        assert analyze("bin", "10").input_type == "binary"

    def test_private_key_results_must_be_redacted(self) -> None:
        with pytest.raises(ValueError, match="redacted"):
            AnalysisResult(
                input_type="private_key",
                original_input="deadbeef",
                normalized_input="deadbeef",
            )
        result = AnalysisResult(
            input_type="private_key",
            original_input="<redacted>",
            normalized_input="<redacted>",
        )
        assert "<redacted>" in str(result.to_dict())

    def test_byte_stats_property(self) -> None:
        assert analyze("binary", "101101").byte_stats is not None
        assert analyze("hex", "2d").byte_stats is not None
