"""Tests for the segmentation / folding / autocorrelation module."""

from __future__ import annotations

import pytest

from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.segmentation import (
    AUTOCORRELATION_LAGS,
    DEFAULT_WIDTHS,
    bit_autocorrelation,
    segmentation_report,
)

PAYLOAD = bytes.fromhex("70542a0b4e6776be4ba75e4d975ec8de3333fecc")


class TestSegments:
    """Cutting into words."""

    def test_default_widths(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert tuple(analysis.width for analysis in report.widths) == DEFAULT_WIDTHS

    def test_eight_bit_segments_are_the_bytes(self) -> None:
        report = segmentation_report(PAYLOAD, widths=(8,))
        segments = report.widths[0].segments
        assert [segment.hex for segment in segments] == [f"{byte:02x}" for byte in PAYLOAD]
        assert [segment.value for segment in segments] == list(PAYLOAD)

    def test_sixty_four_bit_cut_marks_the_tail_incomplete(self) -> None:
        report = segmentation_report(PAYLOAD, widths=(64,))
        analysis = report.widths[0]
        assert analysis.segment_count == 3
        assert analysis.complete is False
        assert analysis.segments[-1].complete is False
        assert analysis.segments[-1].bits == 32
        assert "short" in analysis.note

    def test_exact_multiple_is_complete(self) -> None:
        analysis = segmentation_report(bytes(16), widths=(64,)).widths[0]
        assert analysis.complete is True
        assert analysis.segment_count == 2

    def test_values_are_big_endian(self) -> None:
        analysis = segmentation_report(bytes.fromhex("0102"), widths=(16,)).widths[0]
        assert analysis.segments[0].value == 0x0102

    def test_fold_of_empty_list_case_is_the_single_segment(self) -> None:
        analysis = segmentation_report(bytes.fromhex("dead"), widths=(16,)).widths[0]
        assert analysis.fold_xor == 0xDEAD
        assert "single segment" in analysis.note


class TestFolding:
    """XOR folding, the one place this module can raise a signal."""

    def test_repeated_segments_fold_to_zero(self) -> None:
        report = segmentation_report(bytes.fromhex("deadbeefdeadbeef"), widths=(32,))
        assert report.widths[0].fold_xor == 0
        assert 32 in report.zero_folds
        assert "fold to zero" in report.widths[0].note
        assert "worth inspecting" in report.verdict

    def test_odd_repetition_does_not_fold_to_zero(self) -> None:
        report = segmentation_report(bytes.fromhex("deadbeefdeadbeefdeadbeef"), widths=(32,))
        assert report.widths[0].fold_xor == 0xDEADBEEF
        assert report.zero_folds == ()

    def test_two_equal_halves_fold_to_zero(self) -> None:
        data = bytes.fromhex("00112233") + bytes.fromhex("00112233")
        assert segmentation_report(data, widths=(32,)).zero_folds == (32,)

    def test_incomplete_widths_never_report_a_zero_fold(self) -> None:
        report = segmentation_report(PAYLOAD, widths=(64,))
        assert report.widths[0].fold_xor != 0
        assert 64 not in report.zero_folds

    def test_adjacent_relations_are_complete(self) -> None:
        analysis = segmentation_report(bytes(8), widths=(16,)).widths[0]
        assert len(analysis.adjacent_xor) == analysis.segment_count - 1
        assert len(analysis.adjacent_difference) == analysis.segment_count - 1
        for (left, right, value), (_, _, difference) in zip(
            analysis.adjacent_xor, analysis.adjacent_difference, strict=True
        ):
            assert right == left + 1
            assert isinstance(value, int)
            assert isinstance(difference, int)

    def test_typical_digest_has_no_zero_fold(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert report.zero_folds == ()
        assert "expected result" in report.verdict


class TestReversal:
    """The input against its own byte reversal."""

    def test_palindrome_is_detected(self) -> None:
        report = segmentation_report(bytes.fromhex("01020201"))
        assert report.reversal.is_palindrome is True
        assert report.reversal.xor_hex == "00000000"

    def test_non_palindrome_is_not_called_a_palindrome(self) -> None:
        report = segmentation_report(bytes.fromhex("abba"))
        assert report.reversal.is_palindrome is False
        assert report.reversal.reversed_hex == "baab"

    def test_reversal_round_trips(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert bytes.fromhex(report.reversal.reversed_hex) == PAYLOAD[::-1]
        assert report.reversal.is_palindrome is False

    def test_xor_is_positionwise(self) -> None:
        report = segmentation_report(bytes.fromhex("0102"))
        assert report.reversal.xor_hex == "0303"


class TestAutocorrelation:
    """Lag comparison of the bit string."""

    def test_default_lags(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert tuple(item.lag for item in report.autocorrelation) == AUTOCORRELATION_LAGS

    def test_identical_to_itself_at_every_lag_is_one(self) -> None:
        bits = "01010101" * 4
        results = bit_autocorrelation(bits, lags=(1, 2))
        assert results[0].ratio == 0.0  # alternating string disagrees with itself at lag 1
        assert results[1].ratio == 1.0

    def test_constant_string_agrees_everywhere(self) -> None:
        results = bit_autocorrelation("1" * 32, lags=(1, 8, 16))
        assert all(item.ratio == 1.0 for item in results)

    def test_lag_at_or_beyond_length_is_skipped(self) -> None:
        assert bit_autocorrelation("10", lags=(2, 5, 0)) == ()

    def test_counts_are_consistent(self) -> None:
        report = segmentation_report(PAYLOAD)
        for item in report.autocorrelation:
            assert item.comparisons == report.bit_length - item.lag
            assert item.matches <= item.comparisons
            assert item.deviation == pytest.approx(item.ratio - 0.5)

    def test_empty_bits_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            bit_autocorrelation("")


class TestBalance:
    """Bit balance and run counting."""

    def test_all_ones_is_lopsided(self) -> None:
        report = segmentation_report(b"\xff" * 8)
        assert report.ones == 64
        assert report.zeros == 0
        assert report.balance_p_value < 1e-10
        assert "lop-sided" in report.verdict

    def test_alternating_bits(self) -> None:
        report = segmentation_report(bytes.fromhex("aa"))
        assert report.transitions == 7
        assert report.runs == 8
        assert report.longest_run == 1

    def test_runs_of_a_known_pattern(self) -> None:
        report = segmentation_report(bytes.fromhex("f0"))
        assert report.ones == 4
        assert report.runs == 2
        assert report.longest_run == 4

    def test_typical_payload_is_balanced(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert report.balance_p_value > 0.01

    def test_transitions_bound(self) -> None:
        report = segmentation_report(PAYLOAD)
        assert 0 <= report.transitions <= report.bit_length - 1


class TestValidationAndSerialization:
    """Input handling and JSON readiness."""

    def test_empty_input_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            segmentation_report(b"")

    @pytest.mark.parametrize("width", [0, -8, 7, 12])
    def test_bad_width_rejected(self, width: int) -> None:
        with pytest.raises(InputValidationError):
            segmentation_report(b"\x01", widths=(width,))

    def test_no_widths_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            segmentation_report(b"\x01", widths=())

    def test_json_ready(self) -> None:
        payload = segmentation_report(PAYLOAD).as_dict()
        assert payload["byte_length"] == 20
        assert payload["bit_length"] == 160
        assert len(payload["widths"]) == 4
        assert payload["widths"][0]["segments"][0]["hex"] == "70"
        assert payload["zero_folds"] == []
        assert payload["reversal"]["is_palindrome"] is False
        assert payload["autocorrelation"][0]["lag"] == 1

    def test_accepts_bytes_like_inputs(self) -> None:
        assert segmentation_report(bytearray(PAYLOAD)).byte_length == 20
        assert segmentation_report(memoryview(PAYLOAD)).byte_length == 20

    def test_notes_state_the_null_result(self) -> None:
        notes = " ".join(segmentation_report(PAYLOAD).notes)
        assert "non-zero fold is the normal outcome" in notes
        assert "no null distribution" in notes
