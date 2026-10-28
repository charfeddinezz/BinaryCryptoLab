"""Tests for hexadecimal segmentation, the information ledger, and bounded assembly.

Every solved fixture uses a scalar the test itself chose, so the expected value is
known independently of the code under test.  The tests also assert the honesty
properties: the scalar never appears in ``repr``, the default serialisation is
redacted, and searches above the documented budget are refused rather than
attempted.
"""

from __future__ import annotations

import json
import math

import pytest

from binarycryptolab.ecc import CURVE_ORDER, public_key_from_private
from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.key_reconstruction import (
    HEX_DIGITS,
    MAX_UNKNOWN_BITS,
    ComparisonReport,
    HexSegment,
    InformationLedger,
    KeyTemplate,
    LedgerEntry,
    TemplateSolution,
    assemble_hex,
    build_ledger,
    compare_keys,
    interval_entry,
    parse_template,
    residue_entry,
    segment_bits,
    segment_hex,
    solve_offset,
    solve_template,
)

#: A scalar whose first 58 hex digits are distinctive and whose last 24 bits vary.
TAIL_SCALAR = int("c0ffee" + "0" * 50 + "abcdef", 16)

#: A scalar used for a template whose unknown window sits in the middle.
MIDDLE_SCALAR = int("1234567890abcdef" * 4, 16)


def _public_key(scalar: int) -> str:
    """Return the compressed public key for a test scalar."""
    return public_key_from_private(scalar).compressed_hex


def _tail_template() -> str:
    """Return a template that hides the last 24 bits of :data:`TAIL_SCALAR`."""
    return f"{TAIL_SCALAR:064x}"[:58] + "?" * 6


def _middle_template() -> str:
    """Return a template that hides eight nibbles in the middle of the scalar."""
    text = f"{MIDDLE_SCALAR:064x}"
    return text[:8] + "?" * 8 + text[16:]


class TestSegmentation:
    """Splitting hexadecimal values into comparable pieces."""

    def test_nibbles(self) -> None:
        segments = segment_hex("0f", unit=1)
        assert [segment.digits for segment in segments] == ["0", "f"]
        assert [segment.value for segment in segments] == [0, 15]
        assert [segment.start_bit for segment in segments] == [0, 4]

    def test_bytes_words_and_limbs(self) -> None:
        assert [segment.digits for segment in segment_hex("deadbeef", unit=2)] == [
            "de",
            "ad",
            "be",
            "ef",
        ]
        assert [segment.digits for segment in segment_hex("deadbeef", unit=4)] == ["dead", "beef"]
        assert [segment.digits for segment in segment_hex("deadbeef" * 2, unit=16)] == [
            "deadbeef" * 2
        ]

    def test_labels_and_widths(self) -> None:
        segment = segment_hex("abcd", unit=2)[1]
        assert isinstance(segment, HexSegment)
        assert segment.label == "8-bit segment 1"
        assert segment.width_bits == 8
        assert segment.start_bit == 8

    def test_accepts_prefix_case_and_whitespace(self) -> None:
        assert [s.digits for s in segment_hex(" 0xABCD ", unit=2)] == ["ab", "cd"]

    def test_segment_bits_uses_a_fixed_width(self) -> None:
        segments = segment_bits(1, width=16, unit=1)
        assert "".join(segment.digits for segment in segments) == "0001"
        assert len(segments) == 4
        assert segments[-1].value == 1

    @pytest.mark.parametrize("unit", [0, 3, 5, 32])
    def test_rejects_unsupported_units(self, unit: int) -> None:
        with pytest.raises(InputValidationError):
            segment_hex("abcd", unit=unit)

    def test_rejects_odd_length_for_bytes(self) -> None:
        with pytest.raises(InputValidationError):
            segment_hex("abc", unit=2)

    def test_rejects_non_hex(self) -> None:
        with pytest.raises(InputValidationError):
            segment_hex("zz")
        with pytest.raises(InputValidationError):
            segment_hex("")

    def test_segment_bits_rejects_oversized_values(self) -> None:
        with pytest.raises(InputValidationError):
            segment_bits(256, width=8)

    def test_as_dict(self) -> None:
        payload = segment_hex("ff", unit=1)[0].as_dict()
        assert payload == {
            "label": "4-bit segment 0",
            "digits": "f",
            "start_bit": 0,
            "width_bits": 4,
            "value": 15,
        }


class TestTemplates:
    """Parsing and validating 64-digit patterns."""

    def test_parses_a_tail_window(self) -> None:
        template = parse_template(_tail_template())
        assert isinstance(template, KeyTemplate)
        assert template.known_digits == 58
        assert template.unknown_bits == 24
        assert template.low_bits == 0
        assert template.unknown_start == 232
        assert template.known_bits == 232
        assert template.known_value == TAIL_SCALAR & ~0xFFFFFF

    def test_parses_a_middle_window(self) -> None:
        template = parse_template(_middle_template())
        assert template.unknown_bits == 32
        assert template.unknown_start == 32
        assert template.low_bits == 192
        assert template.known_bits == 224

    def test_accepts_separators_and_prefix(self) -> None:
        grouped = " ".join(["0000"] * 15 + ["????"])
        template = parse_template("0x" + grouped.replace(" ", ":"))
        assert template.pattern == "0" * 60 + "?" * 4
        assert template.unknown_bits == 16

    def test_render_groups_digits(self) -> None:
        rendered = parse_template(_tail_template()).render()
        assert len(rendered.split()) == 16
        assert "?" in rendered

    @pytest.mark.parametrize(
        "pattern",
        [
            "",
            "0" * 63,
            "0" * 65,
            "0" * 60 + "????" + "x" + "0",
            "0" * 30 + "??" + "0" * 10 + "??" + "0" * 18,
            "?" * 64,
            "f" * 64,
        ],
    )
    def test_rejects_invalid_patterns(self, pattern: str) -> None:
        with pytest.raises(InputValidationError):
            parse_template(pattern)

    def test_as_dict_has_no_scalar(self) -> None:
        payload = parse_template(_tail_template()).as_dict()
        assert set(payload) == {
            "pattern",
            "known_digits",
            "known_bits",
            "unknown_bits",
            "unknown_start",
            "low_bits",
        }
        assert len(payload["pattern"]) == HEX_DIGITS


class TestAssembly:
    """Placing a solved value into the template."""

    def test_assemble_returns_the_scalar(self) -> None:
        template = parse_template(_tail_template())
        unknown = TAIL_SCALAR & 0xFFFFFF
        assert template.assemble(unknown) == TAIL_SCALAR
        assert assemble_hex(template, unknown) == f"{TAIL_SCALAR:064x}"

    def test_assemble_rejects_out_of_window(self) -> None:
        template = parse_template(_tail_template())
        with pytest.raises(InputValidationError):
            template.assemble(1 << 24)
        with pytest.raises(InputValidationError):
            template.assemble(-1)

    def test_assemble_rejects_non_integer(self) -> None:
        template = parse_template(_tail_template())
        with pytest.raises(InputValidationError):
            template.assemble("1")  # type: ignore[arg-type]

    def test_search_cost_is_half_the_window(self) -> None:
        assert parse_template(_middle_template()).search_operations_log2 == 16.0


class TestLedger:
    """One scale: how many of the 256 bits are known."""

    def test_known_and_unknown_are_complementary(self) -> None:
        ledger = build_ledger(parse_template(_tail_template()))
        assert ledger.known_bits == 232
        assert ledger.unknown_bits == 24
        assert ledger.space_bits == 256
        assert ledger.feasible

    def test_public_data_is_valued_at_zero_bits(self) -> None:
        ledger = build_ledger()
        assert ledger.known_bits == 0
        assert ledger.unknown_bits == 256
        assert not ledger.feasible
        zero_entries = [entry for entry in ledger.entries if entry.bits == 0.0]
        assert len(zero_entries) == 3
        assert any("discrete logarithm" in entry.note for entry in zero_entries)

    def test_residue_entry(self) -> None:
        entry = residue_entry(7, 1024)
        assert entry.bits == pytest.approx(10.0)
        assert "1024" in entry.label

    def test_interval_entry(self) -> None:
        entry = interval_entry(0, 1 << 40)
        assert entry.bits == pytest.approx(216.0)

    def test_extra_information_reduces_the_window(self) -> None:
        template = parse_template(_middle_template())
        base = build_ledger(template)
        enriched = build_ledger(template, extra=(residue_entry(5, 4096),))
        assert enriched.known_bits == base.known_bits + 12
        assert enriched.unknown_bits == base.unknown_bits - 12

    def test_known_bits_never_exceed_the_space(self) -> None:
        template = parse_template(_tail_template())
        ledger = build_ledger(
            template, extra=(interval_entry(0, 1 << 40), residue_entry(1, 1 << 40))
        )
        assert ledger.known_bits == 256
        assert ledger.unknown_bits == 0
        assert ledger.verdict == "the scalar is fully determined by the known information"

    def test_feasibility_boundary(self) -> None:
        template = parse_template(f"{0:060x}" + "????")
        assert build_ledger(template, solvable_bits=16).feasible
        assert not build_ledger(template, solvable_bits=8).feasible

    def test_search_cost(self) -> None:
        ledger = build_ledger(parse_template(_tail_template()))
        assert ledger.search_operations_log2 == pytest.approx(12.0)
        assert "searchable" in ledger.verdict

    def test_rejects_bad_budget(self) -> None:
        for budget in (0, -1, MAX_UNKNOWN_BITS + 1):
            with pytest.raises(InputValidationError):
                build_ledger(solvable_bits=budget)

    def test_rejects_bad_residue_and_interval(self) -> None:
        with pytest.raises(InputValidationError):
            residue_entry(5, 1)
        with pytest.raises(InputValidationError):
            residue_entry(99, 7)
        with pytest.raises(InputValidationError):
            interval_entry(10, 10)

    def test_as_dict(self) -> None:
        payload = build_ledger(parse_template(_tail_template())).as_dict()
        assert payload["known_bits"] == 232.0
        assert payload["unknown_bits"] == 24.0
        assert payload["feasible"] is True
        assert len(payload["entries"]) == 4
        assert isinstance(payload["verdict"], str)


class TestSolveTemplate:
    """The bounded baby-step/giant-step assembly."""

    def test_tail_window(self) -> None:
        solution = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        assert isinstance(solution, TemplateSolution)
        assert solution.solved
        assert solution.verified
        assert solution.assembled_hex == f"{TAIL_SCALAR:064x}"
        assert solution.unknown_value == TAIL_SCALAR & 0xFFFFFF
        assert solution.steps == math.isqrt((1 << 24) - 1) + 1
        assert solution.elapsed_seconds >= 0.0
        assert "assembled and verified" in solution.message

    def test_middle_window(self) -> None:
        solution = solve_template(_public_key(MIDDLE_SCALAR), _middle_template())
        assert solution.solved
        assert solution.assembled_hex == f"{MIDDLE_SCALAR:064x}"
        assert solution.template.low_bits == 192

    def test_template_object_and_pattern_agree(self) -> None:
        by_pattern = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        by_object = solve_template(_public_key(TAIL_SCALAR), parse_template(_tail_template()))
        assert by_pattern.assembled_hex == by_object.assembled_hex

    def test_wrong_public_key_is_not_solved(self) -> None:
        solution = solve_template(_public_key(MIDDLE_SCALAR), _tail_template())
        assert not solution.solved
        assert solution.assembled_hex is None
        assert "no value in the unknown window" in solution.message

    def test_budget_refusal(self) -> None:
        wide = "0" * 32 + "?" * 32
        with pytest.raises(InputValidationError) as error:
            solve_template(_public_key(TAIL_SCALAR), wide, max_unknown_bits=16)
        message = str(error.value)
        assert "128 unknown bits" in message
        assert "not attack the full keyspace" in message
        assert f"{TAIL_SCALAR:064x}" not in message

    def test_budget_is_capped(self) -> None:
        with pytest.raises(InputValidationError):
            solve_template(_public_key(1), _tail_template(), max_unknown_bits=MAX_UNKNOWN_BITS + 1)
        with pytest.raises(InputValidationError):
            solve_template(_public_key(1), _tail_template(), max_unknown_bits=0)

    def test_invalid_public_key(self) -> None:
        with pytest.raises(InputValidationError):
            solve_template("not-a-key", _tail_template())

    def test_default_serialisation_is_redacted(self) -> None:
        solution = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        payload = solution.as_dict()
        assert payload["assembled_scalar_hex"] is None
        assert payload["unknown_window_value"] is None
        assert payload["redacted"] is True
        assert payload["solved"] is True
        text = json.dumps(payload)
        assert f"{TAIL_SCALAR:064x}" not in text

    def test_reveal_includes_the_scalar(self) -> None:
        solution = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        payload = solution.as_dict(reveal=True)
        assert payload["assembled_scalar_hex"] == f"{TAIL_SCALAR:064x}"
        assert payload["unknown_window_value"] == TAIL_SCALAR & 0xFFFFFF
        assert payload["redacted"] is False

    def test_repr_never_contains_the_scalar(self) -> None:
        solution = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        text = repr(solution)
        assert f"{TAIL_SCALAR:064x}" not in text
        assert "abcdef" not in text

    def test_ledger_is_attached(self) -> None:
        solution = solve_template(_public_key(TAIL_SCALAR), _tail_template())
        assert isinstance(solution.ledger, InformationLedger)
        assert solution.ledger.unknown_bits == 24
        assert solution.ledger.feasible


class TestOffsets:
    """Related-key differences."""

    def test_positive_offset(self) -> None:
        base = 987654
        assert solve_offset(_public_key(base), _public_key(base + 4242), max_delta_bits=16) == 4242

    def test_negative_offset(self) -> None:
        base = 987654
        assert solve_offset(_public_key(base), _public_key(base - 4242), max_delta_bits=16) == -4242

    def test_offset_outside_the_window(self) -> None:
        base = 987654
        assert solve_offset(_public_key(base), _public_key(base + 100000), max_delta_bits=8) is None

    def test_negated_key_is_an_offset_of_two(self) -> None:
        # Q_(n-1) = -G = G - 2G, so this pair really does differ by -2.
        assert solve_offset(_public_key(1), _public_key(CURVE_ORDER - 1), max_delta_bits=8) == -2

    def test_unrelated_keys_have_no_small_offset(self) -> None:
        assert solve_offset(_public_key(1), _public_key(2**200), max_delta_bits=8) is None

    def test_budget_validation(self) -> None:
        with pytest.raises(InputValidationError):
            solve_offset(_public_key(1), _public_key(2), max_delta_bits=0)
        with pytest.raises(InputValidationError):
            solve_offset(_public_key(1), _public_key(2), max_delta_bits=MAX_UNKNOWN_BITS + 1)


class TestCompareKeys:
    """Segmenting and comparing a key set."""

    def test_detects_sequential_keys(self) -> None:
        keys = [_public_key(1000 + step) for step in range(4)]
        report = compare_keys(keys, max_delta_bits=12)
        assert isinstance(report, ComparisonReport)
        assert report.count == 4
        assert report.pairs_examined == 6
        assert not report.truncated
        found = {(item.left, item.right, item.delta) for item in report.relationships}
        assert (1, 2, 1) in found
        assert (1, 3, 2) in found
        assert (2, 4, 2) in found
        assert all(item.verified for item in report.relationships)

    def test_agreement_invariants(self) -> None:
        report = compare_keys([_public_key(11), _public_key(22), _public_key(33)])
        assert len(report.nibble_agreement) == 64
        assert all(1 <= value <= 3 for value in report.nibble_agreement)
        assert report.shared_prefix_nibbles == 0
        assert report.shared_suffix_nibbles == 0
        assert len(report.pairwise_hamming) == 3

    def test_hamming_distance_is_bounded(self) -> None:
        report = compare_keys([_public_key(5), _public_key(6)])
        left, right, distance = report.pairwise_hamming[0]
        assert (left, right) == (1, 2)
        assert 0 <= distance <= 256

    def test_unrelated_keys_have_no_relationship(self) -> None:
        report = compare_keys([_public_key(1), _public_key(2**200)], max_delta_bits=8)
        assert report.relationships == ()

    def test_pair_cap_truncates(self) -> None:
        report = compare_keys([_public_key(step) for step in (10, 20, 30, 40)], max_pairs=2)
        assert report.truncated
        assert report.pairs_examined == 2

    def test_requires_two_keys(self) -> None:
        with pytest.raises(InputValidationError):
            compare_keys([_public_key(1)])

    def test_reports_the_index_of_a_bad_key(self) -> None:
        with pytest.raises(InputValidationError) as error:
            compare_keys([_public_key(1), "zz"])
        assert "#2" in str(error.value)

    def test_notes_explain_the_limits(self) -> None:
        report = compare_keys([_public_key(7), _public_key(8)])
        assert len(report.notes) == 4
        assert any("discrete logarithm" in note for note in report.notes)

    def test_as_dict_round_trips(self) -> None:
        payload = compare_keys([_public_key(3), _public_key(4)], max_delta_bits=8).as_dict()
        assert set(payload) == {
            "count",
            "nibble_agreement",
            "shared_prefix_nibbles",
            "shared_suffix_nibbles",
            "pairwise_hamming",
            "relationships",
            "pairs_examined",
            "truncated",
            "notes",
        }
        assert json.dumps(payload)


class TestLedgerEntry:
    """The small value object used by the ledger."""

    def test_as_dict(self) -> None:
        entry = LedgerEntry(label="x", bits=4.0, note="n")
        assert entry.as_dict() == {"label": "x", "bits": 4.0, "note": "n"}
