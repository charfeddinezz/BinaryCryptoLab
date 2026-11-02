"""CLI tests for v1.8.0: glv-check, analyze-segments, and --segments."""

from __future__ import annotations

import csv
import io
import json

import pytest

from binarycryptolab.cli import main

GENERATOR = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TARGET = "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa"


def _parse_csv(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


class TestGlvCheck:
    """`glv-check` in every format."""

    def test_text_reports_every_check(self, cli_runner) -> None:
        code, out, err = cli_runner(["glv-check", GENERATOR])
        assert code == 0, err
        assert "GLV endomorphism verification" in out
        assert "beta_is_cube_root_of_unity" in out
        assert "sum_is_infinity" in out
        assert "all checks         pass" in out
        assert "phi(P)" in out and "phi^2(P)" in out

    def test_text_states_it_is_not_a_key_property(self, cli_runner) -> None:
        _, out, _ = cli_runner(["glv-check", GENERATOR])
        assert "curve property, not a key property" in out
        assert "property of secp256k1, not of this key" in out
        assert "2^127" in out

    def test_json(self, cli_runner) -> None:
        code, out, _ = cli_runner(["glv-check", GENERATOR, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["verified"] is True
        assert payload["three_torsion"] is True
        assert len(payload["checks"]) == 8
        assert payload["phi_hex"] == (
            "02bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb"
        )

    def test_csv(self, cli_runner) -> None:
        code, out, _ = cli_runner(["glv-check", GENERATOR, "--report-format", "csv"])
        assert code == 0
        rows = _parse_csv(out)
        assert len(rows) == 8
        assert rows[0]["code"] == "beta_is_cube_root_of_unity"
        assert all(row["passed"] == "yes" for row in rows)

    def test_invalid_key_fails_cleanly(self, cli_runner) -> None:
        code, _, err = cli_runner(["glv-check", "02" + "00" * 32])
        assert code == 1
        assert "error:" in err

    def test_help_is_discoverable(self, capsys) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "glv-check" in out
        assert "analyze-segments" in out


class TestAnalyzeSegments:
    """`analyze-segments` in every format."""

    def test_text_has_all_four_widths(self, cli_runner) -> None:
        code, out, err = cli_runner(
            ["analyze-segments", "70542a0b4e6776be4ba75e4d975ec8de3333fecc"]
        )
        assert code == 0, err
        for width in (8, 16, 32, 64):
            assert f"{width}-bit segments" in out
        assert "Byte reversal" in out
        assert "Bit autocorrelation" in out
        assert "fold XOR" in out

    def test_zero_fold_is_reported_as_a_signal(self, cli_runner) -> None:
        code, out, _ = cli_runner(["analyze-segments", "deadbeefdeadbeef", "--widths", "32"])
        assert code == 0
        assert "0x00000000" in out
        assert "worth inspecting" in out

    def test_binary_encoding(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["analyze-segments", "0000000011111111", "--encoding", "binary", "--widths", "8"]
        )
        assert code == 0
        assert "8-bit segments (2)" in out

    def test_widths_and_lags_are_configurable(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["analyze-segments", "00112233", "--widths", "16", "--lags", "1,2"]
        )
        assert code == 0
        assert "16-bit segments (2)" in out
        assert "32-bit segments" not in out
        assert "Lag" in out

    def test_json(self, cli_runner) -> None:
        code, out, _ = cli_runner(["analyze-segments", "70542a0b", "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["byte_length"] == 4
        assert payload["bit_length"] == 32
        assert payload["widths"][0]["segments"][0]["hex"] == "70"
        assert payload["zero_folds"] == []
        assert isinstance(payload["notes"], list)

    def test_csv(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["analyze-segments", "00112233", "--report-format", "csv", "--widths", "16"]
        )
        assert code == 0
        rows = _parse_csv(out)
        assert len(rows) == 2
        assert rows[0]["width_bits"] == "16"
        assert rows[0]["hex"] == "0011"
        assert rows[0]["value_decimal"] == "17"

    def test_bad_width_fails_cleanly(self, cli_runner) -> None:
        code, _, err = cli_runner(["analyze-segments", "0011", "--widths", "12"])
        assert code == 1
        assert "error:" in err

    def test_non_integer_width_fails_cleanly(self, cli_runner) -> None:
        code, _, err = cli_runner(["analyze-segments", "0011", "--widths", "wide"])
        assert code == 1
        assert "error:" in err

    def test_empty_input_fails_cleanly(self, cli_runner) -> None:
        code, _, err = cli_runner(["analyze-segments", ""])
        assert code == 1
        assert "error:" in err

    def test_output_file_round_trip(self, cli_runner, tmp_path) -> None:
        target = tmp_path / "segments.json"
        code, _, err = cli_runner(
            [
                "analyze-segments",
                "00112233",
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 0, err
        assert json.loads(target.read_text())["byte_length"] == 4


class TestSegmentsFlagOnAnalysis:
    """`--segments` wires the same report into analyze-hex and analyze-binary."""

    def test_hex_flag_appends_the_section(self, cli_runner) -> None:
        code, out, err = cli_runner(["analyze-hex", "70542a0b", "--segments"])
        assert code == 0, err
        assert "segmentation analysis" in out
        assert "Byte reversal" in out

    def test_without_flag_the_section_is_absent(self, cli_runner) -> None:
        _, out, _ = cli_runner(["analyze-hex", "70542a0b"])
        assert "segmentation analysis" not in out

    def test_binary_flag_appends_the_section(self, cli_runner) -> None:
        code, out, err = cli_runner(["analyze-binary", "0000000011111111", "--segments"])
        assert code == 0, err
        assert "segmentation analysis" in out

    def test_json_carries_the_report_in_extra(self, cli_runner) -> None:
        code, out, _ = cli_runner(["analyze-hex", "00112233", "--segments", "--format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["extra"]["segmentation"]["byte_length"] == 4


class TestAddressSegmentation:
    """The target address report carries the payload segmentation."""

    def test_text_section(self, cli_runner) -> None:
        code, out, err = cli_runner(["dissect-address", TARGET])
        assert code == 0, err
        assert "Payload segmentation (word folds)" in out
        assert "0xf6" in out
        assert "byte reversal: not a palindrome" in out

    def test_json_section(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", TARGET, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        segmentation = payload["segmentation"]
        assert segmentation["byte_length"] == 20
        assert segmentation["bit_length"] == 160
        assert segmentation["zero_folds"] == []
        assert [item["width_bits"] for item in segmentation["widths"]] == [8, 16, 32, 64]

    def test_public_key_dissection_has_glv(self, cli_runner) -> None:
        code, out, err = cli_runner(["dissect-public-key", "--public-key", GENERATOR])
        assert code == 0, err
        assert "GLV endomorphism (curve property, not a key property)" in out
        assert "verified : yes" in out

    def test_public_key_dissection_json_has_glv(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["dissect-public-key", "--public-key", GENERATOR, "--report-format", "json"]
        )
        assert code == 0
        payload = json.loads(out)
        glv = payload["public_key_forensics"]["glv"]
        assert glv["verified"] is True
        assert glv["speedup_factor"] == 2
