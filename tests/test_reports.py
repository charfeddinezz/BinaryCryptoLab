"""Tests for JSON and CSV report generation."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import replace
from pathlib import Path

import pytest

from binarycryptolab.analysis import analyze, attach_hashes
from binarycryptolab.bitcoin import derive_p2wpkh_address
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.exceptions import ReportGenerationError
from binarycryptolab.hashing import hash_bytes
from binarycryptolab.models.analysis_result import REDACTED, AnalysisResult
from binarycryptolab.reports import (
    render_csv,
    render_json,
    report_to_dict,
    write_csv,
    write_json,
)
from tests.vectors import ADDRESS_P2WPKH_G, PUBKEY_ONE_COMPRESSED


def _fixed_result() -> AnalysisResult:
    result = attach_hashes(analyze("binary", "101101"), (hash_bytes(b"\x2d", "sha256"),))
    return replace(result, generated_at="2026-01-01T00:00:00Z")


class TestJsonReport:
    def test_render_contains_expected_sections(self) -> None:
        payload = json.loads(render_json(_fixed_result()))
        assert payload["application"]["name"] == "BinaryCryptoLab"
        assert payload["application"]["version"]
        assert payload["application"]["generated_at_utc"] == "2026-01-01T00:00:00Z"
        assert payload["input"]["type"] == "binary"
        assert payload["input"]["normalized"] == "101101"
        assert payload["analysis"]["integer"]["decimal"] == "45"
        assert payload["analysis"]["bits"]["hamming_weight"] == 4
        assert payload["analysis"]["bytes"]["byte_length"] == 1
        assert payload["hashes"][0]["algorithm"] == "sha256"
        assert payload["warnings"]
        assert payload["security_notes"]

    def test_render_is_deterministic(self) -> None:
        first = render_json(_fixed_result())
        second = render_json(_fixed_result())
        assert first == second
        assert first.endswith("\n")
        keys = list(json.loads(first)["application"].keys())
        assert keys == sorted(keys)

    def test_render_compact(self) -> None:
        compact = render_json(_fixed_result(), indent=None)
        assert compact.count("\n") == 1

    def test_hex_report(self) -> None:
        payload = json.loads(render_json(analyze("hex", "2D")))
        assert payload["analysis"]["hexadecimal"]["value"] == "2d"
        assert payload["analysis"]["text_preview"]["utf8"] == "-"

    def test_public_key_and_address_sections(self) -> None:
        info = public_key_from_private(1)
        address = derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        result = AnalysisResult(
            input_type="public_key",
            original_input=PUBKEY_ONE_COMPRESSED,
            normalized_input=PUBKEY_ONE_COMPRESSED,
            public_key=info.as_dict(),
            address=address.as_dict(),
        )
        payload = json.loads(render_json(result))
        assert payload["public_key"]["compressed_hex"] == PUBKEY_ONE_COMPRESSED
        assert payload["bitcoin_address"]["address"] == ADDRESS_P2WPKH_G
        assert payload["bitcoin_address"]["type"] == "p2wpkh"
        assert payload["bitcoin_address"]["network"] == "mainnet"

    def test_private_key_result_is_redacted(self) -> None:
        result = AnalysisResult(
            input_type="private_key",
            original_input=REDACTED,
            normalized_input=REDACTED,
            public_key=public_key_from_private(1).as_dict(),
        )
        text = render_json(result)
        payload = json.loads(text)
        assert payload["input"]["type"] == "private_key"
        assert payload["input"]["original"] == "<redacted>"
        assert payload["input"]["normalized"] == "<redacted>"
        assert "deadbeef" not in text

    def test_invalid_result_type(self) -> None:
        with pytest.raises(ReportGenerationError, match="AnalysisResult"):
            render_json("not a result")  # type: ignore[arg-type]
        with pytest.raises(ReportGenerationError):
            report_to_dict({"not": "a result"})  # type: ignore[arg-type]

    def test_write_json_creates_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "reports" / "report.json"
        written = write_json(_fixed_result(), target)
        assert written == target
        assert json.loads(target.read_text(encoding="utf-8"))["application"]["name"] == (
            "BinaryCryptoLab"
        )
        # No temporary files are left behind.
        assert list(target.parent.glob("*.tmp")) == []

    def test_write_json_refuses_overwrite(self, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        write_json(_fixed_result(), target)
        with pytest.raises(ReportGenerationError, match="refusing to overwrite"):
            write_json(_fixed_result(), target)
        write_json(_fixed_result(), target, overwrite=True)

    def test_write_json_rejects_directory(self, tmp_path: Path) -> None:
        with pytest.raises(ReportGenerationError, match="directory"):
            write_json(_fixed_result(), tmp_path)

    def test_write_json_without_parent_creation(self, tmp_path: Path) -> None:
        with pytest.raises(ReportGenerationError, match="does not exist"):
            write_json(_fixed_result(), tmp_path / "missing" / "report.json", create_parents=False)

    def test_invalid_path_type(self) -> None:
        with pytest.raises(ReportGenerationError):
            write_json(_fixed_result(), 123)  # type: ignore[arg-type]


class TestCsvReport:
    def test_header_and_rows(self) -> None:
        text = render_csv(_fixed_result())
        rows = list(csv.reader(io.StringIO(text)))
        assert rows[0] == ["section", "key", "value"]
        mapping = {(section, key): value for section, key, value in rows[1:]}
        assert mapping[("application", "name")] == "BinaryCryptoLab"
        assert mapping[("input", "type")] == "binary"
        assert mapping[("input", "normalized")] == "101101"
        assert mapping[("bits", "hamming_weight")] == "4"
        assert mapping[("bytes", "byte_length")] == "1"
        assert mapping[("byte_frequency", "0x2d")] == "1"
        assert mapping[("hashes", "hexdigest")]
        assert ("warnings", "warning[0]") in mapping
        # Input metadata is reported once, in the "input" section.
        assert not {key for section, key in mapping if section == "report"}
        assert text.endswith("\n")

    def test_quotes_special_characters(self) -> None:
        result = analyze("hex", "2c")  # comma byte
        text = render_csv(result)
        rows = list(csv.reader(io.StringIO(text)))
        values = [row[2] for row in rows[1:] if len(row) == 3]
        assert "," in values  # parsing works even though the value contains a comma

    def test_public_key_and_address_rows(self) -> None:
        info = public_key_from_private(1)
        address = derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        result = AnalysisResult(
            input_type="public_key",
            original_input=PUBKEY_ONE_COMPRESSED,
            normalized_input=PUBKEY_ONE_COMPRESSED,
            public_key=info.as_dict(),
            address=address.as_dict(),
        )
        mapping = {
            (section, key): value
            for section, key, value in list(csv.reader(io.StringIO(render_csv(result))))[1:]
        }
        assert mapping[("public_key", "curve")] == "secp256k1"
        assert mapping[("bitcoin_address", "type")] == "p2wpkh"
        assert mapping[("bitcoin_address", "address")] == ADDRESS_P2WPKH_G

    def test_invalid_result_type(self) -> None:
        with pytest.raises(ReportGenerationError, match="AnalysisResult"):
            render_csv(object())  # type: ignore[arg-type]

    def test_write_csv(self, tmp_path: Path) -> None:
        target = tmp_path / "out" / "report.csv"
        written = write_csv(_fixed_result(), target)
        assert written == target
        assert target.read_text(encoding="utf-8").startswith("section,key,value\n")

    def test_write_csv_refuses_overwrite(self, tmp_path: Path) -> None:
        target = tmp_path / "report.csv"
        write_csv(_fixed_result(), target)
        with pytest.raises(ReportGenerationError):
            write_csv(_fixed_result(), target)
        write_csv(_fixed_result(), target, overwrite=True)
