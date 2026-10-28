"""Tests for the command-line interface.

Success cases, error cases, exit codes, report output, and protection against
private-key disclosure are all covered.  The CLI is exercised in-process; no
subprocesses, network access, or real secrets are involved.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from binarycryptolab._version import __version__
from binarycryptolab.cli import main
from binarycryptolab.hashing import ripemd160_available
from tests.vectors import (
    ADDRESS_P2PKH_G,
    ADDRESS_P2WPKH_G,
    PUBKEY_ONE_COMPRESSED,
    PUBKEY_ONE_UNCOMPRESSED,
)

CliRunner = Callable[[list[str]], "tuple[int, str, str]"]

# A synthetic, in-range scalar used only to prove it is not echoed.
SYNTHETIC_SCALAR = "0x0000000000000000000000000000000000000000000000000000000000c0ffee"


class TestTopLevel:
    def test_no_command_prints_help(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner([])
        assert code == 2
        assert "usage" in err.lower()
        assert out == ""

    def test_help_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "analyze-binary" in captured.out
        assert "SECURITY" not in captured.out  # security text lives in the epilog

    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_unknown_command_is_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["not-a-command"])
        assert excinfo.value.code == 2

    def test_module_entry_point(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "binarycryptolab", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert completed.returncode == 0
        assert __version__ in completed.stdout


class TestAnalyzeCommands:
    def test_analyze_binary(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["analyze-binary", "101101"])
        assert code == 0
        assert err == ""
        assert "Decimal          45" in out
        assert "Hexadecimal      2d" in out
        assert "weight 4" in out
        assert "Warnings:" in out

    def test_analyze_binary_prefix_and_whitespace(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["analyze-binary", " 0b1011 "])
        assert code == 0
        assert "Bit length       4" in out

    def test_analyze_binary_invalid(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["analyze-binary", "10201"])
        assert code == 1
        assert out == ""
        assert err.startswith("error:")
        assert "Traceback" not in err

    def test_analyze_binary_length_limit(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["analyze-binary", "1011", "--max-length", "3"])
        assert code == 1
        assert "too long" in err

    def test_analyze_binary_invalid_limit(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["analyze-binary", "1", "--max-length", "0"])
        assert excinfo.value.code == 2

    def test_analyze_hex(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["analyze-hex", "2D"])
        assert code == 0
        assert "Normalized         2d" in out
        assert "Integer (decimal)  45" in out
        assert "Binary             00101101" in out

    def test_analyze_hex_odd_padded_by_default(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["analyze-hex", "abc"])
        assert code == 0
        assert "odd number of digits" in out

    def test_analyze_hex_strict(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["analyze-hex", "abc", "--strict-hex"])
        assert code == 1
        assert "odd number" in err

    def test_analyze_hex_invalid(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["analyze-hex", "xyz"])
        assert code == 1
        assert "invalid character" in err

    def test_json_to_stdout(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["analyze-binary", "101101", "--format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["input"]["normalized"] == "101101"
        assert payload["application"]["version"] == __version__

    def test_json_to_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "report.json"
        code, out, _ = cli_runner(
            ["analyze-binary", "101101", "--format", "json", "--output", str(target)]
        )
        assert code == 0
        assert f"Report written to {target}" in out
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["analysis"]["integer"]["decimal"] == "45"

    def test_csv_to_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "report.csv"
        code, _, _ = cli_runner(["analyze-hex", "2D", "--format", "csv", "--output", str(target)])
        assert code == 0
        rows = list(csv.reader(io.StringIO(target.read_text(encoding="utf-8"))))
        assert rows[0] == ["section", "key", "value"]
        assert ["input", "normalized", "2d"] in rows

    def test_csv_to_stdout(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["analyze-hex", "2d", "--format", "csv"])
        assert code == 0
        assert out.startswith("section,key,value\n")

    def test_overwrite_guard(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        assert (
            cli_runner(["analyze-binary", "1", "--format", "json", "--output", str(target)])[0] == 0
        )
        code, _, err = cli_runner(
            ["analyze-binary", "1", "--format", "json", "--output", str(target)]
        )
        assert code == 1
        assert "refusing to overwrite" in err
        code, _, _ = cli_runner(
            ["analyze-binary", "1", "--format", "json", "--output", str(target), "--overwrite"]
        )
        assert code == 0


class TestHashCommand:
    def test_sha256_hex(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--algorithm", "sha256", "--hex", "2D"])
        assert code == 0
        assert "3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112" in out
        assert "Algorithm      sha256" in out

    def test_sha256_default_algorithm(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--hex", "2d"])
        assert code == 0
        assert "sha256" in out

    def test_sha512(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--algorithm", "sha512", "--text", "abc"])
        assert code == 0
        assert "ddaf35a193617abacc417349ae2041311" in out

    def test_double_sha256_binary(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--algorithm", "double-sha256", "--binary", "1"])
        assert code == 0
        assert "Digest length  32 bytes" in out

    @pytest.mark.skipif(not ripemd160_available(), reason="backend lacks RIPEMD-160")
    def test_hash160(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--algorithm", "hash160", "--text", ""])
        assert code == 0
        assert "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" in out

    def test_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "data.bin"
        path.write_bytes(b"abc")
        code, out, _ = cli_runner(["hash", "--algorithm", "sha256", "--file", str(path)])
        assert code == 0
        assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in out
        assert "data.bin" in out

    def test_missing_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        code, _, err = cli_runner(["hash", "--file", str(tmp_path / "missing.bin")])
        assert code == 1
        assert "file not found" in err

    def test_directory_instead_of_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        code, _, err = cli_runner(["hash", "--file", str(tmp_path)])
        assert code == 1
        assert "not a regular file" in err

    def test_file_size_limit(
        self, cli_runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import binarycryptolab.cli as cli_module

        monkeypatch.setattr(cli_module, "MAX_FILE_HASH_BYTES", 1)
        path = tmp_path / "big.bin"
        path.write_bytes(b"ab")
        code, _, err = cli_runner(["hash", "--file", str(path)])
        assert code == 1
        assert "too large" in err

    def test_text_is_not_echoed(self, cli_runner: CliRunner) -> None:
        secret = "correct horse battery staple"
        code, out, _ = cli_runner(["hash", "--text", secret])
        assert code == 0
        assert secret not in out

    def test_unknown_algorithm(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["hash", "--algorithm", "md5", "--hex", "2d"])
        assert code == 1
        assert "unknown hash algorithm" in err

    def test_invalid_hex(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["hash", "--hex", "zz"])
        assert code == 1
        assert "invalid character" in err

    def test_sources_are_mutually_exclusive(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["hash", "--hex", "2d", "--text", "abc"])
        assert excinfo.value.code == 2

    def test_source_is_required(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["hash"])
        assert excinfo.value.code == 2

    def test_json_report(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["hash", "--hex", "2d", "--format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["hashes"][0]["algorithm"] == "sha256"
        assert payload["input"]["type"] == "hex"


class TestPublicKeyCommand:
    def test_compressed(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["public-key", "--private-key", "1"])
        assert code == 0
        assert PUBKEY_ONE_COMPRESSED in out
        assert "Curve order (n): 0x" in out
        assert "SECURITY" in err
        assert "Traceback" not in err

    def test_uncompressed(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["public-key", "--private-key", "1", "--format", "uncompressed"])
        assert code == 0
        assert PUBKEY_ONE_UNCOMPRESSED in out
        assert PUBKEY_ONE_COMPRESSED not in out

    def test_both(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["public-key", "--private-key", "1", "--format", "both"])
        assert code == 0
        assert PUBKEY_ONE_COMPRESSED in out
        assert PUBKEY_ONE_UNCOMPRESSED in out

    def test_decimal_base(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["public-key", "--private-key", "1", "--private-key-base", "10"])
        assert code == 0
        assert PUBKEY_ONE_COMPRESSED in out

    def test_scalar_is_never_echoed(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["public-key", "--private-key", SYNTHETIC_SCALAR])
        assert code == 0
        assert "c0ffee" not in out.lower()
        assert "c0ffee" not in err.lower()

    def test_scalar_is_never_echoed_in_reports(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "key.json"
        code, _out, _ = cli_runner(
            [
                "public-key",
                "--private-key",
                SYNTHETIC_SCALAR,
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 0
        content = target.read_text(encoding="utf-8").lower()
        assert "c0ffee" not in content
        assert "<redacted>" in content
        payload = json.loads(content)
        assert payload["input"]["type"] == "private_key"
        assert payload["public_key"]["curve"] == "secp256k1"

    def test_csv_report(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["public-key", "--private-key", "1", "--report-format", "csv"])
        assert code == 0
        assert "public_key,curve,secp256k1" in out

    @pytest.mark.parametrize("scalar", ["0", "-1", "nope"])
    def test_invalid_scalars(self, cli_runner: CliRunner, scalar: str) -> None:
        code, out, err = cli_runner(["public-key", "--private-key", scalar])
        assert code == 1
        assert out == ""
        assert err.startswith("SECURITY:") or "error:" in err
        assert "Traceback" not in err

    def test_out_of_range_scalar_is_not_echoed(self, cli_runner: CliRunner) -> None:
        scalar = "ff" * 32
        code, _, err = cli_runner(["public-key", "--private-key", scalar])
        assert code == 1
        assert scalar not in err
        assert "outside the valid secp256k1 range" in err

    def test_missing_scalar_is_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["public-key"])
        assert excinfo.value.code == 2

    def test_conflicting_sources(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["public-key", "--private-key", "1", "--prompt-private-key"])
        assert excinfo.value.code == 2

    def test_prompt_is_hidden(self, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("binarycryptolab.cli.getpass.getpass", lambda prompt="": "1")
        code, out, _ = cli_runner(["public-key", "--prompt-private-key"])
        assert code == 0
        assert PUBKEY_ONE_COMPRESSED in out


class TestBitcoinAddressCommand:
    def test_p2pkh(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--type",
                "p2pkh",
                "--network",
                "mainnet",
            ]
        )
        assert code == 0
        assert ADDRESS_P2PKH_G in out
        assert "No blockchain data was queried" in out

    def test_p2wpkh(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            ["bitcoin-address", "--public-key", PUBKEY_ONE_COMPRESSED, "--type", "p2wpkh"]
        )
        assert code == 0
        assert ADDRESS_P2WPKH_G in out
        assert "0014751e76e8199196d454941c45d1b3a323f1433bd6" in out

    def test_testnet_warning(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--network",
                "testnet",
            ]
        )
        assert code == 0
        assert "testing only" in out

    def test_uncompressed_key_for_p2wpkh(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(
            ["bitcoin-address", "--public-key", PUBKEY_ONE_UNCOMPRESSED, "--type", "p2wpkh"]
        )
        assert code == 1
        assert "compressed" in err

    def test_invalid_public_key(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["bitcoin-address", "--public-key", "00"])
        assert code == 1
        assert "public key" in err

    def test_json_report(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "address.json"
        code, _, _ = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 0
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["bitcoin_address"]["address"] == ADDRESS_P2PKH_G
        assert payload["public_key"]["compressed_hex"] == PUBKEY_ONE_COMPRESSED
        assert payload["input"]["type"] == "public_key"


class TestNestedSegwitCommand:
    def test_derives_p2sh_p2wpkh(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--type",
                "p2sh-p2wpkh",
            ]
        )
        assert code == 0
        assert "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN" in out
        assert "p2sh-p2wpkh" in out
        assert "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487" in out

    def test_uncompressed_key_is_rejected(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_UNCOMPRESSED,
                "--type",
                "p2sh-p2wpkh",
            ]
        )
        assert code == 1
        assert "compressed" in err

    def test_json_report(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "nested.json"
        code, _, _ = cli_runner(
            [
                "bitcoin-address",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--type",
                "p2sh-p2wpkh",
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 0
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["bitcoin_address"]["type"] == "p2sh-p2wpkh"
        assert payload["bitcoin_address"]["script_pubkey_hex"].startswith("a914")


class TestDecodeAddressCommand:
    def test_valid_mainnet(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["decode-address", ADDRESS_P2PKH_G])
        assert code == 0
        assert "Type               p2pkh" in out
        assert "Network            mainnet" in out

    def test_testnet_ambiguity_warning(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["decode-address", "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"])
        assert code == 0
        assert "shared by testnet" in out

    def test_bech32(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["decode-address", ADDRESS_P2WPKH_G, "--network", "mainnet"])
        assert code == 0
        assert "Type               p2wpkh" in out

    def test_bad_checksum(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(["decode-address", ADDRESS_P2PKH_G[:-1] + "8"])
        assert code == 1
        assert "checksum" in err.lower()

    def test_p2sh_is_decode_only(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["decode-address", "33FFrcn4Tv1qgGEuXPkkPdr44DuWp3RzPo"])
        assert code == 0
        assert "decoded for validation only" in out

    def test_json_report(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["decode-address", ADDRESS_P2WPKH_G, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["bitcoin_address"]["type"] == "p2wpkh"
        assert payload["input"]["type"] == "address"


class TestDissectPublicKeyCommand:
    """The deep dissection command: single key, batch mode, and reports."""

    def test_text_report_sections(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED])
        assert code == 0
        assert err == ""
        assert "public key dissection" in out
        assert "Curve verification: all 10 checks passed" in out
        assert "Address matrix (16)" in out
        assert "consistent with a uniformly random public key" in out
        assert "Recoverable     : no" in out

    def test_text_report_includes_the_statistics(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED])
        assert code == 0
        assert "Randomness battery" in out
        assert "Evidence families" in out
        assert "Fisher p" in out
        assert "Bonferroni p" in out
        assert "monobit" in out
        assert "Log2 BF" not in out
        assert "log2 BF" in out

    def test_reports_the_known_addresses(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED])
        assert code == 0
        assert ADDRESS_P2PKH_G in out
        assert ADDRESS_P2WPKH_G in out
        assert "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN" in out

    def test_uncompressed_input_is_accepted(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(["dissect-public-key", "--public-key", PUBKEY_ONE_UNCOMPRESSED])
        assert code == 0
        assert "uncompressed" in out
        assert "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm" in out

    def test_invalid_key_exits_one(self, cli_runner: CliRunner) -> None:
        code, out, err = cli_runner(["dissect-public-key", "--public-key", "not-hex"])
        assert code == 1
        assert out == ""
        assert err.startswith("error: ")
        assert "not-hex" not in err

    def test_unknown_network_exits_one(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(
            ["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED, "--networks", "moonnet"]
        )
        assert code == 1
        assert "supported networks" in err

    def test_empty_network_list_exits_one(self, cli_runner: CliRunner) -> None:
        code, _, err = cli_runner(
            ["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED, "--networks", " , "]
        )
        assert code == 1
        assert "at least one network" in err

    def test_network_subset(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            [
                "dissect-public-key",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--networks",
                "mainnet,regtest",
            ]
        )
        assert code == 0
        assert "Address matrix (8)" in out
        assert "bcrt1q" in out

    def test_deep_depth_adds_detail(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            ["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED, "--depth", "deep"]
        )
        assert code == 0
        assert "compressed (base32)" in out
        assert "sha512(compressed)" in out

    def test_art_adds_bit_grids(self, cli_runner: CliRunner) -> None:
        code, out, _ = cli_runner(
            ["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED, "--art"]
        )
        assert code == 0
        assert "Bit grid (x, most significant bit first)" in out
        assert "Bit grid (y, most significant bit first)" in out

    def test_json_report(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "dissection.json"
        code, out, _ = cli_runner(
            [
                "dissect-public-key",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 0
        assert "Report written to" in out
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["public_key_forensics"]["curve"] == "secp256k1"
        assert payload["public_key_forensics"]["input"]["encoding"] == "compressed"
        assert len(payload["public_key_forensics"]["address_matrix"]) == 16
        assert payload["public_key_forensics"]["forecast"]["recoverable"] is False

    def test_csv_report(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "dissection.csv"
        code, _, _ = cli_runner(
            [
                "dissect-public-key",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--report-format",
                "csv",
                "--output",
                str(target),
            ]
        )
        assert code == 0
        rows = list(csv.reader(io.StringIO(target.read_text(encoding="utf-8"))))
        assert rows[0] == ["section", "key", "value"]
        sections = {row[0] for row in rows[1:]}
        assert "forensics.forecast" in sections
        assert any(section.startswith("forensics.address_matrix") for section in sections)
        values = {row[2] for row in rows[1:]}
        assert ADDRESS_P2PKH_G in values

    def test_refuses_to_overwrite(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "dissection.json"
        target.write_text("{}", encoding="utf-8")
        code, _, err = cli_runner(
            [
                "dissect-public-key",
                "--public-key",
                PUBKEY_ONE_COMPRESSED,
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 1
        assert "refusing to overwrite" in err
        assert target.read_text(encoding="utf-8") == "{}"

    def test_python_api_matches_the_cli(self, cli_runner: CliRunner) -> None:
        from binarycryptolab.forensics import dissect_public_key

        dissection = dissect_public_key(PUBKEY_ONE_COMPRESSED)
        code, out, _ = cli_runner(["dissect-public-key", "--public-key", PUBKEY_ONE_COMPRESSED])
        assert code == 0
        assert dissection.x.hexadecimal in out


class TestDissectBatch:
    def test_batch_text(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(
            f"# a comment\n{PUBKEY_ONE_COMPRESSED}\n\n{PUBKEY_ONE_UNCOMPRESSED}\n",
            encoding="utf-8",
        )
        code, out, err = cli_runner(["dissect-public-key", "--input-file", str(source)])
        assert code == 0
        assert err == ""
        assert "public key dissection (batch)" in out
        assert "2 key(s) analysed" in out
        assert out.count(ADDRESS_P2PKH_G) == 2

    def test_batch_json_has_indices(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\n{PUBKEY_ONE_UNCOMPRESSED}\n", encoding="utf-8")
        code, out, _ = cli_runner(
            ["dissect-public-key", "--input-file", str(source), "--report-format", "json"]
        )
        assert code == 0
        payload = json.loads(out)
        assert [entry["index"] for entry in payload] == [1, 2]
        assert payload[1]["input"]["encoding"] == "uncompressed"

    def test_batch_csv_has_key_index(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\n{PUBKEY_ONE_UNCOMPRESSED}\n", encoding="utf-8")
        code, out, _ = cli_runner(
            ["dissect-public-key", "--input-file", str(source), "--report-format", "csv"]
        )
        assert code == 0
        rows = list(csv.reader(io.StringIO(out)))
        assert rows[0] == ["key_index", "section", "key", "value"]
        assert {row[0] for row in rows[1:]} == {"1", "2"}

    def test_batch_output_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\n", encoding="utf-8")
        target = tmp_path / "out.txt"
        code, out, _ = cli_runner(
            ["dissect-public-key", "--input-file", str(source), "--output", str(target)]
        )
        assert code == 0
        assert "Report written to" in out
        assert "1 key(s) analysed" in target.read_text(encoding="utf-8")

    def test_batch_art_prints_each_key(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\n", encoding="utf-8")
        code, out, _ = cli_runner(["dissect-public-key", "--input-file", str(source), "--art"])
        assert code == 0
        assert out.count("Bit grid (x") == 1

    def test_invalid_key_in_batch_names_the_position(
        self, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\ndeadbeef\n", encoding="utf-8")
        code, _, err = cli_runner(["dissect-public-key", "--input-file", str(source)])
        assert code == 1
        assert "#2" in err
        assert "deadbeef" not in err

    def test_missing_file(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        code, _, err = cli_runner(
            ["dissect-public-key", "--input-file", str(tmp_path / "absent.txt")]
        )
        assert code == 1
        assert "does not exist" in err

    def test_file_without_keys(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text("# only a comment\n\n", encoding="utf-8")
        code, _, err = cli_runner(["dissect-public-key", "--input-file", str(source)])
        assert code == 1
        assert "no public keys" in err

    def test_directory_is_rejected(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        code, _, err = cli_runner(["dissect-public-key", "--input-file", str(tmp_path)])
        assert code == 1
        assert "is a directory" in err

    def test_batch_size_is_capped(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        from binarycryptolab.cli import MAX_BATCH_KEYS

        source = tmp_path / "keys.txt"
        source.write_text(
            "\n".join([PUBKEY_ONE_COMPRESSED] * (MAX_BATCH_KEYS + 1)) + "\n",
            encoding="utf-8",
        )
        code, _, err = cli_runner(["dissect-public-key", "--input-file", str(source)])
        assert code == 1
        assert str(MAX_BATCH_KEYS) in err

    def test_both_sources_are_exclusive(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        source = tmp_path / "keys.txt"
        source.write_text(f"{PUBKEY_ONE_COMPRESSED}\n", encoding="utf-8")
        with pytest.raises(SystemExit) as excinfo:
            cli_runner(
                [
                    "dissect-public-key",
                    "--public-key",
                    PUBKEY_ONE_COMPRESSED,
                    "--input-file",
                    str(source),
                ]
            )
        assert excinfo.value.code == 2


class TestDebugMode:
    def test_unexpected_error_hides_traceback_by_default(
        self, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import binarycryptolab.cli as cli_module

        def boom(*args: object, **kwargs: object) -> int:
            raise RuntimeError("boom")

        monkeypatch.setattr(cli_module, "_cmd_analyze_binary", boom)
        code, _, err = cli_runner(["analyze-binary", "1"])
        assert code == 1
        assert "unexpected error" in err
        assert "Traceback" not in err
        assert "run with --debug" in err

    def test_debug_shows_traceback(
        self, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import binarycryptolab.cli as cli_module

        def boom(*args: object, **kwargs: object) -> int:
            raise RuntimeError("boom")

        monkeypatch.setattr(cli_module, "_cmd_analyze_binary", boom)
        code, _, err = cli_runner(["--debug", "analyze-binary", "1"])
        assert code == 1
        assert "Traceback" in err
