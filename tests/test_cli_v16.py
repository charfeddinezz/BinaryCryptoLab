"""CLI tests for the v1.6.0 surfaces: redeem scripts, xpubs, stdin, prefix models."""

from __future__ import annotations

import csv
import io
import json

import pytest

from binarycryptolab.base58 import base58check_encode
from binarycryptolab.cli import main
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.hashing import hash160
from binarycryptolab.hd_keys import derive_address, parse_extended_public_key

XPUB = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

KEY_1 = "02" + "11" * 32
KEY_2 = "02" + "22" * 32
KEY_3 = "03" + "33" * 32
MULTISIG = "52" + "21" + KEY_1 + "21" + KEY_2 + "21" + KEY_3 + "53" + "ae"
MULTISIG_P2SH = base58check_encode(b"\x05" + hash160(bytes.fromhex(MULTISIG)))


class TestRedeemScript:
    """--redeem-script."""

    def test_verified_multisig(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", MULTISIG_P2SH, "--redeem-script", MULTISIG])
        assert code == 0
        assert "Redeem-script claim" in out
        assert "template        multisig" in out
        assert "2-of-3" in out
        assert "verified        YES" in out
        assert "HASH160" in out

    def test_rejected_script(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", MULTISIG_P2SH, "--redeem-script", "51"])
        assert code == 0
        assert "verified        no" in out
        assert "not a match" in out

    def test_htlc_classification(self, cli_runner) -> None:
        htlc = (
            "63"
            + "a9"
            + "14"
            + "aa" * 20
            + "88"
            + "75"
            + "76a914"
            + "bb" * 20
            + "88ac"
            + "67"
            + "21"
            + KEY_1
            + "ac"
            + "68"
        )
        address = base58check_encode(b"\x05" + hash160(bytes.fromhex(htlc)))
        code, out, _ = cli_runner(["dissect-address", address, "--redeem-script", htlc])
        assert code == 0
        assert "template        htlc" in out
        assert "hash lock" in out
        assert "spend paths" in out

    def test_timelock_classification(self, cli_runner) -> None:
        script = "04" + "ffff0000" + "b1" + "75" + "21" + KEY_1 + "ac"
        address = base58check_encode(b"\x05" + hash160(bytes.fromhex(script)))
        code, out, _ = cli_runner(["dissect-address", address, "--redeem-script", script])
        assert code == 0
        assert "template        timelock" in out
        assert "65535 (height)" in out

    def test_malformed_script_is_an_error(self, cli_runner) -> None:
        code, _, err = cli_runner(["dissect-address", MULTISIG_P2SH, "--redeem-script", "21aabb"])
        assert code == 1
        assert "truncated" in err.lower()

    def test_json_contains_the_claim(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "dissect-address",
                MULTISIG_P2SH,
                "--redeem-script",
                MULTISIG,
                "--report-format",
                "json",
            ]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["script_claim"]["matches"] is True
        assert payload["script_claim"]["template"]["threshold"] == 2
        assert payload["script_claim"]["proves_membership"] is True

    def test_csv_marks_the_claim(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "dissect-address",
                MULTISIG_P2SH,
                "--redeem-script",
                MULTISIG,
                "--report-format",
                "csv",
            ]
        )
        assert code == 0
        rows = list(csv.DictReader(io.StringIO(out)))
        assert rows[0]["script_claim"] == "match"


class TestXpub:
    """--xpub and --index-range."""

    def test_match_is_found(self, cli_runner) -> None:
        address = derive_address(parse_extended_public_key(XPUB), 7)
        code, out, _ = cli_runner(
            ["dissect-address", address, "--xpub", XPUB, "--index-range", "0:20"]
        )
        assert code == 0
        assert "Extended public key search" in out
        assert "match            index 7 (m/7)" in out
        assert "indices checked  8" in out

    def test_no_match_is_reported(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "dissect-address",
                "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb",
                "--xpub",
                XPUB,
                "--index-range",
                "0:5",
            ]
        )
        assert code == 0
        assert "match            none" in out
        assert "does not prove" in out

    def test_range_narrows_the_search(self, cli_runner) -> None:
        address = derive_address(parse_extended_public_key(XPUB), 3)
        code, out, _ = cli_runner(
            ["dissect-address", address, "--xpub", XPUB, "--index-range", "5:5"]
        )
        assert code == 0
        assert "match            none" in out

    def test_public_derivation_only_note(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["dissect-address", derive_address(parse_extended_public_key(XPUB), 1), "--xpub", XPUB]
        )
        assert code == 0
        assert "public derivation only" in out.lower()

    def test_private_extension_is_refused(self, cli_runner) -> None:
        xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        code, out, err = cli_runner(
            ["dissect-address", "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb", "--xpub", xprv]
        )
        assert code == 1
        assert xprv not in out
        assert xprv not in err
        assert "private" in err.lower()

    def test_bad_range(self, cli_runner) -> None:
        code, _, err = cli_runner(
            [
                "dissect-address",
                "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb",
                "--xpub",
                XPUB,
                "--index-range",
                "start:20",
            ]
        )
        assert code == 1
        assert "index-range" in err

    def test_range_without_colon(self, cli_runner) -> None:
        code, _, err = cli_runner(
            [
                "dissect-address",
                "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb",
                "--xpub",
                XPUB,
                "--index-range",
                "20",
            ]
        )
        assert code == 1
        assert "START:COUNT" in err

    def test_count_cap(self, cli_runner) -> None:
        code, _, err = cli_runner(
            [
                "dissect-address",
                "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb",
                "--xpub",
                XPUB,
                "--index-range",
                "0:20000",
            ]
        )
        assert code == 1
        assert "capped" in err

    def test_json_includes_the_match(self, cli_runner) -> None:
        address = derive_address(parse_extended_public_key(XPUB), 2)
        code, out, _ = cli_runner(
            ["dissect-address", address, "--xpub", XPUB, "--report-format", "json"]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["key_match"]["matched"] is True
        assert payload["key_match"]["matched_index"] == 2
        assert payload["key_match"]["script_type"] == "p2pkh"


class TestStdin:
    """--stdin reads one input per line."""

    def test_reads_lines(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "sys.stdin",
            io.StringIO(
                "# comment\n1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb\n\n"
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n"
            ),
        )
        code = main(["dissect-address", "--stdin"])
        captured = capsys.readouterr()
        assert code == 0
        assert "items     : 2" in captured.out
        assert "p2wpkh" in captured.out

    def test_empty_stdin_is_an_error(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        code = main(["dissect-address", "--stdin"])
        captured = capsys.readouterr()
        assert code == 1
        assert "at least one address" in captured.err


class TestPrefixModels:
    """The prefix report now covers every encoding."""

    def test_bech32_report(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"])
        assert code == 0
        assert "Prefix analysis (bech32)" in out
        assert "constrained bits" in out

    def test_cashaddr_report(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["dissect-address", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"]
        )
        assert code == 0
        assert "Prefix analysis (cashaddr)" in out

    def test_claimed_prefix_on_segwit(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "dissect-address",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "--claimed-prefix",
                "bc1qw508",
            ]
        )
        assert code == 0
        assert "plausibly chosen on purpose" in out


class TestUnregisteredVersion:
    """An unlisted Base58 prefix is decoded, not refused."""

    def test_reports_unknown_chain(self, cli_runner) -> None:
        address = base58check_encode(b"\x7f" + bytes(range(20)))
        code, out, _ = cli_runner(["dissect-address", address])
        assert code == 0
        assert "chain                  unknown" in out
        assert "not registered" in out
        assert "2^288" in out

    def test_json_flags_it(self, cli_runner) -> None:
        address = base58check_encode(b"\x7f" + bytes(range(20)))
        code, out, _ = cli_runner(["dissect-address", address, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["chain"] == "unknown"
        assert any(check["code"] == "unregistered_version" for check in payload["safety"]["checks"])


class TestHelpAndRegression:
    """Discoverability and old behaviour."""

    def test_new_flags_are_documented(self, capsys) -> None:
        with pytest.raises(SystemExit):
            main(["dissect-address", "--help"])
        out = capsys.readouterr().out
        for flag in ("--redeem-script", "--xpub", "--index-range", "--stdin"):
            assert flag in out

    def test_plain_address_is_unchanged(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"])
        assert code == 0
        assert "address dissection" in out
        assert "Redeem-script claim" not in out
        assert "Extended public key" not in out

    def test_public_key_experiment_still_works(self, cli_runner) -> None:
        public_key = public_key_from_private(4242).compressed_hex
        address = base58check_encode(b"\x00" + hash160(bytes.fromhex(public_key)))
        code, out, _ = cli_runner(["dissect-address", address, "--public-key", public_key])
        assert code == 0
        assert "Controlled experiment" in out
        assert "YES" in out
