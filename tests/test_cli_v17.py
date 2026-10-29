"""CLI tests for v1.7.0: recover-script, compare-addresses, estimate-mining, plan."""

from __future__ import annotations

import csv
import io
import json

import pytest

from binarycryptolab.base58 import base58check_encode
from binarycryptolab.cli import main
from binarycryptolab.hashing import hash160
from binarycryptolab.script_recovery import CandidateKey, enumerate_candidate_scripts

TARGET = "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa"
KEY_A = "02" + "11" * 32
KEY_B = "02" + "22" * 32
KEY_C = "03" + "33" * 32

MULTISIG_SCRIPT = next(
    item[2]
    for item in enumerate_candidate_scripts(
        (CandidateKey(KEY_A), CandidateKey(KEY_B), CandidateKey(KEY_C))
    )
    if item[1] == "2-of-3 multisig"
)
MULTISIG_ADDRESS = base58check_encode(b"\x05" + hash160(bytes.fromhex(MULTISIG_SCRIPT)))


class TestRecoverScript:
    """The recovery command."""

    def test_recovers_the_multisig(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "recover-script",
                MULTISIG_ADDRESS,
                "--candidate-key",
                KEY_A,
                "--candidate-key",
                KEY_B,
                "--candidate-key",
                KEY_C,
            ]
        )
        assert code == 0
        assert "script recovery" in out
        assert "recovered          YES" in out
        assert "2-of-3 multisig" in out
        assert MULTISIG_SCRIPT in out

    def test_reports_a_miss_honestly(self, cli_runner) -> None:
        code, out, _ = cli_runner(["recover-script", TARGET, "--candidate-key", KEY_A])
        assert code == 0
        assert "recovered          no" in out
        assert "not derived from any of them" in out
        assert "miss excludes the catalogue" in out

    def test_json(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "recover-script",
                MULTISIG_ADDRESS,
                "--candidate-key",
                KEY_A,
                "--candidate-key",
                KEY_B,
                "--candidate-key",
                KEY_C,
                "--report-format",
                "json",
            ]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["recovered"] is True
        assert payload["matches"][0]["summary"] == "2-of-3 multisig"

    def test_csv(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "recover-script",
                MULTISIG_ADDRESS,
                "--candidate-key",
                KEY_A,
                "--candidate-key",
                KEY_B,
                "--candidate-key",
                KEY_C,
                "--report-format",
                "csv",
            ]
        )
        assert code == 0
        rows = list(csv.DictReader(io.StringIO(out)))
        assert rows[0]["matched"] == "yes"

    def test_needs_at_least_one_key(self, cli_runner) -> None:
        code, _, err = cli_runner(["recover-script", TARGET])
        assert code == 1
        assert "candidate" in err.lower()

    def test_invalid_key(self, cli_runner) -> None:
        code, _, err = cli_runner(["recover-script", TARGET, "--candidate-key", "zz"])
        assert code == 1
        assert "SEC 1" in err


class TestCompareAddresses:
    """The comparison command."""

    def test_reuse_across_networks(self, cli_runner) -> None:
        payload = bytes(range(20))
        mainnet = base58check_encode(b"\x00" + payload)
        testnet = base58check_encode(b"\x6f" + payload)
        code, out, _ = cli_runner(["compare-addresses", mainnet, testnet])
        assert code == 0
        assert "same_payload" in out
        assert "reuse across chains" in out

    def test_unrelated(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["compare-addresses", TARGET, "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"]
        )
        assert code == 0
        assert "none: the payloads are unrelated" in out

    def test_json(self, cli_runner) -> None:
        code, out, _ = cli_runner(["compare-addresses", TARGET, TARGET, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["relations"][0]["kind"] == "same_address"

    def test_needs_two(self, cli_runner) -> None:
        code, _, err = cli_runner(["compare-addresses", TARGET])
        assert code == 2 or code == 1
        assert err


class TestEstimateMining:
    """The mining estimator."""

    def test_reports_measured_rate_and_table(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["estimate-mining", TARGET, "--prefix", "1BEwWK", "--iterations", "16"]
        )
        assert code == 0
        assert "prefix mining estimate" in out
        assert "constrained bits" in out
        assert "Measured on this machine" in out
        assert "Expected time by attack rate" in out
        assert "per second" in out

    def test_default_prefix_is_the_address_prefix(self, cli_runner) -> None:
        code, out, _ = cli_runner(["estimate-mining", TARGET, "--iterations", "16"])
        assert code == 0
        assert "1BEwWK" in out

    def test_impossible_prefix(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["estimate-mining", TARGET, "--prefix", "3BEw", "--iterations", "8"]
        )
        assert code == 0
        assert "cannot occur" in out

    def test_json(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            [
                "estimate-mining",
                TARGET,
                "--prefix",
                "1BEw",
                "--iterations",
                "8",
                "--report-format",
                "json",
            ]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["prefix"] == "1BEw"
        assert payload["measured"]["per_second"] > 0
        assert len(payload["rate_table"]) == 4

    def test_bad_iterations(self, cli_runner) -> None:
        code, _, err = cli_runner(["estimate-mining", TARGET, "--iterations", "0"])
        assert code == 1
        assert "iterations" in err


class TestPlanSection:
    """Every dissection now carries an investigation plan."""

    def test_text_section(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", TARGET])
        assert code == 0
        assert "Investigation plan" in out
        assert "Closed questions" in out
        assert "private_key" in out
        assert "estimate-mining" in out

    def test_json_section(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", TARGET, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["plan"]["leads"]
        assert payload["plan"]["closed"]

    def test_batch_keeps_working(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", TARGET, MULTISIG_ADDRESS])
        assert code == 0
        assert "address batch" in out


class TestHelp:
    """Discoverability."""

    def test_new_commands_listed(self, capsys) -> None:
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        for command in ("recover-script", "compare-addresses", "estimate-mining"):
            assert command in out

    def test_recover_help(self, capsys) -> None:
        with pytest.raises(SystemExit):
            main(["recover-script", "--help"])
        out = capsys.readouterr().out
        for flag in ("--candidate-key", "--hash-lock", "--timelock", "--max-candidates"):
            assert flag in out
