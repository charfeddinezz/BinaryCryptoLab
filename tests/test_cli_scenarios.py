"""CLI tests for the extended address scenarios and the offline data audit."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from binarycryptolab.bitcoin import derive_p2tr_address
from binarycryptolab.cli import main
from binarycryptolab.ecc import public_key_from_private
from tests.vectors import ADDRESS_P2PKH_G, ADDRESS_P2WPKH_G

P2PKH = "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"
SCRIPT = "76a914ab9a4edd7600fe91d0f46a97dc851ad45c1ce17688ac"
BIP350_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
CASHADDR = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"


class TestScenarioInputs:
    """Every accepted input shape reaches the renderer."""

    def test_bip21_uri(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", f"bitcoin:{P2PKH}?amount=0.5&label=rent"])
        assert code == 0
        assert "Payment URI parameters" in out
        assert "amount" in out
        assert "rent" in out

    def test_script_input(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", SCRIPT])
        assert code == 0
        assert "raw locking script" in out
        assert P2PKH in out

    def test_forced_nonstandard_script(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", "script:deadbeefcafe"])
        assert code == 0
        assert "nonstandard" in out

    def test_op_return_script(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", "script:6a0b68656c6c6f"])
        assert code == 0
        assert "not applicable" in out  # no payload to test
        assert "unspendable" in out

    def test_p2pk_script(self, cli_runner) -> None:
        script = "21" + "02" + "79" * 32 + "ac"
        code, out, _ = cli_runner(["dissect-address", script])
        assert code == 0
        assert "p2pk" in out
        assert "public key is written into the output" in out

    def test_taproot(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", BIP350_P2TR])
        assert code == 0
        assert "Taproot output key" in out
        assert "2^128" in out

    def test_cashaddr(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", CASHADDR])
        assert code == 0
        assert "bitcoin_cash" in out

    def test_unknown_witness_version_warns(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", "script:5220" + "ab" * 32])
        assert code == 0
        assert "anyone can spend" in out

    def test_network_expectation_mismatch(self, cli_runner) -> None:
        code, _, err = cli_runner(["dissect-address", P2PKH, "--network", "testnet"])
        assert code == 1
        assert "testnet" in err

    def test_private_key_is_refused_without_echo(self, cli_runner) -> None:
        wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        code, out, err = cli_runner(["dissect-address", wif])
        assert code == 1
        assert wif not in out
        assert wif not in err
        assert "private key" in err.lower()

    def test_controlled_experiment_with_a_matching_key(self, cli_runner) -> None:
        public_key = public_key_from_private(9_999).compressed_hex
        address = derive_p2tr_address(public_key).address
        code, out, _ = cli_runner(["dissect-address", address, "--public-key", public_key])
        assert code == 0
        assert "Controlled experiment" in out
        assert "YES" in out


class TestBatch:
    """Multiple inputs, files, CSV, and exit codes."""

    def test_two_addresses_text(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", P2PKH, ADDRESS_P2WPKH_G])
        assert code == 0
        assert "address batch" in out
        assert "by type" in out
        assert "p2pkh" in out and "p2wpkh" in out

    def test_input_file(self, cli_runner, tmp_path: Path) -> None:
        path = tmp_path / "inputs.txt"
        path.write_text(
            f"# comment line\n\n{P2PKH}\n{BIP350_P2TR}\n{CASHADDR}\n",
            encoding="utf-8",
        )
        code, out, _ = cli_runner(["dissect-address", "--input-file", str(path)])
        assert code == 0
        assert "items     : 3" in out
        assert "p2tr" in out

    def test_partial_failure_exits_one(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", P2PKH, "not-an-address"])
        assert code == 1
        assert "Errors" in out
        assert "address dissection" not in out

    def test_json_batch_envelope(self, cli_runner, tmp_path: Path) -> None:
        path = tmp_path / "inputs.txt"
        path.write_text(f"{P2PKH}\nbroken\n", encoding="utf-8")
        code, out, _ = cli_runner(
            ["dissect-address", "--input-file", str(path), "--report-format", "json"]
        )
        assert code == 1
        payload = json.loads(out)
        assert payload["summary"]["items"] == 2
        assert payload["summary"]["parsed"] == 1
        assert payload["summary"]["failed"] == 1
        assert payload["errors"][0]["input"] == "broken"

    def test_json_summary_counts(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["dissect-address", P2PKH, BIP350_P2TR, "--report-format", "json"]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["summary"]["by_type"] == {"p2pkh": 1, "p2tr": 1}
        assert payload["summary"]["by_chain"]["bitcoin"] == 2

    def test_csv_output(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", P2PKH, BIP350_P2TR, "--report-format", "csv"])
        assert code == 0
        rows = list(csv.DictReader(io.StringIO(out)))
        assert len(rows) == 2
        assert rows[0]["type"] == "p2pkh"
        assert rows[1]["total_cost_log2"] == "128"

    def test_csv_contains_error_rows(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dissect-address", P2PKH, "broken", "--report-format", "csv"])
        assert code == 1
        rows = list(csv.DictReader(io.StringIO(out)))
        assert any(row["error"] for row in rows)

    def test_all_failures_exit_one(self, cli_runner) -> None:
        code, _, err = cli_runner(["dissect-address", "broken", "also-broken"])
        assert code == 1
        assert "error:" in err

    def test_no_input_is_a_usage_error(self, cli_runner) -> None:
        code, _, err = cli_runner(["dissect-address"])
        assert code == 1
        assert "at least one address" in err

    def test_missing_input_file(self, cli_runner, tmp_path: Path) -> None:
        code, _, err = cli_runner(["dissect-address", "--input-file", str(tmp_path / "absent.txt")])
        assert code == 1
        assert "cannot read" in err

    def test_text_batch_writes_to_file(self, cli_runner, tmp_path: Path) -> None:
        target = tmp_path / "batch.txt"
        code, out, _ = cli_runner(
            ["dissect-address", P2PKH, ADDRESS_P2WPKH_G, "--output", str(target)]
        )
        assert code == 0
        assert "Report written to" in out
        assert "address batch" in target.read_text(encoding="utf-8")


class TestAuditAddressData:
    """The offline chain-data audit command."""

    def write_export(self, tmp_path: Path, **overrides: object) -> Path:
        payload = {
            "address": P2PKH,
            "source": "unit test fixture",
            "utxos": [
                {
                    "txid": "ab" * 32,
                    "vout": 0,
                    "value_sats": 250_000,
                    "height": 800_000,
                    "script_pubkey_hex": SCRIPT,
                },
                {"txid": "cd" * 32, "vout": 1, "value_sats": 50_000},
            ],
        }
        payload.update(overrides)
        path = tmp_path / "export.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_text_report(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        code, out, _ = cli_runner(["audit-address-data", P2PKH, "--input-file", str(path)])
        assert code == 0
        assert "address data audit (offline)" in out
        assert "0.00300000 BTC" in out
        assert "unit test fixture" in out
        assert "trusted" in out
        assert "No network request was made" in out

    def test_json_report(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        code, out, _ = cli_runner(
            ["audit-address-data", P2PKH, "--input-file", str(path), "--report-format", "json"]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["balance_sats"] == 300_000
        assert payload["trusted"] is False
        assert payload["utxo_count"] == 2

    def test_csv_report(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        code, out, _ = cli_runner(
            ["audit-address-data", P2PKH, "--input-file", str(path), "--report-format", "csv"]
        )
        assert code == 0
        rows = list(csv.DictReader(io.StringIO(out)))
        assert len(rows) == 2
        assert rows[0]["script_matches"] == "yes"

    def test_source_override(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        code, out, _ = cli_runner(
            ["audit-address-data", P2PKH, "--input-file", str(path), "--source", "cold storage"]
        )
        assert code == 0
        assert "cold storage" in out

    def test_mismatched_script_is_reported(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(
            tmp_path,
            utxos=[{"txid": "ee" * 32, "vout": 0, "value_sats": 1000, "script_pubkey_hex": "00"}],
        )
        code, out, _ = cli_runner(["audit-address-data", P2PKH, "--input-file", str(path)])
        assert code == 0
        assert "different script" in out
        assert "does not describe this address" in out

    def test_invalid_address(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        code, _, err = cli_runner(["audit-address-data", "nope", "--input-file", str(path)])
        assert code == 1
        assert err

    def test_missing_file(self, cli_runner, tmp_path: Path) -> None:
        code, _, err = cli_runner(
            ["audit-address-data", P2PKH, "--input-file", str(tmp_path / "absent.json")]
        )
        assert code == 1
        assert "cannot read" in err

    def test_overwrite_protection(self, cli_runner, tmp_path: Path) -> None:
        path = self.write_export(tmp_path)
        target = tmp_path / "audit.json"
        target.write_text("{}", encoding="utf-8")
        code, _, err = cli_runner(
            [
                "audit-address-data",
                P2PKH,
                "--input-file",
                str(path),
                "--report-format",
                "json",
                "--output",
                str(target),
            ]
        )
        assert code == 1
        assert "overwrite" in err.lower()


class TestHelpAndVersion:
    """The new commands are discoverable."""

    def test_dissect_address_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["dissect-address", "--help"])
        assert excinfo.value.code == 0
        captured = capsys.readouterr().out
        for flag in ("--input-file", "--claimed-prefix", "--public-key", "--network"):
            assert flag in captured

    def test_audit_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["audit-address-data", "--help"])
        assert excinfo.value.code == 0
        captured = capsys.readouterr().out
        assert "--input-file" in captured
        assert "--source" in captured

    def test_top_level_lists_both(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit):
            main(["--help"])
        captured = capsys.readouterr().out
        assert "dissect-address" in captured
        assert "audit-address-data" in captured

    def test_default_address_still_works(self, cli_runner) -> None:
        # The original single-address invocation must remain byte-compatible.
        code, out, _ = cli_runner(["dissect-address", ADDRESS_P2PKH_G])
        assert code == 0
        assert "address dissection" in out
        assert "address batch" not in out
