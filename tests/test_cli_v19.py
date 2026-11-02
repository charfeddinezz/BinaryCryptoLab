"""CLI tests for v1.9.0: the dlp-audit command."""

from __future__ import annotations

import csv
import io
import json

import pytest

from binarycryptolab.cli import main

TARGET = "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa"
FAST = ["--sizes", "10,14,18", "--trials", "3"]


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


class TestDlpAuditText:
    """The readable report."""

    def test_verdict_and_claim(self, cli_runner) -> None:
        code, out, err = cli_runner(["dlp-audit", "--skip-measurement"])
        assert code == 0, err
        assert "discrete logarithm audit" in out
        assert "Verdict: not refuted" in out
        assert "Claim tested" in out

    def test_structural_audit_is_rendered(self, cli_runner) -> None:
        _, out, _ = cli_runner(["dlp-audit", "--skip-measurement"])
        assert "Structural audit (10 properties, 0 exploitable)" in out
        assert "group_order_prime" in out
        assert "no_small_embedding_degree" in out
        assert "generic_group_bound" in out

    def test_claim_families_are_rendered(self, cli_runner) -> None:
        _, out, _ = cli_runner(["dlp-audit", "--skip-measurement"])
        assert "Claim families and the step that fails (8)" in out
        for code in ("index_calculus", "pohlig_hellman", "glv_speedup", "quantum"):
            assert code in out

    def test_falsifiers_are_rendered(self, cli_runner) -> None:
        _, out, _ = cli_runner(["dlp-audit", "--skip-measurement"])
        assert "What would refute this (5)" in out
        assert "signature_from_public_key" in out
        assert "would mean:" in out

    def test_scope_and_honesty_footer(self, cli_runner) -> None:
        _, out, _ = cli_runner(["dlp-audit", "--skip-measurement"])
        assert "Scope" in out
        assert "classical algorithms only" in out
        assert "No private scalar was searched for" in out

    def test_measurement_section(self, cli_runner) -> None:
        code, out, err = cli_runner(["dlp-audit", *FAST])
        assert code == 0, err
        assert "Measured scaling of Pollard rho" in out
        assert "fit: log2(steps)" in out
        assert "Memory-bound comparison" in out
        assert "Positive control (smooth order)" in out
        assert "recovered" in out

    def test_skip_measurement_omits_the_section(self, cli_runner) -> None:
        _, out, _ = cli_runner(["dlp-audit", "--skip-measurement"])
        assert "Measured scaling" not in out
        assert "Positive control" not in out

    def test_address_case(self, cli_runner) -> None:
        code, out, err = cli_runner(["dlp-audit", "--skip-measurement", "--address", TARGET])
        assert code == 0, err
        assert "Address-level chain for the supplied address" in out
        assert "total: 2^288.0" in out
        assert "2^160" in out or "preimage" in out


class TestDlpAuditFormats:
    """Machine-readable output."""

    def test_json_has_every_section(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dlp-audit", *FAST, "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert payload["verdict"] == "not refuted"
        assert payload["audit"]["exploitable_count"] == 0
        assert len(payload["rebuttals"]) == 8
        assert len(payload["falsifiers"]) >= 4
        assert payload["measurement"]["fit"]["slope"] > 0
        assert payload["measurement"]["fit"]["slope_standard_error"] > 0

    def test_json_without_measurement(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dlp-audit", "--skip-measurement", "--report-format", "json"])
        assert code == 0
        payload = json.loads(out)
        assert "measurement" not in payload

    def test_json_address_case(self, cli_runner) -> None:
        code, out, _ = cli_runner(
            ["dlp-audit", "--skip-measurement", "--report-format", "json", "--address", TARGET]
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["address_case"]["total_cost_log2"] == pytest.approx(288.0)

    def test_csv_sections(self, cli_runner) -> None:
        code, out, _ = cli_runner(["dlp-audit", *FAST, "--report-format", "csv"])
        assert code == 0
        rows = _rows(out)
        sections = {row["section"] for row in rows}
        assert {"audit", "claim", "falsifier", "measurement"} <= sections
        assert all(row["key"] for row in rows)

    def test_output_file(self, cli_runner, tmp_path) -> None:
        target = tmp_path / "audit.json"
        code, _, err = cli_runner(
            ["dlp-audit", "--skip-measurement", "--report-format", "json", "--output", str(target)]
        )
        assert code == 0, err
        assert json.loads(target.read_text())["verdict"] == "not refuted"


class TestDlpAuditValidation:
    """Bad input must fail with a clean message."""

    def test_zero_trials(self, cli_runner) -> None:
        code, _, err = cli_runner(["dlp-audit", "--trials", "0"])
        assert code == 1
        assert "error:" in err

    def test_single_size(self, cli_runner) -> None:
        code, _, err = cli_runner(["dlp-audit", "--sizes", "12"])
        assert code == 1
        assert "error:" in err

    def test_bad_size_list(self, cli_runner) -> None:
        code, _, err = cli_runner(["dlp-audit", "--sizes", "twelve,16"])
        assert code == 1
        assert "error:" in err

    def test_invalid_address(self, cli_runner) -> None:
        code, _, err = cli_runner(["dlp-audit", "--skip-measurement", "--address", "nonsense"])
        assert code == 1
        assert "error:" in err

    def test_help_lists_the_command(self, capsys) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        assert "dlp-audit" in capsys.readouterr().out
