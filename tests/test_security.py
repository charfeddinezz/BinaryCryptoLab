"""Security-focused tests.

The rest of the suite samples behaviour; these tests pin down the invariants
that matter most:

* a private scalar never appears in CLI output, reports, exception messages, or
  logs;
* :class:`AnalysisResult` refuses to carry unredacted private-key input;
* text and file contents hashed via the CLI never reach a report;
* address derivation and decoding never claim ownership, balance, or network
  access.

The scalar used throughout is synthetic and controls no funds.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from binarycryptolab.analysis import analyze
from binarycryptolab.bitcoin import address_from_public_key, decode_address
from binarycryptolab.ecc import (
    CURVE_ORDER,
    parse_private_scalar,
    public_key_from_private,
    public_key_info_from_hex,
    validate_private_scalar,
)
from binarycryptolab.exceptions import InvalidPrivateKeyError
from binarycryptolab.models.analysis_result import REDACTED, AnalysisResult
from binarycryptolab.reports import write_csv, write_json

SCALAR = 0xC0FFEE
SCALAR_HEX = "c0ffee"
SCALAR_DECIMAL = str(SCALAR)

CliRunner = Callable[[list[str]], tuple[int, str, str]]


def _combined(run: tuple[int, str, str]) -> str:
    _, out, err = run
    return out + err


def _assert_no_scalar(text: str) -> None:
    """Assert that no textual form of the synthetic scalar is present."""
    lowered = text.lower()
    assert SCALAR_HEX not in lowered
    assert SCALAR_DECIMAL not in text
    assert f"0x{SCALAR_HEX}" not in lowered


# ---------------------------------------------------------------------------
# Model-level guarantees
# ---------------------------------------------------------------------------


def test_result_rejects_unredacted_private_key_input() -> None:
    with pytest.raises(ValueError, match="redacted"):
        AnalysisResult(
            input_type="private_key",
            original_input=SCALAR_HEX,
            normalized_input=SCALAR_HEX,
        )


def test_result_rejects_partially_redacted_private_key_input() -> None:
    with pytest.raises(ValueError, match="redacted"):
        AnalysisResult(
            input_type="private_key",
            original_input=REDACTED,
            normalized_input=SCALAR_HEX,
        )


def test_redacted_result_serialises_without_the_scalar() -> None:
    info = public_key_from_private(SCALAR)
    result = AnalysisResult(
        input_type="private_key",
        original_input=REDACTED,
        normalized_input=REDACTED,
        public_key=info.as_dict(),
    )
    payload = json.dumps(result.to_dict())
    assert REDACTED in payload
    _assert_no_scalar(payload)


def test_scalar_validation_error_never_contains_the_value() -> None:
    for bad in (0, CURVE_ORDER, CURVE_ORDER + 1, (1 << 256) - 1):
        with pytest.raises(InvalidPrivateKeyError) as excinfo:
            validate_private_scalar(bad)
        message = str(excinfo.value)
        assert "1 <= k < n" in message
        if bad:
            assert format(bad, "x") not in message.lower()
            assert str(bad) not in message


def test_private_scalar_parse_error_never_contains_the_text() -> None:
    with pytest.raises(InvalidPrivateKeyError) as excinfo:
        parse_private_scalar("not-a-scalar-abc123")
    assert "not-a-scalar-abc123" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------


def test_cli_public_key_output_contains_no_scalar(cli_runner: CliRunner) -> None:
    run = cli_runner(["public-key", "--private-key", SCALAR_HEX, "--format", "both"])
    assert run[0] == 0
    _assert_no_scalar(_combined(run))
    expected = public_key_from_private(SCALAR)
    assert expected.compressed_hex in run[1]


def test_cli_public_key_decimal_scalar_is_not_echoed(cli_runner: CliRunner) -> None:
    run = cli_runner(["public-key", "--private-key", SCALAR_DECIMAL, "--private-key-base", "10"])
    assert run[0] == 0
    _assert_no_scalar(_combined(run))


def test_cli_public_key_warns_about_shell_history(cli_runner: CliRunner) -> None:
    run = cli_runner(["public-key", "--private-key", SCALAR_HEX])
    assert run[0] == 0
    stderr = run[2]
    assert "SECURITY" in stderr
    assert "shell" in stderr.lower()
    assert "process" in stderr.lower()
    assert "--prompt-private-key" in stderr


def test_cli_public_key_error_does_not_echo_invalid_scalar(cli_runner: CliRunner) -> None:
    run = cli_runner(["public-key", "--private-key", "ffee-ddcc-bbaa"])
    assert run[0] == 1
    # The security warning is printed first; the error line follows it.
    assert run[2].splitlines()[-1].startswith("error: ")
    assert "ffee-ddcc-bbaa" not in _combined(run)
    assert "Traceback" not in _combined(run)


def test_cli_public_key_out_of_range_error_hides_value(cli_runner: CliRunner) -> None:
    too_large = format(CURVE_ORDER, "x")
    run = cli_runner(["public-key", "--private-key", too_large])
    assert run[0] == 1
    assert "error: " in run[2]
    assert too_large not in _combined(run)
    assert "1 <= k < n" in run[2]


def test_cli_prompt_private_key_uses_hidden_input(
    cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    import binarycryptolab.cli as cli_module

    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return SCALAR_HEX

    monkeypatch.setattr(cli_module.getpass, "getpass", fake_getpass)
    run = cli_runner(["public-key", "--prompt-private-key"])
    assert run[0] == 0
    assert prompts and "hidden" in prompts[0].lower()
    _assert_no_scalar(_combined(run))


# ---------------------------------------------------------------------------
# Reports written from the CLI
# ---------------------------------------------------------------------------


def test_json_report_for_private_key_is_redacted(cli_runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "key.json"
    run = cli_runner(
        [
            "public-key",
            "--private-key",
            SCALAR_HEX,
            "--report-format",
            "json",
            "--output",
            str(target),
        ]
    )
    assert run[0] == 0
    text = target.read_text(encoding="utf-8")
    _assert_no_scalar(text)
    payload = json.loads(text)
    assert payload["input"]["type"] == "private_key"
    assert payload["input"]["original"] == REDACTED
    assert payload["input"]["normalized"] == REDACTED


def test_csv_report_for_private_key_is_redacted(cli_runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "key.csv"
    run = cli_runner(
        [
            "public-key",
            "--private-key",
            SCALAR_HEX,
            "--report-format",
            "csv",
            "--output",
            str(target),
        ]
    )
    assert run[0] == 0
    _assert_no_scalar(target.read_text(encoding="utf-8"))


def test_library_reports_never_contain_the_scalar(tmp_path: Path) -> None:
    info = public_key_from_private(SCALAR)
    result = AnalysisResult(
        input_type="private_key",
        original_input=REDACTED,
        normalized_input=REDACTED,
        public_key=info.as_dict(),
    )
    json_path = write_json(result, tmp_path / "key.json")
    csv_path = write_csv(result, tmp_path / "key.csv")
    _assert_no_scalar(json_path.read_text(encoding="utf-8"))
    _assert_no_scalar(csv_path.read_text(encoding="utf-8"))


def test_hash_report_omits_text_content(cli_runner: CliRunner, tmp_path: Path) -> None:
    secret = "passphrase-that-must-not-be-recorded"
    target = tmp_path / "hash.json"
    run = cli_runner(["hash", "--text", secret, "--format", "json", "--output", str(target)])
    assert run[0] == 0
    text = target.read_text(encoding="utf-8")
    assert secret not in text
    payload = json.loads(text)
    assert payload["input"]["type"] == "text"
    assert payload["input"]["original"].startswith("<text input omitted")
    assert payload["hashes"][0]["algorithm"] == "sha256"


def test_hash_report_omits_file_content(cli_runner: CliRunner, tmp_path: Path) -> None:
    secret_file = tmp_path / "artifact.bin"
    secret_content = "file-content-that-must-not-be-recorded"
    secret_file.write_text(secret_content, encoding="utf-8")
    target = tmp_path / "file-hash.json"
    run = cli_runner(
        ["hash", "--file", str(secret_file), "--format", "json", "--output", str(target)]
    )
    assert run[0] == 0
    text = target.read_text(encoding="utf-8")
    assert secret_content not in text
    payload = json.loads(text)
    assert payload["input"]["type"] == "file"
    assert secret_file.name in text


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_scalar_is_not_logged(cli_runner: CliRunner, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        run = cli_runner(["public-key", "--private-key", SCALAR_HEX])
    assert run[0] == 0
    _assert_no_scalar(caplog.text)


def test_ecc_module_does_not_log_scalars(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        public_key_from_private(SCALAR)
        with pytest.raises(InvalidPrivateKeyError):
            validate_private_scalar(0)
    _assert_no_scalar(caplog.text)


# ---------------------------------------------------------------------------
# Hashing and address honesty
# ---------------------------------------------------------------------------


def test_analysis_payload_contains_no_private_material() -> None:
    payload = analyze("binary", "1010").to_dict()
    assert payload["input"]["original"] == "1010"
    assert "private" not in json.dumps(payload["input"]).lower()
    assert "scalar" not in json.dumps(payload).lower()


def test_address_derivation_does_not_claim_ownership() -> None:
    info = public_key_from_private(1)
    address = address_from_public_key(info.compressed_hex, address_type="p2pkh")
    payload = address.as_dict()
    assert set(payload) == {
        "address",
        "type",
        "network",
        "hash160",
        "public_key_hex",
        "public_key_encoding",
        "witness_version",
        "witness_program_hex",
        "script_pubkey_hex",
        "notes",
    }
    notes = " ".join(payload["notes"]).lower()
    assert "does not establish ownership" in notes
    assert "balance" in notes


def test_decoded_address_reports_only_structural_facts() -> None:
    payload = decode_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").as_dict()
    assert set(payload) == {
        "address",
        "type",
        "network",
        "network_ambiguous",
        "payload_hex",
        "witness_version",
    }
    text = json.dumps(payload).lower()
    assert "balance" not in text
    assert "private" not in text


def test_public_key_helpers_never_return_the_scalar() -> None:
    info = public_key_from_private(SCALAR)
    _assert_no_scalar(json.dumps(info.as_dict()))

    parsed = public_key_info_from_hex(info.compressed_hex)
    _assert_no_scalar(json.dumps(parsed.as_dict()))


# ---------------------------------------------------------------------------
# Public-key forensics
# ---------------------------------------------------------------------------


def test_forensics_never_contains_private_material() -> None:
    from binarycryptolab.forensics import dissect_public_key

    payload = dissect_public_key(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ).as_dict()
    text = json.dumps(payload).lower()
    assert "private_key" not in text
    assert "scalar_value" not in text
    assert payload["forecast"]["recoverable"] is False


def test_forensics_cli_report_is_safe(cli_runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "dissection.json"
    run = cli_runner(
        [
            "dissect-public-key",
            "--public-key",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "--report-format",
            "json",
            "--output",
            str(target),
        ]
    )
    assert run[0] == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["public_key_forensics"]["forecast"]["recoverable"] is False
    assert "does not compute private keys" in " ".join(
        payload["public_key_forensics"]["forecast"]["recommendations"]
    )


def test_forensics_batch_error_hides_key_bytes(cli_runner: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "keys.txt"
    source.write_text(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\ndeadbeefdeadbeef\n",
        encoding="utf-8",
    )
    run = cli_runner(["dissect-public-key", "--input-file", str(source)])
    assert run[0] == 1
    assert "deadbeefdeadbeef" not in run[2]
    assert "#2" in run[2]
