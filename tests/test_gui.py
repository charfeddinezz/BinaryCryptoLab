"""Tests for the Streamlit-free GUI service layer and launcher.

Streamlit itself is an optional dependency and is not imported by these tests,
so the core test suite passes with only the required dependencies installed.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from binarycryptolab.exceptions import (
    AddressEncodingError,
    InvalidBinaryError,
    InvalidHexError,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    UnsupportedHashError,
)
from binarycryptolab.gui import service
from binarycryptolab.gui.launcher import main as launcher_main
from tests.vectors import ADDRESS_P2PKH_G, ADDRESS_P2WPKH_G, PUBKEY_ONE_COMPRESSED

SYNTHETIC_SCALAR = "0x0000000000000000000000000000000000000000000000000000000000c0ffee"


class TestAnalysisService:
    def test_binary(self) -> None:
        result = service.analyse("101101", kind="binary")
        assert result.binary is not None
        assert result.binary.integer_value == 45

    def test_hex(self) -> None:
        result = service.analyse("2D", kind="hex")
        assert result.hexadecimal is not None
        assert result.hexadecimal.normalized == "2d"

    def test_strict_hex(self) -> None:
        with pytest.raises(InvalidHexError):
            service.analyse("abc", kind="hex", strict_hex=True)
        assert service.analyse("abc", kind="hex").hexadecimal is not None

    def test_invalid_binary(self) -> None:
        with pytest.raises(InvalidBinaryError):
            service.analyse("102", kind="binary")

    def test_unknown_kind(self) -> None:
        with pytest.raises(ValueError):
            service.analyse("1", kind="octal")


class TestHashService:
    def test_hex(self) -> None:
        result = service.hash_result("sha256", kind="hex", value="2d")
        assert result.hashes[0].hexdigest == (
            "3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112"
        )
        assert result.hexadecimal is not None

    def test_binary(self) -> None:
        result = service.hash_result("sha256", kind="binary", value="101101")
        assert result.hashes[0].input_length == 1
        assert result.binary is not None

    def test_text_is_omitted(self) -> None:
        secret = "correct horse battery staple"
        result = service.hash_result("sha256", kind="text", value=secret)
        assert secret not in str(result.to_dict())
        assert result.hashes[0].input_length == len(secret)

    def test_unknown_algorithm(self) -> None:
        with pytest.raises(UnsupportedHashError):
            service.hash_result("md5", kind="hex", value="2d")

    def test_unknown_kind(self) -> None:
        with pytest.raises(ValueError):
            service.hash_result("sha256", kind="file", value="x")


class TestPublicKeyService:
    def test_derivation(self) -> None:
        result = service.public_key_result("1")
        assert result.public_key is not None
        assert result.public_key["compressed_hex"] == PUBKEY_ONE_COMPRESSED
        assert result.original_input == "<redacted>"
        assert result.normalized_input == "<redacted>"

    def test_scalar_is_never_in_results(self) -> None:
        result = service.public_key_result(SYNTHETIC_SCALAR)
        payload = json.dumps(result.to_dict()).lower()
        assert "c0ffee" not in payload
        assert "<redacted>" in payload

    def test_decimal_base(self) -> None:
        result = service.public_key_result("1", base=10)
        assert result.public_key is not None

    def test_invalid_scalar(self) -> None:
        with pytest.raises(InvalidPrivateKeyError):
            service.public_key_result("0")

    def test_invalid_display_format(self) -> None:
        with pytest.raises(ValueError):
            service.public_key_result("1", display_format="raw")

    def test_display_format_is_recorded(self) -> None:
        result = service.public_key_result("1", display_format="both")
        assert result.extra["display_format"] == "both"


class TestAddressService:
    def test_p2pkh(self) -> None:
        result = service.address_result(PUBKEY_ONE_COMPRESSED)
        assert result.address is not None
        assert result.address["address"] == ADDRESS_P2PKH_G
        assert result.public_key is not None

    def test_p2wpkh_testnet(self) -> None:
        result = service.address_result(
            PUBKEY_ONE_COMPRESSED, address_type="p2wpkh", network="testnet"
        )
        assert result.address is not None
        assert str(result.address["address"]).startswith("tb1q")
        assert any("testing only" in warning for warning in result.warnings)

    def test_invalid_public_key(self) -> None:
        with pytest.raises(InvalidPublicKeyError):
            service.address_result("00")

    def test_invalid_type(self) -> None:
        with pytest.raises(AddressEncodingError):
            service.address_result(PUBKEY_ONE_COMPRESSED, address_type="p2tr")

    def test_no_private_material(self) -> None:
        result = service.address_result(PUBKEY_ONE_COMPRESSED, address_type="p2wpkh")
        assert result.address is not None
        assert result.address["address"] == ADDRESS_P2WPKH_G
        assert "private" not in json.dumps(result.address).lower()


class TestDownloads:
    def test_payloads_are_valid(self) -> None:
        result = service.analyse("101101", kind="binary")
        payloads = service.download_payloads(result)
        assert json.loads(payloads["json"])["input"]["normalized"] == "101101"
        assert payloads["csv"].startswith("section,key,value\n")

    def test_public_key_download_is_redacted(self) -> None:
        result = service.public_key_result(SYNTHETIC_SCALAR)
        payloads = service.download_payloads(result)
        assert "c0ffee" not in payloads["json"].lower()
        assert "c0ffee" not in payloads["csv"].lower()


class TestLauncher:
    def test_missing_streamlit_is_reported(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setitem(sys.modules, "streamlit", None)
        assert launcher_main([]) == 1
        captured = capsys.readouterr()
        assert "requires Streamlit" in captured.err
        assert "pip install" in captured.err

    def test_launches_streamlit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorded: dict[str, object] = {}

        def fake_cli_main() -> int:
            recorded["argv"] = list(sys.argv)
            return 0

        streamlit_module = types.ModuleType("streamlit")
        web_module = types.ModuleType("streamlit.web")
        cli_module = types.ModuleType("streamlit.web.cli")
        cli_module.main = fake_cli_main  # type: ignore[attr-defined]
        web_module.cli = cli_module  # type: ignore[attr-defined]
        streamlit_module.web = web_module  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "streamlit", streamlit_module)
        monkeypatch.setitem(sys.modules, "streamlit.web", web_module)
        monkeypatch.setitem(sys.modules, "streamlit.web.cli", cli_module)
        monkeypatch.setattr(sys, "argv", ["binarycryptolab-gui"])

        assert launcher_main(["--server.port=8600"]) == 0
        argv = recorded["argv"]
        assert isinstance(argv, list)
        assert argv[0] == "streamlit"
        assert argv[1] == "run"
        assert str(argv[2]).endswith("app.py")
        assert "--server.address=127.0.0.1" in argv
        # The caller's port wins over the default instead of duplicating it.
        assert "--server.port=8600" in argv
        assert "--server.port=8501" not in argv

    def test_space_separated_port_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorded: dict[str, object] = {}

        def fake_cli_main() -> int:
            recorded["argv"] = list(sys.argv)
            return 0

        streamlit_module = types.ModuleType("streamlit")
        web_module = types.ModuleType("streamlit.web")
        cli_module = types.ModuleType("streamlit.web.cli")
        cli_module.main = fake_cli_main  # type: ignore[attr-defined]
        web_module.cli = cli_module  # type: ignore[attr-defined]
        streamlit_module.web = web_module  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "streamlit", streamlit_module)
        monkeypatch.setitem(sys.modules, "streamlit.web", web_module)
        monkeypatch.setitem(sys.modules, "streamlit.web.cli", cli_module)
        monkeypatch.setattr(sys, "argv", ["binarycryptolab-gui"])

        assert launcher_main(["--server.port", "8600"]) == 0
        argv = recorded["argv"]
        assert isinstance(argv, list)
        assert "--server.port" in argv
        assert "--server.port=8501" not in argv

    def test_streamlit_exit_code_is_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cli_module = types.ModuleType("streamlit.web.cli")
        cli_module.main = lambda: 3  # type: ignore[attr-defined]
        web_module = types.ModuleType("streamlit.web")
        web_module.cli = cli_module  # type: ignore[attr-defined]
        streamlit_module = types.ModuleType("streamlit")
        streamlit_module.web = web_module  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "streamlit", streamlit_module)
        monkeypatch.setitem(sys.modules, "streamlit.web", web_module)
        monkeypatch.setitem(sys.modules, "streamlit.web.cli", cli_module)
        monkeypatch.setattr(sys, "argv", ["binarycryptolab-gui"])
        assert launcher_main([]) == 3
