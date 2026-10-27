"""End-to-end tests for the Streamlit app using Streamlit's AppTest harness.

These tests are skipped automatically when the optional ``gui`` extra is not
installed, so ``pytest -q`` works with only the core dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

streamlit = pytest.importorskip("streamlit", reason="optional GUI dependency not installed")
from streamlit.testing.v1 import AppTest  # noqa: E402

from tests.vectors import ADDRESS_P2PKH_G, PUBKEY_ONE_COMPRESSED  # noqa: E402

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "binarycryptolab" / "gui" / "app.py"


@pytest.fixture
def app() -> AppTest:
    instance = AppTest.from_file(str(APP_PATH), default_timeout=60)
    instance.run()
    assert not instance.exception
    return instance


class TestInitialRender:
    def test_tabs_and_widgets(self, app: AppTest) -> None:
        assert [tab.label for tab in app.tabs] == [
            "Analysis",
            "Hashing",
            "Public key",
            "Bitcoin address",
        ]
        assert [area.label for area in app.text_area] == [
            "Input",
            "Input to hash",
            "Public key (hexadecimal)",
        ]
        assert [button.label for button in app.button] == [
            "Analyse",
            "Hash",
            "Derive public key",
            "Derive address",
        ]
        assert any("Local, educational tool" in block.value for block in app.markdown)

    def test_no_network_dependencies(self, app: AppTest) -> None:
        # The app must not render HTTP/URL inputs or file uploaders.
        assert list(app.get("file_uploader")) == []
        assert list(app.get("camera_input")) == []


class TestAnalysisTab:
    def test_valid_binary(self, app: AppTest) -> None:
        app.text_area(key="analysis-input").set_value("101101")
        app.button(key="analysis-run").click()
        app.run()
        assert not app.exception
        result = app.session_state["analysis"]
        assert result.binary is not None
        assert result.binary.integer_value == 45
        assert len(app.dataframe) == 2
        assert list(app.get("download_button"))

    def test_hex_with_odd_length_is_rejected_when_strict(self, app: AppTest) -> None:
        app.radio(key="analysis-kind").set_value("Hex")
        app.checkbox(key="analysis-strict").check()
        app.text_area(key="analysis-input").set_value("abc")
        app.button(key="analysis-run").click()
        app.run()
        assert not app.exception
        assert "analysis" not in app.session_state
        assert any("odd number" in error.value for error in app.error)

    def test_invalid_input_shows_error(self, app: AppTest) -> None:
        app.text_area(key="analysis-input").set_value("102")
        app.button(key="analysis-run").click()
        app.run()
        assert any("InvalidBinaryError" in error.value for error in app.error)


class TestHashTab:
    def test_text_hash(self, app: AppTest) -> None:
        app.text_area(key="hash-input").set_value("abc")
        app.button(key="hash-run").click()
        app.run()
        assert not app.exception
        result = app.session_state["hash"]
        assert (
            result.hashes[0].hexdigest
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_hex_hash(self, app: AppTest) -> None:
        app.radio(key="hash-kind").set_value("Hex")
        app.text_area(key="hash-input").set_value("2d")
        app.button(key="hash-run").click()
        app.run()
        result = app.session_state["hash"]
        assert result.hashes[0].hexdigest.startswith("3973e022")


class TestPublicKeyTab:
    def test_derivation_and_redaction(self, app: AppTest) -> None:
        app.text_input(key="pk-scalar").set_value("1")
        app.button(key="pk-run").click()
        app.run()
        assert not app.exception
        result = app.session_state["public-key"]
        assert result.public_key is not None
        assert result.public_key["compressed_hex"] == PUBKEY_ONE_COMPRESSED
        assert result.original_input == "<redacted>"
        assert "1" not in result.normalized_input

    def test_invalid_scalar_shows_error(self, app: AppTest) -> None:
        app.text_input(key="pk-scalar").set_value("0")
        app.button(key="pk-run").click()
        app.run()
        assert not app.exception
        assert any("InvalidPrivateKeyError" in error.value for error in app.error)
        assert "public-key" not in app.session_state


class TestAddressTab:
    def test_derivation(self, app: AppTest) -> None:
        app.button(key="addr-run").click()
        app.run()
        assert not app.exception
        result = app.session_state["address"]
        assert result.address is not None
        assert result.address["address"] == ADDRESS_P2PKH_G

    def test_downloads_are_valid_reports(self, app: AppTest) -> None:
        app.button(key="addr-run").click()
        app.run()
        result = app.session_state["address"]
        payload = json.loads(json.dumps(result.to_dict()))
        assert payload["bitcoin_address"]["address"] == ADDRESS_P2PKH_G
        assert payload["input"]["type"] == "public_key"
