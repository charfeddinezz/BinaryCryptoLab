"""Streamlit interface for BinaryCryptoLab.

Run with::

    binarycryptolab-gui
    # or
    streamlit run src/binarycryptolab/gui/app.py

The interface is entirely local.  It performs no network requests, sends no
telemetry, and writes nothing to disk unless the user explicitly downloads a
report.  Private scalars are entered in a password field and are never placed
in the downloadable result: the result carries the ``<redacted>`` marker.

Only non-sensitive results are kept in ``st.session_state`` so that download
buttons survive Streamlit's re-run model.
"""

from __future__ import annotations

import streamlit as st

from binarycryptolab._version import __version__
from binarycryptolab.config import APP_NAME
from binarycryptolab.exceptions import BinaryCryptoLabError
from binarycryptolab.gui.service import (
    address_result,
    analyse,
    download_payloads,
    hash_result,
    public_key_result,
)
from binarycryptolab.hashing import supported_algorithms
from binarycryptolab.models.analysis_result import AnalysisResult

_SECURITY_NOTICE = """
**Local, educational tool.** BinaryCryptoLab never contacts the network, never
searches for keys, and never attempts to recover anyone's private key. Use
synthetic test values only. A leaked private key must be treated as compromised,
and test keys must never be reused for funded wallets. Address derivation does
not establish ownership or balance.
"""


def _downloads(st_key: str, label: str) -> None:
    result = st.session_state.get(st_key)
    if result is None:
        return
    payloads = download_payloads(result)
    left, right = st.columns(2)
    left.download_button(
        f"{label} (JSON)",
        payloads["json"],
        file_name=f"binarycryptolab-{st_key}.json",
        mime="application/json",
        key=f"{st_key}-json",
    )
    right.download_button(
        f"{label} (CSV)",
        payloads["csv"],
        file_name=f"binarycryptolab-{st_key}.csv",
        mime="text/csv",
        key=f"{st_key}-csv",
    )


def _summary_rows(result: AnalysisResult) -> list[dict[str, str]]:
    payload = result.to_dict()["analysis"]
    rows: list[dict[str, str]] = []
    bits = payload.get("bits", {})
    for key, value in bits.items():
        rows.append({"metric": f"bits.{key}", "value": str(value)})
    byte_section = payload.get("bytes", {})
    for key, value in byte_section.items():
        if key != "frequency":
            rows.append({"metric": f"bytes.{key}", "value": str(value)})
    integer = payload.get("integer", {})
    for key, value in integer.items():
        rows.append({"metric": f"integer.{key}", "value": str(value)})
    return rows


def _analysis_tab() -> None:
    st.subheader("Binary and hexadecimal analysis")
    kind_label = st.radio("Input type", ("Binary", "Hex"), horizontal=True, key="analysis-kind")
    kind = "binary" if kind_label == "Binary" else "hex"
    text = st.text_area(
        "Input",
        value="101101" if kind == "binary" else "2d",
        height=100,
        key="analysis-input",
    )
    strict = st.checkbox("Reject odd-length hexadecimal input", value=False, key="analysis-strict")
    if st.button("Analyse", type="primary", key="analysis-run"):
        try:
            st.session_state["analysis"] = analyse(text, kind=kind, strict_hex=strict)
        except BinaryCryptoLabError as exc:
            st.error(f"{type(exc).__name__}: {exc}")
        except ValueError as exc:
            st.error(str(exc))

    result = st.session_state.get("analysis")
    if result is not None:
        with st.expander("Normalized input and warnings", expanded=True):
            st.write({"type": result.input_type, "normalized": result.normalized_input})
            for warning in result.warnings:
                st.warning(warning)
        st.dataframe(_summary_rows(result), width="stretch", hide_index=True)
        stats = result.byte_stats
        if stats is not None and stats.byte_frequency:
            st.caption("Byte frequency")
            st.dataframe(
                [
                    {"byte": f"0x{value:02x}", "count": count}
                    for value, count in stats.byte_frequency
                ],
                width="stretch",
                hide_index=True,
            )
        _downloads("analysis", "Analysis report")


def _hash_tab() -> None:
    st.subheader("Hashing")
    algorithm = st.selectbox(
        "Algorithm",
        options=[algorithm.value for algorithm in supported_algorithms()],
        key="hash-algorithm",
    )
    kind_label = st.radio("Input type", ("Text", "Hex", "Binary"), horizontal=True, key="hash-kind")
    kind = kind_label.lower()
    value = st.text_area("Input to hash", height=100, key="hash-input")
    if st.button("Hash", type="primary", key="hash-run"):
        try:
            st.session_state["hash"] = hash_result(algorithm, kind=kind, value=value)
        except BinaryCryptoLabError as exc:
            st.error(f"{type(exc).__name__}: {exc}")

    result = st.session_state.get("hash")
    if result is not None and result.hashes:
        digest = result.hashes[0]
        st.code(digest.hexdigest, language="text")
        st.caption(f"{digest.algorithm.value}, {digest.digest_length} bytes")
        for warning in result.warnings:
            st.info(warning)
        _downloads("hash", "Hash report")


def _public_key_tab() -> None:
    st.subheader("secp256k1 public-key derivation")
    st.warning(
        "Enter a synthetic test scalar only. The value is hidden on screen, used to "
        "derive a public key with the cryptography library, and never stored in the "
        "downloadable result or in logs."
    )
    scalar_text = st.text_input(
        "Private scalar (hexadecimal by default)",
        type="password",
        key="pk-scalar",
        help="Example test value: 1",
    )
    base = st.selectbox("Numeric base", options=(16, 10), index=0, key="pk-base")
    display_format = st.selectbox(
        "Public key format", options=("compressed", "uncompressed", "both"), key="pk-format"
    )
    if st.button("Derive public key", type="primary", key="pk-run"):
        try:
            st.session_state["public-key"] = public_key_result(
                scalar_text, base=base, display_format=display_format
            )
        except BinaryCryptoLabError as exc:
            st.error(f"{type(exc).__name__}: {exc}")

    result = st.session_state.get("public-key")
    if result is not None:
        info = result.public_key or {}
        st.write(
            {
                "curve": info.get("curve"),
                "x": info.get("x"),
                "y": info.get("y"),
                "compressed": info.get("compressed_hex"),
                "uncompressed": info.get("uncompressed_hex"),
            }
        )
        for warning in result.warnings:
            st.warning(warning)
        _downloads("public-key", "Public-key report")


def _address_tab() -> None:
    st.subheader("Bitcoin address derivation")
    public_key = st.text_area(
        "Public key (hexadecimal)",
        value=("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        height=100,
        key="addr-public-key",
    )
    address_type = st.selectbox("Address type", options=("p2pkh", "p2wpkh"), key="addr-type")
    network = st.selectbox(
        "Network", options=("mainnet", "testnet", "regtest", "signet"), key="addr-network"
    )
    if st.button("Derive address", type="primary", key="addr-run"):
        try:
            st.session_state["address"] = address_result(
                public_key, address_type=address_type, network=network
            )
        except BinaryCryptoLabError as exc:
            st.error(f"{type(exc).__name__}: {exc}")

    result = st.session_state.get("address")
    if result is not None:
        info = result.address or {}
        st.code(str(info.get("address", "")), language="text")
        st.write(
            {
                "type": info.get("type"),
                "network": info.get("network"),
                "hash160": info.get("hash160"),
                "witness_version": info.get("witness_version"),
                "scriptPubKey": info.get("script_pubkey_hex"),
            }
        )
        for warning in result.warnings:
            st.warning(warning)
        _downloads("address", "Address report")


def run_app() -> None:
    """Render the full Streamlit application."""
    st.set_page_config(page_title=f"{APP_NAME} {__version__}", page_icon="🔐", layout="wide")
    st.title(f"{APP_NAME} {__version__}")
    st.caption("Local binary/hex analysis, hashing, secp256k1 keys, and Bitcoin addresses.")
    with st.sidebar:
        st.header("Security")
        st.markdown(_SECURITY_NOTICE)
        st.divider()
        st.caption(
            "This interface performs no network requests and writes no files unless "
            "you download a report."
        )

    analysis_tab, hash_tab, public_key_tab, address_tab = st.tabs(
        ["Analysis", "Hashing", "Public key", "Bitcoin address"]
    )
    with analysis_tab:
        _analysis_tab()
    with hash_tab:
        _hash_tab()
    with public_key_tab:
        _public_key_tab()
    with address_tab:
        _address_tab()


if __name__ == "__main__":
    run_app()
