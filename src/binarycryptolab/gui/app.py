"""Streamlit interface for BinaryCryptoLab.

Run with::

    binarycryptolab-gui
    # or
    streamlit run src/binarycryptolab/gui/app.py

The interface is entirely local.  It performs no network requests, sends no
telemetry, and writes nothing to disk unless the user explicitly downloads a
report.  Private scalars are entered in a password field and are never placed
in the downloadable result: the result carries the ``<redacted>`` marker.

The interface has five tabs: analysis, hashing, public-key derivation, key
forensics, and address derivation.  Only non-sensitive results are kept in
``st.session_state`` so that download buttons survive Streamlit's re-run model.
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
    forensic_result,
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


def _forensics_tab() -> None:
    st.subheader("Public-key dissection and structural forecast")
    st.caption(
        "Every representation, bit/byte profile, curve check, digest, and address for a "
        "public key, plus a scored structural assessment. No private key is computed, "
        "searched for, or stored."
    )
    public_key = st.text_area(
        "Public key to dissect (hexadecimal)",
        value="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        height=90,
        key="forensics-public-key",
    )
    left, middle, right = st.columns(3)
    networks = left.multiselect(
        "Networks",
        options=("mainnet", "testnet", "signet", "regtest"),
        default=["mainnet", "testnet", "signet", "regtest"],
        key="forensics-networks",
    )
    depth = middle.selectbox("Depth", options=("standard", "deep"), key="forensics-depth")
    show_art = right.checkbox("Show bit grids", value=False, key="forensics-art")
    if st.button("Dissect key", type="primary", key="forensics-run"):
        try:
            st.session_state["forensics"] = forensic_result(
                public_key, networks=tuple(networks), depth=depth
            )
        except BinaryCryptoLabError as exc:
            st.error(f"{type(exc).__name__}: {exc}")
        except ValueError as exc:
            st.error(str(exc))

    result = st.session_state.get("forensics")
    if result is None or result.forensics is None:
        return
    payload = result.forensics
    forecast = payload["forecast"]
    first, second, third, fourth = st.columns(4)
    first.metric("Structure score", f"{forecast['structure_score']:.1f}/100")
    second.metric("Surprisal", f"{forecast['total_surprisal_bits']:.1f} bits")
    third.metric("Findings", str(len(payload["findings"])))
    fourth.metric("Recoverable", "no")
    st.caption(
        f"Fisher p = {forecast['combined_p_value']:.3e} | "
        f"Bonferroni p = {forecast['bonferroni_p_value']:.3e} | "
        f"structure bits = {forecast['structure_bits']:.1f}"
    )

    verdict = str(forecast["verdict"])
    if forecast["structure_score"] >= 25:
        st.error(verdict)
    else:
        st.success(verdict)
    st.caption(str(forecast["size_class"]))
    st.caption(str(forecast["summary"]))

    findings = payload["findings"]
    st.markdown("**Structural findings**")
    if findings:
        st.dataframe(
            [
                {
                    "severity": finding["severity"],
                    "code": finding["code"],
                    "evidence": finding["evidence"],
                    "probability": f"{finding['probability']:.2e}",
                    "surprisal_bits": round(finding["surprisal_bits"], 2),
                }
                for finding in findings
            ],
            width="stretch",
            hide_index=True,
        )
        for finding in findings:
            with st.expander(f"{finding['title']} ({finding['severity']})"):
                st.write(finding["interpretation"])
    else:
        st.info("No structural anomaly detected. This does not prove the key is secure.")

    st.markdown("**Hypotheses**")
    st.dataframe(
        [
            {
                "hypothesis": item["hypothesis"],
                "likelihood": item["likelihood"],
                "score": item["score"],
                "evidence": item["evidence"],
            }
            for item in forecast["hypotheses"]
        ],
        width="stretch",
        hide_index=True,
    )

    evidence = forecast.get("evidence", [])
    if evidence:
        st.markdown("**Evidence families** (independent measurements, strongest per family)")
        st.dataframe(
            [
                {
                    "family": item["family"],
                    "p_value": f"{item['p_value']:.3e}",
                    "surprisal_bits": round(item["surprisal_bits"], 2),
                    "sources": ", ".join(item["sources"]),
                    "interpretation": item["interpretation"],
                }
                for item in evidence
            ],
            width="stretch",
            hide_index=True,
        )

    randomness = payload.get("randomness", {})
    tests = randomness.get("tests", [])
    if tests:
        st.markdown("**Randomness battery**")
        st.dataframe(
            [
                {
                    "test": test["name"],
                    "statistic": round(test["statistic"], 4),
                    "p_value": f"{test['p_value']:.3e}",
                    "result": "pass" if test["passed"] else "FAIL",
                    "detail": test["detail"],
                }
                for test in tests
            ],
            width="stretch",
            hide_index=True,
        )
        st.caption(
            f"Fisher p = {randomness['fisher_p_value']:.3e} | "
            f"Bonferroni p = {randomness['bonferroni_p_value']:.3e} | "
            f"family-wise {'pass' if randomness['familywise_pass'] else 'FAIL'}"
        )
        for note in randomness.get("notes", []):
            st.caption(note)

    st.markdown("**Coordinates**")
    st.dataframe(
        [
            {
                "coordinate": name,
                "hex": profile["hexadecimal"],
                "bits": profile["bit_length"],
                "leading_zero_bits": profile["leading_zero_bits"],
                "trailing_zero_bits": profile["trailing_zero_bits"],
                "hamming_weight": profile["hamming_weight"],
                "hamming_p_value": f"{profile['hamming_p_value']:.2e}",
                "byte_entropy": round(profile["byte_entropy"], 4),
                "parity": "even" if profile["is_even"] else "odd",
            }
            for name, profile in payload["coordinates"].items()
        ],
        width="stretch",
        hide_index=True,
    )

    st.markdown("**Address matrix**")
    st.dataframe(
        [
            {
                "network": entry["network"],
                "type": entry["address_type"],
                "key": entry["key_encoding"],
                "address": entry["address"],
                "scriptPubKey": entry["script_pubkey_hex"],
                "roundtrip": entry["roundtrip_ok"],
            }
            for entry in payload["address_matrix"]
        ],
        width="stretch",
        hide_index=True,
    )

    mirror = payload["mirror_point"]
    with st.expander("Mirror point (-P, shares the same x)"):
        st.caption(mirror["note"])
        st.dataframe(
            [
                {
                    "field": "x",
                    "value": mirror["x_hex"],
                },
                {"field": "y = p - y", "value": mirror["y_hex"]},
                {"field": "compressed", "value": mirror["compressed_hex"]},
                {"field": "y parity", "value": mirror["y_parity"]},
            ],
            width="stretch",
            hide_index=True,
        )
        st.dataframe(
            [
                {
                    "type": entry["address_type"],
                    "address": entry["address"],
                    "scriptPubKey": entry["script_pubkey_hex"],
                }
                for entry in mirror["addresses"]
            ],
            width="stretch",
            hide_index=True,
        )

    with st.expander("Keyspace"):
        st.dataframe(
            [{"property": key, "value": value} for key, value in payload["keyspace"].items()],
            width="stretch",
            hide_index=True,
        )

    with st.expander("Discrete-logarithm cost (not implemented; for scale only)"):
        st.dataframe(
            [
                {
                    "strategy": row["strategy"],
                    "scalar_bits": row["scalar_bits"],
                    "operations": row["operations"],
                    "memory": row["memory"],
                    "time": row["estimated_time"],
                    "today": row["feasible_today"],
                }
                for row in forecast["search_estimates"]
            ],
            width="stretch",
            hide_index=True,
        )

    with st.expander("Bit and byte profiles"):
        st.dataframe(
            [
                {
                    "view": row["label"],
                    "bits": row["length_bits"],
                    "ones": row["ones"],
                    "one_ratio": round(row["one_ratio"], 4),
                    "entropy": round(row["entropy"], 4),
                    "longest_one_run": row["one_run_longest"],
                    "longest_zero_run": row["zero_run_longest"],
                }
                for row in payload["bit_profiles"]
            ],
            width="stretch",
            hide_index=True,
        )

    with st.expander("Digests and representations"):
        st.dataframe(
            [{"algorithm": name, "digest": value} for name, value in payload["digests"].items()],
            width="stretch",
            hide_index=True,
        )
        st.dataframe(
            [
                {
                    "label": row["label"],
                    "encoding": row["encoding"],
                    "value": row["value"],
                    "bytes": row["byte_length"],
                }
                for row in payload["representations"]
            ],
            width="stretch",
            hide_index=True,
        )

    if show_art:
        with st.expander("Bit grids", expanded=True):
            for name, profile in payload["coordinates"].items():
                st.caption(f"{name}: most significant bit first")
                st.code("\n".join(profile["bit_grid"]), language="text")

    with st.expander("Curve verification"):
        st.write(dict(payload["verification"]))

    for warning in result.warnings:
        st.warning(warning)
    _downloads("forensics", "Dissection report")


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

    analysis_tab, hash_tab, public_key_tab, forensics_tab, address_tab = st.tabs(
        ["Analysis", "Hashing", "Public key", "Key forensics", "Bitcoin address"]
    )
    with analysis_tab:
        _analysis_tab()
    with hash_tab:
        _hash_tab()
    with public_key_tab:
        _public_key_tab()
    with forensics_tab:
        _forensics_tab()
    with address_tab:
        _address_tab()


if __name__ == "__main__":
    run_app()
