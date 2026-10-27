"""Pure, Streamlit-free helpers behind the graphical interface.

Keeping this logic separate means it can be unit tested without installing
Streamlit, and the CLI and GUI share identical core behaviour.

Security rules enforced here:

* a private scalar is validated and used only to derive a public key; the
  resulting :class:`AnalysisResult` redacts both ``original_input`` and
  ``normalized_input``;
* text hashed through the GUI is never stored in the returned result;
* downloads are rendered from the same immutable models as CLI reports.
"""

from __future__ import annotations

from typing import Any

from ..analysis import analyze, attach_hashes
from ..binary_utils import binary_to_bytes
from ..bitcoin import address_from_public_key
from ..ecc import public_key_from_private, public_key_info_from_hex
from ..hashing import HashAlgorithm, hash_bytes
from ..hex_utils import hex_to_bytes
from ..models.analysis_result import REDACTED, AnalysisResult
from ..reports import render_csv, render_json
from ..validation import normalize_hex

__all__ = [
    "address_result",
    "analyse",
    "download_payloads",
    "hash_result",
    "public_key_result",
]

_ALLOWED_HASH_SOURCES = frozenset({"text", "hex", "binary"})
_ALLOWED_KINDS = frozenset({"binary", "hex"})
_ALLOWED_DISPLAY_FORMATS = frozenset({"compressed", "uncompressed", "both"})


def analyse(text: str, *, kind: str, strict_hex: bool = False) -> AnalysisResult:
    """Analyse binary or hexadecimal input.

    Args:
        text: Input text.
        kind: ``"binary"`` or ``"hex"``.
        strict_hex: Whether odd-length hexadecimal input is rejected.

    Returns:
        A report-ready analysis result.

    Raises:
        InvalidBinaryError: Binary input is malformed.
        InvalidHexError: Hexadecimal input is malformed.
        ValueError: The input kind is unknown.
    """
    if kind not in _ALLOWED_KINDS:
        raise ValueError("kind must be 'binary' or 'hex'")
    return analyze(kind, text, allow_odd_hex=not strict_hex)


def hash_result(algorithm: str, *, kind: str, value: str) -> AnalysisResult:
    """Hash hexadecimal, binary, or text input and return a report-ready result.

    Args:
        algorithm: Hash algorithm name or alias.
        kind: ``"hex"``, ``"binary"``, or ``"text"``.
        value: Input value.

    Returns:
        An analysis result with the digest attached.  Text content is omitted
        from the result so that GUI downloads cannot capture a pasted secret.

    Raises:
        UnsupportedHashError: The algorithm is unknown or unavailable.
        InvalidHexError: Hexadecimal input is malformed.
        InvalidBinaryError: Binary input is malformed.
    """
    if kind not in _ALLOWED_HASH_SOURCES:
        raise ValueError("kind must be 'hex', 'binary', or 'text'")
    selected = HashAlgorithm.parse(algorithm)
    if kind == "hex":
        data = hex_to_bytes(value)
        base = analyze("hex", value)
    elif kind == "binary":
        base = analyze("binary", value)
        data = binary_to_bytes(value)
    else:
        data = value.encode("utf-8")
        base = AnalysisResult(
            input_type="text",
            original_input=f"<text input omitted, {len(data)} bytes>",
            normalized_input="<omitted>",
            warnings=(
                "Text input is hashed as UTF-8. Its content is omitted from results "
                "to avoid capturing secrets.",
            ),
            extra={"input_length_bytes": len(data)},
        )
    digest = hash_bytes(data, selected)
    return attach_hashes(base, (digest,))


def public_key_result(
    scalar_text: str, *, base: int = 16, display_format: str = "compressed"
) -> AnalysisResult:
    """Derive a public key and return a redacted, report-ready result.

    Args:
        scalar_text: Private scalar as text.
        base: ``16`` (default) or ``10``.
        display_format: ``"compressed"``, ``"uncompressed"``, or ``"both"``.

    Returns:
        An analysis result containing only public key data.  The input fields
        are the literal ``<redacted>`` marker.

    Raises:
        InvalidPrivateKeyError: The scalar is malformed or out of range.
        ValueError: The display format is unknown.
    """
    if display_format not in _ALLOWED_DISPLAY_FORMATS:
        raise ValueError("display_format must be 'compressed', 'uncompressed', or 'both'")
    info = public_key_from_private(scalar_text, base=base)
    return AnalysisResult(
        input_type="private_key",
        original_input=REDACTED,
        normalized_input=REDACTED,
        public_key=info.as_dict(),
        warnings=(
            "The private scalar was validated but is deliberately absent from this result.",
            "Use synthetic test values only; never reuse a test key in a funded wallet.",
        ),
        extra={"display_format": display_format},
    )


def address_result(
    public_key_hex: str, *, address_type: str = "p2pkh", network: str = "mainnet"
) -> AnalysisResult:
    """Derive a Bitcoin address from a public key.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        address_type: ``"p2pkh"`` or ``"p2wpkh"``.
        network: ``"mainnet"``, ``"testnet"``, ``"regtest"``, or ``"signet"``.

    Returns:
        An analysis result with public key and address sections.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
        AddressEncodingError: The type, network, or key encoding is invalid.
    """
    public_info = public_key_info_from_hex(public_key_hex)
    address_info = address_from_public_key(
        public_key_hex, address_type=address_type, network=network
    )
    warnings = [
        "Address derivation is a local computation; no blockchain data was queried.",
        "An address does not prove ownership and does not contain funds by itself.",
    ]
    if network in {"testnet", "regtest", "signet"}:
        warnings.append(f"{network} addresses are for testing only.")
    return AnalysisResult(
        input_type="public_key",
        original_input=public_key_hex,
        normalized_input=normalize_hex(public_key_hex, allow_odd=False),
        public_key=public_info.as_dict(),
        address=address_info.as_dict(),
        warnings=tuple(warnings),
    )


def download_payloads(result: AnalysisResult) -> dict[str, Any]:
    """Return downloadable JSON and CSV text for *result*.

    Returns:
        A mapping with ``"json"`` and ``"csv"`` string values.  Both are
        generated from the same immutable model, so they can never contain a
        private scalar that the model itself does not hold.
    """
    return {"json": render_json(result), "csv": render_csv(result)}
