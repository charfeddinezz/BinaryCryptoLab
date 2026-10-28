"""One decoder for every address and locking-script scenario this tool accepts.

The Bitcoin module :mod:`binarycryptolab.bitcoin` derives and validates the four
Bitcoin address forms it can create.  That is the right scope for a generator, but
it is too narrow for a forensic reader: a real input can be a Litecoin address, a
BIP-21 payment URI, a Taproot output, an unknown witness version, a bare script,
or a private key pasted by mistake.

This module closes that gap.  It recognises:

* Base58Check addresses on Bitcoin and on several derivative chains, including the
  two-byte version prefixes Zcash uses;
* Bech32 and Bech32m addresses for any registered human-readable part, in upper
  case as BIP-173 permits;
* CashAddr addresses (BCH) in ``bitcoincash:``, ``bchtest:``, and ``bchreg:`` form;
* BIP-21 payment URIs, with their query parameters preserved;
* raw ``scriptPubKey`` hex for P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, other
  witness versions, and OP_RETURN;
* and it **refuses** WIF private keys, without echoing them.

Chain recognition is advisory metadata.  Version bytes are conventions, not
consensus: the same byte can mean different things on different chains, so the
decoder returns every candidate instead of inventing certainty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from .base58 import b58decode
from .bech32 import Bech32Spec, bech32_decode, convert_5_to_8, encode_segwit_address
from .bitcoin import Network, p2pkh_address_from_hash160, p2sh_address_from_script_hash
from .exceptions import (
    AddressEncodingError,
    InputValidationError,
    InvalidBase58Error,
    PrivateKeyMaterialError,
)
from .hashing import double_sha256

__all__ = [
    "BASE58_FORMATS",
    "BECH32_FORMATS",
    "CASHADDR_PREFIXES",
    "KNOWN_ADDRESSES",
    "AddressFormat",
    "DecodedInput",
    "KnownAddress",
    "base58_candidates",
    "bech32_format",
    "decode_address_input",
    "decode_cashaddr",
    "decode_script_pubkey",
    "encode_cashaddr",
    "lookup_known_address",
    "normalize_text",
    "script_to_address",
]

_CHECKSUM_BYTES: Final = 4
_HASH160_BYTES: Final = 20
_SHA256_BYTES: Final = 32
_WIF_VERSIONS: Final = (0x80, 0xEF)
_ZERO_WIDTH: Final = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"), None)


# ---------------------------------------------------------------------------
# Format registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AddressFormat:
    """One documented address format.

    Attributes:
        chain: Chain name, e.g. ``bitcoin``.
        kind: ``p2pkh``, ``p2sh``, ``p2wpkh``, ``p2wsh``, ``p2tr``, or
            ``witness_vN``.
        network: ``mainnet``, ``testnet``, ``signet``, or ``regtest``.
        encoding: ``base58check``, ``bech32``, ``bech32m``, or ``cashaddr``.
        version: Version prefix as an integer, or ``None`` for Bech32/CashAddr.
        version_bytes: Width of the version prefix.
        human_readable_part: Bech32 HRP or CashAddr prefix, or ``None``.
        status: ``current``, ``legacy``, or ``shared``.
        note: Why the entry exists, and how far it can be trusted.
    """

    chain: str
    kind: str
    network: str
    encoding: str
    version: int | None = None
    version_bytes: int = 1
    human_readable_part: str | None = None
    status: str = "current"
    note: str = ""

    @property
    def version_hex(self) -> str:
        """Return the version prefix as hexadecimal, or an empty string."""
        if self.version is None:
            return ""
        return f"{self.version:0{self.version_bytes * 2}x}"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "chain": self.chain,
            "kind": self.kind,
            "network": self.network,
            "encoding": self.encoding,
            "version_hex": self.version_hex,
            "human_readable_part": self.human_readable_part,
            "status": self.status,
            "note": self.note,
        }


_BASE58_NOTE: Final = (
    "Version prefixes are project conventions, not consensus rules; the same byte "
    "can be valid on several chains, so every candidate is reported."
)

BASE58_FORMATS: Final[tuple[AddressFormat, ...]] = (
    # Bitcoin
    AddressFormat(
        "bitcoin", "p2pkh", "mainnet", "base58check", 0x00, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "bitcoin", "p2sh", "mainnet", "base58check", 0x05, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "bitcoin", "p2pkh", "testnet", "base58check", 0x6F, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "bitcoin", "p2sh", "testnet", "base58check", 0xC4, 1, None, "current", _BASE58_NOTE
    ),
    # Bitcoin Cash kept the original Bitcoin prefixes for its legacy format.
    AddressFormat(
        "bitcoin_cash", "p2pkh", "mainnet", "base58check", 0x00, 1, None, "legacy", _BASE58_NOTE
    ),
    AddressFormat(
        "bitcoin_cash", "p2sh", "mainnet", "base58check", 0x05, 1, None, "legacy", _BASE58_NOTE
    ),
    # Litecoin
    AddressFormat(
        "litecoin", "p2pkh", "mainnet", "base58check", 0x30, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "litecoin", "p2sh", "mainnet", "base58check", 0x32, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "litecoin", "p2sh", "mainnet", "base58check", 0x05, 1, None, "legacy", _BASE58_NOTE
    ),
    AddressFormat(
        "litecoin", "p2pkh", "testnet", "base58check", 0x6F, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "litecoin", "p2sh", "testnet", "base58check", 0x3A, 1, None, "current", _BASE58_NOTE
    ),
    # Dogecoin
    AddressFormat(
        "dogecoin", "p2pkh", "mainnet", "base58check", 0x1E, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "dogecoin", "p2sh", "mainnet", "base58check", 0x16, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "dogecoin", "p2pkh", "testnet", "base58check", 0x71, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "dogecoin", "p2sh", "testnet", "base58check", 0xC4, 1, None, "current", _BASE58_NOTE
    ),
    # Dash
    AddressFormat(
        "dash", "p2pkh", "mainnet", "base58check", 0x4C, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat("dash", "p2sh", "mainnet", "base58check", 0x10, 1, None, "current", _BASE58_NOTE),
    AddressFormat(
        "dash", "p2pkh", "testnet", "base58check", 0x8C, 1, None, "current", _BASE58_NOTE
    ),
    AddressFormat("dash", "p2sh", "testnet", "base58check", 0x13, 1, None, "current", _BASE58_NOTE),
    # Zcash transparent addresses use two-byte prefixes.
    AddressFormat(
        "zcash", "p2pkh", "mainnet", "base58check", 0x1CB8, 2, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "zcash", "p2sh", "mainnet", "base58check", 0x1CBD, 2, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "zcash", "p2pkh", "testnet", "base58check", 0x1D25, 2, None, "current", _BASE58_NOTE
    ),
    AddressFormat(
        "zcash", "p2sh", "testnet", "base58check", 0x1CBA, 2, None, "current", _BASE58_NOTE
    ),
)

_BECH32_NOTE: Final = (
    "The HRP names the chain and network; the version and program decide the type."
)

BECH32_FORMATS: Final[tuple[AddressFormat, ...]] = (
    AddressFormat("bitcoin", "segwit", "mainnet", "bech32", None, 0, "bc", "current", _BECH32_NOTE),
    AddressFormat("bitcoin", "segwit", "testnet", "bech32", None, 0, "tb", "current", _BECH32_NOTE),
    AddressFormat("bitcoin", "segwit", "signet", "bech32", None, 0, "tb", "current", _BECH32_NOTE),
    AddressFormat(
        "bitcoin", "segwit", "regtest", "bech32", None, 0, "bcrt", "current", _BECH32_NOTE
    ),
    AddressFormat(
        "litecoin", "segwit", "mainnet", "bech32", None, 0, "ltc", "current", _BECH32_NOTE
    ),
    AddressFormat(
        "litecoin", "segwit", "testnet", "bech32", None, 0, "tltc", "current", _BECH32_NOTE
    ),
    AddressFormat(
        "litecoin", "segwit", "regtest", "bech32", None, 0, "rltc", "current", _BECH32_NOTE
    ),
)

CASHADDR_PREFIXES: Final[dict[str, tuple[str, str]]] = {
    "bitcoincash": ("bitcoin_cash", "mainnet"),
    "bchtest": ("bitcoin_cash", "testnet"),
    "bchreg": ("bitcoin_cash", "regtest"),
}


def base58_candidates(version: int) -> tuple[AddressFormat, ...]:
    """Return every registered format that uses *version* as its prefix.

    Args:
        version: Version prefix interpreted as a big-endian integer.

    Returns:
        Zero or more candidate formats.  Two candidates mean the address is valid
        on two chains and the tool refuses to pick one.
    """
    return tuple(
        item for item in BASE58_FORMATS if item.version is not None and item.version == version
    )


def bech32_format(hrp: str) -> AddressFormat | None:
    """Return the registered Bech32 format for *hrp*, if any."""
    lowered = hrp.lower()
    for item in BECH32_FORMATS:
        if item.human_readable_part == lowered:
            return item
    return None


# ---------------------------------------------------------------------------
# Documented addresses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KnownAddress:
    """A publicly documented address, recognised offline.

    Attributes:
        address: The address string in its canonical form.
        label: Human-readable name.
        kind: ``burn``, ``genesis``, ``vector``, or ``unspendable``.
        reference: Where the claim comes from, so it can be checked.
        meaning: What the entry implies for a user who pastes it.
    """

    address: str
    label: str
    kind: str
    reference: str
    meaning: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "label": self.label,
            "kind": self.kind,
            "reference": self.reference,
            "meaning": self.meaning,
        }


KNOWN_ADDRESSES: Final[tuple[KnownAddress, ...]] = (
    KnownAddress(
        address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        label="genesis coinbase output",
        kind="genesis",
        reference="Bitcoin block 0, the coinbase transaction of 2009-01-03",
        meaning=(
            "The block 0 coinbase output is not in the UTXO set, so it is "
            "unspendable by consensus regardless of who holds the key."
        ),
    ),
    KnownAddress(
        address="1111111111111111111114oLvT2",
        label="null payload (all-zero HASH160)",
        kind="unspendable",
        reference="Base58Check encoding of version 0x00 with a 20-byte zero payload",
        meaning=(
            "Spending requires a public key whose HASH160 is all zeros, which "
            "nobody can produce; funds sent here are destroyed."
        ),
    ),
    KnownAddress(
        address="1BitcoinEaterAddressDontSendf59kuE",
        label="Bitcoin Eater",
        kind="burn",
        reference="A long-documented community burn address",
        meaning=(
            "Widely used to destroy coins. Treat any payment as permanently lost; "
            "the tool cannot prove the key is unknown, only that this is the "
            "documented purpose."
        ),
    ),
    KnownAddress(
        address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        label="BIP-173 test vector (P2WPKH)",
        kind="vector",
        reference="BIP-173, valid address section",
        meaning=(
            "A published example used by test suites. Funds sent to a test vector "
            "are not necessarily lost, but the vector's key is public."
        ),
    ),
    KnownAddress(
        address="bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        label="BIP-350 test vector (P2TR)",
        kind="vector",
        reference="BIP-350, valid Bech32m address section",
        meaning=(
            "A published Taproot example. It is a valid output key, not a claim "
            "about who can spend it."
        ),
    ),
)


def lookup_known_address(address: str) -> KnownAddress | None:
    """Return the documented entry for *address*, if the table contains it."""
    lowered = address.strip().lower()
    for entry in KNOWN_ADDRESSES:
        if entry.address.lower() == lowered:
            return entry
    return None


# ---------------------------------------------------------------------------
# CashAddr (Bitcoin Cash)
# ---------------------------------------------------------------------------

_CASHADDR_CHARSET: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CASHADDR_GENERATORS: Final = (
    0x98F2BC8E61,
    0x79B76D99E2,
    0xF33E5FB3C4,
    0xAE2EABE2A8,
    0x1E4F43E470,
)
_CASHADDR_CHECKSUM_LENGTH: Final = 8


def _cashaddr_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, generator in enumerate(_CASHADDR_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum ^ 1


def _cashaddr_prefix_data(prefix: str) -> list[int]:
    return [ord(character) & 0x1F for character in prefix] + [0]


def encode_cashaddr(prefix: str, payload: bytes, *, kind: str = "p2pkh") -> str:
    """Encode *payload* as a CashAddr string.

    Args:
        prefix: ``bitcoincash``, ``bchtest``, or ``bchreg``.
        payload: 20-byte hash (P2PKH or P2SH).
        kind: ``p2pkh`` or ``p2sh``.

    Returns:
        The address with its prefix, e.g. ``bitcoincash:q...``.

    Raises:
        ValueError: The prefix, kind, or payload length is invalid.
    """
    lowered = prefix.lower()
    if lowered not in CASHADDR_PREFIXES:
        raise ValueError(f"unknown CashAddr prefix {prefix!r}")
    if len(payload) != _HASH160_BYTES:
        raise ValueError("CashAddr payload must be 20 bytes")
    if kind not in ("p2pkh", "p2sh"):
        raise ValueError("CashAddr kind must be 'p2pkh' or 'p2sh'")
    version = 0x00 if kind == "p2pkh" else 0x08
    data = _convert_8_to_5(bytes([version]) + payload)
    checksum_input = _cashaddr_prefix_data(lowered) + data + [0] * _CASHADDR_CHECKSUM_LENGTH
    checksum = _cashaddr_polymod(checksum_input)
    tail = [(checksum >> (5 * (7 - index))) & 0x1F for index in range(_CASHADDR_CHECKSUM_LENGTH)]
    encoded = "".join(_CASHADDR_CHARSET[value] for value in data + tail)
    return f"{lowered}:{encoded}"


def _convert_8_to_5(payload: bytes) -> list[int]:
    accumulator = 0
    bits = 0
    out: list[int] = []
    for byte in payload:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((accumulator >> bits) & 0x1F)
    if bits:
        out.append((accumulator << (5 - bits)) & 0x1F)
    return out


def _cashaddr_bytes(groups: list[int]) -> bytes:
    """Regroup 5-bit values into bytes, rejecting invalid padding."""
    accumulator = 0
    bits = 0
    out = bytearray()
    for group in groups:
        accumulator = (accumulator << 5) | group
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    if bits >= 5:
        raise AddressEncodingError("invalid padding in CashAddr payload")
    if accumulator & ((1 << bits) - 1):
        raise AddressEncodingError("non-zero padding bits in CashAddr payload")
    return bytes(out)


def decode_cashaddr(text: str) -> tuple[str, str, bytes]:
    """Decode a CashAddr address.

    Args:
        text: ``prefix:payload`` in either case.

    Returns:
        ``(prefix, kind, payload)`` where kind is ``p2pkh`` or ``p2sh``.

    Raises:
        AddressEncodingError: The prefix is unknown, a character is outside the
            charset, or the checksum does not verify.
    """
    lowered = text.strip().lower()
    if ":" not in lowered:
        raise AddressEncodingError("CashAddr addresses require an explicit prefix")
    prefix, _, body = lowered.partition(":")
    if prefix not in CASHADDR_PREFIXES:
        raise AddressEncodingError(f"unknown CashAddr prefix {prefix!r}")
    data: list[int] = []
    for character in body:
        index = _CASHADDR_CHARSET.find(character)
        if index < 0:
            raise AddressEncodingError(f"invalid CashAddr character {character!r}")
        data.append(index)
    if len(data) < _CASHADDR_CHECKSUM_LENGTH + 2:
        raise AddressEncodingError("CashAddr payload is too short")
    checksum_input = _cashaddr_prefix_data(prefix) + data
    if _cashaddr_polymod(checksum_input) != 0:
        raise AddressEncodingError("CashAddr checksum does not verify")
    raw_body = _cashaddr_bytes(data[:-_CASHADDR_CHECKSUM_LENGTH])
    if len(raw_body) < 2:
        raise AddressEncodingError("CashAddr body is too short")
    version, payload = raw_body[0], raw_body[1:]
    kind = "p2pkh" if (version & 0x08) == 0 else "p2sh"
    if len(payload) != _HASH160_BYTES:
        raise AddressEncodingError("CashAddr payload must be 20 bytes")
    return prefix, kind, payload


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_BIP21_PARAMETERS: Final = ("amount", "label", "message", "lightning", "req-")
_SCRIPT_PATTERN: Final = re.compile(
    r"^(?:76a914[0-9a-f]{40}88ac"  # P2PKH
    r"|a914[0-9a-f]{40}87"  # P2SH
    r"|00(?:14[0-9a-f]{40}|20[0-9a-f]{64})"  # P2WPKH, P2WSH
    r"|5[1-9a-f]20[0-9a-f]{64}"  # Taproot and other v1..v16 32-byte programs
    r"|21[0-9a-f]{66}ac"  # P2PK, compressed
    r"|41[0-9a-f]{130}ac"  # P2PK, uncompressed
    r"|6a[0-9a-f]*)$"  # OP_RETURN
)


def normalize_text(text: str) -> str:
    """Strip whitespace, quotes, and zero-width characters from *text*.

    Raises:
        InputValidationError: The result is empty.
    """
    if not isinstance(text, str):
        raise InputValidationError("address input must be a string")
    cleaned = text.translate(_ZERO_WIDTH).strip().strip("\"'").strip()
    if not cleaned:
        raise InputValidationError("address input is empty")
    return cleaned


@dataclass(frozen=True, slots=True)
class DecodedInput:
    """The result of decoding any accepted address or script input.

    Attributes:
        input_kind: ``address``, ``bip21_uri``, or ``script_pubkey``.
        original: Exactly what the caller supplied, after normalisation.
        address: Canonical address string, or ``None`` for script-only inputs.
        encoding: ``base58check``, ``bech32``, ``bech32m``, ``cashaddr``,
            ``script``, or ``none``.
        address_type: ``p2pkh``, ``p2sh``, ``p2wpkh``, ``p2wsh``, ``p2tr``,
            ``witness_vN``, ``p2pk``, ``op_return``, or ``nonstandard``.
        chain: Best-known chain name.
        chain_candidates: Every chain consistent with the format.
        network: Best-known network.
        network_ambiguous: Whether several networks share these parameters.
        version_byte: Version prefix value, when applicable.
        version_bytes: Width of that prefix.
        human_readable_part: Bech32 HRP or CashAddr prefix.
        payload: Hash or witness program.
        checksum_hex: Checksum as encoded.
        recomputed_checksum_hex: Checksum recomputed locally.
        checksum_valid: Whether the two agree.
        witness_version: Witness version for SegWit outputs.
        leading_zero_bytes: Zero bytes before the payload.
        base58_leading_ones: Leading ``1`` characters.
        uri_params: BIP-21 query parameters, as ordered pairs.
        formats: Candidate formats behind this input.
        notes: Observations collected during decoding.
    """

    input_kind: str
    original: str
    address: str | None
    encoding: str
    address_type: str
    chain: str
    chain_candidates: tuple[str, ...]
    network: str
    network_ambiguous: bool
    version_byte: int | None
    version_bytes: int
    human_readable_part: str | None
    payload: bytes
    checksum_hex: str
    recomputed_checksum_hex: str
    checksum_valid: bool
    witness_version: int | None
    leading_zero_bytes: int
    base58_leading_ones: int
    uri_params: tuple[tuple[str, str], ...]
    formats: tuple[AddressFormat, ...]
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "input_kind": self.input_kind,
            "original": self.original,
            "address": self.address,
            "encoding": self.encoding,
            "type": self.address_type,
            "chain": self.chain,
            "chain_candidates": list(self.chain_candidates),
            "network": self.network,
            "network_ambiguous": self.network_ambiguous,
            "version_hex": (
                None
                if self.version_byte is None
                else f"{self.version_byte:0{self.version_bytes * 2}x}"
            ),
            "human_readable_part": self.human_readable_part,
            "payload_hex": self.payload.hex(),
            "checksum_hex": self.checksum_hex,
            "recomputed_checksum_hex": self.recomputed_checksum_hex,
            "checksum_valid": self.checksum_valid,
            "witness_version": self.witness_version,
            "leading_zero_bytes": self.leading_zero_bytes,
            "base58_leading_ones": self.base58_leading_ones,
            "uri_params": [{"name": name, "value": value} for name, value in self.uri_params],
            "formats": [item.as_dict() for item in self.formats],
            "notes": list(self.notes),
        }


def _require_address(text: str) -> str:
    """Return *text* if it looks like an address, else raise."""
    if not text:
        raise InputValidationError("address input is empty")
    return text


def decode_address_input(text: str, *, network: str | Network | None = None) -> DecodedInput:
    """Decode any accepted input into a :class:`DecodedInput`.

    Args:
        text: An address, a BIP-21 URI, or a raw ``scriptPubKey`` in hexadecimal.
        network: Expected network name.  When given, a mismatch raises.

    Returns:
        The decoded input.

    Raises:
        AddressEncodingError: The input is malformed or fails its checksum.
        InputValidationError: The input is empty or is private key material.
    """
    cleaned = normalize_text(text)
    lowered = cleaned.lower()
    uri_params: tuple[tuple[str, str], ...] = ()
    if lowered.startswith(("bitcoin:", "litecoin:", "dogecoin:", "dash:")):
        cleaned, uri_params = _split_bip21(cleaned)
        lowered = cleaned.lower()

    if lowered.startswith(tuple(f"{prefix}:" for prefix in CASHADDR_PREFIXES)):
        decoded = _decode_cashaddr_input(cleaned, uri_params)
    elif lowered.startswith("script:"):
        decoded = decode_script_pubkey(cleaned[len("script:") :], network=network)
    elif _looks_like_script(cleaned):
        decoded = decode_script_pubkey(cleaned, network=network)
    elif _looks_like_bech32(cleaned):
        try:
            decoded = _decode_bech32_input(cleaned, uri_params)
        except AddressEncodingError:
            # A Base58Check address may coincidentally look like Bech32; only fall
            # back when Base58 actually decodes, so real Bech32 errors still show.
            decoded = _decode_base58_input(cleaned, uri_params)
    elif _is_hexish(cleaned):
        raise AddressEncodingError(
            "hexadecimal input is not a recognised locking script; prefix it with "
            "'script:' to force script interpretation, or supply an address"
        )
    elif "1" in lowered and lowered.split("1", 1)[0] in {
        item.human_readable_part for item in BECH32_FORMATS
    }:
        decoded = _decode_bech32_input(cleaned, uri_params)
    else:
        decoded = _decode_base58_input(cleaned, uri_params)

    if network is not None:
        _check_network(decoded, network)
    return decoded


def _split_bip21(text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Split a BIP-21 URI into its address and query parameters."""
    _, _, remainder = text.partition(":")
    address, _, query = remainder.partition("?")
    address = address.strip()
    if not address:
        raise InputValidationError("BIP-21 URI is missing its address part")
    params: list[tuple[str, str]] = []
    for chunk in query.split("&"):
        if not chunk:
            continue
        name, _, value = chunk.partition("=")
        if not name:
            continue
        params.append((name.strip(), value.strip()))
    return address, tuple(params)


_BECH32_SHAPE: Final = re.compile(r"^[a-z]{1,8}1[023456789acdefghjklmnpqrstuvwxyz]{6,}$")


def _looks_like_bech32(text: str) -> bool:
    """Return whether *text* has the shape of a Bech32 string (any HRP)."""
    return bool(_BECH32_SHAPE.fullmatch(text.lower()))


def _is_hexish(text: str) -> bool:
    """Return whether *text* consists only of hexadecimal digits."""
    return len(text) >= 8 and all(character in "0123456789abcdef" for character in text.lower())


def _looks_like_script(text: str) -> bool:
    lowered = text.lower()
    if len(lowered) < 6 or len(lowered) % 2:
        return False
    if any(character not in "0123456789abcdef" for character in lowered):
        return False
    return bool(_SCRIPT_PATTERN.fullmatch(lowered))


def _check_network(decoded: DecodedInput, expected: str | Network) -> None:
    """Raise when *decoded* does not match the expected network."""
    selected = Network.parse(expected).value
    compatible = {decoded.network, *decoded.chain_candidates}
    aliases = {
        "testnet": {"testnet", "signet", "regtest"},
        "signet": {"signet", "testnet", "regtest"},
        "regtest": {"regtest", "testnet", "signet"},
    }
    allowed = aliases.get(selected, {selected})
    if decoded.network not in allowed and selected not in compatible:
        raise AddressEncodingError(
            f"address belongs to {decoded.network!r}, not to the expected {selected!r}"
        )


def _decode_base58_input(text: str, uri_params: tuple[tuple[str, str], ...]) -> DecodedInput:
    """Decode a Base58Check address on any registered chain."""
    try:
        raw = b58decode(text)
    except Exception as exc:
        raise AddressEncodingError(f"invalid Base58Check address: {exc}") from exc
    if len(raw) < _CHECKSUM_BYTES + 2:
        raise AddressEncodingError("Base58Check data is too short")
    body, checksum = raw[:-_CHECKSUM_BYTES], raw[-_CHECKSUM_BYTES:]
    recomputed = double_sha256(body)[:_CHECKSUM_BYTES]
    if checksum != recomputed:
        raise InvalidBase58Error("Base58Check checksum does not verify")

    # Refuse private key material before anything is printed or stored.
    for width in (1, 2):
        if len(body) > width and int.from_bytes(body[:width], "big") in _WIF_VERSIONS:
            rest = len(body) - width
            if rest in (32, 33):
                raise PrivateKeyMaterialError(
                    "input looks like a WIF-encoded private key: it was refused, "
                    "not analysed, and not repeated in this message"
                )

    for width in (1, 2):
        payload = body[width:]
        if len(payload) != _HASH160_BYTES:
            continue
        version = int.from_bytes(body[:width], "big")
        formats = tuple(item for item in base58_candidates(version) if item.version_bytes == width)
        if not formats:
            continue
        kinds = {item.kind for item in formats}
        kind = kinds.pop() if len(kinds) == 1 else "unknown"
        chains = tuple(dict.fromkeys(item.chain for item in formats))
        networks = tuple(dict.fromkeys(item.network for item in formats))
        notes: list[str] = []
        if len(formats) > 1:
            notes.append(
                "The same version byte is registered on several chains, so the "
                "chain is reported as a set rather than a fact."
            )
        return DecodedInput(
            input_kind="bip21_uri" if uri_params else "address",
            original=text,
            address=text,
            encoding="base58check",
            address_type=kind,
            chain=chains[0],
            chain_candidates=chains,
            network=networks[0],
            network_ambiguous=len(networks) > 1,
            version_byte=version,
            version_bytes=width,
            human_readable_part=None,
            payload=payload,
            checksum_hex=checksum.hex(),
            recomputed_checksum_hex=recomputed.hex(),
            checksum_valid=True,
            witness_version=None,
            leading_zero_bytes=len(body) - len(body.lstrip(b"\x00")),
            base58_leading_ones=len(text) - len(text.lstrip("1")),
            uri_params=uri_params,
            formats=formats,
            notes=tuple(notes),
        )
    raise AddressEncodingError(
        "Base58Check payload is not 20 bytes, or the version prefix is not registered"
    )


def _decode_bech32_input(text: str, uri_params: tuple[tuple[str, str], ...]) -> DecodedInput:
    """Decode a Bech32 or Bech32m SegWit address for any registered HRP."""
    if text.lower() != text and text.upper() != text:
        raise AddressEncodingError(
            "Bech32 addresses must be uniformly lower case or uniformly upper case"
        )
    lowered = text.lower()
    try:
        hrp, data, spec = bech32_decode(lowered)
    except Exception as exc:
        raise AddressEncodingError(f"invalid Bech32 address: {exc}") from exc
    if not data:
        raise AddressEncodingError("Bech32 address is missing its witness version")
    witness_version = data[0]
    if witness_version > 16:
        raise AddressEncodingError("witness version must be between 0 and 16")
    payload = convert_5_to_8(data[1:], pad=False)
    if not 2 <= len(payload) <= 40:
        raise AddressEncodingError("witness program must be 2..40 bytes")
    expected = Bech32Spec.BECH32 if witness_version == 0 else Bech32Spec.BECH32M
    if spec is not expected:
        raise AddressEncodingError(
            f"witness version {witness_version} requires {expected.value} encoding"
        )
    if witness_version == 0 and len(payload) not in (_HASH160_BYTES, _SHA256_BYTES):
        raise AddressEncodingError("witness version 0 programs must be 20 or 32 bytes")

    registered = bech32_format(hrp)
    chains = (registered.chain,) if registered is not None else ("unknown",)
    networks: tuple[str, ...] = (registered.network,) if registered is not None else ("unknown",)
    notes: list[str] = []
    if registered is None:
        notes.append(f"The prefix {hrp!r} is not registered, so the chain is unknown.")
    if hrp == "tb":
        networks = ("testnet", "signet")
        notes.append("The prefix 'tb' is shared by testnet and signet.")
    kind = _witness_kind(witness_version, payload)
    return DecodedInput(
        input_kind="bip21_uri" if uri_params else "address",
        original=text,
        address=lowered,
        encoding="bech32" if spec is Bech32Spec.BECH32 else "bech32m",
        address_type=kind,
        chain=chains[0],
        chain_candidates=chains,
        network=networks[0],
        network_ambiguous=len(networks) > 1,
        version_byte=None,
        version_bytes=0,
        human_readable_part=hrp,
        payload=payload,
        checksum_hex="",
        recomputed_checksum_hex="",
        checksum_valid=True,
        witness_version=witness_version,
        leading_zero_bytes=0,
        base58_leading_ones=0,
        uri_params=uri_params,
        formats=() if registered is None else (registered,),
        notes=tuple(notes),
    )


def _witness_kind(witness_version: int, payload: bytes) -> str:
    """Return the address type for a witness version and program."""
    if witness_version == 0:
        return "p2wpkh" if len(payload) == _HASH160_BYTES else "p2wsh"
    if witness_version == 1 and len(payload) == _SHA256_BYTES:
        return "p2tr"
    return f"witness_v{witness_version}"


def _decode_cashaddr_input(text: str, uri_params: tuple[tuple[str, str], ...]) -> DecodedInput:
    """Decode a CashAddr address."""
    prefix, kind, payload = decode_cashaddr(text)
    chain, network = CASHADDR_PREFIXES[prefix]
    checksum = text.strip().lower().rpartition(":")[2][-8:]
    return DecodedInput(
        input_kind="bip21_uri" if uri_params else "address",
        original=text,
        address=text.strip().lower(),
        encoding="cashaddr",
        address_type=kind,
        chain=chain,
        chain_candidates=(chain,),
        network=network,
        network_ambiguous=False,
        version_byte=None,
        version_bytes=0,
        human_readable_part=prefix,
        payload=payload,
        checksum_hex=checksum,
        recomputed_checksum_hex=checksum,
        checksum_valid=True,
        witness_version=None,
        leading_zero_bytes=0,
        base58_leading_ones=0,
        uri_params=uri_params,
        formats=(),
        notes=("CashAddr encodes the type in its version byte, not in the prefix.",),
    )


# ---------------------------------------------------------------------------
# Locking scripts
# ---------------------------------------------------------------------------

_OP_RETURN: Final = 0x6A
_OP_DUP: Final = 0x76
_OP_HASH160: Final = 0xA9
_OP_EQUAL: Final = 0x87
_OP_EQUALVERIFY: Final = 0x88
_OP_CHECKSIG: Final = 0xAC


def decode_script_pubkey(script_hex: str, *, network: str | Network | None = None) -> DecodedInput:
    """Decode a raw ``scriptPubKey`` and derive the address it pays to.

    Args:
        script_hex: Script bytes in hexadecimal, optionally prefixed with ``0x``.
        network: Network used when encoding the derived address.

    Returns:
        The decoded script.  ``address`` is ``None`` for scripts that have no
        address form (P2PK, OP_RETURN, non-standard).

    Raises:
        AddressEncodingError: The script is empty or malformed.
    """
    cleaned = script_hex.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 or not cleaned:
        raise AddressEncodingError("scriptPubKey must be an even number of hex digits")
    try:
        script = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise AddressEncodingError("scriptPubKey is not valid hexadecimal") from exc
    selected = Network.parse(network) if network is not None else Network.MAINNET

    kind, payload, address, witness_version = _classify_script(script, selected)
    return DecodedInput(
        input_kind="script_pubkey",
        original=script_hex,
        address=address,
        encoding="script",
        address_type=kind,
        chain="bitcoin",
        chain_candidates=("bitcoin",),
        network=selected.value,
        network_ambiguous=False,
        version_byte=None,
        version_bytes=0,
        human_readable_part=None,
        payload=payload,
        checksum_hex="",
        recomputed_checksum_hex="",
        checksum_valid=True,
        witness_version=witness_version,
        leading_zero_bytes=len(payload) - len(payload.lstrip(b"\x00")) if payload else 0,
        base58_leading_ones=0,
        uri_params=(),
        formats=(),
        notes=("The input was a locking script; the address shown is derived from it.",),
    )


def _classify_script(script: bytes, network: Network) -> tuple[str, bytes, str | None, int | None]:
    """Return ``(kind, payload, address, witness_version)`` for a script."""
    if not script:
        raise AddressEncodingError("scriptPubKey is empty")
    if (
        len(script) == 25
        and script[0] == _OP_DUP
        and script[1] == _OP_HASH160
        and script[2] == 20
        and script[23] == _OP_EQUALVERIFY
        and script[24] == _OP_CHECKSIG
    ):
        payload = script[3:23]
        return "p2pkh", payload, p2pkh_address_from_hash160(payload, network), None
    if (
        len(script) == 23
        and script[0] == _OP_HASH160
        and script[1] == 20
        and script[22] == _OP_EQUAL
    ):
        payload = script[2:22]
        return "p2sh", payload, p2sh_address_from_script_hash(payload, network), None
    if len(script) >= 2 and script[0] == 0x00 and script[1] != len(script) - 2:
        raise AddressEncodingError(
            "witness version 0 output declares a program length that does not match the script"
        )
    if len(script) >= 4 and script[0] == 0x00 and script[1] == len(script) - 2:
        program = script[2:]
        if len(program) not in (20, 32):
            raise AddressEncodingError("witness version 0 programs must be 20 or 32 bytes")
        address = encode_segwit_address(network.bech32_hrp, 0, program)
        return _witness_kind(0, program), program, address, 0
    if len(script) >= 2 and 0x51 <= script[0] <= 0x60 and script[1] != len(script) - 2:
        raise AddressEncodingError(
            "witness output declares a program length that does not match the script"
        )
    if len(script) >= 4 and 0x51 <= script[0] <= 0x60 and script[1] == len(script) - 2:
        witness_version = script[0] - 0x50
        program = script[2:]
        if witness_version == 1 and len(program) != 32:
            raise AddressEncodingError("Taproot outputs require a 32-byte program")
        address = encode_segwit_address(network.bech32_hrp, witness_version, program)
        return _witness_kind(witness_version, program), program, address, witness_version
    if script[0] == 0x21 and len(script) == 35 and script[34] == _OP_CHECKSIG:
        return "p2pk", script[1:34], None, None
    if script[0] == 0x41 and len(script) == 67 and script[66] == _OP_CHECKSIG:
        return "p2pk", script[1:66], None, None
    if script[0] == _OP_RETURN:
        return "op_return", b"", None, None
    return "nonstandard", b"", None, None


def script_to_address(script_hex: str, *, network: str | Network | None = None) -> str | None:
    """Return the address a locking script pays to, or ``None``.

    Args:
        script_hex: Script bytes in hexadecimal.
        network: Network used for the address encoding.

    Raises:
        AddressEncodingError: The script is malformed.
    """
    return decode_script_pubkey(script_hex, network=network).address


def _require_payload(payload: bytes, *, label: str = "payload") -> bytes:
    """Reject an empty payload; used by callers that need one."""
    if not payload:
        raise InputValidationError(f"{label} is empty")
    return payload


__all__ += ["_require_address", "_require_payload"]
