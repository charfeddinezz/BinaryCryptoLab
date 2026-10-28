"""Bitcoin address derivation and decoding.

Scope
-----
This module derives addresses **from public keys only**:

* P2PKH (legacy, Base58Check, version byte 0x00 / 0x6f),
* P2WPKH (native SegWit v0, Bech32, witness program 20 bytes),
* P2SH-P2WPKH (nested SegWit: the witness program is wrapped in a P2SH
  redeem script, version byte 0x05 / 0xc4).

It also decodes and validates addresses (checksum, version byte, HRP, witness
version, witness program length) so users can verify what they generated.

It does **not** query the blockchain, does not check balances, and cannot prove
ownership.  Address derivation is a pure local computation.

A public key is not an address, and an address is not a public key.  A private
key is never accepted by, stored by, or returned from this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from .base58 import base58check_decode, base58check_encode
from .bech32 import decode_segwit_address, encode_segwit_address
from .curve_arithmetic import add, decode_public_key, multiply
from .ecc import (
    CURVE_ORDER,
    FIELD_PRIME,
    GENERATOR,
    PublicKeyInfo,
    parse_public_key_hex,
    public_key_bytes,
    public_key_info_from_hex,
)
from .exceptions import (
    AddressEncodingError,
    InputValidationError,
    InvalidBech32Error,
    InvalidPublicKeyError,
)
from .hashing import hash160, sha256

__all__ = [
    "AddressInfo",
    "AddressType",
    "DecodedAddress",
    "Network",
    "address_from_public_key",
    "address_matrix",
    "decode_address",
    "derive_p2pkh_address",
    "derive_p2sh_p2wpkh_address",
    "derive_p2tr_address",
    "derive_p2wpkh_address",
    "hash160_public_key",
    "is_valid_address",
    "p2pkh_address_from_hash160",
    "p2sh_address_from_script_hash",
    "p2wpkh_address_from_hash160",
]

_HASH160_LENGTH: Final = 20
_P2PKH_VERSION_MAINNET: Final = 0x00
_P2SH_VERSION_MAINNET: Final = 0x05
_TESTNET_VERSION: Final = 0x6F
_P2SH_VERSION_TESTNET: Final = 0xC4
_WITNESS_V0_KEYHASH_LENGTH: Final = 20
_WITNESS_V0_SCRIPTHASH_LENGTH: Final = 32
_TAPROOT_TAG: Final = "TapTweak"


class Network(StrEnum):
    """Supported Bitcoin networks and their address parameters."""

    MAINNET = "mainnet"
    TESTNET = "testnet"
    REGTEST = "regtest"
    SIGNET = "signet"

    @classmethod
    def parse(cls, value: str | Network) -> Network:
        """Parse a network name (case-insensitive).

        Raises:
            AddressEncodingError: The name is unknown.
        """
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise AddressEncodingError("network must be a string")
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            supported = ", ".join(network.value for network in cls)
            raise AddressEncodingError(
                f"unknown network {value!r}; supported networks: {supported}"
            ) from exc

    @property
    def p2pkh_version(self) -> int:
        """Base58 version byte for P2PKH addresses."""
        return _P2PKH_VERSION_MAINNET if self is Network.MAINNET else _TESTNET_VERSION

    @property
    def p2sh_version(self) -> int:
        """Base58 version byte for P2SH addresses (decode-only here)."""
        return _P2SH_VERSION_MAINNET if self is Network.MAINNET else _P2SH_VERSION_TESTNET

    @property
    def bech32_hrp(self) -> str:
        """Human-readable part for SegWit addresses."""
        return "bc" if self is Network.MAINNET else ("bcrt" if self is Network.REGTEST else "tb")


class AddressType(StrEnum):
    """Address types supported for derivation."""

    P2PKH = "p2pkh"
    P2WPKH = "p2wpkh"
    P2SH_P2WPKH = "p2sh-p2wpkh"

    @classmethod
    def parse(cls, value: str | AddressType) -> AddressType:
        """Parse an address type name.

        Raises:
            AddressEncodingError: The name is unknown.
        """
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise AddressEncodingError("address type must be a string")
        normalized = value.strip().lower()
        aliases = {
            "p2pkh": cls.P2PKH,
            "legacy": cls.P2PKH,
            "base58": cls.P2PKH,
            "p2wpkh": cls.P2WPKH,
            "segwit": cls.P2WPKH,
            "bech32": cls.P2WPKH,
            "native-segwit": cls.P2WPKH,
            "p2sh-p2wpkh": cls.P2SH_P2WPKH,
            "p2sh_p2wpkh": cls.P2SH_P2WPKH,
            "p2shp2wpkh": cls.P2SH_P2WPKH,
            "nested-segwit": cls.P2SH_P2WPKH,
            "nested": cls.P2SH_P2WPKH,
            "wrapped-segwit": cls.P2SH_P2WPKH,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            supported = ", ".join(member.value for member in cls)
            raise AddressEncodingError(
                f"unknown address type {value!r}; supported types: {supported}"
            ) from exc


@dataclass(frozen=True, slots=True)
class AddressInfo:
    """A derived Bitcoin address and the public data used to build it.

    Attributes:
        address: Encoded address string.
        address_type: ``"p2pkh"`` or ``"p2wpkh"``.
        network: Network name.
        hash160_hex: HASH160 of the public key (the address payload).
        public_key_hex: Public key encoding used (compressed for P2WPKH).
        public_key_encoding: ``"compressed"`` or ``"uncompressed"``.
        witness_version: Witness version for SegWit addresses, else ``None``.
        witness_program_hex: Witness program for SegWit addresses, else ``None``.
        script_pubkey_hex: The locking script that pays to this address.
    """

    address: str
    address_type: str
    network: str
    hash160_hex: str
    public_key_hex: str
    public_key_encoding: str
    witness_version: int | None
    witness_program_hex: str | None
    script_pubkey_hex: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation.  Contains no secrets."""
        return {
            "address": self.address,
            "type": self.address_type,
            "network": self.network,
            "hash160": self.hash160_hex,
            "public_key_hex": self.public_key_hex,
            "public_key_encoding": self.public_key_encoding,
            "witness_version": self.witness_version,
            "witness_program_hex": self.witness_program_hex,
            "script_pubkey_hex": self.script_pubkey_hex,
            "notes": [
                "A public key and an address are not interchangeable.",
                "Deriving an address does not establish ownership or balance.",
            ],
        }


@dataclass(frozen=True, slots=True)
class DecodedAddress:
    """Result of decoding and validating an address.

    Attributes:
        address: The original address string.
        address_type: Detected type (``p2pkh``, ``p2sh``, ``p2wpkh``,
            ``p2wsh``, or ``witness_vN``).
        network: Best-effort network inference.
        network_ambiguous: Whether several networks share these parameters
            (testnet, signet, and regtest reuse the Base58 test version byte).
        payload_hex: Hash160 or witness program in hexadecimal.
        witness_version: Witness version when applicable.
    """

    address: str
    address_type: str
    network: str
    network_ambiguous: bool
    payload_hex: str
    witness_version: int | None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "type": self.address_type,
            "network": self.network,
            "network_ambiguous": self.network_ambiguous,
            "payload_hex": self.payload_hex,
            "witness_version": self.witness_version,
        }


def _tagged_hash(tag: str, message: bytes) -> bytes:
    """Return ``SHA256(SHA256(tag) || SHA256(tag) || message)`` (BIP-340 style)."""
    tag_digest = sha256(tag.encode())
    return sha256(tag_digest + tag_digest + message)


def taproot_output_key(public_key_hex: str, *, script_root: bytes | None = None) -> bytes:
    """Return the 32-byte x-only Taproot output key for an internal key.

    The BIP-341 key-path tweak is applied: the internal key is normalised to even
    ``y``, ``t = int(tagged_hash("TapTweak", x || script_root))``, and the output
    key is the x-coordinate of ``P + t*G``.

    Args:
        public_key_hex: SEC 1 internal public key.
        script_root: Optional 32-byte Merkle root of the script tree.

    Returns:
        The x-only output key.

    Raises:
        InvalidPublicKeyError: The key is invalid.
        AddressEncodingError: The script root is not 32 bytes.
    """
    point = decode_public_key(public_key_hex)
    if point is None:  # pragma: no cover - decode_public_key never returns infinity
        raise InvalidPublicKeyError("the point at infinity is not a public key")
    x_coordinate, y_coordinate = point
    if y_coordinate % 2:
        y_coordinate = FIELD_PRIME - y_coordinate
    even_point = (x_coordinate, y_coordinate)
    message = x_coordinate.to_bytes(32, "big")
    if script_root is not None:
        if len(script_root) != 32:
            raise AddressEncodingError("the Taproot script root must be 32 bytes")
        message += script_root
    tweak = int.from_bytes(_tagged_hash(_TAPROOT_TAG, message), "big")
    if tweak >= CURVE_ORDER:
        raise AddressEncodingError("the Taproot tweak is not a valid scalar")
    output = add(even_point, multiply(GENERATOR, tweak))
    if output is None:
        raise AddressEncodingError("the Tweaked key is the point at infinity")
    return output[0].to_bytes(32, "big")


def derive_p2tr_address(
    public_key_hex: str,
    network: str | Network = Network.MAINNET,
    *,
    script_root: bytes | None = None,
) -> AddressInfo:
    """Derive a Taproot (P2TR, Bech32m) address from a public key.

    Args:
        public_key_hex: SEC 1 public key, used as the internal key.
        network: Destination network.
        script_root: Optional Merkle root for script-path commitments.

    Returns:
        The derived address, its output key, and its locking script.

    Raises:
        InvalidPublicKeyError: The key is invalid.
        AddressEncodingError: The network or script root is invalid.
    """
    selected = Network.parse(network)
    output_key = taproot_output_key(public_key_hex, script_root=script_root)
    address = encode_segwit_address(selected.bech32_hrp, 1, output_key)
    return AddressInfo(
        address=address,
        address_type="p2tr",
        network=selected.value,
        hash160_hex="",
        public_key_hex=public_key_bytes(
            parse_public_key_hex(public_key_hex), compressed=True
        ).hex(),
        public_key_encoding="x-only (BIP-340 output key)",
        witness_version=1,
        witness_program_hex=output_key.hex(),
        script_pubkey_hex=f"5120{output_key.hex()}",
    )


def hash160_public_key(public_key_hex: str, *, compressed: bool | None = None) -> bytes:
    """Return ``RIPEMD160(SHA256(key_bytes))`` for a hexadecimal public key.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        compressed: ``None`` (default) hashes the encoding the caller supplied,
            matching how a P2PKH address is built.  ``True`` forces the
            compressed encoding (the P2WPKH convention) and ``False`` forces
            the uncompressed encoding.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
        UnsupportedHashError: RIPEMD-160 is unavailable.
    """
    public_key = parse_public_key_hex(public_key_hex)
    if compressed is None:
        payload = public_key_bytes(
            public_key,
            compressed=public_key_info_from_hex(public_key_hex).input_encoding == "compressed",
        )
    else:
        payload = public_key_bytes(public_key, compressed=compressed)
    return hash160(payload)


def p2pkh_address_from_hash160(hash160_digest: bytes, network: str | Network) -> str:
    """Encode a 20-byte HASH160 as a Base58Check P2PKH address.

    Raises:
        AddressEncodingError: The digest length or network is invalid.
    """
    if not isinstance(hash160_digest, (bytes, bytearray)):
        raise AddressEncodingError("HASH160 payload must be bytes")
    if len(hash160_digest) != _HASH160_LENGTH:
        raise AddressEncodingError("HASH160 payload must be exactly 20 bytes")
    selected = Network.parse(network)
    return base58check_encode(bytes([selected.p2pkh_version]) + bytes(hash160_digest))


def p2wpkh_address_from_hash160(hash160_digest: bytes, network: str | Network) -> str:
    """Encode a 20-byte HASH160 as a Bech32 P2WPKH address (witness v0).

    Raises:
        AddressEncodingError: The digest length or network is invalid.
        InvalidBech32Error: The address cannot be encoded.
    """
    if not isinstance(hash160_digest, (bytes, bytearray)):
        raise AddressEncodingError("HASH160 payload must be bytes")
    if len(hash160_digest) != _WITNESS_V0_KEYHASH_LENGTH:
        raise AddressEncodingError("P2WPKH witness program must be exactly 20 bytes")
    selected = Network.parse(network)
    return encode_segwit_address(selected.bech32_hrp, 0, bytes(hash160_digest))


def p2sh_address_from_script_hash(script_hash: bytes, network: str | Network) -> str:
    """Encode a 20-byte script hash as a Base58Check P2SH address.

    Args:
        script_hash: ``HASH160`` of the redeem script (20 bytes).
        network: Target network; selects version byte ``0x05`` or ``0xc4``.

    Raises:
        AddressEncodingError: The digest length or network is invalid.
    """
    if not isinstance(script_hash, (bytes, bytearray)):
        raise AddressEncodingError("P2SH script hash must be bytes")
    if len(script_hash) != _HASH160_LENGTH:
        raise AddressEncodingError("P2SH script hash must be exactly 20 bytes")
    selected = Network.parse(network)
    return base58check_encode(bytes([selected.p2sh_version]) + bytes(script_hash))


def _load_public_key(public_key_hex: str) -> tuple[PublicKeyInfo, bytes, bytes]:
    public_key = parse_public_key_hex(public_key_hex)
    info = public_key_info_from_hex(public_key_hex)
    compressed = public_key_bytes(public_key, compressed=True)
    uncompressed = public_key_bytes(public_key, compressed=False)
    return info, compressed, uncompressed


def derive_p2pkh_address(
    public_key_hex: str, network: str | Network = Network.MAINNET
) -> AddressInfo:
    """Derive a P2PKH address from a public key.

    Both compressed and uncompressed public keys are accepted, because both are
    valid P2PKH inputs and produce different addresses.  The encoding that was
    used is recorded in the result.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        network: Target network.

    Returns:
        Address metadata including the address string and locking script.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
        AddressEncodingError: The network is unknown.
        UnsupportedHashError: RIPEMD-160 is unavailable.
    """
    selected = Network.parse(network)
    info, compressed, uncompressed = _load_public_key(public_key_hex)
    encoding = info.input_encoding
    key_bytes = compressed if encoding == "compressed" else uncompressed
    digest = hash160(key_bytes)
    address = p2pkh_address_from_hash160(digest, selected)
    script = (
        b"\x76\xa9\x14" + digest + b"\x88\xac"
    )  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    return AddressInfo(
        address=address,
        address_type=AddressType.P2PKH.value,
        network=selected.value,
        hash160_hex=digest.hex(),
        public_key_hex=key_bytes.hex(),
        public_key_encoding=encoding,
        witness_version=None,
        witness_program_hex=None,
        script_pubkey_hex=script.hex(),
    )


def derive_p2wpkh_address(
    public_key_hex: str, network: str | Network = Network.MAINNET
) -> AddressInfo:
    """Derive a native SegWit (P2WPKH) address from a public key.

    P2WPKH requires a compressed public key.  An uncompressed key is rejected
    explicitly rather than converted, because that would silently produce an
    address the user did not ask for.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        network: Target network.

    Returns:
        Address metadata including the witness program and locking script.

    Raises:
        InvalidPublicKeyError: The public key is invalid or uncompressed.
        AddressEncodingError: The network is unknown.
        UnsupportedHashError: RIPEMD-160 is unavailable.
    """
    selected = Network.parse(network)
    info, compressed, _ = _load_public_key(public_key_hex)
    if info.input_encoding != "compressed":
        raise AddressEncodingError(
            "P2WPKH addresses require a compressed public key; "
            "supply the 33-byte compressed encoding"
        )
    digest = hash160(compressed)
    address = p2wpkh_address_from_hash160(digest, selected)
    script = b"\x00\x14" + digest  # OP_0 <20-byte key hash>
    return AddressInfo(
        address=address,
        address_type=AddressType.P2WPKH.value,
        network=selected.value,
        hash160_hex=digest.hex(),
        public_key_hex=compressed.hex(),
        public_key_encoding="compressed",
        witness_version=0,
        witness_program_hex=digest.hex(),
        script_pubkey_hex=script.hex(),
    )


def derive_p2sh_p2wpkh_address(
    public_key_hex: str, network: str | Network = Network.MAINNET
) -> AddressInfo:
    """Derive a nested SegWit (P2SH-P2WPKH) address from a public key.

    The witness program ``0x0014 || HASH160(compressed_key)`` is hashed again and
    wrapped in a P2SH address, which lets older wallets pay to a SegWit output.
    Like P2WPKH, this construction requires the compressed public key; an
    uncompressed key is rejected rather than converted.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        network: Target network.

    Returns:
        Address metadata including the redeem script and locking script.

    Raises:
        InvalidPublicKeyError: The public key is invalid or uncompressed.
        AddressEncodingError: The network is unknown.
        UnsupportedHashError: RIPEMD-160 is unavailable.
    """
    selected = Network.parse(network)
    info, compressed, _ = _load_public_key(public_key_hex)
    if info.input_encoding != "compressed":
        raise AddressEncodingError(
            "P2SH-P2WPKH addresses require a compressed public key; "
            "supply the 33-byte compressed encoding"
        )
    key_hash = hash160(compressed)
    redeem_script = b"\x00\x14" + key_hash  # OP_0 <20-byte key hash>
    script_hash = hash160(redeem_script)
    address = p2sh_address_from_script_hash(script_hash, selected)
    script = b"\xa9\x14" + script_hash + b"\x87"  # OP_HASH160 <20> OP_EQUAL
    return AddressInfo(
        address=address,
        address_type=AddressType.P2SH_P2WPKH.value,
        network=selected.value,
        hash160_hex=script_hash.hex(),
        public_key_hex=compressed.hex(),
        public_key_encoding="compressed",
        witness_version=0,
        witness_program_hex=key_hash.hex(),
        script_pubkey_hex=script.hex(),
    )


def address_from_public_key(
    public_key_hex: str,
    *,
    address_type: str | AddressType = AddressType.P2PKH,
    network: str | Network = Network.MAINNET,
) -> AddressInfo:
    """Derive an address of the requested type from a public key.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        address_type: ``"p2pkh"``, ``"p2wpkh"``, or ``"p2sh-p2wpkh"`` (aliases
            accepted).
        network: Target network.

    Returns:
        Address metadata.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
        AddressEncodingError: The type or network is unknown, or the key
            encoding is incompatible with the requested type.
    """
    selected_type = AddressType.parse(address_type)
    selected_network = Network.parse(network)
    if selected_type is AddressType.P2PKH:
        return derive_p2pkh_address(public_key_hex, selected_network)
    if selected_type is AddressType.P2WPKH:
        return derive_p2wpkh_address(public_key_hex, selected_network)
    return derive_p2sh_p2wpkh_address(public_key_hex, selected_network)


def _decode_base58_address(address: str, selected: Network | None) -> DecodedAddress:
    try:
        payload = base58check_decode(address)
    except AddressEncodingError as exc:
        raise AddressEncodingError(f"invalid Base58Check address: {exc}") from exc
    if len(payload) != 1 + _HASH160_LENGTH:
        raise AddressEncodingError(
            "Base58Check address payload must be 21 bytes (version byte + 20-byte hash)"
        )
    version, digest = payload[0], payload[1:]
    mainnet_p2pkh = version == _P2PKH_VERSION_MAINNET
    testnet_p2pkh = version == _TESTNET_VERSION
    mainnet_p2sh = version == _P2SH_VERSION_MAINNET
    testnet_p2sh = version == _P2SH_VERSION_TESTNET
    if not any((mainnet_p2pkh, testnet_p2pkh, mainnet_p2sh, testnet_p2sh)):
        raise AddressEncodingError(f"unknown Base58 address version byte 0x{version:02x}")

    if mainnet_p2pkh:
        inferred, ambiguous, kind = Network.MAINNET, False, "p2pkh"
    elif testnet_p2pkh:
        inferred, ambiguous, kind = Network.TESTNET, True, "p2pkh"
    elif mainnet_p2sh:
        inferred, ambiguous, kind = Network.MAINNET, False, "p2sh"
    else:
        inferred, ambiguous, kind = Network.TESTNET, True, "p2sh"

    if (
        selected is not None
        and selected.p2pkh_version != version
        and selected.p2sh_version != version
    ):
        raise AddressEncodingError(
            f"address version byte 0x{version:02x} does not match network {selected.value}"
        )
    return DecodedAddress(
        address=address,
        address_type=kind,
        network=(selected or inferred).value,
        network_ambiguous=ambiguous and selected is None,
        payload_hex=digest.hex(),
        witness_version=None,
    )


def _decode_segwit(address: str, selected: Network) -> DecodedAddress:
    try:
        version, program = decode_segwit_address(selected.bech32_hrp, address)
    except InvalidBech32Error as exc:
        raise AddressEncodingError(f"invalid Bech32 address: {exc}") from exc
    if version == 0 and len(program) == _WITNESS_V0_KEYHASH_LENGTH:
        kind = "p2wpkh"
    elif version == 0 and len(program) == _WITNESS_V0_SCRIPTHASH_LENGTH:
        kind = "p2wsh"
    else:
        kind = f"witness_v{version}"
    return DecodedAddress(
        address=address,
        address_type=kind,
        network=selected.value,
        network_ambiguous=False,
        payload_hex=program.hex(),
        witness_version=version,
    )


def decode_address(address: str, network: str | Network | None = None) -> DecodedAddress:
    """Decode and validate a Bitcoin address.

    Base58Check addresses are checked for checksum, payload length, and version
    byte.  SegWit addresses are checked for HRP, checksum variant, witness
    version, and witness program length.

    Args:
        address: Address string.
        network: Expected network.  When ``None``, the network is inferred for
            Base58 addresses and all candidate HRPs are tried for SegWit
            addresses.

    Returns:
        Decoding metadata.

    Raises:
        AddressEncodingError: The address is malformed, has a bad checksum, has
            an unknown version byte, or does not match the expected network.
    """
    if not isinstance(address, str) or not address:
        raise InputValidationError("address must be a non-empty string")
    text = address.strip()
    if not text:
        raise InputValidationError("address must be a non-empty string")

    selected = Network.parse(network) if network is not None else None
    lowered = text.lower()
    if lowered.startswith(("bc1", "tb1", "bcrt1")):
        candidates = (
            [selected]
            if selected is not None
            else [Network.MAINNET, Network.TESTNET, Network.REGTEST]
        )
        last_error: AddressEncodingError | None = None
        for candidate in candidates:
            if not lowered.startswith(candidate.bech32_hrp + "1"):
                continue
            try:
                return _decode_segwit(text, candidate)
            except AddressEncodingError as exc:
                last_error = exc
        # A Base58Check address can, in principle, begin with "bc1"/"tb1".
        # Fall back to Base58 only when that decoding actually succeeds, so a
        # malformed SegWit address still reports the Bech32 error.
        try:
            return _decode_base58_address(text, selected)
        except AddressEncodingError:
            if last_error is not None:
                raise last_error from None
            raise AddressEncodingError(
                "SegWit address human-readable part does not match the expected network"
            ) from None
    return _decode_base58_address(text, selected)


def is_valid_address(address: str, network: str | Network | None = None) -> bool:
    """Return whether *address* decodes successfully.

    This predicate never raises for malformed strings.
    """
    try:
        decode_address(address, network)
    except (AddressEncodingError, InputValidationError):
        return False
    return True


def address_matrix(
    public_key_hex: str,
    *,
    networks: tuple[str | Network, ...] | None = None,
) -> tuple[AddressInfo, ...]:
    """Derive every supported address for a public key, across all networks.

    Each row states the public-key encoding it was built from, so the
    compressed-derived rows are explicit rather than silent conversions:

    * ``p2pkh`` from the compressed key,
    * ``p2pkh`` from the uncompressed key (a different address),
    * ``p2wpkh`` from the compressed key,
    * ``p2sh-p2wpkh`` from the compressed key.

    Args:
        public_key_hex: SEC 1 public key in hexadecimal.
        networks: Networks to include.  ``None`` uses mainnet, testnet, signet,
            and regtest in that order.

    Returns:
        One :class:`AddressInfo` per ``(network, type, encoding)`` combination.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
        AddressEncodingError: A network is unknown.
        UnsupportedHashError: RIPEMD-160 is unavailable.
    """
    selected_networks: tuple[str | Network, ...] = (
        networks
        if networks is not None
        else (Network.MAINNET, Network.TESTNET, Network.SIGNET, Network.REGTEST)
    )
    public_key = parse_public_key_hex(public_key_hex)
    compressed_hex = public_key_bytes(public_key, compressed=True).hex()
    uncompressed_hex = public_key_bytes(public_key, compressed=False).hex()
    entries: list[AddressInfo] = []
    for network in selected_networks:
        selected = Network.parse(network)
        entries.append(derive_p2pkh_address(compressed_hex, selected))
        entries.append(derive_p2pkh_address(uncompressed_hex, selected))
        entries.append(derive_p2wpkh_address(compressed_hex, selected))
        entries.append(derive_p2sh_p2wpkh_address(compressed_hex, selected))
    return tuple(entries)
