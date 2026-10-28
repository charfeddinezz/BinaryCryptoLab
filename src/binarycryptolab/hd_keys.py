"""BIP-32 extended public keys: derive addresses, match an address to a wallet.

The common real-world question is not "what key does this address hide" but "does
this address belong to this wallet". Answering it needs an extended public key, and
answering it requires **no private material at all**: BIP-32 public derivation
computes ``K_child = K_parent + IL * G`` from public data alone.

What this module does
---------------------
* parses ``xpub``/``ypub``/``zpub`` and their testnet counterparts, validating the
  version, depth, parent fingerprint, child number, chain code, and that the key is a
  real curve point;
* derives non-hardened children at any index, and any non-hardened path;
* turns a child key into the address type its version implies (legacy, nested SegWit,
  native SegWit);
* searches an index range for a given address and reports the first match.

What it deliberately cannot do
------------------------------
* Derive **hardened** children. That needs the private key, which this project never
  accepts, stores, or derives. The error message says so instead of pretending.
* Prove that the wallet holds the key: a match proves the address belongs to the key
  tree, not that its owner has the secret or the coins.

An extended public key is public data, but it is privacy-sensitive: it lets anyone
derive every address in that branch. The report says that on every run.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Final

from .base58 import b58decode, b58encode
from .bitcoin import (
    Network,
    derive_p2pkh_address,
    derive_p2sh_p2wpkh_address,
    derive_p2wpkh_address,
)
from .curve_arithmetic import add, decode_public_key, multiply
from .ecc import CURVE_ORDER, GENERATOR
from .exceptions import AddressEncodingError, InputValidationError
from .hashing import double_sha256, hash160

__all__ = [
    "EXTENDED_KEY_VERSIONS",
    "ExtendedKeyMatch",
    "ExtendedPublicKey",
    "derive_address",
    "match_address",
    "parse_extended_public_key",
]

_VERSION_BYTES: Final[dict[bytes, tuple[str, str, str]]] = {
    # version -> (label, network, script type)
    bytes.fromhex("0488b21e"): ("xpub", "mainnet", "p2pkh"),
    bytes.fromhex("049d7cb2"): ("ypub", "mainnet", "p2sh-p2wpkh"),
    bytes.fromhex("04b24746"): ("zpub", "mainnet", "p2wpkh"),
    bytes.fromhex("043587cf"): ("tpub", "testnet", "p2pkh"),
    bytes.fromhex("044a5262"): ("upub", "testnet", "p2sh-p2wpkh"),
    bytes.fromhex("045f1cf6"): ("vpub", "testnet", "p2wpkh"),
    bytes.fromhex("0295b43f"): ("Ypub", "mainnet", "p2wsh-multisig"),
    bytes.fromhex("02aa7ed3"): ("Zpub", "mainnet", "p2wsh-multisig"),
    bytes.fromhex("024289ef"): ("Upub", "testnet", "p2wsh-multisig"),
    bytes.fromhex("02575483"): ("Vpub", "testnet", "p2wsh-multisig"),
}

#: Human-readable table of the supported versions, exposed for the report.
EXTENDED_KEY_VERSIONS: Final[tuple[tuple[str, str, str, str], ...]] = tuple(
    (label, version.hex(), network, script_type)
    for version, (label, network, script_type) in _VERSION_BYTES.items()
)

#: 78-byte payload plus a 4-byte Base58Check checksum.
_SERIALIZED_LENGTH: Final = 82
_KEY_LENGTH: Final = 33
_CHAIN_LENGTH: Final = 32
_HARDENED: Final = 0x80000000


@dataclass(frozen=True, slots=True)
class ExtendedPublicKey:
    """A parsed BIP-32 extended public key.

    Attributes:
        text: The original text.
        label: ``xpub``, ``ypub``, ``zpub``, ``tpub``, ``upub``, ``vpub``, or a
            multisig variant.
        network: ``mainnet`` or ``testnet``.
        script_type: ``p2pkh``, ``p2sh-p2wpkh``, ``p2wpkh``, or
            ``p2wsh-multisig``.
        depth: Derivation depth of this key.
        parent_fingerprint: Four-byte fingerprint of the parent, in hexadecimal.
        child_number: The child number this key was derived at.
        chain_code: The 32-byte chain code, in hexadecimal.
        public_key_hex: The 33-byte compressed public key, in hexadecimal.
    """

    text: str
    label: str
    network: str
    script_type: str
    depth: int
    parent_fingerprint: str
    child_number: int
    chain_code: str
    public_key_hex: str

    @property
    def fingerprint(self) -> str:
        """Return this key's own fingerprint (first four HASH160 bytes)."""
        return hash160(bytes.fromhex(self.public_key_hex))[:4].hex()

    @property
    def multisig(self) -> bool:
        """Whether the version indicates a multisig account key."""
        return self.script_type == "p2wsh-multisig"

    @property
    def network_enum(self) -> Network:
        """Return the :class:`~binarycryptolab.bitcoin.Network` for this key."""
        return Network.TESTNET if self.network == "testnet" else Network.MAINNET

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "label": self.label,
            "network": self.network,
            "script_type": self.script_type,
            "depth": self.depth,
            "parent_fingerprint": self.parent_fingerprint,
            "child_number": self.child_number,
            "chain_code": self.chain_code,
            "public_key_hex": self.public_key_hex,
            "fingerprint": self.fingerprint,
            "multisig": self.multisig,
            "notes": [
                "An extended public key is not a private key and cannot spend.",
                "It is privacy-sensitive: anyone holding it can derive every address "
                "in this branch and correlate their activity.",
            ],
        }


def parse_extended_public_key(text: str) -> ExtendedPublicKey:
    """Parse and validate an extended public key.

    Args:
        text: The Base58Check-encoded extended key.

    Returns:
        The parsed key.

    Raises:
        InputValidationError: The text is empty or is not an extended key.
        AddressEncodingError: The checksum, version, structure, or key is invalid.
    """
    if not isinstance(text, str) or not text.strip():
        raise InputValidationError("extended public key must be a non-empty string")
    cleaned = "".join(text.split())
    if cleaned.lower().startswith(("xprv", "yprv", "zprv", "tprv", "uprv", "vprv")):
        raise InputValidationError(
            "input is an extended *private* key: it was refused, not analysed, and "
            "never repeated in this message"
        )
    try:
        raw = b58decode(cleaned)
    except Exception as exc:
        raise AddressEncodingError(f"invalid Base58Check data: {exc}") from exc
    if len(raw) != _SERIALIZED_LENGTH:
        raise AddressEncodingError(
            f"an extended key must be {_SERIALIZED_LENGTH} bytes, got {len(raw)}"
        )
    body, checksum = raw[:-4], raw[-4:]
    if len(body) != _SERIALIZED_LENGTH - 4:  # pragma: no cover - guarded above
        raise AddressEncodingError("malformed extended key length")
    if double_sha256(body)[:4] != checksum:
        raise AddressEncodingError("extended key checksum does not verify")
    version = body[:4]
    entry = _VERSION_BYTES.get(version)
    if entry is None:
        raise AddressEncodingError(f"unsupported extended key version {version.hex()}")
    label, network, script_type = entry
    depth = body[4]
    parent_fingerprint = body[5:9].hex()
    child_number = int.from_bytes(body[9:13], "big")
    chain_code = body[13:45].hex()
    key = body[45:78]
    if len(key) != _KEY_LENGTH or key[0] not in (2, 3):
        raise AddressEncodingError("extended key does not contain a compressed public key")
    if decode_public_key(key.hex()) is None:  # pragma: no cover - decode validates
        raise AddressEncodingError("extended key does not contain a valid curve point")
    if depth == 0 and (parent_fingerprint != "00000000" or child_number != 0):
        raise AddressEncodingError(
            "a depth-0 extended key must have a zero parent fingerprint and child number"
        )
    return ExtendedPublicKey(
        text=cleaned,
        label=label,
        network=network,
        script_type=script_type,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        chain_code=chain_code,
        public_key_hex=key.hex(),
    )


def _compress(point: tuple[int, int]) -> bytes:
    """Return the SEC 1 compressed encoding of *point*."""
    x_coordinate, y_coordinate = point
    prefix = b"\x03" if y_coordinate % 2 else b"\x02"
    return prefix + x_coordinate.to_bytes(32, "big")


def _derive_step(key: ExtendedPublicKey, index: int) -> ExtendedPublicKey:
    """Derive one non-hardened child of *key*.

    Raises:
        InputValidationError: The index is hardened or out of range.
    """
    if not isinstance(index, int) or index < 0:
        raise InputValidationError("child index must be a non-negative integer")
    if index >= _HARDENED:
        raise InputValidationError(
            "hardened derivation needs the private key, which this tool never "
            "accepts; only indices below 2^31 (non-hardened) can be derived from an "
            "extended public key"
        )
    parent = decode_public_key(key.public_key_hex)
    if parent is None:  # pragma: no cover - validated at parse time
        raise AddressEncodingError("extended key does not contain a valid curve point")
    payload = bytes.fromhex(key.public_key_hex) + index.to_bytes(4, "big")
    digest = hmac.new(bytes.fromhex(key.chain_code), payload, hashlib.sha512).digest()
    left, right = digest[:32], digest[32:]
    tweak = int.from_bytes(left, "big")
    if tweak >= CURVE_ORDER or tweak == 0:
        # BIP-32 declares this index invalid. It happens with probability ~2^-127.
        raise AddressEncodingError(
            "this index is invalid for the key (BIP-32 skip rule); try the next one"
        )
    child_point = add(parent, multiply(GENERATOR, tweak))
    if child_point is None:
        raise AddressEncodingError("derived child is the point at infinity; try the next index")
    version = bytes.fromhex(
        next(
            version.hex()
            for version, (label, network, script_type) in _VERSION_BYTES.items()
            if (label, network, script_type) == (key.label, key.network, key.script_type)
        )
    )
    body = (
        version
        + bytes([key.depth + 1])
        + hash160(bytes.fromhex(key.public_key_hex))[:4]
        + index.to_bytes(4, "big")
        + right
        + _compress(child_point)
    )
    serialized = b58encode(body + double_sha256(body)[:4])
    return ExtendedPublicKey(
        text=serialized,
        label=key.label,
        network=key.network,
        script_type=key.script_type,
        depth=key.depth + 1,
        parent_fingerprint=hash160(bytes.fromhex(key.public_key_hex))[:4].hex(),
        child_number=index,
        chain_code=right.hex(),
        public_key_hex=_compress(child_point).hex(),
    )


def derive_child(key: ExtendedPublicKey, index: int) -> ExtendedPublicKey:
    """Derive the child key at *index*.

    Args:
        key: The parent extended public key.
        index: A non-hardened child index.

    Returns:
        The child key.

    Raises:
        InputValidationError: The index is hardened, negative, or not an integer.
        AddressEncodingError: The index is invalid under BIP-32.
    """
    return _derive_step(key, index)


def parse_path(path: str) -> tuple[int, ...]:
    """Parse a derivation path such as ``m/0/5`` or ``0/5``.

    Args:
        path: The path.  ``m`` and ``M`` are accepted as prefixes.

    Returns:
        The child indices.

    Raises:
        InputValidationError: A component is not a number, or is hardened.
    """
    cleaned = path.strip()
    if not cleaned or cleaned in {"m", "M"}:
        return ()
    parts = cleaned.split("/")
    if parts[0] in {"m", "M"}:
        parts = parts[1:]
    indices: list[int] = []
    for part in parts:
        if not part:
            raise InputValidationError("derivation path has an empty component")
        if part.endswith(("'", "h", "H")):
            raise InputValidationError(
                "hardened path components cannot be derived from an extended public "
                "key; that requires the private key, which this tool never accepts"
            )
        if not part.isdigit():
            raise InputValidationError(f"derivation path component {part!r} is not a number")
        index = int(part)
        if index >= _HARDENED:
            raise InputValidationError(f"derivation index {index} is out of range")
        indices.append(index)
    return tuple(indices)


def derive_path(key: ExtendedPublicKey, path: str) -> ExtendedPublicKey:
    """Derive a non-hardened path from *key*.

    Args:
        key: The starting extended public key.
        path: For example ``m/0/17``.

    Returns:
        The derived key.

    Raises:
        InputValidationError: The path is invalid or hardened.
        AddressEncodingError: An index is invalid under BIP-32.
    """
    current = key
    for index in parse_path(path):
        current = _derive_step(current, index)
    return current


def derive_address(
    key: ExtendedPublicKey, index: int | None = None, *, path: str | None = None
) -> str:
    """Return the address for a child of *key*.

    Args:
        key: The extended public key.
        index: Child index to derive before encoding, when *path* is not given.
        path: A derivation path applied first.

    Returns:
        The address implied by the key's version: P2PKH for ``xpub``/``tpub``,
        P2SH-P2WPKH for ``ypub``/``upub``, P2WPKH for ``zpub``/``vpub``.

    Raises:
        InputValidationError: The version indicates a multisig account, or the input
            is invalid.
        AddressEncodingError: Derivation fails.

    Example:
        >>> key = parse_extended_public_key(XPUB)  # doctest: +SKIP
        >>> derive_address(key, 0)  # doctest: +SKIP
        '1...'
    """
    if key.multisig:
        raise InputValidationError(
            "this version marks a multisig account key; single-key derivation would be "
            "wrong, and a correct answer needs the other cosigners' extended keys"
        )
    child = derive_path(key, path) if path is not None else key
    if index is not None:
        child = _derive_step(child, index)
    network = child.network_enum
    if child.script_type == "p2pkh":
        return derive_p2pkh_address(child.public_key_hex, network).address
    if child.script_type == "p2wpkh":
        return derive_p2wpkh_address(child.public_key_hex, network).address
    return derive_p2sh_p2wpkh_address(child.public_key_hex, network).address


@dataclass(frozen=True, slots=True)
class ExtendedKeyMatch:
    """The result of searching a key tree for an address.

    Attributes:
        address: The address that was searched for.
        key_label: Version label of the key.
        network: Network of the key.
        script_type: Address type the key derives.
        range_start: First index examined.
        range_end: Last index examined, exclusive.
        matched_index: The index that produced the address, or ``None``.
        matched_path: A readable path for the match, when there is one.
        checked: Number of indices actually derived.
        sample: The first few derived addresses, for transparency.
        verdict: Plain-language conclusion.
        notes: Caveats that apply to every search.
    """

    address: str
    key_label: str
    network: str
    script_type: str
    range_start: int
    range_end: int
    matched_index: int | None
    matched_path: str | None
    checked: int
    sample: tuple[tuple[int, str], ...]
    verdict: str
    notes: tuple[str, ...]

    @property
    def matched(self) -> bool:
        """Whether the address was found in the searched range."""
        return self.matched_index is not None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "key_label": self.key_label,
            "network": self.network,
            "script_type": self.script_type,
            "range_start": self.range_start,
            "range_end": self.range_end,
            "matched": self.matched,
            "matched_index": self.matched_index,
            "matched_path": self.matched_path,
            "checked": self.checked,
            "sample": [{"index": index, "address": addr} for index, addr in self.sample],
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def match_address(
    key: ExtendedPublicKey,
    address: str,
    *,
    start: int = 0,
    count: int = 20,
    gap_limit: int | None = None,
) -> ExtendedKeyMatch:
    """Search ``[start, start + count)`` for *address*.

    Args:
        key: The extended public key.
        address: The address to find.
        start: First child index.
        count: How many indices to examine (hard-capped at 10 000).
        gap_limit: Stop after this many consecutive misses, as a wallet would.
            ``None`` examines the whole range.

    Returns:
        The search result, including the first few derived addresses for review.

    Raises:
        InputValidationError: The range is invalid, or the version is multisig.
        AddressEncodingError: An index is invalid under BIP-32.

    Example:
        >>> result = match_address(parse_extended_public_key(XPUB), address)  # doctest: +SKIP
        >>> result.matched  # doctest: +SKIP
        True
    """
    if start < 0:
        raise InputValidationError("start index must be zero or greater")
    if count < 1 or count > 10_000:
        raise InputValidationError("count must be between 1 and 10000")
    if gap_limit is not None and gap_limit < 1:
        raise InputValidationError("gap_limit must be at least 1")
    target = address.strip()
    sample: list[tuple[int, str]] = []
    matched: int | None = None
    checked = 0
    for position, index in enumerate(range(start, start + count)):
        derived = derive_address(key, index)
        checked += 1
        if len(sample) < 5:
            sample.append((index, derived))
        if derived == target:
            matched = index
            break
        if gap_limit is not None and position + 1 >= gap_limit:
            break
    if matched is not None:
        verdict = (
            f"match at index {matched}: the address belongs to this extended key's "
            "tree, so the wallet that owns the key derives it too"
        )
    else:
        verdict = (
            f"no match in {checked} indices ({start}..{start + checked - 1}) for "
            f"{key.script_type}. This does not prove the address belongs to another "
            "wallet: it may sit deeper in the tree, under another branch, or use a "
            "different script type."
        )
    return ExtendedKeyMatch(
        address=target,
        key_label=key.label,
        network=key.network,
        script_type=key.script_type,
        range_start=start,
        range_end=start + count,
        matched_index=matched,
        matched_path=None if matched is None else f"m/{matched}",
        checked=checked,
        sample=tuple(sample),
        verdict=verdict,
        notes=(
            "Public derivation only: no private key is used, accepted, or derived.",
            "A match proves the address belongs to the key tree, not that anyone still "
            "holds the secret or the coins.",
            "An extended public key is privacy-sensitive: it reveals every address in "
            "this branch to anyone who sees it.",
        ),
    )
