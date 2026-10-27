"""Hash functions used by BinaryCryptoLab.

Supported algorithms
--------------------
* SHA-256 and SHA-512 from :mod:`hashlib` (always available in CPython).
* Double SHA-256, the Bitcoin "hash256" construction.
* RIPEMD-160, available through :func:`hashlib.new`.  Whether it is present
  depends on the OpenSSL build that ships with Python.  When it is missing the
  module raises :class:`UnsupportedHashError`; it never substitutes another
  algorithm.
* HASH160, defined as ``RIPEMD160(SHA256(data))``.

Hashing is not encryption and not encoding.  A hash is a one-way fixed-size
digest: it cannot be decrypted, and this project makes no attempt to reverse
hashes.  See ``docs/cryptography.md`` for the full discussion.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .exceptions import InputValidationError, UnsupportedHashError
from .hex_utils import hex_to_bytes

__all__ = [
    "HashAlgorithm",
    "HashDigest",
    "double_sha256",
    "hash160",
    "hash_bytes",
    "hash_hex",
    "hash_of_hex_input",
    "ripemd160",
    "ripemd160_available",
    "sha256",
    "sha512",
    "supported_algorithms",
]

_RIPEMD160_PROBE: Final = b"BinaryCryptoLab-ripemd160-probe"


class HashAlgorithm(StrEnum):
    """Algorithms supported by :func:`hash_bytes`.

    The enum inherits from :class:`str` so that argparse accepts ``sha256``
    directly and JSON serialization stays readable.
    """

    SHA256 = "sha256"
    SHA512 = "sha512"
    DOUBLE_SHA256 = "double-sha256"
    RIPEMD160 = "ripemd160"
    HASH160 = "hash160"

    @classmethod
    def parse(cls, value: str | HashAlgorithm) -> HashAlgorithm:
        """Parse a user-supplied algorithm name.

        Accepts members, canonical names, and common aliases (``sha-256``,
        ``sha256d``, ``hash256``, ``ripemd-160``).  Matching is
        case-insensitive.

        Raises:
            UnsupportedHashError: The name is unknown.
        """
        if isinstance(value, HashAlgorithm):
            return value
        if not isinstance(value, str):
            raise UnsupportedHashError("algorithm name must be a string")
        normalized = value.strip().lower().replace("_", "-")
        aliases = {
            "sha256": cls.SHA256,
            "sha-256": cls.SHA256,
            "sha512": cls.SHA512,
            "sha-512": cls.SHA512,
            "double-sha256": cls.DOUBLE_SHA256,
            "double-sha-256": cls.DOUBLE_SHA256,
            "sha256d": cls.DOUBLE_SHA256,
            "hash256": cls.DOUBLE_SHA256,
            "ripemd160": cls.RIPEMD160,
            "ripemd-160": cls.RIPEMD160,
            "hash160": cls.HASH160,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            supported = ", ".join(algorithm.value for algorithm in cls)
            raise UnsupportedHashError(
                f"unknown hash algorithm {value!r}; supported algorithms: {supported}"
            ) from exc


@dataclass(frozen=True, slots=True)
class HashDigest:
    """A digest together with the algorithm that produced it.

    Attributes:
        algorithm: Canonical algorithm name.
        digest: Raw digest bytes.
        hexdigest: Lowercase hexadecimal digest.
        input_length: Length of the hashed input in bytes.
    """

    algorithm: HashAlgorithm
    digest: bytes
    hexdigest: str
    input_length: int

    @property
    def digest_length(self) -> int:
        """Digest size in bytes."""
        return len(self.digest)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "algorithm": self.algorithm.value,
            "digest_length": self.digest_length,
            "hexdigest": self.hexdigest,
            "input_length": self.input_length,
        }


def ripemd160_available() -> bool:
    """Return whether the active ``hashlib`` backend provides RIPEMD-160.

    The probe hashes a fixed test string; a backend that reports the name but
    fails to hash is treated as unavailable.
    """
    if "ripemd160" not in hashlib.algorithms_available:
        return False
    try:
        hashlib.new("ripemd160", _RIPEMD160_PROBE).digest()
    except (ValueError, TypeError):
        return False
    return True


def supported_algorithms() -> tuple[HashAlgorithm, ...]:
    """Return the algorithms that work on this interpreter."""
    algorithms = [HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.DOUBLE_SHA256]
    if ripemd160_available():
        algorithms.extend([HashAlgorithm.RIPEMD160, HashAlgorithm.HASH160])
    return tuple(algorithms)


def _require_bytes(data: object, *, label: str = "data") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise InputValidationError(f"{label} must be a bytes-like object")
    return bytes(data)


def sha256(data: bytes | bytearray | memoryview) -> bytes:
    """Return the 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(_require_bytes(data)).digest()


def sha512(data: bytes | bytearray | memoryview) -> bytes:
    """Return the 64-byte SHA-512 digest of *data*."""
    return hashlib.sha512(_require_bytes(data)).digest()


def double_sha256(data: bytes | bytearray | memoryview) -> bytes:
    """Return ``SHA256(SHA256(data))``, the 32-byte Bitcoin hash256 digest."""
    return hashlib.sha256(hashlib.sha256(_require_bytes(data)).digest()).digest()


def ripemd160(data: bytes | bytearray | memoryview) -> bytes:
    """Return the 20-byte RIPEMD-160 digest of *data*.

    Raises:
        UnsupportedHashError: The active backend does not provide RIPEMD-160.
    """
    payload = _require_bytes(data)
    if not ripemd160_available():
        raise UnsupportedHashError(
            "RIPEMD-160 is not available in the installed hashlib backend; "
            "install a Python build linked against OpenSSL with RIPEMD-160 support"
        )
    return hashlib.new("ripemd160", payload).digest()


def hash160(data: bytes | bytearray | memoryview) -> bytes:
    """Return ``RIPEMD160(SHA256(data))``, the Bitcoin HASH160 digest.

    Raises:
        UnsupportedHashError: RIPEMD-160 is unavailable in the backend.
    """
    return ripemd160(sha256(_require_bytes(data)))


def hash_bytes(data: bytes | bytearray | memoryview, algorithm: str | HashAlgorithm) -> HashDigest:
    """Hash bytes with the requested algorithm.

    Args:
        data: Input bytes.
        algorithm: Algorithm name, alias, or :class:`HashAlgorithm` member.

    Returns:
        A :class:`HashDigest` with raw and hexadecimal forms.

    Raises:
        UnsupportedHashError: The algorithm is unknown or unavailable.
        InputValidationError: *data* is not bytes-like.
    """
    payload = _require_bytes(data)
    selected = HashAlgorithm.parse(algorithm)
    dispatch = {
        HashAlgorithm.SHA256: sha256,
        HashAlgorithm.SHA512: sha512,
        HashAlgorithm.DOUBLE_SHA256: double_sha256,
        HashAlgorithm.RIPEMD160: ripemd160,
        HashAlgorithm.HASH160: hash160,
    }
    digest = dispatch[selected](payload)
    return HashDigest(
        algorithm=selected,
        digest=digest,
        hexdigest=digest.hex(),
        input_length=len(payload),
    )


def hash_hex(data: bytes | bytearray | memoryview, algorithm: str | HashAlgorithm) -> str:
    """Return the lowercase hexadecimal digest of *data*."""
    return hash_bytes(data, algorithm).hexdigest


def hash_of_hex_input(
    hex_text: str, algorithm: str | HashAlgorithm, *, allow_odd: bool = True
) -> HashDigest:
    """Decode hexadecimal text to bytes and hash the result.

    Args:
        hex_text: Hexadecimal input, with or without a ``0x`` prefix.
        algorithm: Algorithm name or member.
        allow_odd: Whether odd-length hexadecimal input is accepted (a leading
            zero nibble is prepended).

    Returns:
        A :class:`HashDigest` describing the hashed *bytes*, not the text.

    Raises:
        InvalidHexError: The input is not valid hexadecimal.
        UnsupportedHashError: The algorithm is unknown or unavailable.
    """
    return hash_bytes(hex_to_bytes(hex_text, allow_odd=allow_odd), algorithm)
