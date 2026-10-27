"""secp256k1 elliptic curve operations.

Security posture
----------------
* All elliptic-curve arithmetic is delegated to :mod:`cryptography` (OpenSSL).
  This module contains **no** hand-written point multiplication, no custom
  field arithmetic, and no key generation.
* Private scalars are validated against the secp256k1 group order before use.
* Private scalars are never logged, never included in exceptions, never stored
  in reports, and never returned by any public function.  Only public keys and
  public metadata leave this module.
* A public key cannot be used to recover a private key.  This project makes no
  such claim and implements no such feature.

The curve constants below are the public SEC 2 domain parameters.  They are
used for range validation and for documentation, not for arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .exceptions import InputValidationError, InvalidPrivateKeyError, InvalidPublicKeyError
from .validation import normalize_hex

__all__ = [
    "COMPRESSED_PUBLIC_KEY_LENGTH",
    "CURVE_ORDER",
    "FIELD_PRIME",
    "GENERATOR",
    "UNCOMPRESSED_PUBLIC_KEY_LENGTH",
    "PublicKeyInfo",
    "Secp256k1Parameters",
    "curve_parameters",
    "derive_public_key",
    "parse_private_scalar",
    "parse_public_key_hex",
    "public_key_bytes",
    "public_key_from_private",
    "public_key_info",
    "public_key_info_from_hex",
    "validate_private_scalar",
]

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (SEC 2, section 2.4.1).  Public constants.
#   p  = 2**256 - 2**32 - 977
#   a  = 0
#   b  = 7
#   G  = (Gx, Gy), the standard base point
#   n  = order of G (prime)
#   h  = cofactor 1
# ---------------------------------------------------------------------------
FIELD_PRIME: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_ORDER: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GENERATOR_X: Final = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GENERATOR_Y: Final = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_COFACTOR: Final = 1
_CURVE_A: Final = 0
_CURVE_B: Final = 7

GENERATOR: Final[tuple[int, int]] = (_GENERATOR_X, _GENERATOR_Y)
COMPRESSED_PUBLIC_KEY_LENGTH: Final = 33
UNCOMPRESSED_PUBLIC_KEY_LENGTH: Final = 65
_RAW_UNCOMPRESSED_LENGTH: Final = 64
_MAX_PRIVATE_KEY_HEX_LENGTH: Final = 64


@dataclass(frozen=True, slots=True)
class Secp256k1Parameters:
    """Documentation-friendly view of the secp256k1 domain parameters.

    All values are public and may be freely printed.
    """

    name: str
    field_prime: int
    curve_a: int
    curve_b: int
    generator_x: int
    generator_y: int
    order: int
    cofactor: int

    def as_dict(self) -> dict[str, Any]:
        """Return the parameters as hexadecimal strings."""
        return {
            "name": self.name,
            "field_prime": hex(self.field_prime),
            "a": self.curve_a,
            "b": self.curve_b,
            "generator_x": hex(self.generator_x),
            "generator_y": hex(self.generator_y),
            "order": hex(self.order),
            "cofactor": self.cofactor,
        }


def curve_parameters() -> Secp256k1Parameters:
    """Return the standard secp256k1 domain parameters."""
    return Secp256k1Parameters(
        name="secp256k1",
        field_prime=FIELD_PRIME,
        curve_a=_CURVE_A,
        curve_b=_CURVE_B,
        generator_x=_GENERATOR_X,
        generator_y=_GENERATOR_Y,
        order=CURVE_ORDER,
        cofactor=_COFACTOR,
    )


def _curve() -> ec.SECP256K1:
    return ec.SECP256K1()


def validate_private_scalar(value: int) -> int:
    """Validate a private scalar for secp256k1.

    Args:
        value: Candidate scalar.

    Returns:
        The scalar, unchanged, when it satisfies ``1 <= value < n``.

    Raises:
        InvalidPrivateKeyError: The value is not an integer or is outside the
            valid range.  The message deliberately does not echo the scalar.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidPrivateKeyError("private scalar must be an integer")
    if not 1 <= value < CURVE_ORDER:
        raise InvalidPrivateKeyError(
            "private scalar is outside the valid secp256k1 range; "
            "it must satisfy 1 <= k < n, where n is the curve order"
        )
    return value


def parse_private_scalar(text: str | int, *, base: int = 16) -> int:
    """Parse and validate a private scalar from text or an integer.

    Args:
        text: Integer scalar, hexadecimal string (``0x`` prefix optional), or a
            decimal string when ``base=10``.
        base: ``16`` (default) or ``10``.  Hexadecimal is the conventional
            representation for secp256k1 scalars; the base is always explicit.

    Returns:
        The validated scalar.

    Raises:
        InvalidPrivateKeyError: The text is empty, malformed, not an integer, or
            outside the valid range.  The message never contains the input.
    """
    if isinstance(text, bool):
        raise InvalidPrivateKeyError("private scalar must be an integer or a string")
    if isinstance(text, int):
        return validate_private_scalar(text)
    if not isinstance(text, str):
        raise InvalidPrivateKeyError("private scalar must be an integer or a string")
    if base not in (10, 16):
        raise InvalidPrivateKeyError("private scalar base must be 10 or 16")

    stripped = text.strip().replace("_", "")
    if not stripped:
        raise InvalidPrivateKeyError("private scalar is empty")
    if stripped[:2].lower() == "0x":
        if base != 16:
            raise InvalidPrivateKeyError("a '0x' prefix requires base 16")
        stripped = stripped[2:]
    if not stripped:
        raise InvalidPrivateKeyError("private scalar is empty")
    if len(stripped) > _MAX_PRIVATE_KEY_HEX_LENGTH:
        raise InvalidPrivateKeyError("private scalar is too long for secp256k1")
    allowed = "0123456789abcdef" if base == 16 else "0123456789"
    if any(char.lower() not in allowed for char in stripped):
        kind = "hexadecimal" if base == 16 else "decimal"
        raise InvalidPrivateKeyError(f"private scalar is not a valid {kind} number")
    try:
        value = int(stripped, base)
    except ValueError as exc:  # pragma: no cover - guarded by the alphabet check
        raise InvalidPrivateKeyError("private scalar could not be parsed") from exc
    return validate_private_scalar(value)


def derive_public_key(scalar: int | str, *, base: int = 16) -> ec.EllipticCurvePublicKey:
    """Derive the secp256k1 public key for a validated private scalar.

    The scalar is validated first; derivation is performed by
    :mod:`cryptography`, never by custom arithmetic.

    Args:
        scalar: Private scalar as an integer or text (see
            :func:`parse_private_scalar`).
        base: Numeric base used when *scalar* is text.

    Returns:
        The public key object from :mod:`cryptography`.

    Raises:
        InvalidPrivateKeyError: The scalar is invalid or out of range.
    """
    value = parse_private_scalar(scalar, base=base)
    return ec.derive_private_key(value, _curve()).public_key()


def public_key_bytes(public_key: ec.EllipticCurvePublicKey, *, compressed: bool = True) -> bytes:
    """Serialize a public key in SEC 1 compressed or uncompressed form.

    Raises:
        InvalidPublicKeyError: The key is not a secp256k1 public key.
    """
    _require_secp256k1(public_key)
    if compressed:
        return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def parse_public_key_hex(text: str) -> ec.EllipticCurvePublicKey:
    """Parse and validate a SEC 1 encoded secp256k1 public key.

    Accepted encodings (hexadecimal, optional ``0x`` prefix, whitespace ignored):

    * compressed: ``02`` or ``03`` followed by 32 bytes (33 bytes total);
    * uncompressed: ``04`` followed by 64 bytes (65 bytes total);
    * raw uncompressed affine coordinates without the ``04`` prefix
      (64 bytes).  This common wallet export is accepted explicitly.

    Validation is performed by :mod:`cryptography`, which checks the encoding,
    the point's membership in the curve group, and rejects the point at
    infinity.

    Raises:
        InvalidPublicKeyError: The encoding, length, or point is invalid.
        InputValidationError: The value is not a string.
    """
    if not isinstance(text, str):
        raise InvalidPublicKeyError("public key must be hexadecimal text")
    try:
        digits = normalize_hex(text, allow_odd=False, max_length=2 * UNCOMPRESSED_PUBLIC_KEY_LENGTH)
    except InputValidationError as exc:
        raise InvalidPublicKeyError("public key is not valid hexadecimal text") from exc

    raw = bytes.fromhex(digits)
    if len(raw) == _RAW_UNCOMPRESSED_LENGTH:
        raw = b"\x04" + raw
    if len(raw) == COMPRESSED_PUBLIC_KEY_LENGTH:
        if raw[0] not in (0x02, 0x03):
            raise InvalidPublicKeyError("compressed public key must start with prefix 0x02 or 0x03")
    elif len(raw) == UNCOMPRESSED_PUBLIC_KEY_LENGTH:
        if raw[0] != 0x04:
            raise InvalidPublicKeyError("uncompressed public key must start with prefix 0x04")
    else:
        raise InvalidPublicKeyError(
            "public key must be 33 bytes (compressed) or 65 bytes (uncompressed)"
        )

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(_curve(), raw)
    except ValueError as exc:
        # The library deliberately gives little detail; do not echo key bytes.
        raise InvalidPublicKeyError(
            "public key is not a valid secp256k1 curve point or uses an invalid encoding"
        ) from exc


def _require_secp256k1(public_key: object) -> ec.EllipticCurvePublicKey:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise InvalidPublicKeyError("expected an EllipticCurvePublicKey instance")
    if not isinstance(public_key.curve, ec.SECP256K1):
        raise InvalidPublicKeyError("public key is not on the secp256k1 curve")
    return public_key


@dataclass(frozen=True, slots=True)
class PublicKeyInfo:
    """Public-only metadata for a secp256k1 public key.

    Attributes:
        curve: Curve name (always ``"secp256k1"`` for this class).
        x: Affine x coordinate.
        y: Affine y coordinate.
        compressed_hex: SEC 1 compressed encoding as hexadecimal.
        uncompressed_hex: SEC 1 uncompressed encoding as hexadecimal.
        input_encoding: ``"compressed"`` or ``"uncompressed"``.  Derived keys
            use the canonical compressed form; parsed keys record what the
            caller supplied.
    """

    curve: str
    x: int
    y: int
    compressed_hex: str
    uncompressed_hex: str
    input_encoding: str

    @property
    def compressed_bytes(self) -> bytes:
        """Compressed encoding as bytes."""
        return bytes.fromhex(self.compressed_hex)

    @property
    def uncompressed_bytes(self) -> bytes:
        """Uncompressed encoding as bytes."""
        return bytes.fromhex(self.uncompressed_hex)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation.  Contains no secrets."""
        return {
            "curve": self.curve,
            "x": f"{self.x:064x}",
            "y": f"{self.y:064x}",
            "compressed_hex": self.compressed_hex,
            "uncompressed_hex": self.uncompressed_hex,
            "compressed_length_bytes": COMPRESSED_PUBLIC_KEY_LENGTH,
            "uncompressed_length_bytes": UNCOMPRESSED_PUBLIC_KEY_LENGTH,
            "input_encoding": self.input_encoding,
            "note": "A public key is not an address and reveals no private key material.",
        }


def public_key_info(
    public_key: ec.EllipticCurvePublicKey, *, input_encoding: str = "compressed"
) -> PublicKeyInfo:
    """Build a :class:`PublicKeyInfo` from a secp256k1 public key object.

    Args:
        public_key: Public key from :mod:`cryptography`.
        input_encoding: ``"compressed"`` (default) or ``"uncompressed"``,
            recorded for reports and address derivation.

    Raises:
        InvalidPublicKeyError: The key is not a secp256k1 public key or the
            encoding label is unknown.
    """
    if input_encoding not in {"compressed", "uncompressed"}:
        raise InvalidPublicKeyError("input_encoding must be 'compressed' or 'uncompressed'")
    key = _require_secp256k1(public_key)
    numbers = key.public_numbers()
    return PublicKeyInfo(
        curve="secp256k1",
        x=numbers.x,
        y=numbers.y,
        compressed_hex=key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex(),
        uncompressed_hex=key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex(),
        input_encoding=input_encoding,
    )


def public_key_from_private(scalar: int | str, *, base: int = 16) -> PublicKeyInfo:
    """Derive a public key from a private scalar and return public-only metadata.

    The private scalar is used only to call ``cryptography`` and is not retained.

    Args:
        scalar: Private scalar as integer or text.
        base: Numeric base for text scalars (``16`` by default).

    Returns:
        Public key metadata.

    Raises:
        InvalidPrivateKeyError: The scalar is invalid or out of range.
    """
    public_key = derive_public_key(scalar, base=base)
    return public_key_info(public_key, input_encoding="compressed")


def public_key_info_from_hex(text: str) -> PublicKeyInfo:
    """Parse a hexadecimal public key and return public-only metadata.

    The input encoding (compressed or uncompressed) is detected from the
    decoded length and recorded in the result.

    Raises:
        InvalidPublicKeyError: The public key is invalid.
    """
    public_key = parse_public_key_hex(text)
    raw = bytes.fromhex(normalize_hex(text, allow_odd=False))
    if len(raw) == _RAW_UNCOMPRESSED_LENGTH:
        raw = b"\x04" + raw
    encoding = "compressed" if len(raw) == COMPRESSED_PUBLIC_KEY_LENGTH else "uncompressed"
    return public_key_info(public_key, input_encoding=encoding)


def is_valid_public_key_hex(text: str) -> bool:
    """Return whether *text* is a valid secp256k1 public key encoding.

    This predicate never raises for malformed strings.
    """
    try:
        parse_public_key_hex(text)
    except (InputValidationError, InvalidPublicKeyError):
        return False
    return True
