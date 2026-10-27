"""Exception hierarchy used across BinaryCryptoLab.

All errors that are expected during normal operation derive from
:class:`BinaryCryptoLabError`.  The command-line interface catches that base
class at its outer boundary and turns it into a concise error message plus a
non-zero exit code.  Unexpected exceptions are *not* caught, except when the
user explicitly asks for debug mode.

Error messages never include private key material.  Callers must not attach
secrets to exception strings, arguments, or chained causes.
"""

from __future__ import annotations

__all__ = [
    "AddressEncodingError",
    "Base58Error",
    "Bech32Error",
    "BinaryCryptoLabError",
    "ConfigurationError",
    "InputValidationError",
    "InvalidBase58Error",
    "InvalidBech32Error",
    "InvalidBinaryError",
    "InvalidDecimalError",
    "InvalidHexError",
    "InvalidPrivateKeyError",
    "InvalidPublicKeyError",
    "ReportGenerationError",
    "UnsupportedHashError",
]


class BinaryCryptoLabError(Exception):
    """Base class for all expected BinaryCryptoLab errors."""


class ConfigurationError(BinaryCryptoLabError):
    """Raised when configuration values are inconsistent or unsupported."""


class InputValidationError(BinaryCryptoLabError):
    """Base class for malformed or out-of-range user input."""


class InvalidBinaryError(InputValidationError):
    """Raised when a binary string cannot be parsed."""


class InvalidHexError(InputValidationError):
    """Raised when a hexadecimal string cannot be parsed."""


class InvalidDecimalError(InputValidationError):
    """Raised when a decimal integer cannot be parsed."""


class InvalidPrivateKeyError(BinaryCryptoLabError):
    """Raised when a private scalar is outside the valid secp256k1 range.

    Messages describe the allowed range and never echo the supplied scalar.
    """


class InvalidPublicKeyError(BinaryCryptoLabError):
    """Raised when a public key encoding is malformed or not on the curve."""


class UnsupportedHashError(BinaryCryptoLabError):
    """Raised when the installed cryptographic backend lacks an algorithm."""


class AddressEncodingError(BinaryCryptoLabError):
    """Base class for Bitcoin address encoding and decoding errors."""


class Base58Error(AddressEncodingError):
    """Raised when Base58 or Base58Check data is malformed."""


class InvalidBase58Error(Base58Error):
    """Raised when a Base58Check checksum does not match."""


class Bech32Error(AddressEncodingError):
    """Raised when Bech32 or Bech32m data is malformed."""


class InvalidBech32Error(Bech32Error):
    """Raised when a Bech32 checksum or encoding rule is violated."""


class ReportGenerationError(BinaryCryptoLabError):
    """Raised when a report cannot be rendered or written safely."""
