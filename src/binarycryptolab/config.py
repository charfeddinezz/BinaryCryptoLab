"""Application-wide, non-sensitive configuration.

Nothing in this module may contain credentials, private keys, or user data.
Limits are expressed in characters (or digits) and are enforced *before* any
potentially expensive conversion so that oversized input cannot exhaust
memory.

The limits can be overridden per call (library use) or per command
(``--max-length``) but are never read from files that could store secrets.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._version import __version__

__all__ = [
    "APP_NAME",
    "APP_SLUG",
    "DEFAULT_INPUT_LIMITS",
    "DEFAULT_NETWORK",
    "DEFAULT_REPORT_INDENT",
    "EXIT_ERROR",
    "EXIT_SUCCESS",
    "EXIT_USAGE",
    "MAX_FILE_HASH_BYTES",
    "InputLimits",
    "__version__",
]

APP_NAME = "BinaryCryptoLab"
APP_SLUG = "binarycryptolab"
DEFAULT_NETWORK = "mainnet"
DEFAULT_REPORT_INDENT = 2

#: Exit code used when a command completes successfully.
EXIT_SUCCESS = 0
#: Exit code used for expected runtime errors (invalid input, I/O, ...).
EXIT_ERROR = 1
#: Exit code used for command-line usage errors (argparse default).
EXIT_USAGE = 2

#: Upper bound for hashing a file from the CLI, to avoid accidental huge reads.
MAX_FILE_HASH_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class InputLimits:
    """Maximum accepted input sizes.

    Attributes:
        max_binary_length: Maximum number of binary digits after removing
            whitespace and the optional ``0b`` prefix.
        max_hex_length: Maximum number of hexadecimal digits after removing
            whitespace and the optional ``0x`` prefix.
        max_decimal_digits: Maximum number of decimal digits in a decimal
            integer supplied by the user.
    """

    max_binary_length: int = 100_000
    max_hex_length: int = 100_000
    max_decimal_digits: int = 10_000

    def __post_init__(self) -> None:
        for name in ("max_binary_length", "max_hex_length", "max_decimal_digits"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
            if value <= 0:
                raise ValueError(f"{name} must be positive")


#: Default limits shared by the library, CLI, and GUI.
DEFAULT_INPUT_LIMITS = InputLimits()
