"""Logging configuration.

Design rules
------------
* Loggers are namespaced under ``binarycryptolab``.
* Log output goes to **stderr**, so that stdout stays machine-readable for
  JSON/CSV reports.
* No module in this package logs user input, private scalars, or derived
  secrets.  Log records are limited to lifecycle messages and error types.
* The default level is ``WARNING``; ``--verbose`` selects ``INFO`` and
  ``--debug`` selects ``DEBUG``.
"""

from __future__ import annotations

import logging
import sys
from typing import Final

__all__ = ["LOGGER_NAME", "configure_logging", "get_logger"]

LOGGER_NAME: Final = "binarycryptolab"
_FORMAT: Final = "%(levelname)s %(name)s: %(message)s"


def configure_logging(*, verbose: bool = False, debug: bool = False) -> logging.Logger:
    """Configure and return the package logger.

    The function is idempotent: repeated calls update the level and reuse the
    existing handler instead of stacking duplicates.

    Args:
        verbose: Enable ``INFO`` level messages.
        debug: Enable ``DEBUG`` level messages (takes precedence over *verbose*).

    Returns:
        The configured package logger.
    """
    logger = logging.getLogger(LOGGER_NAME)
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced logger.

    Args:
        name: Optional suffix; ``get_logger("cli")`` returns
            ``binarycryptolab.cli``.
    """
    if not name:
        return logging.getLogger(LOGGER_NAME)
    if isinstance(name, str) and name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
