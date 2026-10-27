"""BinaryCryptoLab: local binary/hex analysis and Bitcoin address toolkit.

Quick start
-----------
>>> from binarycryptolab import analyze_binary
>>> result = analyze_binary("101101")
>>> result.integer_value, result.hexadecimal, result.bit_stats.hamming_weight
(45, '2d', 4)

>>> from binarycryptolab.bitcoin import address_from_public_key
>>> address_from_public_key(
...     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
... ).address
'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'

>>> from binarycryptolab import dissect_public_key
>>> dissect_public_key(
...     "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
... ).forecast.recoverable
False

The package never recovers private keys, never contacts the network, and never
stores secrets.  Read ``SECURITY.md`` before using it with anything other than
synthetic test values.
"""

from __future__ import annotations

from ._version import __version__
from .analysis import analyze, analyze_binary, analyze_hex
from .exceptions import BinaryCryptoLabError
from .forensics import PublicKeyDissection, dissect_many, dissect_public_key
from .hashing import double_sha256, hash160, hash_bytes, ripemd160, sha256, sha512
from .models.analysis_result import AnalysisResult, BinaryAnalysis, HexAnalysis

__all__ = [
    "AnalysisResult",
    "BinaryAnalysis",
    "BinaryCryptoLabError",
    "HexAnalysis",
    "PublicKeyDissection",
    "__version__",
    "analyze",
    "analyze_binary",
    "analyze_hex",
    "dissect_many",
    "dissect_public_key",
    "double_sha256",
    "hash160",
    "hash_bytes",
    "ripemd160",
    "sha256",
    "sha512",
]
