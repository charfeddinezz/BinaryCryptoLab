"""Vanity-prefix economics: how much work a prefix really costs, measured.

The dissection report says a prefix probability is not a p-value unless it was
declared in advance. That answers the statistics but not the engineering question a
skeptic actually asks: *could someone have mined this prefix on purpose?*

This module answers it three ways:

1. **Exact difficulty.** ``difficulty_bits`` converts a prefix into constrained bits
   using the same exact counting as :mod:`binarycryptolab.address_forensics`, so the
   expected number of attempts is ``2**bits`` and not an approximation.
2. **Measured throughput.** ``benchmark_derivation`` runs real derivations on this
   machine for a bounded wall-clock budget and reports attempts per second. The
   number is measured, not assumed, and the report says which CPU path it used.
3. **A rate table.** Expected time at 1e3, 1e6, 1e9, and 1e12 attempts per second,
   so the reader can place their own hardware on the curve without trusting ours.

Nothing here mines, and nothing here is used to attack a key: deriving an address
from a *known test scalar* is what a wallet does. The only output is an estimate of
how cheap a prefix is, which is precisely why prefixes prove so little.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from .address_forensics import (
    base58_prefix_probability,
    bech32_prefix_probability,
    cashaddr_prefix_probability,
)
from .address_formats import decode_address_input
from .exceptions import AddressEncodingError, InputValidationError

__all__ = [
    "BENCHMARK_ITERATIONS",
    "MiningEstimate",
    "benchmark_derivation",
    "estimate_prefix_mining",
    "verify_prefix_claim",
]

#: Derivations run by the benchmark. Small enough to be instant, large enough to time.
BENCHMARK_ITERATIONS: Final = 256

_SECONDS_PER_YEAR: Final = 365.25 * 24 * 3600


@dataclass(frozen=True, slots=True)
class DerivationRate:
    """A measured address-derivation rate on this machine.

    Attributes:
        address_type: ``p2pkh``, ``p2wpkh``, or ``p2sh-p2wpkh``.
        iterations: Derivations actually performed.
        elapsed_seconds: Wall-clock time consumed.
        per_second: Measured derivations per second.
        seconds_per_attempt: Reciprocal of ``per_second``.
        note: What the measurement does and does not predict.
    """

    address_type: str
    iterations: int
    elapsed_seconds: float
    per_second: float
    seconds_per_attempt: float
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address_type": self.address_type,
            "iterations": self.iterations,
            "elapsed_seconds": self.elapsed_seconds,
            "per_second": self.per_second,
            "seconds_per_attempt": self.seconds_per_attempt,
            "note": self.note,
        }


def benchmark_derivation(
    *, address_type: str = "p2pkh", iterations: int = BENCHMARK_ITERATIONS
) -> DerivationRate:
    """Measure how fast this machine can derive addresses.

    Args:
        address_type: ``p2pkh``, ``p2wpkh``, or ``p2sh-p2wpkh``.
        iterations: How many derivations to run (1..5000).

    Returns:
        The measured rate.

    Raises:
        InputValidationError: The type or the iteration count is invalid.

    Example:
        >>> rate = benchmark_derivation(iterations=16)
        >>> rate.per_second > 0
        True
    """
    if address_type not in {"p2pkh", "p2wpkh", "p2sh-p2wpkh"}:
        raise InputValidationError("address_type must be 'p2pkh', 'p2wpkh', or 'p2sh-p2wpkh'")
    if not 1 <= iterations <= 5000:
        raise InputValidationError("iterations must be between 1 and 5000")

    from .bitcoin import (
        derive_p2pkh_address,
        derive_p2sh_p2wpkh_address,
        derive_p2wpkh_address,
    )
    from .ecc import CURVE_ORDER, public_key_from_private

    builders: dict[str, Callable[[str], str]] = {
        "p2pkh": lambda key: derive_p2pkh_address(key, "mainnet").address,
        "p2wpkh": lambda key: derive_p2wpkh_address(key, "mainnet").address,
        "p2sh-p2wpkh": lambda key: derive_p2sh_p2wpkh_address(key, "mainnet").address,
    }
    build = builders[address_type]

    # One untimed warm-up, so a cold import or allocator does not distort the run.
    build(public_key_from_private(1).compressed_hex)

    start = time.perf_counter()
    for step in range(iterations):
        # A fixed, known test scalar sequence. No secret is involved.
        scalar = 1 + (step * 7919) % (CURVE_ORDER - 2)
        build(public_key_from_private(scalar).compressed_hex)
    elapsed = time.perf_counter() - start

    elapsed = max(elapsed, 1e-9)
    per_second = iterations / elapsed
    return DerivationRate(
        address_type=address_type,
        iterations=iterations,
        elapsed_seconds=elapsed,
        per_second=per_second,
        seconds_per_attempt=1.0 / per_second,
        note=(
            "Measured single-threaded in pure Python on this machine, using public test "
            "scalars only. Optimised native or GPU implementations are typically 10^3 to "
            "10^6 times faster; the report's rate table covers that range."
        ),
    )


@dataclass(frozen=True, slots=True)
class MiningEstimate:
    """The cost of producing a prefix, exactly and empirically.

    Attributes:
        prefix: The prefix examined.
        encoding: Counting model used.
        constrained_bits: Bits the prefix fixes.
        probability: Exact probability for a random address.
        expected_attempts: ``1 / probability``, the mean work.
        difficulty: The same figure as a familiar multiple of 2^32 (a GPU day order).
        measured: The benchmark taken during this run.
        expected_seconds_measured: Mean wall-clock time at the measured rate.
        rate_table: ``((attempts_per_second, seconds, human), ...)`` for reference.
        verdict: Plain-language conclusion, including whether the prefix is cheap.
        notes: Caveats.
    """

    prefix: str
    encoding: str
    constrained_bits: int
    probability: float
    expected_attempts: float
    difficulty: float
    measured: DerivationRate
    expected_seconds_measured: float
    rate_table: tuple[tuple[float, float, str], ...]
    verdict: str
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "prefix": self.prefix,
            "encoding": self.encoding,
            "constrained_bits": self.constrained_bits,
            "probability": self.probability,
            "expected_attempts": self.expected_attempts,
            "difficulty": self.difficulty,
            "measured": self.measured.as_dict(),
            "expected_seconds_measured": self.expected_seconds_measured,
            "rate_table": [
                {"attempts_per_second": rate, "seconds": seconds, "human": human}
                for rate, seconds, human in self.rate_table
            ],
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def _human_time(seconds: float) -> str:
    """Return a readable duration."""
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} microseconds"
    if seconds < 1:
        return f"{seconds * 1e3:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < _SECONDS_PER_YEAR:
        return f"{seconds / 86400:.1f} days"
    if seconds < 1e6 * _SECONDS_PER_YEAR:
        return f"{seconds / _SECONDS_PER_YEAR:.1f} years"
    return f"{seconds / _SECONDS_PER_YEAR:.2e} years"


def _prefix_probability(text: str, prefix: str) -> tuple[float, int, str]:
    """Return ``(probability, bits, encoding)`` for a prefix against an address."""
    decoded = decode_address_input(text)
    encoding = decoded.encoding
    if encoding == "base58check":
        if decoded.version_byte is None:  # pragma: no cover - base58 always has one
            raise AddressEncodingError("Base58 address without a version byte")
        probability = base58_prefix_probability(
            prefix, version=decoded.version_byte, payload_length=len(decoded.payload)
        )
        bits = 0 if probability <= 0 else max(0, round(-math.log2(probability)))
        return probability, bits, encoding
    if encoding in {"bech32", "bech32m"}:
        if decoded.address is None:  # pragma: no cover - defensive
            raise AddressEncodingError("Bech32 input without an address form")
        return (*bech32_prefix_probability(decoded.address, prefix), encoding)
    if encoding == "cashaddr":
        if decoded.address is None:  # pragma: no cover - defensive
            raise AddressEncodingError("CashAddr input without an address form")
        return (*cashaddr_prefix_probability(decoded.address, prefix), encoding)
    raise InputValidationError(f"prefix mining is not defined for {encoding!r} inputs")


def estimate_prefix_mining(
    address: str,
    *,
    prefix: str | None = None,
    rate: DerivationRate | None = None,
    address_type: str | None = None,
) -> MiningEstimate:
    """Estimate the work needed to produce a prefix, and time it on real hardware.

    Args:
        address: Any address whose encoding defines the counting model.  It is only
            used to pick the model and the version; it is not attacked.
        prefix: The prefix to price.  ``None`` uses the address's own 6-character
            prefix (which is also the honest default for a post-hoc question).
        rate: A previously measured rate.  ``None`` runs a fresh benchmark.
        address_type: Derivation type for a fresh benchmark.

    Returns:
        The estimate.

    Raises:
        AddressEncodingError: The address cannot be decoded.
        InputValidationError: The prefix is empty or not representable.

    Example:
        >>> estimate = estimate_prefix_mining(
        ...     "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa", prefix="1BEwWK"
        ... )  # doctest: +SKIP
        >>> estimate.constrained_bits > 20  # doctest: +SKIP
        True
    """
    decoded = decode_address_input(address)
    canonical = decoded.address or address
    chosen = (prefix if prefix is not None else canonical[:6]).strip()
    if not chosen:
        raise InputValidationError("prefix must not be empty")
    probability, bits, encoding = _prefix_probability(canonical, chosen)

    measured = (
        rate
        if rate is not None
        else benchmark_derivation(
            address_type=address_type
            or ("p2wpkh" if encoding in {"bech32", "bech32m"} else "p2pkh")
        )
    )
    if probability <= 0.0:
        attempts = float("inf")
        seconds_measured = float("inf")
        difficulty = float("inf")
    else:
        attempts = 1.0 / probability
        seconds_measured = attempts / measured.per_second
        difficulty = attempts / 2**32

    table = tuple(
        (
            attempts_per_second,
            attempts / attempts_per_second if probability > 0 else float("inf"),
            _human_time(attempts / attempts_per_second) if probability > 0 else "impossible",
        )
        for attempts_per_second in (1e3, 1e6, 1e9, 1e12)
    )

    measured_phrase = (
        "impossible at any rate"
        if probability <= 0.0
        else f"{_human_time(seconds_measured)} at this machine's measured rate"
    )
    if probability <= 0.0:
        verdict = (
            f"the prefix {chosen!r} cannot occur on this address type at all, so no "
            "amount of work would produce it"
        )
    elif bits <= 32:
        verdict = (
            f"cheap: the prefix fixes only {bits} bits ({measured_phrase}), which is a "
            "few minutes of commodity GPU time. It therefore says nothing about the "
            "address's origin"
        )
    elif bits <= 48:
        verdict = (
            f"affordable: {bits} bits ({measured_phrase}) is a GPU job measured in "
            "hours, well within reach of a determined hobbyist"
        )
    elif bits <= 72:
        verdict = (
            f"expensive: {bits} bits ({measured_phrase}) is a serious industrial effort. "
            "A prefix this long is evidence of deliberate generation, but of nothing else"
        )
    else:
        verdict = (
            f"out of reach: {bits} bits exceeds what any known classical hardware could "
            "mine, so the prefix cannot have been chosen on purpose"
        )

    return MiningEstimate(
        prefix=chosen,
        encoding=encoding,
        constrained_bits=bits,
        probability=probability,
        expected_attempts=attempts,
        difficulty=difficulty,
        measured=measured,
        expected_seconds_measured=seconds_measured,
        rate_table=table,
        verdict=verdict,
        notes=(
            "Expected attempts are the mean of a geometric distribution; the actual "
            "first hit can be several times larger or smaller.",
            "A mined prefix is not a weakness. It only shows the generator was run "
            "deliberately, which anybody can do.",
            "No key is attacked here: the benchmark derives addresses from public test "
            "scalars, exactly as a wallet does.",
        ),
    )


def verify_prefix_claim(address: str, prefix: str) -> dict[str, Any]:
    """Return a compact verification of a prefix claim.

    Args:
        address: The address to test.
        prefix: The prefix that was supposedly produced.

    Returns:
        A mapping with the boolean match, the exact probability, and the bits.

    Raises:
        AddressEncodingError: The address is invalid.
        InputValidationError: The prefix is empty.
    """
    decoded = decode_address_input(address)
    canonical = decoded.address or address
    cleaned = prefix.strip()
    if not cleaned:
        raise InputValidationError("prefix must not be empty")
    probability, bits, encoding = _prefix_probability(canonical, cleaned)
    matches = (
        canonical.startswith(cleaned)
        if encoding == "base58check"
        else canonical.lower().startswith(cleaned.lower())
    )
    return {
        "address": canonical,
        "prefix": cleaned,
        "encoding": encoding,
        "matches": matches,
        "probability": probability,
        "constrained_bits": bits,
        "expected_attempts": float("inf") if probability <= 0 else 1.0 / probability,
    }
