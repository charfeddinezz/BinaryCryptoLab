"""Analysis-only secp256k1 group arithmetic.

Why this module exists
----------------------
Every cryptographic operation in BinaryCryptoLab is delegated to
:mod:`cryptography` (OpenSSL).  That library deliberately exposes scalar
multiplication of the generator but **not** point addition, subtraction, or
multiplication of an arbitrary point.  Bounded searches such as
"the unknown part of this scalar has at most 32 bits" need exactly those
operations: subtract the known part from the public key, then walk the remaining
interval.

Scope and safety
----------------
* This is **analysis code**, never cryptographic production code.  It is not used
  to generate keys, sign, verify signatures, or protect secrets.
* It is not trusted silently.  ``tests/test_curve_arithmetic.py`` compares every
  operation against ``cryptography``'s OpenSSL implementation for random scalars
  and against published SEC 2 vectors, and the reconstruction layer re-derives
  every candidate scalar through ``cryptography`` before reporting it.
* Only public points (the generator and public keys) and scalars the caller
  already owns are ever passed in.  Nothing here stores or logs a secret.
* The searches are bounded by construction: the interval solver refuses ranges
  that would need more than :data:`MAX_TABLE_ENTRIES` table entries.

The implementation uses Jacobian coordinates for the hot loop (no modular
inversions inside additions) and converts to affine coordinates only when a
result is returned.
"""

from __future__ import annotations

import math
from typing import Final

from .ecc import CURVE_ORDER, FIELD_PRIME, GENERATOR
from .exceptions import InputValidationError

__all__ = [
    "MAX_TABLE_ENTRIES",
    "Point",
    "add",
    "compressed_hex",
    "decode_public_key",
    "discrete_log_interval",
    "double",
    "infinity",
    "is_infinity",
    "multiply",
    "negate",
    "sub",
]

#: Affine curve point, or ``None`` for the point at infinity.
Point = tuple[int, int] | None

#: Hard cap on baby-step table entries.  2**20 entries is about 100 MB of Python
#: integers, which is the largest table this tool will build.
MAX_TABLE_ENTRIES: Final = 1 << 20

_P: Final = FIELD_PRIME
_N: Final = CURVE_ORDER
_CURVE_B: Final = 7

#: The point at infinity, represented as ``None``.
infinity: Final[Point] = None


# ---------------------------------------------------------------------------
# Jacobian helpers: (X, Y, Z) with x = X / Z**2, y = Y / Z**3
# ---------------------------------------------------------------------------


def _to_jacobian(point: Point) -> tuple[int, int, int]:
    """Return the Jacobian triple for an affine point, or ``(0, 1, 0)``."""
    if point is None:
        return (0, 1, 0)
    x, y = point
    return (x % _P, y % _P, 1)


def _to_affine(triple: tuple[int, int, int]) -> Point:
    """Return the affine point for a Jacobian triple."""
    x, y, z = triple
    if z == 0:
        return None
    z_inverse = pow(z, -1, _P)
    z_inverse_squared = z_inverse * z_inverse % _P
    return (x * z_inverse_squared % _P, y * z_inverse_squared * z_inverse % _P)


def _double_jacobian(triple: tuple[int, int, int]) -> tuple[int, int, int]:
    """Double a Jacobian point on ``y**2 = x**3 + 7`` (``a = 0``)."""
    x, y, z = triple
    if z == 0 or y == 0:
        return (0, 1, 0)
    yy = y * y % _P
    s = 4 * x * yy % _P
    m = 3 * x * x % _P
    x3 = (m * m - 2 * s) % _P
    y3 = (m * (s - x3) - 8 * yy * yy) % _P
    z3 = 2 * y * z % _P
    return (x3, y3, z3)


def _add_jacobian(left: tuple[int, int, int], right: tuple[int, int, int]) -> tuple[int, int, int]:
    """Add two Jacobian points, handling doubling, infinity, and negatives."""
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1_squared = z1 * z1 % _P
    z2_squared = z2 * z2 % _P
    u1 = x1 * z2_squared % _P
    u2 = x2 * z1_squared % _P
    s1 = y1 * z2_squared * z2 % _P
    s2 = y2 * z1_squared * z1 % _P
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)  # P + (-P) = infinity
        return _double_jacobian(left)
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    h_squared = h * h % _P
    h_cubed = h_squared * h % _P
    u1_h_squared = u1 * h_squared % _P
    x3 = (r * r - h_cubed - 2 * u1_h_squared) % _P
    y3 = (r * (u1_h_squared - x3) - s1 * h_cubed) % _P
    z3 = h * z1 * z2 % _P
    return (x3, y3, z3)


def _multiply_jacobian(triple: tuple[int, int, int], scalar: int) -> tuple[int, int, int]:
    """Multiply a Jacobian point by a non-negative scalar (double and add)."""
    if scalar == 0 or triple[2] == 0:
        return (0, 1, 0)
    result: tuple[int, int, int] = (0, 1, 0)
    addend = triple
    while scalar:
        if scalar & 1:
            result = _add_jacobian(result, addend)
        addend = _double_jacobian(addend)
        scalar >>= 1
    return result


# ---------------------------------------------------------------------------
# Public affine API
# ---------------------------------------------------------------------------


def is_infinity(point: Point) -> bool:
    """Return whether *point* is the point at infinity."""
    return point is None


def _validate(point: Point) -> Point:
    """Check that an affine point is a field element pair on the curve."""
    if point is None:
        return None
    if not isinstance(point, tuple) or len(point) != 2:
        raise InputValidationError("a point must be a (x, y) pair or None")
    x, y = point
    if not isinstance(x, int) or not isinstance(y, int):
        raise InputValidationError("point coordinates must be integers")
    if not 0 <= x < _P or not 0 <= y < _P:
        raise InputValidationError("point coordinates must be field elements")
    if (y * y - x * x * x - _CURVE_B) % _P != 0:
        raise InputValidationError("point is not on the secp256k1 curve")
    return point


def add(left: Point, right: Point) -> Point:
    """Add two curve points.

    Raises:
        InputValidationError: A point is malformed or not on the curve.
    """
    return _to_affine(_add_jacobian(_to_jacobian(_validate(left)), _to_jacobian(_validate(right))))


def double(point: Point) -> Point:
    """Double a curve point.

    Raises:
        InputValidationError: The point is malformed or not on the curve.
    """
    return _to_affine(_double_jacobian(_to_jacobian(_validate(point))))


def negate(point: Point) -> Point:
    """Return ``-P`` (same x, reflected y).

    Raises:
        InputValidationError: The point is malformed or not on the curve.
    """
    validated = _validate(point)
    if validated is None:
        return None
    x, y = validated
    return (x, (-y) % _P)


def sub(left: Point, right: Point) -> Point:
    """Return ``left - right``.

    Raises:
        InputValidationError: A point is malformed or not on the curve.
    """
    return add(left, negate(right))


def multiply(point: Point, scalar: int) -> Point:
    """Return ``scalar * point``, reducing the scalar modulo the group order.

    Raises:
        InputValidationError: The point or scalar is invalid.
    """
    if not isinstance(scalar, int):
        raise InputValidationError("the scalar must be an integer")
    validated = _validate(point)
    return _to_affine(_multiply_jacobian(_to_jacobian(validated), scalar % _N))


def compressed_hex(point: Point) -> str:
    """Return the SEC 1 compressed hexadecimal encoding of a point.

    Raises:
        InputValidationError: The point is malformed, off the curve, or infinite.
    """
    validated = _validate(point)
    if validated is None:
        raise InputValidationError("the point at infinity has no encoding")
    x, y = validated
    return f"{0x02 if y % 2 == 0 else 0x03:02x}{x:064x}"


def decode_public_key(text: str) -> Point:
    """Decode a SEC 1 public key (compressed, uncompressed, or 64 raw bytes).

    Raises:
        InputValidationError: The text is not a valid secp256k1 public key.
    """
    stripped = "".join(text.split())
    if stripped[:2].lower() == "0x":
        stripped = stripped[2:]
    if not stripped or any(character not in "0123456789abcdefABCDEF" for character in stripped):
        raise InputValidationError("the public key must be hexadecimal")
    raw = bytes.fromhex(stripped)
    if len(raw) == 32:
        raise InputValidationError("an x-only key does not determine a point; supply y parity")
    if len(raw) == 64:
        x = int.from_bytes(raw[:32], "big")
        y = int.from_bytes(raw[32:], "big")
        return _validate((x, y))
    if len(raw) == 65:
        if raw[0] != 4:
            raise InputValidationError("an uncompressed public key starts with 0x04")
        return _validate((int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")))
    if len(raw) != 33:
        raise InputValidationError("a SEC 1 public key is 33 or 65 bytes")
    prefix = raw[0]
    if prefix not in (2, 3):
        raise InputValidationError("a compressed public key starts with 0x02 or 0x03")
    x = int.from_bytes(raw[1:], "big")
    if x >= _P:
        raise InputValidationError("the x coordinate must be smaller than the field prime")
    rhs = (pow(x, 3, _P) + _CURVE_B) % _P
    y = pow(rhs, (_P + 1) // 4, _P)
    if y * y % _P != rhs:
        raise InputValidationError("the x coordinate does not lie on secp256k1")
    if (y & 1) != (prefix & 1):
        y = _P - y
    return (x, y)


# ---------------------------------------------------------------------------
# Bounded discrete logarithm
# ---------------------------------------------------------------------------


def discrete_log_interval(
    target: Point,
    *,
    generator: Point = GENERATOR,
    low: int = 0,
    high: int | None = None,
    max_entries: int = MAX_TABLE_ENTRIES,
) -> int | None:
    r"""Solve ``x * generator == target`` for ``low <= x < high`` (baby-step/giant-step).

    The cost is about :math:`2\\sqrt{n}` group operations and about
    :math:`\\sqrt{n}` stored points, where ``n = high - low``.  Returns ``None``
    when no such ``x`` exists in the interval.

    Args:
        target: The point to explain as a multiple of *generator*.
        generator: Base point; the secp256k1 generator by default.
        low: Inclusive lower bound of the scalar interval.
        high: Exclusive upper bound.  ``None`` means ``low + n`` with ``n`` the
            group order, which is never feasible and is therefore rejected by the
            table cap.
        max_entries: Maximum number of baby steps to store.

    Raises:
        InputValidationError: The interval is empty or too large for the cap.
    """
    if high is None:
        raise InputValidationError("an explicit upper bound is required for a bounded search")
    if not 0 <= low < high:
        raise InputValidationError("the interval must satisfy 0 <= low < high")
    size = high - low
    steps = math.isqrt(size - 1) + 1
    if steps > max_entries:
        raise InputValidationError(
            f"the interval needs {steps} table entries, above the limit of {max_entries}"
        )
    base = _validate(generator)
    if base is None:
        raise InputValidationError("the generator must not be the point at infinity")
    goal = _validate(target)
    if goal is None:
        # The only scalar mapping to infinity is a multiple of the group order, so
        # inside a small interval the sole candidate is zero itself.
        return low if low == 0 else None

    # Shift the target so the search starts at zero: target - low * generator.
    shifted = sub(goal, multiply(base, low))
    if shifted is None:
        return low

    # The table stores index 0 as the point at infinity, so a walker that lands
    # exactly on a multiple of `steps` still matches.
    table: dict[Point, int] = {}
    current = _to_jacobian(None)
    step_point = _to_jacobian(base)
    for index in range(steps):
        table.setdefault(_to_affine(current), index)
        current = _add_jacobian(current, step_point)

    giant = _to_jacobian(multiply(base, steps))
    walker = _to_jacobian(shifted)
    limit = (size + steps - 1) // steps + 1
    for giant_index in range(limit):
        baby_index = table.get(_to_affine(walker))
        if baby_index is not None:
            candidate = low + giant_index * steps + baby_index
            if candidate < high and multiply(base, candidate) == goal:
                return candidate
        walker = _add_jacobian(walker, _negate_jacobian(giant))
    return None


def _negate_jacobian(triple: tuple[int, int, int]) -> tuple[int, int, int]:
    """Return the Jacobian negation of a point."""
    x, y, z = triple
    if z == 0:
        return (0, 1, 0)
    return (x, (-y) % _P, z)
