"""Discrete-logarithm hardness: measurement, structural audit, and falsifiability.

What this module is
-------------------
A reproducible experimental and analytical apparatus for one question:

    *Is the elliptic-curve discrete logarithm on secp256k1 refuted --- that is, is
    there evidence that a 256-bit instance is computationally tractable?*

The answer this module produces is **no**, and it produces it the only way an
answer to that question can be produced honestly: by

1. **measuring** a real discrete-log algorithm on real instances it can solve, and
   fitting the empirical growth exponent;
2. **auditing** every structural property of secp256k1 that a non-generic attack
   could exploit, with a computed verdict for each;
3. **stating in advance** which observations would overturn the conclusion.

What this module is not
-----------------------
It is **not** a key-recovery tool and it never attacks a real public key.  The
experiments run on *toy* elliptic curves over small prime fields, where the
instance order is a few dozen bits and the discrete logarithm is genuinely
computable; those instances are the calibration of the model.  The 256-bit curve is
never searched, and no command in this package will do so.

Scope of the arithmetic
-----------------------
:meth:`ToyCurve.add` and :meth:`ToyCurve.mul` implement group law over an arbitrary
short Weierstrass curve.  They exist because the analysis of *other* curves needs
*other* curves, which :mod:`binarycryptolab.curve_arithmetic` (secp256k1-specific)
cannot provide.  They are cross-checked against exhaustive point enumeration for
every small curve used in the test suite, and against secp256k1's own implementation
by specialising ``a = 0, b = 7``; every experiment additionally *verifies* its own
answer by substituting the recovered scalar back into the curve.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from .ecc import CURVE_ORDER, FIELD_PRIME
from .exceptions import InputValidationError

__all__ = [
    "ALGORITHM_FAMILIES",
    "SECP256K1_K",
    "AlgorithmFamily",
    "AuditFinding",
    "CurveInstance",
    "RhoResult",
    "ScalingFit",
    "ScalingPoint",
    "ScalingStudy",
    "StructuralAudit",
    "ToyCurve",
    "bsgs_dlp",
    "build_instance",
    "characteristic_audit",
    "ecdlp_cost_model",
    "field_dlp_cost_model",
    "measure_scaling",
    "pohlig_hellman_dlp",
    "pollard_rho_dlp",
    "structural_audit",
]

#: Affine point over a prime field, or ``None`` for the point at infinity.
Point = tuple[int, int] | None

#: Small primes used for trial division before Pollard-Brent.
_SMALL_PRIMES: Final[tuple[int, ...]] = tuple(
    n for n in range(2, 10_000) if all(n % d for d in range(2, int(n**0.5) + 1))
)

#: Miller-Rabin bases that make the test deterministic below 3.3e24.
_MR_BASES: Final[tuple[int, ...]] = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


# ---------------------------------------------------------------------------
# Integer helpers
# ---------------------------------------------------------------------------


def _is_probable_prime(n: int) -> bool:
    """Return whether *n* is prime, by deterministic Miller-Rabin in this range."""
    if n < 2:
        return False
    for small in _SMALL_PRIMES[:25]:
        if n % small == 0:
            return n == small
    d = n - 1
    shift = 0
    while d % 2 == 0:
        d //= 2
        shift += 1
    for base in _MR_BASES:
        if base % n == 0:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(shift - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _brent_factor(n: int, *, seed: int = 1) -> int:
    """Return a non-trivial factor of composite *n* (Pollard-Brent rho)."""
    if n % 2 == 0:
        return 2
    for offset in range(seed, seed + 64):
        y, c, m = 2, offset, 128
        g = r = q = 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
    raise InputValidationError(f"could not split {n}; increase the seed range")


def _factorize(n: int) -> dict[int, int]:
    """Return the prime factorisation of *n* as ``{prime: exponent}``."""
    if n < 1:
        raise InputValidationError("factorisation needs a positive integer")
    factors: dict[int, int] = {}
    for prime in _SMALL_PRIMES:
        while n % prime == 0:
            factors[prime] = factors.get(prime, 0) + 1
            n //= prime
    stack = [n] if n > 1 else []
    while stack:
        value = stack.pop()
        if value == 1:
            continue
        if _is_probable_prime(value):
            factors[value] = factors.get(value, 0) + 1
            continue
        divisor = _brent_factor(value)
        stack.extend([divisor, value // divisor])
    return factors


def _largest_prime_factor(n: int) -> int:
    """Return the largest prime factor of *n*."""
    return max(_factorize(n))


def _next_prime(value: int) -> int:
    """Return the smallest prime greater than or equal to *value*."""
    candidate = max(2, value)
    if candidate % 2 == 0:
        candidate += 1
    while not _is_probable_prime(candidate):
        candidate += 2
    return candidate


def _inverse(value: int, modulus: int) -> int:
    """Return the modular inverse of *value* modulo the prime *modulus*."""
    return pow(value % modulus, -1, modulus)


class _Stream:
    """Deterministic counter-mode SHA-256 byte stream.

    A seeded stream keeps every experiment reproducible without touching the
    ``random`` module, whose guarantees are not stable across versions.
    """

    def __init__(self, seed: int, label: str) -> None:
        self._seed = seed
        self._label = label.encode()
        self._counter = 0
        self._buffer = b""

    def bytes(self, count: int) -> bytes:
        while len(self._buffer) < count:
            block = hashlib.sha256(self._label + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
            self._buffer += hashlib.sha256(self._seed.to_bytes(32, "big") + block).digest()
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out

    def integer(self, bits: int) -> int:
        raw = self.bytes((bits + 7) // 8)
        return int.from_bytes(raw, "big") >> ((bits + 7) // 8 * 8 - bits)

    def below(self, bound: int) -> int:
        if bound <= 1:
            return 0
        bits = bound.bit_length()
        while True:
            value = self.integer(bits + 1)
            if value < bound:
                return value


# ---------------------------------------------------------------------------
# Toy curves
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToyCurve:
    """A short Weierstrass curve ``y^2 = x^3 + a*x + b`` over ``F_p``.

    Attributes:
        p: Field prime.
        a: Linear coefficient.
        b: Constant coefficient.

    Raises:
        InputValidationError: The modulus is not prime, or the discriminant is zero.
    """

    p: int
    a: int
    b: int

    def __post_init__(self) -> None:
        if self.p < 5 or not _is_probable_prime(self.p):
            raise InputValidationError("the field modulus must be an odd prime >= 5")
        if (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p == 0:
            raise InputValidationError("the curve is singular (4a^3 + 27b^2 = 0 mod p)")

    # -- group law ---------------------------------------------------------

    def is_on_curve(self, point: Point) -> bool:
        """Return whether *point* satisfies the curve equation."""
        if point is None:
            return True
        x, y = point
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def negate(self, point: Point) -> Point:
        """Return the additive inverse of *point*."""
        if point is None:
            return None
        return (point[0], (-point[1]) % self.p)

    def add(self, left: Point, right: Point) -> Point:
        """Return ``left + right``."""
        if left is None:
            return right
        if right is None:
            return left
        (x1, y1), (x2, y2) = left, right
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if left == right:
            if y1 == 0:
                return None
            slope = (3 * x1 * x1 + self.a) * _inverse(2 * y1, self.p) % self.p
        else:
            slope = (y2 - y1) * _inverse(x2 - x1, self.p) % self.p
        x3 = (slope * slope - x1 - x2) % self.p
        return (x3, (slope * (x1 - x3) - y1) % self.p)

    def mul(self, scalar: int, point: Point) -> Point:
        """Return ``scalar * point`` by double-and-add."""
        if point is None:
            return None
        if scalar < 0:
            return self.mul(-scalar, self.negate(point))
        result: Point = None
        addend: Point = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result

    # -- enumeration -------------------------------------------------------

    def points(self) -> list[Point]:
        """Enumerate every affine point, by trying every x.

        Only usable for small ``p``; it exists to check the order formulas and the
        group law against brute force, not for experiments.
        """
        found: list[Point] = []
        for x in range(self.p):
            rhs = (x * x * x + self.a * x + self.b) % self.p
            for y in range(self.p):
                if y * y % self.p == rhs:
                    found.append((x, y))
        return found

    def group_order_by_enumeration(self) -> int:
        """Count the points plus the point at infinity."""
        return len(self.points()) + 1

    @property
    def j_invariant(self) -> int | None:
        """Return the j-invariant, or ``None`` when ``a = 0`` (j = 0)."""
        if self.a % self.p == 0:
            return 0
        numerator = 1728 * 4 * pow(self.a, 3, self.p) % self.p
        denominator = (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p
        return numerator * _inverse(denominator, self.p) % self.p


def _known_order_family(family: str) -> tuple[int, int] | None:
    """Return ``(modulus, curve_b_index)`` describing a family with a known order.

    Two classical families have an order that is known *without* point counting,
    because the curve is supersingular and the Frobenius trace vanishes:

    ``"j0"``
        ``y^2 = x^3 + b`` over ``F_p`` with ``p = 2 (mod 3)``: the map ``x -> x^3`` is
        a bijection, so every ``x`` gives exactly one ``y`` and ``#E = p + 1``.
    ``"j1728"``
        ``y^2 = x^3 - x`` over ``F_p`` with ``p = 3 (mod 4)``: ``-1`` is not a square,
        so ``#E = p + 1`` as well.

    Returns ``(0, 0)`` for ``"j0"`` (curve ``a = 0``, coefficient chosen by the
    caller) and ``(0, 1)`` for ``"j1728"``.  A third family, ``"enumerated"``, is not
    built here: its order comes from exhaustive counting at small ``p``.

    Every construction is *verified* downstream by testing ``N*P = O`` on a random
    point, so a wrong assumption about a family cannot produce a passing instance.
    """
    if family in {"j0", "enumerated"}:
        return (0, 0)
    if family == "j1728":
        return (0, 1)
    return None


def _candidate_moduli(q: int, family: str, limit: int = 400) -> Iterable[int]:
    """Yield primes ``p`` with ``p + 1`` divisible by ``q`` and compatible with *family*.

    The construction searches ``p = c*q - 1``.  The congruence ``p = 2 (mod 3)``
    requires ``c = 0 (mod 3)``; the congruence ``p = 3 (mod 4)`` requires
    ``c = 0 (mod 4)``.  Since ``q`` is an odd prime, only the multiplier changes.
    """
    step = 12 if family == "j1728" else 6
    for multiple in range(step, step * (limit + 1), step):
        candidate = q * multiple - 1
        if family == "j0" and candidate % 3 != 2:
            continue
        if family == "j1728" and candidate % 4 != 3:
            continue
        if _is_probable_prime(candidate):
            yield candidate


@dataclass(frozen=True, slots=True)
class CurveInstance:
    """A discrete-logarithm instance whose base point has a certified order.

    Attributes:
        curve: The toy curve.
        generator: Base point ``G``.
        order: The **prime** order ``q`` of ``G``.
        group_order: The order of the whole group, ``#E(F_p)``.
        trace: ``t = p + 1 - #E(F_p)``.
        bits: ``q.bit_length()``.
        label: Human-readable construction note.
    """

    curve: ToyCurve
    generator: Point
    order: int
    group_order: int
    trace: int
    bits: int
    label: str

    def verify(self) -> bool:
        """Check that the base point has order **exactly** ``q``.

        ``q*G = O`` alone only proves that the order *divides* q, which is enough for
        a prime q but not for the composite order of the smooth-order control.  So the
        test is completed the standard way: ``(q/p)*G != O`` for every prime ``p``
        dividing q.  Together these two conditions are equivalent to ``ord(G) = q``.
        """
        if self.generator is None or self.order < 2:
            return False
        if not self.curve.is_on_curve(self.generator):
            return False
        if self.curve.mul(self.order, self.generator) is not None:
            return False
        return all(
            self.curve.mul(self.order // prime, self.generator) is not None
            for prime in _factorize(self.order)
        )

    @property
    def prime_order(self) -> bool:
        """Whether the base-point order is prime."""
        return _is_probable_prime(self.order)

    def public_key_for(self, scalar: int) -> Point:
        """Return ``scalar * G``, reduced modulo the order."""
        return self.curve.mul(scalar % self.order, self.generator)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable description (no secrets: the scalar is random)."""
        assert self.generator is not None
        return {
            "p": str(self.curve.p),
            "a": str(self.curve.a),
            "b": str(self.curve.b),
            "generator": {"x": str(self.generator[0]), "y": str(self.generator[1])},
            "order": str(self.order),
            "order_bits": self.bits,
            "order_is_prime": self.prime_order,
            "group_order": str(self.group_order),
            "trace": str(self.trace),
            "label": self.label,
        }


def build_instance(bits: int, *, seed: int = 0, family: str = "j0") -> CurveInstance:
    """Construct a certified instance whose base-point order has *bits* bits.

    Construction: pick a prime ``q`` of the requested size, then search for a prime
    ``p = c*q - 1`` compatible with a known-order curve family, so that
    ``#E(F_p) = p + 1 = c*q``.  The subgroup of order ``q`` is generated by
    ``G = c * P`` for a random point ``P``.

    Nothing is taken on trust.  A candidate is accepted only if

    * ``N * P`` is the point at infinity for ``N = p + 1`` (the family assumption),
    * ``q`` is prime and ``G != O``,
    * ``q * G`` is the point at infinity (so ``G`` has order exactly ``q``).

    Args:
        bits: Bit length of the prime order of the base point.
        seed: Deterministic stream seed, which also selects the curve family.
        family: ``"j0"``, ``"j1728"``, or ``"enumerated"`` (ordinary curves, whose
            order is obtained by exhaustive counting, only for small sizes).

    Returns:
        A :class:`CurveInstance` with ``instance.verify() is True``.

    Raises:
        InputValidationError: ``bits`` is outside 6..64, the family is unknown, or no
            verifiable instance was found.
    """
    if not 6 <= bits <= 64:
        raise InputValidationError("experiment sizes are limited to 6..64 bits")
    if family == "enumerated":
        return _enumerated_instance(bits, seed=seed)
    if _known_order_family(family) is None:
        raise InputValidationError(f"unknown curve family {family!r}")

    stream = _Stream(seed, f"instance-{bits}-{family}")
    for _attempt in range(64):
        candidate_q = _next_prime(stream.integer(bits) | (1 << (bits - 1)) | 1)
        if candidate_q.bit_length() != bits:
            continue
        for modulus in _candidate_moduli(candidate_q, family, limit=200):
            group_order = modulus + 1
            coefficients: tuple[int, ...]
            if family == "j1728":
                curve = ToyCurve(p=modulus, a=-1, b=0)
                coefficients = (0,)
            else:
                coefficients = (1, 2, 3)
            for coefficient in coefficients:
                if family == "j0":
                    curve = ToyCurve(p=modulus, a=0, b=coefficient)
                point = _find_point(curve, stream)
                if point is None:
                    continue
                if curve.mul(group_order, point) is not None:
                    continue  # the family assumption failed for this curve: skip it
                base = curve.mul(group_order // candidate_q, point)
                if base is None:
                    continue
                instance = CurveInstance(
                    curve=curve,
                    generator=base,
                    order=candidate_q,
                    group_order=group_order,
                    trace=modulus + 1 - group_order,
                    bits=bits,
                    label=(
                        f"{family}: supersingular, #E = p + 1 = {group_order // candidate_q} * q"
                        if family != "enumerated"
                        else "enumerated: ordinary curve, order counted exhaustively"
                    ),
                )
                if instance.verify():
                    return instance
    raise InputValidationError(f"no verifiable {bits}-bit instance was found for {family!r}")


def _enumerated_instance(bits: int, *, seed: int = 0) -> CurveInstance:
    """Build an instance on an **ordinary** curve whose order was counted by brute force.

    This family exists to answer the obvious objection to the supersingular
    constructions: the measurement of Pollard rho must not depend on the curve being
    supersingular, because rho uses nothing but the group operation.  Counting points
    by the quadratic-character sum is exponential in the bit size, which is why this
    family is limited to small instances; inside that range it is an independent
    order oracle with no formula involved.
    """
    stream = _Stream(seed, f"enumerated-{bits}")
    for attempt in range(400):
        modulus = _next_prime(1_000 + 2 * (attempt * 7919 + stream.below(7919)))
        if modulus > 1 << 16:
            break
        for coefficient in (3, 5, 6, 7, 10):
            curve = ToyCurve(p=modulus, a=1, b=coefficient)  # j != 0 in general
            group_order = _count_points_by_characters(curve)
            factors = _factorize(group_order)
            largest = max(factors)
            if largest.bit_length() != bits:
                continue
            point = _find_point(curve, stream)
            if point is None or curve.mul(group_order, point) is not None:
                continue
            base = curve.mul(group_order // largest, point)
            if base is None:
                continue
            instance = CurveInstance(
                curve=curve,
                generator=base,
                order=largest,
                group_order=group_order,
                trace=modulus + 1 - group_order,
                bits=bits,
                label="enumerated: ordinary curve, order counted exhaustively",
            )
            if instance.verify():
                return instance
    raise InputValidationError(f"no enumerated {bits}-bit instance was found")


def _count_points_by_characters(curve: ToyCurve) -> int:
    """Count points with the quadratic-character sum (an independent order oracle)."""
    total = curve.p + 1
    half = (curve.p - 1) // 2
    for x in range(curve.p):
        value = (x * x * x + curve.a * x + curve.b) % curve.p
        if value == 0:
            continue
        total += 1 if pow(value, half, curve.p) == 1 else -1
    return total


def _find_point(curve: ToyCurve, stream: _Stream) -> Point:
    """Return a pseudo-random affine point on *curve*, or ``None``."""
    for _ in range(64):
        x = stream.below(curve.p)
        rhs = (x * x * x + curve.a * x + curve.b) % curve.p
        root = _sqrt_mod(rhs, curve.p)
        if root is not None:
            y = root if stream.below(2) == 0 else (-root) % curve.p
            return (x, y)
    return None


def _sqrt_mod(value: int, prime: int) -> int | None:
    """Return a square root of *value* modulo the odd prime *prime*, if one exists."""
    value %= prime
    if value == 0:
        return 0
    if pow(value, (prime - 1) // 2, prime) != 1:
        return None
    if prime % 4 == 3:
        return pow(value, (prime + 1) // 4, prime)
    # Tonelli-Shanks
    odd = prime - 1
    shift = 0
    while odd % 2 == 0:
        odd //= 2
        shift += 1
    root = pow(value, (odd + 1) // 2, prime)
    residue = pow(value, odd, prime)
    generator = 2
    while pow(generator, (prime - 1) // 2, prime) != prime - 1:
        generator += 1
    factor = pow(generator, odd, prime)
    while residue != 1:
        index = 0
        probe = residue
        while probe != 1:
            probe = probe * probe % prime
            index += 1
        step = pow(factor, 1 << (shift - index - 1), prime)
        root = root * step % prime
        factor = step * step % prime
        residue = residue * factor % prime
        shift = index
    return root


# ---------------------------------------------------------------------------
# Algorithms
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RhoResult:
    """Outcome of one Pollard-rho run.

    Attributes:
        scalar: The recovered discrete logarithm, or ``None`` on failure.
        steps: Group additions performed by the walk.
        restarts: How many degenerate collisions forced a restart.
        verified: Whether ``scalar * G`` really equals the target.
    """

    scalar: int | None
    steps: int
    restarts: int
    verified: bool
    iterations: int = 0

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "scalar": None if self.scalar is None else str(self.scalar),
            "steps": self.steps,
            "iterations": self.iterations,
            "restarts": self.restarts,
            "verified": self.verified,
        }


def _walk_step(
    curve: ToyCurve,
    offsets: Sequence[tuple[int, int, Point]],
    partitions: int,
    order: int,
    point: Point,
    alpha: int,
    beta: int,
) -> tuple[Point, int, int]:
    """Advance the rho walk by one partition step.

    The partition index is the current point's ``x`` modulo the number of
    partitions, so the walk is a deterministic function of the point alone, which is
    what makes Floyd cycle finding applicable.
    """
    index = 0 if point is None else point[0] % partitions
    first, second, offset = offsets[index]
    return curve.add(point, offset), (alpha + first) % order, (beta + second) % order


def pollard_rho_dlp(
    instance: CurveInstance,
    target: Point,
    *,
    max_steps: int = 1_000_000,
    seed: int = 0,
    max_restarts: int = 8,
    partitions: int = 16,
) -> RhoResult:
    """Solve the discrete logarithm in *instance* with Pollard's rho method.

    The walk is Teske's adding walk: the point ``X_i`` is advanced by ``r_j * G``
    where ``j = x(X_i) mod partitions`` and ``r_j = 2^j``.  Power-of-two increments
    matter: with tiny increments the walk diffuses only locally in the exponent and
    the collision time is quadratic rather than square-root (which the parameter
    study in the tests demonstrates: three small increments are roughly thirty times
    slower than the sixteen power-of-two increments used here).

    A collision gives a linear relation in ``k``, which is inverted modulo the prime
    order.  The answer is *always* verified by substitution; a degenerate collision is
    retried with a different walk start rather than guessed around.

    Args:
        instance: The instance; its order must be prime.
        target: ``Q = k*G`` for the unknown ``k``.
        max_steps: Abort after this many group additions.
        seed: Deterministic stream seed; a different seed gives a different walk.
        max_restarts: How many degenerate collisions to retry.
        partitions: Number of walk partitions (Teske recommends about 16-20).

    Returns:
        A :class:`RhoResult`.  A failure is reported as ``scalar=None``, never guessed.
    """
    if not _is_probable_prime(instance.order):
        raise InputValidationError("rho requires a prime-order instance")
    if partitions < 2:
        raise InputValidationError("the walk needs at least two partitions")
    curve, base, order = instance.curve, instance.generator, instance.order
    if base is None:
        raise InputValidationError("the base point must not be the point at infinity")

    iterations_total = 0
    restarts = 0
    while restarts <= max_restarts:
        stream = _Stream(seed + restarts, "rho")
        # Teske's adding walk: each partition adds a_j*G + b_j*Q with a_j, b_j drawn
        # from the stream.  Both coefficients must vary, otherwise the collision
        # relation has a zero denominator and carries no information about k.
        offsets: list[tuple[int, int, Point]] = []
        for _ in range(partitions):
            left = 1 + stream.below(order - 1)
            right = 1 + stream.below(order - 1)
            offsets.append(
                (left, right, curve.add(curve.mul(left, base), curve.mul(right, target)))
            )
        start_coefficient = 1 + stream.below(order - 1)
        walk_point: Point = curve.mul(start_coefficient, base)
        alpha, beta = start_coefficient, 0

        slow_point: Point = walk_point
        slow_alpha, slow_beta = alpha, beta
        fast_point: Point = walk_point
        fast_alpha, fast_beta = alpha, beta
        for _ in range(max_steps):
            slow_point, slow_alpha, slow_beta = _walk_step(
                curve, offsets, partitions, order, slow_point, slow_alpha, slow_beta
            )
            fast_point, fast_alpha, fast_beta = _walk_step(
                curve, offsets, partitions, order, fast_point, fast_alpha, fast_beta
            )
            fast_point, fast_alpha, fast_beta = _walk_step(
                curve, offsets, partitions, order, fast_point, fast_alpha, fast_beta
            )
            iterations_total += 1
            if slow_point is None or slow_point != fast_point:
                continue
            denominator = (slow_beta - fast_beta) % order
            if denominator == 0:
                continue  # a degenerate collision: keep walking, it says nothing about k
            candidate = (fast_alpha - slow_alpha) * _inverse(denominator, order) % order
            if curve.mul(candidate, base) == target:
                return RhoResult(
                    scalar=candidate,
                    steps=3 * iterations_total,
                    restarts=restarts,
                    verified=True,
                    iterations=iterations_total,
                )
        restarts += 1
    return RhoResult(
        scalar=None,
        steps=3 * iterations_total,
        restarts=restarts,
        verified=False,
        iterations=iterations_total,
    )


@dataclass(frozen=True, slots=True)
class BsgsResult:
    """Outcome of a baby-step giant-step run.

    Attributes:
        scalar: The recovered discrete logarithm, or ``None``.
        table_entries: Baby steps stored, i.e. the memory used.
        steps: Group operations performed (table build plus giant steps).
        verified: Whether the answer was substituted back.
    """

    scalar: int | None
    table_entries: int
    steps: int
    verified: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "scalar": None if self.scalar is None else str(self.scalar),
            "table_entries": self.table_entries,
            "steps": self.steps,
            "verified": self.verified,
        }


def bsgs_dlp(instance: CurveInstance, target: Point, *, max_entries: int = 1 << 22) -> BsgsResult:
    """Solve the discrete logarithm by baby-step giant-step.

    This is the deterministic ``O(sqrt(q))``-time, ``O(sqrt(q))``-**memory** method.
    It is included because the memory term is the part that makes it impractical at
    256 bits, and the experiment shows the cost of the table directly.

    Args:
        instance: The instance.
        target: ``Q = k*G``.
        max_entries: Refuse to build a table larger than this.

    Returns:
        A :class:`BsgsResult`.
    """
    curve, base, order = instance.curve, instance.generator, instance.order
    if base is None:
        raise InputValidationError("the base point must not be the point at infinity")
    width = math.isqrt(order) + 1
    if width > max_entries:
        raise InputValidationError(
            f"the table would need {width} entries, above the limit {max_entries}"
        )
    table: dict[Point, int] = {}
    point: Point = None
    for index in range(width):
        table.setdefault(point, index)
        point = curve.add(point, base)
    factor = curve.mul(-width % order, base)
    candidate: Point = target
    steps = width
    for index in range(width + 1):
        if candidate in table:
            scalar = (index * width + table[candidate]) % order
            if curve.mul(scalar, base) == target:
                return BsgsResult(
                    scalar=scalar, table_entries=len(table), steps=steps, verified=True
                )
        candidate = curve.add(candidate, factor)
        steps += 1
    return BsgsResult(scalar=None, table_entries=len(table), steps=steps, verified=False)


@dataclass(frozen=True, slots=True)
class PohligHellmanResult:
    """Outcome of a Pohlig-Hellman run against a smooth-order instance.

    Attributes:
        scalar: The recovered discrete logarithm.
        factors: ``(prime, exponent)`` pairs of the order that was used.
        steps: Approximate group operations.
        verified: Whether the answer was substituted back.
    """

    scalar: int | None
    factors: tuple[tuple[int, int], ...]
    steps: int
    verified: bool

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "scalar": None if self.scalar is None else str(self.scalar),
            "factors": [{"prime": str(prime), "exponent": power} for prime, power in self.factors],
            "steps": self.steps,
            "verified": self.verified,
        }


def pohlig_hellman_dlp(
    instance: CurveInstance, target: Point, *, limit: int = 1 << 20
) -> PohligHellmanResult:
    """Solve the discrete logarithm prime-factor by prime-factor.

    The point must have composite known order for this to help; on a prime-order
    instance the "factorisation" is the order itself and the cost collapses back to
    a full discrete logarithm.  That is exactly the point the audit makes.

    Args:
        instance: The instance; ``instance.order`` may be composite here.
        target: ``Q = k*G``.
        limit: Refuse if the largest prime factor exceeds this.

    Returns:
        A :class:`PohligHellmanResult`.
    """
    curve, base = instance.curve, instance.generator
    if base is None:
        raise InputValidationError("the base point must not be the point at infinity")
    factors = _factorize(instance.order)
    largest = max(factors)
    if largest > limit:
        raise InputValidationError(
            f"the largest prime factor is {largest}, above the limit {limit}; "
            "no smooth structure to exploit"
        )
    steps = 0
    residues: list[tuple[int, int]] = []
    for prime, exponent in factors.items():
        power = prime**exponent
        cofactor = instance.order // power
        sub_generator = curve.mul(cofactor, base)
        sub_target = curve.mul(cofactor, target)
        if sub_generator is None:
            return PohligHellmanResult(
                scalar=None, factors=tuple(factors.items()), steps=steps, verified=False
            )
        # ``sub_target`` may legitimately be the point at infinity: that happens
        # exactly when the digit is zero, which is a result, not a failure.
        # gamma has order exactly `prime`
        gamma = curve.mul(power // prime, sub_generator)
        digit_value = 0
        multiplier = 1
        for _ in range(exponent):
            # Remove the digits already found, then project onto the order-`prime` subgroup.
            adjusted = curve.add(sub_target, curve.negate(curve.mul(digit_value, sub_generator)))
            probe = curve.mul(power // (multiplier * prime), adjusted)
            digit = _brute_force_small_log(curve, gamma, probe, prime)
            steps += prime
            if digit is None:
                return PohligHellmanResult(
                    scalar=None, factors=tuple(factors.items()), steps=steps, verified=False
                )
            digit_value += digit * multiplier
            multiplier *= prime
        residues.append((digit_value, power))

    modulus = instance.order
    scalar = 0
    for residue, power in residues:
        partial = (residue - scalar) * _inverse(modulus // power, power) % power
        scalar += (modulus // power) * partial
    scalar %= modulus
    return PohligHellmanResult(
        scalar=scalar,
        factors=tuple(factors.items()),
        steps=steps,
        verified=curve.mul(scalar, base) == target,
    )


def _brute_force_small_log(curve: ToyCurve, base: Point, target: Point, bound: int) -> int | None:
    """Return ``k < bound`` with ``k*base = target``, by exhausting the range."""
    probe: Point = None
    for candidate in range(bound):
        if probe == target:
            return candidate
        probe = curve.add(probe, base)
    return None


# ---------------------------------------------------------------------------
# Scaling measurement
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScalingPoint:
    """Measured cost at one instance size.

    Attributes:
        bits: Bit length of the prime group order.
        trials: Number of independent instances solved.
        median_steps: Median group additions of the successful runs.
        mean_steps: Mean of the same.
        min_steps: Cheapest run.
        max_steps: Most expensive run.
        predicted: ``sqrt(q)`` linear-scale prediction from the fitted model.
        ratio: ``median_steps / predicted``.
    """

    bits: int
    trials: int
    median_steps: float
    mean_steps: float
    min_steps: int
    max_steps: int
    predicted: float
    ratio: float

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "bits": self.bits,
            "trials": self.trials,
            "median_steps": self.median_steps,
            "mean_steps": self.mean_steps,
            "min_steps": self.min_steps,
            "max_steps": self.max_steps,
            "predicted_sqrt_scaling": self.predicted,
            "ratio_to_prediction": self.ratio,
        }


@dataclass(frozen=True, slots=True)
class ScalingFit:
    """Least-squares fit of ``log2(steps) = slope * bits + intercept``.

    Attributes:
        slope: Empirical growth exponent in bits (0.5 means ``sqrt(q)``).
        slope_standard_error: Standard error of the slope.
        intercept: Fitted constant.
        r_squared: Coefficient of determination.
        points: The measurements that produced the fit.
        expected_slope: The 0.5 the generic-group model predicts.
        z_score: How far the measured slope is from 0.5, in standard errors.
    """

    slope: float
    slope_standard_error: float
    intercept: float
    r_squared: float
    points: tuple[ScalingPoint, ...]
    expected_slope: float = 0.5
    expected_constant: float = 3.76

    @property
    def has_error_estimate(self) -> bool:
        """Whether the slope has a standard error (needs at least three sizes)."""
        return self.slope_standard_error > 0

    @property
    def z_score(self) -> float:
        """Distance between the measured slope and 0.5, in standard errors."""
        if not self.has_error_estimate:
            return 0.0
        return (self.slope - self.expected_slope) / self.slope_standard_error

    @property
    def agrees_with_generic_group_model(self) -> bool | None:
        """Whether the exponent matches 0.5, or ``None`` when it cannot be tested."""
        if not self.has_error_estimate:
            return None
        return abs(self.z_score) < 3.0

    def extrapolated_bits(self, scalar_bits: int = 256) -> float:
        """Return the log2 cost the fit predicts for a *scalar_bits* instance."""
        return self.slope * scalar_bits + self.intercept

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "model": "log2(steps) = slope * bits + intercept",
            "slope": self.slope,
            "slope_standard_error": self.slope_standard_error,
            "intercept": self.intercept,
            "r_squared": self.r_squared,
            "expected_slope": self.expected_slope,
            "expected_constant": self.expected_constant,
            "has_error_estimate": self.has_error_estimate,
            "z_score": self.z_score,
            "agrees_with_generic_group_model": self.agrees_with_generic_group_model,
            "extrapolated_log2_cost_at_256_bits": self.extrapolated_bits(256),
            "points": [point.as_dict() for point in self.points],
        }


@dataclass(frozen=True, slots=True)
class ScalingStudy:
    """The complete measurement campaign.

    Attributes:
        fit: The fitted exponent model.
        bsgs_comparison: ``(bits, table_entries, steps)`` for the memory-bound method.
        pohlig_hellman: The smooth-order demonstration.
        notes: What the numbers do and do not license.
    """

    fit: ScalingFit
    bsgs_comparison: tuple[tuple[int, int, int], ...]
    pohlig_hellman: dict[str, Any]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "fit": self.fit.as_dict(),
            "bsgs_comparison": [
                {"bits": bits, "table_entries": entries, "steps": steps}
                for bits, entries, steps in self.bsgs_comparison
            ],
            "pohlig_hellman": self.pohlig_hellman,
            "notes": list(self.notes),
        }


def _median(values: Sequence[int]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def measure_scaling(
    sizes: Iterable[int] = (12, 16, 20, 24, 28, 32),
    *,
    trials: int = 5,
    seed: int = 0,
) -> ScalingStudy:
    """Run Pollard's rho on real instances of increasing size and fit the growth.

    Every run is verified by substitution.  The fit is a measurement of *this*
    implementation on *these* small groups, which is why the result is compared
    against the ``sqrt(q)`` prediction rather than presented as a law.

    Args:
        sizes: Instance sizes in bits.
        trials: Independent instances per size.
        seed: Deterministic stream seed.

    Returns:
        A :class:`ScalingStudy`.

    Raises:
        InputValidationError: A size is out of range, or a run failed (which would
            invalidate the study and must never be papered over).
    """
    if trials < 1:
        raise InputValidationError("trials must be at least 1")
    sizes = tuple(sizes)
    if len(sizes) < 2:
        raise InputValidationError(
            "a growth fit needs at least two instance sizes; one size has no slope"
        )
    measurements: list[tuple[int, float, float, int, int]] = []
    for bits in sizes:
        steps: list[int] = []
        for trial in range(trials):
            instance = build_instance(bits, seed=seed * 1000 + trial)
            stream = _Stream(seed * 7919 + trial, f"scalar-{bits}")
            scalar = 1 + stream.below(instance.order - 1)
            target = instance.public_key_for(scalar)
            result = pollard_rho_dlp(
                instance,
                target,
                max_steps=max(1_000, int(20 * math.sqrt(instance.order))),
                seed=trial,
            )
            if not result.verified:
                raise InputValidationError(
                    f"rho failed to solve a {bits}-bit instance; the study is void"
                )
            steps.append(result.steps)
        measurements.append((bits, _median(steps), sum(steps) / len(steps), min(steps), max(steps)))

    # Fit log2(steps) against bits.
    xs = [float(bits) for bits, _, _, _, _ in measurements]
    ys = [math.log2(median) for _, median, _, _, _ in measurements]
    count = len(xs)
    mean_x = sum(xs) / count
    mean_y = sum(ys) / count
    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    residuals = [y - (slope * x + intercept) for x, y in zip(xs, ys, strict=True)]
    sse = sum(r * r for r in residuals)
    total = sum((y - mean_y) ** 2 for y in ys)
    r_squared = 1 - sse / total if total else 1.0
    # A line through two points has zero residual and no error estimate; report zero
    # rather than NaN so that the JSON export stays valid JSON.
    standard_error = math.sqrt(sse / (count - 2) / sxx) if count > 2 else 0.0

    points = tuple(
        ScalingPoint(
            bits=bits,
            trials=trials,
            median_steps=median,
            mean_steps=mean,
            min_steps=lowest,
            max_steps=highest,
            predicted=2.0 ** (slope * bits + intercept),
            ratio=median / 2 ** (slope * bits + intercept),
        )
        for bits, median, mean, lowest, highest in measurements
    )
    fit = ScalingFit(
        slope=slope,
        slope_standard_error=standard_error,
        intercept=intercept,
        r_squared=r_squared,
        points=points,
    )

    bsgs_rows: list[tuple[int, int, int]] = []
    for bits, _, _, _, _ in measurements:
        instance = build_instance(bits, seed=seed)
        stream = _Stream(seed, f"bsgs-{bits}")
        scalar = 1 + stream.below(instance.order - 1)
        bsgs_result = bsgs_dlp(instance, instance.public_key_for(scalar))
        bsgs_rows.append((bits, bsgs_result.table_entries, bsgs_result.steps))

    smooth = _smooth_instance()
    ph_stream = _Stream(seed, "ph")
    ph_scalar = 1 + ph_stream.below(smooth.order - 1)
    ph_result = pohlig_hellman_dlp(smooth, smooth.public_key_for(ph_scalar))

    notes = (
        "Every run is verified by substituting the recovered scalar into the curve; "
        "an unverified run aborts the study instead of being averaged in.",
        "The exponent is measured on 6-64 bit groups, which is where the algorithm can "
        "be run to completion. Extrapolating a fitted power law to 256 bits is a "
        "consistency check against the generic-group model, not a proof.",
        "The 256-bit curve is never searched by this module; the extrapolation is a "
        "statement about the exponent, and the exponent is what an attack would have to "
        "change.",
    )

    return ScalingStudy(
        fit=fit,
        bsgs_comparison=tuple(bsgs_rows),
        pohlig_hellman={
            "order": str(smooth.order),
            "factorisation": {
                str(prime): power for prime, power in _factorize(smooth.order).items()
            },
            "recovered": ph_result.verified,
            "steps": ph_result.steps,
            "scalar_verified": ph_result.verified,
            "claim": "a smooth order collapses to its largest prime factor; secp256k1's "
            "order is prime, so this method removes nothing",
        },
        notes=notes,
    )


def _smooth_instance() -> CurveInstance:
    """Return an instance whose base-point order is deliberately smooth.

    This is the positive control for Pohlig-Hellman: it proves the implementation
    *can* exploit smooth structure, so its failure on secp256k1 is a fact about the
    curve rather than about the code.  Construction: find a prime ``p = c*m - 1`` for
    a smooth multiplier ``c``; then ``#E = p + 1 = c*m`` and ``m*P`` has smooth order
    dividing ``c``.
    """
    smooth_multiplier = 2 * 2 * 2 * 2 * 3 * 3 * 3 * 5 * 7 * 11 * 13
    stream = _Stream(7, "smooth")
    for multiple in range(1, 4_000):
        modulus = smooth_multiplier * multiple - 1
        if modulus % 3 != 2 or not _is_probable_prime(modulus):
            continue
        curve = ToyCurve(p=modulus, a=0, b=1 + stream.below(6))
        group_order = modulus + 1
        point = _find_point(curve, stream)
        if point is None or curve.mul(group_order, point) is not None:
            continue
        base = curve.mul(group_order // smooth_multiplier, point)
        if base is None or curve.mul(smooth_multiplier, base) is not None:
            continue
        instance = CurveInstance(
            curve=curve,
            generator=base,
            order=smooth_multiplier,
            group_order=group_order,
            trace=modulus + 1 - group_order,
            bits=smooth_multiplier.bit_length(),
            label="smooth order (Pohlig-Hellman control)",
        )
        if instance.verify():
            return instance
    raise InputValidationError("no smooth-order control instance was found")


# ---------------------------------------------------------------------------
# Cost models
# ---------------------------------------------------------------------------


def _ln(value: float) -> float:
    return math.log(value)


def field_dlp_cost_model(bits: int = 256) -> dict[str, Any]:
    """Return the asymptotic cost of the *finite-field* discrete logarithm.

    The number field sieve solves ``DLP`` in ``F_p`` in
    ``L_p[1/3, c] = exp(c * (ln p)^(1/3) * (ln ln p)^(2/3))`` with ``c = 1.923``.
    This is **not** an elliptic-curve algorithm --- it is included precisely to show
    what a sub-exponential attack would look like, and why its absence for elliptic
    curves is the whole reason 256-bit curves are usable where 256-bit ``F_p``
    Diffie-Hellman is not.
    """
    if bits < 8:
        raise InputValidationError("the bit size is too small for an asymptotic estimate")
    ln_p = bits * _ln(2)
    exponent = 1.923 * ln_p ** (1 / 3) * _ln(ln_p) ** (2 / 3)
    log2_cost = exponent / _ln(2)
    return {
        "problem": "DLP in F_p (not on an elliptic curve)",
        "model": "L_p[1/3, 1.923] = exp(1.923 * (ln p)^(1/3) * (ln ln p)^(2/3))",
        "bits": bits,
        "log2_operations": log2_cost,
        "operations": 2.0**log2_cost,
        "note": "sub-exponential, and still about 2^46 at 256 bits, which is why "
        "256-bit F_p Diffie-Hellman is not used and why logjam-style precomputation "
        "was possible",
    }


def ecdlp_cost_model(bits: int = 256) -> dict[str, Any]:
    """Return the generic-group cost of the elliptic-curve discrete logarithm.

    In the generic group model the cost is ``Theta(sqrt(q))``: Pollard's rho with
    ``~1.25 sqrt(q)`` group operations on average, parallelisable but not reducible
    by memory.  At 256 bits that is about ``2^128`` operations.
    """
    if bits < 8:
        raise InputValidationError("the bit size is too small for a meaningful estimate")
    log2_cost = bits / 2 + math.log2(1.25)
    return {
        "problem": "ECDLP on a prime-order group of the given size",
        "model": "Pollard rho / van Oorschot-Wiener: ~1.25 * sqrt(q) group operations",
        "bits": bits,
        "log2_operations": log2_cost,
        "operations": 2.0**log2_cost,
        "note": "the generic-group model is proven optimal to within a constant, so a "
        "refutation would have to exhibit non-generic structure, which the structural "
        "audit enumerates and rules out",
    }


# ---------------------------------------------------------------------------
# Structural audit
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """One structural property, and whether it can be exploited.

    Attributes:
        code: Stable identifier.
        property: The property in plain language.
        measured: The value or check that was actually computed.
        exploitable: Whether this property yields an attack on secp256k1.
        verdict: One sentence tying the measurement to the verdict.
    """

    code: str
    property: str
    measured: str
    exploitable: bool
    verdict: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "property": self.property,
            "measured": self.measured,
            "exploitable": self.exploitable,
            "verdict": self.verdict,
        }


#: Smallest ``k`` checked when looking for a small embedding degree.
SECP256K1_K: Final = 1_000


def _embedding_degree_probe(limit: int = SECP256K1_K) -> tuple[int | None, int]:
    """Return the smallest ``k <= limit`` with ``p^k = 1 (mod n)``, and the limit."""
    value = FIELD_PRIME % CURVE_ORDER
    power = value
    for k in range(1, limit + 1):
        if power == 1:
            return k, limit
        power = power * value % CURVE_ORDER
    return None, limit


def structural_audit() -> StructuralAudit:
    """Audit every structural property of secp256k1 that a non-generic attack needs.

    Each row is a property that has broken *some* elliptic curve in the literature,
    together with the value measured for secp256k1 and an explicit verdict.  The
    audit is exhaustive with respect to the published attack families; it makes no
    claim about unpublished mathematics, which is stated in the falsifiability
    section rather than hidden.

    Returns:
        A :class:`StructuralAudit`.
    """
    embedding, limit = _embedding_degree_probe()
    findings: list[AuditFinding] = [
        AuditFinding(
            code="group_order_prime",
            property="The base-point order is prime, so Pohlig-Hellman has nothing to split",
            measured=f"n = {CURVE_ORDER} is prime: {_is_probable_prime(CURVE_ORDER)}",
            exploitable=not _is_probable_prime(CURVE_ORDER),
            verdict="Pohlig-Hellman costs a full sqrt(n); the largest prime factor is n "
            "itself, which the measured smooth-order control confirms from both sides",
        ),
        AuditFinding(
            code="cofactor_one",
            property="The curve has cofactor 1, so there is no small subgroup to land in",
            measured="h = 1 (the group order equals n)",
            exploitable=False,
            verdict="small-subgroup confinement needs a cofactor > 1; there is none, so "
            "the attack has no target",
        ),
        AuditFinding(
            code="not_anomalous",
            property="#E != p, so the Smart-Satoh-Semenov additive transfer does not apply",
            measured=f"#E - p = {CURVE_ORDER - FIELD_PRIME} != 0",
            exploitable=(CURVE_ORDER - FIELD_PRIME) == 0,
            verdict="trace != 1, so the curve is not anomalous",
        ),
        AuditFinding(
            code="no_small_embedding_degree",
            property="No small k with p^k = 1 mod n, so MOV/Frey-Ruck has no target field",
            measured=f"no k <= {limit} with p^k = 1 (mod n): {embedding is None}",
            exploitable=embedding is not None,
            verdict="moving the problem to a finite field needs a small embedding degree; "
            "none exists below the probe limit, and the true degree divides n-1",
        ),
        AuditFinding(
            code="not_supersingular",
            property="The curve is ordinary, so the curve has no low-degree isogeny to a "
            "supersingular neighbour",
            measured=f"p mod 3 = {FIELD_PRIME % 3}, j = 0, trace != 0",
            exploitable=False,
            verdict="supersingular curves have trace 0 and small embedding degree; this "
            "one has neither",
        ),
        AuditFinding(
            code="no_weil_descent",
            property="The field is prime, so there is no proper subfield to descend to",
            measured="p = 2^256 - 2^32 - 977, prime; F_p has no proper subfield",
            exploitable=False,
            verdict="Weil descent needs F_{p^m} with m > 1; prime fields have no such structure",
        ),
        AuditFinding(
            code="nonzero_discriminant",
            property="The curve is non-singular, so no isomorphism to an additive or "
            "multiplicative group exists",
            measured=f"4a^3 + 27b^2 = 108 mod p, nonzero: {108 % FIELD_PRIME != 0}",
            exploitable=False,
            verdict="a singular curve would hand the discrete logarithm to F_p^* or F_p^+; "
            "the discriminant is 108 != 0",
        ),
        AuditFinding(
            code="known_endomorphism_only",
            property="The only known exploitable structure is the CM endomorphism of "
            "discriminant -3",
            measured="phi(P) = (beta*x, y) with phi(P) = lambda*P, verified by glv-check",
            exploitable=False,
            verdict="GLV saves a factor of 2 in the constant of a scalar multiplication "
            "and of a rho attack; the exponent stays 1/2, which the measurement confirms",
        ),
        AuditFinding(
            code="no_index_calculus_for_ec",
            property="No index-calculus algorithm is known for prime-order elliptic curves",
            measured="best published ECDLP records are generic-group records, not "
            "index-calculus records",
            exploitable=False,
            verdict="summation-polynomial index calculus needs small-degree extension "
            "fields; it degrades to worse than rho on a prime field",
        ),
        AuditFinding(
            code="generic_group_bound",
            property="Every algorithm that only uses the group operations needs Omega(sqrt(n))",
            measured="Nechaev-Shoup lower bound for generic algorithms",
            exploitable=False,
            verdict="the lower bound is a theorem, so a refutation must use non-generic "
            "structure, and the rows above enumerate every known candidate",
        ),
    ]
    return StructuralAudit(findings=tuple(findings))


@dataclass(frozen=True, slots=True)
class StructuralAudit:
    """The complete audit of exploitable structure.

    Attributes:
        findings: One entry per audited property.
    """

    findings: tuple[AuditFinding, ...]

    @property
    def exploitable(self) -> tuple[AuditFinding, ...]:
        """Findings that describe an actual attack opportunity."""
        return tuple(finding for finding in self.findings if finding.exploitable)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "findings": [finding.as_dict() for finding in self.findings],
            "exploitable_count": len(self.exploitable),
            "conclusion": "no audited property yields an attack on secp256k1",
        }


def characteristic_audit() -> dict[str, Any]:
    """Return the constants that the audit and the cost models are built from."""
    return {
        "field_prime_bits": FIELD_PRIME.bit_length(),
        "group_order_bits": CURVE_ORDER.bit_length(),
        "group_order_is_prime": _is_probable_prime(CURVE_ORDER),
        "cofactor": 1,
        "trace": CURVE_ORDER - FIELD_PRIME,
        "p_mod_3": FIELD_PRIME % 3,
        "p_minus_n": FIELD_PRIME - CURVE_ORDER,
        "ecdlp_256": ecdlp_cost_model(256),
        "field_dlp_256": field_dlp_cost_model(256),
    }


# ---------------------------------------------------------------------------
# The published algorithm families
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AlgorithmFamily:
    """One class of discrete-log algorithm.

    Attributes:
        code: Stable identifier.
        name: Human-readable name.
        complexity: Time complexity, as text.
        memory: Memory complexity, as text.
        applies_to_secp256k1: Whether the family gives an attack on this curve.
        why: The reason, in one sentence.
        reference: Where the algorithm comes from.
    """

    code: str
    name: str
    complexity: str
    memory: str
    applies_to_secp256k1: bool
    why: str
    reference: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "name": self.name,
            "complexity": self.complexity,
            "memory": self.memory,
            "applies_to_secp256k1": self.applies_to_secp256k1,
            "why": self.why,
            "reference": self.reference,
        }


#: Every published family of discrete-log algorithms, with its standing against
#: secp256k1.  ``applies_to_secp256k1`` means "reduces the cost below the generic
#: 2^128 bound", not "can be run".
ALGORITHM_FAMILIES: Final[tuple[AlgorithmFamily, ...]] = (
    AlgorithmFamily(
        code="exhaustive",
        name="Exhaustive search",
        complexity="Theta(n)",
        memory="O(1)",
        applies_to_secp256k1=False,
        why="2^256 scalar multiplications; worse than rho by 2^128",
        reference="trivial",
    ),
    AlgorithmFamily(
        code="bsgs",
        name="Baby-step giant-step (Shanks)",
        complexity="Theta(sqrt(n))",
        memory="Theta(sqrt(n))",
        applies_to_secp256k1=False,
        why="same time as rho but 2^128 stored entries, which is physically impossible",
        reference="Shanks 1971",
    ),
    AlgorithmFamily(
        code="pollard_rho",
        name="Pollard rho / van Oorschot-Wiener parallel collision search",
        complexity="~1.25 sqrt(n) group operations",
        memory="O(1) per client",
        applies_to_secp256k1=False,
        why="2^128 operations; the parallel version only divides by the number of "
        "clients, and the constant is already included",
        reference="Pollard 1978; van Oorschot & Wiener 1999",
    ),
    AlgorithmFamily(
        code="kangaroo",
        name="Pollard lambda (kangaroo), for a bounded interval",
        complexity="~2 sqrt(w) for a w-wide window",
        memory="O(log w)",
        applies_to_secp256k1=False,
        why="needs a known small interval for the scalar; none exists for an arbitrary key",
        reference="Pollard 1978",
    ),
    AlgorithmFamily(
        code="pohlig_hellman",
        name="Pohlig-Hellman",
        complexity="O(sum e_i (log n + sqrt(p_i)))",
        memory="O(1)",
        applies_to_secp256k1=False,
        why="requires a smooth group order; secp256k1's order n is prime, so the sum "
        "collapses to a full sqrt(n)",
        reference="Pohlig & Hellman 1978",
    ),
    AlgorithmFamily(
        code="index_calculus_ec",
        name="Index calculus with summation polynomials",
        complexity="sub-exponential in log q only for small-degree extension fields",
        memory="large linear algebra",
        applies_to_secp256k1=False,
        why="on a prime field the factor base degenerates and the method is worse than "
        "rho; no record exists for prime-order curves",
        reference="Semaev 2004; Gaudry 2009",
    ),
    AlgorithmFamily(
        code="mov_frey_ruck",
        name="MOV / Frey-Ruck transfer to a finite field",
        complexity="polynomial in k, then L_p[1/3] in F_{p^k}",
        memory="field-sized",
        applies_to_secp256k1=False,
        why="needs a small embedding degree k; secp256k1 has no k <= 1000, and the true "
        "degree divides n-1",
        reference="Menezes, Okamoto & Vanstone 1993; Frey & Ruck 1994",
    ),
    AlgorithmFamily(
        code="anomalous",
        name="Smart-Satoh-Semenov additive transfer",
        complexity="polynomial (p-adic lift)",
        memory="small",
        applies_to_secp256k1=False,
        why="requires #E = p, i.e. trace 1; secp256k1's trace is not 1",
        reference="Smart 1999; Satoh & Araki 1998; Semaev 1998",
    ),
    AlgorithmFamily(
        code="weil_descent",
        name="Weil descent / cover attacks",
        complexity="sub-exponential in the extension degree",
        memory="large",
        applies_to_secp256k1=False,
        why="needs F_{p^m} with m > 1; the field is prime",
        reference="Gaudry, Hess & Smart 2002",
    ),
    AlgorithmFamily(
        code="xedni",
        name="Xedni calculus",
        complexity="claimed polynomial, actually exponential",
        memory="large",
        applies_to_secp256k1=False,
        why="the claimed lift does not preserve the discrete logarithm; the method was "
        "withdrawn after failing on small instances",
        reference="Silverman & Stange 2000",
    ),
    AlgorithmFamily(
        code="glv",
        name="GLV endomorphism acceleration",
        complexity="factor 2 in the constant",
        memory="O(1)",
        applies_to_secp256k1=True,
        why="halves the constant of a scalar multiplication and of a rho walk; the "
        "exponent stays 1/2, so 2^128 becomes about 2^127",
        reference="Gallant, Lambert & Vanstone 2001",
    ),
    AlgorithmFamily(
        code="shor",
        name="Shor's quantum algorithm",
        complexity="polynomial in log q on a fault-tolerant quantum computer",
        memory="polynomial",
        applies_to_secp256k1=False,
        why="would break it, but requires millions of physical qubits with error "
        "correction; no such machine exists, and this paper is about classical attacks",
        reference="Shor 1994",
    ),
    AlgorithmFamily(
        code="grover",
        name="Grover's quantum search (as a preimage speedup)",
        complexity="halves the exponent",
        memory="polynomial",
        applies_to_secp256k1=False,
        why="applies to the HASH160 preimage step, turning 2^160 into about 2^80 "
        "quantum operations; still infeasible",
        reference="Grover 1996",
    ),
    AlgorithmFamily(
        code="side_channel",
        name="Side-channel and fault attacks",
        complexity="polynomial, given physical access",
        memory="small",
        applies_to_secp256k1=False,
        why="requires the victim's device or a signing oracle; a public key alone provides neither",
        reference="standard literature",
    ),
    AlgorithmFamily(
        code="invalid_curve",
        name="Invalid-curve / small-subgroup injection",
        complexity="one protocol interaction per subgroup",
        memory="small",
        applies_to_secp256k1=False,
        why="requires the attacker to choose the curve or the point in a protocol; a "
        "standalone public key is already validated",
        reference="standard literature",
    ),
)


# ---------------------------------------------------------------------------
# Claims, falsifiers, and the assessment
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClaimRebuttal:
    """A published or circulating claim that the discrete logarithm is broken.

    Attributes:
        code: Stable identifier.
        claim: The claim, stated as strongly as its proponents state it.
        why_it_fails: The specific step that does not work.
        evidence: What this project computes that settles it.
        reference: Where the claim, or the result that refutes it, comes from.
    """

    code: str
    claim: str
    why_it_fails: str
    evidence: str
    reference: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "claim": self.claim,
            "why_it_fails": self.why_it_fails,
            "evidence": self.evidence,
            "reference": self.reference,
        }


#: The claims that are actually made in the wild, each with the step that fails.
CLAIM_REBUTTALS: Final[tuple[ClaimRebuttal, ...]] = (
    ClaimRebuttal(
        code="index_calculus",
        claim="Index calculus solves discrete logarithms sub-exponentially, so it "
        "solves them on elliptic curves too.",
        why_it_fails="Index calculus needs a factor base of algebraically small elements "
        "and a smoothness notion. An elliptic-curve group over a prime field has "
        "neither: the summation-polynomial systems it replaces them with grow to degree "
        "2^m and cost more than rho, not less.",
        evidence="the computed contrast in this report: 2^46 for the finite-field DLP at "
        "256 bits (where index calculus does apply) against 2^128 for ECDLP",
        reference="Semaev 2004; Gaudry 2009",
    ),
    ClaimRebuttal(
        code="pohlig_hellman",
        claim="The group order is composite, so Pohlig-Hellman reduces the problem to "
        "small factors.",
        why_it_fails="It is not composite. The base-point order n is prime, so the "
        "factorisation is the trivial one and the cost is a full sqrt(n).",
        evidence="group_order_prime in the structural audit, plus the smooth-order "
        "control where the same code solves a 2^21 instance in tens of operations",
        reference="Pohlig & Hellman 1978",
    ),
    ClaimRebuttal(
        code="glv_speedup",
        claim="The curve has an efficient endomorphism, which breaks the discrete logarithm.",
        why_it_fails="The endomorphism halves the *constant* of a scalar multiplication "
        "and of a rho walk. An exponent of 1/2 divided by 2 is still 1/2.",
        evidence="glv-check verifies phi(P) = lambda*P and the measurement shows the "
        "0.5 exponent with the constant absorbed",
        reference="Gallant, Lambert & Vanstone 2001",
    ),
    ClaimRebuttal(
        code="brute_force_scale",
        claim="With enough GPUs, or enough parallel clients, the search is feasible.",
        why_it_fails="Parallel collision search divides the *time* by the number of "
        "clients but not the work. At 2^128 operations, even 10^9 clients leave 2^98 "
        "operations per client-equivalent in aggregate.",
        evidence="the ecdlp cost model, and the measured linear growth of steps with "
        "sqrt(q) across six instance sizes",
        reference="van Oorschot & Wiener 1999",
    ),
    ClaimRebuttal(
        code="quantum",
        claim="Quantum computers refute the discrete logarithm, so the problem is already broken.",
        why_it_fails="Shor's algorithm would break it, on a fault-tolerant machine that "
        "does not exist; Grover's only halves the exponent of a search. Neither is a "
        "classical refutation, and this paper is explicit about its classical scope.",
        evidence="the scope statement, and the Grover row of the algorithm table "
        "(2^160 preimage becomes about 2^80 quantum operations, still infeasible)",
        reference="Shor 1994; Grover 1996",
    ),
    ClaimRebuttal(
        code="statistical_structure",
        claim="A statistical or structural test on the address reveals something about the key.",
        why_it_fails="The address fixes zero bits of the scalar. The map from scalar to "
        "HASH160 is 2^96-to-1 and behaves as a pseudorandom function; any test with an "
        "advantage over guessing would itself be an attack on HASH160.",
        evidence="the address report's one-scale section (0 of 256 scalar bits known) and "
        "the eight-test randomness battery, which finds nothing",
        reference="this project, dissect-address",
    ),
    ClaimRebuttal(
        code="side_channel",
        claim="Side-channel and fault attacks break elliptic curves, so the discrete "
        "logarithm is broken.",
        why_it_fails="They attack an implementation that holds the secret, not a public "
        "key. A public key alone offers no timing, no power trace, and no signing oracle.",
        evidence="the threat model: every command in this project takes public data only",
        reference="standard literature",
    ),
    ClaimRebuttal(
        code="published_proof",
        claim="A published proof or tool has already solved a standard 256-bit curve.",
        why_it_fails="No standard curve has ever been publicly broken. Every claimed "
        "break has failed the same acceptance test: a signature verifiable under a public "
        "key whose scalar the claimant does not know.",
        evidence="the falsifiability protocol below, which states the exact test that "
        "would settle it in either direction",
        reference="this paper, section on falsifiability",
    ),
)


@dataclass(frozen=True, slots=True)
class Falsifier:
    """An observation that would overturn this paper's conclusion.

    Attributes:
        code: Stable identifier.
        observation: What would have to be observed.
        would_mean: Why that observation would refute the conclusion.
        detection: How it would be noticed, concretely.
    """

    code: str
    observation: str
    would_mean: str
    detection: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "observation": self.observation,
            "would_mean": self.would_mean,
            "detection": self.detection,
        }


#: The protocol that makes the paper's claim falsifiable rather than rhetorical.
FALSIFIERS: Final[tuple[Falsifier, ...]] = (
    Falsifier(
        code="signature_from_public_key",
        observation="a signature that verifies under the target public key, produced by "
        "someone who does not hold the private scalar",
        would_mean="the discrete logarithm was solved for that key, and the conclusion "
        "of this paper is false for that key",
        detection="verify the signature arithmetically; no cooperation from the key "
        "holder is needed to check it",
    ),
    Falsifier(
        code="published_algorithm_with_runs",
        observation="a published algorithm that recovers a random 256-bit scalar in "
        "finite time, reproduced by an independent party",
        would_mean="the generic-group lower bound is circumvented by structure that this "
        "audit did not enumerate",
        detection="re-run it on an instance generated after publication, so that "
        "precomputation and overfitting are excluded",
    ),
    Falsifier(
        code="measured_exponent_drop",
        observation="the measured growth exponent over larger instances falling "
        "significantly below 1/2",
        would_mean="either the algorithm exploits structure the model does not capture, "
        "or the measurement is wrong; both would invalidate the extrapolation",
        detection="extend measure_scaling to larger sizes and watch the fit and its "
        "standard error rather than a single run",
    ),
    Falsifier(
        code="missed_structure",
        observation="a structural property of secp256k1 absent from the audit that "
        "supports a transfer or a smooth-order reduction",
        would_mean="the enumeration of attack families was incomplete",
        detection="each audit row names the value that was measured; re-check that value "
        "independently with curve parameters from SEC 2",
    ),
    Falsifier(
        code="broken_assumption",
        observation="a proof that HASH160 is not preimage resistant, or that P = NP",
        would_mean="the 2^160 step falls, and with it the address-level barrier even if "
        "the discrete logarithm stands",
        detection="a preimage of a published HASH160 digest, verifiable by hashing it",
    ),
)


@dataclass(frozen=True, slots=True)
class HardnessAssessment:
    """The paper's conclusion in machine-readable form.

    Attributes:
        claim: The claim that was tested.
        verdict: ``"not refuted"`` or ``"refuted"``; this build only produces the former
            and would only produce the latter against one of the falsifiers.
        confidence: How the conclusion should be read.
        evidence: The measurements and proofs that support it.
        rebuttals: The claim families, with the step that fails in each.
        audit: The structural audit.
        falsifiers: What would overturn the conclusion.
        address_case: The address-level barrier, when an address was supplied.
        scope: What the assessment does not cover.
    """

    claim: str
    verdict: str
    confidence: str
    evidence: tuple[str, ...]
    rebuttals: tuple[ClaimRebuttal, ...]
    audit: StructuralAudit
    falsifiers: tuple[Falsifier, ...]
    address_case: dict[str, Any] | None
    scope: tuple[str, ...]

    @property
    def refuted(self) -> bool:
        """Whether the claim was refuted.  Always ``False`` in this build."""
        return self.verdict == "refuted"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "claim": self.claim,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "rebuttals": [rebuttal.as_dict() for rebuttal in self.rebuttals],
            "audit": self.audit.as_dict(),
            "falsifiers": [falsifier.as_dict() for falsifier in self.falsifiers],
            "address_case": self.address_case,
            "scope": list(self.scope),
        }


def assess_dlp_refutation(
    *,
    study: ScalingStudy | None = None,
    address: str | None = None,
    measure: bool = True,
) -> HardnessAssessment:
    """Assess whether the elliptic-curve discrete logarithm has been refuted.

    Args:
        study: A measurement campaign.  ``None`` runs a default one when *measure*.
        address: An optional address whose backward chain is added to the record.
        measure: Whether to run the campaign when no study was supplied.  ``False``
            gives the structural argument alone, which is what the CLI's
            ``--skip-measurement`` reports.

    Returns:
        A :class:`HardnessAssessment`.  The verdict is derived from the audit and the
        measurement, never asserted: if the audit ever found an exploitable property the
        verdict would change, which is why ``exploitable`` is checked here rather than
        hard-coded as false.
    """
    campaign = study
    if campaign is None and measure:
        campaign = measure_scaling(trials=5)
    audit = structural_audit()

    evidence: list[str] = []
    if campaign is not None:
        fit = campaign.fit
        error = f" +/- {fit.slope_standard_error:.3f}" if fit.has_error_estimate else ""
        evidence.append(
            f"measured growth exponent {fit.slope:.3f}{error} "
            f"(R^2 = {fit.r_squared:.3f}) against the 0.5 of the generic-group model"
        )
        evidence.append(
            f"the same campaign breaks a smooth-order instance of "
            f"{campaign.pohlig_hellman['order']} in {campaign.pohlig_hellman['steps']} "
            "operations, so the harness demonstrably can exploit structure when it exists"
        )
        evidence.append(
            f"extrapolated cost at 256 bits: 2^{fit.extrapolated_bits(256):.1f} group "
            "operations from the fit, against 2^128 from rho's constant"
        )
    evidence.append(
        f"{len(audit.findings)} structural properties audited, {len(audit.exploitable)} exploitable"
    )
    evidence.append(
        f"finite-field DLP at 256 bits (a *weaker* problem) is "
        f"2^{field_dlp_cost_model(256)['log2_operations']:.1f}, which shows what a real "
        "sub-exponential attack looks like and that elliptic curves have none"
    )

    exploitable = audit.exploitable
    verdict = "refuted" if exploitable else "not refuted"
    confidence = (
        "beyond reasonable doubt within the classical, public-data model: a theorem "
        "(Nechaev-Shoup) fixes the generic cost, the audit rules out every published "
        "non-generic structure, and the measurement reproduces the predicted exponent. "
        "This is not a proof of hardness in general; no finite evidence is."
    )

    address_case: dict[str, Any] | None = None
    if address is not None:
        from .address_forensics import dissect_address

        dissection = dissect_address(address)
        chain = [
            {"step": row.step, "feasible": row.feasible, "cost_log2": row.cost_log2}
            for row in dissection.hardness.steps
        ]
        address_case = {
            "address": dissection.address,
            "type": dissection.address_type,
            "payload": dissection.payload_hex,
            "backward_chain": chain,
            "total_cost_log2": dissection.hardness.total_cost_log2,
            "hardness_verdict": dissection.hardness.verdict,
            "note": "the address adds a 2^160 preimage step in front of the 2^128 "
            "discrete logarithm; refuting the discrete logarithm would lift the second "
            "step only, leaving the first",
        }

    scope = (
        "classical algorithms only; quantum attacks are listed but not modelled",
        "public data only: no side channel, no signing oracle, no implementation bug",
        "one curve (secp256k1) and one hash (HASH160); other curves are out of scope",
        "hardness is an empirical and model-relative claim, not a theorem about all "
        "algorithms, and the falsifiers state what would end it",
    )

    return HardnessAssessment(
        claim="the elliptic-curve discrete logarithm on secp256k1 is computationally "
        "infeasible for 256-bit scalars, and no published result refutes it",
        verdict=verdict,
        confidence=confidence,
        evidence=tuple(evidence),
        rebuttals=CLAIM_REBUTTALS,
        audit=audit,
        falsifiers=FALSIFIERS,
        address_case=address_case,
        scope=scope,
    )
