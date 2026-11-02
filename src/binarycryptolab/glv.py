"""GLV endomorphism verification for secp256k1.

secp256k1 has an efficiently computable endomorphism

.. math::

    \\phi(x, y) = (\\beta x, y), \\qquad \\beta^3 \\equiv 1 \\pmod p

which acts on a point exactly like multiplication by a scalar :math:`\\lambda`:

.. math::

    \\phi(P) = \\lambda P, \\qquad \\lambda^2 + \\lambda + 1 \\equiv 0 \\pmod n

The GLV method (Gallant-Lambert-Vanstone, CRYPTO 2001) splits a scalar ``k`` into
two half-length scalars and evaluates ``kP`` with Shamir's trick, which roughly
halves the work of one scalar multiplication.

Why this module exists
----------------------
The relationship is *verifiable*: given any point, both sides can be computed and
compared.  That makes it a genuine structural check on an implementation and on a
public key, rather than a claim to be taken on faith.  This module performs every
one of those checks and reports them individually.

What it does **not** mean
-------------------------
The endomorphism is a property of the **curve**, not of a key.  It is identical for
every secp256k1 public key that exists, so it carries no information about the key
under analysis, and it is not a weakness introduced by whoever generated it.  Its
only practical consequence is a factor of about two in the constant of a
discrete-log attack --- ``2^128`` becomes roughly ``2^127`` operations.  An
exponent that moves by a factor of two is still ``2^128``.  The report says this
in as many words.

Arithmetic
----------
No curve arithmetic is implemented here.  :func:`~binarycryptolab.curve_arithmetic.multiply`
does the point operations, and that module is itself cross-checked against
OpenSSL (``cryptography``) and against the published SEC 2 vectors in the test
suite.  This module only decides *what to compare*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from .curve_arithmetic import Point, decode_public_key, multiply
from .ecc import CURVE_ORDER, FIELD_PRIME, GENERATOR

__all__ = [
    "GLV_BETA",
    "GLV_LAMBDA",
    "GlvCheck",
    "GlvReport",
    "endomorphism",
    "verify_glv",
]

#: Cube root of unity modulo the field prime.  ``GLV_BETA ** 3 % FIELD_PRIME == 1``.
GLV_BETA: Final[int] = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE

#: Eigenvalue of the endomorphism.  ``(GLV_LAMBDA**2 + GLV_LAMBDA + 1) % n == 0``.
GLV_LAMBDA: Final[int] = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72

#: The speedup GLV buys: one half-length scalar multiplication instead of one full.
GLV_SPEEDUP_FACTOR: Final[int] = 2


@dataclass(frozen=True, slots=True)
class GlvCheck:
    """One independently verifiable statement about the endomorphism.

    Attributes:
        code: Short identifier, stable across releases.
        statement: The claim in plain language.
        passed: Whether the computation agreed with the claim.
        detail: The numbers that were compared, abbreviated for a report.
    """

    code: str
    statement: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "statement": self.statement,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class GlvReport:
    """Result of verifying the endomorphism on a supplied public key.

    Attributes:
        public_key_hex: Normalized compressed key that was analysed.
        phi_hex: ``phi(P)`` as a compressed key.
        phi_squared_hex: ``phi(phi(P))`` as a compressed key.
        lambda_times_key_hex: ``lambda * P`` as a compressed key.
        checks: Every statement that was verified, in a fixed order.
        notes: Honesty notes about what the check does and does not mean.
    """

    public_key_hex: str
    phi_hex: str
    phi_squared_hex: str
    lambda_times_key_hex: str
    checks: tuple[GlvCheck, ...]
    notes: tuple[str, ...]

    @property
    def verified(self) -> bool:
        """Whether every check passed."""
        return all(check.passed for check in self.checks)

    @property
    def three_torsion(self) -> bool:
        """Whether ``P + phi(P) + phi^2(P)`` is the point at infinity.

        True for every point in the group, because the three images are the three
        cube roots of the same endomorphism orbit.  It is reported separately
        because it is the check that ties the three points together.
        """
        return next(check.passed for check in self.checks if check.code == "sum_is_infinity")

    @property
    def speedup_phrase(self) -> str:
        """How the endomorphism affects an attacker, in one honest sentence."""
        return (
            "GLV splits one 256-bit scalar multiplication into two 128-bit ones, so it "
            "saves roughly a factor of 2. A discrete-log attack quoted at 2^128 becomes "
            "about 2^127 operations: the exponent does not change, and the barrier does "
            "not move."
        )

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "public_key_hex": self.public_key_hex,
            "phi_hex": self.phi_hex,
            "phi_squared_hex": self.phi_squared_hex,
            "lambda_times_key_hex": self.lambda_times_key_hex,
            "verified": self.verified,
            "three_torsion": self.three_torsion,
            "checks": [check.as_dict() for check in self.checks],
            "speedup_factor": GLV_SPEEDUP_FACTOR,
            "speedup_phrase": self.speedup_phrase,
            "notes": list(self.notes),
        }


def endomorphism(point: Point) -> Point:
    """Return ``phi(point) = (beta * x mod p, y)``.

    Args:
        point: An affine point, or ``None`` for the point at infinity.

    Returns:
        The image point, or ``None`` if the input was the point at infinity.
    """
    if point is None:
        return None
    x, y = point
    return (x * GLV_BETA % FIELD_PRIME, y)


def _compressed(point: Point) -> str:
    """Return a compressed SEC 1 encoding for a point, without importing bitcoin.py."""
    if point is None:
        raise ValueError("the point at infinity has no compressed encoding")
    x, y = point
    prefix = "02" if y % 2 == 0 else "03"
    return prefix + f"{x:064x}"


def _check_curve_constants() -> tuple[GlvCheck, ...]:
    """Verify the two constants against the curve, independently of any key."""
    beta_check = GlvCheck(
        code="beta_is_cube_root_of_unity",
        statement="beta^3 = 1 mod p, so phi is a non-trivial automorphism of the curve",
        passed=pow(GLV_BETA, 3, FIELD_PRIME) == 1 and GLV_BETA != 1,
        detail=f"beta^3 mod p = {pow(GLV_BETA, 3, FIELD_PRIME):x}",
    )
    lambda_check = GlvCheck(
        code="lambda_is_primitive_cube_root",
        statement="lambda^2 + lambda + 1 = 0 mod n, so lambda has order 3",
        passed=((GLV_LAMBDA * GLV_LAMBDA + GLV_LAMBDA + 1) % CURVE_ORDER == 0 and GLV_LAMBDA != 1),
        detail="(lambda^2 + lambda + 1) mod n = "
        f"{(GLV_LAMBDA * GLV_LAMBDA + GLV_LAMBDA + 1) % CURVE_ORDER}",
    )
    generator_check = GlvCheck(
        code="endomorphism_matches_lambda_on_generator",
        statement="phi(G) = lambda * G, which anchors the identity on the generator",
        passed=endomorphism(GENERATOR) == multiply(GENERATOR, GLV_LAMBDA),
        detail="phi(G) and lambda*G compared coordinate by coordinate",
    )
    return beta_check, lambda_check, generator_check


def verify_glv(public_key_hex: str) -> GlvReport:
    """Verify the GLV endomorphism on the curve and on one public key.

    Args:
        public_key_hex: SEC 1 public key, compressed or uncompressed.

    Returns:
        A :class:`GlvReport` with every check and its outcome.

    Raises:
        InvalidPublicKeyError: The input is not a valid secp256k1 public key.
        InputValidationError: The input is not a public key encoding at all.

    Example:
        >>> report = verify_glv("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        >>> report.verified, report.three_torsion
        (True, True)
    """
    point = decode_public_key(public_key_hex)
    phi_point = endomorphism(point)
    phi_squared_point = endomorphism(phi_point)
    lambda_point = multiply(point, GLV_LAMBDA)

    checks: list[GlvCheck] = list(_check_curve_constants())

    checks.append(
        GlvCheck(
            code="phi_point_on_curve",
            statement="phi(P) satisfies the curve equation",
            passed=_is_on_curve(phi_point),
            detail=f"phi(P) = {_compressed(phi_point)}",
        )
    )
    checks.append(
        GlvCheck(
            code="phi_squared_on_curve",
            statement="phi(phi(P)) satisfies the curve equation",
            passed=_is_on_curve(phi_squared_point),
            detail=f"phi^2(P) = {_compressed(phi_squared_point)}",
        )
    )
    checks.append(
        GlvCheck(
            code="phi_equals_lambda",
            statement="phi(P) = lambda * P for the supplied point",
            passed=phi_point == lambda_point,
            detail=f"lambda*P = {_compressed(lambda_point)}",
        )
    )
    checks.append(
        GlvCheck(
            code="phi_is_not_identity",
            statement="the endomorphism actually moves this point",
            passed=phi_point != point,
            detail="phi(P) differs from P, so the orbit has three distinct points",
        )
    )
    checks.append(
        GlvCheck(
            code="sum_is_infinity",
            statement="P + phi(P) + phi^2(P) = O",
            passed=_sum_is_infinity(point, phi_point, phi_squared_point),
            detail="the three orbit points sum to the point at infinity",
        )
    )

    notes = (
        "The endomorphism is a property of secp256k1, not of this key: every valid "
        "public key satisfies all of these checks, so the result carries no "
        "information about who generated the key or how.",
        "GLV accelerates a discrete-log search by roughly a factor of 2 in the "
        "constant, which leaves the 2^128 exponent unchanged. A speedup is not a break.",
        "No private scalar is used, derived, or searched for: every value here is "
        "computed from public coordinates and public curve constants.",
    )

    return GlvReport(
        public_key_hex=_compressed(point),
        phi_hex=_compressed(phi_point),
        phi_squared_hex=_compressed(phi_squared_point),
        lambda_times_key_hex=_compressed(lambda_point),
        checks=tuple(checks),
        notes=notes,
    )


def _is_on_curve(point: Point) -> bool:
    """Return whether *point* satisfies ``y^2 = x^3 + 7`` over the field."""
    if point is None:
        return False
    x, y = point
    if not (0 <= x < FIELD_PRIME and 0 <= y < FIELD_PRIME):
        return False
    return (y * y - x * x * x - 7) % FIELD_PRIME == 0


def _sum_is_infinity(first: Point, second: Point, third: Point) -> bool:
    """Return whether ``first + second + third`` is the point at infinity."""
    from .curve_arithmetic import add

    return add(add(first, second), third) is None
