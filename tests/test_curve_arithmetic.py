"""Tests for the analysis-only secp256k1 arithmetic.

The point of this module is that it is *not* trusted: every operation is checked
against ``cryptography``'s OpenSSL implementation and against the published
generator vector before it is used by the reconstruction layer.
"""

from __future__ import annotations

import random

import pytest

from binarycryptolab.curve_arithmetic import (
    MAX_TABLE_ENTRIES,
    add,
    compressed_hex,
    decode_public_key,
    discrete_log_interval,
    double,
    infinity,
    is_infinity,
    multiply,
    negate,
    sub,
)
from binarycryptolab.ecc import CURVE_ORDER, GENERATOR, public_key_from_private
from binarycryptolab.exceptions import InputValidationError

#: A deterministic, documented generator point public key (scalar 1).
GENERATOR_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _random_scalars(count: int, seed: int = 20240502) -> list[int]:
    """Return reproducible scalars in ``[1, n)``."""
    engine = random.Random(seed)
    return [engine.randrange(1, CURVE_ORDER) for _ in range(count)]


class TestAgreementWithOpenSSL:
    """The implementation must reproduce the maintained library exactly."""

    def test_generator_vector(self) -> None:
        assert compressed_hex(multiply(GENERATOR, 1)) == GENERATOR_HEX

    @pytest.mark.parametrize("scalar", _random_scalars(12))
    def test_scalar_multiplication_matches_cryptography(self, scalar: int) -> None:
        expected = public_key_from_private(scalar).compressed_hex
        assert compressed_hex(multiply(GENERATOR, scalar)) == expected

    def test_known_small_scalars(self) -> None:
        for scalar in (1, 2, 3, 4, 5, 255, 256, 65537):
            expected = public_key_from_private(scalar).compressed_hex
            assert compressed_hex(multiply(GENERATOR, scalar)) == expected

    def test_order_multiple_is_infinity(self) -> None:
        assert multiply(GENERATOR, CURVE_ORDER) is None


class TestGroupLaws:
    """Algebraic identities that any correct group implementation satisfies."""

    def test_identity(self) -> None:
        point = multiply(GENERATOR, 12345)
        assert add(point, infinity) == point
        assert add(infinity, point) == point
        assert add(infinity, infinity) is None

    def test_addition_matches_scalar_addition(self) -> None:
        for a, b in ((1, 1), (7, 11), (1000, 2000), (123456, 654321)):
            left = add(multiply(GENERATOR, a), multiply(GENERATOR, b))
            assert left == multiply(GENERATOR, a + b)

    def test_commutative(self) -> None:
        point_a = multiply(GENERATOR, 111)
        point_b = multiply(GENERATOR, 222)
        assert add(point_a, point_b) == add(point_b, point_a)

    def test_negation(self) -> None:
        point = multiply(GENERATOR, 999)
        assert add(point, negate(point)) is None
        assert negate(negate(point)) == point
        assert negate(infinity) is None

    def test_subtraction(self) -> None:
        point_a = multiply(GENERATOR, 5000)
        point_b = multiply(GENERATOR, 3000)
        assert sub(point_a, point_b) == multiply(GENERATOR, 2000)
        assert sub(point_a, point_a) is None

    def test_doubling(self) -> None:
        point = multiply(GENERATOR, 77)
        assert double(point) == add(point, point) == multiply(GENERATOR, 154)

    def test_distributive(self) -> None:
        point = multiply(GENERATOR, 424242)
        assert multiply(point, 5) == add(double(double(point)), point)

    def test_reported_infinity_flag(self) -> None:
        assert is_infinity(infinity)
        assert not is_infinity(GENERATOR)


class TestValidation:
    """Bad points must be rejected before any arithmetic happens."""

    def test_rejects_off_curve_point(self) -> None:
        with pytest.raises(InputValidationError):
            add((1, 1), GENERATOR)

    def test_rejects_out_of_range_coordinates(self) -> None:
        with pytest.raises(InputValidationError):
            negate((-1, 5))
        with pytest.raises(InputValidationError):
            double((0, 0))

    def test_rejects_malformed_point(self) -> None:
        with pytest.raises(InputValidationError):
            multiply((1, 2, 3), 5)  # type: ignore[arg-type]

    def test_rejects_non_integer_scalar(self) -> None:
        with pytest.raises(InputValidationError):
            multiply(GENERATOR, "5")  # type: ignore[arg-type]

    def test_compressed_hex_rejects_infinity(self) -> None:
        with pytest.raises(InputValidationError):
            compressed_hex(None)


class TestDecode:
    """SEC 1 decoding of the three accepted encodings."""

    def test_compressed_and_uncompressed_agree(self) -> None:
        info = public_key_from_private(2024)
        assert decode_public_key(info.compressed_hex) == decode_public_key(info.uncompressed_hex)
        assert decode_public_key(info.uncompressed_hex[2:]) == decode_public_key(
            info.compressed_hex
        )

    def test_round_trip(self) -> None:
        point = multiply(GENERATOR, 31337)
        assert decode_public_key(compressed_hex(point)) == point

    def test_accepts_hex_prefix_and_whitespace(self) -> None:
        assert decode_public_key(" 0X" + GENERATOR_HEX.upper() + " ") == GENERATOR

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "zz",
            "02",
            "04" + "00" * 64,
            "05" + GENERATOR_HEX[2:],
        ],
    )
    def test_rejects_invalid_encodings(self, text: str) -> None:
        with pytest.raises(InputValidationError):
            decode_public_key(text)

    def test_rejects_x_only(self) -> None:
        with pytest.raises(InputValidationError):
            decode_public_key(GENERATOR_HEX[2:])


class TestDiscreteLogInterval:
    """The bounded baby-step/giant-step search."""

    @pytest.mark.parametrize("bits", [1, 4, 8, 12, 16])
    def test_finds_small_scalars(self, bits: int) -> None:
        for scalar in (1, (1 << bits) - 1, 1 << (bits - 1)):
            target = multiply(GENERATOR, scalar)
            assert discrete_log_interval(target, low=0, high=1 << bits) == scalar

    def test_offset_interval(self) -> None:
        scalar = 70000
        target = multiply(GENERATOR, scalar)
        assert discrete_log_interval(target, low=69000, high=71000) == scalar

    def test_returns_none_outside_the_interval(self) -> None:
        target = multiply(GENERATOR, 500)
        assert discrete_log_interval(target, low=0, high=100) is None

    def test_zero_is_found_in_a_unit_interval(self) -> None:
        assert discrete_log_interval(infinity, low=0, high=1) == 0

    def test_arbitrary_generator(self) -> None:
        base = multiply(GENERATOR, 1000)
        target = multiply(base, 37)
        assert discrete_log_interval(target, generator=base, low=0, high=64) == 37

    def test_rejects_empty_interval(self) -> None:
        with pytest.raises(InputValidationError):
            discrete_log_interval(GENERATOR, low=5, high=5)

    def test_rejects_unbounded_search(self) -> None:
        with pytest.raises(InputValidationError):
            discrete_log_interval(GENERATOR)

    def test_rejects_interval_above_the_table_cap(self) -> None:
        with pytest.raises(InputValidationError):
            discrete_log_interval(GENERATOR, low=0, high=1 << 80)

    def test_respects_a_smaller_explicit_cap(self) -> None:
        with pytest.raises(InputValidationError):
            discrete_log_interval(GENERATOR, low=0, high=1 << 16, max_entries=4)

    def test_cap_constant_is_a_power_of_two(self) -> None:
        assert MAX_TABLE_ENTRIES & (MAX_TABLE_ENTRIES - 1) == 0
