"""Tests for the GLV endomorphism verification.

Every check here is independent of the implementation: the identities are curve
facts, and ``phi(G) = lambda * G`` is compared against OpenSSL through
``cryptography`` (which derives ``lambda * G`` as a normal key), so the module
cannot invent agreement with itself.
"""

from __future__ import annotations

import pytest

from binarycryptolab.ecc import CURVE_ORDER, FIELD_PRIME, GENERATOR, public_key_from_private
from binarycryptolab.exceptions import InputValidationError, InvalidPublicKeyError
from binarycryptolab.glv import (
    GLV_BETA,
    GLV_LAMBDA,
    endomorphism,
    verify_glv,
)

GENERATOR_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

#: phi(G), computed by the closed form.  The test below re-derives it through OpenSSL.
PHI_G = "02bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb"


class TestCurveConstants:
    """The self-tests from the original standalone script, kept as assertions."""

    def test_beta_cubed_is_one(self) -> None:
        assert pow(GLV_BETA, 3, FIELD_PRIME) == 1

    def test_beta_is_not_one(self) -> None:
        assert GLV_BETA != 1

    def test_lambda_has_order_three(self) -> None:
        assert (GLV_LAMBDA * GLV_LAMBDA + GLV_LAMBDA + 1) % CURVE_ORDER == 0

    def test_lambda_is_not_one(self) -> None:
        assert GLV_LAMBDA != 1

    def test_generator_is_on_the_curve(self) -> None:
        x, y = GENERATOR
        assert (y * y - x * x * x - 7) % FIELD_PRIME == 0


class TestEndomorphism:
    """The map itself."""

    def test_infinity_maps_to_infinity(self) -> None:
        assert endomorphism(None) is None

    def test_phi_keeps_y_and_scales_x(self) -> None:
        point = (12345, 67890)
        phi = endomorphism(point)
        assert phi is not None
        assert phi[1] == point[1]
        assert phi[0] == 12345 * GLV_BETA % FIELD_PRIME

    def test_phi_of_generator_matches_openssl(self) -> None:
        """lambda*G is a plain key derivation, so OpenSSL can check our arithmetic."""
        assert endomorphism(GENERATOR) is not None
        assert verify_glv(GENERATOR_HEX).phi_hex == PHI_G
        assert public_key_from_private(GLV_LAMBDA).compressed_hex == PHI_G


class TestVerifyGlv:
    """The report."""

    def test_every_check_passes_for_the_generator(self) -> None:
        report = verify_glv(GENERATOR_HEX)
        assert report.verified is True
        assert all(check.passed for check in report.checks)
        assert len(report.checks) == 8

    def test_codes_are_unique_and_ordered(self) -> None:
        codes = [check.code for check in verify_glv(GENERATOR_HEX).checks]
        assert len(codes) == len(set(codes))
        assert codes[0] == "beta_is_cube_root_of_unity"
        assert codes[-1] == "sum_is_infinity"

    def test_three_torsion_sum(self) -> None:
        report = verify_glv(GENERATOR_HEX)
        assert report.three_torsion is True

    def test_phi_squared_differs_from_both(self) -> None:
        report = verify_glv(GENERATOR_HEX)
        assert report.phi_squared_hex not in {report.public_key_hex, report.phi_hex}

    def test_uncompressed_input_is_normalised(self) -> None:
        compressed = verify_glv(GENERATOR_HEX)
        uncompressed = verify_glv(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        assert uncompressed.public_key_hex == compressed.public_key_hex

    @pytest.mark.parametrize("scalar", [1, 2, 3, 7, 255, 123456789])
    def test_holds_for_arbitrary_keys(self, scalar: int) -> None:
        key = public_key_from_private(scalar).compressed_hex
        report = verify_glv(key)
        assert report.verified is True
        expected = public_key_from_private((GLV_LAMBDA * scalar) % CURVE_ORDER)
        assert report.phi_hex == expected.compressed_hex

    def test_serialization_is_json_ready(self) -> None:
        payload = verify_glv(GENERATOR_HEX).as_dict()
        assert payload["verified"] is True
        assert payload["three_torsion"] is True
        assert payload["speedup_factor"] == 2
        assert isinstance(payload["checks"], list)
        assert payload["checks"][0]["passed"] is True

    def test_speedup_phrase_refuses_to_overclaim(self) -> None:
        phrase = verify_glv(GENERATOR_HEX).speedup_phrase
        assert "2^127" in phrase
        assert "does not change" in phrase

    def test_notes_disclaim_key_specificity(self) -> None:
        notes = " ".join(verify_glv(GENERATOR_HEX).notes)
        assert "property of secp256k1, not of this key" in notes
        assert "No private scalar" in notes

    def test_rejects_a_bad_checksum_point(self) -> None:
        with pytest.raises((InvalidPublicKeyError, InputValidationError)):
            verify_glv("02" + "00" * 32)

    def test_rejects_garbage(self) -> None:
        with pytest.raises((InvalidPublicKeyError, InputValidationError)):
            verify_glv("not a key")
