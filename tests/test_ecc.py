"""Tests for secp256k1 public-key derivation and validation.

Vectors are public: the generator point from SEC 2 and the widely published
2G coordinates.  The tests never use real wallet secrets.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.ecc import (
    COMPRESSED_PUBLIC_KEY_LENGTH,
    CURVE_ORDER,
    FIELD_PRIME,
    GENERATOR,
    UNCOMPRESSED_PUBLIC_KEY_LENGTH,
    curve_parameters,
    derive_public_key,
    is_valid_public_key_hex,
    parse_private_scalar,
    parse_public_key_hex,
    public_key_bytes,
    public_key_from_private,
    public_key_info,
    public_key_info_from_hex,
    validate_private_scalar,
)
from binarycryptolab.exceptions import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
)

COMPRESSED_ONE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
UNCOMPRESSED_ONE = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
COMPRESSED_TWO = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
UNCOMPRESSED_TWO = (
    "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
)


class TestCurveParameters:
    def test_known_constants(self) -> None:
        params = curve_parameters()
        assert params.name == "secp256k1"
        assert params.field_prime == 2**256 - 2**32 - 977
        assert params.order == CURVE_ORDER
        assert params.cofactor == 1
        assert params.curve_a == 0
        assert params.curve_b == 7
        assert (params.generator_x, params.generator_y) == GENERATOR
        assert params.field_prime == FIELD_PRIME

    def test_as_dict(self) -> None:
        payload = curve_parameters().as_dict()
        assert payload["name"] == "secp256k1"
        assert payload["field_prime"].startswith("0x")
        assert payload["order"].startswith("0x")


class TestPrivateScalarValidation:
    def test_boundaries(self) -> None:
        assert validate_private_scalar(1) == 1
        assert validate_private_scalar(CURVE_ORDER - 1) == CURVE_ORDER - 1

    @pytest.mark.parametrize("value", [0, -1, CURVE_ORDER, CURVE_ORDER + 1, 2**256])
    def test_out_of_range(self, value: int) -> None:
        with pytest.raises(InvalidPrivateKeyError, match="range"):
            validate_private_scalar(value)

    def test_non_integer(self) -> None:
        with pytest.raises(InvalidPrivateKeyError):
            validate_private_scalar("1")  # type: ignore[arg-type]
        with pytest.raises(InvalidPrivateKeyError):
            validate_private_scalar(True)  # type: ignore[arg-type]

    def test_message_never_contains_scalar(self) -> None:
        scalar = "ff" * 32
        with pytest.raises(InvalidPrivateKeyError) as excinfo:
            parse_private_scalar(scalar)
        message = str(excinfo.value)
        assert scalar not in message
        assert scalar.upper() not in message

    def test_parse_hex_and_decimal(self) -> None:
        assert parse_private_scalar("1") == 1
        assert parse_private_scalar("0x1") == 1
        assert parse_private_scalar("0A") == 10
        assert parse_private_scalar("  0x0a  ") == 10
        assert parse_private_scalar("1_0") == 16
        assert parse_private_scalar("10", base=10) == 10
        assert parse_private_scalar(7) == 7

    @pytest.mark.parametrize(
        "value",
        ["", "  ", "0x", "zz", "1g", "12 3", "0x" + "1" * 65],
    )
    def test_invalid_text(self, value: str) -> None:
        with pytest.raises(InvalidPrivateKeyError):
            parse_private_scalar(value)

    def test_invalid_base(self) -> None:
        with pytest.raises(InvalidPrivateKeyError, match="base"):
            parse_private_scalar("1", base=8)

    def test_decimal_with_hex_prefix(self) -> None:
        with pytest.raises(InvalidPrivateKeyError, match="base 16"):
            parse_private_scalar("0x10", base=10)

    def test_zero_from_text(self) -> None:
        with pytest.raises(InvalidPrivateKeyError, match="range"):
            parse_private_scalar("0")

    @settings(max_examples=25, deadline=None)
    @given(st.integers(min_value=1, max_value=CURVE_ORDER - 1))
    def test_any_in_range_scalar_is_valid(self, scalar: int) -> None:
        assert validate_private_scalar(scalar) == scalar


class TestPublicKeyDerivation:
    def test_generator(self) -> None:
        info = public_key_from_private(1)
        assert info.x == GENERATOR[0]
        assert info.y == GENERATOR[1]
        assert info.compressed_hex == COMPRESSED_ONE
        assert info.uncompressed_hex == UNCOMPRESSED_ONE
        assert info.curve == "secp256k1"
        assert info.input_encoding == "compressed"

    def test_double_generator(self) -> None:
        info = public_key_from_private(2)
        assert info.compressed_hex == COMPRESSED_TWO
        assert info.uncompressed_hex == UNCOMPRESSED_TWO

    def test_derived_key_object(self) -> None:
        public_key = derive_public_key(1)
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        numbers = public_key.public_numbers()
        assert (numbers.x, numbers.y) == GENERATOR

    def test_hex_scalar_input(self) -> None:
        assert public_key_from_private("01").compressed_hex == COMPRESSED_ONE

    def test_invalid_scalars(self) -> None:
        for scalar in (0, CURVE_ORDER, -5):
            with pytest.raises(InvalidPrivateKeyError):
                public_key_from_private(scalar)

    def test_info_has_no_private_material(self) -> None:
        payload = public_key_from_private(1).as_dict()
        assert not any("private" in key for key in payload)
        assert set(payload) >= {"curve", "x", "y", "compressed_hex", "uncompressed_hex"}

    def test_bytes(self) -> None:
        public_key = derive_public_key(1)
        compressed = public_key_bytes(public_key, compressed=True)
        uncompressed = public_key_bytes(public_key, compressed=False)
        assert len(compressed) == COMPRESSED_PUBLIC_KEY_LENGTH
        assert len(uncompressed) == UNCOMPRESSED_PUBLIC_KEY_LENGTH
        assert compressed.hex() == COMPRESSED_ONE
        assert uncompressed.hex() == UNCOMPRESSED_ONE

    @settings(max_examples=20, deadline=None)
    @given(st.integers(min_value=1, max_value=2**32))
    def test_round_trip(self, scalar: int) -> None:
        info = public_key_from_private(scalar)
        parsed = parse_public_key_hex(info.compressed_hex)
        assert parsed.public_numbers().x == info.x
        assert parsed.public_numbers().y == info.y


class TestPublicKeyParsing:
    def test_compressed(self) -> None:
        key = parse_public_key_hex(COMPRESSED_ONE)
        numbers = key.public_numbers()
        assert (numbers.x, numbers.y) == GENERATOR

    def test_compressed_with_prefix_and_whitespace(self) -> None:
        key = parse_public_key_hex(" 0x" + COMPRESSED_ONE.upper() + " ")
        assert key.public_numbers().x == GENERATOR[0]

    def test_uncompressed(self) -> None:
        key = parse_public_key_hex(UNCOMPRESSED_ONE)
        assert key.public_numbers().y == GENERATOR[1]

    def test_raw_uncompressed_coordinates(self) -> None:
        raw = UNCOMPRESSED_ONE[2:]
        key = parse_public_key_hex(raw)
        assert key.public_numbers().x == GENERATOR[0]

    def test_info_from_hex_detects_encoding(self) -> None:
        assert public_key_info_from_hex(COMPRESSED_ONE).input_encoding == "compressed"
        assert public_key_info_from_hex(UNCOMPRESSED_ONE).input_encoding == "uncompressed"
        assert public_key_info_from_hex(COMPRESSED_ONE).compressed_hex == COMPRESSED_ONE

    def test_invalid_encodings(self) -> None:
        invalid = [
            "",
            "00",
            "05" + COMPRESSED_ONE[2:],
            "04" + "00" * 64,
            "02" + f"{FIELD_PRIME:064x}",
            COMPRESSED_ONE[:-2],
            COMPRESSED_ONE + "00",
            "zz" * 33,
        ]
        for value in invalid:
            with pytest.raises(InvalidPublicKeyError):
                parse_public_key_hex(value)

    def test_error_does_not_echo_key(self) -> None:
        candidate = "02" + f"{FIELD_PRIME:064x}"
        with pytest.raises(InvalidPublicKeyError) as excinfo:
            parse_public_key_hex(candidate)
        assert candidate not in str(excinfo.value)

    def test_non_string(self) -> None:
        with pytest.raises(InvalidPublicKeyError):
            parse_public_key_hex(b"02")  # type: ignore[arg-type]

    def test_is_valid_predicate(self) -> None:
        assert is_valid_public_key_hex(COMPRESSED_ONE)
        assert is_valid_public_key_hex(UNCOMPRESSED_ONE)
        assert not is_valid_public_key_hex("00")
        assert not is_valid_public_key_hex("not-a-key")

    def test_public_key_info_rejects_other_curves(self) -> None:
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        with pytest.raises(InvalidPublicKeyError, match="secp256k1"):
            public_key_info(other)
        with pytest.raises(InvalidPublicKeyError):
            public_key_info("not a key")  # type: ignore[arg-type]
