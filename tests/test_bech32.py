"""Bech32 and Bech32m tests against the official BIP-173 and BIP-350 vectors."""

from __future__ import annotations

import pytest

from binarycryptolab.bech32 import (
    BECH32_HRP_LIMIT,
    Bech32Spec,
    bech32_create_checksum,
    bech32_decode,
    bech32_encode,
    bech32_polymod,
    bech32_verify_checksum,
    convert_5_to_8,
    convert_8_to_5,
    decode_segwit_address,
    encode_segwit_address,
)
from binarycryptolab.exceptions import InvalidBech32Error

# BIP-173, "Test vectors": valid Bech32 strings.
VALID_BECH32 = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

INVALID_BECH32 = [
    "\x201nwldj5",
    "\x7f1axkwrx",
    "\x801eym55h",
    ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"),
    "pzry9x0s0muk",
    "1pzry9x0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
    "A1G7SGD8",
    "10a06t8",
    "1qzzfhee",
]

# BIP-350, "Test vectors for Bech32m": valid Bech32m strings.
VALID_BECH32M = [
    "A1LQFN3A",
    "a1lqfn3a",
    ("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"),
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

INVALID_BECH32M = [
    "\x201xj0phk",
    "\x7f1g6xzxy",
    "\x801vctc34",
    ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"),
    "qyrz8wqd2c9m",
    "1qyrz8wqd2c9m",
    "y1b0jsk6g",
    "lt1igcx5c0",
    "in1muywd",
    "mm1crxm3i",
    "au1s5cgom",
    "M1VUXWEZ",
    "16plkw9",
    "1p2gdwpf",
]

# BIP-350, native segwit addresses and their scriptPubKeys.
VALID_SEGWIT = [
    (
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "tb",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "bc",
        ("5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
    ),
    ("BC1SW50QGDZ25J", "bc", "6002751e"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "bc", "5210751e76e8199196d454941c45d1b3a323"),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "tb",
        ("0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ),
    (
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "tb",
        ("5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
]

INVALID_SEGWIT = [
    ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", "bc"),
    ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "bc"),
    ("tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", "tb"),
    ("BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", "bc"),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "bc"),
    ("tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", "tb"),
    ("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", "bc"),
    ("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", "bc"),
    ("bc1pw5dgrnzv", "bc"),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "bc",
    ),
    ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "bc"),
    ("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", "tb"),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "bc",
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "tb",
    ),
    ("bc1gmk9yu", "bc"),
]


class TestGenericBech32:
    @pytest.mark.parametrize("value", VALID_BECH32)
    def test_valid_bech32(self, value: str) -> None:
        hrp, _data, spec = bech32_decode(value)
        assert spec is Bech32Spec.BECH32
        assert hrp == value.lower().rsplit("1", 1)[0]

    @pytest.mark.parametrize("value", INVALID_BECH32)
    def test_invalid_bech32(self, value: str) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_decode(value)

    @pytest.mark.parametrize("value", VALID_BECH32M)
    def test_valid_bech32m(self, value: str) -> None:
        _, _, spec = bech32_decode(value)
        assert spec is Bech32Spec.BECH32M

    @pytest.mark.parametrize("value", INVALID_BECH32M)
    def test_invalid_bech32m(self, value: str) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_decode(value)

    def test_no_string_is_both_variants(self) -> None:
        for value in VALID_BECH32:
            hrp, data, _spec = bech32_decode(value)
            full = [*data, *bech32_create_checksum(hrp, data, Bech32Spec.BECH32)]
            assert bech32_verify_checksum(hrp, full) is Bech32Spec.BECH32
        for value in VALID_BECH32M:
            hrp, data, _spec = bech32_decode(value)
            full = [*data, *bech32_create_checksum(hrp, data, Bech32Spec.BECH32M)]
            assert bech32_verify_checksum(hrp, full) is Bech32Spec.BECH32M

    def test_encode_round_trip(self) -> None:
        for value in VALID_BECH32:
            hrp, data, spec = bech32_decode(value)
            assert bech32_encode(hrp, data, spec).lower() == value.lower()

    def test_mixed_case_rejected(self) -> None:
        with pytest.raises(InvalidBech32Error, match="mix"):
            bech32_decode("A12uEL5L")

    def test_encode_requires_lowercase_hrp(self) -> None:
        with pytest.raises(InvalidBech32Error, match="lowercase"):
            bech32_encode("BC", [0], Bech32Spec.BECH32)

    def test_hrp_length_limits(self) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_encode("", [], Bech32Spec.BECH32)
        with pytest.raises(InvalidBech32Error):
            bech32_encode("a" * (BECH32_HRP_LIMIT + 1), [], Bech32Spec.BECH32)

    def test_polymod_rejects_out_of_range(self) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_polymod([32])

    def test_encode_rejects_bad_data_values(self) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_encode("a", [32], Bech32Spec.BECH32)

    def test_decode_rejects_short_and_long(self) -> None:
        with pytest.raises(InvalidBech32Error):
            bech32_decode("a1qqqqq")
        with pytest.raises(InvalidBech32Error):
            bech32_decode("a1" + "q" * 90)


class TestSegwitAddresses:
    @pytest.mark.parametrize(("address", "hrp", "script_hex"), VALID_SEGWIT)
    def test_valid_addresses(self, address: str, hrp: str, script_hex: str) -> None:
        version, program = decode_segwit_address(hrp, address)
        opcode = 0x00 if version == 0 else 0x50 + version
        script = bytes([opcode, len(program)]) + program
        assert script.hex() == script_hex
        assert encode_segwit_address(hrp, version, program) == address.lower()

    @pytest.mark.parametrize(("address", "hrp"), INVALID_SEGWIT)
    def test_invalid_addresses(self, address: str, hrp: str) -> None:
        with pytest.raises(InvalidBech32Error):
            decode_segwit_address(hrp, address)

    def test_hrp_mismatch(self) -> None:
        with pytest.raises(InvalidBech32Error, match="does not match"):
            decode_segwit_address("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def test_wrong_checksum_variant(self) -> None:
        # Encoding a v0 program with Bech32m must be rejected on decode.
        program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        wrong = bech32_encode("bc", [0, *convert_8_to_5(program)], Bech32Spec.BECH32M)
        with pytest.raises(InvalidBech32Error, match="bech32"):
            decode_segwit_address("bc", wrong)

    def test_version_range(self) -> None:
        program = b"\x00" * 20
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", 17, program)
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", -1, program)
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", True, program)  # type: ignore[arg-type]

    def test_program_length_limits(self) -> None:
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", 0, b"\x00")
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", 0, b"\x00" * 21)
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", 1, b"\x00" * 41)
        with pytest.raises(InvalidBech32Error):
            encode_segwit_address("bc", 1, "program")  # type: ignore[arg-type]

    def test_empty_data_section(self) -> None:
        with pytest.raises(InvalidBech32Error, match="witness version"):
            decode_segwit_address("bc", "bc1gmk9yu")


class TestConvertBits:
    def test_round_trip(self) -> None:
        data = bytes(range(40))
        groups = convert_8_to_5(data)
        assert convert_5_to_8(groups, pad=False) == data

    def test_non_zero_padding_is_rejected(self) -> None:
        with pytest.raises(InvalidBech32Error):
            convert_5_to_8([1], pad=False)
        with pytest.raises(InvalidBech32Error):
            convert_8_to_5(b"\x01", pad=False)

    def test_invalid_values(self) -> None:
        with pytest.raises(InvalidBech32Error):
            convert_5_to_8([32])
        with pytest.raises(InvalidBech32Error):
            convert_5_to_8([-1])
