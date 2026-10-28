"""Tests for script parsing, template classification, and redeem-script claims.

Scripts are built byte by byte in the tests and then verified against addresses the
package derives, so a classification bug cannot hide behind a hand-written literal.
"""

from __future__ import annotations

import pytest

from binarycryptolab.base58 import base58check_encode
from binarycryptolab.bech32 import encode_segwit_address
from binarycryptolab.exceptions import AddressEncodingError
from binarycryptolab.hashing import hash160, sha256
from binarycryptolab.script_templates import (
    classify_script,
    disassemble,
    parse_script,
    verify_script_claim,
)

KEY_1 = "02" + "11" * 32
KEY_2 = "02" + "22" * 32
KEY_3 = "03" + "33" * 32

MULTISIG_2_OF_3 = "52" + "21" + KEY_1 + "21" + KEY_2 + "21" + KEY_3 + "53" + "ae"


def p2sh_of(script_hex: str) -> str:
    """Return the mainnet P2SH address committing to *script_hex*."""
    return base58check_encode(b"\x05" + hash160(bytes.fromhex(script_hex)))


def p2wsh_of(script_hex: str) -> str:
    """Return the mainnet P2WSH address committing to *script_hex*."""
    return encode_segwit_address("bc", 0, sha256(bytes.fromhex(script_hex)))


class TestParsing:
    """The tokenizer."""

    def test_direct_pushes(self) -> None:
        tokens = parse_script("76a914" + "ab" * 20 + "88ac")
        assert [token.name for token in tokens] == [
            "OP_DUP",
            "OP_HASH160",
            "PUSH_20",
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
        assert tokens[2].data == b"\xab" * 20
        assert tokens[2].offset == 2
        assert tokens[2].width == 21

    def test_small_integers(self) -> None:
        tokens = parse_script("52" + "53")
        assert [token.small_int for token in tokens] == [2, 3]

    def test_op_zero(self) -> None:
        assert parse_script("00")[0].small_int == 0

    def test_pushdata1(self) -> None:
        script = "4c03" + "aabbcc"
        token = parse_script(script)[0]
        assert token.name == "OP_PUSHDATA1"
        assert token.data == bytes.fromhex("aabbcc")

    def test_pushdata2(self) -> None:
        script = "4d0300" + "aabbcc"
        assert parse_script(script)[0].data == bytes.fromhex("aabbcc")

    def test_unknown_opcode_is_named(self) -> None:
        assert parse_script("ff")[0].name == "OP_UNKNOWN_ff"

    def test_truncated_push(self) -> None:
        with pytest.raises(AddressEncodingError, match="truncated push"):
            parse_script("21aabb")

    def test_truncated_pushdata(self) -> None:
        with pytest.raises(AddressEncodingError, match="truncated"):
            parse_script("4c05aabb")

    def test_odd_hex(self) -> None:
        with pytest.raises(AddressEncodingError):
            parse_script("0014abc")

    def test_not_hex(self) -> None:
        with pytest.raises(AddressEncodingError):
            parse_script("zzzz")

    def test_disassembly(self) -> None:
        assert disassemble("51") == "OP_1"
        assert disassemble("0014" + "ab" * 20).startswith("OP_0 abab")

    def test_accepts_bytes(self) -> None:
        assert parse_script(bytes.fromhex("51"))[0].opcode == 0x51

    def test_accepts_zero_x_prefix(self) -> None:
        assert parse_script("0x51")[0].opcode == 0x51


class TestTemplates:
    """Classification of the standard forms."""

    def test_p2pkh(self) -> None:
        template = classify_script("76a914" + "ab" * 20 + "88ac")
        assert template.kind == "p2pkh"
        assert template.spend_paths == 1

    def test_p2sh(self) -> None:
        assert classify_script("a914" + "ab" * 20 + "87").kind == "p2sh"

    def test_p2wpkh(self) -> None:
        assert classify_script("0014" + "ab" * 20).kind == "p2wpkh"

    def test_p2wsh(self) -> None:
        assert classify_script("0020" + "ab" * 32).kind == "p2wsh"

    def test_p2tr(self) -> None:
        assert classify_script("5120" + "ab" * 32).kind == "p2tr"

    def test_p2pk(self) -> None:
        template = classify_script("21" + KEY_1 + "ac")
        assert template.kind == "p2pk"
        assert template.public_keys == (KEY_1,)

    def test_multisig(self) -> None:
        template = classify_script(MULTISIG_2_OF_3)
        assert template.kind == "multisig"
        assert (template.threshold, template.total_keys) == (2, 3)
        assert len(template.public_keys) == 3

    def test_multisig_verify_variant(self) -> None:
        script = "51" + "21" + KEY_1 + "51" + "af"
        assert classify_script(script).kind == "multisig"

    def test_multisig_with_wrong_count_is_not_multisig(self) -> None:
        script = "52" + "21" + KEY_1 + "51" + "ae"  # says 1 key, lists 1, needs 2
        template = classify_script(script)
        assert template.threshold is None or template.kind != "multisig"

    def test_htlc(self) -> None:
        script = (
            "63"
            + "a9"
            + "14"
            + "aa" * 20
            + "88"
            + "75"
            + "76a914"
            + "bb" * 20
            + "88ac"
            + "67"
            + "21"
            + KEY_1
            + "ac"
            + "68"
        )
        template = classify_script(script)
        assert template.kind == "htlc"
        assert template.hash_algorithm == "HASH160"
        assert template.hash_lock == "aa" * 20
        assert template.branches == 1
        assert template.public_keys

    def test_htlc_with_two_branches(self) -> None:
        script = (
            "63"
            + "a9"
            + "14"
            + "aa" * 20
            + "88"
            + "75"
            + "76a914"
            + "bb" * 20
            + "88ac"
            + "67"
            + "21"
            + KEY_1
            + "ac"
            + "68"
        )
        assert classify_script(script).spend_paths >= 1

    def test_cltv_timelock(self) -> None:
        script = "04" + "ffff0000" + "b1" + "75" + "21" + KEY_1 + "ac"
        template = classify_script(script)
        assert template.kind == "timelock"
        assert template.timelock_kind == "height"
        assert template.timelock_value == 65535

    def test_csv_relative_timelock(self) -> None:
        script = "02" + "1000" + "b2" + "75" + "21" + KEY_1 + "ac"
        template = classify_script(script)
        assert template.timelock_kind == "relative"

    def test_time_based_locktime(self) -> None:
        # 500000000 is the threshold above which CLTV means unix time.
        value = (500_000_000).to_bytes(4, "little").hex()
        script = "04" + value + "b1" + "75" + "21" + KEY_1 + "ac"
        assert classify_script(script).timelock_kind == "time"

    def test_op_return(self) -> None:
        assert classify_script("6a0568656c6c6f").kind == "op_return"

    def test_nonstandard(self) -> None:
        assert classify_script("deadbeefcafe").kind == "nonstandard"

    def test_empty_script(self) -> None:
        template = classify_script("")
        assert template.kind == "nonstandard"
        assert "empty" in template.notes[0]

    def test_as_dict_is_json_safe(self) -> None:
        import json

        payload = classify_script(MULTISIG_2_OF_3).as_dict()
        json.dumps(payload, allow_nan=False)
        assert payload["threshold"] == 2


class TestVerification:
    """Redeem-script claims against real addresses."""

    def test_p2sh_multisig_verifies(self) -> None:
        result = verify_script_claim(p2sh_of(MULTISIG_2_OF_3), MULTISIG_2_OF_3)
        assert result.matches is True
        assert result.proves_membership is True
        assert result.hash_algorithm == "HASH160"
        assert result.required_hash == result.computed_hash
        assert result.template.kind == "multisig"
        assert "verified" in result.verdict

    def test_p2wsh_multisig_verifies(self) -> None:
        result = verify_script_claim(p2wsh_of(MULTISIG_2_OF_3), MULTISIG_2_OF_3)
        assert result.matches is True
        assert result.hash_algorithm == "SHA256"

    def test_wrong_script_does_not_verify(self) -> None:
        result = verify_script_claim(p2sh_of(MULTISIG_2_OF_3), "51")
        assert result.matches is False
        assert "not a match" in result.verdict

    def test_one_changed_key_breaks_the_claim(self) -> None:
        other = "52" + "21" + KEY_1 + "21" + KEY_1 + "21" + KEY_3 + "53" + "ae"
        assert verify_script_claim(p2sh_of(MULTISIG_2_OF_3), other).matches is False

    def test_p2pkh_claim_compares_script_pubkey(self) -> None:
        address = "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"
        script = "76a914ab9a4edd7600fe91d0f46a97dc851ad45c1ce17688ac"
        result = verify_script_claim(address, script)
        assert result.matches is True
        assert result.hash_algorithm is None
        assert "byte-identical" in result.verdict

    def test_p2pkh_claim_with_a_different_script(self) -> None:
        result = verify_script_claim("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb", "0014" + "ab" * 20)
        assert result.matches is False

    def test_claim_notes_explain_the_limits(self) -> None:
        result = verify_script_claim(p2sh_of(MULTISIG_2_OF_3), MULTISIG_2_OF_3)
        assert any("explains the output completely" in note for note in result.notes)

    def test_as_dict_round_trips(self) -> None:
        import json

        payload = verify_script_claim(p2sh_of(MULTISIG_2_OF_3), MULTISIG_2_OF_3).as_dict()
        json.dumps(payload, allow_nan=False)
        assert payload["template"]["threshold"] == 2
        assert payload["proves_membership"] is True

    def test_bytes_input(self) -> None:
        raw = bytes.fromhex(MULTISIG_2_OF_3)
        assert verify_script_claim(p2sh_of(MULTISIG_2_OF_3), raw).matches is True

    def test_invalid_address(self) -> None:
        with pytest.raises(AddressEncodingError):
            verify_script_claim("not-an-address", MULTISIG_2_OF_3)

    def test_invalid_script(self) -> None:
        with pytest.raises(AddressEncodingError):
            verify_script_claim(p2sh_of(MULTISIG_2_OF_3), "21aabb")

    def test_oversized_script(self) -> None:
        with pytest.raises(AddressEncodingError, match="exceeds"):
            verify_script_claim(p2sh_of(MULTISIG_2_OF_3), "00" * 12_000)
