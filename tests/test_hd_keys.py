"""Tests for BIP-32 extended public keys.

Two independent oracles are used:

* the published BIP-32 test vectors (master, ``m/0H``, ``m/0H/1``), which pin the
  serialization, the HMAC, and the hardened *and* non-hardened rules;
* a private-side derivation written from scratch inside the test, which computes
  ``k_child = IL + k`` and must agree with the public derivation
  ``K_child = K + IL*G`` for random keys and indices.

The second check is the important one: it compares two different algorithms
(scalar arithmetic versus point addition) and would catch a wrong HMAC payload,
a swapped chain code, or a mis-serialized child.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import pytest

from binarycryptolab.base58 import b58encode
from binarycryptolab.ecc import CURVE_ORDER, public_key_from_private
from binarycryptolab.exceptions import AddressEncodingError, InputValidationError
from binarycryptolab.hashing import double_sha256, hash160
from binarycryptolab.hd_keys import (
    EXTENDED_KEY_VERSIONS,
    ExtendedPublicKey,
    derive_address,
    derive_child,
    derive_path,
    match_address,
    parse_extended_public_key,
    parse_path,
)

#: BIP-32 test vector 1, seed 000102030405060708090a0b0c0d0e0f.
VECTOR_M = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
VECTOR_M_0H = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
VECTOR_M_0H_1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"


def serialize(version: str, depth: int, fingerprint: str, child: int, chain: str, key: str) -> str:
    """Serialize an extended key, for building test fixtures."""
    body = (
        bytes.fromhex(version)
        + bytes([depth])
        + bytes.fromhex(fingerprint)
        + child.to_bytes(4, "big")
        + bytes.fromhex(chain)
        + bytes.fromhex(key)
    )
    return b58encode(body + double_sha256(body)[:4])


def private_child(k: int, chain: str, index: int) -> tuple[int, str]:
    """Derive a child from the private side, independently of the module."""
    if index >= 0x80000000:
        payload = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        payload = bytes.fromhex(public_key_from_private(k).compressed_hex) + index.to_bytes(
            4, "big"
        )
    digest = hmac.new(bytes.fromhex(chain), payload, hashlib.sha512).digest()
    return (int.from_bytes(digest[:32], "big") + k) % CURVE_ORDER, digest[32:].hex()


class TestParsing:
    """Validation of the 82-byte structure."""

    def test_vector_parses(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        assert key.label == "xpub"
        assert key.network == "mainnet"
        assert key.script_type == "p2pkh"
        assert key.depth == 0
        assert key.child_number == 0
        assert key.parent_fingerprint == "00000000"
        assert len(key.chain_code) == 64

    def test_vector_m_0h_depth_and_child(self) -> None:
        key = parse_extended_public_key(VECTOR_M_0H)
        assert key.depth == 1
        assert key.child_number == 0x80000000

    def test_fingerprint_matches_hash160_prefix(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        assert key.fingerprint == hash160(bytes.fromhex(key.public_key_hex))[:4].hex()

    def test_whitespace_is_ignored(self) -> None:
        spaced = VECTOR_M[:20] + " " + VECTOR_M[20:]
        assert parse_extended_public_key(spaced).text == VECTOR_M

    def test_private_key_is_refused_without_echo(self) -> None:
        xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        with pytest.raises(InputValidationError) as excinfo:
            parse_extended_public_key(xprv)
        assert xprv not in str(excinfo.value)
        assert "private" in str(excinfo.value)

    def test_bad_checksum(self) -> None:
        with pytest.raises(AddressEncodingError, match="checksum"):
            parse_extended_public_key(VECTOR_M[:-1] + "x")

    def test_wrong_length(self) -> None:
        with pytest.raises(AddressEncodingError):
            parse_extended_public_key("1111111111111111111114oLvT2")

    def test_not_base58(self) -> None:
        with pytest.raises(AddressEncodingError):
            parse_extended_public_key("0OIl" * 30)

    def test_empty(self) -> None:
        with pytest.raises(InputValidationError):
            parse_extended_public_key("  ")

    def test_depth_zero_must_have_zero_parent(self) -> None:
        broken = serialize("0488b21e", 0, "deadbeef", 0, "11" * 32, "02" + "22" * 32)
        with pytest.raises(AddressEncodingError, match="depth-0"):
            parse_extended_public_key(broken)

    def test_uncompressed_key_is_rejected(self) -> None:
        broken = serialize("0488b21e", 0, "00000000", 0, "11" * 32, "04" + "22" * 32)
        with pytest.raises(AddressEncodingError):
            parse_extended_public_key(broken)

    def test_unknown_version(self) -> None:
        broken = serialize("01020304", 0, "00000000", 0, "11" * 32, "02" + "22" * 32)
        with pytest.raises(AddressEncodingError, match="unsupported"):
            parse_extended_public_key(broken)

    def test_version_table_is_documented(self) -> None:
        labels = {label for label, *_ in EXTENDED_KEY_VERSIONS}
        assert {"xpub", "ypub", "zpub", "tpub", "upub", "vpub"} <= labels

    def test_as_dict(self) -> None:
        payload = parse_extended_public_key(VECTOR_M).as_dict()
        assert payload["label"] == "xpub"
        assert payload["multisig"] is False
        assert len(payload["notes"]) == 2


class TestDerivation:
    """Published vectors, then private-versus-public agreement."""

    def test_vector_m_0h_1(self) -> None:
        parent = parse_extended_public_key(VECTOR_M_0H)
        assert derive_child(parent, 1).text == VECTOR_M_0H_1

    def test_two_steps_match_one_path(self) -> None:
        from_one = derive_child(derive_child(parse_extended_public_key(VECTOR_M_0H), 1), 0)
        from_path = derive_path(parse_extended_public_key(VECTOR_M_0H), "m/1/0")
        assert from_one.text == from_path.text

    def test_child_chain_code_and_parent_link(self) -> None:
        parent = parse_extended_public_key(VECTOR_M_0H)
        child = derive_child(parent, 1)
        assert child.chain_code != parent.chain_code
        assert child.parent_fingerprint == parent.fingerprint
        assert child.child_number == 1

    def test_random_agreement_with_private_derivation(self) -> None:
        for _ in range(10):
            k = secrets.randbelow(CURVE_ORDER - 1) + 1
            chain = secrets.token_hex(32)
            public = public_key_from_private(k).compressed_hex
            node = parse_extended_public_key(serialize("0488b21e", 0, "00000000", 0, chain, public))
            for index in (0, 1, 7, 12345):
                expected_k, expected_chain = private_child(k, chain, index)
                expected_public = public_key_from_private(expected_k).compressed_hex
                expected = serialize(
                    "0488b21e",
                    1,
                    hash160(bytes.fromhex(public))[:4].hex(),
                    index,
                    expected_chain,
                    expected_public,
                )
                assert derive_child(node, index).text == expected

    def test_hardened_index_is_refused(self) -> None:
        parent = parse_extended_public_key(VECTOR_M_0H)
        with pytest.raises(InputValidationError, match="hardened"):
            derive_child(parent, 0x80000000)

    def test_negative_index_is_refused(self) -> None:
        with pytest.raises(InputValidationError):
            derive_child(parse_extended_public_key(VECTOR_M_0H), -1)

    def test_depth_increases(self) -> None:
        parent = parse_extended_public_key(VECTOR_M_0H)
        assert derive_child(parent, 1).depth == parent.depth + 1


class TestPaths:
    """Path parsing."""

    def test_plain_path(self) -> None:
        assert parse_path("m/0/5") == (0, 5)

    def test_no_prefix(self) -> None:
        assert parse_path("0/5") == (0, 5)

    def test_bare_m(self) -> None:
        assert parse_path("m") == ()

    def test_hardened_component(self) -> None:
        with pytest.raises(InputValidationError, match="hardened"):
            parse_path("m/0'/1")

    def test_non_numeric(self) -> None:
        with pytest.raises(InputValidationError):
            parse_path("m/zero")

    def test_empty_component(self) -> None:
        with pytest.raises(InputValidationError):
            parse_path("m//1")

    def test_out_of_range(self) -> None:
        with pytest.raises(InputValidationError):
            parse_path(f"m/{2**31}")


class TestAddresses:
    """Address encoding and version semantics."""

    def test_xpub_gives_p2pkh(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        address = derive_address(key, 0)
        assert address.startswith("1")

    def test_zpub_gives_p2wpkh(self) -> None:
        # Same key material, re-serialized under the zpub version.
        key = parse_extended_public_key(VECTOR_M)
        zpub = serialize("04b24746", 0, "00000000", 0, key.chain_code, key.public_key_hex)
        assert derive_address(parse_extended_public_key(zpub), 0).startswith("bc1q")

    def test_ypub_gives_nested_segwit(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        ypub = serialize("049d7cb2", 0, "00000000", 0, key.chain_code, key.public_key_hex)
        assert derive_address(parse_extended_public_key(ypub), 0).startswith("3")

    def test_vpub_is_testnet(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        vpub = serialize("045f1cf6", 0, "00000000", 0, key.chain_code, key.public_key_hex)
        assert derive_address(parse_extended_public_key(vpub), 0).startswith("tb1q")

    def test_multisig_version_is_refused(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        y_pub = serialize("0295b43f", 0, "00000000", 0, key.chain_code, key.public_key_hex)
        parsed = parse_extended_public_key(y_pub)
        assert parsed.multisig is True
        with pytest.raises(InputValidationError, match="multisig"):
            derive_address(parsed, 0)

    def test_different_indices_give_different_addresses(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        addresses = {derive_address(key, index) for index in range(5)}
        assert len(addresses) == 5

    def test_path_and_index_compose(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        assert derive_address(key, path="m/0/1") == derive_address(derive_child(key, 0), 1)
        assert derive_address(key, index=2) == derive_address(key, path="m/2")


class TestMatching:
    """Searching a key tree for an address."""

    def test_finds_a_known_child(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        target = derive_address(key, 7)
        result = match_address(key, target, start=0, count=20)
        assert result.matched is True
        assert result.matched_index == 7
        assert result.matched_path == "m/7"
        assert "belongs to this extended key" in result.verdict
        assert len(result.sample) == 5

    def test_reports_a_miss_honestly(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        result = match_address(key, "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb", count=5)
        assert result.matched is False
        assert "does not prove" in result.verdict
        assert result.checked == 5

    def test_respects_start(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        target = derive_address(key, 3)
        assert match_address(key, target, start=3, count=5).matched_index == 3
        assert match_address(key, target, start=4, count=5).matched is False

    def test_gap_limit_stops_early(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        result = match_address(key, "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb", count=50, gap_limit=5)
        assert result.checked == 5

    def test_as_dict(self) -> None:
        key = parse_extended_public_key(VECTOR_M)
        payload = match_address(key, derive_address(key, 1), count=5).as_dict()
        assert payload["matched"] is True
        assert payload["matched_index"] == 1
        assert payload["notes"]

    @pytest.mark.parametrize("count", [0, -3, 10_001])
    def test_invalid_count(self, count: int) -> None:
        with pytest.raises(InputValidationError):
            match_address(parse_extended_public_key(VECTOR_M), "x", count=count)

    def test_invalid_start(self) -> None:
        with pytest.raises(InputValidationError):
            match_address(parse_extended_public_key(VECTOR_M), "x", start=-1)

    def test_invalid_gap(self) -> None:
        with pytest.raises(InputValidationError):
            match_address(parse_extended_public_key(VECTOR_M), "x", gap_limit=0)


class TestConsistency:
    """Invariants that must hold for any key."""

    def test_child_round_trips_through_serialization(self) -> None:
        parent = parse_extended_public_key(VECTOR_M_0H)
        child = derive_child(parent, 5)
        reparsed = parse_extended_public_key(child.text)
        assert reparsed.chain_code == child.chain_code
        assert reparsed.public_key_hex == child.public_key_hex
        assert reparsed.depth == child.depth

    def test_public_key_is_a_real_point(self) -> None:
        from binarycryptolab.curve_arithmetic import decode_public_key

        key = parse_extended_public_key(VECTOR_M)
        assert decode_public_key(key.public_key_hex) is not None

    def test_type_annotation_is_honest(self) -> None:
        assert isinstance(parse_extended_public_key(VECTOR_M), ExtendedPublicKey)
