"""Tests for Base58 and Base58Check encoding."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.base58 import (
    B58_ALPHABET,
    b58decode,
    b58encode,
    base58check_decode,
    base58check_encode,
    base58check_verify,
)
from binarycryptolab.exceptions import (
    Base58Error,
    InputValidationError,
    InvalidBase58Error,
)


class TestBase58:
    @pytest.mark.parametrize(
        ("data", "encoded"),
        [
            (b"", ""),
            (b"\x00", "1"),
            (b"\x00\x00\x01", "112"),
            (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
            (b"\x00\x00\x00", "111"),
        ],
    )
    def test_known_vectors(self, data: bytes, encoded: str) -> None:
        assert b58encode(data) == encoded
        if encoded:
            assert b58decode(encoded) == data

    def test_alphabet_excludes_ambiguous_characters(self) -> None:
        for char in "0OIl":
            assert char not in B58_ALPHABET
        assert len(B58_ALPHABET) == 58
        assert len(set(B58_ALPHABET)) == 58

    @pytest.mark.parametrize("value", ["0", "O", "I", "l", "hello!", " 1"])
    def test_invalid_characters(self, value: str) -> None:
        with pytest.raises(Base58Error):
            b58decode(value)

    def test_empty_decode_is_rejected(self) -> None:
        with pytest.raises(Base58Error, match="empty"):
            b58decode("")

    def test_non_string_decode(self) -> None:
        with pytest.raises(Base58Error, match="string"):
            b58decode(b"1")  # type: ignore[arg-type]

    def test_encode_non_bytes(self) -> None:
        with pytest.raises(InputValidationError):
            b58encode("1")  # type: ignore[arg-type]

    @settings(max_examples=100, deadline=None)
    @given(st.binary(min_size=1, max_size=64))
    def test_round_trip(self, data: bytes) -> None:
        assert b58decode(b58encode(data)) == data

    @settings(max_examples=50, deadline=None)
    @given(st.binary(min_size=1, max_size=32))
    def test_leading_zeros_round_trip(self, data: bytes) -> None:
        padded = b"\x00" * 3 + data
        assert b58decode(b58encode(padded)) == padded


class TestBase58Check:
    def test_zero_hash_vector(self) -> None:
        payload = b"\x00" * 21
        encoded = base58check_encode(payload)
        assert encoded == "1111111111111111111114oLvT2"
        assert base58check_decode(encoded) == payload

    def test_round_trip(self) -> None:
        payload = bytes(range(20))
        encoded = base58check_encode(payload)
        assert base58check_decode(encoded) == payload
        assert base58check_verify(encoded)

    def test_checksum_failure(self) -> None:
        encoded = base58check_encode(b"\x00" + b"\x01" * 20)
        tampered = encoded[:-1] + ("2" if encoded[-1] != "2" else "3")
        with pytest.raises(InvalidBase58Error, match="checksum"):
            base58check_decode(tampered)
        assert not base58check_verify(tampered)

    def test_checksum_can_be_skipped_explicitly(self) -> None:
        encoded = base58check_encode(b"\x00" + b"\x01" * 20)
        tampered = encoded[:-1] + ("2" if encoded[-1] != "2" else "3")
        assert base58check_decode(tampered, verify=False) == b"\x00" + b"\x01" * 20

    def test_too_short(self) -> None:
        with pytest.raises(InvalidBase58Error, match="too short"):
            base58check_decode("111")

    def test_empty_payload_rejected(self) -> None:
        with pytest.raises(InputValidationError, match="empty"):
            base58check_encode(b"")

    def test_verify_predicate_never_raises(self) -> None:
        assert not base58check_verify("")
        assert not base58check_verify("not-base58")
        assert not base58check_verify("111")

    @settings(max_examples=100, deadline=None)
    @given(st.binary(min_size=1, max_size=64))
    def test_round_trip_property(self, payload: bytes) -> None:
        assert base58check_decode(base58check_encode(payload)) == payload

    @settings(max_examples=50, deadline=None)
    @given(st.binary(min_size=1, max_size=64))
    def test_any_single_character_change_is_detected(self, payload: bytes) -> None:
        encoded = base58check_encode(payload)
        position = len(encoded) // 2
        replacement = "2" if encoded[position] != "2" else "3"
        tampered = encoded[:position] + replacement + encoded[position + 1 :]
        with pytest.raises(InvalidBase58Error):
            base58check_decode(tampered)
