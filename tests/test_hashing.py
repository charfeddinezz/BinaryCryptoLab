"""Tests for hashing, using published test vectors.

Vectors come from FIPS 180-4 (SHA-2), the RIPEMD-160 specification, and the
Bitcoin ``hash256``/``HASH160`` constructions.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from binarycryptolab.exceptions import (
    InputValidationError,
    InvalidHexError,
    UnsupportedHashError,
)
from binarycryptolab.hashing import (
    HashAlgorithm,
    double_sha256,
    hash160,
    hash_bytes,
    hash_hex,
    hash_of_hex_input,
    ripemd160,
    ripemd160_available,
    sha256,
    sha512,
    supported_algorithms,
)

SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SHA512_ABC = (
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
)
DOUBLE_SHA256_EMPTY = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
DOUBLE_SHA256_HELLO = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
RIPEMD160_EMPTY = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
RIPEMD160_ABC = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
HASH160_EMPTY = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"


class TestSha:
    def test_sha256_vectors(self) -> None:
        assert sha256(b"").hex() == SHA256_EMPTY
        assert sha256(b"abc").hex() == SHA256_ABC
        assert len(sha256(b"abc")) == 32

    def test_sha512_vector(self) -> None:
        assert sha512(b"abc").hex() == SHA512_ABC
        assert len(sha512(b"abc")) == 64

    def test_double_sha256_vectors(self) -> None:
        assert double_sha256(b"").hex() == DOUBLE_SHA256_EMPTY
        assert double_sha256(b"hello").hex() == DOUBLE_SHA256_HELLO

    def test_double_sha256_is_not_single_sha256(self) -> None:
        assert double_sha256(b"abc") != sha256(b"abc")


@pytest.mark.skipif(not ripemd160_available(), reason="backend lacks RIPEMD-160")
class TestRipemd160:
    def test_vectors(self) -> None:
        assert ripemd160(b"").hex() == RIPEMD160_EMPTY
        assert ripemd160(b"abc").hex() == RIPEMD160_ABC
        assert len(ripemd160(b"abc")) == 20

    def test_hash160_vectors(self) -> None:
        assert hash160(b"").hex() == HASH160_EMPTY
        assert hash160(b"abc").hex() == ripemd160(sha256(b"abc")).hex()


class TestDigestObjects:
    def test_hash_bytes(self) -> None:
        digest = hash_bytes(b"abc", "sha256")
        assert isinstance(digest.algorithm, HashAlgorithm)
        assert digest.algorithm is HashAlgorithm.SHA256
        assert digest.digest.hex() == SHA256_ABC
        assert digest.hexdigest == SHA256_ABC
        assert digest.input_length == 3
        assert digest.digest_length == 32
        assert digest.as_dict()["algorithm"] == "sha256"
        assert digest.as_dict()["hexdigest"] == SHA256_ABC

    def test_hash_hex(self) -> None:
        assert hash_hex(b"abc", "sha256") == SHA256_ABC
        assert hash_hex(b"abc", HashAlgorithm.SHA256) == SHA256_ABC

    def test_hash_of_hex_input(self) -> None:
        result = hash_of_hex_input("2D", "sha256")
        assert result.digest == sha256(b"\x2d")
        assert result.input_length == 1
        assert hash_of_hex_input("0x2d", "sha256").hexdigest == result.hexdigest

    def test_hash_of_hex_input_odd(self) -> None:
        assert hash_of_hex_input("abc", "sha256").digest == sha256(b"\x0a\xbc")
        with pytest.raises(InvalidHexError):
            hash_of_hex_input("abc", "sha256", allow_odd=False)

    def test_invalid_hex(self) -> None:
        with pytest.raises(InvalidHexError):
            hash_of_hex_input("zz", "sha256")

    def test_input_types(self) -> None:
        assert hash_bytes(bytearray(b"abc"), "sha256").digest == sha256(b"abc")
        assert hash_bytes(memoryview(b"abc"), "sha256").digest == sha256(b"abc")
        with pytest.raises(InputValidationError):
            hash_bytes("abc", "sha256")  # type: ignore[arg-type]


class TestAlgorithmParsing:
    @pytest.mark.parametrize(
        ("alias", "expected"),
        [
            ("sha256", HashAlgorithm.SHA256),
            ("SHA-256", HashAlgorithm.SHA256),
            ("sha512", HashAlgorithm.SHA512),
            ("sha256d", HashAlgorithm.DOUBLE_SHA256),
            ("hash256", HashAlgorithm.DOUBLE_SHA256),
            ("double-sha256", HashAlgorithm.DOUBLE_SHA256),
            ("ripemd160", HashAlgorithm.RIPEMD160),
            ("hash160", HashAlgorithm.HASH160),
            (HashAlgorithm.SHA256, HashAlgorithm.SHA256),
        ],
    )
    def test_aliases(self, alias: str | HashAlgorithm, expected: HashAlgorithm) -> None:
        assert HashAlgorithm.parse(alias) is expected

    @pytest.mark.parametrize("alias", ["md5", "sha1", "", "sha-3"])
    def test_unknown_algorithms(self, alias: str) -> None:
        with pytest.raises(UnsupportedHashError, match="unknown hash algorithm"):
            HashAlgorithm.parse(alias)

    def test_parse_non_string(self) -> None:
        with pytest.raises(UnsupportedHashError):
            HashAlgorithm.parse(123)  # type: ignore[arg-type]

    def test_supported_algorithms(self) -> None:
        supported = supported_algorithms()
        assert HashAlgorithm.SHA256 in supported
        assert HashAlgorithm.SHA512 in supported
        assert HashAlgorithm.DOUBLE_SHA256 in supported


class TestMissingBackend:
    def test_ripemd_missing_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(hashlib, "algorithms_available", {"sha256", "sha512"})
        assert not ripemd160_available()

    def test_ripemd_missing_raises_instead_of_substituting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hashlib, "algorithms_available", {"sha256", "sha512"})
        with pytest.raises(UnsupportedHashError, match="RIPEMD-160"):
            ripemd160(b"abc")
        with pytest.raises(UnsupportedHashError):
            hash160(b"abc")
        with pytest.raises(UnsupportedHashError):
            hash_bytes(b"abc", "ripemd160")

    def test_backend_probe_failure_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(hashlib, "algorithms_available", {"ripemd160"})

        def broken_new(name: str, data: bytes = b"") -> object:
            raise ValueError("backend broken")

        monkeypatch.setattr(hashlib, "new", broken_new)
        assert not ripemd160_available()


class TestProperties:
    @settings(max_examples=25, deadline=None)
    @given(st.binary(min_size=0, max_size=128))
    def test_digest_lengths(self, data: bytes) -> None:
        assert len(sha256(data)) == 32
        assert len(sha512(data)) == 64
        assert len(double_sha256(data)) == 32
        if ripemd160_available():
            assert len(ripemd160(data)) == 20
            assert len(hash160(data)) == 20

    @settings(max_examples=25, deadline=None)
    @given(st.binary(min_size=0, max_size=128))
    def test_deterministic(self, data: bytes) -> None:
        assert sha256(data) == sha256(data)
        assert double_sha256(data) == double_sha256(data)
