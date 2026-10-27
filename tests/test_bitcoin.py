"""Bitcoin address derivation and decoding tests.

Vectors are public: BIP-173/350 examples, the Bitcoin wiki address example,
and deterministic derivations from the generator point.
"""

from __future__ import annotations

import pytest

from binarycryptolab.base58 import base58check_encode
from binarycryptolab.bitcoin import (
    AddressType,
    Network,
    address_from_public_key,
    address_matrix,
    decode_address,
    derive_p2pkh_address,
    derive_p2sh_p2wpkh_address,
    derive_p2wpkh_address,
    hash160_public_key,
    is_valid_address,
    p2pkh_address_from_hash160,
    p2sh_address_from_script_hash,
    p2wpkh_address_from_hash160,
)
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.exceptions import (
    AddressEncodingError,
    InputValidationError,
    InvalidPublicKeyError,
)
from tests.vectors import (
    ADDRESS_P2PKH_G,
    ADDRESS_P2WPKH_G,
    HASH160_OF_G,
    PUBKEY_ONE_COMPRESSED,
    PUBKEY_ONE_UNCOMPRESSED,
    WIKI_ADDRESS_MAINNET,
    WIKI_PRIVATE_KEY,
    WIKI_PUBKEY_UNCOMPRESSED,
)

ADDRESS_P2PKH_G_UNCOMPRESSED = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
ADDRESS_P2PKH_G_TESTNET = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"
ADDRESS_P2WPKH_G_TESTNET = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
ADDRESS_P2WPKH_G_REGTEST = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


class TestNetworks:
    def test_parameters(self) -> None:
        assert Network.MAINNET.p2pkh_version == 0x00
        assert Network.MAINNET.p2sh_version == 0x05
        assert Network.MAINNET.bech32_hrp == "bc"
        assert Network.TESTNET.p2pkh_version == 0x6F
        assert Network.TESTNET.bech32_hrp == "tb"
        assert Network.REGTEST.bech32_hrp == "bcrt"
        assert Network.SIGNET.bech32_hrp == "tb"

    def test_parse(self) -> None:
        assert Network.parse("MAINNET") is Network.MAINNET
        assert Network.parse(Network.REGTEST) is Network.REGTEST
        with pytest.raises(AddressEncodingError):
            Network.parse("lightning")
        with pytest.raises(AddressEncodingError):
            Network.parse(1)  # type: ignore[arg-type]

    def test_address_type_parse(self) -> None:
        assert AddressType.parse("p2pkh") is AddressType.P2PKH
        assert AddressType.parse("legacy") is AddressType.P2PKH
        assert AddressType.parse("segwit") is AddressType.P2WPKH
        assert AddressType.parse("P2WPKH") is AddressType.P2WPKH
        with pytest.raises(AddressEncodingError):
            AddressType.parse("p2tr")


class TestDerivation:
    def test_p2pkh_compressed(self) -> None:
        info = derive_p2pkh_address(PUBKEY_ONE_COMPRESSED)
        assert info.address == ADDRESS_P2PKH_G
        assert info.address_type == "p2pkh"
        assert info.network == "mainnet"
        assert info.hash160_hex == HASH160_OF_G
        assert info.public_key_encoding == "compressed"
        assert info.script_pubkey_hex == f"76a914{HASH160_OF_G}88ac"
        assert info.witness_version is None

    def test_p2pkh_uncompressed(self) -> None:
        info = derive_p2pkh_address(PUBKEY_ONE_UNCOMPRESSED)
        assert info.address == ADDRESS_P2PKH_G_UNCOMPRESSED
        assert info.public_key_encoding == "uncompressed"
        assert info.hash160_hex != HASH160_OF_G

    def test_p2wpkh_compressed(self) -> None:
        info = derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        assert info.address == ADDRESS_P2WPKH_G
        assert info.witness_version == 0
        assert info.witness_program_hex == HASH160_OF_G
        assert info.script_pubkey_hex == f"0014{HASH160_OF_G}"

    def test_p2wpkh_requires_compressed_key(self) -> None:
        with pytest.raises(AddressEncodingError, match="compressed"):
            derive_p2wpkh_address(PUBKEY_ONE_UNCOMPRESSED)

    def test_networks_produce_different_addresses(self) -> None:
        assert (
            derive_p2pkh_address(PUBKEY_ONE_COMPRESSED, "mainnet").address
            != derive_p2pkh_address(PUBKEY_ONE_COMPRESSED, "testnet").address
        )
        assert derive_p2pkh_address(PUBKEY_ONE_COMPRESSED, "testnet").address == (
            ADDRESS_P2PKH_G_TESTNET
        )
        assert derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "testnet").address == (
            ADDRESS_P2WPKH_G_TESTNET
        )
        assert derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "regtest").address == (
            ADDRESS_P2WPKH_G_REGTEST
        )
        assert derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "signet").address.startswith("tb1")

    def test_public_key_forms_give_same_compressed_address(self) -> None:
        # Parsing the uncompressed form but forcing the compressed payload is
        # what P2WPKH does; P2PKH keeps the supplied encoding.
        from binarycryptolab.ecc import parse_public_key_hex, public_key_bytes

        key = parse_public_key_hex(PUBKEY_ONE_UNCOMPRESSED)
        digest = hash160_public_key(PUBKEY_ONE_COMPRESSED)
        assert digest == bytes.fromhex(HASH160_OF_G)
        assert public_key_bytes(key, compressed=False) == bytes.fromhex(PUBKEY_ONE_UNCOMPRESSED)

    def test_hash160_of_uncompressed_is_different(self) -> None:
        assert hash160_public_key(PUBKEY_ONE_UNCOMPRESSED) != bytes.fromhex(HASH160_OF_G)

    def test_wiki_vector(self) -> None:
        info = derive_p2pkh_address(WIKI_PUBKEY_UNCOMPRESSED)
        assert info.address == WIKI_ADDRESS_MAINNET
        # The same scalar produces the same public key and address.
        derived = public_key_from_private(WIKI_PRIVATE_KEY)
        assert derived.uncompressed_hex == WIKI_PUBKEY_UNCOMPRESSED.lower()
        assert derive_p2pkh_address(derived.uncompressed_hex).address == WIKI_ADDRESS_MAINNET

    def test_address_from_public_key_dispatch(self) -> None:
        assert address_from_public_key(PUBKEY_ONE_COMPRESSED, address_type="p2pkh").address == (
            ADDRESS_P2PKH_G
        )
        assert (
            address_from_public_key(
                PUBKEY_ONE_COMPRESSED, address_type="segwit", network="testnet"
            ).address
            == ADDRESS_P2WPKH_G_TESTNET
        )

    def test_invalid_public_key(self) -> None:
        with pytest.raises(InvalidPublicKeyError):
            derive_p2pkh_address("00")

    def test_invalid_network(self) -> None:
        with pytest.raises(AddressEncodingError):
            derive_p2pkh_address(PUBKEY_ONE_COMPRESSED, "moon")

    def test_hash160_helpers(self) -> None:
        digest = bytes.fromhex(HASH160_OF_G)
        assert p2pkh_address_from_hash160(digest, "mainnet") == ADDRESS_P2PKH_G
        assert p2wpkh_address_from_hash160(digest, "mainnet") == ADDRESS_P2WPKH_G
        with pytest.raises(AddressEncodingError):
            p2pkh_address_from_hash160(b"\x00" * 19, "mainnet")
        with pytest.raises(AddressEncodingError):
            p2wpkh_address_from_hash160(b"\x00" * 32, "mainnet")
        with pytest.raises(AddressEncodingError):
            p2pkh_address_from_hash160("00" * 20, "mainnet")  # type: ignore[arg-type]

    def test_result_has_no_private_material(self) -> None:
        payload = derive_p2pkh_address(PUBKEY_ONE_COMPRESSED).as_dict()
        assert not any("private" in key for key in payload)
        assert payload["address"] == ADDRESS_P2PKH_G
        assert payload["notes"]


class TestNestedSegwit:
    """P2SH-P2WPKH derivation and the full address matrix."""

    def test_known_mainnet_address(self) -> None:
        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        assert info.address == "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        assert info.address_type == "p2sh-p2wpkh"
        assert info.public_key_encoding == "compressed"
        assert info.witness_version == 0
        assert info.witness_program_hex == HASH160_OF_G
        assert info.hash160_hex != HASH160_OF_G  # this is the redeem-script hash

    def test_script_pubkey_shape(self) -> None:
        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        assert info.script_pubkey_hex == f"a914{info.hash160_hex}87"
        assert len(info.script_pubkey_hex) == 46

    def test_redeem_script_hash_is_hash160_of_the_witness_program(self) -> None:
        from binarycryptolab.hashing import hash160

        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        redeem = b"\x00\x14" + bytes.fromhex(info.witness_program_hex or "")
        assert redeem == b"\x00\x14" + bytes.fromhex(HASH160_OF_G)
        assert hash160(redeem).hex() == info.hash160_hex

    def test_requires_compressed_key(self) -> None:
        with pytest.raises(AddressEncodingError, match="compressed"):
            derive_p2sh_p2wpkh_address(PUBKEY_ONE_UNCOMPRESSED)

    def test_networks(self) -> None:
        assert (
            derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "testnet").address
            == "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN"
        )
        mainnet = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "mainnet").address
        testnet = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED, "testnet").address
        assert mainnet.startswith("3") and testnet.startswith("2")

    def test_dispatch_through_address_from_public_key(self) -> None:
        for alias in ("p2sh-p2wpkh", "nested-segwit", "nested"):
            info = address_from_public_key(PUBKEY_ONE_COMPRESSED, address_type=alias)
            assert info.address == "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"

    def test_decodes_as_p2sh(self) -> None:
        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        decoded = decode_address(info.address)
        assert decoded.address_type == "p2sh"
        assert decoded.payload_hex == info.hash160_hex
        assert decoded.network == "mainnet"

    def test_p2sh_address_from_script_hash(self) -> None:
        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        rebuilt = p2sh_address_from_script_hash(bytes.fromhex(info.hash160_hex), "mainnet")
        assert rebuilt == info.address
        with pytest.raises(AddressEncodingError):
            p2sh_address_from_script_hash(b"\x00" * 19, "mainnet")
        with pytest.raises(AddressEncodingError):
            p2sh_address_from_script_hash("00" * 20, "mainnet")  # type: ignore[arg-type]

    def test_matrix_covers_every_combination(self) -> None:
        matrix = address_matrix(PUBKEY_ONE_COMPRESSED)
        assert len(matrix) == 16
        combinations = {
            (entry.network, entry.address_type, entry.public_key_encoding) for entry in matrix
        }
        assert len(combinations) == 16
        assert {entry.address_type for entry in matrix} == {"p2pkh", "p2wpkh", "p2sh-p2wpkh"}

    def test_matrix_addresses_are_all_valid(self) -> None:
        for entry in address_matrix(PUBKEY_ONE_COMPRESSED):
            decoded = decode_address(entry.address, entry.network)
            assert decoded.payload_hex == entry.hash160_hex

    def test_matrix_network_subset(self) -> None:
        matrix = address_matrix(PUBKEY_ONE_COMPRESSED, networks=("testnet",))
        assert len(matrix) == 4
        assert {entry.network for entry in matrix} == {"testnet"}

    def test_matrix_rejects_invalid_key(self) -> None:
        with pytest.raises(InvalidPublicKeyError):
            address_matrix("02")


class TestDecoding:
    def test_p2pkh_mainnet(self) -> None:
        decoded = decode_address(ADDRESS_P2PKH_G)
        assert decoded.address_type == "p2pkh"
        assert decoded.network == "mainnet"
        assert not decoded.network_ambiguous
        assert decoded.payload_hex == HASH160_OF_G

    def test_p2pkh_testnet_is_ambiguous(self) -> None:
        decoded = decode_address(ADDRESS_P2PKH_G_TESTNET)
        assert decoded.address_type == "p2pkh"
        assert decoded.network == "testnet"
        assert decoded.network_ambiguous

    def test_expected_network_must_match(self) -> None:
        with pytest.raises(AddressEncodingError, match="does not match"):
            decode_address(ADDRESS_P2PKH_G, "testnet")

    def test_bech32_mainnet(self) -> None:
        decoded = decode_address(ADDRESS_P2WPKH_G)
        assert decoded.address_type == "p2wpkh"
        assert decoded.network == "mainnet"
        assert decoded.witness_version == 0
        assert decoded.payload_hex == HASH160_OF_G

    def test_bech32_wrong_network(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address(ADDRESS_P2WPKH_G, "testnet")

    def test_p2wsh_is_recognized(self) -> None:
        decoded = decode_address("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        assert decoded.address_type == "p2wsh"
        assert decoded.network == "testnet"

    def test_taproot_style_is_recognized(self) -> None:
        decoded = decode_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
        assert decoded.address_type == "witness_v1"
        assert decoded.witness_version == 1

    def test_p2sh_is_decoded_but_not_derived(self) -> None:
        address = base58check_encode(b"\x05" + b"\x11" * 20)
        decoded = decode_address(address)
        assert decoded.address_type == "p2sh"
        assert decoded.network == "mainnet"
        assert decoded.payload_hex == "11" * 20

    def test_unknown_version_byte(self) -> None:
        address = base58check_encode(b"\x30" + b"\x11" * 20)
        with pytest.raises(AddressEncodingError, match="version byte"):
            decode_address(address)

    def test_bad_checksum(self) -> None:
        tampered = ADDRESS_P2PKH_G[:-1] + ("2" if ADDRESS_P2PKH_G[-1] != "2" else "3")
        with pytest.raises(AddressEncodingError, match="Base58Check"):
            decode_address(tampered)

    def test_bad_bech32_checksum(self) -> None:
        tampered = ADDRESS_P2WPKH_G[:-1] + ("q" if ADDRESS_P2WPKH_G[-1] != "q" else "p")
        with pytest.raises(AddressEncodingError, match="Bech32"):
            decode_address(tampered)

    def test_mixed_case_bech32(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address("bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def test_uppercase_bech32_is_accepted(self) -> None:
        assert decode_address(ADDRESS_P2WPKH_G.upper()).payload_hex == HASH160_OF_G

    def test_wrong_hrp_for_expected_network(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address(ADDRESS_P2WPKH_G, "regtest")

    def test_empty_address(self) -> None:
        with pytest.raises(InputValidationError):
            decode_address("")
        with pytest.raises(InputValidationError):
            decode_address("   ")
        with pytest.raises(InputValidationError):
            decode_address(123)  # type: ignore[arg-type]

    def test_too_short_payload(self) -> None:
        address = base58check_encode(b"\x00" + b"\x11" * 10)
        with pytest.raises(AddressEncodingError, match="21 bytes"):
            decode_address(address)

    def test_is_valid_predicate(self) -> None:
        assert is_valid_address(ADDRESS_P2PKH_G)
        assert is_valid_address(ADDRESS_P2WPKH_G)
        assert not is_valid_address("not an address")
        assert not is_valid_address("")
        assert is_valid_address(ADDRESS_P2PKH_G_TESTNET, "testnet")
        assert not is_valid_address(ADDRESS_P2PKH_G_TESTNET, "mainnet")

    def test_decoded_as_dict(self) -> None:
        payload = decode_address(ADDRESS_P2WPKH_G).as_dict()
        assert payload["type"] == "p2wpkh"
        assert payload["witness_version"] == 0
        assert payload["payload_hex"] == HASH160_OF_G


class TestAddressRoundTrip:
    @pytest.mark.parametrize("network", ["mainnet", "testnet", "regtest", "signet"])
    @pytest.mark.parametrize("address_type", ["p2pkh", "p2wpkh"])
    def test_derive_then_decode(self, network: str, address_type: str) -> None:
        info = address_from_public_key(
            PUBKEY_ONE_COMPRESSED, address_type=address_type, network=network
        )
        decoded = decode_address(info.address, network)
        assert decoded.payload_hex == info.hash160_hex
        assert decoded.address_type == info.address_type
        assert decoded.witness_version == info.witness_version

    def test_signature_of_known_vectors(self) -> None:
        # Guard against accidental changes to the derived addresses.
        assert derive_p2pkh_address(PUBKEY_ONE_COMPRESSED).address == ADDRESS_P2PKH_G
        assert derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED).address == ADDRESS_P2WPKH_G
        with pytest.raises(AddressEncodingError):
            decode_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
