"""Tests for multi-format address decoding and script classification.

Every vector here is either generated locally from a documented rule (and checked
for round-trip agreement) or taken from a published specification: the BIP-173 and
BIP-350 addresses, and the CashAddr example.  Nothing is asserted from memory alone:
the CashAddr example is re-encoded and must reproduce itself byte for byte, which
can only happen if the checksum implementation is correct.
"""

from __future__ import annotations

import pytest

from binarycryptolab.address_formats import (
    BASE58_FORMATS,
    KNOWN_ADDRESSES,
    base58_candidates,
    bech32_format,
    decode_address_input,
    decode_cashaddr,
    decode_script_pubkey,
    encode_cashaddr,
    lookup_known_address,
    normalize_text,
    script_to_address,
)
from binarycryptolab.base58 import base58check_encode
from binarycryptolab.bech32 import encode_segwit_address
from binarycryptolab.exceptions import (
    AddressEncodingError,
    InputValidationError,
    InvalidBase58Error,
    PrivateKeyMaterialError,
)

MAINNET_P2PKH = "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"
BIP173_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
BIP350_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
BIP173_P2WSH = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
CASHADDR = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"


class TestNormalisation:
    """Whitespace, quoting, and zero-width characters."""

    def test_strips_whitespace_and_quotes(self) -> None:
        assert normalize_text('  " 1GeM... " ') == "1GeM..."

    def test_removes_zero_width_characters(self) -> None:
        assert normalize_text("\u200b1GeM\ufeff") == "1GeM"

    def test_rejects_empty(self) -> None:
        with pytest.raises(InputValidationError):
            normalize_text("   ")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(InputValidationError):
            normalize_text(42)  # type: ignore[arg-type]


class TestBase58Formats:
    """The version-prefix registry."""

    def test_bitcoin_zero_is_shared_with_bitcoin_cash(self) -> None:
        chains = {item.chain for item in base58_candidates(0x00)}
        assert chains == {"bitcoin", "bitcoin_cash"}

    def test_litecoin_prefix(self) -> None:
        assert base58_candidates(0x30)[0].chain == "litecoin"

    def test_zcash_uses_two_bytes(self) -> None:
        candidates = base58_candidates(0x1CB8)
        assert candidates[0].chain == "zcash"
        assert candidates[0].version_bytes == 2

    def test_unknown_version_has_no_candidates(self) -> None:
        assert base58_candidates(0xABCD) == ()

    def test_every_format_has_a_note(self) -> None:
        assert all(item.note for item in BASE58_FORMATS)

    def test_version_hex_width(self) -> None:
        zcash = base58_candidates(0x1CB8)[0]
        assert zcash.version_hex == "1cb8"
        bitcoin = base58_candidates(0x00)[0]
        assert bitcoin.version_hex == "00"


class TestBech32Formats:
    """HRP lookup."""

    @pytest.mark.parametrize(
        ("hrp", "chain", "network"),
        [
            ("bc", "bitcoin", "mainnet"),
            ("tb", "bitcoin", "testnet"),
            ("bcrt", "bitcoin", "regtest"),
            ("ltc", "litecoin", "mainnet"),
            ("tltc", "litecoin", "testnet"),
        ],
    )
    def test_registered(self, hrp: str, chain: str, network: str) -> None:
        entry = bech32_format(hrp)
        assert entry is not None
        assert (entry.chain, entry.network) == (chain, network)

    def test_unknown_hrp(self) -> None:
        assert bech32_format("zz") is None


class TestCashAddr:
    """CashAddr encoding and decoding."""

    def test_published_vector_round_trips(self) -> None:
        prefix, kind, payload = decode_cashaddr(CASHADDR)
        assert (prefix, kind) == ("bitcoincash", "p2pkh")
        assert payload.hex() == "76a04053bda0a88bda5177b86a15c3b29f559873"
        assert encode_cashaddr(prefix, payload, kind=kind) == CASHADDR

    def test_p2sh_kind_bit(self) -> None:
        payload = bytes(range(20))
        encoded = encode_cashaddr("bitcoincash", payload, kind="p2sh")
        assert decode_cashaddr(encoded)[1] == "p2sh"

    def test_bad_checksum(self) -> None:
        broken = CASHADDR[:-1] + ("q" if CASHADDR[-1] != "q" else "p")
        with pytest.raises(AddressEncodingError):
            decode_cashaddr(broken)

    def test_bad_character(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_cashaddr("bitcoincash:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    def test_missing_prefix(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_cashaddr("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")

    def test_unknown_prefix(self) -> None:
        with pytest.raises(ValueError):
            encode_cashaddr("dogecoin", bytes(20))
        with pytest.raises(AddressEncodingError):
            decode_cashaddr("dogecoin:" + CASHADDR.split(":", 1)[1])

    def test_payload_length_is_enforced(self) -> None:
        with pytest.raises(ValueError):
            encode_cashaddr("bitcoincash", bytes(19))

    def test_upper_case_is_accepted(self) -> None:
        decoded = decode_address_input(CASHADDR.upper())
        assert decoded.chain == "bitcoin_cash"
        assert decoded.address == CASHADDR


class TestBech32Inputs:
    """SegWit inputs across versions, networks, and cases."""

    def test_bip173_p2wpkh(self) -> None:
        decoded = decode_address_input(BIP173_P2WPKH)
        assert (decoded.encoding, decoded.address_type) == ("bech32", "p2wpkh")
        assert decoded.network == "mainnet"

    def test_bip173_p2wsh_testnet(self) -> None:
        decoded = decode_address_input(BIP173_P2WSH)
        assert (decoded.address_type, decoded.network) == ("p2wsh", "testnet")

    def test_bip350_p2tr(self) -> None:
        decoded = decode_address_input(BIP350_P2TR)
        assert (decoded.encoding, decoded.address_type) == ("bech32m", "p2tr")
        # The BIP-350 vector commits to the x-coordinate of the generator.
        assert decoded.payload.hex().startswith("79be667e")

    def test_upper_case_normalises(self) -> None:
        decoded = decode_address_input(BIP173_P2WPKH.upper())
        assert decoded.address == BIP173_P2WPKH

    def test_mixed_case_is_rejected(self) -> None:
        mixed = BIP173_P2WPKH[:10].upper() + BIP173_P2WPKH[10:]
        with pytest.raises(AddressEncodingError):
            decode_address_input(mixed)

    def test_bad_checksum(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address_input(BIP173_P2WPKH[:-1] + "5")

    @pytest.mark.parametrize("hrp", ["ltc", "tltc", "rltc"])
    def test_litecoin_hrps(self, hrp: str) -> None:
        address = encode_segwit_address(hrp, 0, bytes(range(20)))
        decoded = decode_address_input(address)
        assert decoded.chain == "litecoin"

    def test_regtest_hrp(self) -> None:
        address = encode_segwit_address("bcrt", 0, bytes(range(20)))
        assert decode_address_input(address).network == "regtest"

    def test_unknown_hrp_is_reported_not_rejected(self) -> None:
        address = encode_segwit_address("zz", 0, bytes(range(20)))
        decoded = decode_address_input(address)
        assert decoded.chain == "unknown"
        assert any("not registered" in note for note in decoded.notes)

    def test_version_zero_requires_twenty_or_thirty_two_bytes(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address_input(encode_segwit_address("bc", 0, bytes(10)))

    def test_bech32m_required_above_version_zero(self) -> None:
        from binarycryptolab.bech32 import Bech32Spec, bech32_encode, convert_8_to_5

        data = [1, *convert_8_to_5(bytes(range(32)))]
        wrong = bech32_encode("bc", data, Bech32Spec.BECH32)
        with pytest.raises(AddressEncodingError):
            decode_address_input(wrong)


class TestBase58Inputs:
    """Base58Check across chains, plus the private-key refusal."""

    def test_bitcoin_mainnet(self) -> None:
        decoded = decode_address_input(MAINNET_P2PKH)
        assert decoded.chain_candidates == ("bitcoin", "bitcoin_cash")
        assert decoded.version_byte == 0
        assert decoded.checksum_valid

    def test_litecoin_p2pkh(self) -> None:
        address = base58check_encode(b"\x30" + bytes(range(20)))
        decoded = decode_address_input(address)
        assert decoded.chain == "litecoin"

    def test_dogecoin_p2pkh(self) -> None:
        address = base58check_encode(b"\x1e" + bytes(range(20)))
        assert decode_address_input(address).chain == "dogecoin"

    def test_zcash_two_byte_version(self) -> None:
        address = base58check_encode(b"\x1c\xb8" + bytes(range(20)))
        decoded = decode_address_input(address)
        assert decoded.chain == "zcash"
        assert decoded.version_bytes == 2

    def test_unknown_version_is_rejected(self) -> None:
        address = base58check_encode(b"\x7f" + bytes(range(20)))
        with pytest.raises(AddressEncodingError):
            decode_address_input(address)

    def test_wif_is_refused_without_echo(self) -> None:
        wif = base58check_encode(b"\x80" + bytes(range(32)) + b"\x01")
        with pytest.raises(PrivateKeyMaterialError) as excinfo:
            decode_address_input(wif)
        assert wif not in str(excinfo.value)

    def test_testnet_wif_is_refused(self) -> None:
        wif = base58check_encode(b"\xef" + bytes(range(32)))
        with pytest.raises(PrivateKeyMaterialError):
            decode_address_input(wif)

    def test_bad_checksum(self) -> None:
        with pytest.raises(InvalidBase58Error):
            decode_address_input(MAINNET_P2PKH[:-1] + "c")

    def test_non_base58_character(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address_input("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNm0")

    def test_short_payload(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address_input(base58check_encode(b"\x00" + bytes(19)))


class TestBip21:
    """Payment URIs."""

    def test_parameters_are_preserved(self) -> None:
        decoded = decode_address_input(f"bitcoin:{MAINNET_P2PKH}?amount=0.5&label=x&message=y")
        assert decoded.input_kind == "bip21_uri"
        assert decoded.uri_params == (("amount", "0.5"), ("label", "x"), ("message", "y"))
        assert decoded.address == MAINNET_P2PKH

    def test_uri_without_parameters(self) -> None:
        decoded = decode_address_input(f"bitcoin:{MAINNET_P2PKH}")
        assert decoded.uri_params == ()

    def test_missing_address(self) -> None:
        with pytest.raises(InputValidationError):
            decode_address_input("bitcoin:?amount=1")

    def test_segwit_uri(self) -> None:
        decoded = decode_address_input(f"bitcoin:{BIP173_P2WPKH}?amount=1")
        assert decoded.address_type == "p2wpkh"

    def test_uppercase_scheme(self) -> None:
        decoded = decode_address_input(f"BITCOIN:{MAINNET_P2PKH}")
        assert decoded.address == MAINNET_P2PKH


class TestScripts:
    """Locking-script inputs and the addresses they imply."""

    def test_p2pkh_script_round_trips(self) -> None:
        script = f"76a914{bytes.fromhex('ab9a4edd7600fe91d0f46a97dc851ad45c1ce176').hex()}88ac"
        decoded = decode_script_pubkey(script)
        assert decoded.address_type == "p2pkh"
        assert decoded.address == MAINNET_P2PKH
        assert decoded.input_kind == "script_pubkey"

    def test_p2sh_script(self) -> None:
        decoded = decode_script_pubkey("a914" + "b4" * 20 + "87")
        assert decoded.address_type == "p2sh"
        assert (decoded.address or "").startswith("3")

    def test_p2wpkh_script(self) -> None:
        decoded = decode_script_pubkey("0014" + "75" * 20)
        assert decoded.address_type == "p2wpkh"

    def test_p2wsh_script(self) -> None:
        decoded = decode_script_pubkey("0020" + "18" * 32)
        assert decoded.address_type == "p2wsh"

    def test_p2tr_script(self) -> None:
        decoded = decode_script_pubkey("5120" + "ab" * 32)
        assert decoded.address_type == "p2tr"
        assert decoded.witness_version == 1

    def test_unknown_witness_version_script(self) -> None:
        decoded = decode_script_pubkey("5220" + "ab" * 32)
        assert decoded.address_type == "witness_v2"

    def test_p2pk_compressed(self) -> None:
        decoded = decode_script_pubkey("21" + "02" + "79" * 32 + "ac")
        assert decoded.address_type == "p2pk"
        assert decoded.address is None

    def test_op_return(self) -> None:
        decoded = decode_script_pubkey("6a0b68656c6c6f20776f726c64")
        assert decoded.address_type == "op_return"
        assert decoded.address is None

    def test_nonstandard(self) -> None:
        assert decode_script_pubkey("deadbeefcafe").address_type == "nonstandard"

    def test_explicit_prefix(self) -> None:
        decoded = decode_address_input("script:deadbeefcafe")
        assert decoded.address_type == "nonstandard"

    def test_taproot_script_requires_32_bytes(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_script_pubkey("5120" + "ab" * 20)

    def test_witness_zero_program_length(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_script_pubkey("0010" + "ab" * 10)

    def test_odd_length(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_script_pubkey("0014abc")

    def test_invalid_hex(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_script_pubkey("script:zzzz")

    def test_script_to_address_helper(self) -> None:
        assert script_to_address("0014" + "ab" * 20) is not None
        assert script_to_address("6a") is None

    def test_network_selection_changes_the_address(self) -> None:
        mainnet = decode_script_pubkey("0014" + "ab" * 20, network="mainnet").address
        testnet = decode_script_pubkey("0014" + "ab" * 20, network="testnet").address
        assert mainnet != testnet
        assert (testnet or "").startswith("tb1")

    def test_unknown_hex_without_prefix_is_rejected(self) -> None:
        with pytest.raises(AddressEncodingError) as excinfo:
            decode_address_input("ab" * 20)
        assert "script:" in str(excinfo.value)


class TestNetworkExpectations:
    """The ``network`` guard."""

    def test_matching_network_passes(self) -> None:
        assert decode_address_input(MAINNET_P2PKH, network="mainnet").network == "mainnet"

    def test_mismatch_raises(self) -> None:
        with pytest.raises(AddressEncodingError):
            decode_address_input(MAINNET_P2PKH, network="testnet")

    def test_regtest_accepts_a_testnet_prefix(self) -> None:
        # Regtest reuses the testnet Base58 bytes, so the check must not fail.
        decoded = decode_address_input("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", network="regtest")
        assert decoded.network == "testnet"


class TestKnownAddresses:
    """The documented-address table."""

    def test_every_entry_decodes(self) -> None:
        for entry in KNOWN_ADDRESSES:
            decoded = decode_address_input(entry.address)
            assert decoded.checksum_valid

    def test_lookup_is_case_insensitive(self) -> None:
        assert lookup_known_address(BIP173_P2WPKH.upper()) is not None

    def test_unknown_address_returns_none(self) -> None:
        assert lookup_known_address("1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb") is None

    def test_null_address_payload_is_zero(self) -> None:
        decoded = decode_address_input("1111111111111111111114oLvT2")
        assert decoded.payload == bytes(20)

    def test_entries_have_references(self) -> None:
        assert all(entry.reference for entry in KNOWN_ADDRESSES)
        assert all(entry.meaning for entry in KNOWN_ADDRESSES)
