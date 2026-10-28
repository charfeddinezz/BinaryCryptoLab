"""Tests for the offline hazard audit and the user-supplied data audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from binarycryptolab.address_formats import decode_address_input
from binarycryptolab.address_safety import (
    NUMS_POINT_HEX,
    audit_decoded_input,
    inspect_taproot_key,
)
from binarycryptolab.bech32 import encode_segwit_address
from binarycryptolab.bitcoin import derive_p2tr_address
from binarycryptolab.exceptions import AddressEncodingError, InputValidationError
from binarycryptolab.utxo_audit import MAX_SUPPLY_SATS, audit_address_data

ADDRESS = "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"
SCRIPT = "76a914ab9a4edd7600fe91d0f46a97dc851ad45c1ce17688ac"
BIP350_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"


def audit(text: str, **kwargs: object):
    """Return the safety audit for an input."""
    return audit_decoded_input(decode_address_input(text), **kwargs)  # type: ignore[arg-type]


def codes(result) -> set[str]:
    """Return the set of check codes."""
    return {check.code for check in result.checks}


class TestAuditBasics:
    """Severity, ordering, and shape."""

    def test_clean_address(self) -> None:
        result = audit(ADDRESS)
        assert result.grade == "no-known-hazard"
        assert result.unspendable is False
        assert result.anyone_can_spend is False
        assert result.safe_to_share is True
        assert "only the key holder" in result.verdict

    def test_checks_are_sorted_by_severity(self) -> None:
        order = {"critical": 0, "warning": 1, "notice": 2, "ok": 3}
        severities = [order[check.severity] for check in audit(BIP350_P2TR).checks]
        assert severities == sorted(severities)

    def test_as_dict(self) -> None:
        payload = audit(ADDRESS).as_dict()
        assert set(payload) == {
            "checks",
            "known_address",
            "taproot",
            "grade",
            "unspendable",
            "anyone_can_spend",
            "safe_to_share",
            "verdict",
            "notes",
        }
        json.dumps(payload, allow_nan=False)

    def test_critical_and_warnings_properties(self) -> None:
        result = audit("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert result.warnings
        assert all(check.severity == "warning" for check in result.warnings)
        assert result.critical == ()


class TestDocumentedAddresses:
    """The registry drives the strongest findings."""

    def test_burn_address_is_critical(self) -> None:
        result = audit("1BitcoinEaterAddressDontSendf59kuE")
        assert result.grade == "danger"
        assert result.known_address is not None
        assert result.known_address.kind == "burn"
        assert "known_burn" in codes(result)

    def test_genesis_coinbase(self) -> None:
        result = audit("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert "known_genesis" in codes(result)
        assert result.unspendable is True

    def test_null_payload_flagged_twice(self) -> None:
        result = audit("1111111111111111111114oLvT2")
        assert "known_unspendable" in codes(result)
        assert "constant_payload" in codes(result)
        assert result.unspendable is True

    def test_test_vector_is_only_a_notice(self) -> None:
        result = audit("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert "known_vector" in codes(result)
        assert result.grade == "no-known-hazard"


class TestWitnessVersions:
    """Unknown versions are open, not hard."""

    def test_version_two_is_anyone_can_spend(self) -> None:
        address = encode_segwit_address("bc", 2, bytes(range(32)))
        result = audit(address)
        assert result.anyone_can_spend is True
        assert result.grade == "danger"
        assert "unknown_witness_version" in codes(result)
        assert "Anyone can spend" in result.verdict

    def test_version_sixteen(self) -> None:
        address = encode_segwit_address("bc", 16, bytes(range(20)))
        assert audit(address).anyone_can_spend is True

    def test_version_one_with_wrong_length(self) -> None:
        address = encode_segwit_address("bc", 1, bytes(range(20)))
        result = audit(address)
        assert "malformed_taproot_program" in codes(result)
        assert result.unspendable is True


class TestTaproot:
    """Key inspection."""

    def test_valid_key(self) -> None:
        info = inspect_taproot_key(bytes.fromhex("ab" * 32))
        assert info.valid_x_coordinate in (True, False)
        assert info.is_nums_key is False

    def test_generator_key_is_valid(self) -> None:
        internal = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        address = derive_p2tr_address(internal).address
        info = inspect_taproot_key(bytes.fromhex(decode_address_input(address).payload.hex()))
        assert info.valid_x_coordinate is True
        assert info.even_y is True

    def test_nums_key_is_flagged(self) -> None:
        info = inspect_taproot_key(bytes.fromhex(NUMS_POINT_HEX))
        assert info.is_nums_key is True
        assert "unspendable by design" in info.note

    def test_nums_address_is_critical(self) -> None:
        address = encode_segwit_address("bc", 1, bytes.fromhex(NUMS_POINT_HEX))
        result = audit(address)
        assert "taproot_nums_key" in codes(result)
        assert result.grade == "danger"

    def test_off_curve_key_is_flagged(self) -> None:
        # Search for an x that is not on the curve; about half of all x values fail.
        for candidate in range(1, 20):
            payload = candidate.to_bytes(32, "big")
            info = inspect_taproot_key(payload)
            if not info.valid_x_coordinate:
                break
        else:  # pragma: no cover - astronomically unlikely
            pytest.skip("no off-curve x found in the probe range")
        address = encode_segwit_address("bc", 1, payload)
        result = audit(address)
        assert "taproot_invalid_key" in codes(result)
        assert result.unspendable is True

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ValueError):
            inspect_taproot_key(bytes(31))


class TestScriptHazards:
    """P2SH, P2WSH, P2PK, and OP_RETURN."""

    def test_p2sh_is_opaque(self) -> None:
        result = audit("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert "script_hash_opaque" in codes(result)
        assert result.grade == "review"

    def test_p2wsh_is_opaque(self) -> None:
        address = encode_segwit_address("bc", 0, bytes(range(32)))
        assert "script_hash_opaque" in codes(audit(address))

    def test_op_return(self) -> None:
        result = audit("script:6a0b68656c6c6f")
        assert "op_return_output" in codes(result)
        assert result.unspendable is True
        assert "data carrier" in result.verdict

    def test_p2pk_exposes_the_key(self) -> None:
        result = audit(
            "script:210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
        )
        assert "public_key_exposed" in codes(result)

    def test_nonstandard(self) -> None:
        result = audit("script:deadbeefcafe")
        assert "nonstandard_script" in codes(result)

    def test_script_input_is_a_notice(self) -> None:
        result = audit("script:0014" + "ab" * 20)
        assert "script_input" in codes(result)


class TestNetworkAndUri:
    """Network hazards and BIP-21 validation."""

    def test_testnet_warning(self) -> None:
        address = encode_segwit_address("tb", 0, bytes(range(20)))
        result = audit(address)
        assert "non_mainnet" in codes(result)
        assert result.grade == "review"

    def test_network_mismatch_is_reported(self) -> None:
        result = audit(ADDRESS, network_mismatch="testnet")
        assert "network_mismatch" in codes(result)

    def test_declared_prefix_is_a_notice(self) -> None:
        result = audit(ADDRESS, declared_prefix="1Ge")
        assert "declared_prefix" in codes(result)

    def test_amount_accepted(self) -> None:
        result = audit(f"bitcoin:{ADDRESS}?amount=0.001")
        check = next(item for item in result.checks if item.code == "uri_amount")
        assert check.severity == "ok"

    def test_amount_negative(self) -> None:
        result = audit(f"bitcoin:{ADDRESS}?amount=-1")
        check = next(item for item in result.checks if item.code == "uri_amount")
        assert check.severity == "critical"

    def test_amount_beyond_supply(self) -> None:
        result = audit(f"bitcoin:{ADDRESS}?amount=22000000")
        check = next(item for item in result.checks if item.code == "uri_amount")
        assert check.severity == "critical"

    def test_amount_unparsable(self) -> None:
        result = audit(f"bitcoin:{ADDRESS}?amount=abc")
        check = next(item for item in result.checks if item.code == "uri_amount")
        assert check.severity == "warning"

    def test_required_parameter_warns(self) -> None:
        result = audit(f"bitcoin:{ADDRESS}?req-foo=1")
        assert "uri_required_parameter" in codes(result)


class TestUtxoAudit:
    """The offline audit of user-supplied chain data."""

    def export(self, **overrides: object) -> dict[str, object]:
        """Return a valid export."""
        payload: dict[str, object] = {
            "address": ADDRESS,
            "source": "test fixture",
            "utxos": [
                {
                    "txid": "ab" * 32,
                    "vout": 0,
                    "value_sats": 150_000,
                    "height": 800_000,
                    "script_pubkey_hex": SCRIPT,
                },
                {"txid": "cd" * 32, "vout": 1, "value_btc": "0.00025"},
            ],
        }
        payload.update(overrides)
        return payload

    def test_totals(self) -> None:
        result = audit_address_data(ADDRESS, self.export())
        assert result.total_sats == 175_000
        assert result.confirmed_sats == 150_000
        assert result.unconfirmed_sats == 25_000
        assert result.balance_btc == "0.00175000"
        assert result.problems == ()
        assert result.trusted is False

    def test_script_mismatch_is_reported(self) -> None:
        export = self.export()
        export["utxos"][0]["script_pubkey_hex"] = "76a914" + "00" * 20 + "88ac"  # type: ignore[index]
        result = audit_address_data(ADDRESS, export)
        assert any("different script" in problem for problem in result.problems)
        assert "does not describe this address" in result.verdict

    def test_duplicate_outpoints(self) -> None:
        entry = {"txid": "ee" * 32, "vout": 3, "value_sats": 1_000}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry, dict(entry)]))
        assert result.duplicates == (f"{'ee' * 32}:3",)
        assert any("more than once" in problem for problem in result.problems)

    def test_spent_entries(self) -> None:
        entry = {"txid": "ff" * 32, "vout": 0, "value_sats": 5_000, "spent_by": "11" * 32}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert result.spent_sats == 5_000
        assert result.balance_sats == 0
        assert any("already spent" in problem for problem in result.problems)

    def test_impossible_total(self) -> None:
        entry = {"txid": "22" * 32, "vout": 0, "value_sats": MAX_SUPPLY_SATS + 1}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert any("21 million" in problem for problem in result.problems)

    def test_value_validation(self) -> None:
        entry = {"txid": "33" * 32, "vout": 0, "value_sats": -5}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert result.utxos[0].problems
        assert result.total_sats == 0

    def test_value_with_too_many_decimals(self) -> None:
        entry = {"txid": "44" * 32, "vout": 0, "value_btc": "0.000000001"}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert any("eight decimal places" in problem for problem in result.utxos[0].problems)

    def test_missing_value(self) -> None:
        entry = {"txid": "55" * 32, "vout": 0}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert any("neither value_sats nor value_btc" in p for p in result.utxos[0].problems)

    def test_bad_txid(self) -> None:
        entry = {"txid": "nothex", "vout": 0, "value_sats": 1_000}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert any("64 hexadecimal" in problem for problem in result.utxos[0].problems)

    def test_mismatched_address_in_file(self) -> None:
        result = audit_address_data(
            ADDRESS, self.export(address="1BitcoinEaterAddressDontSendf59kuE")
        )
        assert any("different address" in problem for problem in result.problems)

    def test_empty_export(self) -> None:
        result = audit_address_data(ADDRESS, self.export(utxos=[]))
        assert result.balance_sats == 0
        assert "lists no outputs" in result.verdict

    def test_source_override(self) -> None:
        result = audit_address_data(ADDRESS, self.export(), source="override")
        assert result.source == "override"

    def test_reads_a_file(self, tmp_path: Path) -> None:
        path = tmp_path / "export.json"
        path.write_text(json.dumps(self.export()), encoding="utf-8")
        result = audit_address_data(ADDRESS, path)
        assert result.total_sats == 175_000

    def test_missing_file(self, tmp_path: Path) -> None:
        from binarycryptolab.exceptions import ReportGenerationError

        with pytest.raises(ReportGenerationError):
            audit_address_data(ADDRESS, tmp_path / "absent.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(InputValidationError):
            audit_address_data(ADDRESS, path)

    def test_not_a_mapping(self) -> None:
        with pytest.raises(InputValidationError):
            audit_address_data(ADDRESS, ["not", "a", "mapping"])  # type: ignore[arg-type]

    def test_utxos_not_a_list(self) -> None:
        with pytest.raises(InputValidationError):
            audit_address_data(ADDRESS, {"utxos": {}})

    def test_entry_not_an_object(self) -> None:
        with pytest.raises(InputValidationError):
            audit_address_data(ADDRESS, {"utxos": ["entry"]})

    def test_invalid_address(self) -> None:
        with pytest.raises(AddressEncodingError):
            audit_address_data("not-an-address", {"utxos": []})

    def test_as_dict_is_strict_json(self) -> None:
        payload = audit_address_data(ADDRESS, self.export()).as_dict()
        text = json.dumps(payload, allow_nan=False)
        assert '"balance_btc": "0.00175000"' in text
        assert payload["trusted"] is False

    def test_balance_subtracts_spent_entries(self) -> None:
        entry = {"txid": "66" * 32, "vout": 0, "value_sats": 100, "spent_by": "77" * 32}
        other = {"txid": "88" * 32, "vout": 0, "value_sats": 50}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry, other]))
        assert result.balance_sats == 50

    def test_negative_balance_is_clamped(self) -> None:
        entry = {"txid": "66" * 32, "vout": 0, "value_sats": 100, "spent_by": "77" * 32}
        result = audit_address_data(ADDRESS, self.export(utxos=[entry]))
        assert result.balance_sats == 0
