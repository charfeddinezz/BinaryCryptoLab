"""Tests for address dissection, prefix mathematics, and the backward-cost report.

The prefix probabilities are the only non-trivial numeric claim in this module, so
they are checked three ways: the exact counts must sum to one over all possible
first characters, they must agree with a reproducible Monte Carlo sample of real
addresses, and they must agree with the naive ``58^-k`` figure in the limit where
that figure is valid.
"""

from __future__ import annotations

import json
import random

import pytest

from binarycryptolab.address_forensics import (
    ADDRESS_ALPHABET,
    AddressDissection,
    base58_prefix_probability,
    controlled_experiment,
    dissect_address,
    matches_public_key,
    vanity_report,
)
from binarycryptolab.bitcoin import Network, p2pkh_address_from_hash160
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.exceptions import (
    AddressEncodingError,
    InputValidationError,
    InvalidPublicKeyError,
)

#: A public, mainnet P2PKH address used throughout the documentation.
SAMPLE_ADDRESS = "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"
#: Its payload, decoded independently by hand from Base58Check.
SAMPLE_PAYLOAD = "ab9a4edd7600fe91d0f46a97dc851ad45c1ce176"
#: A BIP-173 native SegWit vector.
SEGWIT_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
CASHADDR_ADDRESS = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"


@pytest.fixture(scope="module")
def dissection() -> AddressDissection:
    """Dissection of the sample P2PKH address."""
    return dissect_address(SAMPLE_ADDRESS)


@pytest.fixture(scope="module")
def segwit_dissection() -> AddressDissection:
    """Dissection of the BIP-173 P2WPKH vector."""
    return dissect_address(SEGWIT_ADDRESS)


class TestBase58PrefixProbability:
    """The exact counting model."""

    def test_first_character_probabilities_sum_to_one(self) -> None:
        total = sum(base58_prefix_probability("1" + character) for character in ADDRESS_ALPHABET)
        assert total == pytest.approx(1.0, abs=1e-12)

    def test_monotone_in_prefix_length(self) -> None:
        values = [base58_prefix_probability("1GeM"[:length]) for length in (1, 2, 3, 4)]
        assert values == sorted(values, reverse=True)

    def test_single_one_is_certain(self) -> None:
        # Every mainnet P2PKH address starts with '1' because the version is zero.
        assert base58_prefix_probability("1") == pytest.approx(1.0)

    def test_non_one_first_character_is_impossible(self) -> None:
        assert base58_prefix_probability("3") == 0.0
        assert base58_prefix_probability("2") == 0.0

    def test_exceeds_the_naive_estimate(self) -> None:
        # The fixed version byte and fixed digit length make short prefixes more
        # likely than 58^-k suggests; the exact count is the trustworthy figure.
        exact = base58_prefix_probability("1G")
        naive = 58.0**-1
        assert naive < exact < 3 * naive

    def test_agrees_with_monte_carlo(self) -> None:
        engine = random.Random(20240503)
        samples = 20_000
        hits = 0
        for _ in range(samples):
            payload = bytes(engine.getrandbits(8) for _ in range(20))
            if p2pkh_address_from_hash160(payload, Network.MAINNET).startswith("1Ge"):
                hits += 1
        expected = base58_prefix_probability("1Ge") * samples
        # A 5 percent band around the expectation is about four standard deviations.
        assert abs(hits - expected) <= max(5.0, 0.25 * expected)

    def test_p2sh_version_differs(self) -> None:
        assert base58_prefix_probability("3", version=5) == pytest.approx(1.0, abs=1e-9)
        assert base58_prefix_probability("1", version=5) == 0.0

    @pytest.mark.parametrize("prefix", ["", "0", "O", "I", "l"])
    def test_rejects_invalid_prefixes(self, prefix: str) -> None:
        with pytest.raises(ValueError):
            base58_prefix_probability(prefix)

    def test_rejects_invalid_version(self) -> None:
        with pytest.raises(ValueError):
            base58_prefix_probability("1", version=256)
        with pytest.raises(ValueError):
            base58_prefix_probability("1", payload_length=0)


class TestVanityReport:
    """Post-hoc versus pre-declared prefixes."""

    def test_post_hoc_observation_is_not_significant(self) -> None:
        report = vanity_report(SAMPLE_ADDRESS)
        assert report.claimed_in_advance is False
        assert report.corrected_probability == 1.0
        assert "after seeing the address" in report.verdict
        assert report.probability < 1e-6

    def test_declared_prefix_matches(self) -> None:
        report = vanity_report(SAMPLE_ADDRESS, claimed_prefix="1Ge")
        assert report.claimed_in_advance is True
        assert report.corrected_probability < 0.01
        assert "plausibly chosen" in report.verdict

    def test_declared_prefix_that_does_not_match(self) -> None:
        report = vanity_report(SAMPLE_ADDRESS, claimed_prefix="1AAAA")
        assert "does not start" in report.verdict

    def test_naive_probability_is_reported_for_comparison(self) -> None:
        report = vanity_report(SAMPLE_ADDRESS, claimed_prefix="1GeM")
        assert report.naive_probability < report.probability

    def test_segwit_now_has_its_own_exact_count(self) -> None:
        # v1.6.0 removed the refusal: Bech32 has a counting model of its own.
        report = vanity_report(SEGWIT_ADDRESS)
        assert report.encoding == "bech32"
        assert report.constrained_bits >= 0
        assert report.claimed_in_advance is False

    def test_segwit_claimed_prefix(self) -> None:
        report = vanity_report(SEGWIT_ADDRESS, claimed_prefix="bc1qw508")
        assert report.claimed_in_advance is True
        assert report.probability == pytest.approx(2.0**-20)
        assert report.constrained_bits == 20

    def test_bech32_naive_equals_exact(self) -> None:
        # The Bech32 alphabet is 2^5 and the version character is excluded from both
        # counts, so here the naive figure is genuinely right; the correction only
        # matters for Base58 and CashAddr.
        report = vanity_report(SEGWIT_ADDRESS, claimed_prefix="bc1qw5")
        assert report.probability == pytest.approx(report.naive_probability)

    def test_cashaddr_differs_from_naive(self) -> None:
        report = vanity_report(CASHADDR_ADDRESS, claimed_prefix="bitcoincash:qpm2")
        assert report.encoding == "cashaddr"
        assert report.probability > report.naive_probability

    def test_impossible_prefix_character(self) -> None:
        report = vanity_report(SEGWIT_ADDRESS, claimed_prefix="bc1qb")
        assert report.probability == 0.0
        assert "does not start" in report.verdict

    def test_wrong_human_readable_part(self) -> None:
        report = vanity_report(SEGWIT_ADDRESS, claimed_prefix="tb1qw5")
        assert report.probability == 0.0

    def test_as_dict(self) -> None:
        payload = vanity_report(SAMPLE_ADDRESS).as_dict()
        assert set(payload) == {
            "prefix",
            "probability",
            "naive_probability",
            "claimed_in_advance",
            "corrected_probability",
            "encoding",
            "constrained_bits",
            "verdict",
            "note",
        }


class TestDissectAddress:
    """Decoding, verification, and the profile."""

    def test_identity(self, dissection: AddressDissection) -> None:
        assert dissection.address == SAMPLE_ADDRESS
        assert dissection.encoding == "base58check"
        assert dissection.address_type == "p2pkh"
        assert dissection.network == "mainnet"
        assert dissection.version_byte == 0
        assert dissection.human_readable_part is None

    def test_payload_matches_an_independent_decode(self, dissection: AddressDissection) -> None:
        assert dissection.payload_hex == SAMPLE_PAYLOAD
        assert dissection.payload_length_bytes == 20

    def test_checksum_is_recomputed(self, dissection: AddressDissection) -> None:
        assert dissection.checksum_valid
        assert dissection.checksum_hex == dissection.recomputed_checksum_hex
        assert dissection.checksum_hex == "c6b1840e"

    def test_locking_script(self, dissection: AddressDissection) -> None:
        assert dissection.script_pubkey_hex == f"76a914{SAMPLE_PAYLOAD}88ac"
        assert len(bytes.fromhex(dissection.script_pubkey_hex)) == 25
        assert dissection.script_asm.startswith("OP_DUP OP_HASH160")
        assert dissection.script_asm.endswith("OP_CHECKSIG")

    def test_leading_zero_bytes_and_ones(self, dissection: AddressDissection) -> None:
        assert dissection.leading_zero_bytes == 1
        assert dissection.base58_leading_ones == 1

    def test_payload_profile(self, dissection: AddressDissection) -> None:
        profile = dissection.payload_profile
        assert profile.label == "hash160"
        assert profile.bit_length == 160
        assert profile.leading_zero_bits == 0
        assert profile.hamming_weight == 82
        assert profile.hamming_p_value == pytest.approx(0.8126, abs=1e-3)
        assert profile.distinct_bytes == 19
        assert 0.0 < profile.byte_entropy <= 8.0
        assert sum(count for _, count in profile.nibble_frequency) == 40

    def test_randomness_battery_runs(self, dissection: AddressDissection) -> None:
        assert len(dissection.randomness.tests) == 7
        assert dissection.randomness.bits_used == 160
        assert dissection.randomness.familywise_pass
        assert 0.0 < dissection.randomness.fisher_p_value <= 1.0

    def test_no_structural_findings_for_a_normal_address(
        self, dissection: AddressDissection
    ) -> None:
        assert dissection.findings == ()

    def test_scale_is_explicit(self, dissection: AddressDissection) -> None:
        scale = dissection.scale
        assert scale.address_bits == 160
        assert scale.public_key_candidates_log2 == 96.0
        assert scale.scalar_bits_known == 0.0
        assert scale.scalar_bits_unknown == 256.0
        assert scale.scalar_bits_total == 256
        assert "zero bits" in scale.note

    def test_recoverable_is_always_false(self, dissection: AddressDissection) -> None:
        assert dissection.recoverable is False
        assert dissection.as_dict()["recoverable"] is False

    def test_hardness_chain(self, dissection: AddressDissection) -> None:
        steps = dissection.hardness.steps
        assert [step.feasible for step in steps] == [True, False, False]
        assert steps[0].cost_log2 == 0.0
        assert steps[1].cost_log2 == 160.0
        assert steps[2].cost_log2 == 128.0
        assert dissection.hardness.total_cost_log2 == 288.0
        assert "cannot be run backwards" in dissection.hardness.verdict

    def test_caveats_cover_the_scientific_nuances(self, dissection: AddressDissection) -> None:
        joined = " ".join(dissection.hardness.caveats)
        assert "Grover" in joined
        assert "Shor" in joined
        assert "collision" in joined
        assert "preimage" in joined

    def test_notes_and_limitations(self, dissection: AddressDissection) -> None:
        assert len(dissection.notes) >= 4
        assert len(dissection.limitations) == 4
        assert any("chain data" in item for item in dissection.limitations)

    def test_as_dict_round_trips(self, dissection: AddressDissection) -> None:
        payload = dissection.as_dict()
        text = json.dumps(payload, sort_keys=True)
        assert len(text) > 2000
        assert set(payload) == {
            "address",
            "encoding",
            "type",
            "chain",
            "chain_candidates",
            "chain_ambiguous",
            "input_kind",
            "uri_params",
            "network",
            "network_ambiguous",
            "version_byte",
            "human_readable_part",
            "payload_hex",
            "payload_length_bytes",
            "checksum_hex",
            "recomputed_checksum_hex",
            "checksum_valid",
            "script_pubkey_hex",
            "script_asm",
            "witness_version",
            "leading_zero_bytes",
            "base58_leading_ones",
            "payload_profile",
            "randomness",
            "findings",
            "scale",
            "hardness",
            "vanity",
            "taproot",
            "safety",
            "script_claim",
            "key_match",
            "recoverable",
            "plan",
            "notes",
            "limitations",
        }

    def test_segwit_address(self, segwit_dissection: AddressDissection) -> None:
        assert segwit_dissection.encoding == "bech32"
        assert segwit_dissection.address_type == "p2wpkh"
        assert segwit_dissection.witness_version == 0
        assert segwit_dissection.human_readable_part == "bc"
        assert segwit_dissection.version_byte is None
        assert segwit_dissection.script_pubkey_hex.startswith("0014")
        assert segwit_dissection.script_asm.startswith("OP_0 ")

    def test_segwit_has_its_own_prefix_model(self, segwit_dissection: AddressDissection) -> None:
        assert segwit_dissection.vanity.encoding == "bech32"
        assert segwit_dissection.vanity.constrained_bits > 0

    def test_bech32m_address(self) -> None:
        # BIP-350 v1 vector: Taproot uses Bech32m.
        address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        result = dissect_address(address)
        assert result.encoding == "bech32m"
        assert result.witness_version == 1
        assert result.script_pubkey_hex.startswith("5120")

    def test_rejects_a_public_key(self) -> None:
        with pytest.raises(AddressEncodingError):
            dissect_address(SAMPLE_PAYLOAD)

    def test_rejects_a_broken_checksum(self) -> None:
        broken = SAMPLE_ADDRESS[:-1] + ("b" if SAMPLE_ADDRESS[-1] != "b" else "c")
        with pytest.raises(AddressEncodingError):
            dissect_address(broken)

    def test_rejects_empty_input(self) -> None:
        with pytest.raises(InputValidationError):
            dissect_address("")


class TestFindings:
    """Structural findings appear only when the payload really is odd."""

    def test_leading_zero_payload_is_flagged(self) -> None:
        # A payload with 8 leading zero bits is 256 times less likely than a
        # generic one; the finding records exactly that.
        payload = bytes.fromhex("00" + "ab" * 19)
        address = p2pkh_address_from_hash160(payload, Network.MAINNET)
        result = dissect_address(address)
        codes = {finding.code for finding in result.findings}
        assert "leading_zero_bits" in codes
        finding = next(item for item in result.findings if item.code == "leading_zero_bits")
        assert finding.probability == pytest.approx(2.0**-8)
        assert finding.severity == "notice"

    def test_constant_payload_is_critical(self) -> None:
        address = p2pkh_address_from_hash160(bytes(20), Network.MAINNET)
        result = dissect_address(address)
        codes = {finding.code for finding in result.findings}
        assert "constant_payload" in codes
        assert not result.randomness.familywise_pass


class TestControlledExperiment:
    """The only legitimate way to relate a public key to an address."""

    def test_matching_key(self) -> None:
        public_key = public_key_from_private(999_331).compressed_hex
        address = controlled_experiment(_address_for(public_key), public_key)
        assert address.matching_labels
        assert address.payload_matches
        assert "exact match" in address.verdict

    def test_non_matching_key(self) -> None:
        public_key = public_key_from_private(999_332).compressed_hex
        result = controlled_experiment(SAMPLE_ADDRESS, public_key)
        assert result.matching_labels == ()
        assert result.payload_matches is False
        assert "no match" in result.verdict

    def test_matches_public_key_predicate(self) -> None:
        public_key = public_key_from_private(4_242).compressed_hex
        address = controlled_experiment(_address_for(public_key), public_key).address
        assert matches_public_key(address, public_key) is True
        assert matches_public_key(SAMPLE_ADDRESS, public_key) is False

    def test_lists_every_derivation(self) -> None:
        public_key = public_key_from_private(7).compressed_hex
        result = controlled_experiment(SAMPLE_ADDRESS, public_key)
        assert len(result.derived_addresses) == 5
        labels = [label for label, _ in result.derived_addresses]
        assert labels == [
            "p2pkh (compressed)",
            "p2pkh (uncompressed)",
            "p2wpkh",
            "p2sh-p2wpkh",
            "p2tr (BIP-341 key path)",
        ]

    def test_rejects_an_invalid_public_key(self) -> None:
        with pytest.raises((InvalidPublicKeyError, ValueError)):
            controlled_experiment(SAMPLE_ADDRESS, "not-a-key")

    def test_as_dict(self) -> None:
        public_key = public_key_from_private(11).compressed_hex
        payload = controlled_experiment(SAMPLE_ADDRESS, public_key).as_dict()
        assert set(payload) == {
            "address",
            "public_key",
            "derived_addresses",
            "matching_labels",
            "payload_matches",
            "verdict",
        }


def _address_for(public_key_hex: str) -> str:
    """Return the mainnet P2PKH address for a public key."""
    from binarycryptolab.bitcoin import derive_p2pkh_address

    return derive_p2pkh_address(public_key_hex, Network.MAINNET).address
