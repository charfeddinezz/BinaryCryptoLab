"""Tests for deep public-key dissection and structural forecasting.

Coverage:

* identity, coordinates, verification checks, and every representation;
* digests and the address matrix (all networks and script types);
* structural findings, probability arithmetic, and the forecast;
* depth and network options, batch dissection, and error handling;
* report integration (JSON and CSV) and the "no private data" invariant.

The weak-key fixtures are built from public curve points with deliberately
small coordinates; they contain no private key material.
"""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path

import pytest

from binarycryptolab.base58 import b58decode
from binarycryptolab.bitcoin import (
    AddressType,
    Network,
    derive_p2sh_p2wpkh_address,
    derive_p2wpkh_address,
)
from binarycryptolab.ecc import FIELD_PRIME, public_key_info_from_hex
from binarycryptolab.exceptions import AddressEncodingError, InvalidPublicKeyError
from binarycryptolab.forensics import (
    ALL_NETWORKS,
    DEPTH_LEVELS,
    PublicKeyDissection,
    _binomial_two_sided_p,
    _evidence_family,
    _human_duration,
    _is_palindrome,
    _limbs,
    _magnitude_log2_bayes_factor,
    _posterior_log2,
    _printable_runs,
    _repeated_period,
    _test_family,
    address_type_names,
    dissect_many,
    dissect_public_key,
)
from binarycryptolab.hashing import hash160, sha256
from binarycryptolab.models.analysis_result import AnalysisResult
from binarycryptolab.reports import render_csv, render_json
from tests.vectors import PUBKEY_ONE_COMPRESSED, PUBKEY_ONE_UNCOMPRESSED


def _small_x_key(x: int = 1) -> str:
    """Return a valid compressed public key whose x coordinate is *x*.

    The curve equation is solved for y; no private key is involved.
    """
    rhs = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y = pow(rhs, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    assert (y * y) % FIELD_PRIME == rhs, "x does not yield a quadratic residue"
    prefix = 0x02 if y % 2 == 0 else 0x03
    return (bytes([prefix]) + x.to_bytes(32, "big")).hex()


WEAK_KEY = _small_x_key(1)


@pytest.fixture(scope="module")
def dissection() -> PublicKeyDissection:
    """Dissection of the generator point (a normal, full-size key)."""
    return dissect_public_key(PUBKEY_ONE_COMPRESSED)


@pytest.fixture(scope="module")
def weak_dissection() -> PublicKeyDissection:
    """Dissection of a point with x = 1 (structurally obvious)."""
    return dissect_public_key(WEAK_KEY)


@pytest.fixture(scope="module")
def deep_dissection() -> PublicKeyDissection:
    """Dissection of the generator point in deep mode."""
    return dissect_public_key(PUBKEY_ONE_COMPRESSED, depth="deep")


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_matches_public_key_info(self, dissection: PublicKeyDissection) -> None:
        info = public_key_info_from_hex(PUBKEY_ONE_COMPRESSED)
        assert dissection.curve == "secp256k1"
        assert dissection.compressed_hex == info.compressed_hex
        assert dissection.uncompressed_hex == info.uncompressed_hex
        assert dissection.x.hexadecimal == f"{info.x:064x}"
        assert dissection.y.hexadecimal == f"{info.y:064x}"
        assert dissection.x_only_hex == f"{info.x:064x}"
        assert dissection.input_encoding == "compressed"

    def test_prefix_and_parity_agree(self, dissection: PublicKeyDissection) -> None:
        info = public_key_info_from_hex(PUBKEY_ONE_COMPRESSED)
        expected = "even" if info.y % 2 == 0 else "odd"
        assert dissection.y_parity == expected
        assert dissection.prefix_byte in {"0x02", "0x03"}

    def test_uncompressed_input_is_recorded(self) -> None:
        result = dissect_public_key(PUBKEY_ONE_UNCOMPRESSED)
        assert result.input_encoding == "uncompressed"
        assert result.compressed_hex == PUBKEY_ONE_COMPRESSED

    def test_raw_64_byte_input_is_recorded(self) -> None:
        raw = PUBKEY_ONE_UNCOMPRESSED[2:]
        result = dissect_public_key(raw)
        assert result.input_encoding == "raw-uncompressed"
        assert result.compressed_hex == PUBKEY_ONE_COMPRESSED

    def test_input_is_normalized(self) -> None:
        messy = f"  0X{PUBKEY_ONE_COMPRESSED.upper()}  "
        result = dissect_public_key(messy)
        assert result.input_hex == PUBKEY_ONE_COMPRESSED
        assert result.forecast.structure_score == 0.0

    def test_uppercase_and_prefixes_produce_the_same_point(self) -> None:
        upper = dissect_public_key(PUBKEY_ONE_COMPRESSED.upper())
        prefixed = dissect_public_key("0x" + PUBKEY_ONE_COMPRESSED)
        assert upper.compressed_hex == prefixed.compressed_hex


# ---------------------------------------------------------------------------
# Coordinates
# ---------------------------------------------------------------------------


class TestCoordinates:
    def test_hexadecimal_values_are_zero_padded(self, dissection: PublicKeyDissection) -> None:
        for profile in dissection.coordinates:
            assert len(profile.hexadecimal) == 64
            assert profile.hexadecimal == profile.hexadecimal.lower()

    def test_decimal_matches_hexadecimal(self, dissection: PublicKeyDissection) -> None:
        for profile in dissection.coordinates:
            assert int(profile.decimal) == int(profile.hexadecimal, 16)

    def test_bit_length_and_leading_zeros_sum_to_256(self, dissection: PublicKeyDissection) -> None:
        for profile in dissection.coordinates:
            assert profile.bit_length + profile.leading_zero_bits == 256

    def test_hamming_weight_matches_bin_count(self, dissection: PublicKeyDissection) -> None:
        for profile in dissection.coordinates:
            assert profile.hamming_weight == bin(int(profile.hexadecimal, 16)).count("1")
            assert profile.hamming_ratio == pytest.approx(profile.hamming_weight / 256)

    def test_entropy_is_bounded(self, dissection: PublicKeyDissection) -> None:
        for profile in dissection.coordinates:
            assert 0.0 <= profile.byte_entropy <= 8.0
            assert 1 <= profile.unique_bytes <= 32

    def test_limbs_reconstruct_the_value(self, dissection: PublicKeyDissection) -> None:
        x = int(dissection.x.hexadecimal, 16)
        for base_bits, limbs in dissection.x.limb_bases:
            rebuilt = 0
            for limb in limbs:
                rebuilt = (rebuilt << base_bits) | limb
            assert rebuilt == x
            assert len(limbs) == 256 // base_bits

    def test_little_endian_is_the_byte_reverse(self, dissection: PublicKeyDissection) -> None:
        expected = bytes.fromhex(dissection.x.hexadecimal)[::-1].hex()
        assert dissection.x.little_endian_hex == expected

    def test_bit_grid_shape(self, dissection: PublicKeyDissection) -> None:
        assert len(dissection.x.bit_grid) == 8
        assert all(len(row) == 32 for row in dissection.x.bit_grid)
        assert "".join(dissection.x.bit_grid) == f"{int(dissection.x.hexadecimal, 16):0256b}"

    def test_parity_flag(self, dissection: PublicKeyDissection) -> None:
        assert dissection.x.is_even == (int(dissection.x.hexadecimal, 16) % 2 == 0)
        assert dissection.y.is_even == (dissection.y_parity == "even")

    def test_distance_to_prime(self, dissection: PublicKeyDissection) -> None:
        expected = FIELD_PRIME - int(dissection.x.hexadecimal, 16)
        assert int(dissection.x.distance_to_prime) == expected

    def test_nibble_histogram_covers_all_digits(self, dissection: PublicKeyDissection) -> None:
        total = sum(count for _, count in dissection.x.nibble_frequency)
        assert total == 64
        counts = [count for _, count in dissection.x.nibble_frequency]
        assert counts == sorted(counts, reverse=True)

    def test_ascii_runs_detects_printable_text(self) -> None:
        assert _printable_runs(b"\x00hello\x00") == ("hello",)
        assert _printable_runs(b"\x00\x01\x02") == ()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_all_checks_pass(self, dissection: PublicKeyDissection) -> None:
        assert dissection.verification
        failures = [name for name, passed in dissection.verification if not passed]
        assert failures == []

    def test_expected_check_names(self, dissection: PublicKeyDissection) -> None:
        names = " | ".join(name for name, _ in dissection.verification)
        assert "y^2 = x^3 + 7" in names
        assert "field range" in names
        assert "prefix" in names
        assert "decodes back" in names

    def test_curve_equation_holds(self, dissection: PublicKeyDissection) -> None:
        x = int(dissection.x.hexadecimal, 16)
        y = int(dissection.y.hexadecimal, 16)
        assert (y * y - (pow(x, 3, FIELD_PRIME) + 7)) % FIELD_PRIME == 0


# ---------------------------------------------------------------------------
# Representations and digests
# ---------------------------------------------------------------------------


class TestRepresentations:
    def test_expected_labels(self, dissection: PublicKeyDissection) -> None:
        labels = {item.label for item in dissection.representations}
        assert {
            "compressed (hex)",
            "compressed (hex, uppercase)",
            "uncompressed (hex)",
            "raw coordinates (hex)",
            "x coordinate (hex)",
            "y coordinate (hex)",
            "x-only (hex)",
            "compressed (binary)",
            "x (binary)",
            "x (decimal)",
            "y (decimal)",
            "compressed (decimal)",
            "compressed (base58)",
            "compressed (base64)",
            "compressed (hex, spaced)",
            "x (mod n)",
        } <= labels

    def test_binary_length(self, dissection: PublicKeyDissection) -> None:
        binary = next(
            item for item in dissection.representations if item.label == "compressed (binary)"
        )
        assert binary.value == "".join(
            f"{byte:08b}" for byte in bytes.fromhex(dissection.compressed_hex)
        )
        assert len(binary.value) == 264

    def test_base58_roundtrip(self, dissection: PublicKeyDissection) -> None:
        encoded = next(
            item for item in dissection.representations if item.label == "compressed (base58)"
        )
        assert b58decode(encoded.value).hex() == dissection.compressed_hex

    def test_base64_roundtrip(self, dissection: PublicKeyDissection) -> None:
        encoded = next(
            item for item in dissection.representations if item.label == "compressed (base64)"
        )
        assert base64.b64decode(encoded.value).hex() == dissection.compressed_hex

    def test_deep_only_labels(self, deep_dissection: PublicKeyDissection) -> None:
        labels = {item.label for item in deep_dissection.representations}
        assert "compressed (base32)" in labels
        assert "x (little-endian hex)" in labels
        assert "compressed (base58check)" in labels

    def test_standard_excludes_deep_labels(self, dissection: PublicKeyDissection) -> None:
        labels = {item.label for item in dissection.representations}
        assert "compressed (base32)" not in labels

    def test_representations_are_json_serialisable(
        self, deep_dissection: PublicKeyDissection
    ) -> None:
        json.dumps([item.as_dict() for item in deep_dissection.representations])


class TestDigests:
    def test_sha256_matches_the_library(self, dissection: PublicKeyDissection) -> None:
        digests = dict(dissection.digests)
        assert (
            digests["sha256(compressed)"] == sha256(bytes.fromhex(dissection.compressed_hex)).hex()
        )
        assert (
            digests["sha256(uncompressed)"]
            == sha256(bytes.fromhex(dissection.uncompressed_hex)).hex()
        )

    def test_hash160_matches_the_address_payload(self, dissection: PublicKeyDissection) -> None:
        digests = dict(dissection.digests)
        assert (
            digests["hash160(compressed)"]
            == hash160(bytes.fromhex(dissection.compressed_hex)).hex()
        )
        assert digests["hash160(compressed)"] == dissection.addresses[0].payload_hex

    def test_double_sha256_is_two_rounds(self, dissection: PublicKeyDissection) -> None:
        digests = dict(dissection.digests)
        compressed = bytes.fromhex(dissection.compressed_hex)
        assert digests["double_sha256(compressed)"] == sha256(sha256(compressed)).hex()

    def test_deep_adds_sha512(self, deep_dissection: PublicKeyDissection) -> None:
        assert "sha512(compressed)" in dict(deep_dissection.digests)
        standard = dissect_public_key(PUBKEY_ONE_COMPRESSED)
        assert "sha512(compressed)" not in dict(standard.digests)


# ---------------------------------------------------------------------------
# Address matrix
# ---------------------------------------------------------------------------


class TestAddressMatrix:
    def test_default_size(self, dissection: PublicKeyDissection) -> None:
        assert len(dissection.addresses) == 16
        assert len(dissection.addresses) == 4 * len(ALL_NETWORKS)

    def test_known_mainnet_addresses(self, dissection: PublicKeyDissection) -> None:
        by_key = {
            (entry.network, entry.address_type, entry.key_encoding): entry
            for entry in dissection.addresses
        }
        assert by_key[("mainnet", "p2pkh", "compressed")].address == (
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        )
        assert by_key[("mainnet", "p2pkh", "uncompressed")].address == (
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
        )
        assert by_key[("mainnet", "p2wpkh", "compressed")].address == (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )
        assert by_key[("mainnet", "p2sh-p2wpkh", "compressed")].address == (
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        )

    def test_every_address_roundtrips(self, dissection: PublicKeyDissection) -> None:
        assert all(entry.roundtrip_ok for entry in dissection.addresses)

    def test_script_pubkeys_have_the_right_shape(self, dissection: PublicKeyDissection) -> None:
        for entry in dissection.addresses:
            script = entry.script_pubkey_hex
            if entry.address_type == "p2pkh":
                assert script.startswith("76a914") and script.endswith("88ac")
                assert len(script) == 50
            elif entry.address_type == "p2wpkh":
                assert script.startswith("0014")
                assert len(script) == 44
            else:
                assert script.startswith("a914") and script.endswith("87")
                assert len(script) == 46

    def test_network_subset(self) -> None:
        result = dissect_public_key(PUBKEY_ONE_COMPRESSED, networks=(Network.MAINNET,))
        assert len(result.addresses) == 4
        assert {entry.network for entry in result.addresses} == {"mainnet"}

    def test_network_strings_are_accepted(self) -> None:
        result = dissect_public_key(PUBKEY_ONE_COMPRESSED, networks=("testnet", "regtest"))
        assert len(result.addresses) == 8

    def test_empty_network_list_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one network"):
            dissect_public_key(PUBKEY_ONE_COMPRESSED, networks=())

    def test_unknown_network_is_rejected(self) -> None:
        with pytest.raises(AddressEncodingError):
            dissect_public_key(PUBKEY_ONE_COMPRESSED, networks=("moonnet",))

    def test_p2sh_p2wpkh_matches_the_dedicated_function(self) -> None:
        info = derive_p2sh_p2wpkh_address(PUBKEY_ONE_COMPRESSED)
        result = dissect_public_key(PUBKEY_ONE_COMPRESSED, networks=(Network.MAINNET,))
        entry = next(item for item in result.addresses if item.address_type == "p2sh-p2wpkh")
        assert entry.address == info.address
        assert entry.witness_program_hex == derive_p2wpkh_address(PUBKEY_ONE_COMPRESSED).hash160_hex


# ---------------------------------------------------------------------------
# Findings and forecast
# ---------------------------------------------------------------------------


class TestFindings:
    def test_generator_has_no_findings(self, dissection: PublicKeyDissection) -> None:
        assert dissection.findings == ()
        assert dissection.forecast.structure_score == 0.0

    def test_small_coordinate_is_flagged(self, weak_dissection: PublicKeyDissection) -> None:
        codes = {finding.code for finding in weak_dissection.findings}
        assert "x_small_magnitude" in codes
        assert "x_leading_zero_bits" in codes
        assert weak_dissection.forecast.structure_score == 100.0
        assert "strongly structured" in weak_dissection.forecast.verdict

    def test_findings_are_sorted_by_significance(
        self, weak_dissection: PublicKeyDissection
    ) -> None:
        surprisals = [finding.surprisal_bits for finding in weak_dissection.findings]
        assert surprisals == sorted(surprisals, reverse=True)

    def test_severity_thresholds(self, weak_dissection: PublicKeyDissection) -> None:
        severity = {finding.code: finding.severity for finding in weak_dissection.findings}
        assert severity["x_small_magnitude"] == "critical"

    def test_probabilities_are_in_range(self, weak_dissection: PublicKeyDissection) -> None:
        for finding in weak_dissection.findings:
            assert 0.0 < finding.probability <= 1.0
            assert 0.0 <= finding.surprisal_bits <= 64.0

    def test_no_private_material_in_findings(self, weak_dissection: PublicKeyDissection) -> None:
        payload = json.dumps([finding.as_dict() for finding in weak_dissection.findings]).lower()
        assert "private" not in payload
        assert "scalar_value" not in payload


class TestForecast:
    def test_normal_key_verdict(self, dissection: PublicKeyDissection) -> None:
        forecast = dissection.forecast
        assert forecast.verdict == "consistent with a uniformly random public key"
        assert forecast.size_class == "full 256-bit magnitude"
        assert forecast.recoverable is False
        assert forecast.hypotheses[0].likelihood == "likely"

    def test_weak_key_verdict(self, weak_dissection: PublicKeyDissection) -> None:
        forecast = weak_dissection.forecast
        assert forecast.recoverable is False
        assert forecast.structure_score >= 60
        assert forecast.size_class == "reduced-magnitude coordinate"

    def test_four_hypotheses(self, dissection: PublicKeyDissection) -> None:
        hypotheses = dissection.forecast.hypotheses
        assert len(hypotheses) == 4
        assert all(0.0 <= item.score <= 1.0 for item in hypotheses)
        assert all(item.likelihood for item in hypotheses)
        assert all(item.evidence for item in hypotheses)

    def test_search_estimates_are_ordered(self, dissection: PublicKeyDissection) -> None:
        estimates = dissection.forecast.search_estimates
        assert len(estimates) >= 9
        exhaustive = [item for item in estimates if item.strategy == "exhaustive"]
        assert [item.scalar_bits for item in exhaustive] == [32, 64, 128, 160, 256]
        logs = [item.operations_log2 for item in exhaustive]
        assert logs == sorted(logs)
        assert exhaustive[0].feasible_today == "trivial"
        assert exhaustive[-1].feasible_today == "physically impossible"

    def test_pollard_rho_uses_half_the_bits(self, dissection: PublicKeyDissection) -> None:
        rho = next(
            item
            for item in dissection.forecast.search_estimates
            if item.strategy == "pollard-rho" and item.scalar_bits == 128
        )
        assert rho.operations_log2 == pytest.approx(64.0)

    def test_bsgs_reports_memory(self, dissection: PublicKeyDissection) -> None:
        bsgs = [item for item in dissection.forecast.search_estimates if item.strategy == "bsgs"]
        assert bsgs
        assert all("GB" in item.memory for item in bsgs)

    def test_recommendations_and_limitations(self, dissection: PublicKeyDissection) -> None:
        assert len(dissection.forecast.recommendations) >= 3
        limitations = dissection.forecast.limitations
        assert len(limitations) == 5
        assert any("Bonferroni" in item for item in limitations)
        assert any("cannot confirm or refute" in item for item in limitations)
        assert any(
            "does not compute private keys" in item for item in dissection.forecast.recommendations
        )

    def test_summary_mentions_the_score(self, dissection: PublicKeyDissection) -> None:
        assert "Structure score" in dissection.forecast.summary
        assert "not key recovery" in dissection.forecast.summary


# ---------------------------------------------------------------------------
# Statistical forecast
# ---------------------------------------------------------------------------


class TestEvidenceFamilies:
    """Findings and randomness tests mapped onto independent evidence families."""

    def test_findings_map_to_documented_families(self) -> None:
        assert _evidence_family("x_small_magnitude") == "magnitude"
        assert _evidence_family("y_leading_zero_bits") == "magnitude"
        assert _evidence_family("x_hamming_weight") == "bit-balance"
        assert _evidence_family("x_palindrome") == "repetition"
        assert _evidence_family("x_repeated_period_4") == "repetition"
        assert _evidence_family("x_nibble_skew") == "digit-skew"
        assert _evidence_family("x_ascii_run") == "ascii"
        assert _evidence_family("x_equals_y") == "relation"
        assert _evidence_family("y_is_negation_of_x") == "relation"

    def test_randomness_tests_map_to_families(self) -> None:
        assert _test_family("monobit") == "bit-balance"
        assert _test_family("runs") == "runs"
        assert _test_family("longest_run") == "runs"
        assert _test_family("serial_correlation") == "serial"
        assert _test_family("approximate_entropy") == "sequence"
        assert _test_family("nibble_uniformity") == "digit-skew"
        assert _test_family("distinct_bytes") == "repetition"

    def test_unknown_test_falls_back_to_sequence(self) -> None:
        assert _test_family("not-a-test") == "sequence"

    def test_families_are_unique_in_the_report(self, dissection: PublicKeyDissection) -> None:
        names = [item.family for item in dissection.forecast.evidence]
        assert len(names) == len(set(names))
        assert names

    def test_every_family_cites_its_sources(self, dissection: PublicKeyDissection) -> None:
        for item in dissection.forecast.evidence:
            assert item.sources
            assert item.interpretation
            assert 0.0 < item.p_value <= 1.0


class TestBayesFactors:
    """Explicit priors, log-space posteriors, and model complexity penalties."""

    def test_priors_sum_to_one(self, dissection: PublicKeyDissection) -> None:
        priors = [item.prior for item in dissection.forecast.bayes_factors]
        assert sum(priors) == pytest.approx(1.0)

    def test_posteriors_sum_to_one(self, dissection: PublicKeyDissection) -> None:
        posteriors = [item.posterior for item in dissection.forecast.bayes_factors]
        assert sum(posteriors) == pytest.approx(1.0, abs=1e-6)

    def test_log_posteriors_are_normalised(self, dissection: PublicKeyDissection) -> None:
        logs = [item.log2_posterior for item in dissection.forecast.bayes_factors]
        total = sum(2.0**value for value in logs)
        assert total == pytest.approx(1.0, abs=1e-3)

    def test_log_posterior_agrees_with_posterior(self, dissection: PublicKeyDissection) -> None:
        for item in dissection.forecast.bayes_factors:
            assert math.log2(item.posterior) == pytest.approx(item.log2_posterior, abs=0.01)

    def test_hypothesis_scores_are_the_posteriors(self, dissection: PublicKeyDissection) -> None:
        forecast = dissection.forecast
        for hypothesis, factor in zip(forecast.hypotheses, forecast.bayes_factors, strict=True):
            assert hypothesis.score == pytest.approx(factor.posterior, abs=1e-3)

    def test_normal_key_favours_a_secure_generator(self, dissection: PublicKeyDissection) -> None:
        factors = dissection.forecast.bayes_factors
        assert factors[0].posterior > 0.9
        assert all(factor.posterior < 0.05 for factor in factors[1:])

    def test_weak_key_favours_a_structure(self, weak_dissection: PublicKeyDissection) -> None:
        factors = weak_dissection.forecast.bayes_factors
        best = max(factors, key=lambda factor: factor.log2_posterior)
        assert best is factors[2]
        assert best.posterior > 0.9
        assert 0.0 <= factors[0].posterior < 1e-6

    def test_magnitude_bayes_factor_is_monotone(self) -> None:
        values = [_magnitude_log2_bayes_factor(bits) for bits in (1, 16, 64, 128, 255, 256)]
        assert values == sorted(values, reverse=True)
        # A full-width coordinate is penalised by the 8 bits of model choice.
        assert _magnitude_log2_bayes_factor(256) < 0.0
        assert _magnitude_log2_bayes_factor(1) > 200.0

    def test_posterior_requires_one_weight_per_hypothesis(self) -> None:
        with pytest.raises(ValueError):
            _posterior_log2((0.0, 0.0))

    def test_posterior_is_shift_invariant(self) -> None:
        base = _posterior_log2((0.0, 0.0, 0.0, 0.0))
        shifted = _posterior_log2((5.0, 5.0, 5.0, 5.0))
        assert base == pytest.approx(shifted)


class TestStatisticalForecast:
    """Combined p-values, entropy budgets, and the randomness section."""

    def test_fisher_combination_is_reported(self, dissection: PublicKeyDissection) -> None:
        forecast = dissection.forecast
        assert 0.0 < forecast.combined_p_value <= 1.0
        assert 0.0 < forecast.bonferroni_p_value <= 1.0
        assert forecast.bonferroni_p_value >= forecast.minimum_p_value
        assert forecast.minimum_p_value <= min(item.p_value for item in forecast.evidence)

    def test_alpha_is_the_documented_level(self, dissection: PublicKeyDissection) -> None:
        assert dissection.forecast.alpha == pytest.approx(0.01)

    def test_structure_bits_are_bounded(self, weak_dissection: PublicKeyDissection) -> None:
        forecast = weak_dissection.forecast
        assert 0.0 <= forecast.structure_bits <= 256.0
        assert forecast.total_surprisal_bits <= 256.0
        assert forecast.structure_score == 100.0

    def test_score_follows_the_structure_bits(self, dissection: PublicKeyDissection) -> None:
        forecast = dissection.forecast
        expected = min(100.0, forecast.structure_bits * 100.0 / 128.0)
        assert forecast.structure_score == pytest.approx(expected, abs=1e-3)

    def test_structured_key_summary_reports_the_alternative(
        self, weak_dissection: PublicKeyDissection
    ) -> None:
        summary = weak_dissection.forecast.summary
        assert "Fisher p=" in summary
        assert "Bonferroni p=" in summary
        assert "posterior favours the alternative" in summary

    def test_randomness_section_is_populated(self, dissection: PublicKeyDissection) -> None:
        report = dissection.randomness
        assert len(report.tests) == 7
        assert report.bits_used == 512
        assert 0.0 < report.fisher_p_value <= 1.0
        assert 0.0 < report.bonferroni_p_value <= 1.0
        assert 0.0 < report.bit_entropy_corrected <= 1.0

    def test_normal_key_passes_the_battery(self, dissection: PublicKeyDissection) -> None:
        assert dissection.randomness.familywise_pass
        assert dissection.randomness.failed_tests == ()

    def test_weak_key_fails_the_battery(self, weak_dissection: PublicKeyDissection) -> None:
        assert not weak_dissection.randomness.familywise_pass
        assert "monobit" in weak_dissection.randomness.failed_tests

    def test_randomness_is_serialised(self, dissection: PublicKeyDissection) -> None:
        payload = dissection.as_dict()["randomness"]
        assert set(payload) == {
            "bits_used",
            "alpha",
            "tests",
            "fisher_p_value",
            "bonferroni_p_value",
            "minimum_p_value",
            "familywise_pass",
            "failed_tests",
            "bit_entropy",
            "bit_entropy_corrected",
            "notes",
        }
        assert len(payload["tests"]) == 7

    def test_evidence_and_factors_are_serialised(self, dissection: PublicKeyDissection) -> None:
        payload = dissection.as_dict()["forecast"]
        assert payload["evidence"]
        assert set(payload["evidence"][0]) == {
            "family",
            "p_value",
            "surprisal_bits",
            "sources",
            "interpretation",
        }
        assert set(payload["bayes_factors"][0]) == {
            "hypothesis",
            "prior",
            "log2_bayes_factor",
            "posterior",
            "log2_posterior",
            "rationale",
        }
        assert payload["recoverable"] is False


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------


class TestProbabilityHelpers:
    def test_balanced_binomial_is_certain(self) -> None:
        assert _binomial_two_sided_p(128) == 1.0

    def test_extreme_binomial_is_tiny(self) -> None:
        assert _binomial_two_sided_p(0) < 1e-70
        assert _binomial_two_sided_p(256) < 1e-70

    def test_binomial_is_symmetric(self) -> None:
        assert _binomial_two_sided_p(100) == pytest.approx(_binomial_two_sided_p(156))

    def test_binomial_rejects_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            _binomial_two_sided_p(257)
        with pytest.raises(ValueError):
            _binomial_two_sided_p(-1)

    def test_non_uniform_bias(self) -> None:
        probability = _binomial_two_sided_p(16, trials=64, bias=1 / 16)
        assert 0.0 < probability <= 1.0

    def test_limbs_reject_indivisible_widths(self) -> None:
        with pytest.raises(ValueError):
            _limbs(5, 7, width=256)

    def test_human_duration_units(self) -> None:
        assert _human_duration(0.5) == "500.0 milliseconds"
        assert _human_duration(90) == "1.50 minutes"
        assert _human_duration(2.5 * 86400) == "2.50 days"
        assert "years" in _human_duration(1e8)
        assert "e+" in _human_duration(1e20)

    def test_human_duration_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            _human_duration(-1)

    def test_palindrome_helper(self) -> None:
        assert _is_palindrome("abba")
        assert not _is_palindrome("abca")
        assert not _is_palindrome("a")

    def test_repeated_period_helper(self) -> None:
        assert _repeated_period("abababab", 2)
        assert _repeated_period("abcdabcdabcd", 4)
        assert not _repeated_period("abcdabcx", 4)
        assert not _repeated_period("abababa", 2)


# ---------------------------------------------------------------------------
# Options, batch mode, and errors
# ---------------------------------------------------------------------------


class TestOptions:
    def test_depths_are_two(self) -> None:
        assert DEPTH_LEVELS == ("standard", "deep")

    def test_unknown_depth_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="depth"):
            dissect_public_key(PUBKEY_ONE_COMPRESSED, depth="ultra")

    def test_deep_has_more_limbs(self, deep_dissection: PublicKeyDissection) -> None:
        assert len(deep_dissection.x.limb_bases) == 4
        assert [base for base, _ in deep_dissection.x.limb_bases] == [8, 16, 32, 64]

    def test_standard_has_one_limb_base(self, dissection: PublicKeyDissection) -> None:
        assert [base for base, _ in dissection.x.limb_bases] == [32]

    def test_address_type_names(self) -> None:
        assert address_type_names() == ("p2pkh", "p2wpkh", "p2sh-p2wpkh")


class TestBatch:
    def test_order_is_preserved(self) -> None:
        results = dissect_many([PUBKEY_ONE_COMPRESSED, PUBKEY_ONE_UNCOMPRESSED])
        assert len(results) == 2
        assert results[0].compressed_hex == results[1].compressed_hex
        assert results[0].input_encoding == "compressed"
        assert results[1].input_encoding == "uncompressed"

    def test_single_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="sequence"):
            dissect_many(PUBKEY_ONE_COMPRESSED)  # type: ignore[arg-type]

    def test_error_reports_position_not_key_bytes(self) -> None:
        with pytest.raises(InvalidPublicKeyError) as excinfo:
            dissect_many([PUBKEY_ONE_COMPRESSED, "deadbeef"])
        message = str(excinfo.value)
        assert "#2" in message
        assert "deadbeef" not in message

    def test_empty_batch(self) -> None:
        assert dissect_many([]) == ()


class TestErrors:
    @pytest.mark.parametrize(
        "value",
        [
            "",
            "zz",
            "02",
            "04" + "00" * 64,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179",
        ],
    )
    def test_invalid_keys_raise(self, value: str) -> None:
        with pytest.raises(InvalidPublicKeyError):
            dissect_public_key(value)

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(InvalidPublicKeyError):
            dissect_public_key(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Serialization and report integration
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_as_dict_is_json_serialisable(self, deep_dissection: PublicKeyDissection) -> None:
        payload = deep_dissection.as_dict()
        text = json.dumps(payload, sort_keys=True)
        assert len(text) > 5000
        assert payload["forecast"]["recoverable"] is False
        assert len(payload["address_matrix"]) == 16

    def test_as_dict_has_the_documented_sections(self, dissection: PublicKeyDissection) -> None:
        payload = dissection.as_dict()
        assert set(payload) == {
            "input",
            "depth",
            "curve",
            "public_key",
            "coordinates",
            "verification",
            "representations",
            "bit_profiles",
            "digests",
            "address_matrix",
            "mirror_point",
            "keyspace",
            "randomness",
            "findings",
            "forecast",
            "notes",
        }
        assert set(payload["public_key"]) == {
            "compressed_hex",
            "uncompressed_hex",
            "x_only_hex",
            "y_hex",
            "prefix_byte",
            "y_parity",
            "compressed_length_bytes",
            "uncompressed_length_bytes",
        }

    def test_no_private_fields_anywhere(self, deep_dissection: PublicKeyDissection) -> None:
        text = json.dumps(deep_dissection.as_dict()).lower()
        for forbidden in ("private_key", "scalar_value", "secret", "wif"):
            assert forbidden not in text

    def test_result_model_carries_the_dissection(self, dissection: PublicKeyDissection) -> None:
        result = AnalysisResult(
            input_type="public_key",
            original_input=dissection.input_hex,
            normalized_input=dissection.input_hex,
            forensics=dissection.as_dict(),
        )
        payload = result.to_dict()
        assert payload["public_key_forensics"]["forecast"]["recoverable"] is False
        assert payload["public_key_forensics"]["coordinates"]["x"]["bit_length"] == 255

    def test_json_report_includes_forensics(self, dissection: PublicKeyDissection) -> None:
        result = AnalysisResult(
            input_type="public_key",
            original_input=dissection.input_hex,
            normalized_input=dissection.input_hex,
            forensics=dissection.as_dict(),
        )
        import json as json_module

        payload = json_module.loads(render_json(result))
        assert payload["public_key_forensics"]["curve"] == "secp256k1"
        assert len(payload["public_key_forensics"]["address_matrix"]) == 16

    def test_csv_report_includes_forensics(self, dissection: PublicKeyDissection) -> None:
        result = AnalysisResult(
            input_type="public_key",
            original_input=dissection.input_hex,
            normalized_input=dissection.input_hex,
            forensics=dissection.as_dict(),
        )
        text = render_csv(result)
        assert "forensics.forecast,verdict," in text
        assert "forensics.address_matrix[0],address," in text
        assert text.startswith("section,key,value")

    def test_bit_profiles_are_complete(self, dissection: PublicKeyDissection) -> None:
        labels = [profile.label for profile in dissection.bit_profiles]
        assert labels == [
            "compressed",
            "uncompressed",
            "x",
            "y",
            "hash160(compressed)",
            "sha256(compressed)",
        ]
        for profile in dissection.bit_profiles:
            assert profile.length_bits == profile.ones + profile.zeros
            assert 0.0 <= profile.entropy <= 1.0

    def test_write_json_and_csv(self, dissection: PublicKeyDissection, tmp_path: Path) -> None:
        from binarycryptolab.reports import write_csv, write_json

        result = AnalysisResult(
            input_type="public_key",
            original_input=dissection.input_hex,
            normalized_input=dissection.input_hex,
            forensics=dissection.as_dict(),
        )
        json_path = write_json(result, tmp_path / "dissection.json")
        csv_path = write_csv(result, tmp_path / "dissection.csv")
        assert json_path.exists() and csv_path.exists()
        assert "secp256k1" in json_path.read_text(encoding="utf-8")
        assert "forensics" in csv_path.read_text(encoding="utf-8")


class TestMirrorPoint:
    def test_shares_x_and_flips_parity(self, dissection: PublicKeyDissection) -> None:
        mirror = dissection.mirror
        assert mirror.x_hex == dissection.x_only_hex
        assert mirror.y_parity != dissection.y_parity
        assert mirror.compressed_hex[2:] == dissection.compressed_hex[2:]
        assert mirror.compressed_hex[:2] != dissection.compressed_hex[:2]

    def test_y_is_the_additive_inverse(self, dissection: PublicKeyDissection) -> None:
        assert int(mirror_y := mirror_int(dissection), 16) + int(dissection.y.hexadecimal, 16) == (
            FIELD_PRIME
        )
        assert int(mirror_y, 16) < FIELD_PRIME

    def test_mirror_is_on_the_curve(self, dissection: PublicKeyDissection) -> None:
        x = int(dissection.mirror.x_hex, 16)
        y = int(dissection.mirror.y_hex, 16)
        assert (y * y - (pow(x, 3, FIELD_PRIME) + 7)) % FIELD_PRIME == 0

    def test_addresses_differ_from_the_original(self, dissection: PublicKeyDissection) -> None:
        original = {entry.address for entry in dissection.addresses if entry.network == "mainnet"}
        mirrored = {entry.address for entry in dissection.mirror.addresses}
        assert len(mirrored) == 2
        assert not (original & mirrored)

    def test_known_mainnet_addresses(self, dissection: PublicKeyDissection) -> None:
        addresses = {entry.address_type: entry for entry in dissection.mirror.addresses}
        assert addresses["p2pkh"].address == "1GrLCmVQXoyJXaPJQdqssNqwxvha1eUo2E"
        assert addresses["p2wpkh"].address == "bc1q4h0ycu78h88wzldxc7e79vhw5xsde0n8jk4wl5"

    def test_roundtrips_and_scripts(self, dissection: PublicKeyDissection) -> None:
        for entry in dissection.mirror.addresses:
            assert entry.roundtrip_ok
            assert entry.script_pubkey_hex.startswith(("76a914", "0014"))

    def test_note_explains_the_ambiguity(self, dissection: PublicKeyDissection) -> None:
        assert "x-only" in dissection.mirror.note
        assert "different" in dissection.mirror.note


def mirror_int(dissection: PublicKeyDissection) -> str:
    """Return the mirrored y coordinate as hexadecimal."""
    return dissection.mirror.y_hex


class TestKeyspace:
    def test_reports_the_curve_order(self, dissection: PublicKeyDissection) -> None:
        keyspace = dict(dissection.keyspace)
        assert keyspace["curve_order_bits"] == "256"
        assert (
            keyspace["curve_order_hex"]
            == f"{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:064x}"
        )

    def test_reports_the_field_prime(self, dissection: PublicKeyDissection) -> None:
        assert dict(dissection.keyspace)["field_prime_hex"] == f"{FIELD_PRIME:064x}"

    def test_collision_bound(self, dissection: PublicKeyDissection) -> None:
        exponent = dict(dissection.keyspace)["collision_exponent_at_2^64_keys"]
        assert "2^-128" in exponent

    def test_is_json_friendly(self, dissection: PublicKeyDissection) -> None:
        payload = json.loads(json.dumps(dissection.as_dict()))
        assert payload["keyspace"]["curve_order_bits"] == "256"
        assert payload["mirror_point"]["addresses"][0]["address_type"] == "p2pkh"


class TestAddressTypeExtensions:
    def test_nested_segwit_aliases(self) -> None:
        for alias in ("p2sh-p2wpkh", "p2sh_p2wpkh", "nested-segwit", "nested"):
            assert AddressType.parse(alias) is AddressType.P2SH_P2WPKH
