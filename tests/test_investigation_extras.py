"""Tests for script recovery, address comparison, mining economics, and the plan.

The recovery tests build the address *from* the enumerated script, so a hash bug
cannot pass. The mining tests check the arithmetic against the probability module
and assert the measured rate is a positive real number, never a constant.
"""

from __future__ import annotations

import json

import pytest

from binarycryptolab.address_compare import compare_addresses
from binarycryptolab.address_forensics import (
    base58_prefix_probability,
    dissect_address,
    vanity_report,
)
from binarycryptolab.base58 import base58check_encode
from binarycryptolab.bech32 import encode_segwit_address
from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.hashing import hash160, sha256
from binarycryptolab.investigation import build_plan
from binarycryptolab.mining import (
    benchmark_derivation,
    estimate_prefix_mining,
    verify_prefix_claim,
)
from binarycryptolab.script_recovery import (
    CandidateKey,
    enumerate_candidate_scripts,
    recover_script,
)

TARGET = "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa"
KEY_A = "02" + "11" * 32
KEY_B = "02" + "22" * 32
KEY_C = "03" + "33" * 32


def p2sh_of(script_hex: str) -> str:
    """Return the mainnet P2SH address committing to *script_hex*."""
    return base58check_encode(b"\x05" + hash160(bytes.fromhex(script_hex)))


class TestCandidateKeys:
    """Validation of supplied keys."""

    def test_compressed_key(self) -> None:
        key = CandidateKey(KEY_A, "cosigner A")
        assert key.compressed == KEY_A
        assert len(key.hash160) == 40
        assert key.label == "cosigner A"

    def test_uncompressed_key_is_compressed(self) -> None:
        uncompressed = (
            "04"
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        )
        key = CandidateKey(uncompressed)
        assert len(key.compressed) == 66
        assert key.hash160 == key.hash160.lower()

    def test_whitespace_and_prefix_are_tolerated(self) -> None:
        messy = "0x" + KEY_A[:20] + " " + KEY_A[20:]
        assert CandidateKey(messy).public_key_hex == KEY_A

    @pytest.mark.parametrize("bad", ["", "00", "not-a-key", "04" + "11" * 32])
    def test_invalid_keys(self, bad: str) -> None:
        with pytest.raises(InputValidationError):
            CandidateKey(bad)

    def test_as_dict(self) -> None:
        assert CandidateKey(KEY_A).as_dict()["public_key_hex"] == KEY_A


class TestEnumeration:
    """The template catalogue."""

    def test_single_key_gives_p2pk_and_one_of_one(self) -> None:
        scripts = enumerate_candidate_scripts((CandidateKey(KEY_A),))
        templates = [item[0] for item in scripts]
        assert templates.count("p2pk") == 1
        assert "multisig" in templates

    def test_three_keys_expand_every_subset(self) -> None:
        scripts = enumerate_candidate_scripts(
            (CandidateKey(KEY_A), CandidateKey(KEY_B), CandidateKey(KEY_C))
        )
        multisig = [item for item in scripts if item[0] == "multisig"]
        # 3 singletons + 3 pairs x 2 thresholds + 1 triple x 3 thresholds
        assert len(multisig) == 3 + 6 + 3
        assert any(item[1] == "2-of-3 multisig" for item in multisig)

    def test_timelock_templates(self) -> None:
        scripts = enumerate_candidate_scripts(
            (CandidateKey(KEY_A),), timelock_values=(500, 800_000)
        )
        assert sum(1 for item in scripts if item[0] == "timelock") == 2

    def test_htlc_templates(self) -> None:
        scripts = enumerate_candidate_scripts(
            (CandidateKey(KEY_A), CandidateKey(KEY_B)), hash_locks=("aa" * 20,)
        )
        assert sum(1 for item in scripts if item[0] == "htlc") == 2

    def test_budget_is_enforced(self) -> None:
        scripts = enumerate_candidate_scripts(
            (CandidateKey(KEY_A), CandidateKey(KEY_B), CandidateKey(KEY_C)),
            max_candidates=4,
        )
        assert len(scripts) == 4

    def test_no_keys(self) -> None:
        with pytest.raises(InputValidationError):
            enumerate_candidate_scripts(())

    def test_too_many_keys(self) -> None:
        keys = tuple(CandidateKey(f"02{index:02x}" + "11" * 31) for index in range(16))
        with pytest.raises(InputValidationError, match="at most"):
            enumerate_candidate_scripts(keys)

    def test_invalid_hash_lock(self) -> None:
        with pytest.raises(InputValidationError, match="hash lock"):
            enumerate_candidate_scripts((CandidateKey(KEY_A),), hash_locks=("zz",))


class TestRecovery:
    """End-to-end recovery against addresses built from the scripts."""

    def test_recovers_2_of_3_multisig(self) -> None:
        keys = [CandidateKey(KEY_A, "A"), CandidateKey(KEY_B, "B"), CandidateKey(KEY_C, "C")]
        scripts = enumerate_candidate_scripts(tuple(keys))
        script = next(item[2] for item in scripts if item[1] == "2-of-3 multisig")
        address = p2sh_of(script)
        report = recover_script(address, keys)
        assert report.recovered is True
        assert report.matches[0].summary == "2-of-3 multisig"
        assert report.matches[0].script_hex == script
        assert "recovered" in report.verdict

    def test_recovers_witness_script(self) -> None:
        keys = [CandidateKey(KEY_A), CandidateKey(KEY_B)]
        scripts = enumerate_candidate_scripts(tuple(keys))
        script = next(item[2] for item in scripts if item[1] == "2-of-2 multisig")
        address = encode_segwit_address("bc", 0, sha256(bytes.fromhex(script)))
        report = recover_script(address, keys)
        assert report.recovered is True

    def test_recovers_key_level_for_p2pkh(self) -> None:
        address = base58check_encode(b"\x00" + hash160(bytes.fromhex(KEY_A)))
        report = recover_script(address, [CandidateKey(KEY_A, "mine")])
        assert report.recovered is True
        assert report.key_matches[0].label == "mine"
        assert "key level" in report.verdict

    def test_recovers_p2pk(self) -> None:
        address = f"21{KEY_A}ac"
        report = recover_script(address, [CandidateKey(KEY_A)])
        assert report.recovered is True

    def test_miss_on_the_target_address(self) -> None:
        report = recover_script(TARGET, [CandidateKey(KEY_A), CandidateKey(KEY_B)])
        assert report.recovered is False
        assert "not derived from any of them" in report.verdict

    def test_miss_on_a_foreign_multisig(self) -> None:
        other = [CandidateKey("02" + "44" * 32), CandidateKey("02" + "55" * 32)]
        script = next(
            item[2]
            for item in enumerate_candidate_scripts(tuple(other))
            if item[1] == "2-of-2 multisig"
        )
        report = recover_script(p2sh_of(script), [CandidateKey(KEY_A), CandidateKey(KEY_B)])
        assert report.recovered is False
        assert "script may use a key you did not supply" in report.verdict

    def test_truncation_is_reported_as_inconclusive(self) -> None:
        other = [CandidateKey("02" + "44" * 32), CandidateKey("02" + "55" * 32)]
        script = next(
            item[2]
            for item in enumerate_candidate_scripts(tuple(other))
            if item[1] == "2-of-2 multisig"
        )
        report = recover_script(
            p2sh_of(script),
            [CandidateKey(KEY_A), CandidateKey(KEY_B), CandidateKey(KEY_C)],
            max_candidates=2,
        )
        assert report.truncated is True
        assert "inconclusive" in report.verdict

    def test_htlc_recovery_with_a_hash_lock(self) -> None:
        lock = "aa" * 20
        keys = [CandidateKey(KEY_A), CandidateKey(KEY_B)]
        scripts = enumerate_candidate_scripts(tuple(keys), hash_locks=(lock,))
        script = next(item[2] for item in scripts if item[0] == "htlc")
        report = recover_script(p2sh_of(script), keys, hash_locks=(lock,))
        assert report.recovered is True
        assert report.matches[0].template == "htlc"

    def test_empty_keys(self) -> None:
        with pytest.raises(InputValidationError):
            recover_script(TARGET, [])

    def test_json_safe(self) -> None:
        report = recover_script(TARGET, [CandidateKey(KEY_A)])
        json.dumps(report.as_dict(), allow_nan=False)


class TestComparison:
    """Address-to-address relations."""

    def test_same_payload_across_networks(self) -> None:
        payload = bytes(range(20))
        mainnet = base58check_encode(b"\x00" + payload)
        testnet = base58check_encode(b"\x6f" + payload)
        result = compare_addresses([mainnet, testnet])
        kinds = [relation.kind for relation in result.relations]
        assert kinds == ["same_payload"]
        assert "reuse across chains" in result.relations[0].explanation

    def test_nested_script(self) -> None:
        payload = bytes(range(20))
        native = encode_segwit_address("bc", 0, payload)
        script = "0014" + payload.hex()
        nested = base58check_encode(b"\x05" + hash160(bytes.fromhex(script)))
        result = compare_addresses([nested, native])
        assert any(relation.kind == "nested_script" for relation in result.relations)

    def test_identical_address(self) -> None:
        result = compare_addresses([TARGET, TARGET])
        assert result.relations[0].kind == "same_address"

    def test_unrelated_addresses(self) -> None:
        result = compare_addresses([TARGET, "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"])
        assert result.relations == ()
        assert "unrelated" in result.verdict

    def test_shared_bits_are_probabilistic(self) -> None:
        # Two payloads sharing 20 leading bits of 160.
        left = base58check_encode(b"\x00" + bytes.fromhex("abcdef" + "11" * 17))
        right = base58check_encode(b"\x00" + bytes.fromhex("abcde0" + "22" * 17))
        result = compare_addresses([left, right])
        shared = [item for item in result.relations if item.kind == "shared_bits"]
        assert shared
        assert shared[0].probability is not None
        assert shared[0].probability <= 1.0

    def test_too_few(self) -> None:
        with pytest.raises(InputValidationError):
            compare_addresses([TARGET])

    def test_json_safe(self) -> None:
        result = compare_addresses([TARGET, "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb"])
        json.dumps(result.as_dict(), allow_nan=False)


class TestMining:
    """The economy of prefixes."""

    def test_benchmark_is_positive_and_real(self) -> None:
        rate = benchmark_derivation(iterations=16)
        assert rate.iterations == 16
        assert rate.per_second > 0
        assert rate.elapsed_seconds > 0
        assert rate.seconds_per_attempt == pytest.approx(1 / rate.per_second)

    @pytest.mark.parametrize("kind", ["p2pkh", "p2wpkh", "p2sh-p2wpkh"])
    def test_every_derivation_type(self, kind: str) -> None:
        assert benchmark_derivation(address_type=kind, iterations=8).per_second > 0

    def test_invalid_type(self) -> None:
        with pytest.raises(InputValidationError):
            benchmark_derivation(address_type="p2tr", iterations=4)

    def test_invalid_iterations(self) -> None:
        with pytest.raises(InputValidationError):
            benchmark_derivation(iterations=0)
        with pytest.raises(InputValidationError):
            benchmark_derivation(iterations=5001)

    def test_estimate_matches_the_probability_module(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(TARGET, prefix="1BEwWK", rate=rate)
        expected = base58_prefix_probability("1BEwWK", version=0)
        assert estimate.probability == pytest.approx(expected)
        assert estimate.expected_attempts == pytest.approx(1 / expected)
        assert estimate.expected_seconds_measured == pytest.approx(
            estimate.expected_attempts / rate.per_second
        )

    def test_bits_are_consistent_with_vanity_report(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(TARGET, prefix="1BEwWK", rate=rate)
        report = vanity_report(TARGET, claimed_prefix="1BEwWK")
        assert estimate.constrained_bits == report.constrained_bits

    def test_rate_table_is_ordered(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(TARGET, rate=rate)
        seconds = [row[1] for row in estimate.rate_table]
        assert seconds == sorted(seconds, reverse=True)

    def test_cheap_prefix_verdict(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(TARGET, prefix="1B", rate=rate)
        assert "cheap" in estimate.verdict

    def test_impossible_prefix(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(TARGET, prefix="3BEw", rate=rate)
        assert estimate.probability == 0.0
        assert "cannot occur" in estimate.verdict
        assert estimate.expected_attempts == float("inf")

    def test_segwit_estimate(self) -> None:
        rate = benchmark_derivation(iterations=8)
        estimate = estimate_prefix_mining(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", prefix="bc1qw508", rate=rate
        )
        assert estimate.encoding == "bech32"
        assert estimate.constrained_bits == 20

    def test_verify_prefix_claim(self) -> None:
        payload = verify_prefix_claim(TARGET, "1BEw")
        assert payload["matches"] is True
        assert 0 < payload["probability"] < 1

    def test_verify_prefix_claim_miss(self) -> None:
        assert verify_prefix_claim(TARGET, "1ZZZ")["matches"] is False

    def test_json_safe(self) -> None:
        rate = benchmark_derivation(iterations=8)
        json.dumps(estimate_prefix_mining(TARGET, rate=rate).as_dict())


class TestPlan:
    """The investigation plan."""

    def test_p2pkh_plan(self) -> None:
        plan = build_plan(dissect_address(TARGET))
        codes = [lead.code for lead in plan.leads]
        assert codes[0] == "prefix_economics"
        assert "controlled_experiment" in codes
        assert codes[-1] == "private_key"
        assert plan.leads[-1].effort == "infeasible"
        assert plan.closed

    def test_p2sh_plan_starts_with_script_recovery(self) -> None:
        payload = bytes(range(20))
        nested = base58check_encode(b"\x05" + hash160(b"\x00\x14" + payload))
        plan = build_plan(dissect_address(nested))
        assert any(lead.code == "recover_script" for lead in plan.leads)
        assert "recover" in plan.summary.lower()

    def test_every_lead_has_its_limit(self) -> None:
        plan = build_plan(dissect_address(TARGET))
        assert all(lead.does_not_prove for lead in plan.leads)
        assert all(lead.proves for lead in plan.leads)

    def test_effort_order(self) -> None:
        plan = build_plan(dissect_address(TARGET))
        effort = [lead.effort for lead in plan.leads]
        ranks = {"none": 0, "seconds": 1, "minutes": 2, "hours": 3, "infeasible": 4}
        assert [ranks[item] for item in effort] == sorted(ranks[item] for item in effort)

    def test_plan_is_in_the_dissection_json(self) -> None:
        payload = dissect_address(TARGET).as_dict()
        assert payload["plan"]["leads"]
        json.dumps(payload, allow_nan=False)

    def test_commands_are_copy_pasteable(self) -> None:
        plan = build_plan(dissect_address(TARGET))
        commands = [lead.command for lead in plan.leads if lead.command]
        assert commands
        assert all(command.startswith("binarycryptolab ") for command in commands)
        assert all(TARGET in command for command in commands)
