"""Tests for the discrete-logarithm measurement and audit module.

The suite deliberately **breaks weak instances**.  A harness that cannot solve a
discrete logarithm it is supposed to be able to solve proves nothing when it fails
on a hard one, so every algorithm here has a positive control, and every recovered
scalar is verified by substitution into the curve.
"""

from __future__ import annotations

import math

import pytest

from binarycryptolab.dlp import (
    ALGORITHM_FAMILIES,
    CLAIM_REBUTTALS,
    FALSIFIERS,
    ToyCurve,
    _factorize,
    _is_probable_prime,
    assess_dlp_refutation,
    bsgs_dlp,
    build_instance,
    characteristic_audit,
    ecdlp_cost_model,
    field_dlp_cost_model,
    measure_scaling,
    pohlig_hellman_dlp,
    pollard_rho_dlp,
    structural_audit,
)
from binarycryptolab.ecc import CURVE_ORDER, FIELD_PRIME
from binarycryptolab.exceptions import InputValidationError

SMALL_SIZES = (10, 14, 18)


def non_singular(p: int, a: int = 1) -> tuple[int, int]:
    """Return a non-singular ``(a, b)`` pair for the small prime *p*."""
    for b in range(1, 20):
        if (4 * pow(a, 3, p) + 27 * b * b) % p != 0:
            return a, b
    raise AssertionError(f"no non-singular curve over F_{p}")


class TestIntegerHelpers:
    """Primality and factorisation, the foundations everything else rests on."""

    @pytest.mark.parametrize("value", [2, 3, 5, 7, 97, 7919, 104_729])
    def test_primes(self, value: int) -> None:
        assert _is_probable_prime(value) is True

    @pytest.mark.parametrize("value", [0, 1, 4, 9, 91, 7917, 104_730])
    def test_composites(self, value: int) -> None:
        assert _is_probable_prime(value) is False

    def test_curve_order_is_prime(self) -> None:
        assert _is_probable_prime(CURVE_ORDER) is True

    @pytest.mark.parametrize("value", [2, 12, 1001, 55440, 2162160])
    def test_factorisation_multiplies_back(self, value: int) -> None:
        factors = _factorize(value)
        product = 1
        for prime, power in factors.items():
            assert _is_probable_prime(prime)
            product *= prime**power
        assert product == value

    def test_factorisation_rejects_zero(self) -> None:
        with pytest.raises(InputValidationError):
            _factorize(0)


class TestToyCurve:
    """The group law, checked against brute-force enumeration."""

    @pytest.mark.parametrize("p", [7, 13, 19, 31, 97])
    def test_group_law_closes_and_is_associative(self, p: int) -> None:
        a, b = non_singular(p)
        curve = ToyCurve(p=p, a=a, b=b)
        points = curve.points()[:20]
        for left in points[:6]:
            for right in points[:6]:
                total = curve.add(left, right)
                assert curve.is_on_curve(total)
                assert curve.add(left, right) == curve.add(right, left)
                for third in points[:3]:
                    assert curve.add(curve.add(left, right), third) == curve.add(
                        left, curve.add(right, third)
                    )

    @pytest.mark.parametrize("p", [7, 13, 19, 31])
    def test_order_times_any_point_is_infinity(self, p: int) -> None:
        curve = ToyCurve(p=p, a=0, b=1)
        order = curve.group_order_by_enumeration()
        for point in curve.points()[:10]:
            assert curve.mul(order, point) is None

    def test_identity_and_inverse(self) -> None:
        curve = ToyCurve(p=97, a=2, b=5)
        point = curve.points()[0]
        assert curve.add(point, None) == point
        assert curve.add(point, curve.negate(point)) is None

    def test_scalar_multiplication_matches_repeated_addition(self) -> None:
        curve = ToyCurve(p=97, a=2, b=5)
        point = curve.points()[0]
        accumulated = None
        for _ in range(9):
            accumulated = curve.add(accumulated, point)
        assert curve.mul(9, point) == accumulated

    def test_negative_scalar(self) -> None:
        curve = ToyCurve(p=97, a=2, b=5)
        point = curve.points()[0]
        assert curve.mul(-3, point) == curve.negate(curve.mul(3, point))

    def test_singular_curve_is_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            ToyCurve(p=97, a=0, b=0)

    def test_composite_modulus_is_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            ToyCurve(p=91, a=1, b=1)


class TestKnownOrderFamilies:
    """The two supersingular families really do have exactly ``p + 1`` points."""

    @pytest.mark.parametrize("p", [11, 17, 23, 29, 41, 53, 71, 83, 101, 107])
    def test_j0_family_with_p_2_mod_3(self, p: int) -> None:
        if p % 3 != 2:
            pytest.skip("not in the family")
        for coefficient in (1, 2, 3):
            curve = ToyCurve(p=p, a=0, b=coefficient % p)
            assert curve.group_order_by_enumeration() == p + 1

    @pytest.mark.parametrize("p", [7, 11, 19, 23, 31, 43, 47, 59, 67, 71])
    def test_j1728_family_with_p_3_mod_4(self, p: int) -> None:
        if p % 4 != 3:
            pytest.skip("not in the family")
        curve = ToyCurve(p=p, a=-1, b=0)
        assert curve.group_order_by_enumeration() == p + 1

    def test_ordinary_curve_order_is_counted_independently(self) -> None:
        a, b = non_singular(101)
        curve = ToyCurve(p=101, a=a, b=b)
        counted = curve.group_order_by_enumeration()
        # Hasse bound
        assert abs(counted - (curve.p + 1)) <= 2 * math.isqrt(curve.p)
        assert curve.mul(counted, curve.points()[0]) is None


class TestInstanceConstruction:
    """Instances must be certified, not assumed."""

    @pytest.mark.parametrize("bits", SMALL_SIZES)
    def test_instance_is_certified(self, bits: int) -> None:
        instance = build_instance(bits, seed=3)
        assert instance.verify() is True
        assert instance.prime_order is True
        assert instance.order.bit_length() == bits
        assert instance.curve.is_on_curve(instance.generator)

    def test_two_families_agree_on_the_order_relation(self) -> None:
        for family in ("j0", "j1728"):
            instance = build_instance(14, seed=5, family=family)
            assert instance.verify() is True
            assert instance.group_order == instance.curve.p + 1

    def test_enumerated_family_is_ordinary(self) -> None:
        instance = build_instance(10, seed=2, family="enumerated")
        assert instance.verify() is True
        assert instance.curve.a % instance.curve.p != 0

    def test_unknown_family_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            build_instance(12, family="nonsense")

    @pytest.mark.parametrize("bits", [1, 5, 65])
    def test_out_of_range_sizes_rejected(self, bits: int) -> None:
        with pytest.raises(InputValidationError):
            build_instance(bits)

    def test_verify_rejects_a_broken_instance(self) -> None:
        instance = build_instance(12, seed=1)
        broken = type(instance)(
            curve=instance.curve,
            generator=instance.curve.mul(2, instance.generator),
            order=instance.order * 2,
            group_order=instance.group_order,
            trace=instance.trace,
            bits=instance.bits + 1,
            label="broken on purpose",
        )
        assert broken.verify() is False


class TestPollardRho:
    """The measured algorithm, on instances it can and cannot solve."""

    @pytest.mark.parametrize("bits", SMALL_SIZES)
    def test_solves_and_verifies(self, bits: int) -> None:
        instance = build_instance(bits, seed=11)
        secret = 123_456_789 % instance.order
        result = pollard_rho_dlp(instance, instance.public_key_for(secret), seed=1)
        assert result.verified is True
        assert result.scalar == secret
        assert result.steps == 3 * result.iterations

    def test_cost_matches_the_square_root(self) -> None:
        instance = build_instance(24, seed=4)
        result = pollard_rho_dlp(instance, instance.public_key_for(999_983), seed=2)
        ratio = result.steps / math.sqrt(instance.order)
        assert 0.5 < ratio < 12.0, ratio

    def test_reports_failure_instead_of_guessing(self) -> None:
        instance = build_instance(20, seed=8)
        result = pollard_rho_dlp(
            instance, instance.public_key_for(424242), seed=0, max_steps=2, max_restarts=0
        )
        assert result.scalar is None
        assert result.verified is False

    def test_requires_prime_order(self) -> None:
        smooth = build_instance(12, seed=1)
        broken = type(smooth)(
            curve=smooth.curve,
            generator=smooth.generator,
            order=12,
            group_order=smooth.group_order,
            trace=smooth.trace,
            bits=4,
            label="composite on purpose",
        )
        with pytest.raises(InputValidationError):
            pollard_rho_dlp(broken, broken.generator)

    def test_two_partitions_rejected(self) -> None:
        instance = build_instance(10, seed=1)
        with pytest.raises(InputValidationError):
            pollard_rho_dlp(instance, instance.generator, partitions=1)


class TestBabyStepGiantStep:
    """The memory-bound reference method."""

    def test_agrees_with_rho(self) -> None:
        instance = build_instance(16, seed=6)
        secret = 987_654 % instance.order
        target = instance.public_key_for(secret)
        result = bsgs_dlp(instance, target)
        assert result.verified is True
        assert result.scalar == secret
        width = math.isqrt(instance.order) + 1
        assert result.table_entries <= width
        assert result.table_entries >= width - 2

    def test_memory_is_the_square_root(self) -> None:
        instance = build_instance(20, seed=6)
        result = bsgs_dlp(instance, instance.public_key_for(12345))
        assert abs(result.table_entries - math.sqrt(instance.order)) < 0.05 * math.sqrt(
            instance.order
        )

    def test_table_limit_is_enforced(self) -> None:
        instance = build_instance(24, seed=6)
        with pytest.raises(InputValidationError):
            bsgs_dlp(instance, instance.public_key_for(1), max_entries=10)


class TestPohligHellman:
    """The positive control: smooth structure *is* exploited."""

    def test_breaks_a_smooth_order_quickly(self) -> None:
        from binarycryptolab.dlp import _smooth_instance

        instance = _smooth_instance()
        assert instance.prime_order is False
        secret = 123_457 % instance.order
        result = pohlig_hellman_dlp(instance, instance.public_key_for(secret))
        assert result.verified is True
        assert result.scalar == secret
        assert result.steps < math.sqrt(instance.order)

    def test_refuses_a_prime_order(self) -> None:
        instance = build_instance(24, seed=9)
        with pytest.raises(InputValidationError):
            pohlig_hellman_dlp(instance, instance.public_key_for(7), limit=1000)

    def test_secp256k1_has_nothing_to_split(self) -> None:
        assert _is_probable_prime(CURVE_ORDER)
        assert max(_factorize(CURVE_ORDER)) == CURVE_ORDER


class TestScalingStudy:
    """The measurement campaign and its fit."""

    @pytest.fixture(scope="class")
    @classmethod
    def study(cls):
        return measure_scaling((10, 14, 18), trials=4, seed=2)

    def test_slope_is_a_half(self, study) -> None:
        assert 0.3 < study.fit.slope < 0.7
        assert study.fit.r_squared > 0.85

    def test_every_point_is_measured(self, study) -> None:
        assert [point.bits for point in study.fit.points] == [10, 14, 18]
        assert all(point.trials == 4 for point in study.fit.points)

    def test_min_and_max_bracket_the_median(self, study) -> None:
        for point in study.fit.points:
            assert point.min_steps <= point.median_steps <= point.max_steps

    def test_bsgs_rows_are_consistent(self, study) -> None:
        for bits, entries, steps in study.bsgs_comparison:
            assert entries > 0 and steps > 0
            instance_order = 2**bits
            assert entries < 4 * math.sqrt(instance_order) * 2

    def test_positive_control_is_recorded(self, study) -> None:
        assert study.pohlig_hellman["recovered"] is True
        assert int(study.pohlig_hellman["order"]) > 10**6

    def test_extrapolation_is_reported_with_its_error(self, study) -> None:
        payload = study.as_dict()
        assert payload["fit"]["slope_standard_error"] > 0
        assert payload["fit"]["extrapolated_log2_cost_at_256_bits"] > 0

    def test_zero_trials_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            measure_scaling((10, 14), trials=0)

    def test_single_size_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            measure_scaling((10,), trials=2)

    def test_notes_are_honest(self, study) -> None:
        joined = " ".join(study.notes)
        assert "verified" in joined
        assert "not a proof" in joined


class TestCostModels:
    """The two cost models, and the contrast that motivates the paper."""

    def test_ecdlp_is_a_half_exponent(self) -> None:
        model = ecdlp_cost_model(256)
        assert 127 < model["log2_operations"] < 130

    def test_field_dlp_is_sub_exponential(self) -> None:
        model = field_dlp_cost_model(256)
        assert 40 < model["log2_operations"] < 55

    def test_the_contrast_is_large(self) -> None:
        assert (
            ecdlp_cost_model(256)["log2_operations"] - field_dlp_cost_model(256)["log2_operations"]
            > 60
        )

    def test_models_grow_with_size(self) -> None:
        assert ecdlp_cost_model(200)["log2_operations"] < ecdlp_cost_model(300)["log2_operations"]
        assert (
            field_dlp_cost_model(1024)["log2_operations"]
            < field_dlp_cost_model(2048)["log2_operations"]
        )

    def test_small_sizes_rejected(self) -> None:
        with pytest.raises(InputValidationError):
            field_dlp_cost_model(4)
        with pytest.raises(InputValidationError):
            ecdlp_cost_model(4)


class TestStructuralAudit:
    """Every audited property must be measurable and must not be exploitable."""

    @pytest.fixture(scope="class")
    @classmethod
    def audit(cls):
        return structural_audit()

    def test_nothing_is_exploitable(self, audit) -> None:
        assert audit.exploitable == ()

    def test_codes_are_unique(self, audit) -> None:
        codes = [finding.code for finding in audit.findings]
        assert len(codes) == len(set(codes))

    def test_every_finding_carries_a_measurement(self, audit) -> None:
        for finding in audit.findings:
            assert finding.measured
            assert finding.verdict

    def test_curve_facts_are_really_checked(self) -> None:
        findings = {finding.code: finding for finding in structural_audit().findings}
        assert "is prime: True" in findings["group_order_prime"].measured
        assert "True" in findings["no_small_embedding_degree"].measured
        assert "!= 0" in findings["not_anomalous"].measured

    def test_characteristic_audit(self) -> None:
        payload = characteristic_audit()
        assert payload["field_prime_bits"] == 256
        assert payload["group_order_bits"] == 256
        assert payload["cofactor"] == 1
        assert payload["trace"] == CURVE_ORDER - FIELD_PRIME


class TestAlgorithmRegistry:
    """The registry must cover the families and never overclaim."""

    def test_every_family_has_a_reference(self) -> None:
        for family in ALGORITHM_FAMILIES:
            assert family.reference
            assert family.why

    def test_codes_are_unique(self) -> None:
        codes = [family.code for family in ALGORITHM_FAMILIES]
        assert len(codes) == len(set(codes))

    def test_only_glv_applies(self) -> None:
        applicable = {family.code for family in ALGORITHM_FAMILIES if family.applies_to_secp256k1}
        assert applicable == {"glv"}

    def test_glv_is_labelled_as_a_constant_factor(self) -> None:
        glv = next(family for family in ALGORITHM_FAMILIES if family.code == "glv")
        assert "factor 2" in glv.complexity
        assert "exponent stays" in glv.why

    def test_every_family_is_json_ready(self) -> None:
        payload = [family.as_dict() for family in ALGORITHM_FAMILIES]
        assert all("complexity" in row for row in payload)


class TestClaimsAndFalsifiers:
    """The paper's argument in machine-readable form."""

    def test_claims_are_unique_and_referenced(self) -> None:
        codes = [rebuttal.code for rebuttal in CLAIM_REBUTTALS]
        assert len(codes) == len(set(codes))
        for rebuttal in CLAIM_REBUTTALS:
            assert rebuttal.why_it_fails
            assert rebuttal.evidence
            assert rebuttal.reference

    def test_falsifiers_are_actionable(self) -> None:
        assert len(FALSIFIERS) >= 4
        for falsifier in FALSIFIERS:
            assert falsifier.detection
            assert falsifier.would_mean

    def test_signature_falsifier_is_present(self) -> None:
        codes = {falsifier.code for falsifier in FALSIFIERS}
        assert "signature_from_public_key" in codes


class TestAssessment:
    """The conclusion, and the property that it is derived rather than asserted."""

    @pytest.fixture(scope="class")
    @classmethod
    def assessment(cls):
        return assess_dlp_refutation(study=measure_scaling((10, 14, 18), trials=3, seed=4))

    def test_verdict_is_not_refuted(self, assessment) -> None:
        assert assessment.verdict == "not refuted"
        assert assessment.refuted is False

    def test_evidence_is_quantitative(self, assessment) -> None:
        joined = " ".join(assessment.evidence)
        assert "exponent" in joined
        assert "2^" in joined

    def test_scope_is_stated(self, assessment) -> None:
        assert len(assessment.scope) >= 3
        assert any("classical" in item for item in assessment.scope)

    def test_confidence_does_not_claim_proof(self, assessment) -> None:
        assert "not a proof" in assessment.confidence

    def test_serialisation_round_trips(self, assessment) -> None:
        payload = assessment.as_dict()
        assert payload["verdict"] == "not refuted"
        assert payload["audit"]["exploitable_count"] == 0
        assert payload["address_case"] is None
        assert len(payload["rebuttals"]) == len(CLAIM_REBUTTALS)

    def test_address_case_is_attached(self) -> None:
        assessment = assess_dlp_refutation(
            study=measure_scaling((10, 14), trials=2, seed=0),
            address="1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa",
        )
        assert assessment.address_case is not None
        assert assessment.address_case["total_cost_log2"] == pytest.approx(288.0)
        steps = assessment.address_case["backward_chain"]
        assert len(steps) == 3
        assert steps[-1]["cost_log2"] == pytest.approx(128.0)

    def test_verdict_would_change_if_the_audit_found_something(self, monkeypatch) -> None:
        """The verdict is computed from the audit, not hard-coded."""
        from binarycryptolab import dlp

        original = dlp.structural_audit

        def exploitable_audit():
            audit = original()
            broken = type(audit.findings[0])(
                code="invented",
                property="a fictional weakness",
                measured="invented for the test",
                exploitable=True,
                verdict="would matter",
            )
            return type(audit)(findings=(*audit.findings, broken))

        monkeypatch.setattr(dlp, "structural_audit", exploitable_audit)
        assessment = dlp.assess_dlp_refutation(study=measure_scaling((10, 14), trials=1, seed=0))
        assert assessment.verdict == "refuted"
        assert assessment.refuted is True
