"""Guard the paper's reproduction driver.

The paper makes numerical claims.  A claim is only worth something if the script
that produced it still runs, still writes every artefact it advertises, and still
produces the same numbers as the committed snapshots.  These tests run
``paper/reproduce.py`` end to end into ``tmp_path`` (so the committed data is never
modified) and then check the results against the paper's own claims.

The run takes a few seconds: it solves six toy instances fifteen times each and one
smooth-order instance, which is the whole measurement.
"""

from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAPER = REPO_ROOT / "paper"
EXPECTED_JSON = ("measurement", "assessment", "cost_models", "audit", "claims")
EXPECTED_SVG = ("fig_scaling", "fig_costs", "fig_control")


@pytest.fixture(scope="module")
def paper(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    """Import ``paper/reproduce.py`` and point its writers at a temporary directory."""
    path = PAPER / "reproduce.py"
    assert path.is_file(), "the reproduction driver must exist"
    spec = importlib.util.spec_from_file_location("bcl_paper_reproduce", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    out = tmp_path_factory.mktemp("paper")
    module.DATA = out / "data"
    module.FIGURES = out / "figures"
    assert module.main() == 0
    module.OUT = out
    return module


def load(directory: Path, name: str) -> dict:
    return json.loads((directory / "data" / f"{name}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Artefacts exist and are well formed
# ---------------------------------------------------------------------------


def test_every_artefact_is_written(paper: ModuleType) -> None:
    out: Path = paper.OUT
    for name in EXPECTED_JSON:
        path = out / "data" / f"{name}.json"
        assert path.is_file(), f"{name}.json was not written"
        assert json.loads(path.read_text(encoding="utf-8")), f"{name}.json is empty"
    for name in EXPECTED_SVG:
        path = out / "figures" / f"{name}.svg"
        assert path.is_file(), f"{name}.svg was not written"
        markup = path.read_text(encoding="utf-8")
        assert markup.startswith("<svg")
        assert markup.rstrip().endswith("</svg>")
        assert "nan" not in markup.lower()
        assert "None" not in markup
        assert len(markup) > 900


def test_committed_snapshots_are_current(paper: ModuleType) -> None:
    """The data checked into the repository must match what the code produces today."""
    for name in EXPECTED_JSON:
        fresh = load(paper.OUT, name)
        committed = load(PAPER, name)
        assert fresh == committed, f"paper/data/{name}.json is stale; re-run the driver"


# ---------------------------------------------------------------------------
# The measurement says what the paper says it says
# ---------------------------------------------------------------------------


def test_fit_matches_the_generic_group_model(paper: ModuleType) -> None:
    fit = load(paper.OUT, "measurement")["fit"]
    assert fit["expected_slope"] == 0.5
    assert 0.45 <= fit["slope"] <= 0.55
    assert 0.0 < fit["slope_standard_error"] < 0.05
    assert fit["r_squared"] > 0.98
    assert abs(fit["z_score"]) < 3.0
    assert fit["agrees_with_generic_group_model"] is True
    # A 256-bit extrapolation of the measured law lands near rho's 2^128 constant.
    assert 126.0 <= fit["extrapolated_log2_cost_at_256_bits"] <= 131.0


def test_measurement_points_are_complete_and_ordered(paper: ModuleType) -> None:
    study = load(paper.OUT, "measurement")
    points = study["fit"]["points"]
    assert [point["bits"] for point in points] == [12, 16, 20, 24, 28, 32]
    assert len(points) == 6
    medians = [point["median_steps"] for point in points]
    assert medians == sorted(medians)
    for point in points:
        assert point["trials"] == 15
        assert point["min_steps"] <= point["median_steps"] <= point["max_steps"]
        # Every trial is verified before it is counted, so a broken run shows up as a
        # ratio far from 1 rather than as a plausible-looking average.
        assert 0.5 <= point["ratio_to_prediction"] <= 2.0
        # The prediction is 3.76*sqrt(q) for the instance's own order q, so the ratio
        # must be exactly the median divided by that prediction.
        ratio = point["median_steps"] / point["predicted_sqrt_scaling"]
        assert point["ratio_to_prediction"] == pytest.approx(ratio, rel=1e-9)
        assert (
            0.1 * math.sqrt(2 ** point["bits"])
            <= point["predicted_sqrt_scaling"]
            <= 10 * math.sqrt(2 ** point["bits"])
        )


def test_bsgs_costs_are_consistent_with_its_name(paper: ModuleType) -> None:
    rows = load(paper.OUT, "measurement")["bsgs_comparison"]
    assert [row["bits"] for row in rows] == [12, 16, 20, 24, 28, 32]
    for row in rows:
        table_limit = math.isqrt(2 ** row["bits"]) + 1
        assert 0 < row["table_entries"] <= table_limit
        assert 0 < row["steps"] <= 2 * table_limit + 2


def test_smooth_order_control_recovers_the_scalar(paper: ModuleType) -> None:
    control = load(paper.OUT, "measurement")["pohlig_hellman"]
    order = int(control["order"])
    assert order == 2_162_160
    assert control["recovered"] is True
    assert control["scalar_verified"] is True
    assert control["steps"] < 4_000, "a smooth order must collapse, not be searched"
    assert control["steps"] < 3.76 * math.sqrt(order) / 100


# ---------------------------------------------------------------------------
# The conclusion, the audit, and the falsifiers
# ---------------------------------------------------------------------------


def test_verdict_is_not_refuted_and_says_why(paper: ModuleType) -> None:
    assessment = load(paper.OUT, "assessment")
    assert assessment["verdict"] == "not refuted"
    assert assessment["audit"]["exploitable_count"] == 0
    assert len(assessment["audit"]["findings"]) == 10
    assert len(assessment["evidence"]) >= 4
    assert len(assessment["falsifiers"]) == 5
    assert any("exponent" in line for line in assessment["evidence"])


def test_every_audited_property_carries_its_measurement(paper: ModuleType) -> None:
    audit = load(paper.OUT, "audit")
    assert audit["exploitable_count"] == 0
    for finding in audit["findings"]:
        assert finding["exploitable"] is False
        assert finding["measured"].strip(), "an audit row without a measurement is an opinion"
        assert finding["verdict"].strip()


def test_rebuttals_and_falsifiers_are_both_present(paper: ModuleType) -> None:
    claims = load(paper.OUT, "claims")
    codes = {claim["code"] for claim in claims["claims"]}
    assert codes == {
        "index_calculus",
        "pohlig_hellman",
        "glv_speedup",
        "brute_force_scale",
        "quantum",
        "statistical_structure",
        "side_channel",
        "published_proof",
    }
    assert len(claims["falsifiers"]) == 5
    for entry in claims["claims"]:
        assert (
            entry["claim"].strip() and entry["why_it_fails"].strip() and entry["evidence"].strip()
        )
    for entry in claims["falsifiers"]:
        assert entry["observation"].strip() and entry["detection"].strip()


def test_cost_models_separate_the_two_problems(paper: ModuleType) -> None:
    models = load(paper.OUT, "cost_models")
    ecdlp = models["ecdlp_256"]["log2_operations"]
    field = (
        models["field_dlp"]["log2_operations"]
        if isinstance(models["field_dlp"], dict)
        else models["field_dlp"]
    )
    assert ecdlp == pytest.approx(128.32, abs=0.01)
    assert field == pytest.approx(46.66, abs=0.01)
    # The finite-field problem is the weak one; that gap is the whole contrast.
    assert field + 60 < ecdlp < field + 100
    assert models["address_preimage"] == 160.0
    assert models["address_stage_sum"] == 288.0


def test_figures_draw_the_points_they_claim(paper: ModuleType) -> None:
    out: Path = paper.OUT
    scaling = (out / "figures" / "fig_scaling.svg").read_text(encoding="utf-8")
    assert scaling.count("<circle") == 6, "one marker per measured size"
    costs = (out / "figures" / "fig_costs.svg").read_text(encoding="utf-8")
    assert costs.count("<rect") >= 8, "one bar per attack plus the background"
    assert "HASH160" in costs
    control = (out / "figures" / "fig_control.svg").read_text(encoding="utf-8")
    assert "Pohlig" in control
    assert "2,162,160" in control


def test_the_driver_never_touches_the_256_bit_curve(paper: ModuleType) -> None:
    """The largest instance is a 32-bit toy; attacking secp256k1 is not attempted."""
    source = (PAPER / "reproduce.py").read_text(encoding="utf-8")
    assert "measure_scaling(SIZES" in source
    assert max(paper.SIZES) <= 64
    assert paper.TRIALS >= 5
