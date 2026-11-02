#!/usr/bin/env python3
"""Regenerate every number and figure in the paper.

Run from the repository root:

    python paper/reproduce.py

The script writes ``paper/data/*.json`` and ``paper/figures/*.svg``.  Nothing is
fetched from the network, and the 256-bit curve is never attacked: the measurement
runs on toy instances whose order is small enough to solve to completion.
"""

# ruff: noqa: T201  (this is a report driver: printing the measured values is the point)
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from binarycryptolab.dlp import (
    CLAIM_REBUTTALS,
    FALSIFIERS,
    assess_dlp_refutation,
    ecdlp_cost_model,
    field_dlp_cost_model,
    measure_scaling,
    structural_audit,
)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
FIGURES = ROOT / "figures"
TARGET = "1BEwWKUgvRffDWZFdnj2FLtEXxCVo1ACAa"
SIZES = (12, 16, 20, 24, 28, 32)
TRIALS = 15


# ---------------------------------------------------------------------------
# A minimal SVG writer: no plotting dependency, exact coordinates in the file
# ---------------------------------------------------------------------------


class Svg:
    """Accumulate SVG elements and serialise them."""

    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        self.parts: list[str] = []

    def add(self, markup: str) -> None:
        self.parts.append(markup)

    def text(
        self, x: float, y: float, value: str, *, size: int = 12, anchor: str = "start"
    ) -> None:
        self.add(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="DejaVu Sans, Arial, sans-serif" '
            f'font-size="{size}" text-anchor="{anchor}" fill="#1b1b1b">{escape(value)}</text>'
        )

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        width: float = 1.2,
        colour: str = "#333",
        dash: str = "",
    ) -> None:
        extra = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{colour}" stroke-width="{width}"{extra}/>'
        )

    def circle(self, x: float, y: float, radius: float, *, colour: str = "#0b6e99") -> None:
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{colour}"/>')

    def rect(
        self, x: float, y: float, width: float, height: float, *, colour: str = "#0b6e99"
    ) -> None:
        self.add(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" fill="{colour}"/>'
        )

    def write(self, path: Path) -> None:
        body = "\n".join(self.parts)
        path.write_text(
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}" '
            f'viewBox="0 0 {self.width} {self.height}">\n'
            f'<rect width="{self.width}" height="{self.height}" fill="#ffffff"/>\n'
            f"{body}\n</svg>\n",
            encoding="utf-8",
        )


def escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def figure_scaling(study: dict, path: Path) -> None:
    """Log-log plot of measured steps against instance size, with the fitted line."""
    fit = study["fit"]
    points = fit["points"]
    width, height = 720, 480
    left, right, top, bottom = 90, 40, 60, 70
    svg = Svg(width, height)

    xs = [point["bits"] for point in points]
    ys = [math.log2(point["median_steps"]) for point in points]
    x_min, x_max = min(xs) - 2, max(xs) + 2
    y_min, y_max = math.floor(min(ys)) - 1, math.ceil(max(ys)) + 1

    def px(value: float) -> float:
        return left + (value - x_min) / (x_max - x_min) * (width - left - right)

    def py(value: float) -> float:
        return height - bottom - (value - y_min) / (y_max - y_min) * (height - top - bottom)

    svg.text(
        width / 2,
        30,
        "Measured cost of Pollard rho against instance size",
        size=17,
        anchor="middle",
    )
    svg.line(left, height - bottom, width - right, height - bottom)
    svg.line(left, top, left, height - bottom)

    for tick in range(math.ceil(x_min), math.floor(x_max) + 1, 4):
        svg.line(px(tick), height - bottom, px(tick), height - bottom + 5)
        svg.text(px(tick), height - bottom + 20, str(tick), size=11, anchor="middle")
    for tick in range(y_min, y_max + 1):
        svg.line(left - 5, py(tick), left, py(tick))
        svg.text(left - 10, py(tick) + 4, str(tick), size=11, anchor="end")

    # fitted line
    x1, x2 = x_min + 2, x_max - 2
    svg.line(
        px(x1),
        py(fit["slope"] * x1 + fit["intercept"]),
        px(x2),
        py(fit["slope"] * x2 + fit["intercept"]),
        width=2.0,
        colour="#c0392b",
    )
    # reference slope 0.5 through the first measured point
    anchor_x = points[0]["bits"]
    anchor_y = math.log2(points[0]["median_steps"])
    svg.line(
        px(x1),
        py(anchor_y + 0.5 * (x1 - anchor_x)),
        px(x2),
        py(anchor_y + 0.5 * (x2 - anchor_x)),
        width=1.4,
        colour="#7f8c8d",
        dash="6 4",
    )

    for point in points:
        svg.circle(px(point["bits"]), py(math.log2(point["median_steps"])), 4.5)

    svg.text(
        width / 2,
        height - 30,
        "instance size (bits of the prime group order)",
        size=12,
        anchor="middle",
    )
    svg.add(
        f'<text x="24" y="{height / 2:.0f}" font-family="DejaVu Sans, Arial, sans-serif" font-size="12" '
        f'text-anchor="middle" transform="rotate(-90 24 {height / 2:.0f})">log2(group operations)</text>'
    )
    legend_y = top + 10
    svg.line(120, legend_y, 160, legend_y, width=2.0, colour="#c0392b")
    svg.text(
        168,
        legend_y + 4,
        f"fit: slope = {fit['slope']:.4f} +/- {fit['slope_standard_error']:.4f}",
        size=12,
    )
    svg.line(120, legend_y + 20, 160, legend_y + 20, width=1.4, colour="#7f8c8d", dash="6 4")
    svg.text(168, legend_y + 24, "reference slope 0.5", size=12)
    svg.text(
        left,
        height - 8,
        f"R^2 = {fit['r_squared']:.4f}, n = {len(points)} sizes, {points[0]['trials']} trials each",
        size=11,
    )
    svg.write(path)


def figure_costs(models: dict, path: Path) -> None:
    """Horizontal bars of log2 cost for every relevant method."""
    rows = [
        ("exhaustive search", 256.0, "#95a5a6"),
        ("direct address attack (HASH160 preimage)", models["address_preimage"], "#8e44ad"),
        ("address chain, sum of stage exponents", models["address_stage_sum"], "#d2b4de"),
        ("Pollard rho (ECDLP)", 128.3, "#c0392b"),
        ("BSGS memory", 128.0, "#e67e22"),
        ("GLV-accelerated rho", 127.3, "#d35400"),
        ("Grover on the HASH160 step", 80.0, "#2980b9"),
        ("finite-field DLP, 256-bit F_p", models["field_dlp"], "#16a085"),
    ]
    width, height = 760, 470
    left, right, top = 250, 60, 60
    svg = Svg(width, height)
    bar_height = 30
    gap = 14
    max_bits = 290

    def px(bits: float) -> float:
        return left + bits / max_bits * (width - left - right)

    svg.text(
        width / 2, 32, "Cost of every relevant attack, in log2 operations", size=17, anchor="middle"
    )
    svg.line(left, top - 10, left, height - 40)
    for bits in (0, 64, 128, 192, 256):
        svg.line(px(bits), top - 10, px(bits), height - 40, width=0.6, colour="#dddddd")
        svg.text(px(bits), height - 22, f"2^{bits}", size=11, anchor="middle")
    for index, (label, bits, colour) in enumerate(rows):
        y = top + index * (bar_height + gap)
        svg.text(left - 12, y + bar_height * 0.7, label, size=12, anchor="end")
        svg.rect(left, y, px(bits) - left, bar_height, colour=colour)
        svg.text(px(bits) + 8, y + bar_height * 0.7, f"2^{bits:.1f}", size=11)
    svg.text(left, height - 40, "log2 of the operations needed; lower is weaker", size=11)
    svg.text(
        left,
        height - 22,
        "stage exponents add up but attack costs do not: the address barrier is the preimage step",
        size=11,
    )
    svg.write(path)


def figure_control(study: dict, path: Path) -> None:
    """Pohlig-Hellman on a smooth order versus rho on the same instance."""
    order = int(study["pohlig_hellman"]["order"])
    ph_steps = study["pohlig_hellman"]["steps"]
    rho_expected = 3.76 * math.sqrt(order)
    width, height = 640, 300
    svg = Svg(width, height)
    svg.text(
        width / 2,
        30,
        f"Positive control: order {order:,} is smooth, so it falls",
        size=16,
        anchor="middle",
    )
    left, right = 200, 60
    max_value = max(ph_steps, rho_expected) * 1.15

    def px(value: float) -> float:
        return left + value / max_value * (width - left - right)

    for index, (label, value, colour) in enumerate(
        [
            (f"Pohlig-Hellman: {ph_steps} ops", float(ph_steps), "#16a085"),
            (f"rho would need ~{rho_expected:,.0f}", rho_expected, "#c0392b"),
        ]
    ):
        y = 90 + index * 70
        svg.text(left - 12, y + 22, label, size=12, anchor="end")
        svg.rect(left, y, px(value) - left, 30, colour=colour)
    svg.text(
        left,
        height - 40,
        "the same harness that finds nothing on secp256k1 breaks a smooth order at once:",
        size=12,
    )
    svg.text(
        left,
        height - 22,
        "the negative result is a property of the curve, not of the code",
        size=12,
    )
    svg.write(path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    started = time.time()
    print(f"measuring Pollard rho at {SIZES} with {TRIALS} trials each ...")
    study = measure_scaling(SIZES, trials=TRIALS, seed=1)
    study_payload = study.as_dict()
    (DATA / "measurement.json").write_text(json.dumps(study_payload, indent=2), encoding="utf-8")
    fit = study_payload["fit"]
    print(f"  slope = {fit['slope']:.4f} +/- {fit['slope_standard_error']:.4f}")
    print(f"  R^2   = {fit['r_squared']:.4f}")
    print(f"  z     = {fit['z_score']:+.2f}")
    print(f"  extrapolated 256-bit cost = 2^{fit['extrapolated_log2_cost_at_256_bits']:.1f}")

    assessment = assess_dlp_refutation(study=study, address=TARGET)
    (DATA / "assessment.json").write_text(
        json.dumps(assessment.as_dict(), indent=2), encoding="utf-8"
    )
    print(f"  verdict: {assessment.verdict}")

    models = {
        "ecdlp_256": ecdlp_cost_model(256),
        "field_dlp_256": field_dlp_cost_model(256),
        "field_dlp_256_log2": field_dlp_cost_model(256)["log2_operations"],
        "address_preimage": 160.0,
        "address_stage_sum": assessment.address_case["total_cost_log2"]
        if assessment.address_case
        else 288.0,
    }
    models["address_total"] = models["address_stage_sum"]
    models["field_dlp"] = models["field_dlp_256_log2"]
    (DATA / "cost_models.json").write_text(json.dumps(models, indent=2), encoding="utf-8")
    print(f"  field DLP at 256 bits = 2^{models['field_dlp']:.1f}")
    print(f"  address preimage step = 2^{models['address_preimage']:.1f}")
    print(f"  address stage-exponent sum = 2^{models['address_stage_sum']:.1f}")

    audit = structural_audit()
    (DATA / "audit.json").write_text(json.dumps(audit.as_dict(), indent=2), encoding="utf-8")
    print(f"  audit: {len(audit.findings)} properties, {len(audit.exploitable)} exploitable")

    (DATA / "claims.json").write_text(
        json.dumps(
            {
                "claims": [rebuttal.as_dict() for rebuttal in CLAIM_REBUTTALS],
                "falsifiers": [falsifier.as_dict() for falsifier in FALSIFIERS],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    figure_scaling(study_payload, FIGURES / "fig_scaling.svg")
    figure_costs(models, FIGURES / "fig_costs.svg")
    figure_control(study_payload, FIGURES / "fig_control.svg")
    print(f"figures written to {FIGURES}")
    print(f"done in {time.time() - started:.1f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
