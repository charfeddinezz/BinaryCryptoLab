"""Pydantic-free data models used by BinaryCryptoLab.

Only dependency-free dataclasses are used so that the core package imports
quickly and has a minimal dependency footprint.
"""

from __future__ import annotations

from .analysis_result import (
    REDACTED,
    AnalysisResult,
    BinaryAnalysis,
    HexAnalysis,
    InputType,
    utc_timestamp,
)

__all__ = [
    "REDACTED",
    "AnalysisResult",
    "BinaryAnalysis",
    "HexAnalysis",
    "InputType",
    "utc_timestamp",
]
