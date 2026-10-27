"""Shared fixtures for the BinaryCryptoLab test suite.

Public vectors live in :mod:`tests.vectors` so every test module can import
them without duplicating constants.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest


@pytest.fixture
def cli_runner(capsys: pytest.CaptureFixture[str]) -> Callable[[list[str]], tuple[int, str, str]]:
    """Run the CLI in-process and capture ``(exit_code, stdout, stderr)``."""
    from binarycryptolab.cli import main

    def run(arguments: list[str]) -> tuple[int, str, str]:
        code = main(arguments)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return run


@pytest.fixture
def sample_json_report(tmp_path: Path) -> Path:
    """Write a small JSON report and return its path."""
    from binarycryptolab.analysis import analyze
    from binarycryptolab.reports import write_json

    return write_json(analyze("binary", "101101"), tmp_path / "report.json")


@pytest.fixture
def report_payload(sample_json_report: Path) -> dict[str, object]:
    """Load the sample JSON report."""
    return json.loads(sample_json_report.read_text(encoding="utf-8"))
