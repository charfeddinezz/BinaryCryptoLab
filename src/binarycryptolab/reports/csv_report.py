"""CSV report rendering and atomic file output.

CSV output is a long-format table with three columns::

    section,key,value

Each statistic becomes one row, which keeps the file readable in spreadsheet
applications and stable across runs (rows are emitted in a fixed order).
Frequency tables use one row per byte value.

Like the JSON writer, this module never handles private key material and writes
files atomically.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from ..exceptions import ReportGenerationError
from ..models.analysis_result import AnalysisResult
from ._io import atomic_write_text, resolve_target

__all__ = ["render_csv", "write_csv"]

_HEADER = ("section", "key", "value")


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _flatten(prefix: str, value: Any, rows: list[tuple[str, str, str]]) -> None:
    if isinstance(value, dict):
        for key in value:
            _flatten(f"{prefix}.{key}" if prefix else str(key), value[key], rows)
        return
    if isinstance(value, (list, tuple)):
        if not value:
            rows.append((prefix, "count", "0"))
            return
        for index, item in enumerate(value):
            _flatten(f"{prefix}[{index}]", item, rows)
        return
    section, _, key = prefix.rpartition(".")
    rows.append((section or "report", key or prefix, _stringify(value)))


_INPUT_KEYS = frozenset({"input_type", "original_input", "normalized_input"})


def _analysis_rows(analysis: dict[str, Any], rows: list[tuple[str, str, str]]) -> None:
    for key, value in analysis.items():
        if key in _INPUT_KEYS:
            # Already reported by the top-level ``input`` section.
            continue
        if key == "bytes" and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key != "frequency":
                    rows.append(("bytes", sub_key, _stringify(sub_value)))
            frequency = value.get("frequency", {})
            if frequency:
                for byte_value, count in frequency.items():
                    rows.append(("byte_frequency", f"0x{int(byte_value):02x}", str(count)))
            else:
                rows.append(("byte_frequency", "count", "0"))
        else:
            _flatten(key, value, rows)


def _rows_for(result: AnalysisResult) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    payload = result.to_dict()

    for key in ("application", "input"):
        _flatten(key, payload[key], rows)

    analysis = payload["analysis"]
    if isinstance(analysis, dict):
        _analysis_rows(analysis, rows)

    for digest in result.hashes:
        _flatten("hashes", digest.as_dict(), rows)

    if result.public_key is not None:
        for key, value in result.public_key.items():
            if isinstance(value, (dict, list, tuple)):
                _flatten(f"public_key.{key}", value, rows)
            else:
                rows.append(("public_key", key, _stringify(value)))

    if result.address is not None:
        for key, value in result.address.items():
            if isinstance(value, (dict, list, tuple)):
                _flatten(f"bitcoin_address.{key}", value, rows)
            else:
                rows.append(("bitcoin_address", key, _stringify(value)))

    for index, warning in enumerate(result.warnings):
        rows.append(("warnings", f"warning[{index}]", warning))
    for index, note in enumerate(payload.get("security_notes", [])):
        rows.append(("security_notes", f"note[{index}]", str(note)))
    for key, value in result.extra.items():
        if isinstance(value, (dict, list, tuple)):
            _flatten(f"extra.{key}", value, rows)
        else:
            rows.append(("extra", str(key), _stringify(value)))
    return rows


def render_csv(result: AnalysisResult) -> str:
    """Render *result* as a CSV document.

    Args:
        result: Analysis result to serialize.

    Returns:
        CSV text with ``\\n`` line endings and a trailing newline.

    Raises:
        ReportGenerationError: The result is invalid.
    """
    if not isinstance(result, AnalysisResult):
        raise ReportGenerationError("result must be an AnalysisResult instance")
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_HEADER)
    for row in _rows_for(result):
        writer.writerow(row)
    return buffer.getvalue()


def write_csv(
    result: AnalysisResult,
    path: str | Path,
    *,
    overwrite: bool = False,
    create_parents: bool = True,
) -> Path:
    """Write a CSV report to *path* atomically.

    Args:
        result: Analysis result to serialize.
        path: Destination file path.
        overwrite: Whether an existing file may be replaced.
        create_parents: Whether missing parent directories are created.

    Returns:
        The resolved destination path.

    Raises:
        ReportGenerationError: The report cannot be rendered or written.
    """
    text = render_csv(result)
    target = resolve_target(path, overwrite=overwrite, create_parents=create_parents)
    atomic_write_text(target, text, overwrite=overwrite)
    return target
