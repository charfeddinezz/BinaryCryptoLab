"""JSON report rendering and atomic file output.

Reports contain only non-sensitive data: normalized input, statistics, public
keys, addresses, hashes, and warnings.  Private scalars are never part of the
:class:`~binarycryptolab.models.analysis_result.AnalysisResult` model and
therefore cannot leak into a report through this module.

Serialization is deterministic (``sort_keys=True`` by default) so that reports
can be diffed reproducibly.  Files are written atomically; see
:mod:`binarycryptolab.reports._io`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import DEFAULT_REPORT_INDENT
from ..exceptions import ReportGenerationError
from ..models.analysis_result import AnalysisResult
from ._io import atomic_write_text, resolve_target

__all__ = ["render_json", "report_to_dict", "write_json"]


def report_to_dict(result: AnalysisResult) -> dict[str, Any]:
    """Return the report payload for *result* as a plain dictionary.

    Raises:
        ReportGenerationError: The result is not an :class:`AnalysisResult`.
    """
    if not isinstance(result, AnalysisResult):
        raise ReportGenerationError("result must be an AnalysisResult instance")
    return result.to_dict()


def render_json(
    result: AnalysisResult,
    *,
    indent: int | None = DEFAULT_REPORT_INDENT,
    sort_keys: bool = True,
) -> str:
    """Render *result* as a JSON document.

    Args:
        result: Analysis result to serialize.
        indent: Indentation width, or ``None`` for compact output.
        sort_keys: Whether object keys are sorted (deterministic output).

    Returns:
        The JSON text, ending with a newline.

    Raises:
        ReportGenerationError: The result is invalid or cannot be serialized.
    """
    payload = report_to_dict(result)
    try:
        text = json.dumps(
            payload,
            indent=indent,
            sort_keys=sort_keys,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ReportGenerationError(f"report could not be serialized: {exc}") from exc
    return text + "\n"


def write_json(
    result: AnalysisResult,
    path: str | Path,
    *,
    overwrite: bool = False,
    create_parents: bool = True,
    indent: int | None = DEFAULT_REPORT_INDENT,
    sort_keys: bool = True,
) -> Path:
    """Write a JSON report to *path* atomically.

    Args:
        result: Analysis result to serialize.
        path: Destination file path.
        overwrite: Whether an existing file may be replaced.
        create_parents: Whether missing parent directories are created.
        indent: Indentation width, or ``None`` for compact output.
        sort_keys: Whether object keys are sorted.

    Returns:
        The resolved destination path.

    Raises:
        ReportGenerationError: The report cannot be rendered or written.
    """
    text = render_json(result, indent=indent, sort_keys=sort_keys)
    target = resolve_target(path, overwrite=overwrite, create_parents=create_parents)
    atomic_write_text(target, text, overwrite=overwrite)
    return target
