"""Shared, private file-writing helpers for report modules.

Reports are written to a temporary file in the destination directory and then
atomically moved into place.  Existing files are never replaced unless the
caller explicitly opts in.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

from ..exceptions import ReportGenerationError

__all__ = ["atomic_write_text", "resolve_target"]


def resolve_target(path: str | Path, *, overwrite: bool, create_parents: bool) -> Path:
    """Validate an output path and ensure its parent directory exists.

    Raises:
        ReportGenerationError: The path is unusable or would be overwritten
            without permission.
    """
    try:
        target = Path(path).expanduser()
    except TypeError as exc:
        raise ReportGenerationError("output path must be a string or Path") from exc
    if target.exists() and target.is_dir():
        raise ReportGenerationError(f"output path is a directory: {target}")
    if target.exists() and not overwrite:
        raise ReportGenerationError(
            f"refusing to overwrite existing file {target}; pass overwrite=True to replace it"
        )
    parent = target.parent
    if not parent.exists():
        if not create_parents:
            raise ReportGenerationError(f"output directory does not exist: {parent}")
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReportGenerationError(
                f"could not create output directory {parent}: {exc.strerror or exc}"
            ) from exc
    return target


def atomic_write_text(target: Path, text: str, *, overwrite: bool) -> None:
    """Write *text* to *target* atomically.

    Raises:
        ReportGenerationError: The write fails or the destination appeared
            after the initial check while ``overwrite`` is ``False``.
    """
    directory = target.parent
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=directory,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and not overwrite:
            raise ReportGenerationError(
                f"refusing to overwrite existing file {target}; pass overwrite=True to replace it"
            )
        os.replace(temporary_name, target)
        temporary_name = None
    except OSError as exc:
        raise ReportGenerationError(
            f"could not write report to {target}: {exc.strerror or exc}"
        ) from exc
    finally:
        if temporary_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name)
