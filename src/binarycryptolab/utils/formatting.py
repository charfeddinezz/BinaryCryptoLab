"""Human-readable formatting helpers for the CLI and examples.

These helpers only format data that is already safe to display.  They never
receive, transform, or emit private key material.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Final

from ..statistics import BitStatistics, ByteStatistics

__all__ = [
    "abbreviate",
    "format_bit_row",
    "format_byte_row",
    "format_frequency",
    "format_hex_groups",
    "format_ratio",
    "format_table",
    "human_bytes",
    "join_warning_lines",
    "safe_display",
]

_ELLIPSIS: Final = "..."


def abbreviate(text: str, limit: int = 80) -> str:
    """Shorten *text* to *limit* characters, keeping both ends."""
    if limit < 7:
        raise ValueError("limit must be at least 7")
    if len(text) <= limit:
        return text
    head = (limit - len(_ELLIPSIS)) // 2
    tail = limit - len(_ELLIPSIS) - head
    return f"{text[:head]}{_ELLIPSIS}{text[-tail:]}"


def format_ratio(value: float, *, digits: int = 4) -> str:
    """Format a ratio as a fixed-precision decimal."""
    return f"{value:.{digits}f}"


def format_entropy(value: float, *, digits: int = 4) -> str:
    """Format an entropy value in bits per symbol."""
    return f"{value:.{digits}f} bits/byte"


def format_hex_groups(digits: str, *, group_size: int = 2, groups_per_line: int = 8) -> str:
    """Group hexadecimal digits into bytes and lines for display.

    Raises:
        ValueError: A group size or line size is not positive.
    """
    if group_size <= 0 or groups_per_line <= 0:
        raise ValueError("group sizes must be positive")
    groups = [digits[index : index + group_size] for index in range(0, len(digits), group_size)]
    lines = [
        " ".join(groups[index : index + groups_per_line])
        for index in range(0, len(groups), groups_per_line)
    ]
    return "\n".join(lines)


def format_frequency(frequency: Iterable[tuple[int, int]], *, limit: int = 16) -> str:
    """Render a byte frequency table compactly.

    Args:
        frequency: ``(byte_value, count)`` pairs.
        limit: Maximum number of entries shown before summarising the rest.
    """
    items = list(frequency)
    if not items:
        return "(no bytes)"
    shown = [f"0x{value:02x}:{count}" for value, count in items[:limit]]
    remaining = len(items) - len(shown)
    suffix = f" ... (+{remaining} more)" if remaining else ""
    return ", ".join(shown) + suffix


def format_bit_row(stats: BitStatistics) -> str:
    """Format bit statistics as a single line."""
    return (
        f"{stats.length} bits | {stats.ones} one | {stats.zeros} zero | "
        f"weight {stats.hamming_weight} | one ratio {format_ratio(stats.one_ratio)}"
    )


def format_byte_row(stats: ByteStatistics) -> str:
    """Format byte statistics as a single line."""
    if stats.byte_length == 0:
        return "no bytes"
    min_byte = f"0x{stats.min_byte:02x}" if stats.min_byte is not None else "-"
    max_byte = f"0x{stats.max_byte:02x}" if stats.max_byte is not None else "-"
    average = f"{stats.average_byte:.2f}" if stats.average_byte is not None else "-"
    return (
        f"{stats.byte_length} byte(s) | unique {stats.unique_bytes} | "
        f"min {min_byte} | max {max_byte} | avg {average} | "
        f"entropy {format_entropy(stats.entropy)}"
    )


def safe_display(text: str, limit: int = 120) -> str:
    """Render user-controlled text safely for a terminal.

    Control characters (including ANSI escape sequences) are escaped so that
    input cannot manipulate the terminal.  The result is abbreviated to
    *limit* characters.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    rendered = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )
    return abbreviate(rendered, limit)


def human_bytes(count: int) -> str:
    """Format a byte count with binary units (KiB, MiB, ...)."""
    if count < 0:
        raise ValueError("count must be non-negative")
    value = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB"  # pragma: no cover - unreachable


def format_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    """Render a simple, aligned plain-text table.

    Raises:
        ValueError: A row has a different number of cells than the header.
    """
    materialized = [tuple(str(cell) for cell in row) for row in rows]
    if not headers:
        raise ValueError("a table needs at least one header")
    widths = [len(header) for header in headers]
    for row in materialized:
        if len(row) != len(headers):
            raise ValueError("every table row must have the same number of cells as the header")
        widths = [max(width, len(cell)) for width, cell in zip(widths, row, strict=True)]

    def render(cells: tuple[str, ...]) -> str:
        # The final column is left unpadded to avoid trailing whitespace on
        # rows whose value is much longer than the header.
        padded = [cell.ljust(width) for cell, width in zip(cells[:-1], widths[:-1], strict=True)]
        return "  ".join([*padded, cells[-1]])

    lines = [render(tuple(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend(render(row) for row in materialized)
    return "\n".join(lines)


def join_warning_lines(warnings: Sequence[str]) -> str:
    """Format warnings as a bulleted block, or return an empty string."""
    if not warnings:
        return ""
    return "\n".join(f"  - {warning}" for warning in warnings)
