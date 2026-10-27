"""Console-script launcher for the optional Streamlit interface.

The launcher is a separate module so that ``streamlit run app.py`` does not
re-execute the launcher (a classic recursion trap).  Streamlit is an optional
dependency: when it is missing, the launcher prints install instructions and
returns a non-zero exit code instead of raising an ImportError traceback.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

__all__ = ["main"]

_STREAMLIT_ADDRESS = "127.0.0.1"
_STREAMLIT_PORT = 8501


def _option_supplied(argv: Sequence[str], name: str) -> bool:
    """Return whether *name* already appears in *argv* (``--opt`` or ``--opt=v``)."""
    return any(item == name or item.startswith(f"{name}=") for item in argv)


def main(argv: list[str] | None = None) -> int:
    """Start the Streamlit interface.

    Args:
        argv: Extra arguments forwarded to ``streamlit run`` (for example
            ``["--server.port", "8600"]``).  ``None`` means no extra arguments.

    Returns:
        Exit code from Streamlit, or ``1`` when Streamlit is not installed.
    """
    try:
        from streamlit.web import cli as streamlit_cli
    except ImportError:
        print(
            "The graphical interface requires Streamlit. Install it with:\n"
            "  pip install 'binarycryptolab[gui]'\n"
            "The command-line interface works without it: binarycryptolab --help",
            file=sys.stderr,
        )
        return 1

    extra = list(argv) if argv is not None else []
    app_path = Path(__file__).with_name("app.py")
    command = ["streamlit", "run", str(app_path)]
    if not _option_supplied(extra, "--server.address"):
        command.append(f"--server.address={_STREAMLIT_ADDRESS}")
    if not _option_supplied(extra, "--server.port"):
        command.append(f"--server.port={_STREAMLIT_PORT}")
    sys.argv = [*command, *extra]
    return int(streamlit_cli.main() or 0)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    raise SystemExit(main(sys.argv[1:]))
