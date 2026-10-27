"""Optional Streamlit interface.

Importing this package does **not** import Streamlit.  The pure helpers in
:mod:`binarycryptolab.gui.service` can be used and tested without the optional
``gui`` extra installed; only :mod:`binarycryptolab.gui.app` and the launcher
require Streamlit.
"""

from __future__ import annotations

from .service import (
    address_result,
    analyse,
    download_payloads,
    forensic_result,
    hash_result,
    public_key_result,
)

__all__ = [
    "address_result",
    "analyse",
    "download_payloads",
    "forensic_result",
    "hash_result",
    "public_key_result",
]
