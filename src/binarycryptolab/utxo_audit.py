"""Audit a *user-supplied* UTXO export for one address, offline.

The dissection report says, correctly, that ownership and balance need chain data.
This module closes as much of that gap as can be closed without a network call: the
caller exports the data themselves (from their node, their wallet, or a block
explorer), and this module checks it for consistency against the address.

What it can prove:

* whether every listed output really pays to the script of that address (an export
  for the wrong address, or a copy-paste of the wrong column, shows up here);
* whether the totals add up, whether the same output is counted twice, and whether
  any value is impossible (negative, zero, or beyond the total supply);
* how much of the reported balance is confirmed, unconfirmed, or already spent.

What it cannot prove: that the file is complete, current, or truthful. The report
says so, because an audit of an unverified export is arithmetic, not truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Final

from .address_forensics import dissect_address
from .exceptions import InputValidationError, ReportGenerationError

__all__ = ["MAX_SUPPLY_SATS", "Utxo", "UtxoAudit", "audit_address_data"]

#: Upper bound on the number of satoshis that can exist (21 million BTC).
MAX_SUPPLY_SATS: Final = 21_000_000 * 100_000_000
_SATS_PER_BTC: Final = 100_000_000
_TXID_HEX_LENGTH: Final = 64


@dataclass(frozen=True, slots=True)
class Utxo:
    """One coin reported by the caller's export.

    Attributes:
        txid: Transaction id, 64 hexadecimal characters.
        vout: Output index.
        value_sats: Value in satoshis.
        script_pubkey_hex: The locking script reported for this output, if any.
        height: Block height, or ``None`` while unconfirmed.
        spent_by: Spending transaction id, when the export says it was spent.
        script_matches: Whether the reported script equals the address's script.
        problems: Per-output validation messages.
    """

    txid: str
    vout: int
    value_sats: int
    script_pubkey_hex: str | None
    height: int | None
    spent_by: str | None
    script_matches: bool | None
    problems: tuple[str, ...]

    @property
    def outpoint(self) -> str:
        """Return ``txid:vout``, the canonical outpoint name."""
        return f"{self.txid}:{self.vout}"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "txid": self.txid,
            "vout": self.vout,
            "value_sats": self.value_sats,
            "script_pubkey_hex": self.script_pubkey_hex,
            "height": self.height,
            "spent_by": self.spent_by,
            "script_matches": self.script_matches,
            "problems": list(self.problems),
        }


@dataclass(frozen=True, slots=True)
class UtxoAudit:
    """The result of auditing a user-supplied export.

    Attributes:
        address: The address the export claims to describe.
        source: Provenance string taken from the file or the caller.
        utxos: Every parsed output.
        total_sats: Sum of all valid values in the file.
        confirmed_sats: Sum of values with a block height.
        unconfirmed_sats: Sum of values without one.
        spent_sats: Sum of values the file marks as spent.
        balance_sats: Confirmed plus unconfirmed, minus spent.
        duplicates: Outpoints that appear more than once.
        problems: File-level problems that affect the totals.
        verdict: Plain-language summary.
        notes: What this audit does and does not establish.
    """

    address: str
    source: str
    utxos: tuple[Utxo, ...]
    total_sats: int
    confirmed_sats: int
    unconfirmed_sats: int
    spent_sats: int
    balance_sats: int
    duplicates: tuple[str, ...]
    problems: tuple[str, ...]
    verdict: str
    notes: tuple[str, ...]

    @property
    def balance_btc(self) -> str:
        """Return the balance as an exact BTC decimal string."""
        return _format_sats(self.balance_sats)

    @property
    def total_btc(self) -> str:
        """Return the reported total as an exact BTC decimal string."""
        return _format_sats(self.total_sats)

    @property
    def trusted(self) -> bool:
        """Always ``False``: an unverified export cannot be trusted."""
        return False

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "source": self.source,
            "utxos": [utxo.as_dict() for utxo in self.utxos],
            "utxo_count": len(self.utxos),
            "total_sats": self.total_sats,
            "confirmed_sats": self.confirmed_sats,
            "unconfirmed_sats": self.unconfirmed_sats,
            "spent_sats": self.spent_sats,
            "balance_sats": self.balance_sats,
            "balance_btc": self.balance_btc,
            "duplicates": list(self.duplicates),
            "problems": list(self.problems),
            "verdict": self.verdict,
            "trusted": self.trusted,
            "notes": list(self.notes),
        }


def _format_sats(value: int) -> str:
    """Format satoshis as an exact BTC decimal string."""
    sign = "-" if value < 0 else ""
    magnitude = abs(value)
    return f"{sign}{magnitude // _SATS_PER_BTC}.{magnitude % _SATS_PER_BTC:08d}"


def _require_int(value: object, *, label: str) -> int:
    """Return *value* as an integer, rejecting booleans and non-integers."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(f"{label} must be an integer")
    return value


def _parse_value_sats(entry: dict[str, Any], problems: list[str]) -> int:
    """Return the value of one entry in satoshis, recording problems."""
    if "value_sats" in entry:
        raw = entry["value_sats"]
        try:
            value = _require_int(raw, label="value_sats")
        except InputValidationError as exc:
            problems.append(str(exc))
            return 0
        return value
    if "value_btc" in entry:
        try:
            amount = Decimal(str(entry["value_btc"]))
        except (InvalidOperation, ValueError):
            problems.append("value_btc is not a decimal number")
            return 0
        satoshis = amount * _SATS_PER_BTC
        if satoshis != satoshis.to_integral_value():
            problems.append("value_btc has more than eight decimal places")
        return int(satoshis)
    problems.append("entry has neither value_sats nor value_btc")
    return 0


def _parse_utxo(entry: object, index: int, expected_script: str | None) -> Utxo:
    """Parse one entry of the ``utxos`` list.

    Raises:
        InputValidationError: The entry is not an object.
    """
    if not isinstance(entry, dict):
        raise InputValidationError(f"utxo #{index} must be a JSON object")
    problems: list[str] = []
    txid = str(entry.get("txid", "")).strip().lower()
    if len(txid) != _TXID_HEX_LENGTH or any(
        character not in "0123456789abcdef" for character in txid
    ):
        problems.append("txid must be 64 hexadecimal characters")
    try:
        vout = _require_int(entry.get("vout"), label="vout")
    except InputValidationError as exc:
        problems.append(str(exc))
        vout = -1
    if vout < 0:
        problems.append("vout must be zero or greater")
    value = _parse_value_sats(entry, problems)
    if value < 0:
        problems.append("value cannot be negative")
    elif value == 0:
        problems.append("value is zero, which is below the dust limit on every chain")
    height_raw = entry.get("height", entry.get("block_height"))
    height: int | None = None
    if height_raw is not None:
        try:
            height = _require_int(height_raw, label="height")
        except InputValidationError as exc:
            problems.append(str(exc))
        else:
            if height < 0:
                problems.append("height cannot be negative")
    spent_raw = entry.get("spent_by")
    spent_by = None if spent_raw in (None, "") else str(spent_raw).strip().lower()
    if spent_by is not None and len(spent_by) != _TXID_HEX_LENGTH:
        problems.append("spent_by must be a 64-character transaction id")
    script_raw = entry.get("script_pubkey_hex")
    script_hex = None if script_raw in (None, "") else str(script_raw).strip().lower()
    if script_hex is not None and any(
        character not in "0123456789abcdef" for character in script_hex
    ):
        problems.append("script_pubkey_hex is not hexadecimal")
        script_hex = None
    matches: bool | None = None
    if script_hex is not None and expected_script:
        matches = script_hex.removeprefix("0x") == expected_script.lower()
        if not matches:
            problems.append("the script does not pay to this address")
    return Utxo(
        txid=txid,
        vout=vout,
        value_sats=value,
        script_pubkey_hex=script_hex,
        height=height,
        spent_by=spent_by,
        script_matches=matches,
        problems=tuple(problems),
    )


def _load_payload(data: object) -> dict[str, Any]:
    """Return the export as a mapping.

    Raises:
        InputValidationError: The data is not a mapping or a JSON object.
        ReportGenerationError: The file cannot be read.
    """
    if isinstance(data, dict):
        payload: object = data
    elif isinstance(data, (str, Path)):
        path = Path(data)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReportGenerationError(f"cannot read {path}: {exc}") from exc
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputValidationError(f"the file is not valid JSON: {exc}") from exc
    else:
        raise InputValidationError("the export must be a JSON object or a path to one")
    if not isinstance(payload, dict):
        raise InputValidationError("the export must be a JSON object")
    return payload


def audit_address_data(
    address: str,
    data: object,
    *,
    source: str | None = None,
) -> UtxoAudit:
    """Audit a user-supplied UTXO export against *address*.

    Args:
        address: The address the export is supposed to describe.
        data: A mapping, or a path to a JSON file, with an ``utxos`` list.
        source: Provenance to record instead of the file's own ``source`` field.

    Returns:
        The audit.

    Raises:
        AddressEncodingError: The address is invalid.
        InputValidationError: The export is malformed.
        ReportGenerationError: The file cannot be read.

    Example:
        >>> export = {
        ...     "address": "1GeMQKJ8rqvRWKLMqyVJjPKmWGcR67ZNmb",
        ...     "source": "my node, 2026-10-28",
        ...     "utxos": [
        ...         {"txid": "ab" * 32, "vout": 0, "value_sats": 150000, "height": 800000}
        ...     ],
        ... }
        >>> audit = audit_address_data(export["address"], export)
        >>> audit.balance_btc
        '0.00150000'
    """
    dissection = dissect_address(address)
    payload = _load_payload(data)
    listed = payload.get("utxos", [])
    if not isinstance(listed, list):
        raise InputValidationError("the 'utxos' field must be a list")

    problems: list[str] = []
    declared = payload.get("address")
    if isinstance(declared, str) and declared.strip() and declared.strip() != dissection.address:
        problems.append(
            "the export names a different address than the one being audited: "
            f"{declared.strip()[:16]}... vs {dissection.address[:16]}..."
        )

    expected_script = (
        dissection.script_pubkey_hex
        if dissection.chain == "bitcoin" and dissection.script_pubkey_hex
        else None
    )
    utxos = tuple(_parse_utxo(entry, index, expected_script) for index, entry in enumerate(listed))

    seen: dict[str, int] = {}
    duplicates: list[str] = []
    for utxo in utxos:
        if utxo.outpoint in seen:
            duplicates.append(utxo.outpoint)
            seen[utxo.outpoint] += 1
        else:
            seen[utxo.outpoint] = 1

    total = sum(utxo.value_sats for utxo in utxos if utxo.value_sats > 0)
    confirmed = sum(
        utxo.value_sats for utxo in utxos if utxo.value_sats > 0 and utxo.height is not None
    )
    unconfirmed = sum(
        utxo.value_sats for utxo in utxos if utxo.value_sats > 0 and utxo.height is None
    )
    spent = sum(
        utxo.value_sats for utxo in utxos if utxo.value_sats > 0 and utxo.spent_by is not None
    )
    if duplicates:
        problems.append(
            f"{len(duplicates)} outpoint(s) appear more than once; the totals double-count them"
        )
    if spent:
        problems.append(
            f"{_format_sats(spent)} BTC in the file is marked as already spent; a UTXO "
            "list normally contains only unspent outputs"
        )
    if total > MAX_SUPPLY_SATS:
        problems.append(
            "the reported total exceeds the 21 million BTC supply limit, so the file "
            "cannot be describing real outputs"
        )
    mismatched = [utxo for utxo in utxos if utxo.script_matches is False]
    if mismatched:
        problems.append(f"{len(mismatched)} output(s) pay to a different script than this address")
    malformed = [utxo for utxo in utxos if utxo.problems]
    if malformed:
        problems.append(f"{len(malformed)} output(s) have validation problems")

    balance = max(0, confirmed + unconfirmed - spent)
    if not utxos:
        verdict = (
            "The file lists no outputs. That is consistent with an unused address, and "
            "it is equally consistent with an incomplete export; this tool cannot tell "
            "the difference."
        )
    elif mismatched:
        verdict = (
            "The export does not describe this address: at least one output pays to a "
            "different script. Do not rely on these numbers."
        )
    else:
        verdict = (
            f"The file reports {_format_sats(total)} BTC across {len(utxos)} output(s), "
            f"leaving {_format_sats(balance)} BTC after spent entries. The arithmetic "
            "is checked; the data itself is yours to trust."
        )

    return UtxoAudit(
        address=dissection.address,
        source=source or str(payload.get("source", "user-supplied, unspecified")),
        utxos=utxos,
        total_sats=total,
        confirmed_sats=confirmed,
        unconfirmed_sats=unconfirmed,
        spent_sats=spent,
        balance_sats=balance,
        duplicates=tuple(duplicates),
        problems=tuple(problems),
        verdict=verdict,
        notes=(
            "This audit reads a file you supplied. It makes no network request and "
            "cannot verify that the data is current or complete.",
            "A matching script proves the export was built for this address; it does "
            "not prove that the outputs exist on chain.",
            "Ownership still requires a signature from the key, which this tool never handles.",
        ),
    )
