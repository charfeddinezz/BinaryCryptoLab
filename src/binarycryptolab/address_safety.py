"""Offline hazard audit for an address or locking script.

An address can be *valid* and still be a terrible destination: an unknown witness
version is claimable by anyone, an all-zero payload is burned, a Taproot output can
commit to a nothing-up-my-sleeve key, and a script hash hides whether the coins are
spendable at all.  None of that requires a network connection.

This module answers a narrower question than "is this address safe?" - a question
no offline tool can answer - and a more useful one: **which documented hazards
does this output have?**  Every check carries its evidence, and the verdict states
plainly that only the key holder can prove spendability by signing.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Final

from .address_formats import DecodedInput, KnownAddress, lookup_known_address

__all__ = [
    "NUMS_POINT_HEX",
    "SafetyAudit",
    "SafetyCheck",
    "TaprootInfo",
    "audit_decoded_input",
    "inspect_taproot_key",
]

#: The BIP-341 "nothing up my sleeve" internal key, used by script-path-only outputs.
NUMS_POINT_HEX: Final = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

_FIELD_P: Final = 2**256 - 2**32 - 977
_MAX_MONEY_BTC: Final = 21_000_000
_SEVERITY_ORDER: Final = {"critical": 0, "warning": 1, "notice": 2, "ok": 3}


@dataclass(frozen=True, slots=True)
class SafetyCheck:
    """One hazard check with its evidence.

    Attributes:
        code: Stable identifier, e.g. ``unknown_witness_version``.
        severity: ``critical``, ``warning``, ``notice``, or ``ok``.
        title: One-line description.
        detail: Why the finding matters.
        evidence: The exact value that triggered it.
    """

    code: str
    severity: str
    title: str
    detail: str
    evidence: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class TaprootInfo:
    """What can be verified about a Taproot output key offline.

    Attributes:
        output_key_hex: The 32-byte x-only output key.
        valid_x_coordinate: Whether the x-coordinate lifts to a curve point.
        even_y: Whether the lifted point has an even y, as BIP-340 requires.
        is_nums_key: Whether the key is the documented BIP-341 NUMS point.
        note: What the result means for spendability.
    """

    output_key_hex: str
    valid_x_coordinate: bool
    even_y: bool
    is_nums_key: bool
    note: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "output_key_hex": self.output_key_hex,
            "valid_x_coordinate": self.valid_x_coordinate,
            "even_y": self.even_y,
            "is_nums_key": self.is_nums_key,
            "note": self.note,
        }


def _lift_x(x: int) -> int | None:
    """Return the even y for *x*, or ``None`` when *x* is not on the curve."""
    if not 0 <= x < _FIELD_P:
        return None
    y_squared = (pow(x, 3, _FIELD_P) + 7) % _FIELD_P
    candidate = pow(y_squared, (_FIELD_P + 1) // 4, _FIELD_P)
    if pow(candidate, 2, _FIELD_P) != y_squared:
        return None
    return candidate if candidate % 2 == 0 else _FIELD_P - candidate


def inspect_taproot_key(output_key: bytes) -> TaprootInfo:
    """Inspect a 32-byte Taproot output key.

    Args:
        output_key: The x-only output key.

    Returns:
        The inspection result.  An invalid key is reported, not raised: a
        malformed Taproot output is itself a finding.

    Raises:
        ValueError: The key is not 32 bytes.
    """
    if len(output_key) != 32:
        raise ValueError("a Taproot output key must be 32 bytes")
    coordinate = int.from_bytes(output_key, "big")
    lifted = _lift_x(coordinate)
    valid = lifted is not None
    is_nums = output_key.hex() == NUMS_POINT_HEX
    if not valid:
        note = (
            "The x-coordinate is not on secp256k1. No signature can ever be valid "
            "for this output, so coins sent to it are unspendable."
        )
    elif is_nums:
        note = (
            "This is the documented BIP-341 NUMS point. Its discrete logarithm is "
            "not known to anyone, so the key path is unspendable by design; "
            "spending is possible only through a script path, which the address "
            "does not reveal."
        )
    else:
        note = (
            "The key lifts to a valid curve point. Spendability still depends on "
            "whoever controls the corresponding secret, which cannot be checked "
            "offline."
        )
    return TaprootInfo(
        output_key_hex=output_key.hex(),
        valid_x_coordinate=valid,
        even_y=valid and lifted is not None and lifted % 2 == 0,
        is_nums_key=is_nums,
        note=note,
    )


@dataclass(frozen=True, slots=True)
class SafetyAudit:
    """The collected hazard checks for one output.

    Attributes:
        checks: Every check, critical first.
        known_address: The documented-registry entry, when one matches.
        taproot: Taproot inspection, when the output is Taproot.
        grade: ``danger``, ``review``, or ``no-known-hazard``.
        unspendable: Whether the output is provably unspendable.
        anyone_can_spend: Whether current rules let any miner claim the coins.
        safe_to_share: Always true: addresses are public data.
        verdict: One paragraph a user can act on.
        notes: Caveats that apply to every audit.
    """

    checks: tuple[SafetyCheck, ...]
    known_address: KnownAddress | None
    taproot: TaprootInfo | None
    grade: str
    unspendable: bool
    anyone_can_spend: bool
    safe_to_share: bool
    verdict: str
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "checks": [check.as_dict() for check in self.checks],
            "known_address": None if self.known_address is None else self.known_address.as_dict(),
            "taproot": None if self.taproot is None else self.taproot.as_dict(),
            "grade": self.grade,
            "unspendable": self.unspendable,
            "anyone_can_spend": self.anyone_can_spend,
            "safe_to_share": self.safe_to_share,
            "verdict": self.verdict,
            "notes": list(self.notes),
        }

    @property
    def critical(self) -> tuple[SafetyCheck, ...]:
        """Return only the critical checks."""
        return tuple(check for check in self.checks if check.severity == "critical")

    @property
    def warnings(self) -> tuple[SafetyCheck, ...]:
        """Return only the warning checks."""
        return tuple(check for check in self.checks if check.severity == "warning")


def _check(code: str, severity: str, title: str, detail: str, evidence: str) -> SafetyCheck:
    """Build a check with the given fields."""
    return SafetyCheck(code=code, severity=severity, title=title, detail=detail, evidence=evidence)


def _amount_check(decoded: DecodedInput) -> SafetyCheck | None:
    """Validate a BIP-21 amount parameter, if present."""
    amounts = [value for name, value in decoded.uri_params if name == "amount"]
    if not amounts:
        return None
    raw = amounts[0]
    try:
        amount = Fraction(raw)
    except (ValueError, ZeroDivisionError):
        return _check(
            "uri_amount",
            "warning",
            "unparsable amount in the payment URI",
            "BIP-21 amounts must be decimal BTC. A wallet may refuse or misread this value.",
            raw[:32],
        )
    if amount < 0:
        return _check(
            "uri_amount",
            "critical",
            "negative amount in the payment URI",
            "A negative amount is not a valid payment and some wallets have "
            "misinterpreted such URIs.",
            raw[:32],
        )
    if amount > _MAX_MONEY_BTC:
        return _check(
            "uri_amount",
            "critical",
            "amount exceeds the total supply",
            "More than 21 million BTC cannot exist, so this URI is malformed or hostile.",
            raw[:32],
        )
    return _check(
        "uri_amount",
        "ok",
        "payment URI amount is well formed",
        "The amount parses as a non-negative decimal within the supply limit.",
        raw[:32],
    )


def _unknown_requirement(decoded: DecodedInput) -> SafetyCheck | None:
    """Flag BIP-21 ``req-`` parameters the tool does not implement."""
    required = [name for name, _ in decoded.uri_params if name.startswith("req-")]
    if not required:
        return None
    return _check(
        "uri_required_parameter",
        "warning",
        "the URI requires a feature this tool does not implement",
        "BIP-21 says a wallet must refuse the payment when a req- parameter is "
        "unsupported, rather than paying a different way.",
        ", ".join(sorted(required)),
    )


def audit_decoded_input(
    decoded: DecodedInput,
    *,
    declared_prefix: str | None = None,
    network_mismatch: str | None = None,
) -> SafetyAudit:
    """Run every offline hazard check against a decoded input.

    Args:
        decoded: The output returned by :func:`decode_address_input`.
        declared_prefix: A vanity prefix declared in advance, if any.
        network_mismatch: The expected network, when it differs from the decoded one.

    Returns:
        The audit.  It never raises for a valid decoding.
    """
    checks: list[SafetyCheck] = []
    known = None if decoded.address is None else lookup_known_address(decoded.address)
    payload = decoded.payload

    if decoded.checksum_valid:
        checks.append(
            _check(
                "checksum",
                "ok",
                "checksum verifies",
                "The checksum was recomputed locally and matches the encoding.",
                decoded.encoding,
            )
        )
    else:
        checks.append(
            _check(
                "checksum",
                "critical",
                "checksum does not verify",
                "A single mistyped character is caught here; never pay to an address "
                "that fails this check.",
                decoded.checksum_hex,
            )
        )

    if known is not None:
        severity = {"burn": "critical", "unspendable": "critical", "genesis": "critical"}.get(
            known.kind, "notice"
        )
        checks.append(
            _check(
                f"known_{known.kind}",
                severity,
                f"documented address: {known.label}",
                known.meaning,
                known.reference,
            )
        )

    documented_burn = known is not None and known.kind == "burn"
    unspendable = known is not None and known.kind in {"burn", "unspendable", "genesis"}
    structural = False
    anyone_can_spend = False

    if payload and len(set(payload)) == 1:
        zero = payload[0] == 0
        checks.append(
            _check(
                "constant_payload",
                "critical",
                "payload is a single repeated byte",
                (
                    "No known public key hashes to an all-zero HASH160, so coins sent "
                    "here are destroyed."
                    if zero
                    else "A constant payload is not a plausible hash of any public key."
                ),
                payload.hex(),
            )
        )
        unspendable = True
        structural = True

    if decoded.address_type.startswith("witness_v"):
        try:
            version = int(decoded.address_type.removeprefix("witness_v"))
        except ValueError:
            version = -1
        if version >= 2:
            checks.append(
                _check(
                    "unknown_witness_version",
                    "critical",
                    f"witness version {version} is not defined",
                    "BIP-141 makes future witness versions unencumbered: any miner "
                    "can spend the output without a signature. Sending funds here "
                    "donates them to whoever claims them first.",
                    f"v{version}, {len(payload)}-byte program",
                )
            )
            anyone_can_spend = True
        elif version == 1:
            checks.append(
                _check(
                    "malformed_taproot_program",
                    "critical",
                    "witness version 1 requires a 32-byte program",
                    "BIP-341 defines v1 only for 32-byte Taproot keys. This output is "
                    "not a valid Taproot address and is not spendable by standard rules.",
                    f"{len(payload)}-byte program",
                )
            )
            unspendable = True
            structural = True

    taproot: TaprootInfo | None = None
    if decoded.address_type == "p2tr":
        taproot = inspect_taproot_key(payload)
        if not taproot.valid_x_coordinate:
            checks.append(
                _check(
                    "taproot_invalid_key",
                    "critical",
                    "the Taproot x-coordinate is not on the curve",
                    taproot.note,
                    taproot.output_key_hex,
                )
            )
            unspendable = True
            structural = True
        elif taproot.is_nums_key:
            checks.append(
                _check(
                    "taproot_nums_key",
                    "critical",
                    "the output key is the NUMS point",
                    taproot.note,
                    taproot.output_key_hex,
                )
            )
        else:
            checks.append(
                _check(
                    "taproot_valid_key",
                    "ok",
                    "the Taproot output key is a valid curve point",
                    taproot.note,
                    taproot.output_key_hex,
                )
            )

    if decoded.address_type in {"p2sh", "p2wsh"}:
        checks.append(
            _check(
                "script_hash_opaque",
                "warning",
                f"the {decoded.address_type.upper()} script is not visible",
                "The address commits to a script hash. Whether the coins are "
                "spendable, and by whom, depends on the script, which an address "
                "does not reveal. Multisig and time-locked funds look identical to "
                "lost funds at this level.",
                payload.hex(),
            )
        )

    if decoded.address_type == "p2pk":
        checks.append(
            _check(
                "public_key_exposed",
                "warning",
                "the public key is written into the output",
                "Pay-to-public-key outputs expose the key on chain, so the barrier "
                "is the secp256k1 discrete logarithm (2^128 classically) with no "
                "hash step in between. Modern wallets avoid this form.",
                payload.hex()[:34],
            )
        )
    if decoded.address_type == "op_return":
        checks.append(
            _check(
                "op_return_output",
                "critical",
                "OP_RETURN output",
                "OP_RETURN is a data carrier. It is provably unspendable by consensus "
                "and cannot receive funds.",
                "OP_RETURN",
            )
        )
        unspendable = True
        structural = True
    if decoded.address_type == "nonstandard":
        checks.append(
            _check(
                "nonstandard_script",
                "warning",
                "non-standard locking script",
                "The script does not match a recognised template. It may be spendable "
                "by a custom tool, and it may be unspendable; this must be verified "
                "against the script itself.",
                decoded.original[:64],
            )
        )

    if decoded.network == "unknown":
        checks.append(
            _check(
                "unregistered_version",
                "notice",
                "the version prefix is not registered",
                "The chain and the commitment rule are unknown, so this audit can "
                "verify the checksum and the payload but cannot classify the output. "
                "An address on an unlisted chain looks exactly like this.",
                f"0x{decoded.version_byte:02x}" if decoded.version_byte is not None else "-",
            )
        )
    elif decoded.network != "mainnet":
        checks.append(
            _check(
                "non_mainnet",
                "warning",
                f"this is a {decoded.network} address",
                "Coins on a test network have no market value, and a mainnet wallet "
                "will reject the address or send to a different chain.",
                decoded.network,
            )
        )

    if decoded.network_ambiguous:
        checks.append(
            _check(
                "network_ambiguous",
                "notice",
                "several networks share this format",
                "The same prefix is valid on more than one network. Confirm the "
                "intended network before sending.",
                ", ".join(sorted(decoded.chain_candidates)),
            )
        )

    if decoded.encoding in {"bech32", "bech32m"} and decoded.original != decoded.original.lower():
        checks.append(
            _check(
                "upper_case",
                "notice",
                "upper-case Bech32 input",
                "Upper case is valid per BIP-173. The canonical lower-case form is "
                "shown in the report; do not mix cases when retyping.",
                "normalised",
            )
        )

    if decoded.input_kind == "script_pubkey":
        checks.append(
            _check(
                "script_input",
                "notice",
                "the input was a locking script",
                "The address shown was derived from the script, not supplied by the user.",
                decoded.original[:64],
            )
        )

    if declared_prefix is not None:
        checks.append(
            _check(
                "declared_prefix",
                "notice",
                "a vanity prefix was declared in advance",
                "A pre-declared prefix supports a claim about deliberate generation, "
                "not about safety or ownership.",
                declared_prefix,
            )
        )

    if network_mismatch is not None:
        checks.append(
            _check(
                "network_mismatch",
                "warning",
                "the address does not match the requested network",
                "The caller asked for a different network; paying across networks loses funds.",
                network_mismatch,
            )
        )

    amount = _amount_check(decoded)
    if amount is not None:
        checks.append(amount)
    requirement = _unknown_requirement(decoded)
    if requirement is not None:
        checks.append(requirement)

    checks.sort(key=lambda item: _SEVERITY_ORDER[item.severity])
    critical = any(item.severity == "critical" for item in checks)
    warning = any(item.severity == "warning" for item in checks)
    grade = "danger" if critical else ("review" if warning else "no-known-hazard")

    if decoded.address_type == "op_return":
        verdict = (
            "OP_RETURN is a data carrier, not a payment destination. It is provably "
            "unspendable, so nothing sent to it can ever move again."
        )
    elif anyone_can_spend:
        verdict = "Anyone can spend this output under current rules. Do not send funds to it."
    elif unspendable and structural:
        verdict = (
            "This output is provably unspendable: coins sent to it are destroyed. "
            "This is a structural fact, not a probability."
        )
    elif known is not None and known.kind == "genesis":
        verdict = (
            "This is the block 0 coinbase address. Its output is not in the UTXO set, "
            "so it cannot be spent by consensus regardless of who holds the key, and "
            "anything sent to it now is a separate output with no such protection."
        )
    elif documented_burn:
        verdict = (
            "This is a documented burn address. Payments are treated as destroyed. "
            "The tool cannot prove that the private key is unknown: it reports the "
            "documented purpose of the address, not a proof about its key."
        )
    elif grade == "danger":
        verdict = "At least one critical hazard was found. Do not send funds until it is resolved."
    elif grade == "review":
        verdict = (
            "No fatal hazard, but the output cannot be certified offline: the checks "
            "below list what must be confirmed by the counterparty."
        )
    else:
        verdict = (
            "No documented hazard applies to this output. That is not a guarantee: "
            "only the key holder can prove spendability by producing a signature."
        )

    return SafetyAudit(
        checks=tuple(checks),
        known_address=known,
        taproot=taproot,
        grade=grade,
        unspendable=unspendable,
        anyone_can_spend=anyone_can_spend,
        safe_to_share=True,
        verdict=verdict,
        notes=(
            "An address is public data: it is safe to share and unsafe to trust.",
            "Every check in this audit is offline and deterministic; none of it "
            "proves ownership, balance, or that coins were ever sent.",
            "A clean audit is the absence of known hazards, not evidence of safety.",
        ),
    )
