"""Recover the redeem script behind an address from candidate public keys.

An address commits to a script it never shows. The previous version could verify a
script *if the caller already had it*. This module goes one step further: given the
public keys you plausibly control (yours, your counterparty's, your cosigners'), it
**enumerates the scripts those keys can produce** and checks every one against the
address.

For a P2SH or P2WSH address that is a genuine recovery: if any enumerated script
hashes to the payload, the spending conditions are known exactly, and nothing was
guessed about the key material.

What is enumerated
------------------
* P2PK: ``<key> OP_CHECKSIG``.
* Multisig, every ``m``-of-``n`` for the supplied keys: ``OP_m <k1> ... <kn> OP_n
  OP_CHECKMULTISIG``.
* Timelock-wrapped single key: ``<value> OP_CHECKLOCKTIMEVERIFY OP_DROP <key>
  OP_CHECKSIG`` for each height the caller supplies.
* HTLC, when the caller supplies hash locks: ``OP_IF OP_HASH160 <h>
  OP_EQUALVERIFY OP_DROP <a> OP_CHECKSIG OP_ELSE <b> OP_CHECKSIG OP_ENDIF``.

Limits, stated in the report rather than discovered by the caller
----------------------------------------------------------------
* Only the compositions above are tried. A custom script, a covenant, or a
  script with an unknown key cannot be found: the search is a finite template
  catalogue, not a proof of absence.
* The key material must be supplied. This module never generates, guesses, or
  derives private keys.
* Every attempt is a hash of a few hundred bytes, so a miss is cheap: the default
  budget is thousands of candidates, not billions.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Final

from .address_formats import decode_address_input
from .exceptions import InputValidationError
from .hashing import hash160, sha256

__all__ = [
    "DEFAULT_MAX_CANDIDATES",
    "CandidateKey",
    "RecoveredScript",
    "ScriptRecovery",
    "enumerate_candidate_scripts",
    "recover_script",
]

#: Hard cap on enumerated scripts. 20 000 hashes is instant; a million is not.
DEFAULT_MAX_CANDIDATES: Final = 20_000
#: Largest multisig key set the catalogue expands (2^15 subsets is already 32 768).
_MAX_KEYS: Final = 15
_OP_CHECKMULTISIG: Final = 0xAE
_OP_CHECKSIG: Final = 0xAC


@dataclass(frozen=True, slots=True)
class CandidateKey:
    """One public key offered as a candidate cosigner.

    Attributes:
        public_key_hex: SEC 1 compressed or uncompressed key.
        label: Where the key came from, for the report.
    """

    public_key_hex: str
    label: str = "caller-supplied"

    def __post_init__(self) -> None:
        """Normalise and validate the key.

        Raises:
            InputValidationError: The key is not a SEC 1 public key.
        """
        cleaned = "".join(self.public_key_hex.split())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if not cleaned:
            raise InputValidationError("a candidate key must not be empty")
        prefix = cleaned[:2].lower()
        if prefix in {"02", "03"} and len(cleaned) == 66:
            object.__setattr__(self, "public_key_hex", cleaned.lower())
            return
        if prefix == "04" and len(cleaned) == 130:
            object.__setattr__(self, "public_key_hex", cleaned.lower())
            return
        raise InputValidationError(
            "a candidate key must be a 33-byte compressed or 65-byte uncompressed SEC 1 public key"
        )

    @property
    def compressed(self) -> str:
        """Return the compressed encoding of this key."""
        if len(self.public_key_hex) == 66:
            return self.public_key_hex
        from .ecc import parse_public_key_hex, public_key_bytes

        return public_key_bytes(parse_public_key_hex(self.public_key_hex), compressed=True).hex()

    @property
    def hash160(self) -> str:
        """Return ``HASH160`` of the compressed key, as used by P2PKH and P2WPKH."""
        return hash160(bytes.fromhex(self.compressed)).hex()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {"public_key_hex": self.public_key_hex, "label": self.label}


@dataclass(frozen=True, slots=True)
class RecoveredScript:
    """One candidate script and whether it matches the address.

    Attributes:
        template: ``p2pk``, ``multisig``, ``timelock``, or ``htlc``.
        summary: A one-line description, e.g. ``2-of-3 multisig``.
        script_hex: The candidate script.
        address: The address the script commits to.
        matched: Whether it is the script this address pays to.
        keys_used: Labels of the candidate keys the script was built from.
    """

    template: str
    summary: str
    script_hex: str
    address: str
    matched: bool
    keys_used: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "template": self.template,
            "summary": self.summary,
            "script_hex": self.script_hex,
            "address": self.address,
            "matched": self.matched,
            "keys_used": list(self.keys_used),
        }


@dataclass(frozen=True, slots=True)
class ScriptRecovery:
    """The result of recovering a script from candidate keys.

    Attributes:
        address: The address examined.
        address_type: Its output type.
        candidate_keys: The keys supplied.
        attempts: Number of scripts (and key hashes) tested.
        truncated: Whether the budget stopped the search early.
        matches: Every candidate that reproduces the address.
        key_matches: Candidate keys whose HASH160 is the address payload.
        verdict: Plain-language conclusion.
        notes: What the search does and does not cover.
    """

    address: str
    address_type: str
    candidate_keys: tuple[CandidateKey, ...]
    attempts: int
    truncated: bool
    matches: tuple[RecoveredScript, ...]
    key_matches: tuple[CandidateKey, ...]
    verdict: str
    notes: tuple[str, ...]

    @property
    def recovered(self) -> bool:
        """Whether the spending conditions were found."""
        return bool(self.matches) or bool(self.key_matches)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "address_type": self.address_type,
            "candidate_keys": [key.as_dict() for key in self.candidate_keys],
            "attempts": self.attempts,
            "truncated": self.truncated,
            "recovered": self.recovered,
            "matches": [match.as_dict() for match in self.matches],
            "key_matches": [key.as_dict() for key in self.key_matches],
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def _push(data: bytes) -> bytes:
    """Return a minimal push of *data*."""
    length = len(data)
    if length < 0x4C:
        return bytes([length]) + data
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + data
    return b"\x4d" + length.to_bytes(2, "little") + data


def _small_int(value: int) -> bytes:
    """Return the minimal push for a small integer (0..16)."""
    if value == 0:
        return b"\x00"
    if 1 <= value <= 16:
        return bytes([0x50 + value])
    if value < 0x80:
        return _push(bytes([value]))
    return _push(value.to_bytes(5, "little").rstrip(b"\x00"))


def _script_number(value: int) -> bytes:
    """Encode an integer as a minimal script number push (for CLTV values)."""
    if value == 0:
        return b"\x00"
    if 1 <= value <= 16:
        return bytes([0x50 + value])
    negative = value < 0
    magnitude = abs(value)
    encoded = bytearray()
    while magnitude:
        encoded.append(magnitude & 0xFF)
        magnitude >>= 8
    if encoded and encoded[-1] & 0x80:
        encoded.append(0x80 if negative else 0x00)
    elif negative and encoded:
        encoded[-1] |= 0x80
    return _push(bytes(encoded))


def enumerate_candidate_scripts(
    keys: tuple[CandidateKey, ...],
    *,
    timelock_values: tuple[int, ...] = (),
    hash_locks: tuple[str, ...] = (),
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> list[tuple[str, str, str, tuple[str, ...]]]:
    """Enumerate scripts the supplied keys can produce.

    Args:
        keys: The candidate public keys.
        timelock_values: Heights or times to wrap a single-key script in CLTV.
        hash_locks: 32-hex-character hash160 digests for HTLC branches.
        max_candidates: Hard budget on the number of scripts returned.

    Returns:
        A list of ``(template, summary, script_hex, key_labels)`` tuples.  The list
        is truncated at ``max_candidates``; the caller can detect that by comparing
        the length with the budget.

    Raises:
        InputValidationError: No keys were supplied, or a hash lock is malformed.
    """
    if not keys:
        raise InputValidationError("at least one candidate public key is required")
    if len(keys) > _MAX_KEYS:
        raise InputValidationError(
            f"at most {_MAX_KEYS} candidate keys are accepted; every additional key "
            "multiplies the multisig subsets"
        )
    for lock in hash_locks:
        cleaned = lock.strip().lower()
        if len(cleaned) != 40 or any(c not in "0123456789abcdef" for c in cleaned):
            raise InputValidationError("a hash lock must be a 40-character HASH160 digest")

    compressed = [key.compressed for key in keys]
    labels = [key.label for key in keys]
    scripts: list[tuple[str, str, str, tuple[str, ...]]] = []

    def add(template: str, summary: str, script: bytes, used: tuple[str, ...]) -> bool:
        """Append a candidate, returning ``False`` when the budget is exhausted."""
        if len(scripts) >= max_candidates:
            return False
        scripts.append((template, summary, script.hex(), used))
        return True

    # P2PK, single key.
    for index, key in enumerate(compressed):
        if not add(
            "p2pk",
            f"p2pk with key #{index + 1}",
            _push(bytes.fromhex(key)) + b"\xac",
            (labels[index],),
        ):
            return scripts

    # Multisig, every m-of-n over every subset.
    for size in range(1, len(compressed) + 1):
        for subset in combinations(range(len(compressed)), size):
            body = b"".join(_push(bytes.fromhex(compressed[index])) for index in subset)
            for threshold in range(1, size + 1):
                script = (
                    _small_int(threshold) + body + _small_int(size) + bytes([_OP_CHECKMULTISIG])
                )
                summary = f"{threshold}-of-{size} multisig"
                if not add("multisig", summary, script, tuple(labels[i] for i in subset)):
                    return scripts

    # Timelock-wrapped single key.
    for value in timelock_values:
        for index, key in enumerate(compressed):
            script = (
                _script_number(value)
                + b"\xb1\x75"
                + _push(bytes.fromhex(key))
                + bytes([_OP_CHECKSIG])
            )
            if not add("timelock", f"CLTV {value} + key #{index + 1}", script, (labels[index],)):
                return scripts

    # HTLC: hash lock branch plus two key branches.
    for lock in hash_locks:
        digest = bytes.fromhex(lock.strip().lower())
        for first in range(len(compressed)):
            for second in range(len(compressed)):
                if first == second:
                    continue
                script = (
                    b"\x63\xa9"
                    + _push(digest)
                    + b"\x88\x75"
                    + _push(bytes.fromhex(compressed[first]))
                    + b"\xac\x67"
                    + _push(bytes.fromhex(compressed[second]))
                    + b"\xac\x68"
                )
                if not add(
                    "htlc",
                    f"HTLC {lock[:8]}... keys #{first + 1}/#{second + 1}",
                    script,
                    (labels[first], labels[second]),
                ):
                    return scripts
    return scripts


def recover_script(
    address: str,
    candidate_keys: tuple[CandidateKey, ...] | list[CandidateKey],
    *,
    timelock_values: tuple[int, ...] = (),
    hash_locks: tuple[str, ...] = (),
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> ScriptRecovery:
    """Try to recover the script behind *address* from candidate public keys.

    Args:
        address: A P2SH, P2WSH, P2PKH, P2WPKH, or P2PK address.
        candidate_keys: Public keys the caller plausibly controls.
        timelock_values: Heights or times to try in CLTV templates.
        hash_locks: HASH160 digests to try in HTLC templates.
        max_candidates: Budget on enumerated scripts.

    Returns:
        The recovery report.  A miss is reported as a miss, with the coverage stated.

    Raises:
        AddressEncodingError: The address is invalid.
        InputValidationError: No keys, or an invalid key or hash lock.

    Example:
        >>> keys = [CandidateKey("02" + "11" * 32, "cosigner A")]
        >>> report = recover_script(p2sh_address, keys)
        >>> report.recovered
        True
    """
    decoded = decode_address_input(address)
    canonical = (address if decoded.address is None else decoded.address).strip()
    keys = tuple(candidate_keys)
    if not keys:
        raise InputValidationError("at least one candidate public key is required")
    kind = decoded.address_type
    payload = decoded.payload.hex()

    key_matches = tuple(key for key in keys if key.hash160 == payload)
    attempts = 0
    matches: list[RecoveredScript] = []

    wants_scripts = kind in {"p2sh", "p2wsh", "p2pk"}
    expected_p2pk = f"{len(payload) // 2:02x}{payload}ac" if kind == "p2pk" else ""
    truncated = False
    if wants_scripts:
        scripts = enumerate_candidate_scripts(
            keys,
            timelock_values=timelock_values,
            hash_locks=hash_locks,
            max_candidates=max_candidates,
        )
        truncated = len(scripts) >= max_candidates
        for template, summary, script_hex, used in scripts:
            attempts += 1
            raw = bytes.fromhex(script_hex)
            if kind == "p2pk":
                matched = script_hex == expected_p2pk
            elif kind == "p2sh":
                matched = hash160(raw).hex() == payload
            else:
                matched = sha256(raw).hex() == payload
            if matched:
                matches.append(
                    RecoveredScript(
                        template=template,
                        summary=summary,
                        script_hex=script_hex,
                        address=canonical,
                        matched=True,
                        keys_used=used,
                    )
                )
    attempts += len(keys)

    if matches:
        found = matches[0]
        verdict = (
            f"recovered: the address pays to {found.summary}, verified by recomputing "
            "the hash of the enumerated script"
        )
    elif key_matches:
        verdict = (
            "recovered at the key level: one of the supplied public keys hashes to the "
            "address payload, so the address is that key's P2PKH/P2WPKH output"
        )
    elif truncated:
        verdict = (
            f"no match in the first {attempts} candidates, and the budget stopped the "
            "search: this is inconclusive, not negative"
        )
    elif kind in {"p2sh", "p2wsh", "p2pk"}:
        verdict = (
            f"no match among {attempts} template scripts built from the supplied keys. "
            "The script may use a key you did not supply, a template outside the "
            "catalogue, or a custom construction"
        )
    else:
        verdict = (
            f"none of the {len(keys)} supplied keys hashes to this {kind} payload, so "
            "the address is not derived from any of them"
        )

    notes = [
        "The search is a finite catalogue of standard templates, not a proof of absence.",
        "No private key was generated, guessed, or derived; only supplied public keys were hashed.",
        "A recovered script states the spending conditions, not who can satisfy them.",
    ]
    if kind in {"p2pkh", "p2wpkh"}:
        notes.append(
            "For P2PKH/P2WPKH the committed object is a key hash, so the test is a "
            "direct comparison with each candidate key, not a script enumeration."
        )
    if kind == "p2tr":
        notes.append(
            "Taproot output keys are tweaked, so a supplied internal key does not match "
            "directly; use dissect-address --public-key, which applies the BIP-341 tweak."
        )

    return ScriptRecovery(
        address=canonical,
        address_type=kind,
        candidate_keys=keys,
        attempts=attempts,
        truncated=truncated,
        matches=tuple(matches),
        key_matches=key_matches,
        verdict=verdict,
        notes=tuple(notes),
    )
