"""Bitcoin script tokens, template classification, and redeem-script claims.

An address commits to a script but does not reveal it. This module closes that gap
from the honest direction: the caller supplies a candidate script, and the tool
checks cryptographically whether the address really commits to it, then classifies
what the script *is*.

What it can prove
-----------------
* ``HASH160(script)`` or ``SHA256(script)`` equals the address payload. That is a
  byte-exact verification, not a heuristic: if it matches, the script is the one the
  address pays to (up to hash collisions).
* The script's template: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, multisig with its
  threshold, hash-time-locked contract, CLTV/CSV timelock wrapper, OP_RETURN.

What it cannot prove
--------------------
* Who holds the keys behind the script, or whether those keys still exist.
* Anything at all when no script is supplied: a hash is not a reveal.

The tokenizer is deliberately small and total: every byte sequence either parses
into tokens or raises with the offset that broke it. It is never used to execute,
sign, or construct a transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from .address_formats import DecodedInput, decode_address_input
from .exceptions import AddressEncodingError
from .hashing import hash160, sha256

__all__ = [
    "OPCODES",
    "ScriptTemplate",
    "ScriptVerification",
    "Token",
    "classify_script",
    "disassemble",
    "parse_script",
    "verify_script_claim",
]

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

OPCODES: Final[dict[int, str]] = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    0x61: "OP_NOP",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK",
    0x6C: "OP_FROMALTSTACK",
    0x73: "OP_IFDUP",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x7C: "OP_SWAP",
    0x82: "OP_SIZE",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x93: "OP_ADD",
    0xA6: "OP_RIPEMD160",
    0xA8: "OP_SHA256",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
}
OPCODES.update({code: f"OP_{code - 0x50}" for code in range(0x51, 0x61)})

_HASH_OPS: Final = {0xA6: "RIPEMD160", 0xA8: "SHA256", 0xA9: "HASH160", 0xAA: "HASH256"}
_EQUAL_OPS: Final = {0x87, 0x88}
_CLTV: Final = 0xB1
_CSV: Final = 0xB2
_MAX_SCRIPT_BYTES: Final = 10_000
_LOCKTIME_THRESHOLD: Final = 500_000_000


@dataclass(frozen=True, slots=True)
class Token:
    """One parsed script token.

    Attributes:
        opcode: The opcode byte.
        name: Mnemonic, e.g. ``OP_CHECKSIG``.
        data: Pushed bytes for push operations, else ``None``.
        offset: Byte offset in the script.
        width: Bytes consumed, including the length prefix.
    """

    opcode: int
    name: str
    data: bytes | None
    offset: int
    width: int

    @property
    def is_push(self) -> bool:
        """Whether this token pushes data (or a small integer)."""
        return self.data is not None or self.opcode == 0x00 or 0x51 <= self.opcode <= 0x60

    @property
    def small_int(self) -> int | None:
        """Return the pushed small integer, or ``None``."""
        if self.opcode == 0x00:
            return 0
        if 0x51 <= self.opcode <= 0x60:
            return self.opcode - 0x50
        if self.data is not None and 1 <= len(self.data) <= 4:
            return int.from_bytes(self.data, "little")
        return None

    def as_text(self) -> str:
        """Return a disassembly fragment."""
        if self.data is not None:
            return self.data.hex() if self.data else "OP_0"
        if 0x51 <= self.opcode <= 0x60:
            return f"OP_{self.opcode - 0x50}"
        return self.name

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "offset": self.offset,
            "opcode": f"0x{self.opcode:02x}",
            "name": self.name,
            "push_hex": None if self.data is None else self.data.hex(),
        }


def _to_bytes(script: bytes | str) -> bytes:
    """Return *script* as bytes, parsing hexadecimal when needed."""
    if isinstance(script, bytes):
        return script
    text = script.strip().lower().removeprefix("0x")
    if len(text) % 2:
        raise AddressEncodingError("script hex must have an even number of digits")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise AddressEncodingError("script is not hexadecimal") from exc


def parse_script(script: bytes | str) -> tuple[Token, ...]:
    """Parse a script into tokens.

    Args:
        script: Raw bytes, or a hexadecimal string.

    Returns:
        The token stream.

    Raises:
        AddressEncodingError: The script is too long, truncated, or malformed.
    """
    data = _to_bytes(script)
    if len(data) > _MAX_SCRIPT_BYTES:
        raise AddressEncodingError(f"script exceeds {_MAX_SCRIPT_BYTES} bytes")
    tokens: list[Token] = []
    index = 0
    while index < len(data):
        opcode = data[index]
        offset = index
        index += 1
        if 0x01 <= opcode <= 0x4B:
            end = index + opcode
            if end > len(data):
                raise AddressEncodingError(f"truncated push at offset {offset}")
            tokens.append(Token(opcode, f"PUSH_{opcode}", data[index:end], offset, end - offset))
            index = end
            continue
        width = {0x4C: 1, 0x4D: 2, 0x4E: 4}.get(opcode)
        if width is not None:
            if index + width > len(data):
                raise AddressEncodingError(f"truncated {OPCODES[opcode]} at offset {offset}")
            length = int.from_bytes(data[index : index + width], "little")
            index += width
            end = index + length
            if end > len(data):
                raise AddressEncodingError(f"truncated data push at offset {offset}")
            tokens.append(Token(opcode, OPCODES[opcode], data[index:end], offset, end - offset))
            index = end
            continue
        tokens.append(
            Token(opcode, OPCODES.get(opcode, f"OP_UNKNOWN_{opcode:02x}"), None, offset, 1)
        )
    return tuple(tokens)


def disassemble(script: bytes | str) -> str:
    """Return a readable disassembly of *script*."""
    return " ".join(token.as_text() for token in parse_script(script))


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScriptTemplate:
    """The classification of one script.

    Attributes:
        kind: ``p2pkh``, ``p2sh``, ``p2wpkh``, ``p2wsh``, ``p2tr``, ``p2pk``,
            ``multisig``, ``htlc``, ``timelock``, ``op_return``, or
            ``nonstandard``.
        threshold: Signatures required, for multisig.
        total_keys: Keys listed, for multisig.
        public_keys: Every embedded public key in hexadecimal.
        hash_lock: The hash a spender must preimage, in hexadecimal.
        hash_algorithm: The opcode used for that hash lock.
        timelock_value: The CLTV/CSV argument, in blocks or seconds.
        timelock_kind: ``height``, ``time``, or ``relative``.
        branches: Number of conditional branches (1 when there is no IF/ELSE).
        notes: Facts a reader needs, including what the script hides.
        disassembly: The full token listing.
    """

    kind: str
    threshold: int | None
    total_keys: int | None
    public_keys: tuple[str, ...]
    hash_lock: str | None
    hash_algorithm: str | None
    timelock_value: int | None
    timelock_kind: str | None
    branches: int
    notes: tuple[str, ...]
    disassembly: str

    @property
    def spend_paths(self) -> int:
        """Return the number of distinct spending paths the script allows."""
        if self.kind == "multisig" and self.threshold and self.total_keys:
            return 1
        return max(1, self.branches)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "kind": self.kind,
            "threshold": self.threshold,
            "total_keys": self.total_keys,
            "public_keys": list(self.public_keys),
            "hash_lock": self.hash_lock,
            "hash_algorithm": self.hash_algorithm,
            "timelock_value": self.timelock_value,
            "timelock_kind": self.timelock_kind,
            "branches": self.branches,
            "spend_paths": self.spend_paths,
            "disassembly": self.disassembly,
            "notes": list(self.notes),
        }


def _pushes(tokens: tuple[Token, ...], index: int) -> bytes | None:
    """Return the pushed data at *index*, if it is a direct push."""
    token = tokens[index]
    if token.data is None:
        return None
    return token.data


def _is_pubkey(data: bytes | None) -> bool:
    """Return whether *data* looks like a SEC 1 public key."""
    if data is None:
        return False
    if len(data) == 33 and data[0] in (2, 3):
        return True
    return len(data) == 65 and data[0] == 4


def _match_multisig(tokens: tuple[Token, ...]) -> tuple[int, int, tuple[str, ...]] | None:
    """Return ``(threshold, total, keys)`` when the script is a bare multisig."""
    if len(tokens) < 3:
        return None
    last = tokens[-1]
    if last.opcode not in (0xAE, 0xAF):
        return None
    count = tokens[-2].small_int
    if not count or not 1 <= count <= 16:
        return None
    keys = tokens[1:-2]
    if len(keys) != count or not all(_is_pubkey(token.data) for token in keys):
        return None
    threshold = tokens[0].small_int
    if not threshold or not 1 <= threshold <= count:
        return None
    return threshold, count, tuple((token.data or b"").hex() for token in keys)


def _find_hash_lock(tokens: tuple[Token, ...]) -> tuple[str | None, str | None]:
    """Return ``(hash_hex, algorithm)`` for the first hash lock in the script."""
    for index, token in enumerate(tokens[:-2]):
        if token.opcode in _HASH_OPS and tokens[index + 2].opcode in _EQUAL_OPS:
            digest = tokens[index + 1].data
            if digest and len(digest) in (20, 32):
                return digest.hex(), _HASH_OPS[token.opcode]
    return None, None


def _find_timelock(tokens: tuple[Token, ...]) -> tuple[int | None, str | None]:
    """Return ``(value, kind)`` for the first CLTV/CSV in the script."""
    for index, token in enumerate(tokens):
        if token.opcode in (_CLTV, _CSV) and index > 0:
            value = tokens[index - 1].small_int
            if value is None:
                continue
            if token.opcode == _CSV:
                return value, "relative"
            return value, "time" if value >= _LOCKTIME_THRESHOLD else "height"
    return None, None


def classify_script(script: bytes | str) -> ScriptTemplate:
    """Classify a script into a template, extracting its parameters.

    Args:
        script: Raw bytes or hexadecimal.

    Returns:
        The classification.  An unrecognised script is reported as
        ``nonstandard`` rather than raising.

    Raises:
        AddressEncodingError: The script cannot be parsed.
    """
    tokens = parse_script(script)
    text = " ".join(token.as_text() for token in tokens)
    if not tokens:
        return ScriptTemplate(
            "nonstandard", None, None, (), None, None, None, None, 0, ("empty script",), text
        )
    opcodes = [token.opcode for token in tokens]
    branches = max(1, opcodes.count(0x63) + opcodes.count(0x64))

    if opcodes == [0x76, 0xA9, 0x14, 0x88, 0xAC] and tokens[2].data is not None:
        return ScriptTemplate(
            "p2pkh",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("A single key whose HASH160 is committed here can spend it.",),
            text,
        )
    if opcodes == [0xA9, 0x14, 0x87] and tokens[1].data is not None:
        return ScriptTemplate(
            "p2sh",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("The redeem script is hidden behind HASH160 until the output is spent.",),
            text,
        )
    if opcodes == [0x00, 0x14] and tokens[1].data is not None:
        return ScriptTemplate(
            "p2wpkh",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("Native SegWit v0 key hash.",),
            text,
        )
    if opcodes == [0x00, 0x20] and tokens[1].data is not None:
        return ScriptTemplate(
            "p2wsh",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("Native SegWit v0 script hash.",),
            text,
        )
    if opcodes == [0x51, 0x20] and tokens[1].data is not None:
        return ScriptTemplate(
            "p2tr",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("Taproot output key (BIP-341).",),
            text,
        )
    if len(tokens) == 2 and _is_pubkey(tokens[0].data) and tokens[1].opcode in (0xAC, 0xAD):
        return ScriptTemplate(
            "p2pk",
            None,
            None,
            ((tokens[0].data or b"").hex(),),
            None,
            None,
            None,
            None,
            branches,
            ("The public key is written into the script.",),
            text,
        )
    multisig = _match_multisig(tokens)
    if multisig is not None:
        threshold, total, keys = multisig
        return ScriptTemplate(
            "multisig",
            threshold,
            total,
            keys,
            None,
            None,
            None,
            None,
            branches,
            (
                f"{threshold}-of-{total} multisig: spending needs {threshold} signatures.",
                "The keys are all published in the script, so the address reveals "
                "nothing until it is spent, but the script reveals everything once it is.",
            ),
            text,
        )

    hash_lock, algorithm = _find_hash_lock(tokens)
    timelock_value, timelock_kind = _find_timelock(tokens)
    has_sig = any(opcode in (0xAC, 0xAD, 0xAE, 0xAF) for opcode in opcodes)
    if hash_lock and has_sig:
        notes = [
            "A hash lock plus a signature check: this is the shape of a hash-time-locked "
            "contract (HTLC) or a payment channel script.",
        ]
        if timelock_value is not None:
            notes.append(f"A timelock of {timelock_value} ({timelock_kind}) bounds one branch.")
        if branches > 1:
            notes.append(f"{branches} conditional branch(es) give more than one way to spend.")
        return ScriptTemplate(
            "htlc",
            None,
            None,
            tuple((token.data or b"").hex() for token in tokens if _is_pubkey(token.data)),
            hash_lock,
            algorithm,
            timelock_value,
            timelock_kind,
            branches,
            tuple(notes),
            text,
        )
    if timelock_value is not None and has_sig:
        return ScriptTemplate(
            "timelock",
            None,
            None,
            tuple((token.data or b"").hex() for token in tokens if _is_pubkey(token.data)),
            None,
            None,
            timelock_value,
            timelock_kind,
            branches,
            (
                f"Spending is gated on {timelock_kind} {timelock_value}.",
                "A CLTV/CSV gate is not a signature: whoever satisfies it still needs the "
                "key check that follows.",
            ),
            text,
        )
    if opcodes[0] == 0x6A:
        return ScriptTemplate(
            "op_return",
            None,
            None,
            (),
            None,
            None,
            None,
            None,
            branches,
            ("OP_RETURN marks the output unspendable by consensus.",),
            text,
        )
    return ScriptTemplate(
        "nonstandard",
        None,
        None,
        tuple((token.data or b"").hex() for token in tokens if _is_pubkey(token.data)),
        hash_lock,
        algorithm,
        timelock_value,
        timelock_kind,
        branches,
        ("No known template matches; spendability depends on a custom interpreter.",),
        text,
    )


# ---------------------------------------------------------------------------
# Redeem-script claims
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScriptVerification:
    """The result of checking a script against an address.

    Attributes:
        address: The address being tested.
        address_type: Its output type.
        script_hex: The candidate script.
        hash_algorithm: ``HASH160`` or ``SHA256``, or ``None`` when not applicable.
        required_hash: The digest the address commits to.
        computed_hash: The digest of the candidate script.
        matches: Whether they agree.
        template: Classification of the candidate script.
        verdict: Plain-language conclusion.
        notes: Caveats specific to this comparison.
    """

    address: str
    address_type: str
    script_hex: str
    hash_algorithm: str | None
    required_hash: str
    computed_hash: str
    matches: bool
    template: ScriptTemplate
    verdict: str
    notes: tuple[str, ...]

    @property
    def proves_membership(self) -> bool:
        """Whether the script is cryptographically bound to the address."""
        return self.matches

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "address_type": self.address_type,
            "script_hex": self.script_hex,
            "hash_algorithm": self.hash_algorithm,
            "required_hash": self.required_hash,
            "computed_hash": self.computed_hash,
            "matches": self.matches,
            "proves_membership": self.proves_membership,
            "template": self.template.as_dict(),
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def _script_hash_for(decoded: DecodedInput) -> tuple[str, str] | None:
    """Return ``(algorithm, digest_hex)`` the address commits to, if any."""
    if decoded.address_type == "p2sh":
        return "HASH160", decoded.payload.hex()
    if decoded.address_type == "p2wsh":
        return "SHA256", decoded.payload.hex()
    return None


def verify_script_claim(address: str, script: bytes | str) -> ScriptVerification:
    """Check whether *script* is the script an address commits to.

    For P2SH the address commits to ``HASH160(script)``; for P2WSH it commits to
    ``SHA256(script)``. For every other type the candidate is compared with the
    scriptPubKey the address itself encodes, which is only informative for P2PKH,
    P2WPKH, and P2TR.

    Args:
        address: The address to test.
        script: The candidate redeem or witness script.

    Returns:
        The verification, always with a classification of the candidate.

    Raises:
        AddressEncodingError: The address or the script is malformed.
    """
    decoded = decode_address_input(address)
    raw = _to_bytes(script)
    if len(raw) > _MAX_SCRIPT_BYTES:
        raise AddressEncodingError(f"script exceeds {_MAX_SCRIPT_BYTES} bytes")
    template = classify_script(script)
    target = _script_hash_for(decoded)
    notes: list[str] = []

    if target is None:
        from .address_forensics import dissect_address

        dissection = dissect_address(decoded.address or address)
        expected = dissection.script_pubkey_hex.lower()
        computed = raw.hex()
        matches = expected == computed
        verdict = (
            "the candidate script is byte-identical to this address's scriptPubKey"
            if matches
            else "this address does not commit to a script hash, so the candidate is "
            "only comparable with its scriptPubKey, and it differs"
        )
        notes.append(
            "For P2PKH, P2WPKH, and P2TR the committed object is a key hash or a key, "
            "not a script, so a redeem-script claim is not the right question."
        )
        return ScriptVerification(
            address=decoded.address or address,
            address_type=decoded.address_type,
            script_hex=raw.hex(),
            hash_algorithm=None,
            required_hash=expected,
            computed_hash=computed,
            matches=matches,
            template=template,
            verdict=verdict,
            notes=tuple(notes),
        )

    algorithm, required = target
    computed = (hash160(raw) if algorithm == "HASH160" else sha256(raw)).hex()
    matches = computed == required
    if matches:
        verdict = (
            f"verified: {algorithm}(script) equals the address payload, so this is the "
            "script the address pays to, up to hash collisions"
        )
    else:
        verdict = (
            f"not a match: {algorithm}(script) = {computed[:16]}..., but the address "
            f"commits to {required[:16]}..."
        )
    if decoded.address_type == "p2sh":
        notes.append(
            "A verified P2SH script explains the output completely: the spendability "
            "question now depends on the template below, not on the hash."
        )
    else:
        notes.append(
            "A verified witness script explains the output completely; the spending "
            "conditions are the ones listed in the template."
        )
    return ScriptVerification(
        address=decoded.address or address,
        address_type=decoded.address_type,
        script_hex=raw.hex(),
        hash_algorithm=algorithm,
        required_hash=required,
        computed_hash=computed,
        matches=matches,
        template=template,
        verdict=verdict,
        notes=tuple(notes),
    )
