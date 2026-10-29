"""Relate a set of addresses to each other, offline and exactly.

Comparing public keys finds related scalars. Comparing *addresses* cannot do that,
but it can find a different and genuinely useful family of facts:

* the same payload in different encodings, which is address reuse across networks
  and a real hazard when someone is told "send to this address" on the wrong chain;
* the same script hash appearing as P2SH and as P2WSH of the same script, which
  reveals that the two addresses are two locks on the same fund;
* identical leading or trailing bits in the payloads, with an exact binomial
  p-value, so a "these look similar" intuition becomes a number;
* an address whose payload equals the hash of another address's locking script,
  the nesting relation P2SH(P2WPKH) and P2SH(P2WSH) produce.

Every relation is reported with its evidence and a probability where a probability
exists. Absence of a relation is also reported, because "these are unrelated" is a
finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any

from .address_forensics import dissect_address
from .exceptions import InputValidationError
from .hashing import hash160, sha256

__all__ = ["AddressComparison", "AddressRelation", "compare_addresses"]

_MAX_ADDRESSES = 200


@dataclass(frozen=True, slots=True)
class AddressRelation:
    """One relation between two addresses.

    Attributes:
        kind: ``same_payload``, ``same_address``, ``nested_script``, ``shared_bits``,
            or ``shared_prefix``.
        left: First address, or its index label.
        right: Second address.
        evidence: The exact values that establish the relation.
        probability: Chance of the relation happening by accident, when defined.
        explanation: Why it matters.
    """

    kind: str
    left: str
    right: str
    evidence: str
    probability: float | None
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "kind": self.kind,
            "left": self.left,
            "right": self.right,
            "evidence": self.evidence,
            "probability": self.probability,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class AddressComparison:
    """The full comparison of a set of addresses.

    Attributes:
        addresses: The inputs, in order.
        types: The type of each input.
        payloads: The payload of each input, in hexadecimal.
        relations: Every relation found, most significant first.
        pair_count: Number of pairs examined.
        verdict: Plain-language summary.
        notes: What the comparison cannot establish.
    """

    addresses: tuple[str, ...]
    types: tuple[str, ...]
    payloads: tuple[str, ...]
    relations: tuple[AddressRelation, ...]
    pair_count: int
    verdict: str
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "addresses": list(self.addresses),
            "types": list(self.types),
            "payloads": list(self.payloads),
            "relations": [relation.as_dict() for relation in self.relations],
            "pair_count": self.pair_count,
            "verdict": self.verdict,
            "notes": list(self.notes),
        }


def _shared_bits(left: str, right: str) -> tuple[int, int]:
    """Return ``(shared_leading, shared_trailing)`` in bits between two hex payloads."""
    if len(left) != len(right):
        return 0, 0
    left_bits = bin(int(left, 16))[2:].zfill(len(left) * 4) if left else ""
    right_bits = bin(int(right, 16))[2:].zfill(len(right) * 4) if right else ""
    leading = 0
    for left_bit, right_bit in zip(left_bits, right_bits, strict=True):
        if left_bit != right_bit:
            break
        leading += 1
    trailing = 0
    for left_bit, right_bit in zip(reversed(left_bits), reversed(right_bits), strict=True):
        if left_bit != right_bit:
            break
        trailing += 1
    return leading, trailing


def _shared_bit_probability(shared: int) -> float:
    """Return the chance that two independent payloads agree on *shared* bits."""
    if shared <= 0:
        return 1.0
    return 2.0 ** -min(shared, 1023)


def compare_addresses(addresses: list[str] | tuple[str, ...]) -> AddressComparison:
    """Compare a set of addresses for structural relations.

    Args:
        addresses: Two or more addresses, URIs, or scripts.

    Returns:
        The comparison.

    Raises:
        InputValidationError: Fewer than two or more than 200 inputs.
        AddressEncodingError: An input is invalid.

    Example:
        >>> result = compare_addresses(["1GeMQKJ8...", "bc1qw508..."])  # doctest: +SKIP
        >>> result.relations  # doctest: +SKIP
        ()
    """
    items = [str(item) for item in addresses]
    if len(items) < 2:
        raise InputValidationError("comparison needs at least two addresses")
    if len(items) > _MAX_ADDRESSES:
        raise InputValidationError(f"at most {_MAX_ADDRESSES} addresses can be compared")

    dissections = [dissect_address(item) for item in items]
    canonical = tuple(item.address for item in dissections)
    payloads = tuple(item.payload_hex for item in dissections)
    types = tuple(item.address_type for item in dissections)
    relations: list[AddressRelation] = []

    for left_index, right_index in combinations(range(len(items)), 2):
        left, right = canonical[left_index], canonical[right_index]
        left_payload, right_payload = payloads[left_index], payloads[right_index]
        left_type, right_type = types[left_index], types[right_index]

        if left == right:
            relations.append(
                AddressRelation(
                    kind="same_address",
                    left=left,
                    right=right,
                    evidence="identical string and encoding",
                    probability=1.0,
                    explanation=(
                        "The same address was supplied twice. Nothing follows except that "
                        "the comparison is symmetric."
                    ),
                )
            )
            continue

        if left_payload and left_payload == right_payload:
            relations.append(
                AddressRelation(
                    kind="same_payload",
                    left=left,
                    right=right,
                    evidence=f"payload {left_payload} appears as {left_type} and {right_type}",
                    probability=1.0,
                    explanation=(
                        "The same hash is encoded twice. On different networks this is "
                        "address reuse across chains: a wallet on the wrong chain pays a "
                        "different owner, and some bridges watch exactly this pattern."
                    ),
                )
            )
            continue

        # Nesting: does one address's payload hash the other's locking script?
        left_script = dissections[left_index].script_pubkey_hex
        right_script = dissections[right_index].script_pubkey_hex
        for outer_index, inner_index in ((left_index, right_index), (right_index, left_index)):
            outer = dissections[outer_index]
            inner_script = right_script if inner_index == right_index else left_script
            if not inner_script:
                continue
            candidates = {"hash160": hash160(bytes.fromhex(inner_script)).hex()}
            candidates["sha256"] = sha256(bytes.fromhex(inner_script)).hex()
            for algorithm, digest in candidates.items():
                if digest == outer.payload_hex:
                    relations.append(
                        AddressRelation(
                            kind="nested_script",
                            left=canonical[outer_index],
                            right=canonical[inner_index],
                            evidence=f"{algorithm}(scriptPubKey of the right) = payload of the left",
                            probability=1.0,
                            explanation=(
                                "One address wraps the other's locking script. This is the "
                                "P2SH(P2WPKH) or P2SH(P2WSH) pattern: two locks on the same "
                                "fund, usually the same owner."
                            ),
                        )
                    )

        leading, trailing = _shared_bits(left_payload, right_payload)
        total_bits = max(len(left_payload), len(right_payload)) * 4
        if total_bits and leading >= 16:
            probability = _shared_bit_probability(leading)
            relations.append(
                AddressRelation(
                    kind="shared_bits",
                    left=left,
                    right=right,
                    evidence=f"{leading} shared leading bits of {total_bits}",
                    probability=probability,
                    explanation=(
                        "Long shared prefixes are rare by chance. They usually mean the "
                        "same generator or a truncated comparison, not a shared key."
                    ),
                )
            )
        if total_bits and trailing >= 16 and trailing != leading:
            relations.append(
                AddressRelation(
                    kind="shared_bits",
                    left=left,
                    right=right,
                    evidence=f"{trailing} shared trailing bits of {total_bits}",
                    probability=_shared_bit_probability(trailing),
                    explanation="A shared suffix has the same interpretation as a shared prefix.",
                )
            )

    relations.sort(
        key=lambda item: (
            0 if item.kind in {"same_payload", "nested_script"} else 1,
            item.probability if item.probability is not None else 1.0,
        )
    )

    strong = [item for item in relations if item.kind in {"same_payload", "nested_script"}]
    pair_count = len(items) * (len(items) - 1) // 2
    if strong:
        verdict = (
            f"{len(strong)} structural relation(s) found among {pair_count} pairs: these "
            "addresses are not independent"
        )
    elif relations:
        verdict = (
            f"only statistical resemblance among {pair_count} pairs; no payload, script, "
            "or nesting relation ties these addresses together"
        )
    else:
        verdict = (
            f"no relation found among {pair_count} pairs: the payloads are unrelated at "
            "the resolution this tool can see"
        )

    return AddressComparison(
        addresses=canonical,
        types=types,
        payloads=payloads,
        relations=tuple(relations),
        pair_count=pair_count,
        verdict=verdict,
        notes=(
            "Address comparison cannot relate two private keys: that is a discrete-log "
            "question, not a string question.",
            "A shared payload on two networks is address reuse, which is a privacy and "
            "safety hazard, not evidence of a shared owner.",
            "Absence of a relation is informative only at this resolution; addresses of "
            "different key pairs are expected to show none.",
        ),
    )
