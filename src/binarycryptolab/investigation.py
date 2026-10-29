"""Turn a dissection into an actionable investigation plan.

A report that ends with "no key is recoverable" is honest but not useful. This
module converts every gap in the evidence into a **lead**: the specific public
artefact that would close it, what it would prove, and what it would still not
prove.

The leads are ordered by yield per unit of effort, and each states its own limit.
That ordering is the intelligence: it tells a reader that supplying one cosigner
key is worth more than a week of guessing, and that some questions are not open at
all because the mathematics forbids them.

Nothing here performs an attack. A lead is a request for public data the owner
already has, or a measurement the tool can already make.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from .address_forensics import AddressDissection

__all__ = ["InvestigationLead", "InvestigationPlan", "build_plan"]

_EFFORT_ORDER: Final = {"none": 0, "seconds": 1, "minutes": 2, "hours": 3, "infeasible": 4}


@dataclass(frozen=True, slots=True)
class InvestigationLead:
    """One actionable next step.

    Attributes:
        code: Stable identifier.
        question: The question this lead would answer.
        needs: The public artefact or action required.
        proves: What a positive result establishes.
        does_not_prove: What it leaves unresolved.
        effort: ``none``, ``seconds``, ``minutes``, ``hours``, or ``infeasible``.
        command: A copy-pasteable command, when one exists.
        available: Whether the tool can act on it right now without new input.
    """

    code: str
    question: str
    needs: str
    proves: str
    does_not_prove: str
    effort: str
    command: str | None = None
    available: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "code": self.code,
            "question": self.question,
            "needs": self.needs,
            "proves": self.proves,
            "does_not_prove": self.does_not_prove,
            "effort": self.effort,
            "command": self.command,
            "available": self.available,
        }


@dataclass(frozen=True, slots=True)
class InvestigationPlan:
    """The ordered leads for one address.

    Attributes:
        address: The address being investigated.
        leads: Actionable steps, cheapest first.
        closed: Questions that are mathematically closed, with the reason.
        summary: One-line reading of the plan.
    """

    address: str
    leads: tuple[InvestigationLead, ...]
    closed: tuple[str, ...]
    summary: str

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "address": self.address,
            "leads": [lead.as_dict() for lead in self.leads],
            "closed": list(self.closed),
            "summary": self.summary,
        }


def build_plan(dissection: AddressDissection) -> InvestigationPlan:
    """Derive the investigation plan for a completed dissection.

    Args:
        dissection: A completed :class:`~binarycryptolab.address_forensics.AddressDissection`.

    Returns:
        The plan.  It always contains at least one lead or one closed question.
    """
    address = dissection.address
    kind = dissection.address_type
    chain = dissection.chain
    leads: list[InvestigationLead] = []
    closed: list[str] = []
    spent_condition = (
        "If the output is ever spent and its public key becomes public, the remaining "
        "barrier becomes the"
    )

    if kind in {"p2sh", "p2wsh"}:
        leads.append(
            InvestigationLead(
                code="recover_script",
                question="What spending conditions does this script hash commit to?",
                needs="the public keys of the participants (yours, your cosigners')",
                proves="the exact multisig threshold, HTLC hash lock, or timelock",
                does_not_prove="who holds those keys, or whether they still exist",
                effort="seconds",
                command=f"binarycryptolab recover-script {address} --candidate-key <HEX> ...",
                available=False,
            )
        )
        closed.append(
            f"The script itself cannot be derived from {kind} alone: that is the hash "
            "preimage problem, and the tool will not pretend to brute-force it."
        )
    if kind in {"p2pkh", "p2wpkh", "p2tr"}:
        leads.append(
            InvestigationLead(
                code="controlled_experiment",
                question="Does a public key I already hold own this address?",
                needs="that public key",
                proves="exact ownership of the address by that key",
                does_not_prove="that the coins are still there, or that a signature exists",
                effort="seconds",
                command=f"binarycryptolab dissect-address {address} --public-key <HEX>",
                available=False,
            )
        )
    leads.append(
        InvestigationLead(
            code="extended_key",
            question="Does this address belong to a wallet I can identify?",
            needs="the wallet's extended public key",
            proves="the derivation index, and therefore that the wallet owns it",
            does_not_prove="ownership by anyone else, or the balance",
            effort="minutes",
            command=f"binarycryptolab dissect-address {address} --xpub <XPUB> --index-range 0:100",
            available=False,
        )
    )
    leads.append(
        InvestigationLead(
            code="chain_data",
            question="What has this address received and spent?",
            needs="a UTXO export you produce yourself",
            proves="that the export matches this script, and its arithmetic",
            does_not_prove="that the export is complete or current: the tool is offline",
            effort="minutes",
            command=f"binarycryptolab audit-address-data {address} --input-file export.json",
            available=False,
        )
    )
    if kind == "p2tr":
        leads.append(
            InvestigationLead(
                code="taproot_script_path",
                question="What script path, if any, does this Taproot output commit to?",
                needs="the internal key and the script tree",
                proves="the script-path spending conditions",
                does_not_prove="the key-path secret",
                effort="seconds",
                command=f"binarycryptolab dissect-address {address} --public-key <INTERNAL_KEY>",
                available=False,
            )
        )
    if dissection.uri_params:
        leads.append(
            InvestigationLead(
                code="payment_uri",
                question="Was this address offered with a hostile amount or feature?",
                needs="nothing: the URI is already here",
                proves="the parameters that were attached, verbatim",
                does_not_prove="whether the payer's wallet honoured them",
                effort="none",
                available=True,
            )
        )
    if dissection.vanity.constrained_bits:
        leads.append(
            InvestigationLead(
                code="prefix_economics",
                question="Could this prefix have been mined on purpose?",
                needs="nothing: the cost is measurable",
                proves=(
                    "the expected work in attempts, and the wall-clock time at this "
                    "machine's measured rate"
                ),
                does_not_prove="that anyone actually did mine it",
                effort="none",
                command=f"binarycryptolab estimate-mining {address}",
                available=True,
            )
        )

    leads.append(
        InvestigationLead(
            code="private_key",
            question="What is the private key behind this address?",
            needs="a HASH160 preimage, then a discrete log",
            proves="nothing, because neither step can be run",
            does_not_prove="everything: this is the question the tool refuses to pretend to answer",
            effort="infeasible",
        )
    )
    if chain != "bitcoin":
        leads.append(
            InvestigationLead(
                code="cross_chain",
                question="Is this address reused on another chain with the same payload?",
                needs="the other chain's address list",
                proves="cross-chain reuse, which is a privacy hazard",
                does_not_prove="a shared owner",
                effort="minutes",
                command=f"binarycryptolab compare-addresses {address} <OTHER_ADDRESS>",
                available=False,
            )
        )

    closed.append(
        f"{spent_condition} {kind} discrete logarithm, about 2^128 classical operations."
        if kind in {"p2pkh", "p2wpkh", "p2tr", "p2pk"}
        else "Spending information is not recoverable from an unspent script hash."
    )
    leads.sort(key=lambda lead: _EFFORT_ORDER[lead.effort])
    feasible = [lead for lead in leads if lead.effort != "infeasible"]
    summary = (
        f"{len(feasible)} lead(s) can be acted on with public data you may already hold, "
        f"and {len(closed)} question(s) are mathematically closed. Key recovery is not "
        "among the leads because it is not an open problem: it is a wall."
    )
    if kind in {"p2sh", "p2wsh"}:
        summary += " The highest-yield first step is recovering the script."
    elif kind in {"p2pkh", "p2wpkh", "p2tr"}:
        summary += " The highest-yield first step is testing a key you already hold."
    return InvestigationPlan(
        address=address, leads=tuple(leads), closed=tuple(closed), summary=summary
    )
