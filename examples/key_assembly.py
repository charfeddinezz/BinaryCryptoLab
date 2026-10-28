"""Example: reduce everything known about a scalar to one scale, then assemble it.

Run with::

    python examples/key_assembly.py

The scalars used here are synthetic and chosen by this script; no real key is
involved.  The example shows the three honest capabilities of the module:

1. a segment view of a 64-digit hexadecimal scalar;
2. a single information scale where public data is worth zero bits and only real
   knowledge reduces the remaining search;
3. a bounded assembly of the unknown hex window, verified against the public key,
   plus related-key detection across a set of keys.

It also shows the refusal: a template with too many unknown bits is rejected
instead of pretending to attack the curve.
"""

from __future__ import annotations

from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.exceptions import InputValidationError
from binarycryptolab.key_reconstruction import (
    build_ledger,
    compare_keys,
    parse_template,
    segment_hex,
    solve_template,
)
from binarycryptolab.utils.formatting import format_table

RULE = "-" * 78

#: A synthetic scalar: fixed leading digits, an unknown tail of six nibbles.
DEMO_SCALAR = int("c0ffee" + "0" * 50 + "abcdef", 16)


def main() -> int:
    """Print the ledger, the assembly, and a key comparison."""
    public_key = public_key_from_private(DEMO_SCALAR).compressed_hex
    print("BinaryCryptoLab example: bounded key assembly")
    print(RULE)
    print(f"public key: {public_key}")
    print("The private key is a 64-digit hexadecimal scalar. Nothing below derives")
    print("it from the public key; only the digits you already know are used.\n")

    print("Segments of a 64-digit scalar (8-digit words)")
    print(
        format_table(
            ("Word", "Digits", "Start bit", "Value"),
            [
                (segment.label, segment.digits, str(segment.start_bit), str(segment.value))
                for segment in segment_hex(f"{DEMO_SCALAR:064x}", unit=8)
            ],
        )
    )

    pattern = f"{DEMO_SCALAR:064x}"[:58] + "?" * 6
    template = parse_template(pattern)
    ledger = build_ledger(template)
    print("\nInformation ledger (one scale: bits of the 256-bit scalar)")
    print(
        format_table(
            ("Source", "Bits"),
            [(entry.label, f"{entry.bits:.0f}") for entry in ledger.entries],
        )
    )
    print(f"  known   : {ledger.known_bits:.0f} bits")
    print(f"  unknown : {ledger.unknown_bits:.0f} bits")
    print(f"  verdict : {ledger.verdict}")

    print("\nBounded assembly (the scalar stays redacted in the report)")
    solution = solve_template(public_key, template)
    print(f"  solved   : {solution.solved}")
    print(f"  verified : {solution.verified}")
    print(f"  steps    : {solution.steps}")
    print(f"  elapsed  : {solution.elapsed_seconds:.3f} s")
    print(f"  message  : {solution.message}")

    print("\nRefusal above the budget")
    try:
        solve_template(public_key, "0" * 32 + "?" * 32, max_unknown_bits=16)
    except InputValidationError as error:
        print(f"  refused: {error}")

    print("\nComparing a key set (sequential scalars)")
    keys = [public_key_from_private(1000 + step).compressed_hex for step in range(3)]
    report = compare_keys(keys, max_delta_bits=12)
    print(f"  keys compared  : {report.count}")
    print(f"  shared x prefix: {report.shared_prefix_nibbles} hex digits")
    if report.relationships:
        print(
            format_table(
                ("Left", "Right", "Delta", "Verified"),
                [
                    (str(item.left), str(item.right), str(item.delta), str(item.verified))
                    for item in report.relationships
                ],
            )
        )
    print("  note: a delta links two keys; it does not reveal either scalar.")

    print("\nLimits")
    print("  - A public key alone cannot yield its scalar (discrete logarithm).")
    print("  - Assembly works only when the unknown window is small.")
    print("  - Only use this on keys you generated yourself.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
