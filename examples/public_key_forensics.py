"""Example: dissect a public key from every public angle.

Run with::

    python examples/public_key_forensics.py

The key below is the generator point of secp256k1 (public scalar ``1``). It is
public data and controls no funds. Nothing here computes a private key: the
example shows what *can* be learned from a public key and where the limits are.
"""

from __future__ import annotations

from binarycryptolab.bitcoin import Network
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.forensics import dissect_public_key
from binarycryptolab.utils.formatting import abbreviate, format_table

RULE = "-" * 78


def main() -> int:
    """Print a condensed dissection report."""
    compressed = public_key_from_private(1).compressed_hex
    print("BinaryCryptoLab example: public-key dissection")
    print(RULE)
    print(f"input: {compressed}\n")

    dissection = dissect_public_key(compressed, depth="deep")

    print("Identity")
    print(
        format_table(
            ("Field", "Value"),
            [
                ("curve", dissection.curve),
                ("input encoding", dissection.input_encoding),
                ("prefix byte", dissection.prefix_byte),
                ("y parity", dissection.y_parity),
                ("compressed", dissection.compressed_hex),
                ("uncompressed", dissection.uncompressed_hex),
                ("x-only (BIP-340)", dissection.x_only_hex),
            ],
        )
    )

    print("\nCoordinates")
    print(
        format_table(
            ("Coord", "Bits", "Lead 0s", "Trail 0s", "Weight", "Binomial p", "Entropy"),
            [
                (
                    profile.name,
                    str(profile.bit_length),
                    str(profile.leading_zero_bits),
                    str(profile.trailing_zero_bits),
                    str(profile.hamming_weight),
                    f"{profile.hamming_p_value:.3f}",
                    f"{profile.byte_entropy:.3f}",
                )
                for profile in dissection.coordinates
            ],
        )
    )

    print("\nCurve verification")
    for name, passed in dissection.verification:
        print(f"  [{'ok' if passed else '!!'}] {name}")

    print("\nStructural findings")
    if dissection.findings:
        for finding in dissection.findings:
            print(f"  - [{finding.severity}] {finding.title}: {finding.evidence}")
    else:
        print("  none: this looks like a uniformly random 256-bit point")

    forecast = dissection.forecast
    print("\nForecast")
    print(f"  verdict         : {forecast.verdict}")
    print(f"  size class      : {forecast.size_class}")
    print(f"  structure score : {forecast.structure_score:.1f}/100")
    print(f"  surprisal       : {forecast.total_surprisal_bits:.1f} bits")
    print(f"  recoverable     : {forecast.recoverable}")
    print("\n  Hypotheses")
    for item in forecast.hypotheses:
        print(f"    {item.likelihood:<13} {item.score:.2f}  {item.hypothesis}")

    print("\n  Search cost (not implemented; shown for scale)")
    print(
        format_table(
            ("Strategy", "Bits", "Operations", "Time", "Today"),
            [
                (
                    row.strategy,
                    str(row.scalar_bits),
                    row.operations,
                    abbreviate(row.estimated_time, 30),
                    row.feasible_today,
                )
                for row in forecast.search_estimates[:5]
            ],
        )
    )

    print("\nAddress matrix (mainnet)")
    print(
        format_table(
            ("Type", "Key", "Address", "scriptPubKey"),
            [
                (
                    entry.address_type,
                    entry.key_encoding,
                    entry.address,
                    abbreviate(entry.script_pubkey_hex, 34),
                )
                for entry in dissection.addresses
                if entry.network == Network.MAINNET.value
            ],
        )
    )

    print("\nDigests")
    for name, digest in dissection.digests:
        print(f"  {name:<26} {digest}")

    weak_point = dissect_public_key(_point_with_small_x())
    print("\nA deliberately structured key (x = 1) scores differently")
    print(f"  verdict         : {weak_point.forecast.verdict}")
    print(f"  structure score : {weak_point.forecast.structure_score:.1f}/100")
    print("  finding codes   : " + ", ".join(f.code for f in weak_point.findings))

    print("\nNo private key was computed, searched for, or stored.")
    print("A public key cannot be inverted; the discrete logarithm is infeasible.")
    return 0


def _point_with_small_x() -> str:
    """Return a valid compressed public key whose x coordinate is 1."""
    prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    rhs = (pow(1, 3, prime) + 7) % prime
    y = pow(rhs, (prime + 1) // 4, prime)
    prefix = 0x02 if y % 2 == 0 else 0x03
    return (bytes([prefix]) + (1).to_bytes(32, "big")).hex()


if __name__ == "__main__":
    raise SystemExit(main())
