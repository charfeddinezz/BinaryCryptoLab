"""Example: analyse binary strings with BinaryCryptoLab.

Run from the repository root::

    python examples/binary_analysis.py
"""

from __future__ import annotations

from binarycryptolab import analyze_binary
from binarycryptolab.bit_operations import compare_binary_strings
from binarycryptolab.exceptions import InvalidBinaryError


def main() -> None:
    print("BinaryCryptoLab example: binary analysis")
    print("-" * 60)

    sample = "101101"
    result = analyze_binary(sample)
    print(f"input              : {result.original}")
    print(f"normalized         : {result.normalized}")
    print(f"length             : {result.bit_length} bits")
    print(f"integer value      : {result.integer_value}")
    print(f"hexadecimal        : {result.hexadecimal}")
    print(f"ones / zeros       : {result.bit_stats.ones} / {result.bit_stats.zeros}")
    print(f"hamming weight     : {result.bit_stats.hamming_weight}")
    print(f"byte sequence      : {result.bytes_hex} (padding {result.padding_bits} bits)")
    print(f"byte entropy       : {result.byte_stats.entropy:.4f} bits/byte")
    print(f"grouped for reading: {result.grouped_display}")

    print()
    print("Leading zeros are preserved in the textual statistics:")
    wide = analyze_binary("0000101101")
    print(f"  {wide.normalized} -> {wide.bit_length} bits, {wide.bit_stats.zeros} zeros,")
    print(f"  integer value is still {wide.integer_value}")

    print()
    print("Bit comparison (shorter input is left-padded):")
    comparison = compare_binary_strings("1010", "001011")
    print(f"  differing bits    : {comparison.differing_indices} (from the MSB)")
    print(f"  hamming distance  : {comparison.hamming_distance}")
    print(f"  padding applied   : {comparison.padding_applied}")

    print()
    print("Invalid input is rejected explicitly:")
    for candidate in ("102", "0b", "0x2d"):
        try:
            analyze_binary(candidate)
        except InvalidBinaryError as exc:
            print(f"  {candidate!r}: {exc}")


if __name__ == "__main__":
    main()
