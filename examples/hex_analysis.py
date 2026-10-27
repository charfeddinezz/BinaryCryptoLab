"""Example: analyse hexadecimal data without assuming it is text.

Run from the repository root::

    python examples/hex_analysis.py
"""

from __future__ import annotations

from binarycryptolab import analyze_hex
from binarycryptolab.exceptions import InvalidHexError
from binarycryptolab.hashing import hash_bytes
from binarycryptolab.hex_utils import hex_to_text


def main() -> None:
    print("BinaryCryptoLab example: hexadecimal analysis")
    print("-" * 60)

    result = analyze_hex("2D")
    print(f"input        : {result.original}")
    print(f"normalized   : {result.normalized}")
    print(f"binary       : {result.binary}")
    print(f"integer      : {result.integer_value}")
    print(f"bytes        : {result.byte_stats.byte_length} byte(s)")
    print(f"hamming wt.  : {result.bit_stats.hamming_weight}")
    print(f"entropy      : {result.byte_stats.entropy:.4f} bits/byte")

    print()
    print("A hexadecimal value is just bytes; it is not assumed to be text.")
    print(f"  0x48656c6c6f as UTF-8 (explicit request): {hex_to_text('48656c6c6f')!r}")
    print(f"  0x2d happens to be valid UTF-8          : {analyze_hex('2d').text_utf8!r}")
    print(f"  0xff is not valid UTF-8                 : {analyze_hex('ff').text_utf8!r}")
    try:
        hex_to_text("ff")
    except InvalidHexError as exc:
        print(f"  decoding 0xff as UTF-8 fails clearly    : {exc}")

    print()
    digest = hash_bytes(bytes.fromhex("2d"), "sha256")
    print("Hashing the decoded bytes, not the text:")
    print(f"  sha256(0x2d) = {digest.hexdigest}")

    print()
    print("Odd-length input: a leading zero nibble is prepended and reported.")
    odd = analyze_hex("abc")
    print(f"  abc -> {odd.normalized}, odd_length_input={odd.odd_length_input}")


if __name__ == "__main__":
    main()
