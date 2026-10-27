"""Example: derive public keys and Bitcoin addresses from a TEST scalar.

The scalar ``1`` is the publicly known generator-point scalar.  It is used here
only to demonstrate the API and must never be used for a funded wallet.

Run from the repository root::

    python examples/public_key_analysis.py
"""

from __future__ import annotations

from binarycryptolab.bitcoin import address_from_public_key, decode_address
from binarycryptolab.ecc import public_key_from_private
from binarycryptolab.exceptions import AddressEncodingError


def main() -> None:
    print("BinaryCryptoLab example: public key and address derivation")
    print("-" * 60)

    # Synthetic test scalar only. The private value is never printed.
    info = public_key_from_private(1)
    print(f"curve               : {info.curve}")
    print(f"compressed key      : {info.compressed_hex}")
    print(f"uncompressed key    : {info.uncompressed_hex}")
    print(f"x                   : {info.x:064x}")
    print(f"y                   : {info.y:064x}")
    print("private scalar      : <not retained by the library API>")

    print()
    for address_type in ("p2pkh", "p2wpkh"):
        for network in ("mainnet", "testnet"):
            address = address_from_public_key(
                info.compressed_hex, address_type=address_type, network=network
            )
            print(f"{address_type:7} {network:8} {address.address}")
            decoded = decode_address(address.address, network)
            print(f"        hash160={decoded.payload_hex} type={decoded.address_type}")

    print()
    print("An uncompressed key produces a different P2PKH address:")
    uncompressed = address_from_public_key(info.uncompressed_hex, address_type="p2pkh")
    print(f"  {uncompressed.address} ({uncompressed.public_key_encoding})")

    print()
    print("P2WPKH deliberately rejects uncompressed keys instead of guessing:")
    try:
        address_from_public_key(info.uncompressed_hex, address_type="p2wpkh")
    except AddressEncodingError as exc:
        print(f"  {type(exc).__name__}: {exc}")

    print()
    print("No blockchain data was queried; ownership and balances are unknown.")


if __name__ == "__main__":
    main()
