"""Public test vectors shared by the test modules.

All values are synthetic or published in public specifications.  No real
wallet secrets are used anywhere in this repository.
"""

from __future__ import annotations

# secp256k1 private scalar 0x01 -> generator point G (SEC 2).
PRIVATE_KEY_ONE = "01"
PUBKEY_ONE_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PUBKEY_ONE_UNCOMPRESSED = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

# Bitcoin wiki "Technical background of version 1 Bitcoin addresses" example.
WIKI_PRIVATE_KEY = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
WIKI_PUBKEY_UNCOMPRESSED = (
    "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352"
    "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
)
WIKI_ADDRESS_MAINNET = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"

# BIP-173 example: HASH160 of the compressed generator public key.
HASH160_OF_G = "751e76e8199196d454941c45d1b3a323f1433bd6"
ADDRESS_P2PKH_G = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
ADDRESS_P2WPKH_G = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
