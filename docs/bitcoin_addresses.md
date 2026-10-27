# Bitcoin addresses

This document describes exactly how BinaryCryptoLab turns a **public key** into
a Bitcoin address, which networks are supported, and what the result means.

> A public key is not an address. An address is not a wallet. An address does
> not prove ownership, does not contain funds by itself, and does not reveal a
> balance. BinaryCryptoLab never queries the blockchain.

## Supported networks

| Network | P2PKH version byte | P2SH version byte | SegWit HRP |
| --- | --- | --- | --- |
| `mainnet` | `0x00` | `0x05` | `bc` |
| `testnet` | `0x6f` | `0xc4` | `tb` |
| `signet` | `0x6f` | `0xc4` | `tb` |
| `regtest` | `0x6f` | `0xc4` | `bcrt` |

Testnet, signet, and regtest share the same Base58 version byte, so a Base58
address alone cannot distinguish them. `decode_address` reports this as
`network_ambiguous=True` when the network is not supplied explicitly.

## P2PKH (legacy, Base58Check)

Derivation steps implemented in `bitcoin.derive_p2pkh_address`:

1. Parse and validate the SEC 1 public key.
2. Keep the encoding the caller supplied (compressed or uncompressed).
3. Compute `HASH160 = RIPEMD160(SHA256(public_key))`.
4. Prefix the network version byte: `0x00` on mainnet, `0x6f` elsewhere.
5. Encode with Base58Check (four-byte double-SHA-256 checksum).

The locking script (`scriptPubKey`) is:

```
OP_DUP OP_HASH160 <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG
76       a9          14 <hash160>      88              ac
```

The same public key point produces **different** addresses when serialised in
compressed vs uncompressed form. Both are valid P2PKH addresses and both are
recognised by the network; the tool records which encoding it used instead of
silently converting.

## P2WPKH (native SegWit v0, Bech32)

Derivation steps implemented in `bitcoin.derive_p2wpkh_address`:

1. Parse and validate the public key.
2. Require the **compressed** encoding. BIP-143 defines P2WPKH around compressed
   keys; accepting an uncompressed key would produce an address the user did not
   ask for, so it is rejected with a clear error.
3. Compute `HASH160(compressed_public_key)`; this 20-byte value is the witness
   program.
4. Encode witness version `0` and the program with Bech32 (BIP-173).
   Addresses for witness versions 1–16 use Bech32m (BIP-350); decoding supports
   them, derivation does not.

The locking script is:

```
OP_0 <20-byte key hash>
00   14 <hash160>
```

## Validation performed when decoding

`decode_address` checks:

* **Base58Check**: checksum, 21-byte payload length, known version byte, and
  network match when a network was supplied. P2SH payloads are reported as
  `p2sh`; distinguishing nested SegWit from a generic P2SH script would require
  the redeem script, which an address does not carry.
* **Bech32/Bech32m**: valid checksum, no mixed case, matching HRP, witness
  version `0..16`, witness program length `2..40`, version-0 length of 20 or 32,
  correct checksum variant for the version, and canonical padding.

Decoding recognises P2PKH, P2SH, P2WPKH, P2WSH, and `witness_vN` outputs. Generic
P2SH, P2WSH, and Taproot-style outputs are **decode-only**: this project derives
P2PKH, P2WPKH, and P2SH-P2WPKH.

### P2SH-P2WPKH (nested SegWit)

For wallets that cannot pay to Bech32 addresses, the witness program is wrapped in
a P2SH redeem script:

```
redeemScript = OP_0 <20-byte key hash>        (0x0014 || hash160)
scriptHash   = HASH160(redeemScript)
address      = Base58Check(0x05 || scriptHash)      (0xc4 on test networks)
scriptPubKey = OP_HASH160 <20-byte scriptHash> OP_EQUAL   (a914...87)
```

The key must be compressed. Nested SegWit pays a P2SH address whose redeem script
contains the witness program, so older wallets can spend it.

## Known-answer vectors

Public scalar `1` (the generator point `G`), compressed public key
`0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`:

| Type | Network | Address |
| --- | --- | --- |
| P2PKH | mainnet | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` |
| P2WPKH | mainnet | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| P2PKH | testnet | `mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r` |
| P2WPKH | testnet | `tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx` |
| P2WPKH | regtest | `bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080` |
| P2SH-P2WPKH | mainnet | `3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN` |
| P2SH-P2WPKH | testnet / signet | `2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN` |

The same point in uncompressed form gives the P2PKH address
`1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm`.

The Bitcoin wiki example scalar
`0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725`
produces the uncompressed public key
`0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352…`
and the mainnet address `16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM`.

BIP-173/BIP-350 examples used by the test suite:

| Address | scriptPubKey |
| --- | --- |
| `BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4` | `0014751e76e8199196d454941c45d1b3a323f1433bd6` |
| `tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7` | `0020…903262` (P2WSH) |
| `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0` | `5120…f81798` (witness v1) |

## What address derivation does not tell you

* Whether the address has ever received funds.
* Its balance.
* Whether the person who supplied the public key controls the corresponding
  private key.
* Whether the address belongs to any particular wallet software.

Establishing balance or history requires querying a blockchain data source,
which is outside the scope of this project. If you add such a source, make that
network access explicit, opt-in, and documented; this repository performs no
network requests at all.

## Common pitfalls

* **Mixing formats.** A P2PKH address and a P2WPKH address for the same key are
  different strings. Wallets must be told which script type to pay.
* **Mixing networks.** Sending a testnet address on mainnet (or vice versa)
  results in loss of funds or a failed transaction. The CLI requires the network
  to be explicit for derivation and validates it during decoding.
* **Signing with the wrong encoding.** A signature made with an uncompressed key
  cannot spend a P2WPKH output derived from the compressed form. This tool does
  not sign, but the distinction matters if you extend it.
* **Reusing test keys.** A scalar printed in documentation or committed to a
  repository is public. Never fund it.
