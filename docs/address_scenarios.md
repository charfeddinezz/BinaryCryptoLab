# Address scenarios, and the limitations that were removed

`docs/address_forensics.md` explains one address. This document is about breadth:
every input shape the tool now accepts, every output type it can classify, and an
honest ledger of which previous limitations were removed and which cannot be.

## 1. Input matrix

| Scenario | Example | Result |
| --- | --- | --- |
| Bitcoin P2PKH | `1GeMQKJ8...` | type, payload, script, full report |
| Bitcoin P2SH | `3J98t1Wp...` | type, script hash, opacity warning |
| Bitcoin P2WPKH / P2WSH | `bc1q...`, `tb1q...` | witness version, program, network |
| Bitcoin Taproot | `bc1p...` | on-curve check, y parity, NUMS check, `2^128` |
| Future witness versions | `bc1z...` (v2..v16) | flagged: unencumbered, anyone can spend |
| Upper-case Bech32 | `BC1Q...` | normalised, original preserved as evidence |
| Mixed-case Bech32 | `bc1Q...` | rejected (BIP-173 forbids it) |
| Bitcoin Cash CashAddr | `bitcoincash:qpm2...` | checksum verified, P2PKH/P2SH from the version byte |
| Litecoin | `L...`, `M...`, `ltc1...` | chain resolved from the prefix table |
| Dogecoin, Dash | `D...`, `X...` | chain resolved from the prefix table |
| Zcash transparent | `t1...`, `t3...` | two-byte version prefix handled |
| Test networks | `tb1...`, `bcrt1...`, `m...`/`n...` | warning: not mainnet |
| BIP-21 URI | `bitcoin:ADDR?amount=0.5` | parameters parsed and validated |
| Locking script | `76a914...88ac` | address derived from the script |
| P2PK script | `21<33 bytes>ac` | key exposed, `2^128`, no address form |
| OP_RETURN | `6a...` | provably unspendable |
| Non-standard script | `script:deadbeef` | labelled, no cost bound claimed |
| Whitespace / zero-width | `" bc1q... "` | cleaned before decoding |
| WIF private key | `5Hue...`, `L1...` | **refused**, never echoed |
| Arbitrary hex | `ab9a...` | rejected with guidance, not guessed |

Two rules make this predictable. First, a bare hexadecimal string is only treated
as a script when it matches a known template; otherwise the tool refuses, because
the same bytes could be a hash, a key, or a script. Second, when a version byte is
valid on several chains, every candidate is reported (`chain_candidates`) and the
report says the chain is a set, not a fact.

## 2. Output matrix

Each type gets its own backward chain, because they are not equally hard:

| Type | Committed object | First barrier | Second barrier | Total |
| --- | --- | --- | --- | --- |
| P2PKH | HASH160 of a key | preimage `2^160` | discrete log `2^128` | `2^288` |
| P2WPKH | HASH160 of a key | preimage `2^160` | discrete log `2^128` | `2^288` |
| P2SH | HASH160 of a script | script preimage `2^160` | script semantics | `2^160` |
| P2WSH | SHA256 of a script | script preimage `2^256` | script semantics | `2^256` |
| P2TR | x-only output key | nothing | discrete log `2^128` | `2^128` |
| P2PK | the key itself | nothing | discrete log `2^128` | `2^128` |
| witness v2..v16 | an undefined program | nothing | nothing | `2^0` |
| OP_RETURN | no spending rule | unspendable | - | - |

The P2TR row is the one people get wrong in both directions. A Taproot address
publishes a full 256-bit curve point, so it is *less* private than a hash-based
address at the hash layer (there is no hash layer), but it is *not* easier to break
today, because the discrete logarithm is still `2^128`. Conversely, a P2SH or P2WSH
address looks like a 160- or 256-bit commitment but is usually much weaker in
practice: the "preimage" is a script, and scripts come from a handful of templates.

## 3. The safety audit

Every dissection ends with a graded audit. The grades are deliberately blunt:

| Grade | Meaning |
| --- | --- |
| `danger` | at least one critical hazard: burned, claimable by anyone, or malformed |
| `review` | no fatal hazard, but the output cannot be certified offline |
| `no-known-hazard` | nothing in the documented catalogue applies |

Critical findings include: a documented burn address, an all-zero or constant
payload, an undefined witness version, a malformed Taproot program, the BIP-341
NUMS point as output key, an off-curve Taproot key, OP_RETURN. Warnings include:
an opaque script hash, an undefined network, a hostile BIP-21 amount, a `req-`
parameter the tool does not implement.

None of these can certify safety, and the verdict says so every time: only the key
holder can prove spendability by signing.

## 4. Limitations: removed, reduced, and irreducible

| Previous limitation | Status | How |
| --- | --- | --- |
| Only Bitcoin Base58 and Bech32 were accepted | **removed** | `address_formats` registry, CashAddr, alt-chains, Zcash |
| Only P2PKH/P2SH/P2WPKH/P2WSH were analysed | **removed** | Taproot, P2PK, OP_RETURN, non-standard, v2..v16 |
| One address per invocation | **removed** | batch arguments, `--input-file`, CSV, JSON envelope |
| No warning about dangerous destinations | **removed** | graded safety audit with evidence |
| "Balance needs a blockchain" | **reduced** | `audit-address-data` audits an export you supply |
| "A clean report does not prove safety" | **reduced** | the audit enumerates known hazards explicitly |
| Only four derivations in the controlled experiment | **removed** | Taproot key-path derivation added |
| "No key can be recovered from an address" | **irreducible** | that is the property being measured |
| "Ownership needs a signature" | **irreducible** | the tool never handles private keys |
| "No network, so no chain state" | **by design** | a network call would break the offline guarantee |

The last three are not gaps to be closed by more code. Recovering a key from an
address is a preimage problem with no known shortcut; proving ownership requires a
signature the tool is designed never to see; and reading chain state requires a
network, which this project refuses to use.

## 5. Reproducing the claims

```bash
# every scenario in one batch
binarycryptolab dissect-address --input-file tests/fixtures/address_scenarios.txt

# the hazard catalogue
binarycryptolab dissect-address 1BitcoinEaterAddressDontSendf59kuE
binarycryptolab dissect-address "script:6a0b68656c6c6f"

# the offline audit
binarycryptolab audit-address-data 1GeMQKJ8... --input-file export.json --report-format json
```

The test suite covers each row of the input matrix, the CashAddr round trip against
the published vector, the Taproot tweak against OpenSSL, and the exact-versus-Monte
Carlo prefix mathematics.
