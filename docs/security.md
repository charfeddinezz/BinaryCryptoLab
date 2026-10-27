# Security model

BinaryCryptoLab is a **local educational and analytical tool**. This document
describes what it protects, what it deliberately does not do, and the residual
risks a user should understand.

## Non-goals

The project does not and will not:

* search the internet for private keys;
* scan random addresses for balances;
* brute-force, guess, or derive private keys;
* recover anyone else's wallet secrets;
* claim that a hash can be reversed;
* claim that a public key reveals a private key;
* exfiltrate input, phone home, or hide network requests;
* store private keys in configuration, reports, or logs.

There is no network code in the package. The only network activity in a normal
session would be your browser loading the optional local Streamlit UI.

## Threat model

The relevant threats for this kind of tool are:

1. **Accidental disclosure of a private key** through shell history, process
   listings, terminal logs, screenshots, reports, or committed files.
2. **Mistaking encoded data for security.** Base58Check and Bech32 detect typos;
   they do not authenticate.
3. **Using a test key with real funds.**
4. **Trusting an unverified cryptographic implementation.**
5. **Denial of service through oversized input.**

### Controls

| Threat | Control |
| --- | --- |
| Private key in reports | `AnalysisResult` refuses a `"private_key"` input unless both input fields are `<redacted>`; the CLI and GUI use that marker. |
| Private key in error messages | `InvalidPrivateKeyError` messages describe the valid range and never include the scalar; tests assert the absence of a synthetic scalar. |
| Private key in logs | No module logs user input. The CLI logs only lifecycle events (`INFO`/`DEBUG`). |
| Private key in shell history | The CLI prints a warning whenever `--private-key` is used and offers `--prompt-private-key` (hidden `getpass` input) as an alternative. |
| Private key in the GUI | The input field is a password field; the scalar is passed to the library and never placed in `st.session_state` or downloadable results. |
| Wrong signature algorithms | Hashing uses `hashlib`/OpenSSL; ECC uses `cryptography`/OpenSSL. Missing algorithms raise rather than fall back. |
| Oversized input | `InputLimits` caps binary/hex/decimal input; the CLI caps file hashing at 64 MiB. |
| Overwriting evidence | Reports refuse to overwrite by default and are written atomically. |
| Terminal escape injection | Display helpers escape control characters in user-supplied text before printing. |

## What the software cannot protect against

* **A compromised machine.** Malware, a keylogger, or a shoulder-surfer can
  capture anything you type.
* **A leaked key.** Once a private key is exposed, it must be treated as
  compromised and funds moved immediately. This tool cannot undo exposure.
* **A wrong network or address type.** The tool derives what you ask for;
  sending funds to the wrong network or script type is outside its control.
* **A malicious dependency.** `cryptography` and, optionally, Streamlit are
  third-party packages. Install them from trusted sources and keep them
  up to date.

## Private-key handling rules

1. Use only synthetic test values. The generator scalar `1` and the Bitcoin wiki
   example are fine; a key controlling funds is not.
2. Prefer `--prompt-private-key` over `--private-key`. Command-line arguments
   are visible in shell history, process listings, and terminal scrollback.
3. For programmatic use, pass the scalar only to `ecc.public_key_from_private`
   and do not store it.
4. Never commit a scalar to a repository, issue, chat, or screenshot.
5. Never reuse a test key in a funded wallet. Anyone who knows the key can spend
   the funds.

## Reporting and download rules

* JSON and CSV reports contain only non-sensitive data.
* Text hashed via the CLI `--text` option and file contents hashed via
  `--file` are **not** included in reports; only lengths and a file name are
  recorded.
* Hexadecimal hashed via `--hex` is included, because the user explicitly
  supplied it as data. Treat exported reports as potentially sensitive if you
  pasted sensitive hexadecimal data.
* Files are written atomically and only where you specify.

## Cryptographic implementation notes

* No custom curve arithmetic, block cipher, or hash is implemented.
* RIPEMD-160 availability is probed; absence causes a clear error.
* Checksum comparisons use `hmac.compare_digest`.
* Base58/Base58Check and Bech32 are encoding layers, not secrecy layers.
* SHA-256, SHA-512, and the curve operations rely on the system OpenSSL used by
  `cryptography`.

## Dependency and build security

* Runtime dependency: `cryptography>=42,<52`.
* Optional dependency: `streamlit>=1.50,<2` for the GUI.
* Development dependencies are declared under the `dev` extra and are not
  required at runtime.
* CI installs only from PyPI, runs linting, typing, and tests, and contains no
  secrets.

## Coordinated disclosure

If you believe you have found a security issue, please follow
[`SECURITY.md`](../SECURITY.md): report it privately, do not open a public
issue with exploit details, and allow reasonable time for a fix.

## Safe-use checklist

- [ ] I am using a synthetic test key.
- [ ] I understand that command-line arguments may be recorded.
- [ ] I have not committed any scalar, seed phrase, or keystore file.
- [ ] I know that address derivation does not prove ownership or balance.
- [ ] I will treat any exported report as data that may need to be deleted.
- [ ] I verified the network and address type before using an address anywhere.
