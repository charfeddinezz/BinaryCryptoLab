# Contributing to BinaryCryptoLab

Thank you for considering a contribution. This project values correctness,
small focused changes, and clear documentation over feature count.

## Development setup

```bash
git clone https://github.com/charfeddinezz/BinaryCryptoLab.git
cd BinaryCryptoLab
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Optional, for the graphical interface:

```bash
python -m pip install -e ".[gui]"
```

## Before you open a pull request

Run the full gate:

```bash
python -m ruff check src tests examples
python -m ruff format --check src tests examples
python -m mypy
python -m pytest -q
```

or simply:

```bash
make check
```

All four commands must pass.

## Code standards

* Python 3.11+ with type hints on every public function and class.
* Docstrings for public modules, classes, and functions. Explain units,
  indexing conventions, and failure modes.
* Keep functions small and single-purpose.
* No new runtime dependency unless it is essential. The core dependency budget
  is `cryptography`; Streamlit stays optional.
* Never implement cryptographic primitives yourself. Use `hashlib`,
  `hmac`, and `cryptography`.
* Resolve ambiguity explicitly. If an operation depends on width, byte order,
  numeric base, or network, take a parameter and validate it.
* Raise the documented exception types from `binarycryptolab.exceptions`.
* Do not add `TODO`-only modules or placeholder functions.
* Keep line length at 100 characters or less where practical; Ruff enforces
  style and imports.

## Tests

* Every new public function needs tests, including error paths.
* Use published test vectors for cryptographic code and cite the source in a
  docstring or comment.
* Property-based tests with Hypothesis are welcome for round-trip invariants.
* Never commit real private keys, seed phrases, or funded wallet data. Use
  synthetic values such as the scalar `1`.
* GUI tests use Streamlit's `AppTest` and must skip cleanly when the optional
  dependency is absent.

## Documentation

* Update the relevant file under `docs/` and, when behaviour changes, the
  README.
* Verify every command you document by running it.
* State limitations honestly.

## Commits and pull requests

* Make one logical change per commit and use an imperative summary, e.g.
  `Add Bech32m checksum verification`.
* Describe the motivation and the tests you ran in the pull request.
* Do not include generated artefacts, virtual environments, or reports.
* Security fixes should follow [`SECURITY.md`](SECURITY.md); do not open a
  public issue with exploit details.

## Reporting bugs

Include the Python version, the exact command or code, the expected result, and
the actual result. Redact any private key or sensitive data before posting.
