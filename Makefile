# BinaryCryptoLab development tasks.
#
# Every target uses the interpreter in $(PYTHON), so an activated virtual
# environment is respected.  Run `make help` for a short summary.

PYTHON ?= python3
SRC_DIRS := src tests examples

.PHONY: help install dev gui test test-gui lint format format-check typecheck check \
        build clean run-gui examples

help:
	@echo "BinaryCryptoLab targets:"
	@echo "  install       install the package (runtime dependencies only)"
	@echo "  dev           install the package with test/lint/type dependencies"
	@echo "  gui           install the optional Streamlit dependency"
	@echo "  test          run the test suite with pytest"
	@echo "  test-gui      run the GUI tests (requires the gui extra)"
	@echo "  lint          run ruff checks"
	@echo "  format        format the code with ruff"
	@echo "  format-check  verify formatting without changing files"
	@echo "  typecheck     run mypy in strict mode"
	@echo "  check         lint + format-check + typecheck + test"
	@echo "  run-gui       launch the Streamlit interface"
	@echo "  examples      run the example scripts"
	@echo "  build         build an sdist and wheel into dist/"
	@echo "  clean         remove caches and build artefacts"

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

gui:
	$(PYTHON) -m pip install -e ".[gui]"

test:
	$(PYTHON) -m pytest -q

test-gui:
	$(PYTHON) -m pytest -q tests/test_gui.py tests/test_gui_app.py

lint:
	$(PYTHON) -m ruff check $(SRC_DIRS)

format:
	$(PYTHON) -m ruff format $(SRC_DIRS)

format-check:
	$(PYTHON) -m ruff format --check $(SRC_DIRS)

typecheck:
	$(PYTHON) -m mypy

check: lint format-check typecheck test

build:
	$(PYTHON) -m pip install build
	$(PYTHON) -m build

run-gui:
	$(PYTHON) -m binarycryptolab.gui.launcher

examples:
	$(PYTHON) examples/binary_analysis.py
	$(PYTHON) examples/hex_analysis.py
	$(PYTHON) examples/public_key_analysis.py

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache .hypothesis htmlcov
	rm -rf .coverage coverage.xml src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
