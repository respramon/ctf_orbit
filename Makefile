PYTHON ?= python3

.PHONY: install test lint format build demo release
install:
	$(PYTHON) -m pip install -e ".[full,dev]"
test:
	$(PYTHON) -m unittest discover -s tests -v
lint:
	ruff check .
	ruff format --check .
format:
	ruff format .
build:
	$(PYTHON) -m build
demo:
	$(PYTHON) run.py analyze examples/data --recursive --out reports/demo-make
release:
	$(PYTHON) scripts/package_release.py --output dist/ctf-orbit-v1.0.0.zip
