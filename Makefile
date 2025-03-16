# Kyber-PQC Build Automation
PYTHON := python3
PIP := pip3

.PHONY: all install build test lint profile clean

all: install build

install:
	$(PIP) install -U pip wheel
	$(PIP) install -e .[dev,benchmark]

build:
	$(PYTHON) -m build --wheel
	$(PYTHON) setup.py build_ext --inplace

test:
	$(PYTHON) -m pytest -v tests/ --cov=kyber_pqc --cov-report=xml

lint:
	$(PYTHON) -m flake8 src/ tests/
	$(PYTHON) -m mypy src/ tests/

profile:
	$(PYTHON) -m cProfile -o profile.stats src/kyber_pqc/benchmark.py
	snakeviz profile.stats

clean:
	rm -rf build/ dist/ *.egg-info/ .coverage .pytest_cache/ __pycache__/
	find . -name '*.so' -delete